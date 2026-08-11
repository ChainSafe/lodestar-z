//! Benchmark: RwLock PubkeyCache vs draft LockFreePubkeyCache.
//!
//! Single-thread ops run under zbench. The contention section spawns reader
//! threads doing aggregate() while a writer appends, and reports ops/sec.
//!
//! Run with: zig build run:bench_pubkey_cache -Doptimize=ReleaseFast

const std = @import("std");
const builtin = @import("builtin");
const zbench = @import("zbench");
const bls = @import("bls");
const types = @import("consensus_types");
const state_transition = @import("state_transition");

const Validator = types.phase0.Validator.Type;
const PubkeyCache = state_transition.PubkeyCache;
const LockFreePubkeyCache = state_transition.LockFreePubkeyCache;

const validator_count = 200_000;
const lookup_batch = 1_000;
const aggregate_size = 512;
const extra_writer_keys = 4_096;

/// Cheap unique valid pubkeys: repeatedly add one base point.
fn addChainPubkeys(allocator: std.mem.Allocator, count: usize) ![][48]u8 {
    var ikm = [_]u8{7} ** 32;
    const sk = try bls.SecretKey.keyGen(&ikm, null);
    const base = sk.toPublicKey();
    var acc = base.toAggregate();

    const out = try allocator.alloc([48]u8, count);
    for (out) |*pubkey| {
        acc.add(&base);
        pubkey.* = acc.toPublicKey().compress();
    }
    return out;
}

fn randomIndices(allocator: std.mem.Allocator, count: usize, max: u64) ![]u64 {
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    const out = try allocator.alloc(u64, count);
    for (out) |*index| index.* = random.uintLessThan(u64, max);
    return out;
}

const Shared = struct {
    io: std.Io,
    pubkeys: [][48]u8,
    get_indices: []u64,
    agg_indices: []u64,
    locked: *PubkeyCache,
    lockfree: *LockFreePubkeyCache,
};

var shared: Shared = undefined;

const GetPubkeyLockedBench = struct {
    pub fn run(_: *@This(), _: std.mem.Allocator) void {
        for (shared.get_indices) |index| {
            std.mem.doNotOptimizeAway(shared.locked.getPubkey(shared.io, index));
        }
    }
};

const GetPubkeyLockFreeBench = struct {
    pub fn run(_: *@This(), _: std.mem.Allocator) void {
        for (shared.get_indices) |index| {
            std.mem.doNotOptimizeAway(shared.lockfree.getPubkey(shared.io, index));
        }
    }
};

const GetIndexLockedBench = struct {
    pub fn run(_: *@This(), _: std.mem.Allocator) void {
        for (shared.get_indices) |index| {
            std.mem.doNotOptimizeAway(shared.locked.get(shared.io, shared.pubkeys[@intCast(index)]));
        }
    }
};

const GetIndexLockFreeBench = struct {
    pub fn run(_: *@This(), _: std.mem.Allocator) void {
        for (shared.get_indices) |index| {
            std.mem.doNotOptimizeAway(shared.lockfree.get(shared.io, shared.pubkeys[@intCast(index)]));
        }
    }
};

const AggregateLockedBench = struct {
    pub fn run(_: *@This(), _: std.mem.Allocator) void {
        std.mem.doNotOptimizeAway(shared.locked.aggregate(shared.io, shared.agg_indices) catch unreachable);
    }
};

const AggregateLockFreeBench = struct {
    pub fn run(_: *@This(), _: std.mem.Allocator) void {
        std.mem.doNotOptimizeAway(shared.lockfree.aggregate(shared.io, shared.agg_indices) catch unreachable);
    }
};

// -- contention section --

const CacheKind = enum { locked, lockfree };

const ContentionCtx = struct {
    kind: CacheKind,
    stop: *std.atomic.Value(bool),
    ops: *std.atomic.Value(u64),
};

fn readerLoop(ctx: ContentionCtx) void {
    // Per-thread slice of aggregate indices to avoid trivially shared cache lines.
    var local: [64]u64 = undefined;
    @memcpy(&local, shared.agg_indices[0..64]);
    while (!ctx.stop.load(.acquire)) {
        const result = switch (ctx.kind) {
            .locked => shared.locked.aggregate(shared.io, &local),
            .lockfree => shared.lockfree.aggregate(shared.io, &local),
        };
        std.mem.doNotOptimizeAway(result catch unreachable);
        _ = ctx.ops.fetchAdd(1, .monotonic);
    }
}

/// Writer replays existing indices (idempotent appends, the historical-regen
/// pattern) and appends fresh keys. Locked cache takes the exclusive lock for
/// replays; lock-free treats them as plain reads.
fn writerLoop(kind: CacheKind, extra: [][48]u8, stop: *std.atomic.Value(bool)) void {
    var fresh: usize = 0;
    var replay: u64 = 0;
    while (!stop.load(.acquire)) {
        if (fresh < extra.len) {
            const index = validator_count + fresh;
            const result = switch (kind) {
                .locked => shared.locked.append(shared.io, extra[fresh], index),
                .lockfree => shared.lockfree.append(shared.io, extra[fresh], index),
            };
            result catch unreachable;
            fresh += 1;
        }
        // Ten idempotent replays per fresh append.
        for (0..10) |_| {
            const index = replay % validator_count;
            replay += 1;
            const result = switch (kind) {
                .locked => shared.locked.append(shared.io, shared.pubkeys[@intCast(index)], index),
                .lockfree => shared.lockfree.append(shared.io, shared.pubkeys[@intCast(index)], index),
            };
            result catch unreachable;
        }
    }
}

fn runContention(
    kind: CacheKind,
    reader_count: usize,
    extra: [][48]u8,
    duration_ns: u64,
) !u64 {
    var stop = std.atomic.Value(bool).init(false);
    var ops = std.atomic.Value(u64).init(0);

    var readers: [16]std.Thread = undefined;
    for (readers[0..reader_count]) |*thread| {
        thread.* = try std.Thread.spawn(.{}, readerLoop, .{ContentionCtx{
            .kind = kind,
            .stop = &stop,
            .ops = &ops,
        }});
    }
    const writer = try std.Thread.spawn(.{}, writerLoop, .{ kind, extra, &stop });

    std.Io.sleep(shared.io, std.Io.Duration.fromNanoseconds(@intCast(duration_ns)), .awake) catch {};
    stop.store(true, .release);
    for (readers[0..reader_count]) |*thread| thread.join();
    writer.join();

    return ops.load(.acquire);
}

pub fn main(init: std.process.Init) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    const allocator = if (builtin.mode == .Debug) debug_allocator.allocator() else std.heap.c_allocator;
    defer if (builtin.mode == .Debug) {
        std.debug.assert(debug_allocator.deinit() == .ok);
    };
    const io = init.io;

    std.debug.print("generating {d} pubkeys...\n", .{validator_count + extra_writer_keys});
    const all_pubkeys = try addChainPubkeys(allocator, validator_count + extra_writer_keys);
    defer allocator.free(all_pubkeys);
    const pubkeys = all_pubkeys[0..validator_count];

    const validators = try allocator.alloc(Validator, validator_count);
    defer allocator.free(validators);
    const validator_ptrs = try allocator.alloc(*const Validator, validator_count);
    defer allocator.free(validator_ptrs);
    for (pubkeys, validators, validator_ptrs) |pubkey, *validator, *ptr| {
        validator.* = std.mem.zeroes(Validator);
        validator.pubkey = pubkey;
        ptr.* = validator;
    }

    std.debug.print("populating caches...\n", .{});
    var locked_cache = try PubkeyCache.initCapacity(allocator, io, validator_count + extra_writer_keys);
    defer locked_cache.deinit();
    try locked_cache.syncPubkeys(io, validator_ptrs);

    var lockfree_cache = try LockFreePubkeyCache.initCapacity(allocator, io, validator_count + extra_writer_keys);
    defer lockfree_cache.deinit();
    try lockfree_cache.syncPubkeys(io, validator_ptrs);

    const get_indices = try randomIndices(allocator, lookup_batch, validator_count);
    defer allocator.free(get_indices);
    const agg_indices = try randomIndices(allocator, aggregate_size, validator_count);
    defer allocator.free(agg_indices);

    shared = .{
        .io = io,
        .pubkeys = pubkeys,
        .get_indices = get_indices,
        .agg_indices = agg_indices,
        .locked = &locked_cache,
        .lockfree = &lockfree_cache,
    };

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    const get_pubkey_locked = GetPubkeyLockedBench{};
    const get_pubkey_lockfree = GetPubkeyLockFreeBench{};
    const get_index_locked = GetIndexLockedBench{};
    const get_index_lockfree = GetIndexLockFreeBench{};
    const aggregate_locked = AggregateLockedBench{};
    const aggregate_lockfree = AggregateLockFreeBench{};

    try bench.addParam("getPubkey x1k rwlock", &get_pubkey_locked, .{});
    try bench.addParam("getPubkey x1k lockfree", &get_pubkey_lockfree, .{});
    try bench.addParam("getIndex x1k rwlock", &get_index_locked, .{});
    try bench.addParam("getIndex x1k lockfree", &get_index_lockfree, .{});
    try bench.addParam("aggregate 512 rwlock", &aggregate_locked, .{});
    try bench.addParam("aggregate 512 lockfree", &aggregate_lockfree, .{});

    try bench.run(io, std.Io.File.stdout());

    // Contention: readers aggregate while a writer appends and replays.
    const duration_ns = 2 * std.time.ns_per_s;
    std.debug.print("\ncontention: aggregate(64) readers vs 1 writer, {d}s per row\n", .{duration_ns / std.time.ns_per_s});
    std.debug.print("{s:>10} {s:>8} {s:>16} {s:>16}\n", .{ "readers", "impl", "reads/s", "reads/s/thread" });
    for ([_]usize{ 1, 2, 4, 8 }) |reader_count| {
        inline for ([_]CacheKind{ .locked, .lockfree }) |kind| {
            // Fresh extra-key range per run: reset by replaying the same indices.
            const extra = all_pubkeys[validator_count..];
            const ops = try runContention(kind, reader_count, extra, duration_ns);
            const per_sec = ops * std.time.ns_per_s / duration_ns;
            std.debug.print("{d:>10} {s:>8} {d:>16} {d:>16}\n", .{
                reader_count,
                @tagName(kind),
                per_sec,
                per_sec / reader_count,
            });
        }
    }
}
