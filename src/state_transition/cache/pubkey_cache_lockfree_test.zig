const std = @import("std");
const bls = @import("bls");
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;
const cache_module = @import("pubkey_cache_lockfree.zig");
const LockFreePubkeyCache = cache_module.LockFreePubkeyCache;
const testing = std.testing;
const interop = @import("../test_utils/interop_pubkeys.zig");

fn validatorsForPubkeys(
    pubkeys: []const types.primitive.BLSPubkey.Type,
    validators: []Validator,
    validator_ptrs: []*const Validator,
) void {
    std.debug.assert(pubkeys.len == validators.len);
    std.debug.assert(pubkeys.len == validator_ptrs.len);
    for (pubkeys, validators, validator_ptrs) |pubkey, *validator, *validator_ptr| {
        validator.* = std.mem.zeroes(Validator);
        validator.pubkey = pubkey;
        validator_ptr.* = validator;
    }
}

/// Cheap unique valid pubkeys: repeatedly add one base point. Sums of subgroup
/// points stay in the subgroup, and consecutive sums are distinct.
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

test "lockfree: syncPubkeys incrementally populates both lookup directions" {
    const initial_count = 2;
    const total_count = 16;
    var pubkeys: [total_count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(total_count, &pubkeys);

    var validators: [total_count]Validator = undefined;
    var validator_ptrs: [total_count]*const Validator = undefined;
    validatorsForPubkeys(&pubkeys, &validators, &validator_ptrs);

    var cache = LockFreePubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    try cache.syncPubkeys(testing.io, validator_ptrs[0..initial_count]);
    try cache.syncPubkeys(testing.io, &validator_ptrs);

    try testing.expectEqual(@as(u32, total_count), cache.count(testing.io));
    for (pubkeys, 0..) |pubkey, expected_index| {
        try testing.expectEqual(
            @as(u64, @intCast(expected_index)),
            cache.get(testing.io, pubkey).?,
        );
        const compressed = cache.getPubkey(testing.io, expected_index).?.compress();
        try testing.expectEqualSlices(u8, &pubkey, &compressed);
    }
}

test "lockfree: syncPubkeys accepts a historical validator slice" {
    var pubkeys: [4]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var validators: [4]Validator = undefined;
    var validator_ptrs: [4]*const Validator = undefined;
    validatorsForPubkeys(&pubkeys, &validators, &validator_ptrs);

    var cache = LockFreePubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    try cache.syncPubkeys(testing.io, &validator_ptrs);
    // A historical (shorter) slice is a no-op, not a rollback.
    try cache.syncPubkeys(testing.io, validator_ptrs[0..2]);

    try testing.expectEqual(@as(u32, 4), cache.count(testing.io));
}

test "lockfree: syncPubkeys rejects duplicates without publishing" {
    var pubkeys: [4]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);
    // Duplicate within the new suffix.
    pubkeys[3] = pubkeys[2];

    var validators: [4]Validator = undefined;
    var validator_ptrs: [4]*const Validator = undefined;
    validatorsForPubkeys(&pubkeys, &validators, &validator_ptrs);

    var cache = LockFreePubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    try cache.syncPubkeys(testing.io, validator_ptrs[0..2]);
    try testing.expectError(
        error.DuplicatePubkey,
        cache.syncPubkeys(testing.io, &validator_ptrs),
    );
    try testing.expectEqual(@as(u32, 2), cache.count(testing.io));
    try testing.expectEqual(@as(?u64, 0), cache.get(testing.io, pubkeys[0]));
}

test "lockfree: append semantics match the locked cache" {
    var pubkeys: [3]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = LockFreePubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    try cache.append(testing.io, pubkeys[0], 0);
    try cache.append(testing.io, pubkeys[1], 1);

    // Idempotent replay of an existing index.
    try cache.append(testing.io, pubkeys[0], 0);
    try testing.expectEqual(@as(u32, 2), cache.count(testing.io));

    // Conflicting pubkey at an existing index.
    try testing.expectError(error.ConflictingPubkey, cache.append(testing.io, pubkeys[2], 0));
    // Known pubkey at a fresh index.
    try testing.expectError(error.DuplicatePubkey, cache.append(testing.io, pubkeys[0], 2));
    // Gap in the index sequence.
    try testing.expectError(error.InvalidIndexToAppend, cache.append(testing.io, pubkeys[2], 3));

    try cache.append(testing.io, pubkeys[2], 2);
    try testing.expectEqual(@as(?u64, 2), cache.get(testing.io, pubkeys[2]));
}

test "lockfree: batch lookups and aggregate" {
    var pubkeys: [8]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = LockFreePubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    for (pubkeys, 0..) |pubkey, i| try cache.append(testing.io, pubkey, i);

    const indices = [_]u64{ 1, 3, 5 };
    var out: [3]bls.PublicKey = undefined;
    try cache.getPubkeys(testing.io, &indices, &out);
    for (indices, out) |index, pubkey| {
        try testing.expectEqualSlices(u8, &pubkeys[@intCast(index)], &pubkey.compress());
    }

    var index_out: [8]u64 = undefined;
    try cache.getValidatorIndices(testing.io, &pubkeys, &index_out);
    for (index_out, 0..) |index, expected| {
        try testing.expectEqual(@as(u64, @intCast(expected)), index);
    }

    var expected_agg = bls.PublicKey.uncompress(&pubkeys[1]) catch unreachable;
    var acc = expected_agg.toAggregate();
    const pk3 = bls.PublicKey.uncompress(&pubkeys[3]) catch unreachable;
    const pk5 = bls.PublicKey.uncompress(&pubkeys[5]) catch unreachable;
    acc.add(&pk3);
    acc.add(&pk5);
    const aggregated = try cache.aggregate(testing.io, &indices);
    try testing.expectEqualSlices(u8, &acc.toPublicKey().compress(), &aggregated.compress());

    try testing.expectError(error.InvalidIndex, cache.aggregate(testing.io, &[_]u64{99}));
    try testing.expectError(error.InvalidLength, cache.aggregate(testing.io, &[_]u64{}));
}

test "lockfree: growth across chunk boundaries and table swaps" {
    const total = 10_000; // crosses the 4096 and 12288 chunk boundaries
    const allocator = testing.allocator;
    const pubkeys = try addChainPubkeys(allocator, total);
    defer allocator.free(pubkeys);

    var cache = LockFreePubkeyCache.init(allocator, testing.io);
    defer cache.deinit();

    for (pubkeys, 0..) |pubkey, i| try cache.append(testing.io, pubkey, i);

    try testing.expectEqual(@as(u32, total), cache.count(testing.io));
    for (pubkeys, 0..) |pubkey, i| {
        try testing.expectEqual(@as(?u64, @intCast(i)), cache.get(testing.io, pubkey));
        const compressed = cache.getPubkey(testing.io, i).?.compress();
        try testing.expectEqualSlices(u8, &pubkey, &compressed);
    }
}

test "lockfree: ensureTotalCapacity preallocates without publishing entries" {
    var cache = LockFreePubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    try cache.ensureTotalCapacity(testing.io, 100_000);
    try testing.expectEqual(@as(u32, 0), cache.count(testing.io));
    try testing.expect(cache.capacity(testing.io) >= 100_000);
}

const ReaderCtx = struct {
    cache: *const LockFreePubkeyCache,
    io: std.Io,
    pubkeys: []const [48]u8,
    failed: *std.atomic.Value(bool),
};

/// Readers race the writer and must only ever observe fully published entries.
fn readerLoop(ctx: ReaderCtx) void {
    var iterations: usize = 0;
    while (iterations < 2_000) : (iterations += 1) {
        const len = ctx.cache.count(ctx.io);
        if (len == 0) continue;
        const index: u64 = iterations % len;
        const pubkey = ctx.cache.getPubkey(ctx.io, index) orelse {
            // len may lag between loads; a published index must resolve.
            ctx.failed.store(true, .release);
            return;
        };
        if (!std.mem.eql(u8, &pubkey.compress(), &ctx.pubkeys[@intCast(index)])) {
            ctx.failed.store(true, .release);
            return;
        }
        const found = ctx.cache.get(ctx.io, ctx.pubkeys[@intCast(index)]) orelse continue;
        if (found != index) {
            ctx.failed.store(true, .release);
            return;
        }
    }
}

test "lockfree: concurrent readers observe consistent entries during appends" {
    const total = 4_200; // crosses the first chunk boundary mid-run
    const allocator = testing.allocator;
    const pubkeys = try addChainPubkeys(allocator, total);
    defer allocator.free(pubkeys);

    var cache = LockFreePubkeyCache.init(allocator, testing.io);
    defer cache.deinit();

    var failed = std.atomic.Value(bool).init(false);
    const ctx = ReaderCtx{
        .cache = &cache,
        .io = testing.io,
        .pubkeys = pubkeys,
        .failed = &failed,
    };

    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, readerLoop, .{ctx});
    }
    for (pubkeys, 0..) |pubkey, i| try cache.append(testing.io, pubkey, i);
    for (&threads) |*thread| thread.join();

    try testing.expect(!failed.load(.acquire));
    try testing.expectEqual(@as(u32, total), cache.count(testing.io));
}
