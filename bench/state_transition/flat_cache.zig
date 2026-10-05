//! Flat validator cache, measured on its own and through the real `EpochTransitionCache.init`
//! and a full epoch transition.
//!
//! Every simulated epoch runs 32 "blocks" of churn (clone, balance bumps, participation writes,
//! commit, old states released) and an epoch step (all balances rewritten, FLAT_WRITES validators
//! rewritten). The benchmark owns one `ValidatorFlatCache` that is filled once and from then on
//! only brought forward by `sync`.
//!
//! Env:
//!   FLAT_STATE=<path to fulu state ssz>  (required)
//!   FLAT_EPOCHS=<n>                      default 900
//!   FLAT_REPORT_EVERY=<n>                default 150
//!   FLAT_WRITES=<n>                      validator writes per epoch, default 50
//!   FLAT_RING=<n>                        live states, default 64

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("state_transition");
const time = @import("time");
const config = @import("config");
const fork_types = @import("fork_types");

const AnyBeaconState = fork_types.AnyBeaconState;
const CachedBeaconState = state_transition.CachedBeaconState;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const ValidatorFlatCache = state_transition.validator_flat_cache.ValidatorFlatCache;
const preset = state_transition.preset;

const MAX_RING = 256;

fn envUsize(name: [*:0]const u8, default: usize) !usize {
    const raw = std.c.getenv(name) orelse return default;
    return try std.fmt.parseInt(usize, std.mem.span(raw), 10);
}

fn ms(io: std.Io, from: std.Io.Timestamp) f64 {
    return @as(f64, @floatFromInt(time.since(io, from).nanoseconds)) / std.time.ns_per_ms;
}

const ValidatorsRef = struct { root: Node.Id, len: usize };

fn validatorsRef(state: *AnyBeaconState) !ValidatorsRef {
    var view = try state.validators();
    try view.commit();
    return .{
        .root = view.getRoot(),
        .len = try view.length(),
    };
}

/// Milliseconds for one real `EpochTransitionCache.init`.
fn runInit(
    allocator: std.mem.Allocator,
    io: std.Io,
    beacon_config: *const config.BeaconConfig,
    head: *CachedBeaconState,
) !f64 {
    const t = time.start(io);
    var cache = try EpochTransitionCache.init(allocator, beacon_config, head.epoch_cache, head.state);
    const elapsed = ms(io, t);
    cache.deinit();
    return elapsed;
}

const SyncRun = struct { us: f64, patched: usize };

fn runSync(io: std.Io, cache: *ValidatorFlatCache, state: *AnyBeaconState) !SyncRun {
    const ref = try validatorsRef(state);
    const t = time.start(io);
    try cache.sync(ref.root, ref.len);
    return .{ .us = ms(io, t) * 1000.0, .patched = cache.last_patched };
}

const TransitionRun = struct { ms: f64 };

/// A full epoch transition, which always uses the flat cache, on a throwaway clone: advance to the last slot of the epoch untimed,
/// then time the slot that crosses the boundary.
fn runTransition(
    allocator: std.mem.Allocator,
    io: std.Io,
    head: *CachedBeaconState,
) !TransitionRun {
    const clone = try head.clone(allocator, .{ .transfer_cache = false });
    defer {
        clone.deinit();
        allocator.destroy(clone);
    }
    const slot = try clone.state.slot();
    const boundary = (slot / preset.SLOTS_PER_EPOCH + 1) * preset.SLOTS_PER_EPOCH;
    try state_transition.processSlots(allocator, io, clone, boundary - 1, null);

    const t = time.start(io);
    try state_transition.processSlots(allocator, io, clone, boundary, null);
    const elapsed = ms(io, t);
    return .{ .ms = elapsed };
}

const Window = struct {
    n: usize = 0,
    init_sum: f64 = 0,
    sync_sum_us: f64 = 0,
    patched_sum: usize = 0,

    fn mean(sum: f64, n: usize) f64 {
        return if (n == 0) 0 else sum / @as(f64, @floatFromInt(n));
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    const state_path = std.mem.span(std.c.getenv("FLAT_STATE") orelse {
        std.debug.print("FLAT_STATE is required\n", .{});
        return error.MissingStatePath;
    });
    const epochs = try envUsize("FLAT_EPOCHS", 900);
    const report_every = try envUsize("FLAT_REPORT_EVERY", 150);
    const validator_writes = try envUsize("FLAT_WRITES", 50);
    const ring_size = @min(MAX_RING, try envUsize("FLAT_RING", 64));
    const block_balance_bumps: usize = 512;
    const block_participation_writes: usize = 8192;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 10_000_000 });
    defer pool.deinit();

    const state_bytes = try std.Io.Dir.cwd().readFileAlloc(io, state_path, allocator, .unlimited);
    defer allocator.free(state_bytes);

    const state = try allocator.create(AnyBeaconState);
    state.* = try AnyBeaconState.deserialize(allocator, &pool, .fulu, state_bytes);
    const validator_count = try state.validatorsCount();

    var beacon_config: config.BeaconConfig = config.hoodi.config;
    var pubkey_cache = try state_transition.PubkeyCache.initCapacity(
        allocator,
        io,
        validator_count + preset.MAX_PENDING_DEPOSITS_PER_EPOCH,
    );
    defer pubkey_cache.deinit();

    const first = try CachedBeaconState.createCachedBeaconState(allocator, io, state, .{
        .config = &beacon_config,
        .pubkey_cache = &pubkey_cache,
    }, .{ .skip_sync_committee_cache = false, .skip_sync_pubkeys = false });
    defer state_transition.deinitReusedEpochTransitionCache();

    var flat_cache = ValidatorFlatCache.init(allocator, &pool);
    defer flat_cache.deinit();

    var ring: [MAX_RING]?*CachedBeaconState = @splat(null);
    var ring_pos: usize = 0;
    var head: *CachedBeaconState = first;
    ring[ring_pos] = head;
    ring_pos = (ring_pos + 1) % ring_size;
    defer for (ring[0..ring_size]) |maybe| if (maybe) |s| {
        s.deinit();
        allocator.destroy(s);
    };

    var prng = std.Random.DefaultPrng.init(42);
    const rng = prng.random();

    std.debug.print("validators={} writes_per_epoch={} ring={}\n", .{ validator_count, validator_writes, ring_size });

    // Cold start: the first sync fills the whole cache.
    {
        const cold = try runSync(io, &flat_cache, head.state);
        std.debug.print("cold fill: {d:.1} ms, patched={}, cache={d:.1} MiB\n", .{
            cold.us / 1000.0,
            cold.patched,
            @as(f64, @floatFromInt(flat_cache.byteSize())) / (1024.0 * 1024.0),
        });
    }

    std.debug.print("epoch,init_ms,sync_us,patched_per_epoch,transition_ms,cache_mismatches\n", .{});

    var window: Window = .{};
    for (0..epochs + 1) |epoch| {
        if (epoch > 0) {
            for (0..preset.SLOTS_PER_EPOCH) |_| {
                const next = try head.clone(allocator, .{ .transfer_cache = true });
                {
                    var balances = try next.state.balances();
                    for (0..block_balance_bumps) |_| {
                        const i = rng.uintLessThan(usize, validator_count);
                        try balances.set(i, (try balances.get(i)) + 1);
                    }
                }
                {
                    var participation = try next.state.currentEpochParticipation();
                    for (0..block_participation_writes) |_| {
                        const i = rng.uintLessThan(usize, validator_count);
                        try participation.set(i, try participation.get(i));
                    }
                }
                try next.state.commit();

                if (ring[ring_pos]) |old| {
                    old.deinit();
                    allocator.destroy(old);
                }
                ring[ring_pos] = next;
                ring_pos = (ring_pos + 1) % ring_size;
                head = next;
            }

            const bals = try head.state.balancesSlice(allocator);
            for (bals) |*b| b.* += 1;
            var list: std.ArrayList(u64) = .fromOwnedSlice(bals);
            defer list.deinit(allocator);
            try head.state.setBalances(&list);

            var validators = try head.state.validators();
            for (0..validator_writes) |_| {
                const i = rng.uintLessThan(usize, validator_count);
                var v = try validators.get(i);
                // A value the cache stores really changes, so parity is not trivially true. The
                // exit stays far in the future, which keeps the validator active this epoch.
                try v.set("exit_epoch", head.epoch_cache.epoch + 1_000_000 + epoch * validator_writes + i % 1024);
                try v.set("withdrawable_epoch", head.epoch_cache.epoch + 2_000_000 + epoch);
            }
            try head.state.commit();
        }

        const synced = try runSync(io, &flat_cache, head.state);
        const init_ms = try runInit(allocator, io, &beacon_config, head);

        window.n += 1;
        window.init_sum += init_ms;
        window.sync_sum_us += synced.us;
        window.patched_sum += synced.patched;

        if (epoch % report_every == 0) {
            const ref = try validatorsRef(head.state);
            const mismatches = try state_transition.flatCacheCountMismatches(&flat_cache, ref.root, ref.len);
            if (mismatches != 0) return error.FlatCacheOutOfSync;

            const transition = try runTransition(allocator, io, head);

            std.debug.print("{},{d:.1},{d:.0},{d:.1},{d:.1},{}\n", .{
                epoch,
                Window.mean(window.init_sum, window.n),
                Window.mean(window.sync_sum_us, window.n),
                Window.mean(@floatFromInt(window.patched_sum), window.n),
                transition.ms,
                mismatches,
            });
            window = .{};
        }
    }

    // Switching to a state on another branch and back: cost follows the number of differences.
    {
        const other = ring[ring_pos] orelse first;
        const away = try runSync(io, &flat_cache, other.state);
        const back = try runSync(io, &flat_cache, head.state);
        std.debug.print("switch to state {} blocks back: {d:.3} ms ({} patched), and back: {d:.3} ms ({} patched)\n", .{
            ring_size - 1, away.us / 1000.0, away.patched, back.us / 1000.0, back.patched,
        });
    }

    // A state loaded from bytes shares no nodes with the head, so everything is patched.
    {
        var loaded = try AnyBeaconState.deserialize(allocator, &pool, .fulu, state_bytes);
        defer loaded.deinit();
        const away = try runSync(io, &flat_cache, &loaded);
        const back = try runSync(io, &flat_cache, head.state);
        std.debug.print("switch to a state loaded from bytes: {d:.1} ms ({} patched), and back to the scattered head: {d:.1} ms ({} patched)\n", .{
            away.us / 1000.0, away.patched, back.us / 1000.0, back.patched,
        });
    }

    // Full refill on the scattered head.
    {
        flat_cache.invalidate();
        const cold = try runSync(io, &flat_cache, head.state);
        std.debug.print("cold fill on the scattered head: {d:.1} ms ({} patched)\n", .{ cold.us / 1000.0, cold.patched });
    }
}
