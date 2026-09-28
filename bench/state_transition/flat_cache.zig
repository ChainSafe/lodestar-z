//! Maintained flat validator cache vs the tree walk, measured on the real
//! `EpochTransitionCache.init` and on a full epoch transition.
//!
//! Every simulated epoch runs 32 "blocks" of churn (clone, balance bumps, participation writes,
//! commit, old states released) and an epoch step (all balances rewritten, FLAT_WRITES validators
//! rewritten). After each epoch both paths are timed on the same state, alternating which goes
//! first. The flat cache is never rebuilt: it is only ever brought forward by `sync`.
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
const flat = state_transition.validator_flat_cache;
const preset = state_transition.preset;

const MAX_RING = 256;

fn envUsize(name: [*:0]const u8, default: usize) !usize {
    const raw = std.c.getenv(name) orelse return default;
    return try std.fmt.parseInt(usize, std.mem.span(raw), 10);
}

fn ms(io: std.Io, from: std.Io.Timestamp) f64 {
    return @as(f64, @floatFromInt(time.since(io, from).nanoseconds)) / std.time.ns_per_ms;
}

const ValidatorsRef = struct { root: Node.Id, depth: usize, len: usize };

fn validatorsRef(state: *AnyBeaconState) !ValidatorsRef {
    var view = try state.validators();
    try view.commit();
    return .{
        .root = view.getRoot(),
        .depth = view.iteratorReadonly(0).depth_iterator.base_gindex.pathLen(),
        .len = try view.length(),
    };
}

fn checksum(cache: *const EpochTransitionCache) u64 {
    var h = std.hash.Wyhash.init(0);
    h.update(cache.flags);
    h.update(std.mem.sliceAsBytes(cache.is_active_prev_epoch));
    h.update(std.mem.sliceAsBytes(cache.is_active_curr_epoch));
    h.update(std.mem.sliceAsBytes(cache.is_active_next_epoch));
    h.update(std.mem.sliceAsBytes(cache.is_compounding_validator_arr.items()));
    h.update(std.mem.sliceAsBytes(cache.next_shuffling_active_indices));
    h.update(std.mem.sliceAsBytes(cache.indices_to_slash.items));
    h.update(std.mem.sliceAsBytes(cache.indices_eligible_for_activation_queue.items));
    h.update(std.mem.sliceAsBytes(cache.indices_eligible_for_activation.items));
    h.update(std.mem.sliceAsBytes(cache.indices_to_eject.items));
    h.update(std.mem.asBytes(&cache.total_active_stake_by_increment));
    h.update(std.mem.asBytes(&cache.base_reward_per_increment));
    h.update(std.mem.asBytes(&cache.prev_epoch_unslashed_stake_target_by_increment));
    h.update(std.mem.asBytes(&cache.curr_epoch_unslashed_target_stake_by_increment));
    return h.final();
}

const InitRun = struct { ms: f64, sync_us: f64, patched: usize, checksum: u64 };

/// One real `EpochTransitionCache.init`. With the flat path, the sync that init would do is
/// timed on its own first, then counted into the total.
fn runInit(
    allocator: std.mem.Allocator,
    io: std.Io,
    beacon_config: *const config.BeaconConfig,
    pool: *Node.Pool,
    head: *CachedBeaconState,
    use_flat: bool,
) !InitRun {
    flat.enabled = use_flat;
    defer flat.enabled = false;

    var sync_us: f64 = 0;
    var patched: usize = 0;
    const t = time.start(io);
    if (use_flat) {
        const ref = try validatorsRef(head.state);
        const ts = time.start(io);
        const cache = try flat.syncGlobal(allocator, pool, ref.root, ref.depth, ref.len);
        sync_us = ms(io, ts) * 1000.0;
        patched = cache.last_patched;
    }
    var cache = try EpochTransitionCache.init(allocator, io, beacon_config, head.epoch_cache, head.state);
    const elapsed = ms(io, t);
    const sum = checksum(&cache);
    cache.deinit();
    return .{ .ms = elapsed, .sync_us = sync_us, .patched = patched, .checksum = sum };
}

const TransitionRun = struct { ms: f64, root: [32]u8 };

/// A full epoch transition on a throwaway clone: advance to the last slot of the epoch untimed,
/// then time the slot that crosses the boundary.
fn runTransition(
    allocator: std.mem.Allocator,
    io: std.Io,
    head: *CachedBeaconState,
    use_flat: bool,
) !TransitionRun {
    flat.enabled = use_flat;
    defer flat.enabled = false;

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
    return .{ .ms = elapsed, .root = (try clone.state.hashTreeRoot()).* };
}

const Window = struct {
    n: usize = 0,
    tree_sum: f64 = 0,
    flat_sum: f64 = 0,
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
    defer state_transition.deinitReusedEpochTransitionCache(io);
    defer flat.deinitGlobal();

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
        const ref = try validatorsRef(head.state);
        const t = time.start(io);
        const cache = try flat.syncGlobal(allocator, &pool, ref.root, ref.depth, ref.len);
        std.debug.print("cold fill: {d:.1} ms, patched={}, cache={d:.1} MiB\n", .{
            ms(io, t),
            cache.last_patched,
            @as(f64, @floatFromInt(cache.byteSize())) / (1024.0 * 1024.0),
        });
    }

    std.debug.print("epoch,init_tree_ms,init_flat_ms,of_which_sync_us,patched_per_epoch,transition_tree_ms,transition_flat_ms,cache_mismatches,init_parity,root_parity\n", .{});

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

        const flat_first = epoch % 2 == 0;
        const a = try runInit(allocator, io, &beacon_config, &pool, head, flat_first);
        const b = try runInit(allocator, io, &beacon_config, &pool, head, !flat_first);
        const flat_run = if (flat_first) a else b;
        const tree_run = if (flat_first) b else a;
        if (flat_run.checksum != tree_run.checksum) return error.InitOutputMismatch;

        window.n += 1;
        window.tree_sum += tree_run.ms;
        window.flat_sum += flat_run.ms;
        window.sync_sum_us += flat_run.sync_us;
        window.patched_sum += flat_run.patched;

        if (epoch % report_every == 0) {
            const ref = try validatorsRef(head.state);
            const mismatches = try flat.getGlobal().?.countMismatches(ref.root, ref.depth, ref.len);
            if (mismatches != 0) return error.FlatCacheOutOfSync;

            const t_a = try runTransition(allocator, io, head, flat_first);
            const t_b = try runTransition(allocator, io, head, !flat_first);
            const t_flat = if (flat_first) t_a else t_b;
            const t_tree = if (flat_first) t_b else t_a;
            if (!std.mem.eql(u8, &t_flat.root, &t_tree.root)) return error.TransitionRootMismatch;

            std.debug.print("{},{d:.1},{d:.1},{d:.0},{d:.1},{d:.1},{d:.1},{},ok,ok\n", .{
                epoch,
                Window.mean(window.tree_sum, window.n),
                Window.mean(window.flat_sum, window.n),
                Window.mean(window.sync_sum_us, window.n),
                Window.mean(@floatFromInt(window.patched_sum), window.n),
                t_tree.ms,
                t_flat.ms,
                mismatches,
            });
            window = .{};
        }
    }

    // Switching to a state on another branch and back: cost follows the number of differences.
    {
        const other = ring[ring_pos] orelse first;
        const there = try validatorsRef(other.state);
        const here = try validatorsRef(head.state);
        var t = time.start(io);
        var cache = try flat.syncGlobal(allocator, &pool, there.root, there.depth, there.len);
        const away_ms = ms(io, t);
        const away_patched = cache.last_patched;
        t = time.start(io);
        cache = try flat.syncGlobal(allocator, &pool, here.root, here.depth, here.len);
        std.debug.print("switch to state {} blocks back: {d:.3} ms ({} patched), and back: {d:.3} ms ({} patched)\n", .{
            ring_size - 1, away_ms, away_patched, ms(io, t), cache.last_patched,
        });
    }

    // A state loaded from bytes shares no nodes with the head, so everything is patched.
    {
        var loaded = try AnyBeaconState.deserialize(allocator, &pool, .fulu, state_bytes);
        defer loaded.deinit();
        const there = try validatorsRef(&loaded);
        const here = try validatorsRef(head.state);
        var t = time.start(io);
        var cache = try flat.syncGlobal(allocator, &pool, there.root, there.depth, there.len);
        const away_ms = ms(io, t);
        const away_patched = cache.last_patched;
        t = time.start(io);
        cache = try flat.syncGlobal(allocator, &pool, here.root, here.depth, here.len);
        std.debug.print("switch to a state loaded from bytes: {d:.1} ms ({} patched), and back to the scattered head: {d:.1} ms ({} patched)\n", .{
            away_ms, away_patched, ms(io, t), cache.last_patched,
        });
    }

    // Full refill on the scattered head.
    {
        flat.invalidateGlobal();
        const here = try validatorsRef(head.state);
        const t = time.start(io);
        const cache = try flat.syncGlobal(allocator, &pool, here.root, here.depth, here.len);
        std.debug.print("cold fill on the scattered head: {d:.1} ms ({} patched)\n", .{ ms(io, t), cache.last_patched });
    }
}
