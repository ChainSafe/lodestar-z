//! Reproduction for ChainSafe/lodestar-z#703: `before_process_epoch` drifts up with node uptime.
//!
//! Replays the production access pattern against a real state and times
//! `EpochTransitionCache.init` (the `before_process_epoch` metric) as "blocks" go by:
//!   per block : clone(transfer_cache) -> withdrawals-sweep style `validators.get()` on
//!               MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP consecutive validators -> a few hundred
//!               balance bumps -> participation flag writes -> commit; old states are released
//!               once the ring is full (mimics the block state cache).
//!   per epoch : rewrite all balances via setBalances (process_rewards_and_penalties).
//!
//! Env:
//!   LOCALITY_STATE=<path to fulu state ssz>   (required)
//!   LOCALITY_EPOCHS=<n>                        default 200
//!   LOCALITY_MEASURE_EVERY=<n>                 default 10
//!   LOCALITY_RING=<n>                          default 64 (states kept alive)
//!   LOCALITY_READONLY=1                        use validators.getReadonly() in the sweep (control)
//!   LOCALITY_NO_SWEEP=1                        skip the sweep entirely (control)
//!   LOCALITY_REAL_SWEEP=1                      run the real getExpectedWithdrawals sweep per block
//!                                              (early-exits at MAX_WITHDRAWALS_PER_PAYLOAD like production)
//!
//! Run with: LOCALITY_STATE=... zig build run:bench_locality_decay -Doptimize=ReleaseFast

const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("state_transition");
const time = @import("time");
const config = @import("config");
const fork_types = @import("fork_types");
const types = @import("consensus_types");

const AnyBeaconState = fork_types.AnyBeaconState;
const CachedBeaconState = state_transition.CachedBeaconState;
const EpochTransitionCache = state_transition.EpochTransitionCache;
const preset = state_transition.preset;
const Withdrawals = types.capella.Withdrawals.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

const MAX_RING = 256;

fn envUsize(name: [*:0]const u8, default: usize) !usize {
    const raw = std.c.getenv(name) orelse return default;
    return try std.fmt.parseInt(usize, std.mem.span(raw), 10);
}

fn envFlag(name: [*:0]const u8) bool {
    const raw = std.c.getenv(name) orelse return false;
    return std.mem.eql(u8, std.mem.span(raw), "1");
}

fn ms(io: std.Io, from: std.Io.Timestamp) f64 {
    return @as(f64, @floatFromInt(time.since(io, from).nanoseconds)) / std.time.ns_per_ms;
}

const flat_chunk_len = 4096;
const FAR_FUTURE_EPOCH: u64 = std.math.maxInt(u64);

/// Prototype of an index-addressed cache of the validator fields EpochTransitionCache.init reads.
const FlatChunk = struct {
    activation_eligibility_epoch: [flat_chunk_len]u64,
    activation_epoch: [flat_chunk_len]u64,
    exit_epoch: [flat_chunk_len]u64,
    withdrawable_epoch: [flat_chunk_len]u64,
    /// bit 0 = slashed, bit 1 = compounding withdrawal credentials
    flags: [flat_chunk_len]u8,
};

/// The per-validator inputs of EpochTransitionCache.init's validator loop, whatever their source.
const Fields = struct {
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
    effective_balance: u64,
    slashed: bool,
    compounding: bool,

    inline fn fromValidator(v: *const types.phase0.Validator.Type) Fields {
        return .{
            .activation_eligibility_epoch = v.activation_eligibility_epoch,
            .activation_epoch = v.activation_epoch,
            .exit_epoch = v.exit_epoch,
            .withdrawable_epoch = v.withdrawable_epoch,
            .effective_balance = v.effective_balance,
            .slashed = v.slashed,
            .compounding = v.withdrawal_credentials[0] == 2,
        };
    }
};

const PassParams = struct {
    prev_epoch: u64,
    current_epoch: u64,
    slashings_epoch: u64,
    ejection_balance: u64,
    increments: []const u16,
};

/// Outputs shaped like ReusedEpochTransitionCache so every variant does the same writes.
const PassOut = struct {
    flags: []u8,
    is_active_prev: []bool,
    is_active_curr: []bool,
    is_active_next: []bool,
    compounding: []bool,
    next_shuffling_indices: []u64,
    next_shuffling_len: usize = 0,
    total_active_stake: u64 = 0,
    to_slash: usize = 0,
    eligible_for_queue: usize = 0,
    eligible_for_activation: usize = 0,
    to_eject: usize = 0,

    fn init(allocator: std.mem.Allocator, count: usize) !PassOut {
        return .{
            .flags = try allocator.alloc(u8, count),
            .is_active_prev = try allocator.alloc(bool, count),
            .is_active_curr = try allocator.alloc(bool, count),
            .is_active_next = try allocator.alloc(bool, count),
            .compounding = try allocator.alloc(bool, count),
            .next_shuffling_indices = try allocator.alloc(u64, count),
        };
    }

    fn deinit(self: *PassOut, allocator: std.mem.Allocator) void {
        allocator.free(self.flags);
        allocator.free(self.is_active_prev);
        allocator.free(self.is_active_curr);
        allocator.free(self.is_active_next);
        allocator.free(self.compounding);
        allocator.free(self.next_shuffling_indices);
    }

    fn reset(self: *PassOut) void {
        @memset(self.is_active_prev, true);
        @memset(self.is_active_curr, true);
        @memset(self.is_active_next, true);
        self.next_shuffling_len = 0;
        self.total_active_stake = 0;
        self.to_slash = 0;
        self.eligible_for_queue = 0;
        self.eligible_for_activation = 0;
        self.to_eject = 0;
    }

    fn checksum(self: *const PassOut) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(self.flags);
        h.update(std.mem.sliceAsBytes(self.is_active_prev));
        h.update(std.mem.sliceAsBytes(self.is_active_curr));
        h.update(std.mem.sliceAsBytes(self.is_active_next));
        h.update(std.mem.sliceAsBytes(self.compounding));
        h.update(std.mem.sliceAsBytes(self.next_shuffling_indices[0..self.next_shuffling_len]));
        h.update(std.mem.asBytes(&self.total_active_stake));
        h.update(std.mem.asBytes(&self.to_slash));
        h.update(std.mem.asBytes(&self.eligible_for_queue));
        h.update(std.mem.asBytes(&self.eligible_for_activation));
        h.update(std.mem.asBytes(&self.to_eject));
        return h.final();
    }
};

/// Mirrors the body of the validator loop in EpochTransitionCache.init.
inline fn visit(out: *PassOut, p: PassParams, i: usize, v: Fields) void {
    var flag: u8 = 0;
    if (v.slashed) {
        if (p.slashings_epoch == v.withdrawable_epoch) out.to_slash += 1;
    } else {
        flag |= 1 << 6;
    }

    const next_epoch = p.current_epoch + 1;
    const next_epoch_2 = p.current_epoch + 2;
    const is_active_prev = v.activation_epoch <= p.prev_epoch and p.prev_epoch < v.exit_epoch;
    const is_active_curr = v.activation_epoch <= p.current_epoch and p.current_epoch < v.exit_epoch;
    const is_active_next = v.activation_epoch <= next_epoch and next_epoch < v.exit_epoch;
    const is_active_next_2 = v.activation_epoch <= next_epoch_2 and next_epoch_2 < v.exit_epoch;

    if (!is_active_prev) out.is_active_prev[i] = false;
    if (is_active_prev or (v.slashed and p.prev_epoch + 1 < v.withdrawable_epoch)) flag |= 1 << 7;
    out.flags[i] = flag;
    out.compounding[i] = v.compounding;

    if (is_active_curr) {
        out.total_active_stake += p.increments[i];
    } else {
        out.is_active_curr[i] = false;
    }

    if (v.activation_eligibility_epoch == FAR_FUTURE_EPOCH and v.effective_balance >= preset.MIN_ACTIVATION_BALANCE) {
        out.eligible_for_queue += 1;
    } else if (v.activation_epoch == FAR_FUTURE_EPOCH and v.activation_eligibility_epoch <= p.current_epoch) {
        out.eligible_for_activation += 1;
    } else if (is_active_curr and v.exit_epoch == FAR_FUTURE_EPOCH and v.effective_balance <= p.ejection_balance) {
        out.to_eject += 1;
    }

    if (!is_active_next) out.is_active_next[i] = false;
    if (is_active_next_2) {
        out.next_shuffling_indices[out.next_shuffling_len] = i;
        out.next_shuffling_len += 1;
    }
}

const Measurement = struct {
    init_ms: f64,
    pass_tree_ms: f64,
    pass_leaf_ms: f64,
    pass_flat_ms: f64,
    leaf_build_ms: f64,
    flat_build_ms: f64,
    flat_chunk_copy_us: f64,
    leaf_mem_mb: f64,
    flat_mem_mb: f64,
};

/// Times EpochTransitionCache.init as shipped, then the same validator pass fed from three
/// sources: the tree iterator (today), a flat array of leaf node ids, and a chunked flat cache.
fn measure(
    allocator: std.mem.Allocator,
    io: std.Io,
    beacon_config: *const config.BeaconConfig,
    head: *CachedBeaconState,
    pool: *Node.Pool,
    rounds: usize,
) !Measurement {
    var m: Measurement = .{
        .init_ms = std.math.inf(f64),
        .pass_tree_ms = std.math.inf(f64),
        .pass_leaf_ms = std.math.inf(f64),
        .pass_flat_ms = std.math.inf(f64),
        .leaf_build_ms = std.math.inf(f64),
        .flat_build_ms = std.math.inf(f64),
        .flat_chunk_copy_us = std.math.inf(f64),
        .leaf_mem_mb = 0,
        .flat_mem_mb = 0,
    };

    var validators = try head.state.validators();
    try validators.commit();
    const count = try validators.length();
    const mb = 1024.0 * 1024.0;

    var out = try PassOut.init(allocator, count);
    defer out.deinit(allocator);

    const ids = try allocator.alloc(Node.Id, count);
    defer allocator.free(ids);
    m.leaf_mem_mb = @as(f64, @floatFromInt(count * @sizeOf(Node.Id))) / mb;

    const n_chunks = (count + flat_chunk_len - 1) / flat_chunk_len;
    const chunks = try allocator.alloc(*FlatChunk, n_chunks);
    defer allocator.free(chunks);
    for (chunks) |*slot| slot.* = try allocator.create(FlatChunk);
    defer for (chunks) |c| allocator.destroy(c);
    m.flat_mem_mb = @as(f64, @floatFromInt(n_chunks * @sizeOf(FlatChunk))) / mb;

    for (0..rounds) |_| {
        {
            const t = time.start(io);
            var cache = try EpochTransitionCache.init(allocator, io, beacon_config, head.epoch_cache, head.state);
            const elapsed = ms(io, t);
            cache.deinit();
            m.init_ms = @min(m.init_ms, elapsed);
        }

        // init() swaps in a fresh effective-balance-increments array, so read it afterwards.
        const params: PassParams = .{
            .prev_epoch = head.epoch_cache.getPreviousShuffling().epoch,
            .current_epoch = head.epoch_cache.epoch,
            .slashings_epoch = head.epoch_cache.epoch + @divFloor(preset.EPOCHS_PER_SLASHINGS_VECTOR, 2),
            .ejection_balance = beacon_config.chain.EJECTION_BALANCE,
            .increments = head.epoch_cache.getEffectiveBalanceIncrements().items,
        };

        // Cold-state cost of each cache: one tree walk to fill it.
        {
            const t = time.start(io);
            var it = validators.iteratorReadonly(0);
            for (ids) |*id| id.* = try it.depth_iterator.next();
            m.leaf_build_ms = @min(m.leaf_build_ms, ms(io, t));
        }
        {
            const t = time.start(io);
            var it = validators.iteratorReadonly(0);
            for (chunks, 0..) |c, ci| {
                const start = ci * flat_chunk_len;
                const end = @min(count, start + flat_chunk_len);
                for (0..end - start) |j| {
                    const v = try it.nextValuePtr();
                    c.activation_eligibility_epoch[j] = v.activation_eligibility_epoch;
                    c.activation_epoch[j] = v.activation_epoch;
                    c.exit_epoch[j] = v.exit_epoch;
                    c.withdrawable_epoch[j] = v.withdrawable_epoch;
                    c.flags[j] = @as(u8, @intFromBool(v.slashed)) | (@as(u8, @intFromBool(v.withdrawal_credentials[0] == 2)) << 1);
                }
            }
            m.flat_build_ms = @min(m.flat_build_ms, ms(io, t));
        }

        out.reset();
        {
            const t = time.start(io);
            var it = validators.iteratorReadonly(0);
            for (0..count) |i| visit(&out, params, i, Fields.fromValidator(try it.nextValuePtr()));
            m.pass_tree_ms = @min(m.pass_tree_ms, ms(io, t));
        }
        const expected = out.checksum();

        out.reset();
        {
            const t = time.start(io);
            for (ids, 0..) |id, i| {
                visit(&out, params, i, Fields.fromValidator(try types.phase0.Validator.tree.getValuePtr(id, pool)));
            }
            m.pass_leaf_ms = @min(m.pass_leaf_ms, ms(io, t));
        }
        if (out.checksum() != expected) return error.LeafPassMismatch;

        out.reset();
        {
            const t = time.start(io);
            for (chunks, 0..) |c, ci| {
                const start = ci * flat_chunk_len;
                const end = @min(count, start + flat_chunk_len);
                for (0..end - start) |j| {
                    const i = start + j;
                    visit(&out, params, i, .{
                        .activation_eligibility_epoch = c.activation_eligibility_epoch[j],
                        .activation_epoch = c.activation_epoch[j],
                        .exit_epoch = c.exit_epoch[j],
                        .withdrawable_epoch = c.withdrawable_epoch[j],
                        .effective_balance = @as(u64, params.increments[i]) * preset.EFFECTIVE_BALANCE_INCREMENT,
                        .slashed = (c.flags[j] & 1) != 0,
                        .compounding = (c.flags[j] & 2) != 0,
                    });
                }
            }
            m.pass_flat_ms = @min(m.pass_flat_ms, ms(io, t));
        }
        if (out.checksum() != expected) {
            var shown: usize = 0;
            for (ids, 0..) |id, i| {
                const v = try types.phase0.Validator.tree.getValuePtr(id, pool);
                const c = chunks[i / flat_chunk_len];
                const j = i % flat_chunk_len;
                const flat_eb = @as(u64, params.increments[i]) * preset.EFFECTIVE_BALANCE_INCREMENT;
                if (v.effective_balance != flat_eb or v.activation_epoch != c.activation_epoch[j] or v.exit_epoch != c.exit_epoch[j] or
                    v.withdrawable_epoch != c.withdrawable_epoch[j] or v.activation_eligibility_epoch != c.activation_eligibility_epoch[j])
                {
                    std.debug.print("mismatch i={} tree_eb={} flat_eb={} act={}/{} exit={}/{}\n", .{ i, v.effective_balance, flat_eb, v.activation_epoch, c.activation_epoch[j], v.exit_epoch, c.exit_epoch[j] });
                    shown += 1;
                    if (shown >= 5) break;
                }
            }
            return error.FlatPassMismatch;
        }

        // Copy-on-write cost of one validator write in the flat cache.
        {
            const writes = 2000;
            var prng = std.Random.DefaultPrng.init(7);
            const t = time.start(io);
            for (0..writes) |_| {
                const ci = prng.random().uintLessThan(usize, n_chunks);
                const fresh = try allocator.create(FlatChunk);
                fresh.* = chunks[ci].*;
                allocator.destroy(chunks[ci]);
                chunks[ci] = fresh;
            }
            m.flat_chunk_copy_us = @min(m.flat_chunk_copy_us, ms(io, t) * 1000.0 / writes);
        }
    }
    return m;
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    const state_path = std.mem.span(std.c.getenv("LOCALITY_STATE") orelse {
        std.debug.print("LOCALITY_STATE is required\n", .{});
        return error.MissingStatePath;
    });
    const epochs = try envUsize("LOCALITY_EPOCHS", 200);
    const measure_every = try envUsize("LOCALITY_MEASURE_EVERY", 10);
    const ring_size = @min(MAX_RING, try envUsize("LOCALITY_RING", 64));
    const readonly_sweep = envFlag("LOCALITY_READONLY");
    const no_sweep = envFlag("LOCALITY_NO_SWEEP");
    const real_sweep = envFlag("LOCALITY_REAL_SWEEP");
    const validator_writes = try envUsize("LOCALITY_VALIDATOR_WRITES", 0);
    const sweep: usize = preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP;
    const block_balance_bumps: usize = 512;
    const block_participation_writes: usize = 8192;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 10_000_000 });
    defer pool.deinit();

    const state_bytes = try std.Io.Dir.cwd().readFileAlloc(io, state_path, allocator, .unlimited);
    defer allocator.free(state_bytes);

    const state = try allocator.create(AnyBeaconState);
    state.* = try AnyBeaconState.deserialize(allocator, &pool, .fulu, state_bytes);

    const validator_count = try state.validatorsCount();
    std.debug.print(
        "state slot={} validators={} sweep={} ring={} readonly_sweep={} no_sweep={} real_sweep={} nodes_in_use={}\n",
        .{ try state.slot(), validator_count, sweep, ring_size, readonly_sweep, no_sweep, real_sweep, pool.getNodesInUse() },
    );

    var beacon_config: config.BeaconConfig = config.hoodi.config;

    var pubkey_cache = try state_transition.PubkeyCache.initCapacity(
        allocator,
        io,
        validator_count + preset.MAX_PENDING_DEPOSITS_PER_EPOCH,
    );
    defer pubkey_cache.deinit();

    const immutable_data = state_transition.EpochCacheImmutableData{
        .config = &beacon_config,
        .pubkey_cache = &pubkey_cache,
    };

    const t_cache = time.start(io);
    const first = try CachedBeaconState.createCachedBeaconState(allocator, io, state, immutable_data, .{
        .skip_sync_committee_cache = false,
        .skip_sync_pubkeys = false,
    });
    std.debug.print("cached state ready in {d:.0} ms\n", .{ms(io, t_cache)});
    defer state_transition.deinitReusedEpochTransitionCache(io);

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
    var next_sweep_index: usize = 0;
    var sampled_total: usize = 0;
    var blocks_total: usize = 0;

    std.debug.print("validator_writes_per_epoch={}\n", .{validator_writes});
    std.debug.print("epoch,init_ms,pass_tree_ms,pass_leaf_ms,pass_flat_ms,leaf_build_ms,flat_build_ms,chunk_copy_us,leaf_mem_mb,flat_mem_mb\n", .{});
    {
        const m = try measure(allocator, io, &beacon_config, head, &pool, 3);
        std.debug.print("{},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1}\n", .{ 0, m.init_ms, m.pass_tree_ms, m.pass_leaf_ms, m.pass_flat_ms, m.leaf_build_ms, m.flat_build_ms, m.flat_chunk_copy_us, m.leaf_mem_mb, m.flat_mem_mb });
    }

    for (0..epochs) |epoch| {
        for (0..preset.SLOTS_PER_EPOCH) |_| {
            const next = try head.clone(allocator, .{ .transfer_cache = true });

            if (real_sweep) {
                // The production path: getExpectedWithdrawals reads validators through the list
                // view, then processWithdrawals advances next_withdrawal_validator_index.
                const fork_state = next.state.castToFork(.fulu);
                var withdrawals_buf: [preset.MAX_WITHDRAWALS_PER_PAYLOAD]types.capella.Withdrawal.Type = undefined;
                var result = state_transition.WithdrawalsResult{ .withdrawals = Withdrawals.initBuffer(&withdrawals_buf) };
                var withdrawal_balances = std.AutoHashMap(ValidatorIndex, usize).init(allocator);
                defer withdrawal_balances.deinit();
                try state_transition.getExpectedWithdrawals(.fulu, next.epoch_cache, fork_state, &result, &withdrawal_balances);
                sampled_total += result.sampled_validators;
                blocks_total += 1;

                const items = result.withdrawals.items;
                var balances = try next.state.balances();
                for (items) |w| {
                    const bal = try balances.get(w.validator_index);
                    try balances.set(w.validator_index, bal -| w.amount);
                }
                const cur = try next.state.nextWithdrawalValidatorIndex();
                const nxt = if (items.len == preset.MAX_WITHDRAWALS_PER_PAYLOAD)
                    (items[items.len - 1].validator_index + 1) % validator_count
                else
                    (cur + sweep) % validator_count;
                try next.state.setNextWithdrawalValidatorIndex(nxt);
            } else if (!no_sweep) {
                var validators = try next.state.validators();
                for (0..sweep) |n| {
                    const idx = (next_sweep_index + n) % validator_count;
                    var v = if (readonly_sweep) try validators.getReadonly(idx) else try validators.get(idx);
                    const withdrawable_epoch = try v.get("withdrawable_epoch");
                    const effective_balance = try v.get("effective_balance");
                    const wc = try v.getFieldRoot("withdrawal_credentials");
                    std.mem.doNotOptimizeAway(withdrawable_epoch);
                    std.mem.doNotOptimizeAway(effective_balance);
                    std.mem.doNotOptimizeAway(wc);
                }
                next_sweep_index = (next_sweep_index + sweep) % validator_count;
            }

            {
                var balances = try next.state.balances();
                for (0..block_balance_bumps) |_| {
                    const i = rng.uintLessThan(usize, validator_count);
                    const b = try balances.get(i);
                    try balances.set(i, b + 1);
                }
            }
            {
                var participation = try next.state.currentEpochParticipation();
                for (0..block_participation_writes) |_| {
                    const i = rng.uintLessThan(usize, validator_count);
                    // Rewrite the existing value: churns the chunk nodes like an attestation
                    // would without changing the target-balance totals the epoch cache checks.
                    const flags = try participation.get(i);
                    try participation.set(i, flags);
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

        // Epoch transition: rewrite every balance, as processRewardsAndPenalties does.
        {
            const bals = try head.state.balancesSlice(allocator);
            for (bals) |*b| b.* += 1;
            var list: std.ArrayList(u64) = .fromOwnedSlice(bals);
            defer list.deinit(allocator);
            try head.state.setBalances(&list);

            // Real validator writes: rewriting a field relocates the leaf and its path.
            if (validator_writes > 0) {
                var validators = try head.state.validators();
                for (0..validator_writes) |_| {
                    const i = rng.uintLessThan(usize, validator_count);
                    var v = try validators.get(i);
                    try v.set("effective_balance", try v.get("effective_balance"));
                }
            }
            try head.state.commit();
        }

        if ((epoch + 1) % measure_every == 0) {
            const m = try measure(allocator, io, &beacon_config, head, &pool, 3);
            std.debug.print("{},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1},{d:.1}\n", .{ epoch + 1, m.init_ms, m.pass_tree_ms, m.pass_leaf_ms, m.pass_flat_ms, m.leaf_build_ms, m.flat_build_ms, m.flat_chunk_copy_us, m.leaf_mem_mb, m.flat_mem_mb });
        }
    }
    if (blocks_total > 0) {
        std.debug.print("real sweep: avg sampled validators per block = {d:.1}\n", .{@as(f64, @floatFromInt(sampled_total)) / @as(f64, @floatFromInt(blocks_total))});
    }
}
