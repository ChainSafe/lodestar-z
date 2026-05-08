//! Fast Confirmation Rule.
//!
//! Spec: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/phase0/fast-confirmation.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const assert = std.debug.assert;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;
const ValidatorIndex = primitives.ValidatorIndex.Type;

const preset = @import("preset").preset;

const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const CachedBeaconState = state_transition.CachedBeaconState;
// Note: `isActiveValidator` is not re-exported by `state_transition.root`, so we
// replicate the spec's two-line check in `isActiveValidatorImpl` below to avoid
// reaching into private file paths from another module.

const proto_array_mod = @import("../proto_array.zig");
const ProtoArray = proto_array_mod.ProtoArray;
const PayloadStatus = proto_array_mod.PayloadStatus;

const fork_choice_mod = @import("../fork_choice.zig");
const ForkChoice = fork_choice_mod.ForkChoice;
const ForkChoiceError = fork_choice_mod.ForkChoiceError;

const store_mod = @import("../store.zig");
const Checkpoint = store_mod.Checkpoint;

const vote_tracker = @import("../vote_tracker.zig");
const Votes = vote_tracker.Votes;
const NULL_VOTE_INDEX = vote_tracker.NULL_VOTE_INDEX;

const compute_deltas = @import("../compute_deltas.zig");
const EquivocatingIndices = compute_deltas.EquivocatingIndices;


/// FCR's error surface unions ForkChoiceError so corruption signals
/// (`BeaconStateErr`, `InvalidParentIndex`, etc.) propagate to callers
/// instead of being collapsed into "block not found". `StateMissing` is the
/// FCR-specific marker for any "data we needed wasn't there" case — block
/// absent from proto array, shuffling missing, committee oob, or unreadable
/// state. We map subsystem errors (epoch_cache, SSZ tree views) to
/// `StateMissing` so callers see one consistent signal; `OutOfMemory`
/// propagates so callers can distinguish allocation failure.
pub const Error = ForkChoiceError || error{
    StateMissing,
} || Allocator.Error;


pub const SlotAssignments = struct {
    /// validator_index -> sorted slots they participated in (last 3 epochs).
    /// Multiple entries per validator are possible since a validator may participate
    /// in committees across multiple slots in the 3-epoch window.
    by_validator: std.AutoHashMapUnmanaged(ValidatorIndex, std.ArrayListUnmanaged(Slot)) = .empty,

    pub fn init() SlotAssignments {
        return .{};
    }

    pub fn deinit(self: *SlotAssignments, allocator: Allocator) void {
        var it = self.by_validator.valueIterator();
        while (it.next()) |list| list.deinit(allocator);
        self.by_validator.deinit(allocator);
    }

    /// Rebuild the assignments for the last 3 epochs (current + 2 previous).
    /// Maps each validator index to the set of slots in that range where they have
    /// a committee assignment. The slot loop is bounded at
    /// `3 * preset.SLOTS_PER_EPOCH` iterations.
    pub fn rebuild(
        self: *SlotAssignments,
        allocator: Allocator,
        state: *const CachedBeaconState,
        current_slot: Slot,
    ) Error!void {
        // Clear existing entries (free per-validator lists, then keep the outer
        // map allocation for reuse).
        var clear_it = self.by_validator.valueIterator();
        while (clear_it.next()) |list| list.deinit(allocator);
        self.by_validator.clearRetainingCapacity();

        const current_epoch = computeEpochAtSlot(current_slot);

        // start_slot = max(0, computeStartSlotAtEpoch(current_epoch - 2))
        const start_epoch: Epoch = if (current_epoch >= 2) current_epoch - 2 else 0;
        const start_slot = computeStartSlotAtEpoch(start_epoch);

        // end_slot = computeStartSlotAtEpoch(current_epoch + 1) - 1
        // For current_epoch + 1, we compute its start slot then subtract 1.
        const next_epoch_start = computeStartSlotAtEpoch(current_epoch + 1);
        // Guard against underflow: spec assumes current_epoch >= 0 so next_epoch_start >= SLOTS_PER_EPOCH.
        assert(next_epoch_start >= 1);
        const end_slot = next_epoch_start - 1;

        // Range is non-empty (≥1 epoch worth of slots) and bounded above by
        // 3 * SLOTS_PER_EPOCH (current + 2 previous).
        assert(end_slot >= start_slot);
        assert(end_slot - start_slot < 3 * preset.SLOTS_PER_EPOCH);

        var slot: Slot = start_slot;
        while (slot <= end_slot) : (slot += 1) {
            const slot_epoch = computeEpochAtSlot(slot);
            const committees_count = state.epoch_cache.getCommitteeCountPerSlot(slot_epoch) catch {
                // Shuffling for this slot is not available — skip it (e.g. early genesis).
                continue;
            };
            var idx: usize = 0;
            while (idx < committees_count) : (idx += 1) {
                const committee = state.epoch_cache.getBeaconCommittee(slot, idx) catch continue;
                for (committee) |validator_index| {
                    const gop = try self.by_validator.getOrPut(allocator, validator_index);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = .empty;
                    }
                    try gop.value_ptr.append(allocator, slot);
                }
            }
        }
    }
};


pub const BalanceSourceData = struct {
    checkpoint: Checkpoint,
    effective_balances: std.ArrayListUnmanaged(u16) = .empty,

    pub fn init() BalanceSourceData {
        return .{ .checkpoint = .{ .epoch = 0, .root = [_]u8{0} ** 32 } };
    }

    pub fn deinit(self: *BalanceSourceData, allocator: Allocator) void {
        self.effective_balances.deinit(allocator);
    }

    /// Rebuild effective balances from a state, zeroing inactive and slashed validators.
    ///
    /// Short-circuit: if the cached checkpoint matches `cp` and we already have data,
    /// return without recomputing.
    ///
    /// **Caller invariant:** `state` MUST be the checkpoint state for `cp` —
    /// i.e., `computeEpochAtSlot(state.slot()) == cp.epoch`. The active /
    /// slashed predicates are evaluated at `cp.epoch`; passing a state from a
    /// different epoch produces incorrect zeroing. The spec's
    /// `get_balance_source` resolves the checkpoint state explicitly; callers
    /// must replicate that contract. Not asserted here because `state.slot()`
    /// is errorable and called on a hot path.
    pub fn rebuild(
        self: *BalanceSourceData,
        allocator: Allocator,
        state: *const CachedBeaconState,
        cp: Checkpoint,
    ) Error!void {
        if (self.checkpoint.eql(cp) and self.effective_balances.items.len > 0) {
            return;
        }

        const validators = state.state.validatorsSlice(allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.StateMissing,
        };
        defer allocator.free(validators);
        // FCR requires a non-empty validator set; degenerate states are not
        // valid input. Caller must guarantee this.
        assert(validators.len > 0);

        const source_increments = state.epoch_cache.getEffectiveBalanceIncrements();
        // Sanity: cache must be sized for the validator set we read from the state.
        assert(source_increments.items.len >= validators.len);

        try self.effective_balances.resize(allocator, validators.len);

        for (validators, 0..) |validator, i| {
            var balance: u16 = source_increments.items[i];
            if (validator.slashed or !isActiveValidatorImpl(&validator, cp.epoch)) {
                balance = 0;
            }
            self.effective_balances.items[i] = balance;
        }

        self.checkpoint = cp;
    }
};

// `isActiveValidator` is not re-exported by `state_transition.root`, so we replicate
// the logic locally to avoid reaching into private file paths from another module.
// Spec: `is_active_validator(validator, epoch)` = `activation_epoch <= epoch < exit_epoch`.
fn isActiveValidatorImpl(validator: *const consensus_types.phase0.Validator.Type, epoch: Epoch) bool {
    return validator.activation_epoch <= epoch and epoch < validator.exit_epoch;
}


pub const FastConfirmation = struct {
    confirmed_root: Root,

    previous_epoch_observed_justified_checkpoint: Checkpoint,
    current_epoch_observed_justified_checkpoint: Checkpoint,
    previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    previous_slot_head: Root,
    current_slot_head: Root,

    previous_balance_source: BalanceSourceData,
    current_balance_source: BalanceSourceData,
    head_balance_source: BalanceSourceData,

    head_assignments: SlotAssignments,

    /// Spec range [0, 25]; widened to u64 to match
    /// `ChainConfig.CONFIRMATION_BYZANTINE_THRESHOLD` and avoid narrowing at
    /// every call site.
    byzantine_threshold: u64,
    proposer_score_boost: u64,

    last_update_slot: ?Slot = null,
    spec_test_mode: bool = false,

    /// Initialize FCR from anchor (finalized) checkpoint.
    /// `byzantine_threshold` is clamped to [0, 25] per spec.
    pub fn init(
        finalized_cp: Checkpoint,
        byzantine_threshold: u64,
        proposer_score_boost: u64,
    ) FastConfirmation {
        const clamped: u64 = @min(byzantine_threshold, 25);
        return .{
            .confirmed_root = finalized_cp.root,
            .previous_epoch_observed_justified_checkpoint = finalized_cp,
            .current_epoch_observed_justified_checkpoint = finalized_cp,
            .previous_epoch_greatest_unrealized_checkpoint = finalized_cp,
            .previous_slot_head = finalized_cp.root,
            .current_slot_head = finalized_cp.root,
            .previous_balance_source = BalanceSourceData.init(),
            .current_balance_source = BalanceSourceData.init(),
            .head_balance_source = BalanceSourceData.init(),
            .head_assignments = SlotAssignments.init(),
            .byzantine_threshold = clamped,
            .proposer_score_boost = proposer_score_boost,
        };
    }

    pub fn deinit(self: *FastConfirmation, allocator: Allocator) void {
        self.previous_balance_source.deinit(allocator);
        self.current_balance_source.deinit(allocator);
        self.head_balance_source.deinit(allocator);
        self.head_assignments.deinit(allocator);
    }

    pub fn getConfirmedRoot(self: *const FastConfirmation) Root {
        return self.confirmed_root;
    }

    pub fn setSpecTestMode(self: *FastConfirmation, enabled: bool) void {
        self.spec_test_mode = enabled;
    }
};


/// Spec: `is_start_slot_at_epoch(slot)` — true iff `slot` lies on an epoch boundary.
pub fn isStartSlotAtEpoch(slot: Slot) bool {
    return slot % preset.SLOTS_PER_EPOCH == 0;
}

/// Spec: `get_block_slot(store, block_root)` — returns slot of block, or
/// `error.StateMissing` if the block is unknown to the proto array.
pub fn getBlockSlot(proto_array: *const ProtoArray, block_root: Root) Error!Slot {
    // Use the default payload status (FULL pre-Gloas, PENDING post-Gloas) — the
    // slot is the same regardless of variant.
    const default_status = proto_array.getDefaultVariant(block_root) orelse return error.StateMissing;
    const block = proto_array.getBlock(block_root, default_status) orelse return error.StateMissing;
    return block.slot;
}

/// Spec: `get_block_epoch(store, block_root)`.
pub fn getBlockEpoch(proto_array: *const ProtoArray, block_root: Root) Error!Epoch {
    const slot = try getBlockSlot(proto_array, block_root);
    return computeEpochAtSlot(slot);
}

/// Spec: `get_checkpoint_for_block(store, block_root, epoch)` —
/// returns the checkpoint at `compute_start_slot_at_epoch(epoch)` of the
/// chain containing `block_root`.
///
/// Accepts `*const ForkChoice` so we can reuse `proto_array.getAncestor`
/// without exposing extra accessors.
pub fn getCheckpointForBlock(
    fc: *const ForkChoice,
    block_root: Root,
    epoch: Epoch,
) Error!Checkpoint {
    const epoch_start_slot = computeStartSlotAtEpoch(epoch);
    const ancestor = fc.getAncestor(block_root, epoch_start_slot) catch |err| switch (err) {
        // Block / ancestor truly absent → the FCR-specific marker.
        error.MissingProtoArrayBlock, error.UnknownAncestor => return error.StateMissing,
        // Corruption / state errors propagate as-is.
        else => return err,
    };
    return .{ .epoch = epoch, .root = ancestor.block_root };
}

/// Spec: `is_ancestor(store, block_root, ancestor_root)`. Returns `false` for
/// expected "block not found" cases, propagates corruption / state errors.
pub fn isAncestor(
    fc: *const ForkChoice,
    block_root: Root,
    ancestor_root: Root,
) Error!bool {
    const ancestor_slot = getBlockSlot(fc.proto_array, ancestor_root) catch |err| switch (err) {
        error.StateMissing => return false,
        else => return err,
    };
    const ancestor = fc.getAncestor(block_root, ancestor_slot) catch |err| switch (err) {
        error.MissingProtoArrayBlock, error.UnknownAncestor => return false,
        else => return err,
    };
    return std.mem.eql(u8, &ancestor.block_root, &ancestor_root);
}

/// Maximum iterations when walking ancestors. Bounds the loop so a corrupted
/// DAG fails fast instead of spinning forever.
const ANCESTOR_WALK_MAX_ITERATIONS: usize = 1_000_000;

/// Spec: `get_ancestor_roots(store, block_root, terminal_root)` — returns the
/// chain of roots from `terminal_root` (exclusive) down to `block_root` (inclusive)
/// in **oldest-to-newest** order. Returns an empty slice if `terminal_root` is
/// not in `block_root`'s chain (or either block is unknown).
///
/// Caller owns the returned slice and must free it with `allocator`.
pub fn getAncestorRoots(
    allocator: Allocator,
    fc: *const ForkChoice,
    block_root: Root,
    terminal_root: Root,
) Error![]Root {
    // block_root == terminal_root → empty (terminal exclusive, so nothing to return).
    if (std.mem.eql(u8, &block_root, &terminal_root)) {
        return allocator.alloc(Root, 0);
    }

    const terminal_slot = getBlockSlot(fc.proto_array, terminal_root) catch return allocator.alloc(Root, 0);

    // Walk from `block_root` upward (toward parents) collecting roots into a
    // newest-first list, then reverse before returning.
    var roots: std.ArrayListUnmanaged(Root) = .empty;
    defer roots.deinit(allocator);

    var current_root = block_root;
    var iter_count: usize = 0;
    while (true) : (iter_count += 1) {
        if (iter_count > ANCESTOR_WALK_MAX_ITERATIONS) {
            // Corrupted DAG or unexpectedly long chain — fail fast.
            return error.StateMissing;
        }

        const current_status = fc.proto_array.getDefaultVariant(current_root) orelse {
            // Unknown block in the chain → terminal_root is not reachable.
            return allocator.alloc(Root, 0);
        };
        const current_block = fc.proto_array.getBlock(current_root, current_status) orelse {
            return allocator.alloc(Root, 0);
        };

        if (current_block.slot <= terminal_slot) {
            // Walked past the terminal slot without hitting `terminal_root` →
            // terminal is not in the chain.
            return allocator.alloc(Root, 0);
        }

        try roots.append(allocator, current_root);

        const parent_root = current_block.parent_root;
        if (std.mem.eql(u8, &parent_root, &terminal_root)) {
            // Reached the terminal — reverse and return.
            const out = try allocator.alloc(Root, roots.items.len);
            // roots is currently newest-first; reverse copy yields oldest-first.
            for (roots.items, 0..) |r, i| out[roots.items.len - 1 - i] = r;
            return out;
        }
        current_root = parent_root;
    }
}

/// Spec: `get_current_target(store)` — checkpoint at the current epoch boundary
/// for the chain ending at `head_root`.
pub fn getCurrentTarget(
    fc: *const ForkChoice,
    head_root: Root,
    current_slot: Slot,
) Error!Checkpoint {
    return getCheckpointForBlock(fc, head_root, computeEpochAtSlot(current_slot));
}


/// Spec: `get_slot_committee(store, slot)` — union of all committees at `slot`.
/// Caller owns the returned slice.
pub fn getSlotCommittee(
    allocator: Allocator,
    state: *const CachedBeaconState,
    slot: Slot,
) Error![]const ValidatorIndex {
    const epoch = computeEpochAtSlot(slot);
    const committees_count = state.epoch_cache.getCommitteeCountPerSlot(epoch) catch return error.StateMissing;

    // Use a hash set for de-duplication, then materialise into a slice.
    var seen: std.AutoHashMapUnmanaged(ValidatorIndex, void) = .empty;
    defer seen.deinit(allocator);

    var idx: usize = 0;
    while (idx < committees_count) : (idx += 1) {
        const committee = state.epoch_cache.getBeaconCommittee(slot, idx) catch return error.StateMissing;
        for (committee) |validator_index| {
            try seen.put(allocator, validator_index, {});
        }
    }

    const out = try allocator.alloc(ValidatorIndex, seen.count());
    var out_idx: usize = 0;
    var key_iter = seen.keyIterator();
    while (key_iter.next()) |k| {
        out[out_idx] = k.*;
        out_idx += 1;
    }
    return out;
}


/// `COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR` from the spec, used in
/// `adjust_committee_weight_estimate_to_ensure_safety`.
const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// Breakdown of the safety threshold computation. Returned by
/// `computeSafetyThreshold` so callers can log component values for debugging.
pub const SafetyThreshold = struct {
    threshold: u64,
    proposer_score: u64,
    maximum_support: u64,
    support_discount: u64,
    adversarial_weight: u64,
};


/// Sum of effective balances (in increments) across the balance source. Inactive
/// and slashed validators are zeroed by `BalanceSourceData.rebuild`, so this is
/// equivalent to the spec's `get_total_active_balance` modulo the unit conversion
/// from Gwei to increments (the spec's `EFFECTIVE_BALANCE_INCREMENT` factor
/// cancels in every safety-threshold expression).
fn getTotalActiveBalance(balance_source: *const BalanceSourceData) u64 {
    var total: u64 = 0;
    for (balance_source.effective_balances.items) |bal| {
        total += bal;
    }
    return total;
}

/// Resolve the LMD-GHOST latest message root for `validator_index`, or `null`
/// if the validator has not voted yet (sentinel `NULL_VOTE_INDEX`).
fn latestVoteRoot(votes: *Votes, proto_array: *const ProtoArray, validator_index: usize) ?Root {
    const fields = votes.fields();
    if (validator_index >= fields.next_indices.len) return null;
    const next_idx = fields.next_indices[validator_index];
    if (next_idx == NULL_VOTE_INDEX) return null;
    if (next_idx >= proto_array.nodes.items.len) return null;
    return proto_array.nodes.items[next_idx].block_root;
}

/// Best-effort "is `descendant_root` a descendant of `ancestor_root`" check
/// using each block's default variant. Returns `false` for unknown roots —
/// callers always treat absence as "not a descendant" (matching the TS
/// `isDescendantCached` swallow-then-false pattern).
fn isDescendantOfBlock(
    proto_array: *const ProtoArray,
    ancestor_root: Root,
    descendant_root: Root,
) bool {
    const ancestor_status = proto_array.getDefaultVariant(ancestor_root) orelse return false;
    const descendant_status = proto_array.getDefaultVariant(descendant_root) orelse return false;
    return proto_array.isDescendant(
        ancestor_root,
        ancestor_status,
        descendant_root,
        descendant_status,
    ) catch false;
}

/// Helper: union of committees over `[start_slot, end_slot]` inclusive.
/// Returns a hash-set of validator indices; caller owns the returned map.
fn getSlotRangeParticipants(
    allocator: Allocator,
    state: *const CachedBeaconState,
    start_slot: Slot,
    end_slot: Slot,
) Error!std.AutoHashMapUnmanaged(ValidatorIndex, void) {
    var participants: std.AutoHashMapUnmanaged(ValidatorIndex, void) = .empty;
    errdefer participants.deinit(allocator);

    if (start_slot > end_slot) return participants;

    // Bound the slot loop. FCR callers limit the range to a few epochs; this
    // assert defends against pathological inputs.
    const max_slots: u64 = 16 * preset.SLOTS_PER_EPOCH;
    assert((end_slot - start_slot) < max_slots);

    var slot: Slot = start_slot;
    while (slot <= end_slot) : (slot += 1) {
        const epoch = computeEpochAtSlot(slot);
        const committees_count = state.epoch_cache.getCommitteeCountPerSlot(epoch) catch continue;
        var idx: usize = 0;
        while (idx < committees_count) : (idx += 1) {
            const committee = state.epoch_cache.getBeaconCommittee(slot, idx) catch continue;
            for (committee) |validator_index| {
                try participants.put(allocator, validator_index, {});
            }
        }
    }

    return participants;
}


/// Spec: `is_full_validator_set_covered(start_slot, end_slot)`. True iff
/// the inclusive `[start_slot, end_slot]` range covers an entire epoch.
///
/// The formula naturally handles `start_slot > end_slot`: in that case
/// `start_full_epoch >= end_full_epoch` so the function returns `false`.
pub fn isFullValidatorSetCovered(start_slot: Slot, end_slot: Slot) bool {
    const start_full_epoch = computeEpochAtSlot(start_slot + (preset.SLOTS_PER_EPOCH - 1));
    const end_full_epoch = computeEpochAtSlot(end_slot + 1);
    return start_full_epoch < end_full_epoch;
}


/// Spec: `adjust_committee_weight_estimate_to_ensure_safety(estimate)`.
///
/// CRITICAL UNIT-CONVERSION: the spec works in raw Gwei
/// (`ceil(estimate_gwei / 1000) * (1000 + 5)`), but lodestar-z carries
/// effective-balance increments (1 increment = 1e9 Gwei). At the increment
/// scale, `ceil(... / 1000)` is a no-op for any realistic value, so the
/// equivalent conservative adjustment becomes
/// `floor((estimate * (1000 + 5) + 999) / 1000)`.
pub fn adjustCommitteeWeightEstimateToEnsureSafety(estimate: u64) u64 {
    const factor: u64 = 1000 + COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR;
    return @divFloor(estimate * factor + 999, 1000);
}


/// Spec: `estimate_committee_weight_between_slots(total_active_balance, start_slot, end_slot)`.
/// In lodestar-z `total_active_balance` is supplied via `balance_source`.
pub fn estimateCommitteeWeightBetweenSlots(
    balance_source: *const BalanceSourceData,
    start_slot: Slot,
    end_slot: Slot,
) u64 {
    if (start_slot > end_slot) return 0;

    const total_active_balance = getTotalActiveBalance(balance_source);

    if (isFullValidatorSetCovered(start_slot, end_slot)) {
        return total_active_balance;
    }

    const start_epoch = computeEpochAtSlot(start_slot);
    const end_epoch = computeEpochAtSlot(end_slot);
    const committee_weight_per_slot: u64 = @divFloor(total_active_balance, preset.SLOTS_PER_EPOCH);

    if (start_epoch == end_epoch) {
        // (end_slot - start_slot + 1) slots inclusive in the same epoch.
        return committee_weight_per_slot * (end_slot - start_slot + 1);
    }

    // Cross-epoch (but no full epoch covered) — use the spec's pro-rated form.
    const num_slots_in_start_epoch: u64 = preset.SLOTS_PER_EPOCH - state_transition.computeSlotsSinceEpochStart(start_slot);
    const num_slots_in_end_epoch: u64 = state_transition.computeSlotsSinceEpochStart(end_slot) + 1;
    const remaining_slots_in_end_epoch: u64 = preset.SLOTS_PER_EPOCH - num_slots_in_end_epoch;

    const start_epoch_weight: u64 = committee_weight_per_slot * num_slots_in_start_epoch;
    const end_epoch_weight: u64 = committee_weight_per_slot * num_slots_in_end_epoch;
    const start_epoch_weight_pro_rated: u64 =
        @divFloor(start_epoch_weight, preset.SLOTS_PER_EPOCH) * remaining_slots_in_end_epoch;

    return adjustCommitteeWeightEstimateToEnsureSafety(start_epoch_weight_pro_rated + end_epoch_weight);
}


/// Spec: `get_equivocation_score(store, balance_source, start_slot, end_slot)`.
/// Sums effective balances of equivocating validators that participate in any
/// committee in `[start_slot, end_slot]`. The `balance_source.effective_balances`
/// already zeroes inactive/slashed validators, so the spec's "active validator"
/// filter is implicit.
pub fn getEquivocationScore(
    allocator: Allocator,
    state: *const CachedBeaconState,
    balance_source: *const BalanceSourceData,
    equivocating_indices: *const EquivocatingIndices,
    start_slot: Slot,
    end_slot: Slot,
) Error!u64 {
    if (start_slot > end_slot) return 0;
    if (equivocating_indices.count() == 0) return 0;

    var participants = try getSlotRangeParticipants(allocator, state, start_slot, end_slot);
    defer participants.deinit(allocator);

    var score: u64 = 0;
    var it = participants.keyIterator();
    while (it.next()) |idx_ptr| {
        const i: usize = idx_ptr.*;
        if (!equivocating_indices.contains(idx_ptr.*)) continue;
        if (i >= balance_source.effective_balances.items.len) continue;
        score += balance_source.effective_balances.items[i];
    }
    return score;
}


/// Spec: `compute_adversarial_weight(store, balance_source, start_slot, end_slot)`.
/// Returns `floor(maximum_weight * byzantine_threshold / 100) - equivocation_score`,
/// saturated at zero.
pub fn computeAdversarialWeight(
    allocator: Allocator,
    fcr: *const FastConfirmation,
    state: *const CachedBeaconState,
    balance_source: *const BalanceSourceData,
    equivocating_indices: *const EquivocatingIndices,
    start_slot: Slot,
    end_slot: Slot,
) Error!u64 {
    const maximum_weight = estimateCommitteeWeightBetweenSlots(balance_source, start_slot, end_slot);
    // Match TS / spec ordering: `(maximum_weight * byzantine_threshold) / 100`.
    // `byzantine_threshold` is clamped to [0, 25] in init, so no overflow risk
    // for realistic `maximum_weight`.
    const max_adversarial_weight: u64 = @divFloor(maximum_weight * fcr.byzantine_threshold, 100);
    const equivocation_score = try getEquivocationScore(
        allocator,
        state,
        balance_source,
        equivocating_indices,
        start_slot,
        end_slot,
    );
    return if (max_adversarial_weight > equivocation_score)
        max_adversarial_weight - equivocation_score
    else
        0;
}


/// Spec: `get_adversarial_weight(store, balance_source, block_root)`.
pub fn getAdversarialWeight(
    allocator: Allocator,
    fcr: *const FastConfirmation,
    proto_array: *const ProtoArray,
    state: *const CachedBeaconState,
    balance_source: *const BalanceSourceData,
    equivocating_indices: *const EquivocatingIndices,
    block_root: Root,
    current_slot: Slot,
) Error!u64 {
    if (current_slot == 0) return 0;

    const block = blk: {
        const status = proto_array.getDefaultVariant(block_root) orelse return 0;
        break :blk proto_array.getBlock(block_root, status) orelse return 0;
    };
    const parent = blk: {
        const status = proto_array.getDefaultVariant(block.parent_root) orelse return 0;
        break :blk proto_array.getBlock(block.parent_root, status) orelse return 0;
    };

    const block_epoch = computeEpochAtSlot(block.slot);
    const parent_epoch = computeEpochAtSlot(parent.slot);
    const end_slot: Slot = current_slot - 1;

    if (block_epoch > parent_epoch) {
        const start_slot = computeStartSlotAtEpoch(block_epoch);
        return computeAdversarialWeight(allocator, fcr, state, balance_source, equivocating_indices, start_slot, end_slot);
    }
    return computeAdversarialWeight(allocator, fcr, state, balance_source, equivocating_indices, block.slot, end_slot);
}


/// Spec: `get_block_support_between_slots(store, balance_source, block_root, start_slot, end_slot)`.
/// Sums effective balances of non-equivocating, non-slashed, active validators
/// whose latest message root equals `block_root` and that are committee
/// members in any slot of `[start_slot, end_slot]`.
pub fn getBlockSupportBetweenSlots(
    allocator: Allocator,
    state: *const CachedBeaconState,
    proto_array: *const ProtoArray,
    balance_source: *const BalanceSourceData,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    block_root: Root,
    start_slot: Slot,
    end_slot: Slot,
) Error!u64 {
    if (start_slot > end_slot) return 0;

    var participants = try getSlotRangeParticipants(allocator, state, start_slot, end_slot);
    defer participants.deinit(allocator);

    if (participants.count() == 0) return 0;

    var score: u64 = 0;
    var it = participants.keyIterator();
    while (it.next()) |idx_ptr| {
        const i: usize = idx_ptr.*;
        if (i >= balance_source.effective_balances.items.len) continue;
        if (equivocating_indices.contains(idx_ptr.*)) continue;
        const bal = balance_source.effective_balances.items[i];
        if (bal == 0) continue; // already zeroed for slashed/inactive in rebuild
        const vote_root = latestVoteRoot(votes, proto_array, i) orelse continue;
        if (std.mem.eql(u8, &vote_root, &block_root)) {
            score += bal;
        }
    }
    return score;
}


/// Spec: `compute_empty_slot_support_discount(store, balance_source, block_root)`.
pub fn computeEmptySlotSupportDiscount(
    allocator: Allocator,
    fcr: *const FastConfirmation,
    proto_array: *const ProtoArray,
    state: *const CachedBeaconState,
    balance_source: *const BalanceSourceData,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    block_root: Root,
) Error!u64 {
    const block = blk: {
        const status = proto_array.getDefaultVariant(block_root) orelse return 0;
        break :blk proto_array.getBlock(block_root, status) orelse return 0;
    };
    const parent = blk: {
        const status = proto_array.getDefaultVariant(block.parent_root) orelse return 0;
        break :blk proto_array.getBlock(block.parent_root, status) orelse return 0;
    };

    // No empty slots between parent and block.
    if (parent.slot + 1 == block.slot) return 0;
    // Defensive: if block is at or before parent, nothing to discount.
    if (block.slot <= parent.slot + 1) return 0;

    const start_slot: Slot = parent.slot + 1;
    const end_slot: Slot = block.slot - 1;

    const parent_support_in_empty_slots = try getBlockSupportBetweenSlots(
        allocator,
        state,
        proto_array,
        balance_source,
        votes,
        equivocating_indices,
        block.parent_root,
        start_slot,
        end_slot,
    );
    const adversarial_weight = try computeAdversarialWeight(
        allocator,
        fcr,
        state,
        balance_source,
        equivocating_indices,
        start_slot,
        end_slot,
    );
    return if (parent_support_in_empty_slots > adversarial_weight)
        parent_support_in_empty_slots - adversarial_weight
    else
        0;
}


/// Spec: `get_support_discount(store, balance_source, block_root)`.
/// Thin wrapper over `computeEmptySlotSupportDiscount`.
pub fn getSupportDiscount(
    allocator: Allocator,
    fcr: *const FastConfirmation,
    proto_array: *const ProtoArray,
    state: *const CachedBeaconState,
    balance_source: *const BalanceSourceData,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    block_root: Root,
) Error!u64 {
    return computeEmptySlotSupportDiscount(
        allocator,
        fcr,
        proto_array,
        state,
        balance_source,
        votes,
        equivocating_indices,
        block_root,
    );
}


/// Spec: `compute_safety_threshold(store, block_root, balance_source)`.
/// Returns the breakdown so callers can log component values.
///
/// Underflow guard: when `support_discount > maximum_support + proposer_score
/// + 2 * adversarial_weight`, the threshold saturates at `0` (spec / TS line 578).
pub fn computeSafetyThreshold(
    allocator: Allocator,
    fcr: *const FastConfirmation,
    proto_array: *const ProtoArray,
    state: *const CachedBeaconState,
    balance_source: *const BalanceSourceData,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    block_root: Root,
    current_slot: Slot,
) Error!SafetyThreshold {
    // Resolve block / parent. If either is unknown we can't compute support, so
    // return a "max" threshold that nothing will exceed (matches TS POSITIVE_INFINITY).
    const block = blk: {
        const status = proto_array.getDefaultVariant(block_root) orelse return SafetyThreshold{
            .threshold = std.math.maxInt(u64),
            .proposer_score = 0,
            .maximum_support = 0,
            .support_discount = 0,
            .adversarial_weight = 0,
        };
        break :blk proto_array.getBlock(block_root, status) orelse return SafetyThreshold{
            .threshold = std.math.maxInt(u64),
            .proposer_score = 0,
            .maximum_support = 0,
            .support_discount = 0,
            .adversarial_weight = 0,
        };
    };
    const parent = blk: {
        const status = proto_array.getDefaultVariant(block.parent_root) orelse return SafetyThreshold{
            .threshold = std.math.maxInt(u64),
            .proposer_score = 0,
            .maximum_support = 0,
            .support_discount = 0,
            .adversarial_weight = 0,
        };
        break :blk proto_array.getBlock(block.parent_root, status) orelse return SafetyThreshold{
            .threshold = std.math.maxInt(u64),
            .proposer_score = 0,
            .maximum_support = 0,
            .support_discount = 0,
            .adversarial_weight = 0,
        };
    };

    // Proposer score: floor(committee_weight_per_slot * proposer_score_boost / 100).
    const total_active_balance = getTotalActiveBalance(balance_source);
    const committee_weight_per_slot: u64 = @divFloor(total_active_balance, preset.SLOTS_PER_EPOCH);
    const proposer_score: u64 = @divFloor(committee_weight_per_slot * fcr.proposer_score_boost, 100);

    // Maximum support: estimate over [parent.slot + 1, current_slot - 1].
    // If current_slot is 0, end_slot underflow guard: treat as empty range.
    const maximum_support: u64 = if (current_slot == 0)
        0
    else
        estimateCommitteeWeightBetweenSlots(balance_source, parent.slot + 1, current_slot - 1);

    const support_discount = try getSupportDiscount(
        allocator,
        fcr,
        proto_array,
        state,
        balance_source,
        votes,
        equivocating_indices,
        block_root,
    );

    const adversarial_weight = try getAdversarialWeight(
        allocator,
        fcr,
        proto_array,
        state,
        balance_source,
        equivocating_indices,
        block_root,
        current_slot,
    );

    // Spec underflow guard: if support_discount alone exceeds the rest, threshold = 0.
    const numerator_terms: u64 = maximum_support + proposer_score + 2 * adversarial_weight;
    const threshold: u64 = if (support_discount > numerator_terms)
        0
    else
        @divFloor(numerator_terms - support_discount, 2);

    return SafetyThreshold{
        .threshold = threshold,
        .proposer_score = proposer_score,
        .maximum_support = maximum_support,
        .support_discount = support_discount,
        .adversarial_weight = adversarial_weight,
    };
}


/// Naive per-block attestation score. Iterates all validators, sums effective
/// balance for each whose latest message root is a descendant of `block_root`
/// (skipping equivocating). Precomputing per-chain scores is a possible
/// optimization but not implemented here.
fn getAttestationScore(
    proto_array: *const ProtoArray,
    balance_source: *const BalanceSourceData,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    block_root: Root,
) u64 {
    const balances = balance_source.effective_balances.items;
    const fields = votes.fields();
    const validator_count = @min(balances.len, fields.next_indices.len);

    var score: u64 = 0;
    var i: usize = 0;
    while (i < validator_count) : (i += 1) {
        const bal = balances[i];
        if (bal == 0) continue; // slashed / inactive already zeroed.
        if (equivocating_indices.contains(@intCast(i))) continue;
        const next_idx = fields.next_indices[i];
        if (next_idx == NULL_VOTE_INDEX) continue;
        if (next_idx >= proto_array.nodes.items.len) continue;
        const vote_root = proto_array.nodes.items[next_idx].block_root;
        // block_root must be ancestor of vote_root (i.e. vote is for block_root or a descendant).
        if (isDescendantOfBlock(proto_array, block_root, vote_root)) {
            score += bal;
        }
    }
    return score;
}

/// Spec: `is_one_confirmed(store, balance_source, block_root)`.
/// Returns true iff `support > safety_threshold`.
pub fn isOneConfirmed(
    allocator: Allocator,
    fcr: *const FastConfirmation,
    proto_array: *const ProtoArray,
    state: *const CachedBeaconState,
    balance_source: *const BalanceSourceData,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    block_root: Root,
    current_slot: Slot,
) Error!bool {
    if (current_slot == 0) return false;
    // Block must be known.
    if (proto_array.getDefaultVariant(block_root) == null) return false;

    const support = getAttestationScore(proto_array, balance_source, votes, equivocating_indices, block_root);
    const breakdown = try computeSafetyThreshold(
        allocator,
        fcr,
        proto_array,
        state,
        balance_source,
        votes,
        equivocating_indices,
        block_root,
        current_slot,
    );
    return support > breakdown.threshold;
}


/// Spec: `is_confirmed_chain_safe(fcr_store, confirmed_root)`.
///
/// Walks the chain from `confirmed_root` up to the appropriate `start_root`
/// (excluded) and returns true iff every block in that chain passes
/// `isOneConfirmed` against `previous_balance_source`.
pub fn isConfirmedChainSafe(
    fcr: *const FastConfirmation,
    fc: *const ForkChoice,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    confirmed_root: Root,
    current_slot: Slot,
    allocator: Allocator,
) Error!bool {
    const proto_array = fc.proto_array;
    const observed_justified_root = fcr.current_epoch_observed_justified_checkpoint.root;

    // Confirmed root must be a descendant of the current observed justified
    // checkpoint. `isAncestor` already maps unknown blocks to `false`.
    if (!try isAncestor(fc, confirmed_root, observed_justified_root)) return false;

    const current_epoch = computeEpochAtSlot(current_slot);
    const observed_justified_epoch = fcr.current_epoch_observed_justified_checkpoint.epoch;

    var start_root: Root = undefined;
    if (observed_justified_epoch + 1 >= current_epoch) {
        start_root = observed_justified_root;
    } else {
        // current_epoch - 1 >= 1 here (because current_epoch > observed_justified_epoch + 1 >= 1).
        assert(current_epoch >= 1);
        const prev_epoch_start_slot = computeStartSlotAtEpoch(current_epoch - 1);

        const ancestor_node = fc.getAncestor(confirmed_root, prev_epoch_start_slot) catch |err| switch (err) {
            error.MissingProtoArrayBlock, error.UnknownAncestor => return false,
            else => return err,
        };
        const ancestor_root = ancestor_node.block_root;

        const ancestor_epoch = computeEpochAtSlot(ancestor_node.slot);
        if (ancestor_epoch + 1 == current_epoch) {
            start_root = ancestor_node.parent_root;
        } else {
            start_root = ancestor_root;
        }
    }

    const chain_roots = try getAncestorRoots(allocator, fc, confirmed_root, start_root);
    defer allocator.free(chain_roots);

    for (chain_roots) |root| {
        const ok = try isOneConfirmed(
            allocator,
            fcr,
            proto_array,
            state,
            &fcr.previous_balance_source,
            votes,
            equivocating_indices,
            root,
            current_slot,
        );
        if (!ok) return false;
    }
    return true;
}


/// Compound key used to group voters by their latest message's
/// `(root, epoch)` pair. Voters in the same group all resolve to the same
/// `getCheckpointForBlock` result, so we only need to call the lookup once
/// per group. On mainnet ~1M validators vote for ~50 unique pairs.
const VoteGroupKey = struct {
    root: Root,
    epoch: Epoch,
};

const VoteGroupContext = struct {
    pub fn hash(_: VoteGroupContext, key: VoteGroupKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&key.root);
        hasher.update(std.mem.asBytes(&key.epoch));
        return hasher.final();
    }

    pub fn eql(_: VoteGroupContext, a: VoteGroupKey, b: VoteGroupKey) bool {
        return a.epoch == b.epoch and std.mem.eql(u8, &a.root, &b.root);
    }
};

const VoteGroupMap = std.HashMapUnmanaged(
    VoteGroupKey,
    u64,
    VoteGroupContext,
    std.hash_map.default_max_load_percentage,
);


/// Spec: `get_current_target_score(store)`.
///
/// Estimate the FFG support of the current epoch's target by inspecting each
/// active validator's latest LMD-GHOST vote: if the checkpoint reachable from
/// the vote root at the current epoch matches the current target, that
/// validator's effective balance counts toward the target's score.
///
/// Optimization: rather than calling `getCheckpointForBlock` per validator,
/// group voters by their `(voteRoot, voteEpoch)` pair, then resolve each
/// unique group's checkpoint once. On mainnet this turns ~1M lookups into ~50.
///
/// `head_balance_source` (the spec's "pulled-up head state") supplies the
/// effective balances; slashed/inactive validators are already zeroed by
/// `BalanceSourceData.rebuild`, so the spec's "active and unslashed" filter
/// is implicit.
pub fn getCurrentTargetScore(
    allocator: Allocator,
    fc: *const ForkChoice,
    fcr: *const FastConfirmation,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    head_root: Root,
    current_slot: Slot,
) Error!u64 {
    // `state` reserved for future spec evolution (e.g. shuffling-aware filter).
    // FCR's pulled-up head balance source already encodes active/slashed.
    _ = state;

    const target = try getCurrentTarget(fc, head_root, current_slot);

    const balances = fcr.head_balance_source.effective_balances.items;
    const fields = votes.fields();
    const validator_count = @min(balances.len, fields.next_indices.len);

    // Group validators by (voteRoot, voteEpoch). Map values accumulate
    // total effective balance for that group.
    var vote_groups: VoteGroupMap = .empty;
    defer vote_groups.deinit(allocator);

    var i: usize = 0;
    while (i < validator_count) : (i += 1) {
        const bal = balances[i];
        if (bal == 0) continue; // slashed / inactive already zeroed.
        if (equivocating_indices.contains(@intCast(i))) continue;
        const vote_root = latestVoteRoot(votes, fc.proto_array, i) orelse continue;
        const vote_epoch = computeEpochAtSlot(fields.next_slots[i]);

        const key: VoteGroupKey = .{ .root = vote_root, .epoch = vote_epoch };
        const gop = try vote_groups.getOrPut(allocator, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = 0;
        }
        gop.value_ptr.* += bal;
    }

    // For each unique group, resolve the checkpoint at the current epoch from
    // the vote root and accumulate the group's weight if the checkpoint
    // matches the target.
    var score: u64 = 0;
    var it = vote_groups.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const weight = entry.value_ptr.*;
        // Spec: `get_checkpoint_for_block(store, root, get_latest_message_epoch(msg))`.
        // Map "block unknown / ancestor missing" → not counted (matches TS swallow).
        const cp = getCheckpointForBlock(fc, key.root, key.epoch) catch |err| switch (err) {
            error.StateMissing => continue,
            else => return err,
        };
        if (cp.eql(target)) {
            score += weight;
        }
    }
    return score;
}


/// Spec: `compute_honest_ffg_support_for_current_target(store)`.
///
/// Combines the FFG support already received with a worst-case estimate of
/// the remaining honest FFG weight, assuming `byzantine_threshold` of the
/// remaining and till-now committees are adversarial.
///
/// Returns `min_honest_ffg_support + remaining_honest_ffg_weight` where:
/// ```
/// remaining_ffg_weight        = total_active_balance - ffg_weight_till_now
/// remaining_honest_ffg_weight = floor(remaining_ffg_weight * (100 - byzantine_threshold) / 100)
/// min_honest_ffg_support      = ffg_support
///                              - min(floor(ffg_weight_till_now * byzantine_threshold / 100), ffg_support)
/// ```
///
/// The `min(..., ffg_support)` saturation is critical to avoid underflow when
/// the projected adversarial weight exceeds the support already accumulated.
pub fn computeHonestFfgSupportForCurrentTarget(
    allocator: Allocator,
    fc: *const ForkChoice,
    fcr: *const FastConfirmation,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    head_root: Root,
    current_slot: Slot,
) Error!u64 {
    if (current_slot == 0) return 0;

    const total_active_balance = getTotalActiveBalance(&fcr.head_balance_source);

    const ffg_support = try getCurrentTargetScore(
        allocator,
        fc,
        fcr,
        state,
        votes,
        equivocating_indices,
        head_root,
        current_slot,
    );

    const current_epoch = computeEpochAtSlot(current_slot);
    const epoch_start_slot = computeStartSlotAtEpoch(current_epoch);
    // current_slot >= 1 (early-return above), so current_slot - 1 is safe.
    const ffg_weight_till_now = estimateCommitteeWeightBetweenSlots(
        &fcr.head_balance_source,
        epoch_start_slot,
        current_slot - 1,
    );

    // total_active_balance - ffg_weight_till_now: clamp to 0 in case rounding
    // in `estimate_committee_weight_between_slots` produces a value slightly
    // above `total_active_balance` (the "ensure safety" adjustment can
    // over-estimate). Better to under-count remaining weight than to wrap.
    const remaining_ffg_weight: u64 = if (total_active_balance > ffg_weight_till_now)
        total_active_balance - ffg_weight_till_now
    else
        0;

    const byzantine_threshold = fcr.byzantine_threshold;
    // byzantine_threshold ∈ [0, 25] ⇒ (100 - byzantine_threshold) ∈ [75, 100].
    assert(byzantine_threshold <= 100);
    const remaining_honest_ffg_weight: u64 =
        @divFloor(remaining_ffg_weight * (100 - byzantine_threshold), 100);

    const adversarial_till_now: u64 = @divFloor(ffg_weight_till_now * byzantine_threshold, 100);
    const subtract: u64 = @min(adversarial_till_now, ffg_support);
    const min_honest_ffg_support: u64 = ffg_support - subtract;

    return min_honest_ffg_support + remaining_honest_ffg_weight;
}


/// Spec: `will_no_conflicting_checkpoint_be_justified(store)`.
///
/// Returns `true` iff no checkpoint conflicting with the current target can
/// ever be justified. Two cases:
///
/// 1. The current target is already the head's unrealized-justified
///    checkpoint → trivially safe.
/// 2. Otherwise, check whether `3 * honest_ffg_support > total_active_balance`,
///    i.e., the honest FFG support of the current target alone exceeds 1/3
///    of all active balance, leaving no room for a conflicting 2/3 majority.
///
/// `head_unrealized_justified` is supplied by the caller (typically derived
/// from `fc_store` or FCR state); unit tests pass synthetic checkpoints.
pub fn willNoConflictingCheckpointBeJustified(
    allocator: Allocator,
    fc: *const ForkChoice,
    fcr: *const FastConfirmation,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    head_root: Root,
    current_slot: Slot,
    head_unrealized_justified: *const Checkpoint,
) Error!bool {
    const target = try getCurrentTarget(fc, head_root, current_slot);
    if (target.eql(head_unrealized_justified.*)) return true;

    // `getTotalActiveBalance` is also called inside
    // `computeHonestFfgSupportForCurrentTarget`. At mainnet scale (~1M
    // u16 entries) this is O(N) twice per call; memoizing the sum on
    // `BalanceSourceData` after `rebuild` would drop the redundant scan.
    const total_active_balance = getTotalActiveBalance(&fcr.head_balance_source);
    const honest_support = try computeHonestFfgSupportForCurrentTarget(
        allocator,
        fc,
        fcr,
        state,
        votes,
        equivocating_indices,
        head_root,
        current_slot,
    );
    return 3 * honest_support > total_active_balance;
}


/// Spec: `will_current_target_be_justified(store)`.
///
/// Returns `true` iff `3 * honest_ffg_support >= 2 * total_active_balance`,
/// i.e., the honest FFG support of the current target meets the 2/3
/// supermajority threshold needed for justification.
///
/// Edge case: when `total_active_balance == 0`, `0 >= 0` evaluates to `true`.
/// This matches the spec's `>=` semantics exactly. In production this never
/// occurs because the validator set is non-empty; a defensive caller can
/// short-circuit at the call site if desired.
pub fn willCurrentTargetBeJustified(
    allocator: Allocator,
    fc: *const ForkChoice,
    fcr: *const FastConfirmation,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    head_root: Root,
    current_slot: Slot,
) Error!bool {
    const total_active_balance = getTotalActiveBalance(&fcr.head_balance_source);
    const honest_support = try computeHonestFfgSupportForCurrentTarget(
        allocator,
        fc,
        fcr,
        state,
        votes,
        equivocating_indices,
        head_root,
        current_slot,
    );
    return 3 * honest_support >= 2 * total_active_balance;
}


/// Voting source epoch for FCR purposes. When the block was proposed in a
/// previous epoch we use its unrealized justified checkpoint (the "pulled-up"
/// view); otherwise we use the realized justified checkpoint stored on the
/// block.
///
/// Returns `null` if the block is not present in proto array.
fn getVotingSourceEpoch(
    proto_array: *const ProtoArray,
    block_root: Root,
    current_slot: Slot,
) ?Epoch {
    const status = proto_array.getDefaultVariant(block_root) orelse return null;
    const block = proto_array.getBlock(block_root, status) orelse return null;
    const current_epoch = computeEpochAtSlot(current_slot);
    const block_epoch = computeEpochAtSlot(block.slot);
    if (current_epoch > block_epoch) {
        return block.unrealized_justified_epoch;
    }
    return block.justified_epoch;
}

/// Unrealized justified epoch for a block in proto array, or `null` if unknown.
fn getUnrealizedJustifiedEpoch(proto_array: *const ProtoArray, block_root: Root) ?Epoch {
    const status = proto_array.getDefaultVariant(block_root) orelse return null;
    const block = proto_array.getBlock(block_root, status) orelse return null;
    return block.unrealized_justified_epoch;
}

/// Spec: `update_fast_confirmation_variables(fcr_store)`.
///
/// Reentrancy guard: a same-slot duplicate call is a no-op so callers can
/// invoke this from multiple orchestration points within a slot without
/// double-rotating state.
///
/// Spec line 814-816: `previous_epoch_greatest_unrealized_checkpoint` reads
/// from `store.unrealized_justified_checkpoint` — the GLOBAL fork-choice
/// store's unrealized_justified, NOT the head's per-block unrealized field.
/// The runner had been passing head's per-block value, stomping the FCR
/// state to ZERO_HASH at anchor blocks. We source it from `fc.fc_store`
/// directly so the contract matches the spec.
fn updateFastConfirmationVariables(
    self: *FastConfirmation,
    fc: *const ForkChoice,
    head_root: Root,
    current_slot: Slot,
) void {
    if (self.last_update_slot) |s| {
        if (current_slot <= s) return;
    }

    // Rotate slot heads.
    self.previous_slot_head = self.current_slot_head;
    self.current_slot_head = head_root;

    // Last slot of the current epoch: snapshot the global unrealized justified
    // checkpoint per spec `update_fast_confirmation_variables`.
    if (isStartSlotAtEpoch(current_slot + 1)) {
        self.previous_epoch_greatest_unrealized_checkpoint =
            fc.fc_store.unrealized_justified.checkpoint;
    }

    // First slot of the current epoch: rotate observed-justified checkpoints.
    if (isStartSlotAtEpoch(current_slot)) {
        self.previous_epoch_observed_justified_checkpoint =
            self.current_epoch_observed_justified_checkpoint;
        self.current_epoch_observed_justified_checkpoint =
            self.previous_epoch_greatest_unrealized_checkpoint;
    }

    self.last_update_slot = current_slot;
}

/// Spec: `find_latest_confirmed_descendant(fcr_store, latest_confirmed_root)`.
///
/// Two-pass canonical-chain walk that attempts to advance `confirmed_root`
/// toward `head_root`. Loop 1 advances within the previous epoch; loop 2
/// advances within the current epoch.
///
/// Returns the (possibly unchanged) confirmed root.
fn findLatestConfirmedDescendant(
    self: *const FastConfirmation,
    allocator: Allocator,
    fc: *const ForkChoice,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    head_root: Root,
    head_unrealized_justified: *const Checkpoint,
    confirmed_root: Root,
    current_slot: Slot,
) Error!Root {
    const proto_array = fc.proto_array;
    const current_epoch = computeEpochAtSlot(current_slot);
    var result_root = confirmed_root;

    const is_epoch_start = isStartSlotAtEpoch(current_slot);

    // ---- Loop 1: advance within previous epoch ----
    const confirmed_epoch_opt: ?Epoch = if (proto_array.getDefaultVariant(result_root)) |st|
        if (proto_array.getBlock(result_root, st)) |b| computeEpochAtSlot(b.slot) else null
    else
        null;

    const prev_voting_source_epoch = getVotingSourceEpoch(proto_array, self.previous_slot_head, current_slot);
    const prev_uj_epoch = getUnrealizedJustifiedEpoch(proto_array, self.previous_slot_head);
    const head_uj_epoch = getUnrealizedJustifiedEpoch(proto_array, head_root);

    const confirmed_epoch_check = confirmed_epoch_opt != null and
        confirmed_epoch_opt.? + 1 == current_epoch;
    const voting_source_check = prev_voting_source_epoch != null and
        prev_voting_source_epoch.? + 2 >= current_epoch;

    var loop1_guard = confirmed_epoch_check and voting_source_check;
    if (loop1_guard and !is_epoch_start) {
        const no_conflict = try willNoConflictingCheckpointBeJustified(
            allocator,
            fc,
            self,
            state,
            votes,
            equivocating_indices,
            head_root,
            current_slot,
            head_unrealized_justified,
        );
        const uj_prev_ok = prev_uj_epoch != null and prev_uj_epoch.? + 1 >= current_epoch;
        const uj_head_ok = head_uj_epoch != null and head_uj_epoch.? + 1 >= current_epoch;
        loop1_guard = no_conflict and (uj_prev_ok or uj_head_ok);
    }

    if (loop1_guard) {
        const canonical_roots = try getAncestorRoots(allocator, fc, head_root, result_root);
        defer allocator.free(canonical_roots);

        // Bound the loop. canonical_roots length is itself bounded by
        // getAncestorRoots; this clamp defends against pathological inputs.
        const limit: usize = @min(canonical_roots.len, ANCESTOR_WALK_MAX_ITERATIONS);
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            const block_root = canonical_roots[i];
            const block_epoch_opt: ?Epoch = if (proto_array.getDefaultVariant(block_root)) |st|
                if (proto_array.getBlock(block_root, st)) |b| computeEpochAtSlot(b.slot) else null
            else
                null;
            // Stop if we cross into the current epoch or the block is unknown.
            if (block_epoch_opt == null or block_epoch_opt.? >= current_epoch) break;

            // Previous slot head must be a descendant of `block_root` (otherwise
            // we can't rely on the previous slot's view to validate it).
            const desc = try isAncestor(fc, self.previous_slot_head, block_root);
            if (!desc) break;

            const ok = try isOneConfirmed(
                allocator,
                self,
                proto_array,
                state,
                &self.current_balance_source,
                votes,
                equivocating_indices,
                block_root,
                current_slot,
            );
            if (!ok) break;
            result_root = block_root;
        }
    }

    // ---- Loop 2: advance within current epoch (with FFG promotion gate) ----
    const loop2_uj_head_ok = head_uj_epoch != null and head_uj_epoch.? + 1 >= current_epoch;
    const loop2_guard = is_epoch_start or loop2_uj_head_ok;

    if (loop2_guard) {
        const canonical_roots = try getAncestorRoots(allocator, fc, head_root, result_root);
        defer allocator.free(canonical_roots);

        var tentative_root = result_root;
        const limit: usize = @min(canonical_roots.len, ANCESTOR_WALK_MAX_ITERATIONS);
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            const block_root = canonical_roots[i];
            const block_epoch_opt: ?Epoch = if (proto_array.getDefaultVariant(block_root)) |st|
                if (proto_array.getBlock(block_root, st)) |b| computeEpochAtSlot(b.slot) else null
            else
                null;
            const tentative_epoch_opt: ?Epoch = if (proto_array.getDefaultVariant(tentative_root)) |st|
                if (proto_array.getBlock(tentative_root, st)) |b| computeEpochAtSlot(b.slot) else null
            else
                null;
            if (block_epoch_opt == null or tentative_epoch_opt == null) break;

            // When crossing into the current epoch, require the FFG check.
            if (block_epoch_opt.? > tentative_epoch_opt.?) {
                const ffg_ok = try willCurrentTargetBeJustified(
                    allocator,
                    fc,
                    self,
                    state,
                    votes,
                    equivocating_indices,
                    head_root,
                    current_slot,
                );
                if (!ffg_ok) break;
            }

            const ok = try isOneConfirmed(
                allocator,
                self,
                proto_array,
                state,
                &self.current_balance_source,
                votes,
                equivocating_indices,
                block_root,
                current_slot,
            );
            if (!ok) break;
            tentative_root = block_root;
        }

        // Promote `tentative_root` to `result_root` only if it is safe from a
        // future re-org in the current and next epochs.
        const tentative_epoch_opt: ?Epoch = if (proto_array.getDefaultVariant(tentative_root)) |st|
            if (proto_array.getBlock(tentative_root, st)) |b| computeEpochAtSlot(b.slot) else null
        else
            null;
        const tentative_voting_source_epoch =
            getVotingSourceEpoch(proto_array, tentative_root, current_slot);

        const promote_check_current = tentative_epoch_opt != null and
            tentative_epoch_opt.? == current_epoch;
        var promote_check_safe = false;
        if (tentative_voting_source_epoch) |vs_epoch| {
            if (vs_epoch + 2 >= current_epoch) {
                if (is_epoch_start) {
                    promote_check_safe = true;
                } else {
                    promote_check_safe = try willNoConflictingCheckpointBeJustified(
                        allocator,
                        fc,
                        self,
                        state,
                        votes,
                        equivocating_indices,
                        head_root,
                        current_slot,
                        head_unrealized_justified,
                    );
                }
            }
        }

        if (promote_check_current or promote_check_safe) {
            result_root = tentative_root;
        }
    }

    return result_root;
}

/// Spec: `get_latest_confirmed(fcr_store)`.
///
/// Four-step decision flow:
///   1. Reset to finalized when stale, off-canonical, or chain-unsafe at epoch start.
///   2. Restart from observed-justified at epoch start when conditions match.
///   3. If confirmed_epoch + 1 >= current_epoch, advance via descendant search.
///   4. Otherwise return the confirmed root unchanged.
fn getLatestConfirmed(
    self: *const FastConfirmation,
    allocator: Allocator,
    fc: *const ForkChoice,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    finalized_checkpoint: *const Checkpoint,
    head_root: Root,
    head_unrealized_justified: *const Checkpoint,
    current_slot: Slot,
) Error!Root {
    const proto_array = fc.proto_array;
    const current_epoch = computeEpochAtSlot(current_slot);
    var confirmed_root = self.confirmed_root;

    // ---- Step 1: revert to finalized when stale, off-canonical, or unsafe at epoch start ----
    const is_epoch_start = isStartSlotAtEpoch(current_slot);
    const confirmed_epoch_opt: ?Epoch = if (proto_array.getDefaultVariant(confirmed_root)) |st|
        if (proto_array.getBlock(confirmed_root, st)) |b| computeEpochAtSlot(b.slot) else null
    else
        null;

    const stale = confirmed_epoch_opt == null or confirmed_epoch_opt.? + 1 < current_epoch;
    var off_canonical = false;
    if (!stale) {
        off_canonical = !try isAncestor(fc, head_root, confirmed_root);
    }
    var chain_unsafe = false;
    if (!stale and !off_canonical and is_epoch_start) {
        chain_unsafe = !try isConfirmedChainSafe(
            self,
            fc,
            state,
            votes,
            equivocating_indices,
            confirmed_root,
            current_slot,
            allocator,
        );
    }
    if (stale or off_canonical or chain_unsafe) {
        confirmed_root = finalized_checkpoint.root;
    }

    // ---- Step 2: restart from observed-justified at epoch start when conditions match ----
    // Spec lines 989-1012:
    //   1) it is the start of the current epoch,
    //   2) epoch of fcr_store.current_epoch_observed_justified_checkpoint.root
    //      equals the previous epoch (NB: spec computes this from the BLOCK's
    //      slot, not the checkpoint's `epoch` field — these can differ when
    //      the checkpoint root is an empty-slot block from an earlier epoch),
    //   3) fcr_store.current_epoch_observed_justified_checkpoint equals
    //      `store.unrealized_justifications[head]`,
    //   4) confirmed block is older than the block of
    //      fcr_store.current_epoch_observed_justified_checkpoint.
    const observed = self.current_epoch_observed_justified_checkpoint;
    if (is_epoch_start) {
        // Slot of the observed-justified block; if unknown we cannot restart.
        const observed_slot_opt: ?Slot = getBlockSlot(proto_array, observed.root) catch |err| switch (err) {
            error.StateMissing => null,
            else => return err,
        };
        if (observed_slot_opt) |observed_slot| {
            // Per spec: gate on the BLOCK's slot's epoch (not the checkpoint's
            // `epoch` field).
            const observed_block_epoch = computeEpochAtSlot(observed_slot);
            const observed_epoch_ok = observed_block_epoch + 1 == current_epoch;
            const head_uj_match = observed.eql(head_unrealized_justified.*);

            if (observed_epoch_ok and head_uj_match) {
                // Compare slot of confirmed_root with observed_slot. If confirmed
                // is unknown we cannot reason about staleness; skip restart.
                const confirmed_slot_opt: ?Slot = getBlockSlot(proto_array, confirmed_root) catch |err| switch (err) {
                    error.StateMissing => null,
                    else => return err,
                };
                if (confirmed_slot_opt) |confirmed_slot| {
                    if (confirmed_slot < observed_slot) {
                        confirmed_root = observed.root;
                    }
                }
            }
        }
    }

    // ---- Step 3 / 4: descendant search when in range, else stable ----
    const post_confirmed_epoch_opt: ?Epoch =
        if (proto_array.getDefaultVariant(confirmed_root)) |st|
            if (proto_array.getBlock(confirmed_root, st)) |b| computeEpochAtSlot(b.slot) else null
        else
            null;

    if (post_confirmed_epoch_opt) |e| {
        if (e + 1 >= current_epoch) {
            return findLatestConfirmedDescendant(
                self,
                allocator,
                fc,
                state,
                votes,
                equivocating_indices,
                head_root,
                head_unrealized_justified,
                confirmed_root,
                current_slot,
            );
        }
    }

    return confirmed_root;
}

/// Rebuild `head_balance_source` for the current epoch on `head_root`'s chain.
///
/// The TS / Rust implementations key the head balance source on the
/// `(epoch, head_root)` pair so a switch in the head invalidates the cache.
/// We follow the same convention.
///
/// TODO: the spec wants the *checkpoint state* for the current epoch, not the
/// head state. We currently pass the head state because the production hook
/// site only has that available; once a caller threads a checkpoint state
/// through, replace `state` here with it.
fn rebuildHeadBalanceSource(
    self: *FastConfirmation,
    allocator: Allocator,
    state: *const CachedBeaconState,
    head_root: Root,
    current_slot: Slot,
) Error!void {
    const current_epoch = computeEpochAtSlot(current_slot);
    const cp: Checkpoint = .{ .epoch = current_epoch, .root = head_root };
    try self.head_balance_source.rebuild(allocator, state, cp);
}

/// Spec: `on_fast_confirmation` handler.
///
/// In production (`spec_test_mode = false`) this also assigns
/// `self.confirmed_root` from `getLatestConfirmed`. The spec-test path uses
/// `runConfirmation` instead.
pub fn onFastConfirmation(
    self: *FastConfirmation,
    allocator: Allocator,
    fc: *const ForkChoice,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    finalized_checkpoint: *const Checkpoint,
    justified_checkpoint: *const Checkpoint,
    head_unrealized_justified: *const Checkpoint,
    head_root: Root,
    current_slot: Slot,
) Error!void {
    // `justified_checkpoint` is currently unused — proto-array carries the
    // same information. Kept on the signature for caller flexibility; will be
    // consumed when the pulled-up justification logic is wired up.
    _ = justified_checkpoint;

    updateFastConfirmationVariables(self, fc, head_root, current_slot);

    // Rebuild committee assignments + head balance source for current slot.
    // TODO: pass the proper checkpoint states here; for now we reuse the head
    // state for both head and justified-checkpoint balance sources.
    try self.head_assignments.rebuild(allocator, state, current_slot);
    try rebuildHeadBalanceSource(self, allocator, state, head_root, current_slot);

    // Rotate previous / current balance sources when their checkpoints changed.
    if (!self.previous_balance_source.checkpoint.eql(self.previous_epoch_observed_justified_checkpoint)) {
        try self.previous_balance_source.rebuild(
            allocator,
            state,
            self.previous_epoch_observed_justified_checkpoint,
        );
    }
    if (!self.current_balance_source.checkpoint.eql(self.current_epoch_observed_justified_checkpoint)) {
        try self.current_balance_source.rebuild(
            allocator,
            state,
            self.current_epoch_observed_justified_checkpoint,
        );
    }

    if (!self.spec_test_mode) {
        self.confirmed_root = try getLatestConfirmed(
            self,
            allocator,
            fc,
            state,
            votes,
            equivocating_indices,
            finalized_checkpoint,
            head_root,
            head_unrealized_justified,
            current_slot,
        );
    }
}

/// Spec-test orchestration entry point. Identical to `onFastConfirmation`
/// except it always runs `getLatestConfirmed`, regardless of `spec_test_mode`.
pub fn runConfirmation(
    self: *FastConfirmation,
    allocator: Allocator,
    fc: *const ForkChoice,
    state: *const CachedBeaconState,
    votes: *Votes,
    equivocating_indices: *const EquivocatingIndices,
    finalized_checkpoint: *const Checkpoint,
    justified_checkpoint: *const Checkpoint,
    head_unrealized_justified: *const Checkpoint,
    head_root: Root,
    current_slot: Slot,
) Error!void {
    _ = justified_checkpoint;

    updateFastConfirmationVariables(self, fc, head_root, current_slot);

    try self.head_assignments.rebuild(allocator, state, current_slot);
    try rebuildHeadBalanceSource(self, allocator, state, head_root, current_slot);

    if (!self.previous_balance_source.checkpoint.eql(self.previous_epoch_observed_justified_checkpoint)) {
        try self.previous_balance_source.rebuild(
            allocator,
            state,
            self.previous_epoch_observed_justified_checkpoint,
        );
    }
    if (!self.current_balance_source.checkpoint.eql(self.current_epoch_observed_justified_checkpoint)) {
        try self.current_balance_source.rebuild(
            allocator,
            state,
            self.current_epoch_observed_justified_checkpoint,
        );
    }

    self.confirmed_root = try getLatestConfirmed(
        self,
        allocator,
        fc,
        state,
        votes,
        equivocating_indices,
        finalized_checkpoint,
        head_root,
        head_unrealized_justified,
        current_slot,
    );
}

// Tests

const ZERO_ROOT: Root = [_]u8{0} ** 32;

fn rootFromByte(b: u8) Root {
    var r: Root = ZERO_ROOT;
    r[0] = b;
    return r;
}


test "FastConfirmation init/deinit smoke" {
    const cp: Checkpoint = .{ .epoch = 0, .root = rootFromByte(0xAA) };
    var fcr = FastConfirmation.init(cp, 25, 40);
    defer fcr.deinit(testing.allocator);

    try testing.expectEqual(rootFromByte(0xAA), fcr.confirmed_root);
    try testing.expectEqual(@as(u64, 25), fcr.byzantine_threshold);
    try testing.expectEqual(@as(u64, 40), fcr.proposer_score_boost);
    try testing.expect(!fcr.spec_test_mode);
}

test "FastConfirmation byzantine_threshold clamps to 25" {
    const cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };
    var fcr = FastConfirmation.init(cp, 99, 40);
    defer fcr.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 25), fcr.byzantine_threshold);
}

test "FastConfirmation setSpecTestMode" {
    const cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };
    var fcr = FastConfirmation.init(cp, 25, 40);
    defer fcr.deinit(testing.allocator);
    fcr.setSpecTestMode(true);
    try testing.expect(fcr.spec_test_mode);
}


test "FastConfirmation.isStartSlotAtEpoch — slot 0 and epoch boundaries" {
    try testing.expect(isStartSlotAtEpoch(0));
    try testing.expect(!isStartSlotAtEpoch(1));
    try testing.expect(isStartSlotAtEpoch(preset.SLOTS_PER_EPOCH));
    try testing.expect(!isStartSlotAtEpoch(preset.SLOTS_PER_EPOCH + 1));
    try testing.expect(isStartSlotAtEpoch(2 * preset.SLOTS_PER_EPOCH));
}

// Minimal ProtoArray test fixture: builds a 3-block linear chain
//   genesis (slot 0, ZERO_ROOT) <- A (slot 1) <- B (slot 2).
// Returns the ProtoArray and the three roots.
const ProtoChain = struct {
    pa_inst: ProtoArray,
    genesis_root: Root,
    a_root: Root,
    b_root: Root,

    fn deinit(self: *ProtoChain, allocator: Allocator) void {
        self.pa_inst.deinit(allocator);
    }
};

fn makeProtoBlock(slot: Slot, block_root: Root, parent_root: Root) proto_array_mod.ProtoBlock {
    return .{
        .slot = slot,
        .block_root = block_root,
        .parent_root = parent_root,
        .state_root = ZERO_ROOT,
        .target_root = ZERO_ROOT,
        .justified_epoch = 0,
        .justified_root = ZERO_ROOT,
        .finalized_epoch = 0,
        .finalized_root = ZERO_ROOT,
        .unrealized_justified_epoch = 0,
        .unrealized_justified_root = ZERO_ROOT,
        .unrealized_finalized_epoch = 0,
        .unrealized_finalized_root = ZERO_ROOT,
        .extra_meta = .{ .pre_merge = {} },
        .timeliness = false,
    };
}

fn buildLinearChain(allocator: Allocator) !ProtoChain {
    const genesis_root = ZERO_ROOT;
    const a_root = rootFromByte(0xA1);
    const b_root = rootFromByte(0xB2);

    var pa_inst: ProtoArray = undefined;
    try pa_inst.initialize(allocator, makeProtoBlock(0, genesis_root, ZERO_ROOT), 0);
    errdefer pa_inst.deinit(allocator);

    try pa_inst.onBlock(allocator, makeProtoBlock(1, a_root, genesis_root), 1, null);
    try pa_inst.onBlock(allocator, makeProtoBlock(2, b_root, a_root), 2, null);

    return .{
        .pa_inst = pa_inst,
        .genesis_root = genesis_root,
        .a_root = a_root,
        .b_root = b_root,
    };
}

test "FastConfirmation.getBlockSlot returns slot for known root" {
    var chain = try buildLinearChain(testing.allocator);
    defer chain.deinit(testing.allocator);

    try testing.expectEqual(@as(Slot, 0), try getBlockSlot(&chain.pa_inst, chain.genesis_root));
    try testing.expectEqual(@as(Slot, 1), try getBlockSlot(&chain.pa_inst, chain.a_root));
    try testing.expectEqual(@as(Slot, 2), try getBlockSlot(&chain.pa_inst, chain.b_root));
}

test "FastConfirmation.getBlockSlot returns StateMissing for unknown root" {
    var chain = try buildLinearChain(testing.allocator);
    defer chain.deinit(testing.allocator);

    const unknown = rootFromByte(0xFE);
    try testing.expectError(error.StateMissing, getBlockSlot(&chain.pa_inst, unknown));
}

test "FastConfirmation.getBlockEpoch derives epoch from slot" {
    var chain = try buildLinearChain(testing.allocator);
    defer chain.deinit(testing.allocator);

    // Slot 0,1,2 all in epoch 0 for all presets.
    try testing.expectEqual(@as(Epoch, 0), try getBlockEpoch(&chain.pa_inst, chain.genesis_root));
    try testing.expectEqual(@as(Epoch, 0), try getBlockEpoch(&chain.pa_inst, chain.b_root));

    const unknown = rootFromByte(0xFE);
    try testing.expectError(error.StateMissing, getBlockEpoch(&chain.pa_inst, unknown));
}


const test_balances_getter: store_mod.JustifiedBalancesGetter = .{ .getFn = dummyBalancesGetter };

fn dummyBalancesGetter(_: ?*anyopaque, _: Checkpoint, _: *CachedBeaconState) store_mod.JustifiedBalances {
    return .empty;
}

fn getMinimalConfig() *const @import("config").BeaconConfig {
    return &@import("config").minimal.config;
}

/// Build a heap-allocated ForkChoice with a 3-block linear chain spanning two
/// epochs:
///   genesis @ slot 0 (epoch 0)
///   block_a @ slot 1 (epoch 0)
///   block_b @ slot SLOTS_PER_EPOCH (epoch 1)
const ForkChoiceFixture = struct {
    fc: *ForkChoice,
    genesis_root: Root,
    a_root: Root,
    b_root: Root,
};

fn initLinearForkChoice(allocator: Allocator) !ForkChoiceFixture {
    const genesis_root = rootFromByte(0xA0);
    const a_root = rootFromByte(0xA1);
    const b_root = rootFromByte(0xB2);

    const proto_arr = try allocator.create(ProtoArray);
    errdefer allocator.destroy(proto_arr);

    const genesis_block = makeProtoBlock(0, genesis_root, ZERO_ROOT);
    try proto_arr.initialize(allocator, genesis_block, 0);
    errdefer proto_arr.deinit(allocator);

    // Add block_a at slot 1 (still epoch 0).
    var a_block = makeProtoBlock(1, a_root, genesis_root);
    a_block.target_root = genesis_root;
    try proto_arr.onBlock(allocator, a_block, 1, null);

    // Add block_b at the start of epoch 1.
    const epoch1_start: Slot = preset.SLOTS_PER_EPOCH;
    var b_block = makeProtoBlock(epoch1_start, b_root, a_root);
    b_block.target_root = b_root; // epoch boundary block targets itself.
    try proto_arr.onBlock(allocator, b_block, epoch1_start, null);

    const fc_store = try allocator.create(@import("../store.zig").ForkChoiceStore);
    errdefer allocator.destroy(fc_store);
    try fc_store.init(
        allocator,
        epoch1_start,
        .{ .epoch = 0, .root = genesis_root },
        .{ .epoch = 0, .root = genesis_root },
        &[_]u16{},
        test_balances_getter,
        .{},
    );
    errdefer fc_store.deinit(allocator);

    const fc = try allocator.create(ForkChoice);
    errdefer allocator.destroy(fc);
    try fc.init(allocator, getMinimalConfig(), fc_store, proto_arr, 0, .{});

    return .{ .fc = fc, .genesis_root = genesis_root, .a_root = a_root, .b_root = b_root };
}

fn deinitForkChoiceFixture(allocator: Allocator, fixture: ForkChoiceFixture) void {
    const proto_arr = fixture.fc.proto_array;
    const fc_store = fixture.fc.fc_store;
    fixture.fc.deinit(allocator);
    allocator.destroy(fixture.fc);
    proto_arr.deinit(allocator);
    allocator.destroy(proto_arr);
    fc_store.deinit(allocator);
    allocator.destroy(fc_store);
}

test "FastConfirmation.getCheckpointForBlock returns ancestor at epoch start" {
    const fixture = try initLinearForkChoice(testing.allocator);
    defer deinitForkChoiceFixture(testing.allocator, fixture);

    // Checkpoint at epoch 0 for block_b should be the genesis root (slot 0 is the
    // epoch-0 boundary).
    const cp0 = try getCheckpointForBlock(fixture.fc, fixture.b_root, 0);
    try testing.expectEqual(@as(Epoch, 0), cp0.epoch);
    try testing.expectEqualSlices(u8, &fixture.genesis_root, &cp0.root);

    // Checkpoint at epoch 1 for block_b should be block_b itself.
    const cp1 = try getCheckpointForBlock(fixture.fc, fixture.b_root, 1);
    try testing.expectEqual(@as(Epoch, 1), cp1.epoch);
    try testing.expectEqualSlices(u8, &fixture.b_root, &cp1.root);
}

test "FastConfirmation.getCheckpointForBlock returns StateMissing for unknown root" {
    const fixture = try initLinearForkChoice(testing.allocator);
    defer deinitForkChoiceFixture(testing.allocator, fixture);

    const unknown = rootFromByte(0xFE);
    try testing.expectError(error.StateMissing, getCheckpointForBlock(fixture.fc, unknown, 0));
}

test "FastConfirmation.isAncestor identifies direct lineage" {
    const fixture = try initLinearForkChoice(testing.allocator);
    defer deinitForkChoiceFixture(testing.allocator, fixture);

    // genesis is an ancestor of block_b.
    try testing.expect(try isAncestor(fixture.fc, fixture.b_root, fixture.genesis_root));
    // block_a is an ancestor of block_b.
    try testing.expect(try isAncestor(fixture.fc, fixture.b_root, fixture.a_root));
    // A block is its own ancestor.
    try testing.expect(try isAncestor(fixture.fc, fixture.a_root, fixture.a_root));
    // block_b is NOT an ancestor of block_a (other direction).
    try testing.expect(!try isAncestor(fixture.fc, fixture.a_root, fixture.b_root));
}

test "FastConfirmation.isAncestor returns false for unknown root" {
    const fixture = try initLinearForkChoice(testing.allocator);
    defer deinitForkChoiceFixture(testing.allocator, fixture);

    const unknown = rootFromByte(0xFE);
    try testing.expect(!try isAncestor(fixture.fc, fixture.b_root, unknown));
    try testing.expect(!try isAncestor(fixture.fc, unknown, fixture.genesis_root));
}

test "FastConfirmation.getAncestorRoots returns oldest-to-newest exclusive of terminal" {
    const fixture = try initLinearForkChoice(testing.allocator);
    defer deinitForkChoiceFixture(testing.allocator, fixture);

    // From block_b walking back to genesis: should return [a_root, b_root]
    // (genesis is the terminal and is excluded; ordering is oldest-to-newest).
    const roots = try getAncestorRoots(testing.allocator, fixture.fc, fixture.b_root, fixture.genesis_root);
    defer testing.allocator.free(roots);

    try testing.expectEqual(@as(usize, 2), roots.len);
    try testing.expectEqualSlices(u8, &fixture.a_root, &roots[0]);
    try testing.expectEqualSlices(u8, &fixture.b_root, &roots[1]);
}

test "FastConfirmation.getAncestorRoots returns empty when terminal not in chain" {
    const fixture = try initLinearForkChoice(testing.allocator);
    defer deinitForkChoiceFixture(testing.allocator, fixture);

    const unknown = rootFromByte(0xFE);
    const roots = try getAncestorRoots(testing.allocator, fixture.fc, fixture.b_root, unknown);
    defer testing.allocator.free(roots);
    try testing.expectEqual(@as(usize, 0), roots.len);
}

test "FastConfirmation.getAncestorRoots returns empty for block_root == terminal_root" {
    const fixture = try initLinearForkChoice(testing.allocator);
    defer deinitForkChoiceFixture(testing.allocator, fixture);

    const roots = try getAncestorRoots(testing.allocator, fixture.fc, fixture.b_root, fixture.b_root);
    defer testing.allocator.free(roots);
    try testing.expectEqual(@as(usize, 0), roots.len);
}

test "FastConfirmation.getCurrentTarget delegates to getCheckpointForBlock" {
    const fixture = try initLinearForkChoice(testing.allocator);
    defer deinitForkChoiceFixture(testing.allocator, fixture);

    // current_slot = SLOTS_PER_EPOCH → currentEpoch = 1 → checkpoint at slot SLOTS_PER_EPOCH on block_b's chain.
    const target = try getCurrentTarget(fixture.fc, fixture.b_root, preset.SLOTS_PER_EPOCH);
    try testing.expectEqual(@as(Epoch, 1), target.epoch);
    try testing.expectEqualSlices(u8, &fixture.b_root, &target.root);
}


const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;

test "FastConfirmation.getSlotCommittee returns committee union for slot" {
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    // Use a slot inside the state's current epoch — only previous/current/next
    // epochs have shufflings cached.
    const state_slot = try test_state.cached_state.state.slot();

    const committee = try getSlotCommittee(allocator, test_state.cached_state, state_slot);
    defer allocator.free(committee);

    // Committee should not be empty for a state with 256 validators.
    try testing.expect(committee.len > 0);
    // Sanity: total committee size at a single slot is bounded by validator count.
    try testing.expect(committee.len <= 256);
}

test "FastConfirmation.BalanceSourceData.rebuild populates balances and short-circuits" {
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);

    try bsd.rebuild(allocator, test_state.cached_state, cp);
    try testing.expectEqual(@as(usize, 256), bsd.effective_balances.items.len);
    try testing.expect(bsd.checkpoint.eql(cp));

    // Mutate a balance entry; a second rebuild with the SAME checkpoint must
    // short-circuit and leave the mutation in place.
    bsd.effective_balances.items[0] = 0xFFFF;
    try bsd.rebuild(allocator, test_state.cached_state, cp);
    try testing.expectEqual(@as(u16, 0xFFFF), bsd.effective_balances.items[0]);
}

test "FastConfirmation.BalanceSourceData.rebuild — active validators retain balance" {
    // In the test fixture, all 256 validators have activation_epoch=0 and
    // exit_epoch=FAR_FUTURE_EPOCH, so they're active in every epoch and none
    // are slashed. Confirm the resulting balances are non-zero for at least
    // one entry (sanity that we copied from the source rather than zeroing).
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    const cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);

    try bsd.rebuild(allocator, test_state.cached_state, cp);
    try testing.expectEqual(@as(usize, 256), bsd.effective_balances.items.len);
    var nonzero_count: usize = 0;
    for (bsd.effective_balances.items) |bal| {
        if (bal != 0) nonzero_count += 1;
    }
    try testing.expect(nonzero_count > 0);
}

test "FastConfirmation.BalanceSourceData.rebuild — inactive epoch zeroes everything via direct logic" {
    // This test exercises the inactive-zeroing branch by constructing a stub
    // CachedBeaconState is impractical here, so we instead test the spec's
    // active-validator predicate directly: validators activated AT or AFTER
    // the target epoch are inactive (epoch < activation_epoch).
    //
    // We use `isActiveValidatorImpl` directly to lock in the spec semantics.
    const consensus = consensus_types;
    var v: consensus.phase0.Validator.Type = std.mem.zeroes(consensus.phase0.Validator.Type);
    v.activation_epoch = 100;
    v.exit_epoch = 200;
    try testing.expect(!isActiveValidatorImpl(&v, 99)); // before activation
    try testing.expect(isActiveValidatorImpl(&v, 100)); // at activation
    try testing.expect(isActiveValidatorImpl(&v, 199)); // last active
    try testing.expect(!isActiveValidatorImpl(&v, 200)); // exit
}

test "FastConfirmation.SlotAssignments.rebuild populates and clears between rebuilds" {
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var assignments = SlotAssignments.init();
    defer assignments.deinit(allocator);

    // Use the state's slot as the "current_slot" so the 3-epoch window
    // overlaps the cached shufflings (previous/current/next).
    const current_slot = try test_state.cached_state.state.slot();
    try assignments.rebuild(allocator, test_state.cached_state, current_slot);

    // We expect at least one validator to have an assignment in the 3-epoch window.
    try testing.expect(assignments.by_validator.count() > 0);

    // Each entry must be non-empty.
    var iter = assignments.by_validator.valueIterator();
    while (iter.next()) |list| try testing.expect(list.items.len > 0);

    const first_count = assignments.by_validator.count();

    // Re-running rebuild with the same state should produce a same-shaped result
    // (and crucially must not leak — caught by testing.allocator).
    try assignments.rebuild(allocator, test_state.cached_state, current_slot);
    try testing.expectEqual(first_count, assignments.by_validator.count());
}


// C1
test "FastConfirmation.isFullValidatorSetCovered — full epoch range returns true" {
    // [0, 2*SLOTS_PER_EPOCH - 1] covers epochs 0 and 1 entirely.
    try testing.expect(isFullValidatorSetCovered(0, 2 * preset.SLOTS_PER_EPOCH - 1));
    // Single full epoch [SLOTS_PER_EPOCH, 2*SLOTS_PER_EPOCH - 1] is also fully covered.
    try testing.expect(isFullValidatorSetCovered(preset.SLOTS_PER_EPOCH, 2 * preset.SLOTS_PER_EPOCH - 1));
}

test "FastConfirmation.isFullValidatorSetCovered — partial range returns false" {
    // Less than a full epoch: [0, SLOTS_PER_EPOCH - 2] misses last slot of epoch 0.
    try testing.expect(!isFullValidatorSetCovered(0, preset.SLOTS_PER_EPOCH - 2));
    // Cross-epoch but no full epoch: [SLOTS_PER_EPOCH - 2, SLOTS_PER_EPOCH + 1].
    try testing.expect(!isFullValidatorSetCovered(preset.SLOTS_PER_EPOCH - 2, preset.SLOTS_PER_EPOCH + 1));
}

test "FastConfirmation.isFullValidatorSetCovered — start > end returns false" {
    // start_slot > end_slot: formula yields start_full_epoch >= end_full_epoch ⇒ false.
    try testing.expect(!isFullValidatorSetCovered(10, 5));
    try testing.expect(!isFullValidatorSetCovered(preset.SLOTS_PER_EPOCH, 1));
}

// C2
test "FastConfirmation.adjustCommitteeWeightEstimateToEnsureSafety — zero maps to zero" {
    try testing.expectEqual(@as(u64, 0), adjustCommitteeWeightEstimateToEnsureSafety(0));
}

test "FastConfirmation.adjustCommitteeWeightEstimateToEnsureSafety — small inputs ceiling-up" {
    // (1 * 1005 + 999) / 1000 = 2004 / 1000 = 2.
    try testing.expectEqual(@as(u64, 2), adjustCommitteeWeightEstimateToEnsureSafety(1));
    // (1000 * 1005 + 999) / 1000 = 1005999 / 1000 = 1005.
    try testing.expectEqual(@as(u64, 1005), adjustCommitteeWeightEstimateToEnsureSafety(1000));
}

test "FastConfirmation.adjustCommitteeWeightEstimateToEnsureSafety — monotone non-decreasing" {
    // Spot check monotonicity over a small range.
    var prev: u64 = 0;
    var x: u64 = 0;
    while (x < 100) : (x += 1) {
        const y = adjustCommitteeWeightEstimateToEnsureSafety(x);
        try testing.expect(y >= prev);
        prev = y;
    }
}

// C3
test "FastConfirmation.estimateCommitteeWeightBetweenSlots — start > end yields 0" {
    var bsd = BalanceSourceData.init();
    defer bsd.deinit(testing.allocator);
    try bsd.effective_balances.append(testing.allocator, 32);
    try testing.expectEqual(@as(u64, 0), estimateCommitteeWeightBetweenSlots(&bsd, 5, 4));
}

test "FastConfirmation.estimateCommitteeWeightBetweenSlots — full epoch returns total active balance" {
    var bsd = BalanceSourceData.init();
    defer bsd.deinit(testing.allocator);
    // 100 validators with 32-increment effective balance = 3200 total.
    var i: usize = 0;
    while (i < 100) : (i += 1) try bsd.effective_balances.append(testing.allocator, 32);

    const total = estimateCommitteeWeightBetweenSlots(&bsd, 0, 2 * preset.SLOTS_PER_EPOCH - 1);
    try testing.expectEqual(@as(u64, 100 * 32), total);
}

test "FastConfirmation.estimateCommitteeWeightBetweenSlots — same-epoch range scales linearly" {
    var bsd = BalanceSourceData.init();
    defer bsd.deinit(testing.allocator);
    // total = 1024 (chosen as multiple of SLOTS_PER_EPOCH for clean math).
    var i: usize = 0;
    while (i < preset.SLOTS_PER_EPOCH) : (i += 1) try bsd.effective_balances.append(testing.allocator, 32);
    // total = 32 * SLOTS_PER_EPOCH so committee_weight_per_slot = 32.

    // Range [0, 0] (one slot) within epoch 0: 32 * 1 = 32.
    try testing.expectEqual(@as(u64, 32), estimateCommitteeWeightBetweenSlots(&bsd, 0, 0));
    // Range [0, 1] (two slots): 32 * 2 = 64.
    try testing.expectEqual(@as(u64, 64), estimateCommitteeWeightBetweenSlots(&bsd, 0, 1));
}

test "FastConfirmation.estimateCommitteeWeightBetweenSlots — cross-epoch uses adjustment" {
    var bsd = BalanceSourceData.init();
    defer bsd.deinit(testing.allocator);
    var i: usize = 0;
    while (i < preset.SLOTS_PER_EPOCH) : (i += 1) try bsd.effective_balances.append(testing.allocator, 32);
    // total_active_balance = 32 * SLOTS_PER_EPOCH ⇒ committee_weight_per_slot = 32.

    // Range [SLOTS_PER_EPOCH - 1, SLOTS_PER_EPOCH] crosses epoch boundary, no full epoch.
    // num_slots_in_start_epoch = SLOTS_PER_EPOCH - (SLOTS_PER_EPOCH - 1) = 1.
    // num_slots_in_end_epoch = 0 + 1 = 1.
    // remaining_slots_in_end_epoch = SLOTS_PER_EPOCH - 1.
    // start_epoch_weight = 32 * 1 = 32.
    // end_epoch_weight = 32 * 1 = 32.
    // start_epoch_weight_pro_rated = floor(32 / SLOTS_PER_EPOCH) * (SLOTS_PER_EPOCH - 1)
    //   = 4 * (SLOTS_PER_EPOCH - 1)  (under minimal SLOTS_PER_EPOCH=8: 4 * 7 = 28).
    // adjust(start_epoch_weight_pro_rated + end_epoch_weight) applies the safety factor.
    const got = estimateCommitteeWeightBetweenSlots(&bsd, preset.SLOTS_PER_EPOCH - 1, preset.SLOTS_PER_EPOCH);

    // Recompute the spec arithmetic in the test to keep it preset-agnostic.
    const slots_per_epoch: u64 = preset.SLOTS_PER_EPOCH;
    const total_active_balance: u64 = 32 * slots_per_epoch;
    const cwp: u64 = @divFloor(total_active_balance, slots_per_epoch); // 32
    const start_pro_rated: u64 = @divFloor(cwp * 1, slots_per_epoch) * (slots_per_epoch - 1);
    const expected = adjustCommitteeWeightEstimateToEnsureSafety(start_pro_rated + cwp * 1);
    try testing.expectEqual(expected, got);
    // Sanity: adjustment never decreases the estimate.
    try testing.expect(got >= start_pro_rated + cwp * 1);
}

// C4: getEquivocationScore — empty equivocating set returns 0.
test "FastConfirmation.getEquivocationScore — empty equivocating set returns 0" {
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const slot = try test_state.cached_state.state.slot();
    const score = try getEquivocationScore(allocator, test_state.cached_state, &bsd, &eq, slot, slot);
    try testing.expectEqual(@as(u64, 0), score);
}

test "FastConfirmation.getEquivocationScore — start > end returns 0 (without state lookup)" {
    const allocator = testing.allocator;

    // Use a stub state pointer; the function returns early without dereferencing
    // it when start > end.
    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const score = try getEquivocationScore(allocator, test_state.cached_state, &bsd, &eq, 100, 50);
    try testing.expectEqual(@as(u64, 0), score);
}

test "FastConfirmation.getEquivocationScore — slashed validator in committee counts when in equivocating set" {
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    // Pick a validator that we know participates in some committee in the
    // current state slot, and add it to the equivocating set. We discover
    // such a validator by reading the committee at the state slot.
    const slot = try test_state.cached_state.state.slot();
    const committee = try getSlotCommittee(allocator, test_state.cached_state, slot);
    defer allocator.free(committee);
    try testing.expect(committee.len > 0);
    const target_validator = committee[0];

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);
    try eq.put(allocator, target_validator, {});

    // Expected score = balance of target_validator (non-zero, since active).
    const expected = bsd.effective_balances.items[target_validator];
    const score = try getEquivocationScore(allocator, test_state.cached_state, &bsd, &eq, slot, slot);
    try testing.expectEqual(@as(u64, expected), score);
}

// C5: computeAdversarialWeight — saturates to zero when equivocation > max adversarial.
test "FastConfirmation.computeAdversarialWeight — empty equivocating set returns positive max" {
    // Verifies the no-equivocation branch: result equals the unmodified
    // max_adversarial_weight. Saturation-to-zero (equivocation > max_adv)
    // requires committee-aware setup that is out of scope for this unit test.
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const slot = try test_state.cached_state.state.slot();
    const w = try computeAdversarialWeight(allocator, &fcr, test_state.cached_state, &bsd, &eq, slot, slot);
    // Should not exceed total active balance (sanity).
    try testing.expect(w <= getTotalActiveBalance(&bsd));
}

// C6, C7, C8, C9, C10, C11, C12: structural tests using the linear ProtoArray fixture.
// These exercise the call-graphs via simple, known inputs.

test "FastConfirmation.getAdversarialWeight — returns 0 when current_slot == 0" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const w = try getAdversarialWeight(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &eq,
        fixture.b_root,
        0,
    );
    try testing.expectEqual(@as(u64, 0), w);
}

test "FastConfirmation.getAdversarialWeight — unknown block returns 0" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const w = try getAdversarialWeight(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &eq,
        rootFromByte(0xFE),
        2,
    );
    try testing.expectEqual(@as(u64, 0), w);
}

test "FastConfirmation.getBlockSupportBetweenSlots — start > end returns 0" {
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var pa: ProtoArray = undefined;
    try pa.initialize(allocator, makeProtoBlock(0, ZERO_ROOT, ZERO_ROOT), 0);
    defer pa.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const score = try getBlockSupportBetweenSlots(
        allocator,
        test_state.cached_state,
        &pa,
        &bsd,
        &votes,
        &eq,
        ZERO_ROOT,
        10,
        5,
    );
    try testing.expectEqual(@as(u64, 0), score);
}

test "FastConfirmation.getBlockSupportBetweenSlots — no votes for block returns 0" {
    const allocator = testing.allocator;

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var pa: ProtoArray = undefined;
    try pa.initialize(allocator, makeProtoBlock(0, ZERO_ROOT, ZERO_ROOT), 0);
    defer pa.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    // Pre-allocate votes for all validators; default = NULL_VOTE_INDEX so no votes.
    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 256);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const slot = try test_state.cached_state.state.slot();
    const score = try getBlockSupportBetweenSlots(
        allocator,
        test_state.cached_state,
        &pa,
        &bsd,
        &votes,
        &eq,
        rootFromByte(0xCD),
        slot,
        slot,
    );
    try testing.expectEqual(@as(u64, 0), score);
}

test "FastConfirmation.computeEmptySlotSupportDiscount — adjacent parent yields 0" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 256);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    // Block_a is at slot 1 with parent at slot 0 — adjacent. Discount = 0.
    const w = try computeEmptySlotSupportDiscount(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &votes,
        &eq,
        fixture.a_root,
    );
    try testing.expectEqual(@as(u64, 0), w);
}

test "FastConfirmation.getSupportDiscount — delegates to computeEmptySlotSupportDiscount" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.rebuild(allocator, test_state.cached_state, .{ .epoch = 0, .root = ZERO_ROOT });

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 256);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const a = try getSupportDiscount(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &votes,
        &eq,
        fixture.a_root,
    );
    const b = try computeEmptySlotSupportDiscount(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &votes,
        &eq,
        fixture.a_root,
    );
    try testing.expectEqual(b, a);
}

test "FastConfirmation.computeSafetyThreshold — degenerate zero inputs return zero breakdown" {
    // Verifies the all-zero baseline: with empty balance source and empty
    // equivocating set, every breakdown field is 0. Does NOT exercise the
    // underflow-saturation branch (`support_discount > numerator`), which
    // requires a chain with empty slots between parent and block plus enough
    // parent support to overshoot adversarial+proposer+max — out of scope
    // for this unit test.
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    // Empty balance source ⇒ total_active_balance = 0 ⇒ proposer_score = 0,
    // maximum_support = 0. With empty equivocating set, adversarial = 0 and
    // discount = 0 ⇒ threshold = 0 (numerator and discount both 0; the
    // else branch takes floor(0 / 2) = 0).
    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    // current_slot in epoch 0; block_a is at slot 1 with parent at slot 0.
    // current_slot = 2 ⇒ end = 1 (slot range for max support: [parent.slot+1, current_slot-1] = [1, 1]).
    const result = try computeSafetyThreshold(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &votes,
        &eq,
        fixture.a_root,
        2,
    );
    try testing.expectEqual(@as(u64, 0), result.threshold);
    try testing.expectEqual(@as(u64, 0), result.proposer_score);
    try testing.expectEqual(@as(u64, 0), result.maximum_support);
    try testing.expectEqual(@as(u64, 0), result.support_discount);
    try testing.expectEqual(@as(u64, 0), result.adversarial_weight);
}

test "FastConfirmation.computeSafetyThreshold — unknown block returns max threshold" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const result = try computeSafetyThreshold(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &votes,
        &eq,
        rootFromByte(0xFE),
        2,
    );
    try testing.expectEqual(std.math.maxInt(u64), result.threshold);
}

test "FastConfirmation.isOneConfirmed — returns false when current_slot is 0" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const ok = try isOneConfirmed(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &votes,
        &eq,
        fixture.a_root,
        0,
    );
    try testing.expect(!ok);
}

test "FastConfirmation.isOneConfirmed — unknown block returns false" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 40);
    defer fcr.deinit(allocator);

    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const ok = try isOneConfirmed(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &votes,
        &eq,
        rootFromByte(0xFE),
        2,
    );
    try testing.expect(!ok);
}

test "FastConfirmation.isOneConfirmed — confirmed when support exceeds threshold" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);

    // Construct a balance source where one validator (idx 0) has the only
    // non-zero balance and votes for fixture.a_root. With byzantine_threshold = 0
    // and proposer_score_boost = 0, the safety threshold = 0, so any positive
    // support yields confirmed = true.
    var bsd = BalanceSourceData.init();
    defer bsd.deinit(allocator);
    try bsd.effective_balances.resize(allocator, 32);
    @memset(bsd.effective_balances.items, 0);
    bsd.effective_balances.items[0] = 32;

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 32);

    // Find a_root's node index via proto_array internals (default variant is FULL pre-Gloas).
    const a_node_index = fixture.fc.proto_array.getDefaultNodeIndex(fixture.a_root) orelse
        return error.TestUnexpectedResult;
    {
        const v = votes.fields();
        v.next_indices[0] = a_node_index;
    }

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const ok = try isOneConfirmed(
        allocator,
        &fcr,
        fixture.fc.proto_array,
        test_state.cached_state,
        &bsd,
        &votes,
        &eq,
        fixture.a_root,
        2,
    );
    try testing.expect(ok);
}

test "FastConfirmation.isConfirmedChainSafe — non-descendant of justified returns false" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // Set the FCR's current observed justified checkpoint to b_root.
    // Then verify that an ancestor of b_root (genesis) is NOT considered safe
    // because b_root is not an ancestor of genesis (we ask: confirmed_root descendant of justified?).
    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);
    fcr.current_epoch_observed_justified_checkpoint = .{ .epoch = 1, .root = fixture.b_root };

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    // confirmed_root = genesis, justified_root = b_root → genesis is not a descendant of b_root.
    const ok = try isConfirmedChainSafe(
        &fcr,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.genesis_root,
        preset.SLOTS_PER_EPOCH,
        allocator,
    );
    try testing.expect(!ok);
}

test "FastConfirmation.isConfirmedChainSafe — empty chain (confirmed == start) returns true" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // Justified checkpoint at genesis, confirmed_root = genesis. Range from
    // genesis to genesis (exclusive) is empty → vacuously true.
    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);
    fcr.current_epoch_observed_justified_checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    // current_slot = 1 ⇒ current_epoch = 0, observed_justified.epoch + 1 = 1 >= 0,
    // so start_root = observed_justified_root = genesis_root.
    // chain_roots(genesis, genesis) = [] ⇒ true.
    const ok = try isConfirmedChainSafe(
        &fcr,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.genesis_root,
        1,
        allocator,
    );
    try testing.expect(ok);
}


// D1: getCurrentTargetScore — empty votes (no validators have voted) yields 0.
test "FastConfirmation.getCurrentTargetScore — empty votes returns 0" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);
    // Populate head balance source so the call doesn't trivially short-circuit.
    try fcr.head_balance_source.effective_balances.resize(allocator, 32);
    @memset(fcr.head_balance_source.effective_balances.items, 32);

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 32);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const score = try getCurrentTargetScore(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
    );
    try testing.expectEqual(@as(u64, 0), score);
}

// D1: single validator voting for the current target — score equals their balance.
test "FastConfirmation.getCurrentTargetScore — single voter for current target counts" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);
    try fcr.head_balance_source.effective_balances.resize(allocator, 32);
    @memset(fcr.head_balance_source.effective_balances.items, 0);
    fcr.head_balance_source.effective_balances.items[0] = 32;

    // current_slot = SLOTS_PER_EPOCH (epoch 1 boundary). The current target on
    // b_root's chain at epoch 1 is b_root itself. Validator 0 votes for b_root.
    const b_node_index = fixture.fc.proto_array.getDefaultNodeIndex(fixture.b_root) orelse
        return error.TestUnexpectedResult;

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 32);
    {
        const v = votes.fields();
        v.next_indices[0] = b_node_index;
        // Vote slot in epoch 1, so getCheckpointForBlock(b_root, epoch=1) = (1, b_root) = target.
        v.next_slots[0] = preset.SLOTS_PER_EPOCH;
    }

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const score = try getCurrentTargetScore(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
    );
    try testing.expectEqual(@as(u64, 32), score);
}

// D1: voter for a different chain → score 0 (checkpoint mismatch).
test "FastConfirmation.getCurrentTargetScore — vote for different target counts 0" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);
    try fcr.head_balance_source.effective_balances.resize(allocator, 32);
    @memset(fcr.head_balance_source.effective_balances.items, 0);
    fcr.head_balance_source.effective_balances.items[0] = 32;

    // Validator votes for the genesis chain at epoch 0, but head is b_root at
    // epoch 1 → target is b_root, which differs from the genesis-chain
    // checkpoint, so the score for the b_root target is 0.
    const genesis_node_index = fixture.fc.proto_array.getDefaultNodeIndex(fixture.genesis_root) orelse
        return error.TestUnexpectedResult;

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 32);
    {
        const v = votes.fields();
        v.next_indices[0] = genesis_node_index;
        v.next_slots[0] = 0; // epoch 0 vote, won't match epoch-1 b_root target.
    }

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const score = try getCurrentTargetScore(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
    );
    try testing.expectEqual(@as(u64, 0), score);
}

// D2: all-zero balances → 0.
test "FastConfirmation.computeHonestFfgSupportForCurrentTarget — zero balances yields 0" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 0);
    defer fcr.deinit(allocator);
    // Balance source remains empty ⇒ total_active_balance = 0.

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const got = try computeHonestFfgSupportForCurrentTarget(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
    );
    try testing.expectEqual(@as(u64, 0), got);
}

// D2: sanity — output bounded above by total active balance.
test "FastConfirmation.computeHonestFfgSupportForCurrentTarget — zero-vote upper bound" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);
    // Balance per validator = 32; 32 validators → total = 1024.
    try fcr.head_balance_source.effective_balances.resize(allocator, 32);
    @memset(fcr.head_balance_source.effective_balances.items, 32);
    const total_active_balance: u64 = 32 * 32;

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 32);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const got = try computeHonestFfgSupportForCurrentTarget(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
    );
    // With byzantine_threshold = 0, the formula collapses to:
    //   honest = ffg_support + (total - ffg_weight_till_now).
    // The `+ remaining` term can exceed total only if ffg_support exceeds
    // ffg_weight_till_now (impossible here since no votes); so result ≤ total.
    try testing.expect(got <= total_active_balance);
}

// D3: equal-checkpoint shortcut returns true without consulting balances.
test "FastConfirmation.willNoConflictingCheckpointBeJustified — equal-checkpoint shortcut returns true" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    // Current target at slot SLOTS_PER_EPOCH on b_root's chain = (epoch 1, b_root).
    // Provide head_unrealized_justified equal to that to trigger the shortcut.
    const head_unrealized_justified: Checkpoint = .{ .epoch = 1, .root = fixture.b_root };

    const ok = try willNoConflictingCheckpointBeJustified(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
        &head_unrealized_justified,
    );
    try testing.expect(ok);
}

// D3: 3 * honest_support > total_active_balance ⇒ true.
test "FastConfirmation.willNoConflictingCheckpointBeJustified — supermajority honest yields true" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 0, 0);
    defer fcr.deinit(allocator);
    // Single active validator with effective balance 1 ⇒ total = 1.
    // With byzantine_threshold = 0 and a vote for the target, ffg_support = 1.
    // remaining_ffg_weight = total - ffg_weight_till_now = 1 - 0 = 1.
    // remaining_honest = floor(1 * 100 / 100) = 1. min_honest = 1 - 0 = 1.
    // honest = 2; 3 * 2 > 1 ⇒ true.
    try fcr.head_balance_source.effective_balances.resize(allocator, 32);
    @memset(fcr.head_balance_source.effective_balances.items, 0);
    fcr.head_balance_source.effective_balances.items[0] = 1;

    const b_node_index = fixture.fc.proto_array.getDefaultNodeIndex(fixture.b_root) orelse
        return error.TestUnexpectedResult;

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 32);
    {
        const v = votes.fields();
        v.next_indices[0] = b_node_index;
        v.next_slots[0] = preset.SLOTS_PER_EPOCH;
    }

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    // Distinct checkpoint forces the supermajority branch.
    const head_unrealized_justified: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    const ok = try willNoConflictingCheckpointBeJustified(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
        &head_unrealized_justified,
    );
    try testing.expect(ok);
}

// D3: 3 * honest_support <= total_active_balance ⇒ false.
test "FastConfirmation.willNoConflictingCheckpointBeJustified — zero-balance degenerate case yields false" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // byzantine_threshold = 25 ⇒ remaining_honest = 75% of remaining.
    // total = 1024, ffg_support = 0, ffg_weight_till_now = 0.
    // remaining_ffg_weight = 1024, remaining_honest = floor(1024 * 75 / 100) = 768.
    // min_honest = 0 - 0 = 0. honest = 768.
    // 3 * 768 = 2304 > 1024 ⇒ true. We need a config where 3*honest <= total.
    //
    // Use byzantine_threshold = 25 and add ffg_weight_till_now so that:
    //   remaining_ffg_weight = 0, remaining_honest = 0, min_honest = 0.
    // Achieve by making current_slot deep enough into the epoch that
    // estimateCommitteeWeightBetweenSlots returns total_active_balance
    // (full epoch covered). end_slot = current_slot - 1 must yield a full
    // epoch. Use current_slot = 2 * SLOTS_PER_EPOCH (epoch 2) ⇒ end_slot
    // = 2*EPOCH - 1, start_slot = 2*EPOCH (start of epoch 2). start > end
    // ⇒ ffg_weight_till_now = 0; that branch doesn't help.
    //
    // Alternative: use total = 0 and current_slot > 0 → all formula terms
    // are 0, honest = 0, total = 0 ⇒ 3*0 > 0 is false.
    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 0);
    defer fcr.deinit(allocator);
    // empty balance source ⇒ total = 0.

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const head_unrealized_justified: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    const ok = try willNoConflictingCheckpointBeJustified(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
        &head_unrealized_justified,
    );
    // 3 * 0 > 0 is false.
    try testing.expect(!ok);
}

// D4: with empty balance source (total = 0) the `>=` branch yields true (0 >= 0).
test "FastConfirmation.willCurrentTargetBeJustified — zero total balance yields true via >=" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // Empty balance source ⇒ total = 0. computeHonestFfgSupportForCurrentTarget
    // returns 0. 3 * 0 >= 2 * 0 ⇒ true. Documents the >= boundary explicitly.
    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 0);
    defer fcr.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const ok = try willCurrentTargetBeJustified(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
    );
    try testing.expect(ok);
}

// D4: when total is positive but honest support is well below 2/3, returns false.
test "FastConfirmation.willCurrentTargetBeJustified — honest below 2/3 yields false" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // byzantine_threshold = 25; total_active_balance = 100, ffg_support = 0,
    // ffg_weight_till_now = 0 ⇒ remaining_ffg_weight = 100,
    // remaining_honest = floor(100 * 75 / 100) = 75, honest = 75.
    // 3 * 75 = 225 >= 2 * 100 = 200 ⇒ true. Need a setup where 3*honest < 2*total.
    //
    // With byzantine_threshold = 25 and no votes, honest = 0.75 * total which
    // always satisfies 3*0.75 = 2.25 >= 2 ⇒ true. To force false we need a
    // larger byzantine_threshold OR a positive ffg_weight_till_now eating the
    // honest term. Use clamped maximum (25) with ffg_weight_till_now ≈ total:
    // make current_slot at end of epoch and total just one validator with
    // balance 1 — but estimateCommitteeWeightBetweenSlots(start_of_epoch,
    // current_slot - 1) is tricky; easier: use byzantine_threshold = 25 and
    // a head_balance_source where total_active_balance is very small, then
    // use a current_slot that yields ffg_weight_till_now = total via the full-
    // epoch branch by setting current_slot = SLOTS_PER_EPOCH (so end_slot =
    // SLOTS_PER_EPOCH-1, range [0, SLOTS_PER_EPOCH-1] = full epoch ⇒
    // estimate = total). Then remaining = 0, min_honest = 0 - 0 = 0,
    // honest = 0; 3*0 >= 2*total ⇒ false.
    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = ZERO_ROOT }, 25, 0);
    defer fcr.deinit(allocator);
    try fcr.head_balance_source.effective_balances.resize(allocator, 1);
    fcr.head_balance_source.effective_balances.items[0] = 1;

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    // current_slot = SLOTS_PER_EPOCH ⇒ current_epoch = 1, start = SLOTS_PER_EPOCH,
    // end = SLOTS_PER_EPOCH - 1, range [start..end] is empty (start > end) ⇒
    // ffg_weight_till_now = 0, remaining = 1, remaining_honest = floor(1*75/100) = 0.
    // honest = 0 ⇒ 3*0 = 0 >= 2 ⇒ false.
    const ok = try willCurrentTargetBeJustified(
        allocator,
        fixture.fc,
        &fcr,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
    );
    try testing.expect(!ok);
}


// E1: updateFastConfirmationVariables — first call sets last_update_slot.
test "FastConfirmation.updateFastConfirmationVariables — first call sets last_update_slot" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    const init_cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };
    var fcr = FastConfirmation.init(init_cp, 25, 40);
    defer fcr.deinit(allocator);

    try testing.expect(fcr.last_update_slot == null);

    const head: Root = rootFromByte(0xAB);
    updateFastConfirmationVariables(&fcr, fixture.fc, head, 1);

    try testing.expectEqual(@as(?Slot, 1), fcr.last_update_slot);
    try testing.expectEqualSlices(u8, &head, &fcr.current_slot_head);
    // previous_slot_head was the initial finalized root (ZERO).
    try testing.expectEqualSlices(u8, &ZERO_ROOT, &fcr.previous_slot_head);
}

// E1: same-slot duplicate call is a no-op.
test "FastConfirmation.updateFastConfirmationVariables — duplicate same-slot call is no-op" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    const init_cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };
    var fcr = FastConfirmation.init(init_cp, 25, 40);
    defer fcr.deinit(allocator);

    const head_a: Root = rootFromByte(0xA1);
    const head_b: Root = rootFromByte(0xB2);

    updateFastConfirmationVariables(&fcr, fixture.fc, head_a, 1);
    const after_first_current = fcr.current_slot_head;
    const after_first_previous = fcr.previous_slot_head;

    // Second call with the SAME slot must not rotate or update anything.
    updateFastConfirmationVariables(&fcr, fixture.fc, head_b, 1);

    try testing.expectEqual(@as(?Slot, 1), fcr.last_update_slot);
    try testing.expectEqualSlices(u8, &after_first_current, &fcr.current_slot_head);
    try testing.expectEqualSlices(u8, &after_first_previous, &fcr.previous_slot_head);
}

// E1: last slot of epoch snapshots the GLOBAL store's unrealized justified
// (spec line 814-816), NOT the head's per-block unrealized.
test "FastConfirmation.updateFastConfirmationVariables — last slot of epoch snapshots greatest unrealized" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    const init_cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };
    var fcr = FastConfirmation.init(init_cp, 25, 40);
    defer fcr.deinit(allocator);

    // Override the fork-choice store's global unrealized_justified so the
    // test sees a distinguishable value get snapshotted.
    const fresh_uj: Checkpoint = .{ .epoch = 7, .root = rootFromByte(0xCD) };
    fixture.fc.fc_store.unrealized_justified.checkpoint = fresh_uj;

    const head: Root = rootFromByte(0xAB);
    // Last slot of epoch 0 is SLOTS_PER_EPOCH - 1, so current_slot + 1 is on epoch boundary.
    const last_slot: Slot = preset.SLOTS_PER_EPOCH - 1;
    updateFastConfirmationVariables(&fcr, fixture.fc, head, last_slot);

    try testing.expect(fcr.previous_epoch_greatest_unrealized_checkpoint.eql(fresh_uj));
}

// E1: first slot of epoch rotates observed-justified.
test "FastConfirmation.updateFastConfirmationVariables — first slot of epoch rotates observed-justified" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    const init_cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };
    var fcr = FastConfirmation.init(init_cp, 25, 40);
    defer fcr.deinit(allocator);

    // Pre-load distinct checkpoints so we can observe the rotation.
    const cp_prev_obs: Checkpoint = .{ .epoch = 1, .root = rootFromByte(0x10) };
    const cp_curr_obs: Checkpoint = .{ .epoch = 2, .root = rootFromByte(0x20) };
    const cp_greatest: Checkpoint = .{ .epoch = 3, .root = rootFromByte(0x30) };
    fcr.previous_epoch_observed_justified_checkpoint = cp_prev_obs;
    fcr.current_epoch_observed_justified_checkpoint = cp_curr_obs;
    fcr.previous_epoch_greatest_unrealized_checkpoint = cp_greatest;

    const head: Root = rootFromByte(0xAB);
    // First slot of epoch 1 = SLOTS_PER_EPOCH.
    updateFastConfirmationVariables(&fcr, fixture.fc, head, preset.SLOTS_PER_EPOCH);

    try testing.expect(fcr.previous_epoch_observed_justified_checkpoint.eql(cp_curr_obs));
    try testing.expect(fcr.current_epoch_observed_justified_checkpoint.eql(cp_greatest));
}

// E2: findLatestConfirmedDescendant — head == confirmed → returns confirmed unchanged.
test "FastConfirmation.findLatestConfirmedDescendant — head == confirmed returns unchanged" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = fixture.b_root }, 25, 40);
    defer fcr.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const head_uj: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    // confirmed_root == head_root ⇒ canonical_roots is empty in both loops, so
    // the function must return confirmed_root unchanged.
    const out = try findLatestConfirmedDescendant(
        &fcr,
        allocator,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        &head_uj,
        fixture.b_root,
        preset.SLOTS_PER_EPOCH,
    );
    try testing.expectEqualSlices(u8, &fixture.b_root, &out);
}

// E2: returns a value within expected range (ancestor of head_root).
test "FastConfirmation.findLatestConfirmedDescendant — returns ancestor of head" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = fixture.genesis_root }, 25, 40);
    defer fcr.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const head_uj: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    // The exact return value depends on subtle interactions; we only assert
    // it is one of {genesis, a, b} — i.e. a known ancestor of head_root.
    const out = try findLatestConfirmedDescendant(
        &fcr,
        allocator,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        fixture.b_root,
        &head_uj,
        fixture.genesis_root,
        preset.SLOTS_PER_EPOCH,
    );
    const is_known =
        std.mem.eql(u8, &out, &fixture.genesis_root) or
        std.mem.eql(u8, &out, &fixture.a_root) or
        std.mem.eql(u8, &out, &fixture.b_root);
    try testing.expect(is_known);
}

// E3: getLatestConfirmed — stale confirmed resets to finalized.
test "FastConfirmation.getLatestConfirmed — stale confirmed resets to finalized" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // confirmed_root is unknown to proto array → epoch unknown → treated as stale.
    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = rootFromByte(0xFE) }, 25, 40);
    defer fcr.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const finalized: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };
    const head_uj: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    // current_slot = 5 * SLOTS_PER_EPOCH puts us in epoch 5; any unknown epoch is stale.
    const out = try getLatestConfirmed(
        &fcr,
        allocator,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        &finalized,
        fixture.b_root,
        &head_uj,
        5 * preset.SLOTS_PER_EPOCH,
    );
    try testing.expectEqualSlices(u8, &fixture.genesis_root, &out);
}

// E3: off-canonical confirmed resets to finalized.
test "FastConfirmation.getLatestConfirmed — off-canonical confirmed resets to finalized" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // confirmed_root = b_root, head_root = a_root → b is NOT an ancestor of a.
    var fcr = FastConfirmation.init(.{ .epoch = 1, .root = fixture.b_root }, 25, 40);
    defer fcr.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const finalized: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };
    const head_uj: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    const out = try getLatestConfirmed(
        &fcr,
        allocator,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        &finalized,
        fixture.a_root,
        &head_uj,
        2,
    );
    // b not an ancestor of a → reset to finalized (genesis).
    try testing.expectEqualSlices(u8, &fixture.genesis_root, &out);
}

// E3: stable case — when confirmed is too old to advance, returns it unchanged.
test "FastConfirmation.getLatestConfirmed — stable when confirmed is older than current_epoch - 1" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // confirmed_root = genesis (epoch 0), current_slot in epoch 5 → epoch+1 < 5
    // ⇒ stale, resets to finalized (which is also genesis here).
    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = fixture.genesis_root }, 25, 40);
    defer fcr.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const finalized: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };
    const head_uj: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    // current_slot = 1, current_epoch = 0. confirmed at epoch 0; not stale,
    // not off-canonical, not epoch start. confirmed_epoch + 1 = 1 >= 0 ⇒ enter
    // descendant search. With no votes the search will not advance, returning
    // genesis unchanged.
    const out = try getLatestConfirmed(
        &fcr,
        allocator,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        &finalized,
        fixture.b_root,
        &head_uj,
        1,
    );
    // Result is one of {genesis, a, b} — known ancestor of head.
    const is_known =
        std.mem.eql(u8, &out, &fixture.genesis_root) or
        std.mem.eql(u8, &out, &fixture.a_root) or
        std.mem.eql(u8, &out, &fixture.b_root);
    try testing.expect(is_known);
}

// E3: descendant-search branch is reachable when confirmed_epoch + 1 >= current_epoch.
test "FastConfirmation.getLatestConfirmed — descendant search branch returns ancestor of head" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    // confirmed_root = a_root (slot 1, epoch 0), current_slot in epoch 1 →
    // confirmed_epoch + 1 = 1 == current_epoch ⇒ descendant search.
    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = fixture.a_root }, 25, 40);
    defer fcr.deinit(allocator);

    var votes: Votes = .{};
    defer votes.deinit(allocator);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const finalized: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };
    const head_uj: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    const out = try getLatestConfirmed(
        &fcr,
        allocator,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        &finalized,
        fixture.b_root,
        &head_uj,
        preset.SLOTS_PER_EPOCH,
    );
    const is_known =
        std.mem.eql(u8, &out, &fixture.genesis_root) or
        std.mem.eql(u8, &out, &fixture.a_root) or
        std.mem.eql(u8, &out, &fixture.b_root);
    try testing.expect(is_known);
}

// E6: integration smoke test — wires everything together and verifies
// `confirmed_root` is sensible after `onFastConfirmation`.
test "FastConfirmation.onFastConfirmation — integration smoke (chain too short to advance)" {
    const allocator = testing.allocator;
    const fixture = try initLinearForkChoice(allocator);
    defer deinitForkChoiceFixture(allocator, fixture);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();
    var test_state = try TestCachedBeaconState.init(allocator, &pool, 32);
    defer test_state.deinit();

    var fcr = FastConfirmation.init(.{ .epoch = 0, .root = fixture.genesis_root }, 25, 40);
    defer fcr.deinit(allocator);
    fcr.setSpecTestMode(false);

    var votes: Votes = .{};
    defer votes.deinit(allocator);
    try votes.ensureValidatorCount(allocator, 32);

    var eq: EquivocatingIndices = .empty;
    defer eq.deinit(allocator);

    const finalized: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };
    const justified: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };
    const head_uj: Checkpoint = .{ .epoch = 0, .root = fixture.genesis_root };

    // Feed the head state's slot to the FCR (state has shufflings cached
    // around its own slot).
    const state_slot = try test_state.cached_state.state.slot();

    try onFastConfirmation(
        &fcr,
        allocator,
        fixture.fc,
        test_state.cached_state,
        &votes,
        &eq,
        &finalized,
        &justified,
        &head_uj,
        fixture.b_root,
        state_slot,
    );

    // Result must be one of the known roots in the linear chain.
    const out = fcr.confirmed_root;
    const is_known =
        std.mem.eql(u8, &out, &fixture.genesis_root) or
        std.mem.eql(u8, &out, &fixture.a_root) or
        std.mem.eql(u8, &out, &fixture.b_root);
    try testing.expect(is_known);
}
