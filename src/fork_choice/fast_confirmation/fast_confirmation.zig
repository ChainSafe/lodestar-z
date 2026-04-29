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

const fork_choice_mod = @import("../fork_choice.zig");
const ForkChoice = fork_choice_mod.ForkChoice;
const ForkChoiceError = fork_choice_mod.ForkChoiceError;

const store_mod = @import("../store.zig");
const Checkpoint = store_mod.Checkpoint;

// =========================================================================
// 1. Errors
// =========================================================================

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

// =========================================================================
// 2. SlotAssignments
// =========================================================================

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
    /// a committee assignment.
    ///
    /// TigerStyle: validator slot range is bounded; outer loop iterates at most
    /// `3 * preset.SLOTS_PER_EPOCH` slots.
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

        // TigerStyle: range is non-empty (≥1 epoch worth of slots) and bounded
        // above by 3 * SLOTS_PER_EPOCH (current + 2 previous).
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

// =========================================================================
// 3. BalanceSourceData
// =========================================================================

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
        // TigerStyle: FCR requires a non-empty validator set; degenerate states
        // are not valid input. Caller must guarantee this.
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

// =========================================================================
// 4. FastConfirmation struct
// =========================================================================

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

    /// Spec range [0, 25]; types match `ChainConfig.CONFIRMATION_BYZANTINE_THRESHOLD` (u64)
    /// and Lighthouse's `byzantine_threshold: u64` to avoid narrowing at every call site.
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

// =========================================================================
// 5. Spec helpers — Misc + State (Phase B)
// =========================================================================

// --- Misc helpers ---

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
/// NOTE: We accept `*const ForkChoice` (Option (a) in plan §B4) so we can
/// reuse `proto_array.getAncestor` without exposing extra accessors.
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

/// Maximum iterations when walking ancestors. TigerStyle limit to fail fast on
/// a corrupted DAG instead of spinning forever.
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

// --- State helpers ---

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

// =========================================================================
// Tests
// =========================================================================

const ZERO_ROOT: Root = [_]u8{0} ** 32;

fn rootFromByte(b: u8) Root {
    var r: Root = ZERO_ROOT;
    r[0] = b;
    return r;
}

// --- Phase A bootstrap tests ---

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

// --- Misc helper tests ---

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

// --- ForkChoice-backed fixture for ancestor walks ---

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

// --- State helpers tests ---

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
