//! Consensus invariant checker for deterministic simulation testing.
//!
//! Verifies that critical consensus invariants hold after every slot and
//! epoch transition.  Also supports deterministic replay verification:
//! two simulation runs with the same seed must produce identical state
//! history.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const AnyBeaconState = @import("fork_types").AnyBeaconState;

pub const StateHistoryEntry = struct {
    slot: u64,
    state_root: [32]u8,
};

pub const InvariantChecker = struct {
    allocator: Allocator,
    /// Monotonically increasing slot tracker.
    last_slot: ?u64 = null,
    /// Finalized epoch must never decrease.
    finalized_epoch: u64 = 0,
    /// Justified epoch must never decrease.
    justified_epoch: u64 = 0,
    /// State root history for deterministic replay comparison.
    state_history: std.ArrayListUnmanaged(StateHistoryEntry) = .empty,

    pub fn init(allocator: Allocator) InvariantChecker {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *InvariantChecker) void {
        self.state_history.deinit(self.allocator);
    }

    /// Check invariants after processing a slot.
    pub fn checkSlot(self: *InvariantChecker, state: *AnyBeaconState) !void {
        const slot = try state.slot();

        // 1. Slot must be monotonically increasing.
        if (self.last_slot) |prev| {
            if (slot <= prev) return error.SlotNotMonotonicallyIncreasing;
        }
        self.last_slot = slot;

        // 2. Compute and record state root.
        const state_root = try state.hashTreeRoot();
        try self.state_history.append(self.allocator, .{
            .slot = slot,
            .state_root = state_root.*,
        });

        // 3. Finalized epoch must never decrease.
        var finalized_cp: types.phase0.Checkpoint.Type = undefined;
        try state.finalizedCheckpoint(&finalized_cp);
        if (finalized_cp.epoch < self.finalized_epoch) return error.FinalizedEpochDecreased;
        self.finalized_epoch = finalized_cp.epoch;

        // 4. Justified epoch must never decrease.
        var justified_cp: types.phase0.Checkpoint.Type = undefined;
        try state.currentJustifiedCheckpoint(&justified_cp);
        if (justified_cp.epoch < self.justified_epoch) return error.JustifiedEpochDecreased;
        self.justified_epoch = justified_cp.epoch;
    }

    /// Verify that two checker instances recorded identical state history.
    /// This is the core determinism assertion: same seed ⇒ same states.
    pub fn verifyDeterminism(self: *const InvariantChecker, other: *const InvariantChecker) !void {
        if (self.state_history.items.len != other.state_history.items.len) {
            return error.DeterminismHistoryLengthMismatch;
        }
        for (self.state_history.items, other.state_history.items) |a, b| {
            if (a.slot != b.slot) return error.DeterminismSlotMismatch;
            if (!std.mem.eql(u8, &a.state_root, &b.state_root)) return error.DeterminismStateRootMismatch;
        }
    }
};
