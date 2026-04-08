//! Scriptable scenario system for deterministic simulation testing.
//!
//! Scenarios are sequences of Steps that describe a specific test case.
//! The SimController executes steps in order, providing deterministic
//! replay of complex network conditions, fault injection, and invariant
//! checking.
//!
//! Built-in scenarios cover common test patterns:
//!   - happy_path: 4 nodes reach finality
//!   - missed_proposals: some proposers skip
//!   - network_partition: split then heal
//!   - late_attestations: delayed attestations
//!   - late_joiner_finalized_sync: reconnect after peers finalize
//!   - short_gap_sync: recover after missing a parent slot
//!   - short_gap_quiescent_sync: recover short-gap unknown head during empty slots
//!   - network_partition_quiescent_recovery: heal then drain to exact head agreement

const std = @import("std");
const preset = @import("preset").preset;

pub const AdvanceUntilCondition = union(enum) {
    finalized_epoch_at_least: u64,
    finality_agreement: void,
    head_agreement: void,
    sync_idle: void,
};

pub const Step = union(enum) {
    /// Advance simulation by one slot (with block production).
    advance_slot: void,
    /// Advance forward by N slots from the current slot.
    advance_slots: u64,
    /// Advance to the first slot of the given absolute epoch.
    advance_to_epoch: u64,
    /// Advance forward by N epochs from the current slot.
    advance_epochs: u64,
    /// Advance until a semantic condition is satisfied or a slot budget is exhausted.
    advance_until: struct {
        condition: AdvanceUntilCondition,
        max_slots: u64,
        produce_blocks: bool = true,
    },
    /// Skip a slot (proposer misses).
    skip_slot: void,
    /// Skip forward by N empty slots.
    skip_slots: u64,
    /// Inject a fault into the simulation.
    inject_fault: Fault,
    /// Check that an invariant holds.
    check_invariant: Invariant,
    /// Create a network partition between two groups.
    network_partition: struct {
        group_a: []const u8,
        group_b: []const u8,
    },
    /// Heal all network partitions.
    heal_partition: void,
    /// Disconnect a node from all others.
    disconnect_node: u8,
    /// Reconnect a previously disconnected node.
    reconnect_node: u8,
    /// Set participation rate for all validators.
    set_participation_rate: f64,
};

pub const Fault = union(enum) {
    // Block production faults
    missed_proposal: usize, // validator/node index misses proposal
    missed_attestation: usize, // validator/node index misses attestation

    // Network faults
    message_delay: struct {
        min_ms: u64,
        max_ms: u64,
    },
    message_drop_rate: f64, // randomly drop N% of messages

    // Node faults
    node_crash: u8, // node stops processing
    node_restart: u8, // node restarts
};

pub const Invariant = union(enum) {
    /// All nodes agree on finalized checkpoint.
    finality_agreement: void,
    /// No safety violations (no two finalized blocks at same slot from different chains).
    safety: void,
    /// Liveness: finalized epoch advances within N epochs.
    liveness: u64,
    /// Fork choice heads are consistent across nodes.
    head_agreement: void,
    /// Head slot is within N of clock.
    head_freshness: u64,
    /// No state divergences detected.
    no_state_divergence: void,
};

pub const Scenario = struct {
    name: []const u8,
    steps: []const Step,
};

// ── Built-in Scenarios ──────────────────────────────────────────────

/// Happy path: advance 5 epochs, check finality and safety.
pub const happy_path = Scenario{
    .name = "happy_path",
    .steps = &happy_path_steps,
};

const happy_path_steps = [_]Step{
    // Set full participation.
    .{ .set_participation_rate = 1.0 },
    .{ .advance_until = .{
        .condition = .{ .finalized_epoch_at_least = 1 },
        .max_slots = 5 * preset.SLOTS_PER_EPOCH,
    } },
    // Check invariants.
    .{ .check_invariant = .safety },
    .{ .check_invariant = .finality_agreement },
    .{ .check_invariant = .{ .head_freshness = 4 } },
    .{ .check_invariant = .no_state_divergence },
};

/// Missed proposals: advance with some skipped slots.
pub const missed_proposals = Scenario{
    .name = "missed_proposals",
    .steps = &missed_proposals_steps,
};

const missed_proposals_steps = [_]Step{
    .{ .set_participation_rate = 1.0 },
    // Normal epoch.
    .{ .advance_epochs = 1 },
    // Skip a few slots.
    .{ .skip_slot = {} },
    .{ .skip_slot = {} },
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    .{ .skip_slot = {} },
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    // Continue normally.
    .{ .advance_epochs = 5 },
    // Verify safety still holds.
    .{ .check_invariant = .safety },
    .{ .check_invariant = .no_state_divergence },
};

/// Network partition under continued block production: split [0,1] from [2,3],
/// run long enough to require real range sync on heal, then verify safety and
/// bounded recovery while the chain keeps moving.
pub const network_partition = Scenario{
    .name = "network_partition",
    .steps = &network_partition_steps,
};

const network_partition_steps = [_]Step{
    .{ .set_participation_rate = 1.0 },
    // Establish baseline.
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    .{ .check_invariant = .head_agreement },
    // Create partition.
    .{ .network_partition = .{
        .group_a = &[_]u8{ 0, 1 },
        .group_b = &[_]u8{ 2, 3 },
    } },
    // Run long enough that healing requires real range-sync catch-up,
    // not just short-gap unknown-parent recovery.
    .{ .advance_slots = preset.SLOTS_PER_EPOCH + 2 },
    // Heal and keep the network running until the nodes re-converge on a
    // single finalized checkpoint.
    .{ .heal_partition = {} },
    .{ .advance_until = .{
        .condition = .finality_agreement,
        .max_slots = 2 * preset.SLOTS_PER_EPOCH,
    } },
    // Verify recovery.
    .{ .check_invariant = .safety },
    .{ .check_invariant = .finality_agreement },
    .{ .check_invariant = .{ .head_freshness = 4 } },
};

/// Network partition with post-heal quiescence: after a short live period to
/// expose the competing head, stop block production long enough for the healed
/// nodes to drain sync and settle on one exact head.
pub const network_partition_quiescent_recovery = Scenario{
    .name = "network_partition_quiescent_recovery",
    .steps = &network_partition_quiescent_recovery_steps,
};

const network_partition_quiescent_recovery_steps = [_]Step{
    .{ .set_participation_rate = 1.0 },
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    .{ .check_invariant = .head_agreement },
    .{ .network_partition = .{
        .group_a = &[_]u8{ 0, 1 },
        .group_b = &[_]u8{ 2, 3 },
    } },
    .{ .advance_slots = preset.SLOTS_PER_EPOCH + 2 },
    .{ .heal_partition = {} },
    // Keep producing briefly so nodes learn about the competing tip.
    .{ .advance_slots = 2 },
    // Then quiesce until linked-chain sync drains and the nodes settle on
    // one exact head, without hard-coding a full epoch wait.
    .{ .advance_until = .{
        .condition = .head_agreement,
        .max_slots = preset.SLOTS_PER_EPOCH + 2,
        .produce_blocks = false,
    } },
    // Resume briefly so the healed network can build on one synchronized head.
    .{ .advance_slots = 2 },
    .{ .check_invariant = .safety },
    .{ .check_invariant = .finality_agreement },
    .{ .check_invariant = .head_agreement },
};

/// Late attestations: start with no attestations, then enable them.
pub const late_attestations = Scenario{
    .name = "late_attestations",
    .steps = &late_attestations_steps,
};

const late_attestations_steps = [_]Step{
    // Phase 1: No attestations.
    .{ .set_participation_rate = 0.0 },
    .{ .advance_epochs = 2 },
    // Phase 2: Full attestations.
    .{ .set_participation_rate = 1.0 },
    .{ .advance_until = .{
        .condition = .{ .finalized_epoch_at_least = 1 },
        .max_slots = 5 * preset.SLOTS_PER_EPOCH,
    } },
    // Safety must hold throughout.
    .{ .check_invariant = .safety },
    .{ .check_invariant = .no_state_divergence },
};

/// Lodestar-style finalized sync: one node joins late after peers already finalized.
pub const late_joiner_finalized_sync = Scenario{
    .name = "late_joiner_finalized_sync",
    .steps = &late_joiner_finalized_sync_steps,
};

const late_joiner_finalized_sync_steps = [_]Step{
    .{ .set_participation_rate = 1.0 },
    .{ .inject_fault = .{ .node_crash = 1 } },
    .{ .advance_slots = preset.SLOTS_PER_EPOCH + 2 },
    .{ .inject_fault = .{ .node_restart = 1 } },
    .{ .advance_until = .{
        .condition = .finality_agreement,
        .max_slots = preset.SLOTS_PER_EPOCH + 4,
    } },
    .{ .check_invariant = .safety },
    .{ .check_invariant = .finality_agreement },
    .{ .check_invariant = .head_agreement },
};

/// Short-gap recovery: a node misses one parent slot, then reconnects and catches up.
pub const short_gap_sync = Scenario{
    .name = "short_gap_sync",
    .steps = &short_gap_sync_steps,
};

const short_gap_sync_steps = [_]Step{
    .{ .set_participation_rate = 1.0 },
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    .{ .disconnect_node = 1 },
    .{ .advance_slot = {} },
    .{ .reconnect_node = 1 },
    .{ .advance_until = .{
        .condition = .head_agreement,
        .max_slots = preset.SLOTS_PER_EPOCH,
    } },
    .{ .check_invariant = .safety },
    .{ .check_invariant = .head_agreement },
};

/// Lodestar-style short-gap recovery without fresh block production after restart:
/// a node misses a few slots, restarts, and catches up via status/by-root sync
/// while subsequent slots are empty so the sync path can drain quiescently.
pub const short_gap_quiescent_sync = Scenario{
    .name = "short_gap_quiescent_sync",
    .steps = &short_gap_quiescent_sync_steps,
};

const short_gap_quiescent_sync_steps = [_]Step{
    .{ .set_participation_rate = 1.0 },
    .{ .advance_slot = {} },
    .{ .advance_slot = {} },
    .{ .inject_fault = .{ .node_crash = 1 } },
    .{ .advance_slots = 3 },
    .{ .inject_fault = .{ .node_restart = 1 } },
    .{ .advance_until = .{
        .condition = .head_agreement,
        .max_slots = preset.SLOTS_PER_EPOCH,
        .produce_blocks = false,
    } },
    .{ .check_invariant = .safety },
    .{ .check_invariant = .head_agreement },
};
