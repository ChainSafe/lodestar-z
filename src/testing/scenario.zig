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

const std = @import("std");
const preset = @import("preset").preset;

pub const Step = union(enum) {
    /// Advance simulation by one slot (with block production).
    advance_slot: void,
    /// Advance to the first slot of the given epoch.
    advance_to_epoch: u64,
    /// Skip a slot (proposer misses).
    skip_slot: void,
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
    missed_proposal: usize,            // validator/node index misses proposal
    missed_attestation: usize,         // validator/node index misses attestation

    // Network faults
    message_delay: struct {
        min_ms: u64,
        max_ms: u64,
    },
    message_drop_rate: f64,            // randomly drop N% of messages

    // Node faults
    node_crash: u8,                    // node stops processing
    node_restart: u8,                  // node restarts
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
    // Advance through 5 epochs.
    .{ .advance_to_epoch = 5 },
    // Check invariants.
    .{ .check_invariant = .safety },
    .{ .check_invariant = .finality_agreement },
    .{ .check_invariant = .head_agreement },
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
    .{ .advance_to_epoch = 1 },
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
    .{ .advance_to_epoch = 5 },
    // Verify safety still holds.
    .{ .check_invariant = .safety },
    .{ .check_invariant = .no_state_divergence },
};

/// Network partition: split [0,1] from [2,3], run, heal, verify convergence.
pub const network_partition = Scenario{
    .name = "network_partition",
    .steps = &network_partition_steps,
};

const network_partition_steps = [_]Step{
    .{ .set_participation_rate = 1.0 },
    // Establish baseline.
    .{ .advance_to_epoch = 1 },
    .{ .check_invariant = .head_agreement },
    // Create partition.
    .{ .network_partition = .{
        .group_a = &[_]u8{ 0, 1 },
        .group_b = &[_]u8{ 2, 3 },
    } },
    // Run during partition.
    .{ .advance_to_epoch = 3 },
    // Heal.
    .{ .heal_partition = {} },
    // Recovery.
    .{ .advance_to_epoch = 6 },
    // Verify convergence.
    .{ .check_invariant = .safety },
    .{ .check_invariant = .no_state_divergence },
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
    .{ .advance_to_epoch = 2 },
    // Phase 2: Full attestations.
    .{ .set_participation_rate = 1.0 },
    .{ .advance_to_epoch = 7 },
    // Safety must hold throughout.
    .{ .check_invariant = .safety },
    .{ .check_invariant = .no_state_divergence },
};
