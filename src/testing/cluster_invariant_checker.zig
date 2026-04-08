//! Cross-node consensus invariant checker for multi-node simulation.
//!
//! Verifies multi-node safety, liveness, and consistency invariants
//! that a single-node checker cannot observe:
//!   - SAFETY: No two nodes disagree on finalized blocks.
//!   - LIVENESS: Finality progresses within bounded time.
//!   - CONSISTENCY: Nodes processing the same blocks produce identical state roots.

const std = @import("std");
const Allocator = std.mem.Allocator;
const preset = @import("preset").preset;

pub const ClusterInvariantChecker = struct {
    /// Info about the last detected state divergence (for test diagnostics).
    pub const DivergenceInfo = struct {
        slot: u64 = 0,
        node_a: u8 = 0,
        node_b: u8 = 0,
        root_a: [32]u8 = [_]u8{0} ** 32,
        root_b: [32]u8 = [_]u8{0} ** 32,
    };

    pub const CheckpointObservation = struct {
        epoch: u64 = 0,
        root: [32]u8 = [_]u8{0} ** 32,
    };

    pub const NodeObservation = struct {
        /// Simulation clock slot when this observation was recorded.
        clock_slot: u64,
        /// Node's current head slot.
        head_slot: u64,
        /// Current head block root.
        head_block_root: [32]u8,
        /// Current head state root.
        head_state_root: [32]u8,
        /// Latest finalized checkpoint observed by the node.
        finalized: CheckpointObservation = .{},
        /// Latest justified checkpoint observed by the node.
        justified: CheckpointObservation = .{},
    };

    allocator: Allocator,
    num_nodes: u8,

    /// Per-node observation history, one entry per simulated tick.
    node_observations: []std.ArrayListUnmanaged(NodeObservation),

    /// Per-node finalized epoch (latest known).
    node_finalized_epochs: []u64,

    /// Global maximum finalized epoch observed across all nodes.
    max_finalized_epoch: u64 = 0,

    /// Slot at which max_finalized_epoch last advanced.
    last_finality_advance_slot: u64 = 0,

    /// Maximum observed gap (in slots) between finality advances.
    max_finality_gap_slots: u64 = 0,

    /// Last divergence details (inspectable in tests without stderr output).
    last_divergence: DivergenceInfo = .{},

    /// Number of safety violations detected.
    safety_violations: u64 = 0,

    /// Number of state divergences detected (nodes that received the same
    /// block but produced different state roots).
    state_divergences: u64 = 0,

    /// Number of liveness stalls detected (>4 epochs without finality
    /// advance under normal conditions).
    liveness_stalls: u64 = 0,

    /// Current simulation slot (updated on each tick check).
    current_slot: u64 = 0,

    pub const FinalReport = struct {
        safety_ok: bool,
        liveness_ok: bool,
        max_finality_gap_epochs: u64,
        state_divergences: u64,
        safety_violations: u64,
    };

    pub fn init(allocator: Allocator, num_nodes: u8) !ClusterInvariantChecker {
        const observations = try allocator.alloc(std.ArrayListUnmanaged(NodeObservation), num_nodes);
        for (observations) |*r| r.* = .empty;

        const epochs = try allocator.alloc(u64, num_nodes);
        @memset(epochs, 0);

        return .{
            .allocator = allocator,
            .num_nodes = num_nodes,
            .node_observations = observations,
            .node_finalized_epochs = epochs,
        };
    }

    pub fn deinit(self: *ClusterInvariantChecker) void {
        for (self.node_observations) |*r| r.deinit(self.allocator);
        self.allocator.free(self.node_observations);
        self.allocator.free(self.node_finalized_epochs);
    }

    /// Record a node's full consensus observation after a simulated tick.
    pub fn recordNodeObservation(
        self: *ClusterInvariantChecker,
        node_id: u8,
        observation: NodeObservation,
    ) !void {
        try self.node_observations[node_id].append(self.allocator, observation);
        self.node_finalized_epochs[node_id] = observation.finalized.epoch;
    }

    /// Legacy helper for tests that model head and finalized roots identically.
    pub fn recordNodeState(
        self: *ClusterInvariantChecker,
        node_id: u8,
        slot: u64,
        state_root: [32]u8,
        finalized_epoch: u64,
    ) !void {
        try self.recordNodeObservation(node_id, .{
            .clock_slot = slot,
            .head_slot = slot,
            .head_block_root = state_root,
            .head_state_root = state_root,
            .finalized = .{
                .epoch = finalized_epoch,
                .root = if (finalized_epoch == 0) [_]u8{0} ** 32 else state_root,
            },
            .justified = .{
                .epoch = finalized_epoch,
                .root = if (finalized_epoch == 0) [_]u8{0} ** 32 else state_root,
            },
        });
    }

    pub fn latestObservation(self: *const ClusterInvariantChecker, node_id: u8) ?NodeObservation {
        return self.findLatestObservationForNode(node_id);
    }

    /// Check multi-node invariants after a tick.
    ///
    /// `nodes_that_processed` is a bitmask of which nodes processed the
    /// block this slot (used for consistency checks).
    pub fn checkTick(
        self: *ClusterInvariantChecker,
        slot: u64,
        nodes_that_processed: []const bool,
    ) !void {
        self.current_slot = slot;

        // ── CONSISTENCY: Nodes that processed the same slot must agree ──
        try self.checkConsistency(slot, nodes_that_processed);

        // ── SAFETY: Finalized epochs must agree across nodes ──
        try self.checkSafety();

        // ── LIVENESS: Track finality progress ──
        self.checkLiveness(slot);
    }

    /// CONSISTENCY: All nodes that processed the same slot must have the
    /// same state root at that slot.
    fn checkConsistency(
        self: *ClusterInvariantChecker,
        slot: u64,
        nodes_that_processed: []const bool,
    ) !void {
        var reference_root: ?[32]u8 = null;
        var reference_node: u8 = 0;

        for (0..self.num_nodes) |i| {
            if (!nodes_that_processed[i]) continue;

            // Find this node's state root for the given slot.
            const observation = self.findObservationAtSlot(@intCast(i), slot) orelse continue;
            const root = observation.head_state_root;

            if (reference_root) |ref| {
                if (!std.mem.eql(u8, &ref, &root)) {
                    self.last_divergence = .{
                        .slot = slot,
                        .node_a = reference_node,
                        .node_b = @intCast(i),
                        .root_a = ref,
                        .root_b = root,
                    };
                    self.state_divergences += 1;
                }
            } else {
                reference_root = root;
                reference_node = @intCast(i);
            }
        }
    }

    /// SAFETY: If two nodes share a finalized epoch, they must agree on the
    /// finalized checkpoint root for that epoch.
    fn checkSafety(self: *ClusterInvariantChecker) !void {
        for (0..self.num_nodes) |i| {
            for (i + 1..self.num_nodes) |j| {
                const epoch_i = self.node_finalized_epochs[i];
                const epoch_j = self.node_finalized_epochs[j];

                const common_epoch = @min(epoch_i, epoch_j);
                if (common_epoch == 0) continue;

                const finalized_i = self.findFinalizedCheckpointForEpoch(@intCast(i), common_epoch) orelse continue;
                const finalized_j = self.findFinalizedCheckpointForEpoch(@intCast(j), common_epoch) orelse continue;
                if (!std.mem.eql(u8, &finalized_i.root, &finalized_j.root)) {
                    self.safety_violations += 1;
                }
            }
        }
    }

    /// LIVENESS: Track how long since finality last advanced.
    fn checkLiveness(self: *ClusterInvariantChecker, slot: u64) void {
        // Find the maximum finalized epoch across all nodes.
        var max_epoch: u64 = 0;
        for (self.node_finalized_epochs) |e| {
            max_epoch = @max(max_epoch, e);
        }

        if (max_epoch > self.max_finalized_epoch) {
            // Finality advanced.
            const gap = slot - self.last_finality_advance_slot;
            self.max_finality_gap_slots = @max(self.max_finality_gap_slots, gap);
            self.max_finalized_epoch = max_epoch;
            self.last_finality_advance_slot = slot;
        } else {
            // No finality advance. Check if we've stalled.
            // Stall = >4 epochs without finality.
            const gap = slot - self.last_finality_advance_slot;
            if (gap > 0 and gap % (4 * preset.SLOTS_PER_EPOCH) == 0) {
                self.liveness_stalls += 1;
            }
        }
    }

    /// Look up a node's observation at a specific simulated clock slot.
    fn findObservationAtSlot(
        self: *const ClusterInvariantChecker,
        node_id: u8,
        slot: u64,
    ) ?NodeObservation {
        for (self.node_observations[node_id].items) |entry| {
            if (entry.clock_slot == slot) return entry;
        }
        return null;
    }

    /// Get the latest observation for a node.
    fn findLatestObservationForNode(
        self: *const ClusterInvariantChecker,
        node_id: u8,
    ) ?NodeObservation {
        const items = self.node_observations[node_id].items;
        if (items.len == 0) return null;
        return items[items.len - 1];
    }

    fn findFinalizedCheckpointForEpoch(
        self: *const ClusterInvariantChecker,
        node_id: u8,
        epoch: u64,
    ) ?CheckpointObservation {
        const items = self.node_observations[node_id].items;
        var i = items.len;
        while (i > 0) {
            i -= 1;
            const observation = items[i];
            if (observation.finalized.epoch == epoch) return observation.finalized;
            if (observation.finalized.epoch < epoch) break;
        }
        return null;
    }

    /// Generate a final report summarizing all detected violations.
    pub fn checkFinal(self: *const ClusterInvariantChecker) FinalReport {
        const gap_epochs = self.max_finality_gap_slots / preset.SLOTS_PER_EPOCH;

        return .{
            .safety_ok = self.safety_violations == 0,
            .liveness_ok = self.liveness_stalls == 0,
            .max_finality_gap_epochs = gap_epochs,
            .state_divergences = self.state_divergences,
            .safety_violations = self.safety_violations,
        };
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "ClusterInvariantChecker: init and deinit" {
    var checker = try ClusterInvariantChecker.init(std.testing.allocator, 4);
    defer checker.deinit();

    try std.testing.expectEqual(@as(u8, 4), checker.num_nodes);
    try std.testing.expectEqual(@as(u64, 0), checker.safety_violations);
    try std.testing.expectEqual(@as(u64, 0), checker.state_divergences);
}

test "ClusterInvariantChecker: consistent nodes pass" {
    var checker = try ClusterInvariantChecker.init(std.testing.allocator, 3);
    defer checker.deinit();

    const root = [_]u8{0xAA} ** 32;
    const processed = [_]bool{ true, true, true };

    // All three nodes produce the same root at slot 1.
    try checker.recordNodeState(0, 1, root, 0);
    try checker.recordNodeState(1, 1, root, 0);
    try checker.recordNodeState(2, 1, root, 0);

    try checker.checkTick(1, &processed);
    try std.testing.expectEqual(@as(u64, 0), checker.state_divergences);
}

test "ClusterInvariantChecker: divergent roots detected" {
    var checker = try ClusterInvariantChecker.init(std.testing.allocator, 2);
    defer checker.deinit();

    const root_a = [_]u8{0xAA} ** 32;
    const root_b = [_]u8{0xBB} ** 32;
    const processed = [_]bool{ true, true };

    try checker.recordNodeState(0, 1, root_a, 0);
    try checker.recordNodeState(1, 1, root_b, 0);

    try checker.checkTick(1, &processed);
    try std.testing.expectEqual(@as(u64, 1), checker.state_divergences);
}

test "ClusterInvariantChecker: divergent heads do not imply finalized safety violation" {
    var checker = try ClusterInvariantChecker.init(std.testing.allocator, 2);
    defer checker.deinit();

    const root_a = [_]u8{0xAA} ** 32;
    const root_b = [_]u8{0xBB} ** 32;
    const processed = [_]bool{ true, true };

    try checker.recordNodeState(0, 64, root_a, 2);
    try checker.recordNodeState(1, 64, root_a, 2);
    try checker.checkTick(64, &processed);

    try checker.recordNodeState(0, 65, root_a, 2);
    try checker.recordNodeState(1, 65, root_b, 2);
    try checker.checkTick(65, &processed);

    try std.testing.expectEqual(@as(u64, 1), checker.state_divergences);
    try std.testing.expectEqual(@as(u64, 0), checker.safety_violations);
}

test "ClusterInvariantChecker: final report" {
    var checker = try ClusterInvariantChecker.init(std.testing.allocator, 2);
    defer checker.deinit();

    const root = [_]u8{0xAA} ** 32;
    const processed = [_]bool{ true, true };

    try checker.recordNodeState(0, 1, root, 0);
    try checker.recordNodeState(1, 1, root, 0);
    try checker.checkTick(1, &processed);

    const report = checker.checkFinal();
    try std.testing.expect(report.safety_ok);
    try std.testing.expect(report.liveness_ok);
    try std.testing.expectEqual(@as(u64, 0), report.state_divergences);
}

test "ClusterInvariantChecker: conflicting finalized checkpoints are detected by root" {
    var checker = try ClusterInvariantChecker.init(std.testing.allocator, 2);
    defer checker.deinit();

    const shared_head = [_]u8{0xAA} ** 32;
    const finalized_a = [_]u8{0x11} ** 32;
    const finalized_b = [_]u8{0x22} ** 32;
    const processed = [_]bool{ true, true };

    try checker.recordNodeObservation(0, .{
        .clock_slot = preset.SLOTS_PER_EPOCH * 2,
        .head_slot = preset.SLOTS_PER_EPOCH * 2,
        .head_block_root = shared_head,
        .head_state_root = shared_head,
        .finalized = .{ .epoch = 2, .root = finalized_a },
        .justified = .{ .epoch = 3, .root = shared_head },
    });
    try checker.recordNodeObservation(1, .{
        .clock_slot = preset.SLOTS_PER_EPOCH * 2,
        .head_slot = preset.SLOTS_PER_EPOCH * 2,
        .head_block_root = shared_head,
        .head_state_root = shared_head,
        .finalized = .{ .epoch = 2, .root = finalized_b },
        .justified = .{ .epoch = 3, .root = shared_head },
    });

    try checker.checkTick(preset.SLOTS_PER_EPOCH * 2, &processed);
    try std.testing.expectEqual(@as(u64, 1), checker.safety_violations);
}
