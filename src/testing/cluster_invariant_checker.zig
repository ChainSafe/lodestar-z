//! Cross-node consensus invariant checker for multi-node simulation.
//!
//! Verifies cluster-wide safety, liveness, and consistency invariants
//! that a single-node checker cannot observe:
//!   - SAFETY: No two nodes disagree on finalized blocks.
//!   - LIVENESS: Finality progresses within bounded time.
//!   - CONSISTENCY: Nodes processing the same blocks produce identical state roots.

const std = @import("std");
const Allocator = std.mem.Allocator;


pub const ClusterInvariantChecker = struct {
    /// Info about the last detected state divergence (for test diagnostics).
    pub const DivergenceInfo = struct {
        slot: u64 = 0,
        node_a: u8 = 0,
        node_b: u8 = 0,
        root_a: [32]u8 = [_]u8{0} ** 32,
        root_b: [32]u8 = [_]u8{0} ** 32,
    };

    allocator: Allocator,
    num_nodes: u8,

    /// Per-node state root history indexed by slot offset.
    /// node_state_roots[node_id] is an ArrayList of (slot, root) pairs.
    node_state_roots: []std.ArrayList(SlotRoot),

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

    pub const SlotRoot = struct {
        slot: u64,
        state_root: [32]u8,
    };

    pub const FinalReport = struct {
        safety_ok: bool,
        liveness_ok: bool,
        max_finality_gap_epochs: u64,
        state_divergences: u64,
        safety_violations: u64,
    };

    pub fn init(allocator: Allocator, num_nodes: u8) !ClusterInvariantChecker {
        const roots = try allocator.alloc(std.ArrayList(SlotRoot), num_nodes);
        for (roots) |*r| r.* = .empty;

        const epochs = try allocator.alloc(u64, num_nodes);
        @memset(epochs, 0);

        return .{
            .allocator = allocator,
            .num_nodes = num_nodes,
            .node_state_roots = roots,
            .node_finalized_epochs = epochs,
        };
    }

    pub fn deinit(self: *ClusterInvariantChecker) void {
        for (self.node_state_roots) |*r| r.deinit(self.allocator);
        self.allocator.free(self.node_state_roots);
        self.allocator.free(self.node_finalized_epochs);
    }

    /// Record a node's state root after processing a slot.
    pub fn recordNodeState(
        self: *ClusterInvariantChecker,
        node_id: u8,
        slot: u64,
        state_root: [32]u8,
        finalized_epoch: u64,
    ) !void {
        try self.node_state_roots[node_id].append(self.allocator, .{
            .slot = slot,
            .state_root = state_root,
        });
        self.node_finalized_epochs[node_id] = finalized_epoch;
    }

    /// Check cluster invariants after a tick.
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
            const root = self.findRootAtSlot(@intCast(i), slot) orelse continue;

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

    /// SAFETY: If two nodes both finalized the same epoch, they must agree
    /// on state roots at the epoch boundary slot.
    fn checkSafety(self: *ClusterInvariantChecker) !void {
        for (0..self.num_nodes) |i| {
            for (i + 1..self.num_nodes) |j| {
                const epoch_i = self.node_finalized_epochs[i];
                const epoch_j = self.node_finalized_epochs[j];

                // Find the common finalized epoch.
                const common_epoch = @min(epoch_i, epoch_j);
                if (common_epoch == 0) continue;

                // Both nodes should agree on state roots up to the common
                // finalized epoch.  We check the latest common root.
                const root_i = self.findLatestRootForNode(@intCast(i));
                const root_j = self.findLatestRootForNode(@intCast(j));

                if (root_i != null and root_j != null) {
                    // If both are at the same slot and finalized the same
                    // epoch, their roots must match.
                    if (epoch_i == epoch_j and epoch_i > 0) {
                        const ri = root_i.?;
                        const rj = root_j.?;
                        if (ri.slot == rj.slot and
                            !std.mem.eql(u8, &ri.state_root, &rj.state_root))
                        {
                            self.safety_violations += 1;
                        }
                    }
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
            // Stall = >4 epochs (128 slots with 32 slots/epoch) without finality.
            const gap = slot - self.last_finality_advance_slot;
            if (gap > 0 and gap % 128 == 0) {
                self.liveness_stalls += 1;
            }
        }
    }

    /// Look up a node's state root at a specific slot.
    fn findRootAtSlot(self: *const ClusterInvariantChecker, node_id: u8, slot: u64) ?[32]u8 {
        for (self.node_state_roots[node_id].items) |entry| {
            if (entry.slot == slot) return entry.state_root;
        }
        return null;
    }

    /// Get the latest (slot, root) pair for a node.
    fn findLatestRootForNode(self: *const ClusterInvariantChecker, node_id: u8) ?SlotRoot {
        const items = self.node_state_roots[node_id].items;
        if (items.len == 0) return null;
        return items[items.len - 1];
    }

    /// Generate a final report summarizing all detected violations.
    pub fn checkFinal(self: *const ClusterInvariantChecker) FinalReport {
        // Convert max gap from slots to epochs (32 slots/epoch).
        const gap_epochs = self.max_finality_gap_slots / 32;

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
