//! Validator Monitor — tracks on-chain performance of monitored validators.
//!
//! Operators configure a list of validator indices to observe. The monitor
//! records attestation inclusion delays, proposal hit/miss, sync committee
//! participation, balance changes, and computes an effectiveness score.
//!
//! Integration points:
//! - `processBlockAttestations()` — called after each imported block
//! - `processBlock()` — called for each imported block (proposer tracking)
//! - `processSyncAggregate()` — called for each imported block (sync tracking)
//! - `onEpochTransition()` — called at epoch boundaries for summary + balance
//!
//! This module has no dependency on the metrics library — it stores raw data
//! that the node layer can scrape into Prometheus gauges/counters.

const std = @import("std");
const scoped_log = std.log.scoped(.validator_monitor);
const Allocator = std.mem.Allocator;
const consensus_types = @import("consensus_types");
const preset = @import("preset").preset;

/// Maximum number of epoch summaries retained in the rolling window.
const DEFAULT_MAX_EPOCHS: u32 = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Per-validator, per-epoch tracking state. Reset at each epoch boundary.
pub const EpochData = struct {
    /// Was an attestation from this validator included in a block?
    attestation_included: bool = false,
    /// Inclusion distance in slots (attestation_slot → inclusion_slot).
    attestation_delay: ?u32 = null,
    /// Did the attestation vote for the correct head?
    attestation_head_correct: bool = false,
    /// Did the attestation vote for the correct source?
    attestation_source_correct: bool = false,
    /// Did the attestation vote for the correct target?
    attestation_target_correct: bool = false,
    /// Did this validator propose a block this epoch?
    block_proposed: bool = false,
    /// Root of the proposed block, if any.
    block_proposed_root: ?[32]u8 = null,
    /// Did this validator participate in the sync committee this epoch?
    sync_committee_participated: bool = false,
    /// Number of sync committee slots where participation was seen.
    sync_participated_count: u32 = 0,
    /// Number of sync committee slots where this validator was expected.
    sync_expected_count: u32 = 0,
};

/// Cumulative statistics for a monitored validator (never reset).
pub const CumulativeStats = struct {
    total_attestations_included: u64 = 0,
    total_attestations_expected: u64 = 0,
    total_head_correct: u64 = 0,
    total_source_correct: u64 = 0,
    total_target_correct: u64 = 0,
    total_blocks_proposed: u64 = 0,
    total_blocks_expected: u64 = 0,
    total_sync_participated: u64 = 0,
    total_sync_expected: u64 = 0,
    total_reward_gwei: i64 = 0,
    /// Inclusion delay histogram: [delay=0, delay=1, delay=2, delay≥3]
    inclusion_delay_histogram: [4]u64 = .{ 0, 0, 0, 0 },
    /// Sum of all inclusion delays (for average calculation).
    inclusion_delay_sum: u64 = 0,
};

/// A monitored validator with current epoch data and cumulative stats.
pub const MonitoredValidator = struct {
    index: u64,
    /// Current epoch tracking (reset each epoch).
    epoch_data: EpochData = .{},
    /// Cumulative statistics (never reset).
    cumulative: CumulativeStats = .{},
    /// Balance tracking.
    balance: u64 = 0,
    effective_balance: u64 = 0,
    /// Balance change vs. previous epoch.
    balance_delta: i64 = 0,

    /// Reset per-epoch fields at epoch boundary.
    pub fn resetEpoch(self: *MonitoredValidator) void {
        self.epoch_data = .{};
    }

    /// Commit current epoch data into cumulative stats.
    pub fn commitEpoch(self: *MonitoredValidator, was_active: bool) void {
        if (!was_active) return;

        // Attestation tracking
        self.cumulative.total_attestations_expected += 1;
        if (self.epoch_data.attestation_included) {
            self.cumulative.total_attestations_included += 1;
            if (self.epoch_data.attestation_head_correct) {
                self.cumulative.total_head_correct += 1;
            }
            if (self.epoch_data.attestation_source_correct) {
                self.cumulative.total_source_correct += 1;
            }
            if (self.epoch_data.attestation_target_correct) {
                self.cumulative.total_target_correct += 1;
            }
            // Inclusion delay histogram
            if (self.epoch_data.attestation_delay) |delay| {
                const bucket: usize = if (delay >= 3) 3 else @intCast(delay);
                self.cumulative.inclusion_delay_histogram[bucket] += 1;
                self.cumulative.inclusion_delay_sum += delay;
            }
        }

        // Block tracking
        if (self.epoch_data.block_proposed) {
            self.cumulative.total_blocks_proposed += 1;
        }

        // Sync committee tracking
        self.cumulative.total_sync_expected += self.epoch_data.sync_expected_count;
        self.cumulative.total_sync_participated += self.epoch_data.sync_participated_count;

        // Balance reward tracking
        self.cumulative.total_reward_gwei += self.balance_delta;
    }
};

/// Per-epoch aggregate summary across all monitored validators.
pub const EpochSummary = struct {
    epoch: u64,
    validators_monitored: u32 = 0,
    attestation_hit_rate: f64 = 0.0,
    head_accuracy_rate: f64 = 0.0,
    source_accuracy_rate: f64 = 0.0,
    target_accuracy_rate: f64 = 0.0,
    avg_inclusion_delay: f64 = 0.0,
    blocks_proposed: u32 = 0,
    blocks_expected: u32 = 0,
    sync_participation_rate: f64 = 0.0,
    total_balance_delta_gwei: i64 = 0,
};

/// JSON-serializable snapshot of a monitored validator's status.
pub const ValidatorSummary = struct {
    index: u64,
    balance_gwei: u64,
    effective_balance_gwei: u64,
    balance_delta_gwei: i64,
    effectiveness_score: f64,
    attestation_included: bool,
    attestation_delay: ?u32,
    head_correct: bool,
    source_correct: bool,
    target_correct: bool,
    block_proposed: bool,
    sync_participated: bool,
    cumulative_reward_gwei: i64,
    total_attestations_included: u64,
    total_attestations_expected: u64,
    inclusion_delay_histogram: [4]u64,
};

// ---------------------------------------------------------------------------
// ValidatorMonitor
// ---------------------------------------------------------------------------

pub const ValidatorMonitor = struct {
    allocator: Allocator,
    /// Monitored validator index → state.
    monitored: std.AutoHashMap(u64, MonitoredValidator),
    /// Rolling epoch summaries (newest at end).
    epoch_summaries: std.ArrayListUnmanaged(EpochSummary) = .empty,
    /// Maximum epoch summaries to retain.
    max_epochs: u32,
    /// Last epoch that was processed.
    last_processed_epoch: ?u64 = null,

    pub fn init(allocator: Allocator, indices: []const u64) ValidatorMonitor {
        var monitored = std.AutoHashMap(u64, MonitoredValidator).init(allocator);
        for (indices) |idx| {
            monitored.put(idx, .{ .index = idx }) catch {};
        }
        return .{
            .allocator = allocator,
            .monitored = monitored,

            .max_epochs = DEFAULT_MAX_EPOCHS,
        };
    }

    pub fn deinit(self: *ValidatorMonitor) void {
        self.monitored.deinit();
        self.epoch_summaries.deinit(self.allocator);
    }

    /// Add a validator index to the monitor set at runtime.
    pub fn addValidator(self: *ValidatorMonitor, index: u64) !void {
        const result = try self.monitored.getOrPut(index);
        if (!result.found_existing) {
            result.value_ptr.* = .{ .index = index };
        }
    }

    /// Remove a validator index from the monitor set.
    pub fn removeValidator(self: *ValidatorMonitor, index: u64) void {
        _ = self.monitored.remove(index);
    }

    /// Check if a validator index is monitored.
    pub fn isMonitored(self: *const ValidatorMonitor, index: u64) bool {
        return self.monitored.contains(index);
    }

    /// Return count of monitored validators.
    pub fn monitoredCount(self: *const ValidatorMonitor) usize {
        return self.monitored.count();
    }

    // ===================================================================
    // Block processing hooks
    // ===================================================================

    /// Process attestations from an imported block.
    ///
    /// For each attestation in the block, check if any attesting validator
    /// is monitored. If so, record inclusion delay, head/source/target correctness.
    ///
    /// `block_slot` is the slot of the block containing the attestations.
    /// `attestation_slot` and `attesting_indices` come from each attestation.
    pub fn processAttestation(
        self: *ValidatorMonitor,
        block_slot: u64,
        attestation_slot: u64,
        attesting_indices: []const u64,
        head_correct: bool,
        source_correct: bool,
        target_correct: bool,
    ) void {
        const inclusion_delay: u32 = if (block_slot > attestation_slot)
            @intCast(block_slot - attestation_slot)
        else
            0;

        for (attesting_indices) |vi| {
            if (self.monitored.getPtr(vi)) |v| {
                // Only record the first (best) inclusion for this epoch
                if (!v.epoch_data.attestation_included) {
                    v.epoch_data.attestation_included = true;
                    v.epoch_data.attestation_delay = inclusion_delay;
                    v.epoch_data.attestation_head_correct = head_correct;
                    v.epoch_data.attestation_source_correct = source_correct;
                    v.epoch_data.attestation_target_correct = target_correct;
                } else if (v.epoch_data.attestation_delay) |existing_delay| {
                    // If we see a better inclusion delay, update
                    if (inclusion_delay < existing_delay) {
                        v.epoch_data.attestation_delay = inclusion_delay;
                        v.epoch_data.attestation_head_correct = head_correct;
                        v.epoch_data.attestation_source_correct = source_correct;
                        v.epoch_data.attestation_target_correct = target_correct;
                    }
                }
            }
        }
    }

    /// Record a block proposal from a monitored validator.
    pub fn processBlock(self: *ValidatorMonitor, proposer_index: u64, block_root: [32]u8) void {
        if (self.monitored.getPtr(proposer_index)) |v| {
            v.epoch_data.block_proposed = true;
            v.epoch_data.block_proposed_root = block_root;
        }
    }

    /// Record sync committee participation from a block's sync aggregate.
    ///
    /// `participant_indices` are the validator indices that participated.
    /// `committee_indices` are all validators in the current sync committee.
    pub fn processSyncAggregate(
        self: *ValidatorMonitor,
        participant_indices: []const u64,
        committee_indices: []const u64,
    ) void {
        // Mark expected for all monitored validators in the committee
        for (committee_indices) |ci| {
            if (self.monitored.getPtr(ci)) |v| {
                v.epoch_data.sync_expected_count += 1;
            }
        }
        // Mark participated for those who did
        for (participant_indices) |pi| {
            if (self.monitored.getPtr(pi)) |v| {
                v.epoch_data.sync_committee_participated = true;
                v.epoch_data.sync_participated_count += 1;
            }
        }
    }

    // ===================================================================
    // Epoch boundary
    // ===================================================================

    /// Called at epoch boundary. Updates balance tracking and commits
    /// current epoch data to cumulative stats.
    ///
    /// `balances` is the full validator balance array from the state.
    /// `effective_balances` is the effective balance array.
    /// `active_indices` is the set of active validator indices.
    /// `epoch` is the epoch that just ended.
    pub fn onEpochTransition(
        self: *ValidatorMonitor,
        epoch: u64,
        balances: []const u64,
        effective_balances: []const u64,
        active_indices: []const u64,
    ) void {
        // Build a quick lookup for active validators
        // (for small monitor sets, linear scan of active_indices per validator is fine)
        var summary = EpochSummary{ .epoch = epoch };
        var total_included: u32 = 0;
        var total_expected: u32 = 0;
        var total_head: u32 = 0;
        var total_source: u32 = 0;
        var total_target: u32 = 0;
        var delay_sum: u64 = 0;
        var delay_count: u32 = 0;
        var sync_participated: u32 = 0;
        var sync_expected: u32 = 0;

        var it = self.monitored.iterator();
        while (it.next()) |entry| {
            const v = entry.value_ptr;
            const idx = v.index;

            // Update balance
            if (idx < balances.len) {
                const prev_balance = v.balance;
                v.balance = balances[idx];
                v.balance_delta = @as(i64, @intCast(v.balance)) - @as(i64, @intCast(prev_balance));
                summary.total_balance_delta_gwei += v.balance_delta;
            }
            if (idx < effective_balances.len) {
                v.effective_balance = effective_balances[idx];
            }

            // Check if active
            var is_active = false;
            for (active_indices) |ai| {
                if (ai == idx) {
                    is_active = true;
                    break;
                }
            }

            if (is_active) {
                total_expected += 1;
                if (v.epoch_data.attestation_included) {
                    total_included += 1;
                    if (v.epoch_data.attestation_head_correct) total_head += 1;
                    if (v.epoch_data.attestation_source_correct) total_source += 1;
                    if (v.epoch_data.attestation_target_correct) total_target += 1;
                    if (v.epoch_data.attestation_delay) |d| {
                        delay_sum += d;
                        delay_count += 1;
                    }
                }
                if (v.epoch_data.block_proposed) summary.blocks_proposed += 1;
                sync_participated += v.epoch_data.sync_participated_count;
                sync_expected += v.epoch_data.sync_expected_count;
            }

            // Commit to cumulative and reset
            v.commitEpoch(is_active);
            v.resetEpoch();

            summary.validators_monitored += 1;
        }

        // Compute rates
        if (total_expected > 0) {
            summary.attestation_hit_rate = @as(f64, @floatFromInt(total_included)) /
                @as(f64, @floatFromInt(total_expected));
        }
        if (total_included > 0) {
            const fi = @as(f64, @floatFromInt(total_included));
            summary.head_accuracy_rate = @as(f64, @floatFromInt(total_head)) / fi;
            summary.source_accuracy_rate = @as(f64, @floatFromInt(total_source)) / fi;
            summary.target_accuracy_rate = @as(f64, @floatFromInt(total_target)) / fi;
        }
        if (delay_count > 0) {
            summary.avg_inclusion_delay = @as(f64, @floatFromInt(delay_sum)) /
                @as(f64, @floatFromInt(delay_count));
        }
        if (sync_expected > 0) {
            summary.sync_participation_rate = @as(f64, @floatFromInt(sync_participated)) /
                @as(f64, @floatFromInt(sync_expected));
        }

        // Store summary (ring buffer semantics)
        if (self.epoch_summaries.items.len >= @as(usize, self.max_epochs)) {
            // Remove oldest
            _ = self.epoch_summaries.orderedRemove(0);
        }
        self.epoch_summaries.append(self.allocator, summary) catch {};
        self.last_processed_epoch = epoch;

        scoped_log.info("validator monitor: epoch {d} — {d} monitored, att_rate={d:.1}%, head={d:.1}%, balance_delta={d}", .{
            epoch,
            summary.validators_monitored,
            summary.attestation_hit_rate * 100.0,
            summary.head_accuracy_rate * 100.0,
            summary.total_balance_delta_gwei,
        });
    }

    // ===================================================================
    // Query API
    // ===================================================================

    /// Get a snapshot of a monitored validator's status.
    pub fn getValidatorSummary(self: *const ValidatorMonitor, index: u64) ?ValidatorSummary {
        const v = self.monitored.get(index) orelse return null;
        return .{
            .index = v.index,
            .balance_gwei = v.balance,
            .effective_balance_gwei = v.effective_balance,
            .balance_delta_gwei = v.balance_delta,
            .effectiveness_score = computeEffectiveness(&v.cumulative),
            .attestation_included = v.epoch_data.attestation_included,
            .attestation_delay = v.epoch_data.attestation_delay,
            .head_correct = v.epoch_data.attestation_head_correct,
            .source_correct = v.epoch_data.attestation_source_correct,
            .target_correct = v.epoch_data.attestation_target_correct,
            .block_proposed = v.epoch_data.block_proposed,
            .sync_participated = v.epoch_data.sync_committee_participated,
            .cumulative_reward_gwei = v.cumulative.total_reward_gwei,
            .total_attestations_included = v.cumulative.total_attestations_included,
            .total_attestations_expected = v.cumulative.total_attestations_expected,
            .inclusion_delay_histogram = v.cumulative.inclusion_delay_histogram,
        };
    }

    /// Get an epoch summary by epoch number.
    pub fn getEpochSummary(self: *const ValidatorMonitor, epoch: u64) ?EpochSummary {
        for (self.epoch_summaries.items) |s| {
            if (s.epoch == epoch) return s;
        }
        return null;
    }

    /// Get all epoch summaries (for API export).
    pub fn getAllEpochSummaries(self: *const ValidatorMonitor) []const EpochSummary {
        return self.epoch_summaries.items;
    }

    /// Get the effectiveness score for a monitored validator.
    pub fn getEffectivenessScore(self: *const ValidatorMonitor, index: u64) ?f64 {
        const v = self.monitored.get(index) orelse return null;
        return computeEffectiveness(&v.cumulative);
    }

    /// Get indices of all monitored validators.
    pub fn getMonitoredIndices(self: *const ValidatorMonitor, allocator: Allocator) ![]u64 {
        var indices: std.ArrayListUnmanaged(u64) = .empty;
        var it = self.monitored.iterator();
        while (it.next()) |entry| {
            try indices.append(allocator, entry.key_ptr.*);
        }
        return indices.toOwnedSlice(allocator);
    }
};

// ---------------------------------------------------------------------------
// Effectiveness score computation
// ---------------------------------------------------------------------------

/// Compute effectiveness score (0-100) from cumulative stats.
///
/// Weights:
///   40% — attestation inclusion rate
///   20% — average 1/inclusion_delay (perfect = 1.0 for delay=1)
///   15% — head vote accuracy
///   15% — target vote accuracy
///   10% — source vote accuracy
pub fn computeEffectiveness(stats: *const CumulativeStats) f64 {
    if (stats.total_attestations_expected == 0) return 0.0;

    const expected_f = @as(f64, @floatFromInt(stats.total_attestations_expected));
    const included_f = @as(f64, @floatFromInt(stats.total_attestations_included));

    // Inclusion rate
    const inclusion_rate = included_f / expected_f;

    // Average inverse inclusion delay (1/delay, best = 1.0 for delay=1)
    var avg_inv_delay: f64 = 0.0;
    if (stats.total_attestations_included > 0) {
        // Compute from histogram: sum(count_i * 1/delay_i) / total
        const h = stats.inclusion_delay_histogram;
        // delay=0 shouldn't happen in practice (MIN_ATTESTATION_INCLUSION_DELAY=1)
        // but if it does, treat as perfect
        const inv_sum = @as(f64, @floatFromInt(h[0])) * 1.0 + // delay 0 → perfect
            @as(f64, @floatFromInt(h[1])) * 1.0 + // delay 1 → perfect
            @as(f64, @floatFromInt(h[2])) * 0.5 + // delay 2 → half
            @as(f64, @floatFromInt(h[3])) * 0.333; // delay 3+ → third
        avg_inv_delay = inv_sum / included_f;
    }

    // Accuracy rates (relative to included attestations)
    var head_rate: f64 = 0.0;
    var target_rate: f64 = 0.0;
    var source_rate: f64 = 0.0;
    if (stats.total_attestations_included > 0) {
        head_rate = @as(f64, @floatFromInt(stats.total_head_correct)) / included_f;
        target_rate = @as(f64, @floatFromInt(stats.total_target_correct)) / included_f;
        source_rate = @as(f64, @floatFromInt(stats.total_source_correct)) / included_f;
    }

    return 100.0 * (0.40 * inclusion_rate +
        0.20 * avg_inv_delay +
        0.15 * head_rate +
        0.15 * target_rate +
        0.10 * source_rate);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ValidatorMonitor: init and basic tracking" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{ 10, 20, 30 };
    var monitor = ValidatorMonitor.init(allocator, &indices);
    defer monitor.deinit();

    try std.testing.expect(monitor.isMonitored(10));
    try std.testing.expect(monitor.isMonitored(20));
    try std.testing.expect(monitor.isMonitored(30));
    try std.testing.expect(!monitor.isMonitored(99));
    try std.testing.expectEqual(@as(usize, 3), monitor.monitoredCount());
}

test "ValidatorMonitor: process attestation records inclusion delay" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{ 10, 20 };
    var monitor = ValidatorMonitor.init(allocator, &indices);
    defer monitor.deinit();

    // Attestation at slot 100, included at slot 101 → delay = 1
    const attesting = [_]u64{ 10, 99 }; // 10 is monitored, 99 is not
    monitor.processAttestation(101, 100, &attesting, true, true, true);

    const v10 = monitor.monitored.get(10).?;
    try std.testing.expect(v10.epoch_data.attestation_included);
    try std.testing.expectEqual(@as(u32, 1), v10.epoch_data.attestation_delay.?);
    try std.testing.expect(v10.epoch_data.attestation_head_correct);
    try std.testing.expect(v10.epoch_data.attestation_source_correct);
    try std.testing.expect(v10.epoch_data.attestation_target_correct);

    // Validator 20 should not have been affected
    const v20 = monitor.monitored.get(20).?;
    try std.testing.expect(!v20.epoch_data.attestation_included);
}

test "ValidatorMonitor: process block records proposer" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{42};
    var monitor = ValidatorMonitor.init(allocator, &indices);
    defer monitor.deinit();

    const root = [_]u8{0xAB} ** 32;
    monitor.processBlock(42, root);

    const v = monitor.monitored.get(42).?;
    try std.testing.expect(v.epoch_data.block_proposed);
    try std.testing.expectEqual(root, v.epoch_data.block_proposed_root.?);
}

test "ValidatorMonitor: sync aggregate tracking" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{ 10, 20 };
    var monitor = ValidatorMonitor.init(allocator, &indices);
    defer monitor.deinit();

    const committee = [_]u64{ 10, 20, 30 };
    const participants = [_]u64{ 10, 30 }; // 20 missed
    monitor.processSyncAggregate(&participants, &committee);

    const v10 = monitor.monitored.get(10).?;
    try std.testing.expect(v10.epoch_data.sync_committee_participated);
    try std.testing.expectEqual(@as(u32, 1), v10.epoch_data.sync_participated_count);
    try std.testing.expectEqual(@as(u32, 1), v10.epoch_data.sync_expected_count);

    const v20 = monitor.monitored.get(20).?;
    try std.testing.expect(!v20.epoch_data.sync_committee_participated);
    try std.testing.expectEqual(@as(u32, 0), v20.epoch_data.sync_participated_count);
    try std.testing.expectEqual(@as(u32, 1), v20.epoch_data.sync_expected_count);
}

test "ValidatorMonitor: epoch transition computes summary" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{ 0, 1 };
    var monitor = ValidatorMonitor.init(allocator, &indices);
    defer monitor.deinit();

    // Simulate attestation for validator 0 at slot 31, included at slot 32
    const attesting = [_]u64{0};
    monitor.processAttestation(32, 31, &attesting, true, true, false);

    // Block proposed by validator 1
    monitor.processBlock(1, [_]u8{0xFF} ** 32);

    // Epoch transition with balances
    const balances = [_]u64{ 32_000_000_000, 32_000_000_000 };
    const eff_balances = [_]u64{ 32_000_000_000, 32_000_000_000 };
    const active = [_]u64{ 0, 1 };
    monitor.onEpochTransition(1, &balances, &eff_balances, &active);

    // Check epoch summary
    const summary = monitor.getEpochSummary(1).?;
    try std.testing.expectEqual(@as(u32, 2), summary.validators_monitored);
    try std.testing.expect(summary.attestation_hit_rate > 0.49); // 1/2 = 0.5
    try std.testing.expect(summary.attestation_hit_rate < 0.51);
    try std.testing.expectEqual(@as(u32, 1), summary.blocks_proposed);

    // Check cumulative stats were updated
    const v0 = monitor.monitored.get(0).?;
    try std.testing.expectEqual(@as(u64, 1), v0.cumulative.total_attestations_included);
    try std.testing.expectEqual(@as(u64, 1), v0.cumulative.total_attestations_expected);
    try std.testing.expectEqual(@as(u64, 1), v0.cumulative.total_head_correct);
    try std.testing.expectEqual(@as(u64, 0), v0.cumulative.total_target_correct);

    // Check epoch data was reset
    try std.testing.expect(!v0.epoch_data.attestation_included);
}

test "ValidatorMonitor: effectiveness score calculation" {
    // Perfect validator: all attestations included at delay=1, all votes correct
    var stats = CumulativeStats{};
    stats.total_attestations_expected = 10;
    stats.total_attestations_included = 10;
    stats.total_head_correct = 10;
    stats.total_source_correct = 10;
    stats.total_target_correct = 10;
    stats.inclusion_delay_histogram = .{ 0, 10, 0, 0 }; // all at delay=1

    const score = computeEffectiveness(&stats);
    // Should be 100: 0.40*1.0 + 0.20*1.0 + 0.15*1.0 + 0.15*1.0 + 0.10*1.0 = 1.0 → 100
    try std.testing.expect(score > 99.9);
    try std.testing.expect(score <= 100.01);
}

test "ValidatorMonitor: effectiveness with missed attestations" {
    // Validator missed half their attestations
    var stats = CumulativeStats{};
    stats.total_attestations_expected = 10;
    stats.total_attestations_included = 5;
    stats.total_head_correct = 5;
    stats.total_source_correct = 5;
    stats.total_target_correct = 5;
    stats.inclusion_delay_histogram = .{ 0, 5, 0, 0 };

    const score = computeEffectiveness(&stats);
    // 0.40*0.5 + 0.20*1.0 + 0.15*1.0 + 0.15*1.0 + 0.10*1.0 = 0.20+0.20+0.15+0.15+0.10 = 0.80 → 80
    try std.testing.expect(score > 79.9);
    try std.testing.expect(score < 80.1);
}

test "ValidatorMonitor: effectiveness with high inclusion delays" {
    // All attestations included but at delay=3+
    var stats = CumulativeStats{};
    stats.total_attestations_expected = 10;
    stats.total_attestations_included = 10;
    stats.total_head_correct = 10;
    stats.total_source_correct = 10;
    stats.total_target_correct = 10;
    stats.inclusion_delay_histogram = .{ 0, 0, 0, 10 }; // all at delay≥3

    const score = computeEffectiveness(&stats);
    // 0.40*1.0 + 0.20*0.333 + 0.15*1.0 + 0.15*1.0 + 0.10*1.0 = 0.40+0.0666+0.15+0.15+0.10 = 0.8666 → 86.66
    try std.testing.expect(score > 86.0);
    try std.testing.expect(score < 87.0);
}

test "ValidatorMonitor: add and remove validators" {
    const allocator = std.testing.allocator;
    var monitor = ValidatorMonitor.init(allocator, &.{});
    defer monitor.deinit();

    try std.testing.expectEqual(@as(usize, 0), monitor.monitoredCount());

    try monitor.addValidator(100);
    try std.testing.expect(monitor.isMonitored(100));
    try std.testing.expectEqual(@as(usize, 1), monitor.monitoredCount());

    monitor.removeValidator(100);
    try std.testing.expect(!monitor.isMonitored(100));
    try std.testing.expectEqual(@as(usize, 0), monitor.monitoredCount());
}

test "ValidatorMonitor: getValidatorSummary" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{5};
    var monitor = ValidatorMonitor.init(allocator, &indices);
    defer monitor.deinit();

    // No data yet
    const summary = monitor.getValidatorSummary(5).?;
    try std.testing.expectEqual(@as(u64, 5), summary.index);
    try std.testing.expectEqual(@as(u64, 0), summary.balance_gwei);
    try std.testing.expectEqual(@as(f64, 0.0), summary.effectiveness_score);

    // Non-existent validator
    try std.testing.expect(monitor.getValidatorSummary(999) == null);
}

test "ValidatorMonitor: better inclusion delay updates" {
    const allocator = std.testing.allocator;
    const indices = [_]u64{10};
    var monitor = ValidatorMonitor.init(allocator, &indices);
    defer monitor.deinit();

    // First attestation: delay=3
    const att1 = [_]u64{10};
    monitor.processAttestation(103, 100, &att1, false, true, true);
    try std.testing.expectEqual(@as(u32, 3), monitor.monitored.get(10).?.epoch_data.attestation_delay.?);

    // Second attestation: delay=1 (better) — should update
    monitor.processAttestation(101, 100, &att1, true, true, true);
    try std.testing.expectEqual(@as(u32, 1), monitor.monitored.get(10).?.epoch_data.attestation_delay.?);
    // Head correct should also update to the better attestation's value
    try std.testing.expect(monitor.monitored.get(10).?.epoch_data.attestation_head_correct);
}

test "ValidatorMonitor: epoch summary rolling window" {
    const allocator = std.testing.allocator;
    var monitor = ValidatorMonitor.init(allocator, &.{});
    defer monitor.deinit();
    monitor.max_epochs = 3; // small window for testing (u32)

    const empty_bal = [_]u64{};
    const empty_idx = [_]u64{};

    monitor.onEpochTransition(0, &empty_bal, &empty_bal, &empty_idx);
    monitor.onEpochTransition(1, &empty_bal, &empty_bal, &empty_idx);
    monitor.onEpochTransition(2, &empty_bal, &empty_bal, &empty_idx);
    try std.testing.expectEqual(@as(usize, 3), monitor.epoch_summaries.items.len);

    // Adding a 4th should evict the oldest
    monitor.onEpochTransition(3, &empty_bal, &empty_bal, &empty_idx);
    try std.testing.expectEqual(@as(usize, 3), monitor.epoch_summaries.items.len);
    // Oldest should now be epoch 1
    try std.testing.expectEqual(@as(u64, 1), monitor.epoch_summaries.items[0].epoch);
    try std.testing.expectEqual(@as(u64, 3), monitor.epoch_summaries.items[2].epoch);
}
