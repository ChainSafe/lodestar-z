//! ValidatorMetrics — Prometheus metrics for the validator client.
//!
//! Tracks validator performance: attestations, blocks, sync committee duties,
//! and timing. These metrics answer "is my validator performing?" and
//! "how timely are my duties?"
//!
//! Uses the same pattern as BeaconMetrics: real or noop depending on CLI flags.

const std = @import("std");
const metrics_lib = @import("metrics");

pub const Counter = metrics_lib.Counter;
pub const Gauge = metrics_lib.Gauge;
pub const Histogram = metrics_lib.Histogram;

const attestation_delay_buckets = [_]f64{ 0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 12.0 };
const block_delay_buckets = [_]f64{ 0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 12.0 };

/// Validator client metrics.
///
/// Categories:
///   - Attestation duties (published, missed, delay)
///   - Block proposal duties (proposed, missed, delay)
///   - Sync committee duties
///   - Validator state (active count, balance)
pub const ValidatorMetrics = struct {
    // ===================================================================
    // Attestation duties
    // ===================================================================

    /// Total attestations successfully published.
    attestation_published_total: Counter(u64),
    /// Total attestation duties that were missed.
    attestation_missed_total: Counter(u64),
    /// Time from slot start to attestation submission in seconds.
    attestation_delay_seconds: Histogram(f64, &attestation_delay_buckets),

    // ===================================================================
    // Block proposal duties
    // ===================================================================

    /// Total blocks successfully proposed.
    block_proposed_total: Counter(u64),
    /// Total block proposal duties that were missed (we were proposer but didn't produce).
    block_missed_total: Counter(u64),
    /// Time from slot start to block submission in seconds.
    block_delay_seconds: Histogram(f64, &block_delay_buckets),

    // ===================================================================
    // Sync committee duties
    // ===================================================================

    /// Total sync committee messages published.
    sync_committee_message_total: Counter(u64),
    /// Total sync committee contributions published.
    sync_committee_contribution_total: Counter(u64),

    // ===================================================================
    // Validator state
    // ===================================================================

    /// Number of active validators managed by this VC.
    active_validators: Gauge(u64),
    /// Total balance of all managed validators (in Gwei).
    total_balance_gwei: Gauge(u64),

    // -------------------------------------------------------------------
    // Initializers
    // -------------------------------------------------------------------

    pub fn init() ValidatorMetrics {
        const ro: metrics_lib.RegistryOpts = .{};
        return .{
            // Attestation duties
            .attestation_published_total = Counter(u64).init("validator_attestation_published_total", .{}, ro),
            .attestation_missed_total = Counter(u64).init("validator_attestation_missed_total", .{}, ro),
            .attestation_delay_seconds = Histogram(f64, &attestation_delay_buckets).init("validator_attestation_delay_seconds", .{}, ro),

            // Block proposal duties
            .block_proposed_total = Counter(u64).init("validator_block_proposed_total", .{}, ro),
            .block_missed_total = Counter(u64).init("validator_block_missed_total", .{}, ro),
            .block_delay_seconds = Histogram(f64, &block_delay_buckets).init("validator_block_delay_seconds", .{}, ro),

            // Sync committee
            .sync_committee_message_total = Counter(u64).init("validator_sync_committee_message_total", .{}, ro),
            .sync_committee_contribution_total = Counter(u64).init("validator_sync_committee_contribution_total", .{}, ro),

            // State
            .active_validators = Gauge(u64).init("validator_active_count", .{}, ro),
            .total_balance_gwei = Gauge(u64).init("validator_total_balance_gwei", .{}, ro),
        };
    }

    pub fn initNoop() ValidatorMetrics {
        return metrics_lib.initializeNoop(ValidatorMetrics);
    }

    pub fn write(self: *ValidatorMetrics, writer: *std.Io.Writer) !void {
        try metrics_lib.write(self, writer);
    }
};

test "ValidatorMetrics: init and observe" {
    var m = ValidatorMetrics.init();
    m.attestation_published_total.incr();
    m.block_proposed_total.incr();
    m.attestation_delay_seconds.observe(1.5);
    m.active_validators.set(100);
    try std.testing.expectEqual(@as(u64, 1), m.attestation_published_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.block_proposed_total.impl.count);
    try std.testing.expectEqual(@as(u64, 100), m.active_validators.impl.value);
}

test "ValidatorMetrics: noop is safe" {
    var m = ValidatorMetrics.initNoop();
    m.attestation_published_total.incr();
    m.block_proposed_total.incr();
    m.attestation_delay_seconds.observe(1.5);
    m.active_validators.set(100);
    try std.testing.expect(std.meta.activeTag(m.attestation_published_total) == .noop);
}

test "ValidatorMetrics: write produces Prometheus output" {
    var m = ValidatorMetrics.init();
    m.attestation_published_total.incr();
    m.block_proposed_total.incr();

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try m.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_attestation_published_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_block_proposed_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_attestation_delay_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_active_count") != null);
}
