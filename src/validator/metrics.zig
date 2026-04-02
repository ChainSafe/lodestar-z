//! ValidatorMetrics — Prometheus metrics for the validator client.
//!
//! Tracks validator duty throughput and timing plus high-level validator counts.

const std = @import("std");
const metrics_lib = @import("metrics");
const api_mod = @import("api");

pub const Counter = metrics_lib.Counter;
pub const CounterVec = metrics_lib.CounterVec;
pub const Gauge = metrics_lib.Gauge;
pub const Histogram = metrics_lib.Histogram;
pub const HistogramVec = metrics_lib.HistogramVec;

const attestation_delay_buckets = [_]f64{ 0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 12.0 };
const block_delay_buckets = [_]f64{ 0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 12.0 };
const keymanager_response_buckets = [_]f64{ 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0 };
const monitoring_collect_buckets = [_]f64{ 0.001, 0.01, 0.1, 1.0, 5.0 };
const monitoring_send_buckets = [_]f64{ 0.3, 0.5, 1.0, 2.0, 5.0, 10.0 };

const OperationLabels = struct {
    operation_id: []const u8,
};

const MonitoringStatusLabels = struct {
    status: []const u8,
};

pub const BeaconHealth = enum(u64) {
    ready = 0,
    syncing = 1,
    err = 2,
};

pub const ValidatorMetrics = struct {
    attestation_published_total: Counter(u64),
    attestation_missed_total: Counter(u64),
    attestation_delay_seconds: Histogram(f64, &attestation_delay_buckets),

    block_proposed_total: Counter(u64),
    block_missed_total: Counter(u64),
    block_delay_seconds: Histogram(f64, &block_delay_buckets),

    sync_committee_message_total: Counter(u64),
    sync_committee_contribution_total: Counter(u64),

    total_validators: Gauge(u64),
    active_validators: Gauge(u64),
    beacon_health: Gauge(u64),
    keymanager_requests_total: CounterVec(u64, OperationLabels),
    keymanager_errors_total: CounterVec(u64, OperationLabels),
    keymanager_response_seconds: HistogramVec(f64, OperationLabels, &keymanager_response_buckets),
    keymanager_active_connections: Gauge(u64),
    monitoring_collect_data_seconds: Histogram(f64, &monitoring_collect_buckets),
    monitoring_send_data_seconds: HistogramVec(f64, MonitoringStatusLabels, &monitoring_send_buckets),

    pub fn init(allocator: std.mem.Allocator) !ValidatorMetrics {
        const ro: metrics_lib.RegistryOpts = .{};
        return .{
            .attestation_published_total = Counter(u64).init("validator_attestation_published_total", .{}, ro),
            .attestation_missed_total = Counter(u64).init("validator_attestation_missed_total", .{}, ro),
            .attestation_delay_seconds = Histogram(f64, &attestation_delay_buckets).init("validator_attestation_delay_seconds", .{}, ro),
            .block_proposed_total = Counter(u64).init("validator_block_proposed_total", .{}, ro),
            .block_missed_total = Counter(u64).init("validator_block_missed_total", .{}, ro),
            .block_delay_seconds = Histogram(f64, &block_delay_buckets).init("validator_block_delay_seconds", .{}, ro),
            .sync_committee_message_total = Counter(u64).init("validator_sync_committee_message_total", .{}, ro),
            .sync_committee_contribution_total = Counter(u64).init("validator_sync_committee_contribution_total", .{}, ro),
            .total_validators = Gauge(u64).init("validator_total_count", .{}, ro),
            .active_validators = Gauge(u64).init("validator_active_count", .{}, ro),
            .beacon_health = Gauge(u64).init("vc_beacon_health", .{}, ro),
            .keymanager_requests_total = try CounterVec(u64, OperationLabels).init(
                allocator,
                "validator_keymanager_requests_total",
                .{},
                ro,
            ),
            .keymanager_errors_total = try CounterVec(u64, OperationLabels).init(
                allocator,
                "validator_keymanager_errors_total",
                .{},
                ro,
            ),
            .keymanager_response_seconds = try HistogramVec(f64, OperationLabels, &keymanager_response_buckets).init(
                allocator,
                "validator_keymanager_response_seconds",
                .{},
                ro,
            ),
            .keymanager_active_connections = Gauge(u64).init("validator_keymanager_active_connections", .{}, ro),
            .monitoring_collect_data_seconds = Histogram(f64, &monitoring_collect_buckets).init(
                "lodestar_monitoring_collect_data_seconds",
                .{},
                ro,
            ),
            .monitoring_send_data_seconds = try HistogramVec(f64, MonitoringStatusLabels, &monitoring_send_buckets).init(
                allocator,
                "lodestar_monitoring_send_data_seconds",
                .{},
                ro,
            ),
        };
    }

    pub fn initNoop() ValidatorMetrics {
        return metrics_lib.initializeNoop(ValidatorMetrics);
    }

    pub fn deinit(self: *ValidatorMetrics) void {
        self.keymanager_requests_total.deinit();
        self.keymanager_errors_total.deinit();
        self.keymanager_response_seconds.deinit();
        self.monitoring_send_data_seconds.deinit();
    }

    pub fn write(self: *ValidatorMetrics, writer: *std.Io.Writer) !void {
        try metrics_lib.write(self, writer);
    }

    pub fn observeKeymanagerRequest(
        self: *ValidatorMetrics,
        operation_id: []const u8,
        response_time_seconds: f64,
        is_error: bool,
    ) void {
        const labels: OperationLabels = .{ .operation_id = operation_id };
        self.keymanager_requests_total.incr(labels) catch return;
        if (is_error) {
            self.keymanager_errors_total.incr(labels) catch return;
        }
        self.keymanager_response_seconds.observe(labels, response_time_seconds) catch return;
    }

    pub fn setKeymanagerActiveConnections(self: *ValidatorMetrics, active_connections: u32) void {
        self.keymanager_active_connections.set(active_connections);
    }

    pub fn setBeaconHealth(self: *ValidatorMetrics, health: BeaconHealth) void {
        self.beacon_health.set(@intFromEnum(health));
    }

    pub fn observeMonitoringCollect(self: *ValidatorMetrics, response_time_seconds: f64) void {
        self.monitoring_collect_data_seconds.observe(response_time_seconds);
    }

    pub fn observeMonitoringSend(
        self: *ValidatorMetrics,
        response_time_seconds: f64,
        success: bool,
    ) void {
        const labels: MonitoringStatusLabels = .{
            .status = if (success) "success" else "error",
        };
        self.monitoring_send_data_seconds.observe(labels, response_time_seconds) catch return;
    }

    pub fn keymanagerObserver(self: *ValidatorMetrics) api_mod.HttpServer.Observer {
        return .{
            .ptr = self,
            .onActiveConnectionsChangedFn = onKeymanagerActiveConnectionsChanged,
            .onRequestCompletedFn = onKeymanagerRequestCompleted,
        };
    }
};

fn onKeymanagerActiveConnectionsChanged(ptr: *anyopaque, active_connections: u32) void {
    const metrics: *ValidatorMetrics = @ptrCast(@alignCast(ptr));
    metrics.setKeymanagerActiveConnections(active_connections);
}

fn onKeymanagerRequestCompleted(
    ptr: *anyopaque,
    operation_id: []const u8,
    response_time_seconds: f64,
    is_error: bool,
) void {
    const metrics: *ValidatorMetrics = @ptrCast(@alignCast(ptr));
    metrics.observeKeymanagerRequest(operation_id, response_time_seconds, is_error);
}

test "ValidatorMetrics: init and observe" {
    var m = try ValidatorMetrics.init(std.testing.allocator);
    defer m.deinit();
    m.attestation_published_total.incr();
    m.block_proposed_total.incr();
    m.attestation_delay_seconds.observe(1.5);
    m.total_validators.set(123);
    m.active_validators.set(100);
    m.setBeaconHealth(.ready);
    try std.testing.expectEqual(@as(u64, 1), m.attestation_published_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.block_proposed_total.impl.count);
    try std.testing.expectEqual(@as(u64, 123), m.total_validators.impl.value);
    try std.testing.expectEqual(@as(u64, 100), m.active_validators.impl.value);
    try std.testing.expectEqual(@as(u64, 0), m.beacon_health.impl.value);
}

test "ValidatorMetrics: noop is safe" {
    var m = ValidatorMetrics.initNoop();
    m.attestation_published_total.incr();
    m.block_proposed_total.incr();
    m.attestation_delay_seconds.observe(1.5);
    m.total_validators.set(123);
    m.active_validators.set(100);
    m.setBeaconHealth(.err);
    try std.testing.expect(std.meta.activeTag(m.attestation_published_total) == .noop);
}

test "ValidatorMetrics: write produces Prometheus output" {
    var m = try ValidatorMetrics.init(std.testing.allocator);
    defer m.deinit();
    m.attestation_published_total.incr();
    m.block_proposed_total.incr();
    m.observeKeymanagerRequest("listKeystores", 0.01, false);
    m.observeKeymanagerRequest("importKeystores", 0.02, true);
    m.setKeymanagerActiveConnections(1);
    m.observeMonitoringCollect(0.01);
    m.observeMonitoringSend(0.25, true);
    m.total_validators.set(123);
    m.setBeaconHealth(.syncing);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try m.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_attestation_published_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_block_proposed_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_attestation_delay_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_total_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_active_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_beacon_health") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_keymanager_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_keymanager_errors_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_keymanager_response_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_keymanager_active_connections") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "lodestar_monitoring_collect_data_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "lodestar_monitoring_send_data_seconds") != null);
}
