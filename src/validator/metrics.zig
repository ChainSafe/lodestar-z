//! ValidatorMetrics — Prometheus metrics for the validator client.
//!
//! Tracks validator duty throughput and timing plus high-level validator counts.

const std = @import("std");
const metrics_lib = @import("metrics");
const api_mod = @import("api");

pub const Counter = metrics_lib.Counter;
pub const CounterVec = metrics_lib.CounterVec;
pub const Gauge = metrics_lib.Gauge;
pub const GaugeVec = metrics_lib.GaugeVec;
pub const Histogram = metrics_lib.Histogram;
pub const HistogramVec = metrics_lib.HistogramVec;

const attestation_delay_buckets = [_]f64{ 0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 12.0 };
const block_delay_buckets = [_]f64{ 0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 12.0 };
const keymanager_response_buckets = [_]f64{ 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0 };
const monitoring_collect_buckets = [_]f64{ 0.001, 0.01, 0.1, 1.0, 5.0 };
const monitoring_send_buckets = [_]f64{ 0.3, 0.5, 1.0, 2.0, 5.0, 10.0 };
const rest_api_request_buckets = [_]f64{ 0.01, 0.1, 1.0, 2.0, 5.0 };

const OperationLabels = struct {
    operation_id: []const u8,
};

const MonitoringStatusLabels = struct {
    status: []const u8,
};

const RestApiRouteLabels = struct {
    routeId: []const u8,
};

const RestApiRouteUrlLabels = struct {
    routeId: []const u8,
    baseUrl: []const u8,
};

const RestApiUrlScoreLabels = struct {
    urlIndex: u64,
    baseUrl: []const u8,
};

const DoppelgangerStatusLabels = struct {
    status: []const u8,
};

pub const BeaconHealth = enum(u64) {
    ready = 0,
    syncing = 1,
    err = 2,
};

pub const ValidatorMetrics = struct {
    remote_sign_errors_total: Counter(u64),
    sign_errors_total: Counter(u64),
    slashing_protection_block_errors_total: Counter(u64),
    slashing_protection_attestation_errors_total: Counter(u64),
    attestation_published_total: Counter(u64),
    attestation_missed_total: Counter(u64),
    attestation_delay_seconds: Histogram(f64, &attestation_delay_buckets),
    attestation_delay_count: Histogram(f64, &attestation_delay_buckets),
    attestations_published_total: Gauge(u64),
    attester_duties_count: Gauge(u64),
    attester_duties_epoch_count: Gauge(u64),
    attestation_duties_reorg_total: Counter(u64),
    attestation_duty_slot: Gauge(u64),

    block_proposed_total: Counter(u64),
    block_missed_total: Counter(u64),
    block_delay_seconds: Histogram(f64, &block_delay_buckets),
    block_delay_count: Histogram(f64, &block_delay_buckets),
    beacon_block_proposed_total: Gauge(u64),
    proposer_duties_epoch_count: Gauge(u64),
    proposer_duties_reorg_total: Counter(u64),
    new_proposal_duties_detected_total: Counter(u64),

    sync_committee_message_total: Counter(u64),
    sync_committee_contribution_total: Counter(u64),
    sync_committee_duties_count: Gauge(u64),
    sync_committee_duties_epoch_count: Gauge(u64),
    sync_committee_duties_reorg_total: Counter(u64),

    total_validators: Gauge(u64),
    active_validators: Gauge(u64),
    local_validator_count: Gauge(u64),
    beacon_health: Gauge(u64),
    rest_api_request_seconds: HistogramVec(f64, RestApiRouteLabels, &rest_api_request_buckets),
    rest_api_stream_seconds: HistogramVec(f64, RestApiRouteLabels, &rest_api_request_buckets),
    rest_api_request_errors_total: CounterVec(u64, RestApiRouteUrlLabels),
    rest_api_request_to_fallbacks_total: CounterVec(u64, RestApiRouteUrlLabels),
    rest_api_urls_score: GaugeVec(u64, RestApiUrlScoreLabels),
    keymanager_requests_total: CounterVec(u64, OperationLabels),
    keymanager_errors_total: CounterVec(u64, OperationLabels),
    keymanager_response_seconds: HistogramVec(f64, OperationLabels, &keymanager_response_buckets),
    keymanager_active_connections: Gauge(u64),
    monitoring_collect_data_seconds: Histogram(f64, &monitoring_collect_buckets),
    monitoring_send_data_seconds: HistogramVec(f64, MonitoringStatusLabels, &monitoring_send_buckets),
    doppelganger_validator_status_count: GaugeVec(u64, DoppelgangerStatusLabels),
    doppelganger_epochs_checked_total: Counter(u64),

    pub fn init(allocator: std.mem.Allocator) !ValidatorMetrics {
        const ro: metrics_lib.RegistryOpts = .{};
        return .{
            .remote_sign_errors_total = Counter(u64).init("vc_remote_sign_errors_total", .{}, ro),
            .sign_errors_total = Counter(u64).init("vc_sign_errors_total", .{}, ro),
            .slashing_protection_block_errors_total = Counter(u64).init(
                "vc_slashing_protection_block_errors_total",
                .{},
                ro,
            ),
            .slashing_protection_attestation_errors_total = Counter(u64).init(
                "vc_slashing_protection_attestation_errors_total",
                .{},
                ro,
            ),
            .attestation_published_total = Counter(u64).init("validator_attestation_published_total", .{}, ro),
            .attestation_missed_total = Counter(u64).init("validator_attestation_missed_total", .{}, ro),
            .attestation_delay_seconds = Histogram(f64, &attestation_delay_buckets).init("validator_attestation_delay_seconds", .{}, ro),
            .attestation_delay_count = Histogram(f64, &attestation_delay_buckets).init("beacon_attestation_delay_count", .{}, ro),
            .attestations_published_total = Gauge(u64).init("beacon_attestations_published_total", .{}, ro),
            .attester_duties_count = Gauge(u64).init("vc_attester_duties_count", .{}, ro),
            .attester_duties_epoch_count = Gauge(u64).init("vc_attester_duties_epoch_count", .{}, ro),
            .attestation_duties_reorg_total = Counter(u64).init("vc_attestation_duties_reorg_total", .{}, ro),
            .attestation_duty_slot = Gauge(u64).init("vc_attestation_duty_slot", .{}, ro),
            .block_proposed_total = Counter(u64).init("validator_block_proposed_total", .{}, ro),
            .block_missed_total = Counter(u64).init("validator_block_missed_total", .{}, ro),
            .block_delay_seconds = Histogram(f64, &block_delay_buckets).init("validator_block_delay_seconds", .{}, ro),
            .block_delay_count = Histogram(f64, &block_delay_buckets).init("beacon_block_delay_count", .{}, ro),
            .beacon_block_proposed_total = Gauge(u64).init("beacon_block_proposed_total", .{}, ro),
            .proposer_duties_epoch_count = Gauge(u64).init("vc_proposer_duties_epoch_count", .{}, ro),
            .proposer_duties_reorg_total = Counter(u64).init("vc_proposer_duties_reorg_total", .{}, ro),
            .new_proposal_duties_detected_total = Counter(u64).init("vc_new_proposal_duties_detected_total", .{}, ro),
            .sync_committee_message_total = Counter(u64).init("validator_sync_committee_message_total", .{}, ro),
            .sync_committee_contribution_total = Counter(u64).init("validator_sync_committee_contribution_total", .{}, ro),
            .sync_committee_duties_count = Gauge(u64).init("vc_sync_committee_duties_count", .{}, ro),
            .sync_committee_duties_epoch_count = Gauge(u64).init("vc_sync_committee_duties_epoch_count", .{}, ro),
            .sync_committee_duties_reorg_total = Counter(u64).init("vc_sync_committee_duties_reorg_total", .{}, ro),
            .total_validators = Gauge(u64).init("validator_total_count", .{}, ro),
            .active_validators = Gauge(u64).init("validator_active_count", .{}, ro),
            .local_validator_count = Gauge(u64).init("local_validator_count", .{}, ro),
            .beacon_health = Gauge(u64).init("vc_beacon_health", .{}, ro),
            .rest_api_request_seconds = try HistogramVec(f64, RestApiRouteLabels, &rest_api_request_buckets).init(
                allocator,
                "vc_rest_api_client_request_time_seconds",
                .{},
                ro,
            ),
            .rest_api_stream_seconds = try HistogramVec(f64, RestApiRouteLabels, &rest_api_request_buckets).init(
                allocator,
                "vc_rest_api_client_stream_time_seconds",
                .{},
                ro,
            ),
            .rest_api_request_errors_total = try CounterVec(u64, RestApiRouteUrlLabels).init(
                allocator,
                "vc_rest_api_client_request_errors_total",
                .{},
                ro,
            ),
            .rest_api_request_to_fallbacks_total = try CounterVec(u64, RestApiRouteUrlLabels).init(
                allocator,
                "vc_rest_api_client_request_to_fallbacks_total",
                .{},
                ro,
            ),
            .rest_api_urls_score = try GaugeVec(u64, RestApiUrlScoreLabels).init(
                allocator,
                "vc_rest_api_client_urls_score",
                .{},
                ro,
            ),
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
            .doppelganger_validator_status_count = try GaugeVec(u64, DoppelgangerStatusLabels).init(
                allocator,
                "vc_doppelganger_validator_status_count",
                .{},
                ro,
            ),
            .doppelganger_epochs_checked_total = Counter(u64).init(
                "vc_doppelganger_epochs_checked_total",
                .{},
                ro,
            ),
        };
    }

    pub fn initNoop() ValidatorMetrics {
        return metrics_lib.initializeNoop(ValidatorMetrics);
    }

    pub fn deinit(self: *ValidatorMetrics) void {
        self.rest_api_request_seconds.deinit();
        self.rest_api_stream_seconds.deinit();
        self.rest_api_request_errors_total.deinit();
        self.rest_api_request_to_fallbacks_total.deinit();
        self.rest_api_urls_score.deinit();
        self.keymanager_requests_total.deinit();
        self.keymanager_errors_total.deinit();
        self.keymanager_response_seconds.deinit();
        self.monitoring_send_data_seconds.deinit();
        self.doppelganger_validator_status_count.deinit();
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

    pub fn incrRemoteSignError(self: *ValidatorMetrics) void {
        self.remote_sign_errors_total.incr();
    }

    pub fn incrSignError(self: *ValidatorMetrics) void {
        self.sign_errors_total.incr();
    }

    pub fn incrSlashingProtectionBlockError(self: *ValidatorMetrics) void {
        self.slashing_protection_block_errors_total.incr();
    }

    pub fn incrSlashingProtectionAttestationError(self: *ValidatorMetrics) void {
        self.slashing_protection_attestation_errors_total.incr();
    }

    pub fn setKeymanagerActiveConnections(self: *ValidatorMetrics, active_connections: u32) void {
        self.keymanager_active_connections.set(active_connections);
    }

    pub fn setBeaconHealth(self: *ValidatorMetrics, health: BeaconHealth) void {
        self.beacon_health.set(@intFromEnum(health));
    }

    pub fn recordAttestationPublished(self: *ValidatorMetrics, count: u64) void {
        if (count == 0) return;
        self.attestation_published_total.incrBy(count);
        self.attestations_published_total.incrBy(count);
    }

    pub fn observeAttestationDelay(self: *ValidatorMetrics, delay_seconds: f64) void {
        self.attestation_delay_seconds.observe(delay_seconds);
        self.attestation_delay_count.observe(delay_seconds);
    }

    pub fn observeRestApiRequest(self: *ValidatorMetrics, route_id: []const u8, response_time_seconds: f64) void {
        self.rest_api_request_seconds.observe(.{ .routeId = route_id }, response_time_seconds) catch return;
    }

    pub fn setAttesterDutyCache(self: *ValidatorMetrics, duty_count: usize, epoch_count: usize, next_duty_slot: ?u64) void {
        self.attester_duties_count.set(@intCast(duty_count));
        self.attester_duties_epoch_count.set(@intCast(epoch_count));
        self.attestation_duty_slot.set(next_duty_slot orelse 0);
    }

    pub fn incrAttesterDutyReorg(self: *ValidatorMetrics) void {
        self.attestation_duties_reorg_total.incr();
    }

    pub fn setProposerDutyEpochCount(self: *ValidatorMetrics, epoch_count: usize) void {
        self.proposer_duties_epoch_count.set(@intCast(epoch_count));
    }

    pub fn recordBlockProposed(self: *ValidatorMetrics) void {
        self.block_proposed_total.incr();
        self.beacon_block_proposed_total.incr();
    }

    pub fn observeBlockDelay(self: *ValidatorMetrics, delay_seconds: f64) void {
        self.block_delay_seconds.observe(delay_seconds);
        self.block_delay_count.observe(delay_seconds);
    }

    pub fn incrProposerDutyReorg(self: *ValidatorMetrics) void {
        self.proposer_duties_reorg_total.incr();
    }

    pub fn incrNewProposalDutiesDetected(self: *ValidatorMetrics) void {
        self.new_proposal_duties_detected_total.incr();
    }

    pub fn setSyncCommitteeDutyCache(self: *ValidatorMetrics, duty_count: usize, epoch_count: usize) void {
        self.sync_committee_duties_count.set(@intCast(duty_count));
        self.sync_committee_duties_epoch_count.set(@intCast(epoch_count));
    }

    pub fn incrSyncCommitteeDutyReorg(self: *ValidatorMetrics) void {
        self.sync_committee_duties_reorg_total.incr();
    }

    pub fn observeRestApiStream(self: *ValidatorMetrics, route_id: []const u8, response_time_seconds: f64) void {
        self.rest_api_stream_seconds.observe(.{ .routeId = route_id }, response_time_seconds) catch return;
    }

    pub fn recordRestApiError(self: *ValidatorMetrics, route_id: []const u8, base_url: []const u8) void {
        self.rest_api_request_errors_total.incr(.{
            .routeId = route_id,
            .baseUrl = base_url,
        }) catch return;
    }

    pub fn recordRestApiFallback(self: *ValidatorMetrics, route_id: []const u8, base_url: []const u8) void {
        self.rest_api_request_to_fallbacks_total.incr(.{
            .routeId = route_id,
            .baseUrl = base_url,
        }) catch return;
    }

    pub fn setRestApiUrlScore(self: *ValidatorMetrics, url_index: usize, base_url: []const u8, score: u64) void {
        self.rest_api_urls_score.set(.{
            .urlIndex = @intCast(url_index),
            .baseUrl = base_url,
        }, score) catch return;
    }

    pub fn setValidatorCounts(self: *ValidatorMetrics, total: u64, active: u64) void {
        self.total_validators.set(total);
        self.active_validators.set(active);
        self.local_validator_count.set(total);
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

    pub fn setDoppelgangerStatusCount(self: *ValidatorMetrics, status: []const u8, count: u64) void {
        self.doppelganger_validator_status_count.set(.{ .status = status }, count) catch return;
    }

    pub fn incrDoppelgangerEpochsChecked(self: *ValidatorMetrics) void {
        self.doppelganger_epochs_checked_total.incr();
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
    m.incrRemoteSignError();
    m.incrSignError();
    m.incrSlashingProtectionBlockError();
    m.incrSlashingProtectionAttestationError();
    m.recordAttestationPublished(1);
    m.recordBlockProposed();
    m.observeAttestationDelay(1.5);
    m.setAttesterDutyCache(12, 2, 96);
    m.incrAttesterDutyReorg();
    m.setProposerDutyEpochCount(2);
    m.incrProposerDutyReorg();
    m.incrNewProposalDutiesDetected();
    m.setSyncCommitteeDutyCache(8, 2);
    m.incrSyncCommitteeDutyReorg();
    m.setValidatorCounts(123, 100);
    m.setBeaconHealth(.ready);
    m.observeRestApiRequest("beacon.getGenesis", 0.02);
    m.observeRestApiStream("events.eventstream", 0.03);
    m.recordRestApiError("beacon.getGenesis", "http://127.0.0.1:5052");
    m.recordRestApiFallback("beacon.getGenesis", "http://127.0.0.1:5053");
    m.setRestApiUrlScore(0, "http://127.0.0.1:5052", 10);
    try std.testing.expectEqual(@as(u64, 1), m.remote_sign_errors_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.sign_errors_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.slashing_protection_block_errors_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.slashing_protection_attestation_errors_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.attestation_published_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.block_proposed_total.impl.count);
    try std.testing.expectEqual(@as(u64, 1), m.attestations_published_total.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.beacon_block_proposed_total.impl.value);
    try std.testing.expectEqual(@as(u64, 12), m.attester_duties_count.impl.value);
    try std.testing.expectEqual(@as(u64, 2), m.attester_duties_epoch_count.impl.value);
    try std.testing.expectEqual(@as(u64, 96), m.attestation_duty_slot.impl.value);
    try std.testing.expectEqual(@as(u64, 2), m.proposer_duties_epoch_count.impl.value);
    try std.testing.expectEqual(@as(u64, 8), m.sync_committee_duties_count.impl.value);
    try std.testing.expectEqual(@as(u64, 2), m.sync_committee_duties_epoch_count.impl.value);
    try std.testing.expectEqual(@as(u64, 123), m.total_validators.impl.value);
    try std.testing.expectEqual(@as(u64, 100), m.active_validators.impl.value);
    try std.testing.expectEqual(@as(u64, 123), m.local_validator_count.impl.value);
    try std.testing.expectEqual(@as(u64, 0), m.beacon_health.impl.value);
}

test "ValidatorMetrics: noop is safe" {
    var m = ValidatorMetrics.initNoop();
    m.incrRemoteSignError();
    m.incrSignError();
    m.incrSlashingProtectionBlockError();
    m.incrSlashingProtectionAttestationError();
    m.recordAttestationPublished(1);
    m.recordBlockProposed();
    m.observeAttestationDelay(1.5);
    m.setAttesterDutyCache(1, 1, 1);
    m.incrAttesterDutyReorg();
    m.setProposerDutyEpochCount(1);
    m.incrProposerDutyReorg();
    m.incrNewProposalDutiesDetected();
    m.setSyncCommitteeDutyCache(1, 1);
    m.incrSyncCommitteeDutyReorg();
    m.setValidatorCounts(123, 100);
    m.setBeaconHealth(.err);
    m.observeRestApiRequest("beacon.getGenesis", 0.02);
    m.observeRestApiStream("events.eventstream", 0.03);
    m.recordRestApiError("beacon.getGenesis", "http://127.0.0.1:5052");
    m.recordRestApiFallback("beacon.getGenesis", "http://127.0.0.1:5053");
    m.setRestApiUrlScore(0, "http://127.0.0.1:5052", 0);
    try std.testing.expect(std.meta.activeTag(m.attestation_published_total) == .noop);
}

test "ValidatorMetrics: write produces Prometheus output" {
    var m = try ValidatorMetrics.init(std.testing.allocator);
    defer m.deinit();
    m.incrRemoteSignError();
    m.incrSignError();
    m.incrSlashingProtectionBlockError();
    m.incrSlashingProtectionAttestationError();
    m.recordAttestationPublished(1);
    m.recordBlockProposed();
    m.observeKeymanagerRequest("listKeystores", 0.01, false);
    m.observeKeymanagerRequest("importKeystores", 0.02, true);
    m.setKeymanagerActiveConnections(1);
    m.observeRestApiRequest("beacon.getGenesis", 0.02);
    m.observeRestApiStream("events.eventstream", 0.03);
    m.recordRestApiError("beacon.getGenesis", "http://127.0.0.1:5052");
    m.recordRestApiFallback("beacon.getGenesis", "http://127.0.0.1:5053");
    m.setRestApiUrlScore(0, "http://127.0.0.1:5052", 8);
    m.observeMonitoringCollect(0.01);
    m.observeMonitoringSend(0.25, true);
    m.setAttesterDutyCache(12, 2, 96);
    m.incrAttesterDutyReorg();
    m.setProposerDutyEpochCount(2);
    m.incrProposerDutyReorg();
    m.incrNewProposalDutiesDetected();
    m.setSyncCommitteeDutyCache(8, 2);
    m.incrSyncCommitteeDutyReorg();
    m.setDoppelgangerStatusCount("Unverified", 3);
    m.incrDoppelgangerEpochsChecked();
    m.setValidatorCounts(123, 0);
    m.setBeaconHealth(.syncing);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try m.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_attestation_published_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_attestations_published_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_block_proposed_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_proposed_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_attestation_delay_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_attestation_delay_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_block_delay_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_attester_duties_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_attester_duties_epoch_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_attestation_duties_reorg_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_attestation_duty_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_total_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_active_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "local_validator_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_proposer_duties_epoch_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_proposer_duties_reorg_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_new_proposal_duties_detected_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_sync_committee_duties_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_sync_committee_duties_epoch_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_sync_committee_duties_reorg_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_beacon_health") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_rest_api_client_request_time_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_rest_api_client_stream_time_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_rest_api_client_request_errors_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_rest_api_client_request_to_fallbacks_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_rest_api_client_urls_score") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon.getGenesis") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "events.eventstream") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_keymanager_requests_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_keymanager_errors_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_keymanager_response_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "validator_keymanager_active_connections") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "lodestar_monitoring_collect_data_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "lodestar_monitoring_send_data_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_doppelganger_validator_status_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "vc_doppelganger_epochs_checked_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "Unverified") != null);
}
