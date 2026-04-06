//! Beacon metrics that are actually emitted by the live beacon-node runtime.
//!
//! The surface here is intentionally small and honest. If a metric is not wired
//! through a real runtime path, it should not be exported from this module.

const std = @import("std");
const metrics_lib = @import("metrics");
const state_transition = @import("state_transition");

pub const Counter = metrics_lib.Counter;
pub const Gauge = metrics_lib.Gauge;
pub const Histogram = metrics_lib.Histogram;

pub const MetricsSurface = struct {
    beacon: *BeaconMetrics,
    state_transition: *state_transition.metrics.StateTransitionMetrics = state_transition.metrics.noop(),

    pub fn write(self: *MetricsSurface, writer: *std.Io.Writer) !void {
        try self.beacon.write(writer);
        if (self.state_transition.isEnabled()) {
            try writer.writeByte('\n');
            try self.state_transition.write(writer);
        }
    }
};

const block_import_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0 };
const el_request_buckets = [_]f64{ 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0 };

pub const BeaconMetrics = struct {
    // Chain state.
    head_slot: Gauge(u64),
    head_root: Gauge(u64),
    finalized_epoch: Gauge(u64),
    justified_epoch: Gauge(u64),

    // Block import.
    blocks_imported_total: Counter(u64),
    block_import_seconds: Histogram(f64, &block_import_buckets),

    // Network / P2P.
    peers_connected: Gauge(u64),
    peer_connected_total: Counter(u64),
    peer_disconnected_total: Counter(u64),
    gossip_messages_received: Counter(u64),
    gossip_messages_validated: Counter(u64),
    gossip_messages_rejected: Counter(u64),
    gossip_messages_ignored: Counter(u64),

    // Discovery / sync.
    discovery_peers_known: Gauge(u64),
    sync_status: Gauge(u64),
    sync_distance: Gauge(u64),

    // Execution layer.
    execution_new_payload_seconds: Histogram(f64, &el_request_buckets),
    execution_forkchoice_updated_seconds: Histogram(f64, &el_request_buckets),
    execution_payload_valid_total: Counter(u64),
    execution_payload_invalid_total: Counter(u64),
    execution_payload_syncing_total: Counter(u64),
    execution_errors_total: Counter(u64),

    pub fn init() BeaconMetrics {
        const ro: metrics_lib.RegistryOpts = .{};
        return .{
            .head_slot = Gauge(u64).init("beacon_head_slot", .{}, ro),
            .head_root = Gauge(u64).init("beacon_head_root", .{}, ro),
            .finalized_epoch = Gauge(u64).init("beacon_finalized_epoch", .{}, ro),
            .justified_epoch = Gauge(u64).init("beacon_justified_epoch", .{}, ro),

            .blocks_imported_total = Counter(u64).init("beacon_blocks_imported_total", .{}, ro),
            .block_import_seconds = Histogram(f64, &block_import_buckets).init("beacon_block_import_seconds", .{}, ro),

            .peers_connected = Gauge(u64).init("p2p_peer_count", .{}, ro),
            .peer_connected_total = Counter(u64).init("p2p_peer_connected_total", .{}, ro),
            .peer_disconnected_total = Counter(u64).init("p2p_peer_disconnected_total", .{}, ro),
            .gossip_messages_received = Counter(u64).init("beacon_gossip_messages_received_total", .{}, ro),
            .gossip_messages_validated = Counter(u64).init("beacon_gossip_messages_validated_total", .{}, ro),
            .gossip_messages_rejected = Counter(u64).init("beacon_gossip_messages_rejected_total", .{}, ro),
            .gossip_messages_ignored = Counter(u64).init("beacon_gossip_messages_ignored_total", .{}, ro),

            .discovery_peers_known = Gauge(u64).init("beacon_discovery_peers_known", .{}, ro),
            .sync_status = Gauge(u64).init("beacon_sync_status", .{}, ro),
            .sync_distance = Gauge(u64).init("beacon_sync_distance", .{}, ro),

            .execution_new_payload_seconds = Histogram(f64, &el_request_buckets).init("execution_new_payload_seconds", .{}, ro),
            .execution_forkchoice_updated_seconds = Histogram(f64, &el_request_buckets).init("execution_forkchoice_updated_seconds", .{}, ro),
            .execution_payload_valid_total = Counter(u64).init("execution_payload_valid_total", .{}, ro),
            .execution_payload_invalid_total = Counter(u64).init("execution_payload_invalid_total", .{}, ro),
            .execution_payload_syncing_total = Counter(u64).init("execution_payload_syncing_total", .{}, ro),
            .execution_errors_total = Counter(u64).init("execution_errors_total", .{}, ro),
        };
    }

    pub fn initNoop() BeaconMetrics {
        return metrics_lib.initializeNoop(BeaconMetrics);
    }

    pub fn write(self: *BeaconMetrics, writer: *std.Io.Writer) !void {
        try metrics_lib.write(self, writer);
    }
};

test "BeaconMetrics: init fields are accessible" {
    var m = BeaconMetrics.init();
    m.head_slot.set(42);
    m.blocks_imported_total.incr();
    m.peers_connected.set(10);
    m.execution_new_payload_seconds.observe(0.1);
    m.peer_connected_total.incr();
    try std.testing.expectEqual(@as(u64, 42), m.head_slot.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.blocks_imported_total.impl.count);
    try std.testing.expectEqual(@as(u64, 10), m.peers_connected.impl.value);
    try std.testing.expectEqual(@as(u64, 1), m.peer_connected_total.impl.count);
}

test "BeaconMetrics: initNoop produces zero-overhead stubs" {
    var m = BeaconMetrics.initNoop();
    m.head_slot.set(999);
    m.blocks_imported_total.incr();
    m.execution_new_payload_seconds.observe(1.0);
    m.peer_connected_total.incr();
    try std.testing.expect(std.meta.activeTag(m.head_slot) == .noop);
    try std.testing.expect(std.meta.activeTag(m.blocks_imported_total) == .noop);
    try std.testing.expect(std.meta.activeTag(m.execution_new_payload_seconds) == .noop);
}

test "BeaconMetrics: write produces live Prometheus output" {
    var m = BeaconMetrics.init();
    m.head_slot.set(100);
    m.finalized_epoch.set(3);
    m.blocks_imported_total.incr();
    m.execution_new_payload_seconds.observe(0.5);
    m.peer_connected_total.incr();

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try m.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_head_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_finalized_epoch") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_blocks_imported_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "execution_new_payload_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "execution_forkchoice_updated_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "p2p_peer_connected_total") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_api_request_seconds") == null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_state_cache_hit_total") == null);
}

test "MetricsSurface: skips noop state-transition metrics" {
    var beacon = BeaconMetrics.init();
    var surface = MetricsSurface{ .beacon = &beacon };
    beacon.head_slot.set(12);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try surface.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_head_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "lodestar_stfn_") == null);
}

test "MetricsSurface: includes enabled state-transition metrics" {
    const io = std.Options.debug_io;
    var beacon = BeaconMetrics.init();
    var st_metrics = try state_transition.metrics.StateTransitionMetrics.init(std.testing.allocator, io, .{});
    defer st_metrics.deinit();
    var surface = MetricsSurface{
        .beacon = &beacon,
        .state_transition = &st_metrics,
    };

    beacon.head_slot.set(12);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try surface.write(&out.writer);

    const buf = out.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, buf, "beacon_head_slot") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf, "lodestar_stfn_epoch_transition_seconds") != null);
}
