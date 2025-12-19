//! Simple example to show collection of metrics using metrics.zig.
//!
//! In an actual workload for Lodestar, metrics are scraped on a node process via bindings.
//! The metrics are written and published by native zig code which runs the state transition.
//!
//! Run with `zig build run:metrics_server`
//TODO(bing): think about where this lives within lodestar-z

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    try state_transition.metrics.initializeMetrics(allocator, .{});
    defer state_transition.metrics.state_transition.deinit();

    // blocks
    try serve(allocator, 8008);
}

const MetricsHandler = struct {
    allocator: std.mem.Allocator,
};

pub fn serve(
    allocator: std.mem.Allocator,
    port: u16,
) !void {
    var handler = MetricsHandler{
        .allocator = allocator,
    };
    const address = "0.0.0.0";
    var server = try httpz.Server(*MetricsHandler).init(
        allocator,
        .{ .port = port, .address = address, .thread_pool = .{ .count = 1 } },
        &handler,
    );
    defer {
        server.stop();
        server.deinit();
    }
    var router = try server.router(.{});
    router.get("/metrics", getMetrics, .{});
    //TODO: this is here just for convenience to test metrics. Remove when not needed
    router.get("/run-stf", runStf, .{});

    std.log.info("Listening at {s}/{d}", .{ address, port });
    try server.listen(); // blocks
}

pub fn spawnMetrics(gpa_allocator: std.mem.Allocator, port: u16) !std.Thread {
    const thread = try std.Thread.spawn(.{}, serve, .{ gpa_allocator, port });
    return thread;
}

//TODO: this is here just for convenience to test metrics. Remove when not needed
///
/// Convenience endpoint to simulate a state transition run to collect metrics.
pub fn runStf(_: *MetricsHandler, _: *httpz.Request, _: *httpz.Response) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var test_state = try TestCachedBeaconStateAllForks.init(allocator, 256);
    defer test_state.deinit();
    const electra_block_ptr = try allocator.create(types.electra.SignedBeaconBlock.Type);
    try generateElectraBlock(allocator, test_state.cached_state, electra_block_ptr);
    defer {
        types.electra.SignedBeaconBlock.deinit(allocator, electra_block_ptr);
        allocator.destroy(electra_block_ptr);
    }

    const signed_beacon_block = SignedBeaconBlock{ .electra = electra_block_ptr };
    const signed_block = SignedBlock{ .regular = signed_beacon_block };

    const post_state = try state_transition.stateTransition(
        allocator,
        test_state.cached_state,
        signed_block,
        .{
            .verify_signatures = false,
            .verify_proposer = false,
            .verify_state_root = false,
        },
    );

    defer post_state.deinit();
}

/// Endpoint to write all state transition metrics to the server.
fn getMetrics(_: *MetricsHandler, _: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = .TEXT;
    const writer = res.writer();
    try state_transition.metrics.write(writer);
}

const httpz = @import("httpz");

const std = @import("std");
const state_transition = @import("state_transition");
const metrics = @import("metrics_ext");
const types = @import("consensus_types");

const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const generateElectraBlock = state_transition.test_utils.generateElectraBlock;

const SignedBeaconBlock = state_transition.state_transition.SignedBeaconBlock;
const CachedBeaconStateAllForks = state_transition.CachedBeaconStateAllForks;
const SignedBlock = state_transition.SignedBlock;
