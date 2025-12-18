//! Simple example to show collection of metrics using metrics.zig.
//!
//! In an actual workload for Lodestar, metrics are scraped on a node process via bindings.
//! The metrics are written and published by native zig code which runs the state transition.
//!
//! Run with `zig build run:metrics_server`

//TODO: Set up prometheus?
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    try state_transition.metrics.initializeMetrics(allocator, .{});
    defer state_transition.metrics.deinitMetrics(&state_transition.metrics.state_transition);

    // blocks
    try metrics.server.serve(allocator, 8008);
}

const std = @import("std");
const state_transition = @import("state_transition");
const metrics = @import("metrics_mod");
const types = @import("consensus_types");

const TestCachedBeaconStateAllForks = state_transition.test_utils.TestCachedBeaconStateAllForks;
const generateElectraBlock = state_transition.test_utils.generateElectraBlock;

const SignedBeaconBlock = state_transition.state_transition.SignedBeaconBlock;
const CachedBeaconStateAllForks = state_transition.CachedBeaconStateAllForks;
const SignedBlock = state_transition.SignedBlock;
