//! Node orchestrator module.
//!
//! Provides the top-level BeaconNode struct that ties together all beacon
//! chain components: state transition, caches, database, operation pools,
//! networking handlers, and the REST API.
//!
//! This is the main entry point for a running beacon node instance.

const std = @import("std");
const testing = std.testing;

pub const beacon_node = @import("beacon_node.zig");
pub const clock = @import("clock.zig");
pub const options = @import("options.zig");

pub const BeaconNode = beacon_node.BeaconNode;
pub const HeadTracker = beacon_node.HeadTracker;
pub const BlockImporter = beacon_node.BlockImporter;
pub const ImportResult = beacon_node.ImportResult;
pub const HeadInfo = beacon_node.HeadInfo;
pub const SyncStatus = beacon_node.SyncStatus;

pub const sync_controller = @import("sync_controller.zig");
pub const SyncController = sync_controller.SyncController;
pub const BlockRequester = sync_controller.BlockRequester;

pub const SlotClock = clock.SlotClock;
pub const NodeOptions = options.NodeOptions;
pub const NetworkName = options.NetworkName;

pub const metrics_mod = @import("metrics.zig");
pub const BeaconMetrics = metrics_mod.BeaconMetrics;

pub const metrics_server_mod = @import("metrics_server.zig");
pub const MetricsServer = metrics_server_mod.MetricsServer;

test {
    testing.refAllDecls(@This());
}

pub const gossip_handler_mod = @import("gossip_handler.zig");
pub const GossipHandler = gossip_handler_mod.GossipHandler;
