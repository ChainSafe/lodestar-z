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
pub const identity = @import("identity.zig");
pub const NodeIdentity = identity.NodeIdentity;

pub const BeaconNode = beacon_node.BeaconNode;
pub const HeadTracker = beacon_node.HeadTracker;
pub const ImportResult = beacon_node.ImportResult;
pub const HeadInfo = beacon_node.HeadInfo;
pub const SyncStatus = beacon_node.SyncStatus;

// sync_controller removed — SyncService is the direct entry point.

pub const SlotClock = clock.SlotClock;
pub const NodeOptions = options.NodeOptions;
pub const NetworkName = options.NetworkName;

pub const metrics_mod = @import("metrics.zig");
pub const BeaconMetrics = metrics_mod.BeaconMetrics;

pub const validator_metrics_mod = @import("validator_metrics.zig");
pub const ValidatorMetrics = validator_metrics_mod.ValidatorMetrics;

pub const metrics_server_mod = @import("metrics_server.zig");
pub const MetricsServer = metrics_server_mod.MetricsServer;

test {
    testing.refAllDecls(@This());
}

test {
    _ = @import("beacon_node_test.zig");
}

pub const gossip_handler_mod = @import("gossip_handler.zig");
pub const GossipHandler = gossip_handler_mod.GossipHandler;

// Processor module re-exports for convenience.
pub const processor_mod = @import("processor");
pub const BeaconProcessor = processor_mod.BeaconProcessor;
pub const WorkItem = processor_mod.WorkItem;
pub const WorkType = processor_mod.WorkType;
pub const QueueConfig = processor_mod.QueueConfig;

pub const data_dir_mod = @import("data_dir.zig");
pub const DataDir = data_dir_mod.DataDir;
pub const defaultDataRoot = data_dir_mod.defaultRoot;

pub const jwt_mod = @import("jwt.zig");

pub const block_production_mod = @import("block_production.zig");
pub const block_import_mod = @import("block_import.zig");
// BlockImporter re-exported via beacon_node.BlockImporter (which imports from block_import.zig)

pub const api_callbacks_mod = @import("api_callbacks.zig");
pub const p2p_runtime_mod = @import("p2p_runtime.zig");
pub const lifecycle_mod = @import("lifecycle.zig");

pub const sync_bridge_mod = @import("sync_bridge.zig");
// SyncCallbackCtx re-exported via beacon_node.SyncCallbackCtx

pub const reqresp_callbacks_mod = @import("reqresp_callbacks.zig");
pub const RequestContext = reqresp_callbacks_mod.RequestContext;

pub const gossip_node_callbacks_mod = @import("gossip_node_callbacks.zig");
