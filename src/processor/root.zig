//! BeaconProcessor module.
//!
//! Central priority scheduler for the work we currently route through the
//! processor. The active ingress boundary is gossip: raw gossip admission,
//! replay, deferred validation completion, and async gossip verification all
//! live here now.

const std = @import("std");
const testing = std.testing;

pub const work_item = @import("work_item.zig");
pub const WorkItem = work_item.WorkItem;
pub const WorkType = work_item.WorkType;
pub const GossipSource = work_item.GossipSource;
pub const PeerIdHandle = work_item.PeerIdHandle;
pub const OpaqueHandle = work_item.OpaqueHandle;

pub const queues = @import("queues.zig");
pub const FifoQueue = queues.FifoQueue;
pub const LifoQueue = queues.LifoQueue;

pub const work_queues = @import("work_queues.zig");
pub const WorkQueues = work_queues.WorkQueues;
pub const QueueConfig = work_queues.QueueConfig;
pub const SyncState = work_queues.SyncState;

pub const pending_unknown_block_gossip = @import("pending_unknown_block_gossip.zig");

pub const processor = @import("processor.zig");
pub const BeaconProcessor = processor.BeaconProcessor;
pub const ProcessorMetrics = processor.ProcessorMetrics;
pub const HandlerFn = processor.HandlerFn;

test {
    testing.refAllDecls(@This());
}
