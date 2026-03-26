//! BeaconProcessor module.
//!
//! Central priority scheduler that receives all inbound work (gossip, reqresp,
//! API, clock ticks) and dispatches it to workers in priority order. This is
//! the beating heart of the beacon node's real-time scheduling system.

const std = @import("std");
const testing = std.testing;

pub const work_item = @import("work_item.zig");
pub const WorkItem = work_item.WorkItem;
pub const WorkType = work_item.WorkType;

pub const queues = @import("queues.zig");
pub const FifoQueue = queues.FifoQueue;
pub const LifoQueue = queues.LifoQueue;

pub const work_queues = @import("work_queues.zig");
pub const WorkQueues = work_queues.WorkQueues;
pub const QueueConfig = work_queues.QueueConfig;
pub const SyncState = work_queues.SyncState;

pub const processor = @import("processor.zig");
pub const BeaconProcessor = processor.BeaconProcessor;
pub const ProcessorMetrics = processor.ProcessorMetrics;
pub const HandlerFn = processor.HandlerFn;

test {
    testing.refAllDecls(@This());
}
