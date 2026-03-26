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

test {
    testing.refAllDecls(@This());
}
