//! Each authenticated connection has independently backed protocol reservations.
//! A selected request keeps its buffers across fork changes and service admission.
const std = @import("std");
const protocol = @import("protocol.zig");
const constants = @import("constants.zig");
const codec = @import("codec.zig");
const Policy = @import("request_policy.zig").Policy;
const Protocol = protocol.Protocol;

pub const slots_per_peer = Protocol.count * constants.MAX_CONCURRENT_REQUESTS;
comptime {
    std.debug.assert(slots_per_peer <= std.math.maxInt(u8));
    std.debug.assert(slots_per_peer * constants.slots_ceiling <= std.math.maxInt(u16));
}
const read_max = 16 * 1024;
const handoff_max = @import("../negotiate.zig").inbox_capacity;

const Entry = struct {
    sink_offset: usize,
    io_offset: usize,
    sink_bytes: usize,
    scratch_bytes: usize,
    read_bytes: usize,
};

pub const Buffers = struct { sink: []u8, scratch: []u8, read: []u8 };

const ReceivePlan = @This();

entries: [Protocol.count]Entry,
sink_bytes: usize = 0,
io_bytes: usize = 0,

pub fn init(policy: *const Policy) ReceivePlan {
    var plan: ReceivePlan = .{ .entries = undefined };
    for (std.enums.values(Protocol)) |which| {
        const size = policy.requestMaxFor(which);
        const scratch = codec.frameLengthMax(@min(constants.frame_uncompressed_max, @max(size, codec.error_message_max, if (which.isControl()) which.info().response_max else 0)));
        const read = @max(handoff_max, @min(read_max, codec.header_max + codec.frameLengthMax(@min(size, constants.frame_uncompressed_max))));
        plan.entries[@intFromEnum(which)] = .{
            .sink_offset = plan.sink_bytes,
            .io_offset = plan.io_bytes,
            .sink_bytes = size,
            .scratch_bytes = scratch,
            .read_bytes = read,
        };
        plan.sink_bytes += constants.MAX_CONCURRENT_REQUESTS * size;
        plan.io_bytes += constants.MAX_CONCURRENT_REQUESTS * (scratch + read);
    }
    return plan;
}

pub fn first(peer: u16, which: Protocol) usize {
    return @as(usize, peer) * slots_per_peer + @as(usize, @intFromEnum(which)) * constants.MAX_CONCURRENT_REQUESTS;
}

pub fn buffers(self: *const ReceivePlan, index: usize, sinks: []u8, arena: []u8) Buffers {
    const peer = index / slots_per_peer;
    const entry = self.entries[(index % slots_per_peer) / constants.MAX_CONCURRENT_REQUESTS];
    const position = index % constants.MAX_CONCURRENT_REQUESTS;
    const sink_offset = peer * self.sink_bytes + entry.sink_offset + position * entry.sink_bytes;
    const io_offset = peer * self.io_bytes + entry.io_offset + position * (entry.scratch_bytes + entry.read_bytes);
    return .{
        .sink = sinks[sink_offset..][0..entry.sink_bytes],
        .scratch = arena[io_offset..][0..entry.scratch_bytes],
        .read = arena[io_offset + entry.scratch_bytes ..][0..entry.read_bytes],
    };
}
