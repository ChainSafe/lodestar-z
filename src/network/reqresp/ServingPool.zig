const std = @import("std");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const RequestHandle = @import("events.zig").RequestHandle;
const codec = @import("codec.zig");
const protocol = @import("protocol.zig");

pub const Handle = struct { index: u16, generation: u64 };

const Entry = struct {
    generation: u64 = 0,
    request: ?RequestHandle = null,
    identity: PeerId = undefined,
    control: bool = false,
    retained: bool = false,
    retiring: bool = false,
};

const ServingPool = @This();

entries: []Entry,
scratch: []u8,
control_reserved: u16,
per_peer_max: u8,

pub fn init(allocator: std.mem.Allocator, capacity: u16, control_reserved: u16, per_peer_max: u8) !ServingPool {
    std.debug.assert(control_reserved <= capacity);
    const entries = try allocator.alloc(Entry, capacity);
    errdefer allocator.free(entries);
    @memset(entries, .{});
    const scratch = try allocator.alloc(u8, @as(usize, control_reserved) * protocol.control_scratch_length + @as(usize, capacity - control_reserved) * codec.frame_scratch_max);
    return .{ .entries = entries, .scratch = scratch, .control_reserved = control_reserved, .per_peer_max = per_peer_max };
}

pub fn deinit(self: *ServingPool, allocator: std.mem.Allocator) void {
    allocator.free(self.scratch);
    allocator.free(self.entries);
    self.* = undefined;
}

pub fn memoryBytes(self: *const ServingPool) usize {
    return self.scratch.len + self.entries.len * @sizeOf(Entry);
}

pub fn available(self: *const ServingPool, identity: *const PeerId, control: bool) ?u16 {
    var occupied: usize = 0;
    for (self.entries) |*entry| {
        if (entry.request != null and entry.control == control and entry.identity.eql(identity)) occupied += 1;
    }
    if (control and self.control_reserved > 0 and occupied > 0) return null;
    if (!control and occupied >= self.per_peer_max) return null;
    const start: usize = if (control) 0 else self.control_reserved;
    const end: usize = if (control and self.control_reserved != 0) self.control_reserved else self.entries.len;
    for (self.entries[start..end], start..) |*entry, index| if (entry.request == null and entry.generation != std.math.maxInt(u64)) return @intCast(index);
    return null;
}

pub fn acquire(self: *ServingPool, index: u16, request: RequestHandle, identity: *const PeerId, control: bool) []u8 {
    std.debug.assert(self.entries[index].request == null);
    self.entries[index] = .{ .generation = self.entries[index].generation, .request = request, .identity = identity.*, .control = control };
    const reserved = index < self.control_reserved;
    std.debug.assert(!reserved or control);
    const offset = if (reserved) @as(usize, index) * protocol.control_scratch_length else @as(usize, self.control_reserved) * protocol.control_scratch_length + @as(usize, index - self.control_reserved) * codec.frame_scratch_max;
    return self.scratch[offset..][0..if (reserved) protocol.control_scratch_length else codec.frame_scratch_max];
}

pub fn retire(self: *ServingPool, index: u16) void {
    const entry = &self.entries[index];
    std.debug.assert(entry.request != null and !entry.retiring);
    if (entry.retained) entry.retiring = true else entry.* = .{ .generation = entry.generation };
}

pub fn retain(self: *ServingPool, request: RequestHandle) ?Handle {
    for (self.entries, 0..) |*entry, index| if (entry.request) |handle| {
        if (!std.meta.eql(handle, request)) continue;
        if (entry.retained or entry.retiring or entry.generation == std.math.maxInt(u64)) return null;
        entry.generation += 1;
        entry.retained = true;
        return .{ .index = @intCast(index), .generation = entry.generation };
    };
    return null;
}

pub fn release(self: *ServingPool, handle: Handle) bool {
    if (handle.index >= self.entries.len) return false;
    const entry = &self.entries[handle.index];
    if (!entry.retained or entry.generation != handle.generation) return false;
    entry.retained = false;
    if (entry.retiring) entry.* = .{ .generation = entry.generation };
    return true;
}

test {
    _ = @import("serving_pool_test.zig");
}
