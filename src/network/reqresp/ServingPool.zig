const std = @import("std");
const AddressGroup = @import("udp").AddressGroup;
const RequestHandle = @import("events.zig").RequestHandle;

pub const Handle = struct { index: u16, generation: u64 };

const Entry = struct {
    generation: u64 = 0,
    request: ?RequestHandle = null,
    group: AddressGroup = undefined,
    retained: bool = false,
    retiring: bool = false,
};

const ServingPool = @This();

entries: []Entry,
scratch: []u8,
scratch_bytes: usize,
per_group_max: u8,

pub fn init(allocator: std.mem.Allocator, capacity: u16, per_group_max: u8, scratch_bytes: usize) !ServingPool {
    std.debug.assert(capacity > 0 and per_group_max > 0 and scratch_bytes > 0);
    const entries = try allocator.alloc(Entry, capacity);
    errdefer allocator.free(entries);
    @memset(entries, .{});
    const scratch = try allocator.alloc(u8, @as(usize, capacity) * scratch_bytes);
    return .{ .entries = entries, .scratch = scratch, .scratch_bytes = scratch_bytes, .per_group_max = per_group_max };
}

pub fn deinit(self: *ServingPool, allocator: std.mem.Allocator) void {
    allocator.free(self.scratch);
    allocator.free(self.entries);
    self.* = undefined;
}

pub fn memoryBytes(self: *const ServingPool) usize {
    return self.scratch.len + self.entries.len * @sizeOf(Entry);
}

pub fn available(self: *const ServingPool, group: AddressGroup) ?u16 {
    var occupied: usize = 0;
    for (self.entries) |*entry| {
        if (entry.request != null and entry.group.eql(group)) occupied += 1;
    }
    if (occupied >= self.per_group_max) return null;
    for (self.entries, 0..) |*entry, index| if (entry.request == null and entry.generation != std.math.maxInt(u64)) return @intCast(index);
    return null;
}

/// Copies the connection's admission group; host retention keeps it charged after disconnect
/// and limiter-row reuse until both the request and host execution retire.
pub fn acquire(self: *ServingPool, index: u16, request: RequestHandle, group: AddressGroup) []u8 {
    std.debug.assert(self.entries[index].request == null);
    std.debug.assert(self.available(group) == index);
    self.entries[index] = .{ .generation = self.entries[index].generation, .request = request, .group = group };
    const offset = @as(usize, index) * self.scratch_bytes;
    return self.scratch[offset..][0..self.scratch_bytes];
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
