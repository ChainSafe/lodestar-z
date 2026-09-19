const std = @import("std");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const RequestHandle = @import("events.zig").RequestHandle;
const codec = @import("codec.zig");

const Entry = struct {
    request: ?RequestHandle = null,
    identity: PeerId = undefined,
    control: bool = false,
    retained: bool = false,
    retiring: bool = false,
};

pub const Pool = struct {
    entries: []Entry,
    scratch: []u8,
    control_reserved: u16,
    per_peer_max: u8,

    pub fn init(allocator: std.mem.Allocator, capacity: u16, control_reserved: u16, per_peer_max: u8) !Pool {
        const entries = try allocator.alloc(Entry, capacity);
        errdefer allocator.free(entries);
        @memset(entries, .{});
        const scratch = try allocator.alloc(u8, @as(usize, capacity) * codec.frame_scratch_max);
        return .{ .entries = entries, .scratch = scratch, .control_reserved = control_reserved, .per_peer_max = per_peer_max };
    }

    pub fn deinit(self: *Pool, allocator: std.mem.Allocator) void {
        allocator.free(self.scratch);
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn memoryBytes(self: *const Pool) usize {
        return self.scratch.len + self.entries.len * @sizeOf(Entry);
    }

    pub fn available(self: *const Pool, identity: *const PeerId, control: bool) ?u16 {
        var occupied: usize = 0;
        for (self.entries) |*entry| {
            if (entry.request != null and entry.control == control and entry.identity.eql(identity)) occupied += 1;
        }
        // Control replies need no asynchronous host work. One blocked writer per
        // identity leaves the control reserve available to other peers.
        if (control and self.control_reserved > 0 and occupied > 0) return null;
        if (!control and occupied >= self.per_peer_max) return null;
        const start: usize = if (control) 0 else self.control_reserved;
        const end: usize = if (control and self.control_reserved != 0) self.control_reserved else self.entries.len;
        for (self.entries[start..end], start..) |*entry, index| if (entry.request == null) return @intCast(index);
        return null;
    }

    pub fn acquire(self: *Pool, index: u16, request: RequestHandle, identity: *const PeerId, control: bool) []u8 {
        std.debug.assert(self.entries[index].request == null);
        self.entries[index] = .{ .request = request, .identity = identity.*, .control = control };
        return self.scratch[@as(usize, index) * codec.frame_scratch_max ..][0..codec.frame_scratch_max];
    }

    pub fn retire(self: *Pool, index: u16) void {
        const entry = &self.entries[index];
        std.debug.assert(entry.request != null and !entry.retiring);
        if (entry.retained) entry.retiring = true else entry.* = .{};
    }

    pub fn retain(self: *Pool, request: RequestHandle) bool {
        const entry = self.find(request) orelse return false;
        if (entry.retained or entry.retiring) return false;
        entry.retained = true;
        return true;
    }

    pub fn release(self: *Pool, request: RequestHandle) bool {
        const entry = self.find(request) orelse return false;
        if (!entry.retained) return false;
        entry.retained = false;
        if (entry.retiring) entry.* = .{};
        return true;
    }

    fn find(self: *Pool, request: RequestHandle) ?*Entry {
        for (self.entries) |*entry| if (entry.request) |handle| {
            if (std.meta.eql(handle, request)) return entry;
        };
        return null;
    }
};
