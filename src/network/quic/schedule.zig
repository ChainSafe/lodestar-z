const std = @import("std");
const api = @import("api.zig");
const constants = @import("../constants.zig");
const types = @import("../types.zig");
const assert = std.debug.assert;

pub const Entry = struct {
    handle: ?api.Handle = null,
    deadline_ns: u64 = 0,
    destination: types.Address = .unspecified,
    length: u16 = 0,
    bytes: [constants.datagram_size_max]u8 = undefined,
};

/// One reserved datagram per connection prevents a future-paced peer from occupying
/// another peer's output storage. Native send must only run when that reservation is free.
pub const Queue = struct {
    entries: []Entry,
    count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, connections: u16) std.mem.Allocator.Error!Queue {
        assert(connections > 0);
        assert(connections <= @import("limits.zig").connections_max_ceiling);
        const entries = try allocator.alloc(Entry, connections);
        @memset(entries, .{});
        return .{ .entries = entries };
    }

    pub fn deinit(self: *Queue, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn owner(self: *const Queue, index: u16) ?api.Handle {
        assert(index < self.entries.len);
        return self.entries[index].handle;
    }

    pub fn put(self: *Queue, handle: api.Handle, sent: types.Sent) error{Occupied}!void {
        assert(handle.index < self.entries.len);
        assert(sent.bytes.len > 0 and sent.bytes.len <= constants.datagram_size_max);
        const entry = &self.entries[handle.index];
        if (entry.handle != null) return error.Occupied;
        @memcpy(entry.bytes[0..sent.bytes.len], sent.bytes);
        entry.length = @intCast(sent.bytes.len);
        entry.destination = sent.to;
        entry.deadline_ns = sent.transmit_at_ns;
        entry.handle = handle;
        self.count += 1;
        assert(self.count <= self.entries.len);
    }

    pub fn ready(self: *Queue, index: u16, now_ns: u64) ?types.Sent {
        assert(index < self.entries.len);
        const entry = &self.entries[index];
        if (entry.handle == null or entry.deadline_ns > now_ns) return null;
        return .{
            .bytes = entry.bytes[0..entry.length],
            .to = entry.destination,
            .transmit_at_ns = entry.deadline_ns,
        };
    }

    pub fn remove(self: *Queue, index: u16) void {
        assert(index < self.entries.len);
        if (self.entries[index].handle == null) return;
        assert(self.count > 0);
        self.entries[index].handle = null;
        self.count -= 1;
    }

    pub fn nextDeadline(self: *const Queue) ?u64 {
        var earliest: ?u64 = null;
        for (self.entries) |*entry| {
            if (entry.handle == null) continue;
            earliest = @min(earliest orelse entry.deadline_ns, entry.deadline_ns);
        }
        return earliest;
    }
};

pub const Cursor = struct {
    position: u16 = 0,

    pub fn next(self: *Cursor, active: []const u16) ?u16 {
        if (active.len == 0) return null;
        self.position %= @intCast(active.len);
        const index = active[self.position];
        self.position = @intCast((self.position + 1) % active.len);
        return index;
    }
};

pub const Turn = struct {
    send_max: u32,
    work_max: u32,
    sent: u32 = 0,
    work: u32 = 0,

    pub fn init(send_max: u32, work_max: u32) Turn {
        assert(send_max > 0 and work_max > 0);
        return .{ .send_max = send_max, .work_max = work_max };
    }

    pub fn takeWork(self: *Turn) bool {
        if (self.work == self.work_max) return false;
        self.work += 1;
        return true;
    }

    pub fn canSend(self: *const Turn) bool {
        return self.sent < self.send_max;
    }

    pub fn recordSend(self: *Turn) void {
        assert(self.canSend());
        self.sent += 1;
    }
};

pub fn remainingMs(deadline_ns: u64, now_ns: u64) u64 {
    const delta = deadline_ns -| now_ns;
    return delta / std.time.ns_per_ms + @intFromBool(delta % std.time.ns_per_ms != 0);
}
