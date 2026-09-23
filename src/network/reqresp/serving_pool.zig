const std = @import("std");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const RequestHandle = @import("events.zig").RequestHandle;
const codec = @import("codec.zig");
const protocol = @import("protocol.zig");
const control_scratch = codec.frameLengthMax(@max(protocol.payloadMaxControl(), codec.error_message_max));

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
        std.debug.assert(control_reserved <= capacity);
        const entries = try allocator.alloc(Entry, capacity);
        errdefer allocator.free(entries);
        @memset(entries, .{});
        const scratch = try allocator.alloc(u8, @as(usize, control_reserved) * control_scratch + @as(usize, capacity - control_reserved) * codec.frame_scratch_max);
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
        const reserved = index < self.control_reserved;
        std.debug.assert(!reserved or control);
        const offset = if (reserved) @as(usize, index) * control_scratch else @as(usize, self.control_reserved) * control_scratch + @as(usize, index - self.control_reserved) * codec.frame_scratch_max;
        return self.scratch[offset..][0..if (reserved) control_scratch else codec.frame_scratch_max];
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

test "control writers isolate two hundred identities with small scratch and bounded retirement" {
    var pool = try Pool.init(std.testing.allocator, 202, 200, 2);
    defer pool.deinit(std.testing.allocator);
    const ids = [_]PeerId{.{ .bytes = @splat(0) }} ** 201;
    var identities = ids;
    for (&identities, 0..) |*identity, index| std.mem.writeInt(u16, identity.bytes[0..2], @intCast(index), .little);
    for (identities[0..200], 0..) |*identity, index| {
        const slot = pool.available(identity, true).?;
        const scratch = pool.acquire(slot, .{ .index = @intCast(index), .generation = 1, .direction = .inbound }, identity, true);
        try std.testing.expect(scratch.len < 1024);
        const status: [92]u8 = @splat(0);
        _ = try codec.encodeChunk(0, null, &status, scratch);
        try std.testing.expectEqual(@as(?u16, null), pool.available(identity, true));
    }
    try std.testing.expectEqual(@as(?u16, null), pool.available(&identities[200], true));
    const application = pool.available(&identities[200], false).?;
    try std.testing.expectEqual(@as(usize, codec.frame_scratch_max), pool.acquire(application, .{ .index = 200, .generation = 1, .direction = .inbound }, &identities[200], false).len);
    const retiring: RequestHandle = .{ .index = 0, .generation = 1, .direction = .inbound };
    try std.testing.expect(pool.retain(retiring));
    pool.retire(0);
    try std.testing.expectEqual(@as(?u16, null), pool.available(&identities[0], true));
    try std.testing.expectEqual(@as(?u16, null), pool.available(&identities[200], true));
    try std.testing.expect(pool.release(retiring));
    try std.testing.expectEqual(@as(?u16, 0), pool.available(&identities[200], true));
    try std.testing.expectEqual(@as(usize, 200 * control_scratch + 2 * codec.frame_scratch_max), pool.scratch.len);
}
