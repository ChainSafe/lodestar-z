const std = @import("std");

const constants = @import("constants.zig");

pub const Slot = u8;

pub const ReceivePool = struct {
    bytes: []u8,
    occupied: std.StaticBitSet(16) = .initEmpty(),
    count: u8,
    frame_bytes: usize,

    pub fn init(allocator: std.mem.Allocator, count: usize, frame_bytes: usize) !ReceivePool {
        if (count == 0 or count > 16 or frame_bytes == 0 or frame_bytes > 2 * constants.GOSSIP_MAX_SIZE) return error.InvalidLimits;
        const bytes = try allocator.alloc(u8, count * frame_bytes);
        return .{ .bytes = bytes, .count = @intCast(count), .frame_bytes = frame_bytes };
    }

    pub fn deinit(self: *ReceivePool, allocator: std.mem.Allocator) void {
        std.debug.assert(self.occupied.count() == 0);
        allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn available(self: *const ReceivePool) usize {
        return self.count - self.occupied.count();
    }

    pub fn claim(self: *ReceivePool) ?Slot {
        for (0..self.count) |index| {
            if (self.occupied.isSet(index)) continue;
            self.occupied.set(index);
            return @intCast(index);
        }
        return null;
    }

    pub fn buffer(self: *ReceivePool, slot: Slot) []u8 {
        std.debug.assert(slot < self.count and self.occupied.isSet(slot));
        const base = @as(usize, slot) * self.frame_bytes;
        return self.bytes[base..][0..self.frame_bytes];
    }

    pub fn release(self: *ReceivePool, slot: Slot) void {
        std.debug.assert(slot < self.count and self.occupied.isSet(slot));
        self.occupied.unset(slot);
    }
};

test "receive pool exhaustion and release reuse owned storage" {
    var pool = try ReceivePool.init(std.testing.allocator, 1, 64);
    defer pool.deinit(std.testing.allocator);
    const first = pool.claim().?;
    @memset(pool.buffer(first), 7);
    try std.testing.expect(pool.claim() == null);
    pool.release(first);
    const second = pool.claim().?;
    try std.testing.expectEqual(first, second);
    try std.testing.expect(pool.claim() == null);
    try std.testing.expectEqual(@as(usize, 64), pool.buffer(second).len);
    pool.release(second);
    try std.testing.expectEqual(@as(usize, 1), pool.available());
}

fn initFailure(allocator: std.mem.Allocator) !void {
    var pool = try ReceivePool.init(allocator, 2, 64);
    defer pool.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 128), pool.bytes.len);
}

test "receive pool partial initialization unwinds" {
    try std.testing.expectError(error.InvalidLimits, ReceivePool.init(std.testing.allocator, 0, 64));
    try std.testing.expectError(error.InvalidLimits, ReceivePool.init(std.testing.allocator, 17, 64));
    try std.testing.expectError(error.InvalidLimits, ReceivePool.init(std.testing.allocator, 1, 0));
    try std.testing.expectError(error.InvalidLimits, ReceivePool.init(std.testing.allocator, 1, 2 * constants.GOSSIP_MAX_SIZE + 1));
    var maximum = try ReceivePool.init(std.testing.allocator, 1, 2 * constants.GOSSIP_MAX_SIZE);
    defer maximum.deinit(std.testing.allocator);
    const lease = maximum.claim().?;
    try std.testing.expectEqual(@as(usize, 2 * constants.GOSSIP_MAX_SIZE), maximum.buffer(lease).len);
    maximum.release(lease);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initFailure, .{});
}
