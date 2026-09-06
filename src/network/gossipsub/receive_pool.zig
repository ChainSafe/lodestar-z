const std = @import("std");

const constants = @import("constants.zig");

pub const Lease = struct { index: u8, generation: u64 };
const Slot = struct { generation: u64 = 0, used: bool = false };

pub const ReceivePool = struct {
    bytes: []u8,
    slots: []Slot,
    frame_bytes: usize,

    pub fn init(allocator: std.mem.Allocator, count: usize, frame_bytes: usize) !ReceivePool {
        if (count == 0 or count > 16 or frame_bytes == 0 or frame_bytes > 2 * constants.GOSSIP_MAX_SIZE) return error.InvalidLimits;
        const bytes = try allocator.alloc(u8, count * frame_bytes);
        errdefer allocator.free(bytes);
        const slots = try allocator.alloc(Slot, count);
        errdefer allocator.free(slots);
        @memset(slots, .{});
        return .{ .bytes = bytes, .slots = slots, .frame_bytes = frame_bytes };
    }

    pub fn deinit(self: *ReceivePool, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
        allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn metadataBytes(self: *const ReceivePool) usize {
        return self.slots.len * @sizeOf(Slot);
    }

    pub fn available(self: *const ReceivePool) usize {
        var count: usize = 0;
        for (self.slots) |slot| if (!slot.used and slot.generation < std.math.maxInt(u64)) {
            count += 1;
        };
        return count;
    }

    pub fn claim(self: *ReceivePool) ?Lease {
        for (self.slots, 0..) |*slot, index| {
            if (slot.used or slot.generation == std.math.maxInt(u64)) continue;
            slot.generation += 1;
            slot.used = true;
            return .{ .index = @intCast(index), .generation = slot.generation };
        }
        return null;
    }

    pub fn buffer(self: *ReceivePool, lease: Lease) ?[]u8 {
        if (!self.matches(lease)) return null;
        const base = @as(usize, lease.index) * self.frame_bytes;
        return self.bytes[base..][0..self.frame_bytes];
    }

    pub fn release(self: *ReceivePool, lease: Lease) bool {
        if (!self.matches(lease)) return false;
        self.slots[lease.index].used = false;
        return true;
    }

    fn matches(self: *const ReceivePool, lease: Lease) bool {
        if (lease.index >= self.slots.len) return false;
        const slot = self.slots[lease.index];
        return slot.used and slot.generation == lease.generation;
    }
};

test "receive pool exhaustion release and late lease do not alias a new frame" {
    var pool = try ReceivePool.init(std.testing.allocator, 1, 64);
    defer pool.deinit(std.testing.allocator);
    const first = pool.claim().?;
    @memset(pool.buffer(first).?, 7);
    try std.testing.expect(pool.claim() == null);
    try std.testing.expect(pool.release(first));
    const second = pool.claim().?;
    try std.testing.expect(pool.buffer(first) == null);
    try std.testing.expect(!pool.release(first));
    try std.testing.expect(pool.claim() == null);
    try std.testing.expectEqual(@as(usize, 64), pool.buffer(second).?.len);
    try std.testing.expect(pool.release(second));
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
    try std.testing.expectEqual(@as(usize, 2 * constants.GOSSIP_MAX_SIZE), maximum.buffer(maximum.claim().?).?.len);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initFailure, .{});
}

test "receive pool rejects invalid leases and retires exhausted generations" {
    var pool = try ReceivePool.init(std.testing.allocator, 1, 64);
    defer pool.deinit(std.testing.allocator);
    try std.testing.expect(!pool.release(.{ .index = 1, .generation = 1 }));
    try std.testing.expect(pool.buffer(.{ .index = 0, .generation = 0 }) == null);
    pool.slots[0].generation = std.math.maxInt(u64) - 1;
    const last = pool.claim().?;
    try std.testing.expectEqual(std.math.maxInt(u64), last.generation);
    try std.testing.expect(pool.release(last));
    try std.testing.expectEqual(@as(usize, 0), pool.available());
    try std.testing.expect(pool.claim() == null);
    try std.testing.expect(!pool.release(last));
}
