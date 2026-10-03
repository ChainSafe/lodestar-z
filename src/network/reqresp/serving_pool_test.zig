const protocol = @import("protocol.zig");
const std = @import("std");
const Pool = @import("ServingPool.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const RequestHandle = @import("events.zig").RequestHandle;
const codec = @import("codec.zig");

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
    const serving = pool.retain(retiring) orelse return error.TestUnexpectedResult;
    pool.retire(0);
    try std.testing.expectEqual(@as(?u16, null), pool.available(&identities[0], true));
    try std.testing.expectEqual(@as(?u16, null), pool.available(&identities[200], true));
    try std.testing.expect(pool.release(serving));
    try std.testing.expectEqual(@as(?u16, 0), pool.available(&identities[200], true));
    try std.testing.expectEqual(@as(usize, 200 * protocol.control_scratch_length + 2 * codec.frame_scratch_max), pool.scratch.len);
}

test "reqresp admission lifecycle a blocked control writer cannot take another peer's execution reserve" {
    var pool = try @import("ServingPool.zig").init(std.testing.allocator, 6, 2, 4);
    defer pool.deinit(std.testing.allocator);
    const first: PeerId = .{ .bytes = @splat(1) };
    const second: PeerId = .{ .bytes = @splat(2) };
    const index = pool.available(&first, true).?;
    _ = pool.acquire(index, .{ .direction = .inbound, .index = 0, .generation = 1 }, &first, true);
    try std.testing.expectEqual(@as(?u16, null), pool.available(&first, true));
    try std.testing.expect(pool.available(&second, true) != null);
    try std.testing.expect(pool.available(&first, false) != null);
    pool.retire(index);
    try std.testing.expect(pool.available(&first, true) != null);
}

test "serving handles reject stale releases across retention and request reuse" {
    var pool = try Pool.init(std.testing.allocator, 1, 0, 1);
    defer pool.deinit(std.testing.allocator);
    const identity: PeerId = .{ .bytes = @splat(1) };
    const request: RequestHandle = .{ .index = 0, .generation = 1, .direction = .inbound };
    _ = pool.acquire(0, request, &identity, false);
    const first = pool.retain(request).?;
    try std.testing.expect(pool.retain(request) == null);
    try std.testing.expect(pool.release(first));
    try std.testing.expect(!pool.release(first));
    const second = pool.retain(request).?;
    try std.testing.expect(!pool.release(first));
    pool.retire(0);
    try std.testing.expect(pool.available(&identity, false) == null);
    try std.testing.expect(pool.release(second));
    try std.testing.expectEqual(@as(?u16, 0), pool.available(&identity, false));
    _ = pool.acquire(0, .{ .index = 0, .generation = 2, .direction = .inbound }, &identity, false);
    const third = pool.retain(.{ .index = 0, .generation = 2, .direction = .inbound }).?;
    try std.testing.expect(!pool.release(second));
    try std.testing.expect(!pool.release(.{ .index = 1, .generation = third.generation }));
    try std.testing.expect(pool.release(third));
    pool.retire(0);
}

test "serving generations exhaust without wrapping" {
    var pool = try Pool.init(std.testing.allocator, 1, 0, 1);
    defer pool.deinit(std.testing.allocator);
    const identity: PeerId = .{ .bytes = @splat(1) };
    const request: RequestHandle = .{ .index = 0, .generation = 1, .direction = .inbound };
    pool.entries[0].generation = std.math.maxInt(u64) - 1;
    _ = pool.acquire(0, request, &identity, false);
    const retained = pool.retain(request).?;
    try std.testing.expectEqual(std.math.maxInt(u64), retained.generation);
    try std.testing.expect(pool.release(retained));
    try std.testing.expect(pool.retain(request) == null);
    pool.retire(0);
    try std.testing.expect(pool.available(&identity, false) == null);
}
