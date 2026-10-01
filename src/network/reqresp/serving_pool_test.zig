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
    try std.testing.expect(pool.retain(retiring));
    pool.retire(0);
    try std.testing.expectEqual(@as(?u16, null), pool.available(&identities[0], true));
    try std.testing.expectEqual(@as(?u16, null), pool.available(&identities[200], true));
    try std.testing.expect(pool.release(retiring));
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
