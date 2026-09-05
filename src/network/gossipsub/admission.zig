const std = @import("std");
const protobuf = @import("protobuf.zig");
const topic = @import("topic.zig");
const constants = @import("constants.zig");
const snappy = @import("snappy");

pub const Header = union(enum) { rejected, invalid, payload: usize };
pub const Decoded = union(enum) {
    invalid: topic.MessageId,
    valid: struct { id: topic.MessageId, bytes: []const u8 },
};

pub fn inspect(msg: *const protobuf.Message) Header {
    if (msg.signed or msg.data.len > constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE)) return .rejected;
    const size = snappy.raw.uncompressedLength(msg.data) catch return .invalid;
    if (size > constants.MAX_PAYLOAD_SIZE) return .rejected;
    return .{ .payload = size };
}

/// Call after inspect returns payload, with output sized to that declared length.
pub fn decode(msg: *const protobuf.Message, output: []u8, policy: topic.MessageIdPolicy) Decoded {
    const header = inspect(msg);
    std.debug.assert(header == .payload and header.payload == output.len);
    const written = snappy.raw.uncompress(msg.data, output) catch {
        return .{ .invalid = topic.invalidMessageId(msg.topic, msg.data, policy) };
    };
    std.debug.assert(written == output.len);
    return .{ .valid = .{ .id = topic.validMessageId(msg.topic, output[0..written], policy), .bytes = output[0..written] } };
}

test "gossip admission rejects signed and malformed payloads and preserves exact IDs" {
    const name = "/eth2/01000000/beacon_block/ssz_snappy";
    var output: [5]u8 = undefined;
    const valid = protobuf.Message{ .topic = name, .data = &.{ 5, 16, 'h', 'e', 'l', 'l', 'o' } };
    try std.testing.expectEqual(@as(usize, 5), inspect(&valid).payload);
    const decoded = decode(&valid, &output, .{}).valid;
    try std.testing.expectEqualStrings("hello", decoded.bytes);
    try std.testing.expectEqual(topic.validMessageId(name, "hello", .{}), decoded.id);
    var signed = valid;
    signed.signed = true;
    try std.testing.expect(inspect(&signed) == .rejected);
    const bad_header = protobuf.Message{ .topic = name, .data = &.{0xff} };
    try std.testing.expect(inspect(&bad_header) == .invalid);
    const bad_body = protobuf.Message{ .topic = name, .data = &.{5} };
    try std.testing.expectEqual(@as(usize, 5), inspect(&bad_body).payload);
    try std.testing.expectEqual(topic.invalidMessageId(name, bad_body.data, .{}), decode(&bad_body, &output, .{}).invalid);
    const oversize = protobuf.Message{ .topic = name, .data = &.{ 0x81, 0x80, 0x80, 5 } };
    try std.testing.expect(inspect(&oversize) == .rejected);
}

test "gossip admission validates compressed and declared payload boundaries" {
    const maximum = protobuf.Message{ .topic = "topic", .data = &.{ 0x80, 0x80, 0x80, 5 } };
    try std.testing.expectEqual(@as(usize, constants.MAX_PAYLOAD_SIZE), inspect(&maximum).payload);
    const oversized = try std.testing.allocator.alloc(u8, constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + 1);
    defer std.testing.allocator.free(oversized);
    const too_long = protobuf.Message{ .topic = "topic", .data = oversized };
    try std.testing.expect(inspect(&too_long) == .rejected);
    const empty = protobuf.Message{ .topic = "topic", .data = &.{0} };
    try std.testing.expectEqual(@as(usize, 0), inspect(&empty).payload);
    try std.testing.expectEqual(@as(usize, 0), decode(&empty, &.{}, .{}).valid.bytes.len);
}
