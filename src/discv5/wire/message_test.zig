const std = @import("std");
const constants = @import("constants.zig");
const message = @import("message.zig");
const rlp = @import("rlp.zig");

test "request IDs preserve length and reject more than eight bytes" {
    const short = try message.RequestId.init(&.{ 0x01, 0x00 });
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, short.slice());
    try std.testing.expectError(
        message.Error.InvalidMessage,
        message.RequestId.init(&([_]u8{0} ** 9)),
    );
}

test "all RPC messages round-trip without allocation" {
    const request_id = try message.RequestId.init(&.{ 0x01, 0x00 });
    const enr = [_]u8{ 0x83, 'e', 'n', 'r' };
    const enrs = [_][]const u8{&enr};
    const cases = [_]message.Message{
        .{ .ping = .{ .request_id = request_id, .enr_sequence = 2 } },
        .{ .pong = .{
            .request_id = request_id,
            .enr_sequence = 3,
            .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } },
            .recipient_port = 9_000,
        } },
        .{ .find_node = .{ .request_id = request_id, .distances = &.{ 0, 1, 256 } } },
        .{ .nodes = .{ .request_id = request_id, .total = 1, .enrs = &enrs } },
        .{ .talk_request = .{
            .request_id = request_id,
            .protocol = "portal",
            .request = "request",
        } },
        .{ .talk_response = .{ .request_id = request_id, .response = "response" } },
    };

    var encoded: [constants.message_size_max]u8 = undefined;
    var scratch: message.DecodeScratch = .{};
    for (&cases) |*expected| {
        const bytes = try expected.encode(&encoded);
        const actual = try message.Message.decode(bytes, &scratch);
        try expectMessageEqual(expected, &actual);
    }
}

test "message decoder rejects trailing fields and bytes" {
    var buffer: [64]u8 = undefined;
    const ping = message.Message{ .ping = .{
        .request_id = try message.RequestId.init(&.{0x01}),
        .enr_sequence = 2,
    } };
    const encoded = try ping.encode(&buffer);
    var with_trailing: [65]u8 = undefined;
    @memcpy(with_trailing[0..encoded.len], encoded);
    with_trailing[encoded.len] = 0x80;
    var scratch: message.DecodeScratch = .{};
    try std.testing.expectError(
        message.Error.InvalidEncoding,
        message.Message.decode(with_trailing[0 .. encoded.len + 1], &scratch),
    );

    const extra_field = [_]u8{ 0x01, 0xc3, 0x01, 0x02, 0x80 };
    try std.testing.expectError(
        message.Error.InvalidEncoding,
        message.Message.decode(&extra_field, &scratch),
    );
}

test "FINDNODE validates every distance before publishing scratch" {
    var encoded: [64]u8 = undefined;
    encoded[0] = 0x03;
    var writer = rlp.Writer.init(encoded[1..]);
    const outer = try writer.beginList();
    try writer.writeBytes(&.{0x01});
    const distances = try writer.beginList();
    try writer.writeUint(1);
    try writer.writeUint(257);
    writer.finishList(distances);
    writer.finishList(outer);
    const encoded_length = writer.bytes().len + 1;
    var scratch: message.DecodeScratch = .{};
    @memset(&scratch.distances, 0xa5a5);
    const before = scratch.distances;

    try std.testing.expectError(
        message.Error.InvalidMessage,
        message.Message.decode(encoded[0..encoded_length], &scratch),
    );
    try std.testing.expectEqualSlices(u16, &before, &scratch.distances);
}

test "NODES enforces the bounded ENR count" {
    const request_id = try message.RequestId.init(&.{});
    const enrs = [_][]const u8{&.{0x80}} ** (constants.nodes_enrs_max + 1);
    const nodes = message.Message{ .nodes = .{
        .request_id = request_id,
        .total = 1,
        .enrs = &enrs,
    } };
    var encoded: [constants.message_size_max]u8 = undefined;
    try std.testing.expectError(message.Error.InvalidMessage, nodes.encode(&encoded));
}

fn expectMessageEqual(expected: *const message.Message, actual: *const message.Message) !void {
    try std.testing.expectEqual(std.meta.activeTag(expected.*), std.meta.activeTag(actual.*));
    switch (expected.*) {
        .ping => |value| try std.testing.expectEqualDeep(value, actual.ping),
        .pong => |value| try std.testing.expectEqualDeep(value, actual.pong),
        .find_node => |value| {
            try expectRequestIdEqual(value.request_id, actual.find_node.request_id);
            try std.testing.expectEqualSlices(u16, value.distances, actual.find_node.distances);
        },
        .nodes => |value| {
            try expectRequestIdEqual(value.request_id, actual.nodes.request_id);
            try std.testing.expectEqual(value.total, actual.nodes.total);
            for (value.enrs, actual.nodes.enrs) |expected_enr, actual_enr| {
                try std.testing.expectEqualSlices(u8, expected_enr, actual_enr);
            }
        },
        .talk_request => |value| {
            try expectRequestIdEqual(value.request_id, actual.talk_request.request_id);
            try std.testing.expectEqualSlices(u8, value.protocol, actual.talk_request.protocol);
            try std.testing.expectEqualSlices(u8, value.request, actual.talk_request.request);
        },
        .talk_response => |value| {
            try expectRequestIdEqual(value.request_id, actual.talk_response.request_id);
            try std.testing.expectEqualSlices(u8, value.response, actual.talk_response.response);
        },
    }
}

fn expectRequestIdEqual(expected: message.RequestId, actual: message.RequestId) !void {
    try std.testing.expectEqualSlices(u8, expected.slice(), actual.slice());
}
