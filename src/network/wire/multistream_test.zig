const std = @import("std");
const multistream = @import("multistream.zig");

const ping = "/ipfs/ping/1.0.0";
const other = "/other/1.0.0";

test "multistream messages are varint length prefixed lines" {
    var buffer: [multistream.message_length_max]u8 = undefined;
    const encoded = try multistream.encodeMessage(multistream.header, &buffer);
    try std.testing.expectEqual(@as(u8, 19), encoded[0]);
    try std.testing.expectEqualStrings("/multistream/1.0.0\n", encoded[1..]);
    const decoded = (try multistream.decodeMessage(encoded)).?;
    try std.testing.expectEqualStrings(multistream.header, decoded.token);
    try std.testing.expectEqual(encoded.len, decoded.consumed);
    try std.testing.expectEqual(@as(?multistream.Message, null), try multistream.decodeMessage(encoded[0..5]));
    try std.testing.expectError(error.Malformed, multistream.decodeMessage(&.{ 0x02, 'a', 'b' }));
    try std.testing.expectError(error.Malformed, multistream.decodeMessage(&.{0x00}));
    try std.testing.expectError(error.TooLong, multistream.decodeMessage(&.{ 0xff, 0x01 }));
    var small: [4]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, multistream.encodeMessage(multistream.header, &small));
    try std.testing.expectError(error.TooLong, multistream.encodeMessage("x" ** 129, &buffer));
}

test "multistream dialer and listener agree on a protocol" {
    var dialer = try multistream.Dialer.init(ping);
    var listener = multistream.Listener.init(&.{ other, ping });

    var dial_buffer: [2 * multistream.message_length_max]u8 = undefined;
    const dial_bytes = try dialer.initialWrite(&dial_buffer);

    var reply_buffer: [2 * multistream.message_length_max]u8 = undefined;
    const half = dial_bytes.len / 2;
    const first = try listener.feed(dial_bytes[0..half], &reply_buffer);
    try std.testing.expectEqual(multistream.ListenerStatus.pending, first.status);
    const second = try listener.feed(dial_bytes[first.consumed..], reply_buffer[first.write.len..]);
    try std.testing.expectEqual(multistream.ListenerStatus{ .selected = 1 }, second.status);
    try std.testing.expectEqual(dial_bytes.len, first.consumed + second.consumed);

    const reply = reply_buffer[0 .. first.write.len + second.write.len];
    const outcome = try dialer.feed(reply);
    try std.testing.expectEqual(multistream.Status.accepted, outcome.status);
    try std.testing.expectEqual(reply.len, outcome.consumed);
}

test "multistream listener answers na and bounds proposals" {
    var listener = multistream.Listener.init(&.{ping});
    var request: [4 * multistream.message_length_max]u8 = undefined;
    var cursor: usize = 0;
    cursor += (try multistream.encodeMessage(multistream.header, request[cursor..])).len;
    cursor += (try multistream.encodeMessage(other, request[cursor..])).len;
    var reply: [4 * multistream.message_length_max]u8 = undefined;
    const outcome = try listener.feed(request[0..cursor], &reply);
    try std.testing.expectEqual(multistream.ListenerStatus.pending, outcome.status);
    const decoded_header = (try multistream.decodeMessage(outcome.write)).?;
    try std.testing.expectEqualStrings(multistream.header, decoded_header.token);
    const decoded_na = (try multistream.decodeMessage(outcome.write[decoded_header.consumed..])).?;
    try std.testing.expectEqualStrings(multistream.na, decoded_na.token);

    var proposals: [5 * multistream.message_length_max]u8 = undefined;
    var proposals_len: usize = 0;
    for (0..4) |_| proposals_len += (try multistream.encodeMessage(other, proposals[proposals_len..])).len;
    const bounded = try listener.feed(proposals[0..proposals_len], &reply);
    try std.testing.expectEqual(multistream.ListenerStatus.failed, bounded.status);
    try std.testing.expectEqual(@as(usize, 3 * 4), bounded.write.len);

    var dialer = try multistream.Dialer.init(ping);
    var rejected: [2 * multistream.message_length_max]u8 = undefined;
    var rejected_len: usize = 0;
    rejected_len += (try multistream.encodeMessage(multistream.header, rejected[rejected_len..])).len;
    rejected_len += (try multistream.encodeMessage(multistream.na, rejected[rejected_len..])).len;
    try std.testing.expectEqual(multistream.Status.rejected, (try dialer.feed(rejected[0..rejected_len])).status);

    var wrong_header = try multistream.Dialer.init(ping);
    var bad: [2 * multistream.message_length_max]u8 = undefined;
    const bad_len = (try multistream.encodeMessage(other, &bad)).len;
    try std.testing.expectError(error.Malformed, wrong_header.feed(bad[0..bad_len]));
    try std.testing.expectError(error.TooLong, multistream.Dialer.init("x" ** 129));
}
