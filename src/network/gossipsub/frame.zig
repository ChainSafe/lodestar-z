const std = @import("std");
const constants = @import("constants.zig");
const protobuf = @import("protobuf.zig");

const assert = std.debug.assert;

pub const Error = error{ FrameTooLarge, VarintTooLong, BufferTooSmall };

/// The bytes an unsigned-varint length prefix needs for a frame of `body_len`.
pub fn prefixLen(body_len: usize) usize {
    return protobuf.varintLen(body_len);
}

/// Writes `body` framed with its unsigned-varint length prefix into `out` and
/// returns the framed slice. `out` must hold `prefixLen(body.len) + body.len`.
pub fn writeFrame(out: []u8, body: []const u8) []const u8 {
    var writer = protobuf.Writer.init(out);
    writer.varint(body.len);
    writer.bytes(body);
    return writer.written();
}

pub const Result = struct { consumed: usize, frame: ?[]const u8 };

/// A resumable length-prefixed frame reader. Stream bytes are fed in; body bytes
/// accumulate into a caller-provided buffer so the engine can grow it for a rare
/// large frame. State survives a `BufferTooSmall` so the caller re-feeds the
/// remaining input into a bigger body buffer.
pub const Reader = struct {
    prefix: [constants_varint_max]u8 = undefined,
    prefix_len: u8 = 0,
    declared: ?usize = null,
    filled: usize = 0,

    const constants_varint_max = 10;

    /// Returns the declared body length once the prefix has been parsed, so the
    /// caller can size the body buffer before feeding more.
    pub fn declaredLen(self: *const Reader) ?usize {
        return self.declared;
    }

    pub fn feed(self: *Reader, input: []const u8, body: []u8) Error!Result {
        var pos: usize = 0;
        if (self.declared == null) {
            while (pos < input.len) {
                const byte = input[pos];
                pos += 1;
                if (self.prefix_len == constants_varint_max) return error.VarintTooLong;
                self.prefix[self.prefix_len] = byte;
                self.prefix_len += 1;
                if (byte & 0x80 == 0) {
                    var reader = protobuf.Reader.init(self.prefix[0..self.prefix_len]);
                    const len = reader.varint() catch return error.VarintTooLong;
                    if (len > constants.GOSSIP_MAX_SIZE) return error.FrameTooLarge;
                    self.declared = @intCast(len);
                    self.filled = 0;
                    break;
                }
            }
            if (self.declared == null) return .{ .consumed = pos, .frame = null };
        }
        const declared = self.declared.?;
        if (declared > body.len) return error.BufferTooSmall;
        const want = declared - self.filled;
        const take = @min(want, input.len - pos);
        @memcpy(body[self.filled..][0..take], input[pos..][0..take]);
        self.filled += take;
        pos += take;
        if (self.filled == declared) {
            self.declared = null;
            self.prefix_len = 0;
            return .{ .consumed = pos, .frame = body[0..declared] };
        }
        return .{ .consumed = pos, .frame = null };
    }
};

test "frame reader reads a whole frame and round trips writeFrame" {
    var out: [64]u8 = undefined;
    const framed = writeFrame(&out, "hello frame");
    try std.testing.expectEqual(@as(usize, 1 + 11), framed.len);
    var reader = Reader{};
    var body: [64]u8 = undefined;
    const result = try reader.feed(framed, &body);
    try std.testing.expectEqual(framed.len, result.consumed);
    try std.testing.expectEqualStrings("hello frame", result.frame.?);
}

test "frame reader resumes across split prefix and body" {
    var out: [64]u8 = undefined;
    const framed = writeFrame(&out, "abcdefghij"); // 10-byte body, 1-byte prefix
    var reader = Reader{};
    var body: [64]u8 = undefined;
    // feed one byte at a time
    var offset: usize = 0;
    var got: ?[]const u8 = null;
    while (offset < framed.len) {
        const result = try reader.feed(framed[offset..], &body);
        offset += result.consumed;
        if (result.frame) |frame| got = frame;
        try std.testing.expect(result.consumed > 0);
    }
    try std.testing.expectEqualStrings("abcdefghij", got.?);
}

test "frame reader delivers multiple frames from one buffer" {
    var out: [128]u8 = undefined;
    var writer = protobuf.Writer.init(&out);
    writer.varint(3);
    writer.bytes("aaa");
    writer.varint(3);
    writer.bytes("bbb");
    var reader = Reader{};
    var body: [16]u8 = undefined;
    var input = writer.written();
    const first = try reader.feed(input, &body);
    try std.testing.expectEqualStrings("aaa", first.frame.?);
    input = input[first.consumed..];
    const second = try reader.feed(input, &body);
    try std.testing.expectEqualStrings("bbb", second.frame.?);
}

test "frame reader signals a body too large for the buffer, then resumes" {
    var out: [64]u8 = undefined;
    const framed = writeFrame(&out, "0123456789ABCDEF"); // 16-byte body
    var reader = Reader{};
    var small: [8]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, reader.feed(framed, &small));
    try std.testing.expectEqual(@as(?usize, 16), reader.declaredLen());
    var big: [32]u8 = undefined;
    const result = try reader.feed(framed[1..], &big); // skip the consumed prefix
    try std.testing.expectEqualStrings("0123456789ABCDEF", result.frame.?);
}

test "frame reader rejects an overlong varint" {
    var reader = Reader{};
    var body: [8]u8 = undefined;
    try std.testing.expectError(error.VarintTooLong, reader.feed(&([_]u8{0x80} ** 11), &body));
}
