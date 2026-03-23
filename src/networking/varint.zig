//! Unsigned LEB128 varint encoding.
//!
//! Used for the SSZ payload length prefix in the req/resp wire protocol.
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#encoding-strategies

const std = @import("std");
const testing = std.testing;

/// Maximum number of bytes a varint-encoded u64 can occupy.
/// The unsigned protobuf varint used for the length-prefix MUST NOT be longer than 10 bytes.
pub const max_length: usize = 10;

pub const DecodeError = error{
    /// The buffer is empty or truncated mid-varint.
    EndOfInput,
    /// The varint exceeds the 10-byte limit for a u64.
    Overflow,
};

pub const DecodeResult = struct {
    value: u64,
    bytes_consumed: usize,
};

/// Encode `value` as an unsigned LEB128 varint into `buf`.
///
/// Returns the number of bytes written. `buf` must have at least `max_length` bytes available.
pub fn encode(value: u64, buf: []u8) usize {
    std.debug.assert(buf.len >= max_length);

    var v = value;
    var i: usize = 0;

    while (true) {
        const byte: u8 = @truncate(v & 0x7F);
        v >>= 7;
        if (v == 0) {
            buf[i] = byte;
            return i + 1;
        }
        buf[i] = byte | 0x80;
        i += 1;
    }
}

/// Decode an unsigned LEB128 varint from the beginning of `buf`.
///
/// Returns the decoded value and the number of bytes consumed.
pub fn decode(buf: []const u8) DecodeError!DecodeResult {
    if (buf.len == 0) {
        return DecodeError.EndOfInput;
    }

    var value: u64 = 0;
    var i: usize = 0;

    while (i < buf.len) {
        if (i >= max_length) {
            return DecodeError.Overflow;
        }

        const byte = buf[i];
        // For the 10th byte (i == 9), only the lowest bit is valid for u64.
        if (i == 9 and byte > 1) {
            return DecodeError.Overflow;
        }
        value |= @as(u64, byte & 0x7F) << @intCast(i * 7);
        i += 1;

        // MSB not set means this is the last byte.
        if (byte & 0x80 == 0) {
            return .{ .value = value, .bytes_consumed = i };
        }
    }

    // Ran out of bytes before seeing a terminating byte.
    return DecodeError.EndOfInput;
}

/// Return the number of bytes needed to encode `value` as unsigned LEB128.
pub fn encodingLength(value: u64) usize {
    if (value == 0) return 1;

    // Number of bits needed, divided by 7, rounded up.
    const bits = 64 - @as(usize, @clz(value));
    return (bits + 6) / 7;
}

// === Tests ===

test "encode and decode zero" {
    var buf: [max_length]u8 = undefined;
    const n = encode(0, &buf);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x00), buf[0]);

    const result = try decode(buf[0..n]);
    try testing.expectEqual(@as(u64, 0), result.value);
    try testing.expectEqual(@as(usize, 1), result.bytes_consumed);
}

test "encode and decode single byte values" {
    var buf: [max_length]u8 = undefined;

    // Value 1.
    const n1 = encode(1, &buf);
    try testing.expectEqual(@as(usize, 1), n1);
    try testing.expectEqual(@as(u8, 0x01), buf[0]);
    const r1 = try decode(buf[0..n1]);
    try testing.expectEqual(@as(u64, 1), r1.value);

    // Value 127 (max single-byte).
    const n127 = encode(127, &buf);
    try testing.expectEqual(@as(usize, 1), n127);
    try testing.expectEqual(@as(u8, 0x7F), buf[0]);
    const r127 = try decode(buf[0..n127]);
    try testing.expectEqual(@as(u64, 127), r127.value);
}

test "encode and decode multi-byte values" {
    var buf: [max_length]u8 = undefined;

    // 128 -> 0x80 0x01.
    const n128 = encode(128, &buf);
    try testing.expectEqual(@as(usize, 2), n128);
    try testing.expectEqual(@as(u8, 0x80), buf[0]);
    try testing.expectEqual(@as(u8, 0x01), buf[1]);
    const r128 = try decode(buf[0..n128]);
    try testing.expectEqual(@as(u64, 128), r128.value);

    // 300 -> 0xAC 0x02.
    const n300 = encode(300, &buf);
    try testing.expectEqual(@as(usize, 2), n300);
    const r300 = try decode(buf[0..n300]);
    try testing.expectEqual(@as(u64, 300), r300.value);
}

test "encode and decode u64 max" {
    var buf: [max_length]u8 = undefined;
    const n = encode(std.math.maxInt(u64), &buf);
    try testing.expectEqual(@as(usize, 10), n);

    const result = try decode(buf[0..n]);
    try testing.expectEqual(std.math.maxInt(u64), result.value);
    try testing.expectEqual(@as(usize, 10), result.bytes_consumed);
}

test "roundtrip for various values" {
    const test_values = [_]u64{
        0,    1,    127,  128,   255,    256,
        1000, 4096, 8192, 16384, 65535,  65536,
        1 << 21, 1 << 28, 1 << 35, 1 << 42, 1 << 49,
        1 << 56, 1 << 63, std.math.maxInt(u64),
    };

    for (test_values) |value| {
        var buf: [max_length]u8 = undefined;
        const n = encode(value, &buf);

        try testing.expectEqual(encodingLength(value), n);

        const result = try decode(buf[0..n]);
        try testing.expectEqual(value, result.value);
        try testing.expectEqual(n, result.bytes_consumed);
    }
}

test "decode error on empty input" {
    try testing.expectError(DecodeError.EndOfInput, decode(&[_]u8{}));
}

test "decode error on truncated input" {
    // 0x80 has continuation bit set but no following byte.
    try testing.expectError(DecodeError.EndOfInput, decode(&[_]u8{0x80}));
    // Two continuation bytes, no terminator.
    try testing.expectError(DecodeError.EndOfInput, decode(&[_]u8{ 0x80, 0x80 }));
}

test "decode error on overflow" {
    // 11 bytes of continuation — exceeds the 10-byte limit.
    try testing.expectError(DecodeError.Overflow, decode(&[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 }));
}

test "decode ignores trailing bytes" {
    // Encode value 1, then append garbage.
    var buf = [_]u8{ 0x01, 0xFF, 0xFF, 0xFF };
    const result = try decode(&buf);
    try testing.expectEqual(@as(u64, 1), result.value);
    try testing.expectEqual(@as(usize, 1), result.bytes_consumed);
}

test "encodingLength correctness" {
    try testing.expectEqual(@as(usize, 1), encodingLength(0));
    try testing.expectEqual(@as(usize, 1), encodingLength(1));
    try testing.expectEqual(@as(usize, 1), encodingLength(127));
    try testing.expectEqual(@as(usize, 2), encodingLength(128));
    try testing.expectEqual(@as(usize, 2), encodingLength(16383));
    try testing.expectEqual(@as(usize, 3), encodingLength(16384));
    try testing.expectEqual(@as(usize, 10), encodingLength(std.math.maxInt(u64)));
}
