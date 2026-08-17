//! RLP encoder/decoder for discv5 messages

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    Overflow,
    InvalidEncoding,
    BufferTooSmall,
    OutOfMemory,
    UnexpectedType,
    TrailingData,
};

pub const BoundedError = error{BufferTooSmall};

// =========== Writer ===========

pub const Writer = struct {
    buf: std.ArrayListUnmanaged(u8),

    pub fn init() Writer {
        return .{ .buf = .empty };
    }

    pub fn initBuffer(buffer: []u8) Writer {
        return .{ .buf = std.ArrayListUnmanaged(u8).initBuffer(buffer) };
    }

    pub fn deinit(self: *Writer, alloc: Allocator) void {
        self.buf.deinit(alloc);
    }

    pub fn toOwnedSlice(self: *Writer, alloc: Allocator) ![]u8 {
        return self.buf.toOwnedSlice(alloc);
    }

    pub fn bytes(self: *const Writer) []const u8 {
        return self.buf.items;
    }

    pub fn writeBytes(self: *Writer, alloc: Allocator, data: []const u8) !void {
        try self.buf.ensureUnusedCapacity(alloc, try encodedStringLen(data));
        self.writeBytesBounded(data) catch unreachable;
    }

    pub fn writeBytesBounded(self: *Writer, data: []const u8) BoundedError!void {
        if (data.len == 1 and data[0] < 0x80) {
            try self.appendBounded(data[0]);
        } else {
            var prefix: [9]u8 = undefined;
            const prefix_len = encodeLenPrefix(&prefix, 0x80, 0xb7, data.len);
            try self.appendSliceBounded(prefix[0..prefix_len]);
            try self.appendSliceBounded(data);
        }
    }

    /// Append a pre-encoded RLP item directly.
    pub fn writeRawItem(self: *Writer, alloc: Allocator, data: []const u8) !void {
        try self.buf.ensureUnusedCapacity(alloc, data.len);
        self.writeRawItemBounded(data) catch unreachable;
    }

    /// Append a pre-encoded RLP item directly.
    pub fn writeRawItemBounded(self: *Writer, data: []const u8) BoundedError!void {
        try self.appendSliceBounded(data);
    }

    pub fn writeUint64(self: *Writer, alloc: Allocator, v: u64) !void {
        var tmp: [8]u8 = undefined;
        try self.writeBytes(alloc, uint64Bytes(&tmp, v));
    }

    pub fn writeUint64Bounded(self: *Writer, v: u64) BoundedError!void {
        var tmp: [8]u8 = undefined;
        try self.writeBytesBounded(uint64Bytes(&tmp, v));
    }

    pub fn beginList(self: *Writer, alloc: Allocator) !usize {
        try self.buf.ensureUnusedCapacity(alloc, 4);
        return self.beginListBounded() catch unreachable;
    }

    pub fn beginListBounded(self: *Writer) BoundedError!usize {
        const pos = self.buf.items.len;
        try self.appendNTimesBounded(0, 4);
        return pos;
    }

    pub fn finishList(self: *Writer, start_pos: usize) BoundedError!void {
        const content_start = start_pos + 4;
        const content_len = self.buf.items.len - content_start;
        var prefix: [9]u8 = undefined;
        const prefix_len = encodeLenPrefix(&prefix, 0xc0, 0xf7, content_len);
        const old_total = self.buf.items.len;
        if (prefix_len > 4) return BoundedError.BufferTooSmall;
        const shift = 4 - prefix_len;
        if (shift > 0) {
            @memmove(self.buf.items[start_pos + prefix_len .. old_total - shift], self.buf.items[content_start..old_total]);
            self.buf.shrinkRetainingCapacity(old_total - shift);
        }
        @memcpy(self.buf.items[start_pos .. start_pos + prefix_len], prefix[0..prefix_len]);
    }

    fn appendBounded(self: *Writer, byte: u8) BoundedError!void {
        self.buf.appendBounded(byte) catch return BoundedError.BufferTooSmall;
    }

    fn appendSliceBounded(self: *Writer, data: []const u8) BoundedError!void {
        self.buf.appendSliceBounded(data) catch return BoundedError.BufferTooSmall;
    }

    fn appendNTimesBounded(self: *Writer, byte: u8, count: usize) BoundedError!void {
        self.buf.appendNTimesBounded(byte, count) catch return BoundedError.BufferTooSmall;
    }
};

fn encodedStringLen(data: []const u8) Error!usize {
    if (data.len == 1 and data[0] < 0x80) return 1;
    return std.math.add(usize, lenPrefixLen(data.len), data.len) catch Error.Overflow;
}

fn lenPrefixLen(len: usize) usize {
    return if (len <= 55) 1 else 1 + minBytesForUint(len);
}

fn uint64Bytes(out: *[8]u8, value: u64) []const u8 {
    if (value == 0) return out[0..0];
    std.mem.writeInt(u64, out, value, .big);
    var start: usize = 0;
    while (start < 7 and out[start] == 0) start += 1;
    return out[start..];
}

fn minBytesForUint(v: usize) usize {
    if (v == 0) return 1;
    var n: usize = 0;
    var vv = v;
    while (vv > 0) : (vv >>= 8) n += 1;
    return n;
}

fn encodeLenPrefix(out: *[9]u8, short_base: u8, long_base: u8, len: usize) usize {
    if (len <= 55) {
        out[0] = short_base + @as(u8, @intCast(len));
        return 1;
    }

    const len_bytes = minBytesForUint(len);
    out[0] = long_base + @as(u8, @intCast(len_bytes));
    var i: usize = 0;
    var tmp = len;
    while (i < len_bytes) : (i += 1) {
        out[1 + len_bytes - 1 - i] = @as(u8, @intCast(tmp & 0xff));
        tmp >>= 8;
    }
    return 1 + len_bytes;
}

// =========== Reader ===========

pub const Reader = struct {
    data: []const u8,
    pos: usize,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data, .pos = 0 };
    }

    pub fn remaining(self: *const Reader) usize {
        return self.data.len - self.pos;
    }

    pub fn atEnd(self: *const Reader) bool {
        return self.pos >= self.data.len;
    }

    pub fn peekIsList(self: *const Reader) bool {
        if (self.pos >= self.data.len) return false;
        return self.data[self.pos] >= 0xc0;
    }

    /// Read the next complete RLP item (string or list) as raw bytes.
    pub fn readRawItem(self: *Reader) Error![]const u8 {
        if (self.pos >= self.data.len) return Error.InvalidEncoding;
        const start = self.pos;
        const b = self.data[self.pos];
        if (b < 0x80) {
            self.pos += 1;
        } else if (b < 0xb8) {
            const len: usize = b - 0x80;
            if (self.pos + 1 + len > self.data.len) return Error.InvalidEncoding;
            if (len == 1 and self.data[self.pos + 1] < 0x80) return Error.InvalidEncoding;
            self.pos += 1 + len;
        } else if (b < 0xc0) {
            const len_bytes: usize = b - 0xb7;
            const payload = try readLongPayload(self.data, self.pos + 1, len_bytes);
            self.pos = payload.end;
        } else if (b < 0xf8) {
            const len: usize = b - 0xc0;
            if (self.pos + 1 + len > self.data.len) return Error.InvalidEncoding;
            self.pos += 1 + len;
        } else {
            const len_bytes: usize = b - 0xf7;
            const payload = try readLongPayload(self.data, self.pos + 1, len_bytes);
            self.pos = payload.end;
        }
        return self.data[start..self.pos];
    }

    pub fn readBytes(self: *Reader) Error![]const u8 {
        if (self.pos >= self.data.len) return Error.InvalidEncoding;
        const b = self.data[self.pos];
        if (b < 0x80) {
            self.pos += 1;
            return self.data[self.pos - 1 .. self.pos];
        } else if (b < 0xb8) {
            const len = b - 0x80;
            const start = self.pos + 1;
            if (len > self.data.len - start) return Error.InvalidEncoding;
            if (len == 1 and self.data[start] < 0x80) return Error.InvalidEncoding;
            self.pos = start + len;
            return self.data[start .. start + len];
        } else if (b < 0xc0) {
            const len_bytes = b - 0xb7;
            const payload = try readLongPayload(self.data, self.pos + 1, len_bytes);
            self.pos = payload.end;
            return self.data[payload.start..payload.end];
        } else {
            return Error.UnexpectedType;
        }
    }

    pub fn readUint64(self: *Reader) Error!u64 {
        const b_slice = try self.readBytes();
        if (b_slice.len == 0) return 0;
        if (b_slice.len > 8) return Error.Overflow;
        if (b_slice[0] == 0) return Error.InvalidEncoding;
        var v: u64 = 0;
        for (b_slice) |b| {
            v = (v << 8) | b;
        }
        return v;
    }

    pub fn readList(self: *Reader) Error!Reader {
        if (self.pos >= self.data.len) return Error.InvalidEncoding;
        const b = self.data[self.pos];
        if (b < 0xc0) return Error.UnexpectedType;
        if (b < 0xf8) {
            const len = b - 0xc0;
            const start = self.pos + 1;
            if (len > self.data.len - start) return Error.InvalidEncoding;
            self.pos = start + len;
            return Reader.init(self.data[start .. start + len]);
        } else {
            const len_bytes = b - 0xf7;
            const payload = try readLongPayload(self.data, self.pos + 1, len_bytes);
            self.pos = payload.end;
            return Reader.init(self.data[payload.start..payload.end]);
        }
    }

    pub fn skipItem(self: *Reader) Error!void {
        if (self.pos >= self.data.len) return Error.InvalidEncoding;
        const b = self.data[self.pos];
        if (b < 0x80) {
            self.pos += 1;
        } else if (b < 0xb8) {
            const len = b - 0x80;
            if (self.pos + 1 + len > self.data.len) return Error.InvalidEncoding;
            if (len == 1 and self.data[self.pos + 1] < 0x80) return Error.InvalidEncoding;
            self.pos += 1 + len;
        } else if (b < 0xc0) {
            const len_bytes = b - 0xb7;
            const payload = try readLongPayload(self.data, self.pos + 1, len_bytes);
            self.pos = payload.end;
        } else if (b < 0xf8) {
            const len = b - 0xc0;
            if (self.pos + 1 + len > self.data.len) return Error.InvalidEncoding;
            self.pos += 1 + len;
        } else {
            const len_bytes = b - 0xf7;
            const payload = try readLongPayload(self.data, self.pos + 1, len_bytes);
            self.pos = payload.end;
        }
    }
};

const PayloadRange = struct {
    start: usize,
    end: usize,
};

fn readLongPayload(data: []const u8, length_start: usize, length_size: usize) Error!PayloadRange {
    if (length_start > data.len) return Error.InvalidEncoding;
    if (length_size == 0) return Error.InvalidEncoding;
    if (length_size > @sizeOf(usize)) return Error.InvalidEncoding;
    if (length_size > data.len - length_start) return Error.InvalidEncoding;

    const encoded_length = data[length_start..][0..length_size];
    if (encoded_length[0] == 0) return Error.InvalidEncoding;
    const payload_size = readBigEndianUsize(encoded_length);
    if (payload_size < 56) return Error.InvalidEncoding;

    const payload_start = length_start + length_size;
    if (payload_size > data.len - payload_start) return Error.InvalidEncoding;
    return .{ .start = payload_start, .end = payload_start + payload_size };
}

fn readBigEndianUsize(bytes: []const u8) usize {
    var v: usize = 0;
    for (bytes) |b| {
        v = (v << 8) | b;
    }
    return v;
}

// =========== Tests ===========

test "RLP encode/decode bytes" {
    var buf: [32]u8 = undefined;
    var w = Writer.initBuffer(&buf);

    try w.writeBytesBounded(&[_]u8{ 0x01, 0x02, 0x03 });
    const encoded = w.bytes();
    try std.testing.expectEqual(@as(u8, 0x83), encoded[0]);

    var r = Reader.init(encoded);
    const decoded = try r.readBytes();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, decoded);
}

test "RLP encode/decode single byte < 0x80" {
    var buf: [32]u8 = undefined;
    var w = Writer.initBuffer(&buf);

    try w.writeBytesBounded(&[_]u8{0x42});
    const encoded = w.bytes();
    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x42), encoded[0]);

    var r = Reader.init(encoded);
    const decoded = try r.readBytes();
    try std.testing.expectEqualSlices(u8, &[_]u8{0x42}, decoded);
}

test "RLP encode/decode uint64" {
    var buf: [32]u8 = undefined;
    var w = Writer.initBuffer(&buf);

    try w.writeUint64Bounded(2);
    const encoded = w.bytes();

    var r = Reader.init(encoded);
    const v = try r.readUint64();
    try std.testing.expectEqual(@as(u64, 2), v);
}

test "RLP encode/decode list" {
    var buf: [32]u8 = undefined;
    var w = Writer.initBuffer(&buf);

    const list_start = try w.beginListBounded();
    try w.writeBytesBounded(&[_]u8{ 0x01, 0x02 });
    try w.writeUint64Bounded(42);
    try w.finishList(list_start);

    const encoded = w.bytes();

    var r = Reader.init(encoded);
    var list = try r.readList();
    const a = try list.readBytes();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02 }, a);
    const b = try list.readUint64();
    try std.testing.expectEqual(@as(u64, 42), b);
}

test "RLP reader rejects non-canonical encodings" {
    const encoded_single = [_]u8{ 0x81, 0x01 };
    var single = Reader.init(&encoded_single);
    try std.testing.expectError(Error.InvalidEncoding, single.readBytes());

    const long_short_string = [_]u8{ 0xb8, 0x01, 0x80 };
    var string = Reader.init(&long_short_string);
    try std.testing.expectError(Error.InvalidEncoding, string.readRawItem());

    const long_short_list = [_]u8{ 0xf8, 0x01, 0xc0 };
    var list = Reader.init(&long_short_list);
    try std.testing.expectError(Error.InvalidEncoding, list.readList());

    const leading_zero_integer = [_]u8{0x00};
    var integer = Reader.init(&leading_zero_integer);
    try std.testing.expectError(Error.InvalidEncoding, integer.readUint64());

    var skipped = Reader.init(&encoded_single);
    try std.testing.expectError(Error.InvalidEncoding, skipped.skipItem());

    const oversized_string = [_]u8{0xbf} ++ ([_]u8{0xff} ** 8);
    var oversized = Reader.init(&oversized_string);
    try std.testing.expectError(Error.InvalidEncoding, oversized.readRawItem());
}
