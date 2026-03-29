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

// =========== Writer ===========

pub const Writer = struct {
    buf: std.ArrayListUnmanaged(u8),
    alloc: Allocator,

    pub fn init(alloc: Allocator) Writer {
        return .{ .buf = .empty, .alloc = alloc };
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(self.alloc);
    }

    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        return self.buf.toOwnedSlice(self.alloc);
    }

    pub fn bytes(self: *const Writer) []const u8 {
        return self.buf.items;
    }

    pub fn writeBytes(self: *Writer, data: []const u8) !void {
        if (data.len == 1 and data[0] < 0x80) {
            try self.buf.append(self.alloc, data[0]);
        } else if (data.len <= 55) {
            try self.buf.append(self.alloc, @as(u8, 0x80) + @as(u8, @intCast(data.len)));
            try self.buf.appendSlice(self.alloc, data);
        } else {
            const len_bytes = minBytesForUint(data.len);
            try self.buf.append(self.alloc, @as(u8, 0xb7) + @as(u8, @intCast(len_bytes)));
            try self.writeUintBytes(data.len, len_bytes);
            try self.buf.appendSlice(self.alloc, data);
        }
    }

    pub fn writeUint64(self: *Writer, v: u64) !void {
        if (v == 0) {
            try self.buf.append(self.alloc, 0x80);
        } else {
            var tmp: [8]u8 = undefined;
            std.mem.writeInt(u64, &tmp, v, .big);
            var start: usize = 0;
            while (start < 7 and tmp[start] == 0) start += 1;
            try self.writeBytes(tmp[start..]);
        }
    }

    pub fn beginList(self: *Writer) !usize {
        const pos = self.buf.items.len;
        try self.buf.appendNTimes(self.alloc, 0, 4);
        return pos;
    }

    pub fn finishList(self: *Writer, start_pos: usize) !void {
        const content_start = start_pos + 4;
        const content_len = self.buf.items.len - content_start;
        var prefix: [5]u8 = undefined;
        var prefix_len: usize = 0;
        if (content_len <= 55) {
            prefix[0] = @as(u8, 0xc0) + @as(u8, @intCast(content_len));
            prefix_len = 1;
        } else {
            const len_bytes = minBytesForUint(content_len);
            prefix[0] = @as(u8, 0xf7) + @as(u8, @intCast(len_bytes));
            var i: usize = 0;
            var tmp = content_len;
            while (i < len_bytes) : (i += 1) {
                prefix[1 + len_bytes - 1 - i] = @as(u8, @intCast(tmp & 0xff));
                tmp >>= 8;
            }
            prefix_len = 1 + len_bytes;
        }
        const old_total = self.buf.items.len;
        if (prefix_len <= 4) {
            const shift = 4 - prefix_len;
            if (shift > 0) {
                std.mem.copyForwards(u8, self.buf.items[start_pos + prefix_len ..], self.buf.items[content_start..old_total]);
                self.buf.shrinkRetainingCapacity(old_total - shift);
            }
            @memcpy(self.buf.items[start_pos .. start_pos + prefix_len], prefix[0..prefix_len]);
        } else {
            unreachable;
        }
    }

    fn writeUintBytes(self: *Writer, v: usize, nb: usize) !void {
        var tmp: [8]u8 = undefined;
        var i: usize = 0;
        var vv = v;
        while (i < nb) : (i += 1) {
            tmp[nb - 1 - i] = @as(u8, @intCast(vv & 0xff));
            vv >>= 8;
        }
        try self.buf.appendSlice(self.alloc, tmp[0..nb]);
    }
};

fn minBytesForUint(v: usize) usize {
    if (v == 0) return 1;
    var n: usize = 0;
    var vv = v;
    while (vv > 0) : (vv >>= 8) n += 1;
    return n;
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

    pub fn readBytes(self: *Reader) Error![]const u8 {
        if (self.pos >= self.data.len) return Error.InvalidEncoding;
        const b = self.data[self.pos];
        if (b < 0x80) {
            self.pos += 1;
            return self.data[self.pos - 1 .. self.pos];
        } else if (b < 0xb8) {
            const len = b - 0x80;
            self.pos += 1;
            if (self.pos + len > self.data.len) return Error.InvalidEncoding;
            const start = self.pos;
            self.pos += len;
            return self.data[start .. start + len];
        } else if (b < 0xc0) {
            const len_bytes = b - 0xb7;
            self.pos += 1;
            if (self.pos + len_bytes > self.data.len) return Error.InvalidEncoding;
            const len = readBigEndianUsize(self.data[self.pos .. self.pos + len_bytes]);
            self.pos += len_bytes;
            if (self.pos + len > self.data.len) return Error.InvalidEncoding;
            const start = self.pos;
            self.pos += len;
            return self.data[start .. start + len];
        } else {
            return Error.UnexpectedType;
        }
    }

    pub fn readUint64(self: *Reader) Error!u64 {
        const b_slice = try self.readBytes();
        if (b_slice.len == 0) return 0;
        if (b_slice.len > 8) return Error.Overflow;
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
            self.pos += 1;
            if (self.pos + len > self.data.len) return Error.InvalidEncoding;
            const start = self.pos;
            self.pos += len;
            return Reader.init(self.data[start .. start + len]);
        } else {
            const len_bytes = b - 0xf7;
            self.pos += 1;
            if (self.pos + len_bytes > self.data.len) return Error.InvalidEncoding;
            const len = readBigEndianUsize(self.data[self.pos .. self.pos + len_bytes]);
            self.pos += len_bytes;
            if (self.pos + len > self.data.len) return Error.InvalidEncoding;
            const start = self.pos;
            self.pos += len;
            return Reader.init(self.data[start .. start + len]);
        }
    }

    pub fn skipItem(self: *Reader) Error!void {
        if (self.pos >= self.data.len) return Error.InvalidEncoding;
        const b = self.data[self.pos];
        if (b < 0x80) {
            self.pos += 1;
        } else if (b < 0xb8) {
            const len = b - 0x80;
            self.pos += 1 + len;
            if (self.pos > self.data.len) return Error.InvalidEncoding;
        } else if (b < 0xc0) {
            const len_bytes = b - 0xb7;
            self.pos += 1;
            if (self.pos + len_bytes > self.data.len) return Error.InvalidEncoding;
            const len = readBigEndianUsize(self.data[self.pos .. self.pos + len_bytes]);
            self.pos += len_bytes + len;
            if (self.pos > self.data.len) return Error.InvalidEncoding;
        } else if (b < 0xf8) {
            const len = b - 0xc0;
            self.pos += 1 + len;
            if (self.pos > self.data.len) return Error.InvalidEncoding;
        } else {
            const len_bytes = b - 0xf7;
            self.pos += 1;
            if (self.pos + len_bytes > self.data.len) return Error.InvalidEncoding;
            const len = readBigEndianUsize(self.data[self.pos .. self.pos + len_bytes]);
            self.pos += len_bytes + len;
            if (self.pos > self.data.len) return Error.InvalidEncoding;
        }
    }
};

fn readBigEndianUsize(bytes: []const u8) usize {
    var v: usize = 0;
    for (bytes) |b| {
        v = (v << 8) | b;
    }
    return v;
}

// =========== Tests ===========

test "RLP encode/decode bytes" {
    const alloc = std.testing.allocator;
    var w = Writer.init(alloc);
    defer w.deinit();

    try w.writeBytes(&[_]u8{ 0x01, 0x02, 0x03 });
    const encoded = w.bytes();
    try std.testing.expectEqual(@as(u8, 0x83), encoded[0]);

    var r = Reader.init(encoded);
    const decoded = try r.readBytes();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, decoded);
}

test "RLP encode/decode single byte < 0x80" {
    const alloc = std.testing.allocator;
    var w = Writer.init(alloc);
    defer w.deinit();

    try w.writeBytes(&[_]u8{0x42});
    const encoded = w.bytes();
    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x42), encoded[0]);

    var r = Reader.init(encoded);
    const decoded = try r.readBytes();
    try std.testing.expectEqualSlices(u8, &[_]u8{0x42}, decoded);
}

test "RLP encode/decode uint64" {
    const alloc = std.testing.allocator;
    var w = Writer.init(alloc);
    defer w.deinit();

    try w.writeUint64(2);
    const encoded = w.bytes();

    var r = Reader.init(encoded);
    const v = try r.readUint64();
    try std.testing.expectEqual(@as(u64, 2), v);
}

test "RLP encode/decode list" {
    const alloc = std.testing.allocator;
    var w = Writer.init(alloc);
    defer w.deinit();

    const list_start = try w.beginList();
    try w.writeBytes(&[_]u8{ 0x01, 0x02 });
    try w.writeUint64(42);
    try w.finishList(list_start);

    const encoded = w.bytes();

    var r = Reader.init(encoded);
    var list = try r.readList();
    const a = try list.readBytes();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02 }, a);
    const b = try list.readUint64();
    try std.testing.expectEqual(@as(u64, 42), b);
}
