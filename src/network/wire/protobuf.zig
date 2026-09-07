const std = @import("std");

const assert = std.debug.assert;

pub const Error = error{ Truncated, Overflow, BadWireType, FieldLimit };

pub const wire_varint: u3 = 0;
pub const wire_len: u3 = 2;
pub const wire_i64: u3 = 1;
pub const wire_i32: u3 = 5;

pub const Tag = struct { field: u64, wire: u3 };

/// A bounds-checked reader over one protobuf message's bytes.
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,
    fields: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn atEnd(self: *const Reader) bool {
        assert(self.pos <= self.data.len);
        return self.pos >= self.data.len;
    }

    pub fn varint(self: *Reader) Error!u64 {
        var result: u64 = 0;
        var count: usize = 0;
        while (count < 10) : (count += 1) {
            if (self.pos >= self.data.len) return error.Truncated;
            const byte = self.data[self.pos];
            self.pos += 1;
            if (count == 9 and byte > 1) return error.Overflow;
            const shift: u6 = @intCast(count * 7);
            result |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) return result;
        }
        return error.Overflow;
    }

    pub fn tag(self: *Reader) Error!Tag {
        if (self.fields == 8192) return error.FieldLimit;
        self.fields += 1;
        const raw = try self.varint();
        return .{ .field = raw >> 3, .wire = @intCast(raw & 0x7) };
    }

    pub fn lenDelimited(self: *Reader) Error![]const u8 {
        const len = try self.varint();
        if (len > self.data.len - self.pos) return error.Truncated;
        const start = self.pos;
        self.pos += @intCast(len);
        return self.data[start..self.pos];
    }

    pub fn skip(self: *Reader, wire: u3) Error!void {
        switch (wire) {
            wire_varint => _ = try self.varint(),
            wire_len => _ = try self.lenDelimited(),
            wire_i64 => self.pos = try self.advance(8),
            wire_i32 => self.pos = try self.advance(4),
            else => return error.BadWireType,
        }
    }

    fn advance(self: *Reader, n: usize) Error!usize {
        if (n > self.data.len - self.pos) return error.Truncated;
        return self.pos + n;
    }
};

pub fn varintLen(value: u64) usize {
    var len: usize = 1;
    var rest = value >> 7;
    for (0..9) |_| {
        if (rest == 0) break;
        len += 1;
        rest >>= 7;
    }
    return len;
}

/// An append-only writer over a caller-provided buffer; never allocates and
/// asserts the buffer is large enough (callers size it from the `*Size` helpers).
pub const Writer = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn varint(self: *Writer, value: u64) void {
        var rest = value;
        for (0..10) |_| {
            assert(self.len < self.buf.len);
            const byte: u8 = @intCast(rest & 0x7f);
            rest >>= 7;
            if (rest != 0) {
                self.buf[self.len] = byte | 0x80;
                self.len += 1;
            } else {
                self.buf[self.len] = byte;
                self.len += 1;
                return;
            }
        }
    }

    pub fn tag(self: *Writer, field: u32, wire: u3) void {
        self.varint((@as(u64, field) << 3) | wire);
    }

    pub fn bytes(self: *Writer, data: []const u8) void {
        assert(self.len + data.len <= self.buf.len);
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
    }

    pub fn varintField(self: *Writer, field: u32, value: u64) void {
        self.tag(field, wire_varint);
        self.varint(value);
    }

    pub fn bytesField(self: *Writer, field: u32, data: []const u8) void {
        self.tag(field, wire_len);
        self.varint(data.len);
        self.bytes(data);
    }
};

pub fn keySize(field: u32) usize {
    return varintLen(@as(u64, field) << 3);
}

pub fn bytesFieldSize(field: u32, data_len: usize) usize {
    return keySize(field) + varintLen(data_len) + data_len;
}

pub fn varintFieldSize(field: u32, value: u64) usize {
    return keySize(field) + varintLen(value);
}
