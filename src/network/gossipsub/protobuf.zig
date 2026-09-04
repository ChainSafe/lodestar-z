const std = @import("std");

const assert = std.debug.assert;

pub const Error = error{ Truncated, Overflow, BadWireType };

pub const wire_varint: u3 = 0;
pub const wire_len: u3 = 2;
pub const wire_i64: u3 = 1;
pub const wire_i32: u3 = 5;

pub const Tag = struct { field: u32, wire: u3 };

/// A bounds-checked reader over one protobuf message's bytes.
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

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
            const shift: u6 = @intCast(count * 7);
            result |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) return result;
        }
        return error.Overflow;
    }

    pub fn tag(self: *Reader) Error!Tag {
        const raw = try self.varint();
        return .{ .field = @intCast(raw >> 3), .wire = @intCast(raw & 0x7) };
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
    while (rest != 0) : (rest >>= 7) len += 1;
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
        while (true) {
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

fn keySize(field: u32) usize {
    return varintLen(@as(u64, field) << 3);
}

fn bytesFieldSize(field: u32, data_len: usize) usize {
    return keySize(field) + varintLen(data_len) + data_len;
}

fn varintFieldSize(field: u32, value: u64) usize {
    return keySize(field) + varintLen(value);
}

/// A `SubOpts { subscribe = 1, topicid = 2 }` view into the message bytes.
pub const SubOpts = struct {
    subscribe: bool = false,
    topic: []const u8 = &.{},

    pub fn decode(data: []const u8) Error!SubOpts {
        var out: SubOpts = .{};
        var reader = Reader.init(data);
        while (!reader.atEnd()) {
            const t = try reader.tag();
            switch (t.field) {
                1 => out.subscribe = (try reader.varint()) != 0,
                2 => out.topic = try reader.lenDelimited(),
                else => try reader.skip(t.wire),
            }
        }
        return out;
    }
};

/// A `Message { data = 2, topic = 4 }` view (StrictNoSign omits the rest).
pub const Message = struct {
    data: []const u8 = &.{},
    topic: []const u8 = &.{},
    signed: bool = false,

    pub fn decode(bytes_in: []const u8) Error!Message {
        var out: Message = .{};
        var reader = Reader.init(bytes_in);
        while (!reader.atEnd()) {
            const t = try reader.tag();
            switch (t.field) {
                2 => out.data = try reader.lenDelimited(),
                4 => out.topic = try reader.lenDelimited(),
                1, 3, 5, 6 => {
                    out.signed = true;
                    try reader.skip(t.wire);
                },
                else => try reader.skip(t.wire),
            }
        }
        return out;
    }
};

/// Iterates the repeated `bytes` message ids in an IHAVE/IWANT/IDONTWANT body.
pub const IdIterator = struct {
    reader: Reader,
    field: u32,

    pub fn next(self: *IdIterator) Error!?[]const u8 {
        while (!self.reader.atEnd()) {
            const t = try self.reader.tag();
            if (t.field == self.field and t.wire == wire_len) return try self.reader.lenDelimited();
            try self.reader.skip(t.wire);
        }
        return null;
    }
};

fn topicOf(data: []const u8, field: u32) Error![]const u8 {
    var reader = Reader.init(data);
    var topic: []const u8 = &.{};
    while (!reader.atEnd()) {
        const t = try reader.tag();
        if (t.field == field) topic = try reader.lenDelimited() else try reader.skip(t.wire);
    }
    return topic;
}

pub const IHave = struct {
    topic: []const u8,
    body: []const u8,

    pub fn ids(self: *const IHave) IdIterator {
        return .{ .reader = Reader.init(self.body), .field = 2 };
    }
};

pub const IdList = struct {
    body: []const u8,

    pub fn ids(self: *const IdList) IdIterator {
        return .{ .reader = Reader.init(self.body), .field = 1 };
    }
};

pub const Prune = struct {
    topic: []const u8 = &.{},
    backoff: u64 = 0,

    pub fn decode(data: []const u8) Error!Prune {
        var out: Prune = .{};
        var reader = Reader.init(data);
        while (!reader.atEnd()) {
            const t = try reader.tag();
            switch (t.field) {
                1 => out.topic = try reader.lenDelimited(),
                3 => out.backoff = try reader.varint(),
                else => try reader.skip(t.wire),
            }
        }
        return out;
    }
};

pub const Item = union(enum) {
    subscription: SubOpts,
    message: Message,
    ihave: IHave,
    iwant: IdList,
    graft: []const u8,
    prune: Prune,
    idontwant: IdList,
};

/// Streams the top-level RPC fields, descending transparently into the control
/// submessage, so the engine processes a flat sequence of items without
/// materializing the whole RPC.
pub const RpcReader = struct {
    top: Reader,
    control: ?Reader = null,

    pub fn init(data: []const u8) RpcReader {
        return .{ .top = Reader.init(data) };
    }

    pub fn next(self: *RpcReader) Error!?Item {
        while (true) {
            if (self.control) |*control| {
                if (control.atEnd()) {
                    self.control = null;
                    continue;
                }
                const t = try control.tag();
                const body = try control.lenDelimited();
                switch (t.field) {
                    1 => return .{ .ihave = .{ .topic = try topicOf(body, 1), .body = body } },
                    2 => return .{ .iwant = .{ .body = body } },
                    3 => return .{ .graft = try topicOf(body, 1) },
                    4 => return .{ .prune = try Prune.decode(body) },
                    5 => return .{ .idontwant = .{ .body = body } },
                    else => continue,
                }
            }
            if (self.top.atEnd()) return null;
            const t = try self.top.tag();
            const body = try self.top.lenDelimited();
            switch (t.field) {
                1 => return .{ .subscription = try SubOpts.decode(body) },
                2 => return .{ .message = try Message.decode(body) },
                3 => self.control = Reader.init(body),
                else => {},
            }
        }
    }
};

pub fn subscriptionSize(topic: []const u8) usize {
    const content = varintFieldSize(1, 1) + bytesFieldSize(2, topic.len);
    return bytesFieldSize(1, content);
}

pub fn writeSubscription(w: *Writer, subscribe: bool, topic: []const u8) void {
    const content = varintFieldSize(1, 1) + bytesFieldSize(2, topic.len);
    w.tag(1, wire_len);
    w.varint(content);
    w.varintField(1, @intFromBool(subscribe));
    w.bytesField(2, topic);
}

pub fn messageSize(data: []const u8, topic: []const u8) usize {
    const content = bytesFieldSize(2, data.len) + bytesFieldSize(4, topic.len);
    return bytesFieldSize(2, content);
}

pub fn writeMessage(w: *Writer, data: []const u8, topic: []const u8) void {
    const content = bytesFieldSize(2, data.len) + bytesFieldSize(4, topic.len);
    w.tag(2, wire_len);
    w.varint(content);
    w.bytesField(2, data);
    w.bytesField(4, topic);
}

/// Writes a whole RPC carrying one GRAFT control message for `topic`.
pub fn graftRpcSize(topic: []const u8) usize {
    const graft = bytesFieldSize(1, topic.len);
    return bytesFieldSize(3, bytesFieldSize(3, graft));
}

pub fn writeGraftRpc(w: *Writer, topic: []const u8) void {
    const graft = bytesFieldSize(1, topic.len);
    const control = bytesFieldSize(3, graft);
    w.tag(3, wire_len);
    w.varint(control);
    w.tag(3, wire_len);
    w.varint(graft);
    w.bytesField(1, topic);
}

/// Writes a whole RPC carrying one PRUNE control message with a backoff in
/// seconds (Ethereum sends no peer-exchange records).
pub fn pruneRpcSize(topic: []const u8, backoff_s: u64) usize {
    const prune = bytesFieldSize(1, topic.len) + varintFieldSize(3, backoff_s);
    return bytesFieldSize(3, bytesFieldSize(4, prune));
}

pub fn writePruneRpc(w: *Writer, topic: []const u8, backoff_s: u64) void {
    const prune = bytesFieldSize(1, topic.len) + varintFieldSize(3, backoff_s);
    const control = bytesFieldSize(4, prune);
    w.tag(3, wire_len);
    w.varint(control);
    w.tag(4, wire_len);
    w.varint(prune);
    w.bytesField(1, topic);
    w.varintField(3, backoff_s);
}

test "protobuf round trips graft and prune control rpcs" {
    var buf: [128]u8 = undefined;
    var w = Writer.init(&buf);
    writeGraftRpc(&w, "topic_a");
    try std.testing.expectEqual(graftRpcSize("topic_a"), w.len);
    var reader = RpcReader.init(w.written());
    const graft = (try reader.next()).?;
    try std.testing.expectEqualStrings("topic_a", graft.graft);
    try std.testing.expect((try reader.next()) == null);

    w = Writer.init(&buf);
    writePruneRpc(&w, "topic_b", 60);
    try std.testing.expectEqual(pruneRpcSize("topic_b", 60), w.len);
    reader = RpcReader.init(w.written());
    const prune = (try reader.next()).?;
    try std.testing.expectEqualStrings("topic_b", prune.prune.topic);
    try std.testing.expectEqual(@as(u64, 60), prune.prune.backoff);
}

test "protobuf round trips an RPC with subscriptions, messages, and control" {
    var buf: [512]u8 = undefined;
    var w = Writer.init(&buf);
    writeSubscription(&w, true, "topic_a");
    writeMessage(&w, "payload", "topic_a");
    // control: graft topic_a, then idontwant [id1,id2]
    const graft_content = bytesFieldSize(1, "topic_a".len);
    const idontwant_content = bytesFieldSize(1, 3) + bytesFieldSize(1, 3);
    const control_content = bytesFieldSize(3, graft_content) + bytesFieldSize(5, idontwant_content);
    w.tag(3, wire_len);
    w.varint(control_content);
    w.tag(3, wire_len);
    w.varint(graft_content);
    w.bytesField(1, "topic_a");
    w.tag(5, wire_len);
    w.varint(idontwant_content);
    w.bytesField(1, "aaa");
    w.bytesField(1, "bbb");

    var reader = RpcReader.init(w.written());
    const sub = (try reader.next()).?;
    try std.testing.expect(sub.subscription.subscribe);
    try std.testing.expectEqualStrings("topic_a", sub.subscription.topic);
    const msg = (try reader.next()).?;
    try std.testing.expectEqualStrings("payload", msg.message.data);
    try std.testing.expectEqualStrings("topic_a", msg.message.topic);
    try std.testing.expect(!msg.message.signed);
    const graft = (try reader.next()).?;
    try std.testing.expectEqualStrings("topic_a", graft.graft);
    const idontwant = (try reader.next()).?;
    var ids = idontwant.idontwant.ids();
    try std.testing.expectEqualStrings("aaa", (try ids.next()).?);
    try std.testing.expectEqualStrings("bbb", (try ids.next()).?);
    try std.testing.expect((try ids.next()) == null);
    try std.testing.expect((try reader.next()) == null);
}

test "protobuf decodes ihave and iwant ids" {
    var buf: [256]u8 = undefined;
    var w = Writer.init(&buf);
    const ihave_content = bytesFieldSize(1, "t".len) + bytesFieldSize(2, 4) + bytesFieldSize(2, 4);
    const iwant_content = bytesFieldSize(1, 4);
    const control_content = bytesFieldSize(1, ihave_content) + bytesFieldSize(2, iwant_content);
    w.tag(3, wire_len);
    w.varint(control_content);
    w.tag(1, wire_len);
    w.varint(ihave_content);
    w.bytesField(1, "t");
    w.bytesField(2, "id01");
    w.bytesField(2, "id02");
    w.tag(2, wire_len);
    w.varint(iwant_content);
    w.bytesField(1, "id03");

    var reader = RpcReader.init(w.written());
    const ihave = (try reader.next()).?;
    try std.testing.expectEqualStrings("t", ihave.ihave.topic);
    var hids = ihave.ihave.ids();
    try std.testing.expectEqualStrings("id01", (try hids.next()).?);
    try std.testing.expectEqualStrings("id02", (try hids.next()).?);
    try std.testing.expect((try hids.next()) == null);
    const iwant = (try reader.next()).?;
    var wids = iwant.iwant.ids();
    try std.testing.expectEqualStrings("id03", (try wids.next()).?);
}

test "protobuf rejects truncated and malformed input" {
    try std.testing.expectError(error.Truncated, blk: {
        var r = Reader.init(&[_]u8{0x80});
        break :blk r.varint();
    });
    try std.testing.expectError(error.Overflow, blk: {
        var r = Reader.init(&([_]u8{0x80} ** 11));
        break :blk r.varint();
    });
    try std.testing.expectError(error.Truncated, blk: {
        var r = Reader.init(&[_]u8{ 0x0a, 0x05, 0x01 }); // len 5, only 1 byte
        break :blk r.lenDelimited();
    });
}

test "protobuf varintLen matches the encoded width" {
    var buf: [16]u8 = undefined;
    for ([_]u64{ 0, 1, 127, 128, 300, 16_384, std.math.maxInt(u64) }) |value| {
        var w = Writer.init(&buf);
        w.varint(value);
        try std.testing.expectEqual(w.len, varintLen(value));
        var r = Reader.init(w.written());
        try std.testing.expectEqual(value, try r.varint());
    }
}
