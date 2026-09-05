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
                1 => if (t.wire == wire_varint) {
                    out.subscribe = (try reader.varint()) != 0;
                } else try reader.skip(t.wire),
                2 => if (t.wire == wire_len) {
                    out.topic = try reader.lenDelimited();
                } else try reader.skip(t.wire),
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
                2 => if (t.wire == wire_len) {
                    out.data = try reader.lenDelimited();
                } else try reader.skip(t.wire),
                4 => if (t.wire == wire_len) {
                    out.topic = try reader.lenDelimited();
                } else try reader.skip(t.wire),
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
        if (t.field == field and t.wire == wire_len)
            topic = try reader.lenDelimited()
        else
            try reader.skip(t.wire);
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
                1 => if (t.wire == wire_len) {
                    out.topic = try reader.lenDelimited();
                } else try reader.skip(t.wire),
                3 => if (t.wire == wire_varint) {
                    out.backoff = try reader.varint();
                } else try reader.skip(t.wire),
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

    pub const Step = union(enum) { item: Item, skipped, end, deferred };

    pub fn step(self: *RpcReader, fields: *usize) Error!Step {
        if (fields.* == 0) return .deferred;
        const nested = self.control != null;
        var reader = if (self.control) |control| control else self.top;
        if (reader.atEnd()) {
            if (nested) {
                self.control = null;
                return .skipped;
            }
            return .end;
        }
        // Top/control cursors resume after every field; nested schema readers enforce their own cap.
        reader.fields = 0;
        const t = try reader.tag();
        const body = if (t.wire == wire_len) try reader.lenDelimited() else blk: {
            try reader.skip(t.wire);
            break :blk null;
        };
        const known = if (nested) t.field >= 1 and t.field <= 5 else t.field == 1 or t.field == 2;
        const cost = 1 + if (known and body != null) @as(usize, @min(body.?.len, 8192)) * 2 else @as(usize, 0);
        if (cost > fields.*) return .deferred;
        fields.* -= cost;
        if (nested) self.control = reader else self.top = reader;
        const bytes = body orelse return .skipped;
        if (nested) return switch (t.field) {
            1 => .{ .item = .{ .ihave = .{ .topic = try topicOf(bytes, 1), .body = bytes } } },
            2 => .{ .item = .{ .iwant = .{ .body = bytes } } },
            3 => .{ .item = .{ .graft = try topicOf(bytes, 1) } },
            4 => .{ .item = .{ .prune = try Prune.decode(bytes) } },
            5 => .{ .item = .{ .idontwant = .{ .body = bytes } } },
            else => .skipped,
        };
        return switch (t.field) {
            1 => .{ .item = .{ .subscription = try SubOpts.decode(bytes) } },
            2 => .{ .item = .{ .message = try Message.decode(bytes) } },
            3 => blk: {
                self.control = Reader.init(bytes);
                break :blk .skipped;
            },
            else => .skipped,
        };
    }

    pub fn next(self: *RpcReader) Error!?Item {
        var budget: usize = std.math.maxInt(usize);
        for (0..self.top.data.len + 2) |_| {
            switch (try self.step(&budget)) {
                .item => |item| return item,
                .end => return null,
                .skipped => {},
                .deferred => unreachable,
            }
        }
        return error.FieldLimit;
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

/// Size of a whole RPC carrying one IHAVE for `topic` and `id_count` ids.
pub fn ihaveRpcSize(topic: []const u8, id_count: usize, id_len: usize) usize {
    const ihave = bytesFieldSize(1, topic.len) + id_count * bytesFieldSize(2, id_len);
    return bytesFieldSize(3, bytesFieldSize(1, ihave));
}

/// Begins an IHAVE RPC; the caller appends each id with `writeIhaveId` in order.
pub fn beginIhaveRpc(w: *Writer, topic: []const u8, id_count: usize, id_len: usize) void {
    const ihave = bytesFieldSize(1, topic.len) + id_count * bytesFieldSize(2, id_len);
    w.tag(3, wire_len);
    w.varint(bytesFieldSize(1, ihave));
    w.tag(1, wire_len);
    w.varint(ihave);
    w.bytesField(1, topic);
}

pub fn writeIhaveId(w: *Writer, id: []const u8) void {
    w.bytesField(2, id);
}

/// Size of a whole RPC carrying one IWANT for `id_count` ids.
pub fn iwantRpcSize(id_count: usize, id_len: usize) usize {
    const iwant = id_count * bytesFieldSize(1, id_len);
    return bytesFieldSize(3, bytesFieldSize(2, iwant));
}

pub fn beginIwantRpc(w: *Writer, id_count: usize, id_len: usize) void {
    const iwant = id_count * bytesFieldSize(1, id_len);
    w.tag(3, wire_len);
    w.varint(bytesFieldSize(2, iwant));
    w.tag(2, wire_len);
    w.varint(iwant);
}

pub fn writeIwantId(w: *Writer, id: []const u8) void {
    w.bytesField(1, id);
}

/// Size of a whole RPC carrying one IDONTWANT for `id_count` ids.
pub fn idontwantRpcSize(id_count: usize, id_len: usize) usize {
    const idontwant = id_count * bytesFieldSize(1, id_len);
    return bytesFieldSize(3, bytesFieldSize(5, idontwant));
}

pub fn beginIdontwantRpc(w: *Writer, id_count: usize, id_len: usize) void {
    const idontwant = id_count * bytesFieldSize(1, id_len);
    w.tag(3, wire_len);
    w.varint(bytesFieldSize(5, idontwant));
    w.tag(5, wire_len);
    w.varint(idontwant);
}

pub fn writeIdontwantId(w: *Writer, id: []const u8) void {
    w.bytesField(1, id);
}

test "protobuf round trips an idontwant control rpc" {
    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    beginIdontwantRpc(&w, 1, 4);
    writeIdontwantId(&w, "id09");
    try std.testing.expectEqual(idontwantRpcSize(1, 4), w.len);
    var reader = RpcReader.init(w.written());
    const item = (try reader.next()).?;
    var ids = item.idontwant.ids();
    try std.testing.expectEqualStrings("id09", (try ids.next()).?);
}

test "protobuf round trips ihave and iwant control rpcs" {
    var buf: [256]u8 = undefined;
    var w = Writer.init(&buf);
    beginIhaveRpc(&w, "t", 2, 4);
    writeIhaveId(&w, "id01");
    writeIhaveId(&w, "id02");
    try std.testing.expectEqual(ihaveRpcSize("t", 2, 4), w.len);
    var reader = RpcReader.init(w.written());
    const ihave = (try reader.next()).?;
    try std.testing.expectEqualStrings("t", ihave.ihave.topic);
    var ids = ihave.ihave.ids();
    try std.testing.expectEqualStrings("id01", (try ids.next()).?);
    try std.testing.expectEqualStrings("id02", (try ids.next()).?);

    w = Writer.init(&buf);
    beginIwantRpc(&w, 1, 4);
    writeIwantId(&w, "id03");
    try std.testing.expectEqual(iwantRpcSize(1, 4), w.len);
    reader = RpcReader.init(w.written());
    const iwant = (try reader.next()).?;
    var wids = iwant.iwant.ids();
    try std.testing.expectEqualStrings("id03", (try wids.next()).?);
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

test "protobuf tolerates a field number above u32 without overflow" {
    // tag varint 0x800000000 => field 2^32, wire 0; a u32 field would panic here.
    var r = Reader.init(&[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 });
    const t = try r.tag();
    try std.testing.expect(t.field > std.math.maxInt(u32));
    try std.testing.expectEqual(@as(u3, 0), t.wire);
}

test "protobuf skips a field carrying an unexpected wire type" {
    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    w.varintField(1, 12_345); // field 1 as a varint: not a valid subscription
    writeSubscription(&w, true, "topic_a");
    var reader = RpcReader.init(w.written());
    const sub = (try reader.next()).?;
    try std.testing.expect(sub.subscription.subscribe);
    try std.testing.expectEqualStrings("topic_a", sub.subscription.topic);
    try std.testing.expect((try reader.next()) == null);
}

test "gossip protobuf steps unknown fields under explicit scan credit" {
    var bytes: [8192]u8 = undefined;
    for (0..4096) |i| @memcpy(bytes[i * 2 ..][0..2], &[_]u8{ 0x38, 0 });
    var rpc = RpcReader.init(&bytes);
    for (0..4096) |_| {
        var fields: usize = 1;
        try std.testing.expectEqual(RpcReader.Step.skipped, try rpc.step(&fields));
        try std.testing.expectEqual(@as(usize, 0), fields);
        try std.testing.expectEqual(RpcReader.Step.deferred, try rpc.step(&fields));
    }
    var fields: usize = 1;
    try std.testing.expectEqual(RpcReader.Step.end, try rpc.step(&fields));
}

test "gossip protobuf rejects excessive nested field visits and preserves deferred cursor" {
    var bytes: [16386]u8 = undefined;
    for (0..8193) |i| @memcpy(bytes[i * 2 ..][0..2], &[_]u8{ 0x38, 0 });
    try std.testing.expectError(error.FieldLimit, Message.decode(&bytes));
    var encoded: [256]u8 = undefined;
    var w = Writer.init(&encoded);
    writeMessage(&w, "data", "topic");
    var rpc = RpcReader.init(w.written());
    var fields: usize = 1;
    try std.testing.expectEqual(RpcReader.Step.deferred, try rpc.step(&fields));
    try std.testing.expectEqual(@as(usize, 0), rpc.top.pos);
    fields = 16385;
    const result = try rpc.step(&fields);
    try std.testing.expectEqualStrings("data", result.item.message.data);
}
