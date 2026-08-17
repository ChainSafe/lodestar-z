//! Discovery v5 message types

const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("../rlp.zig");

pub const MSG_PING: u8 = 0x01;
pub const MSG_PONG: u8 = 0x02;
pub const MSG_FINDNODE: u8 = 0x03;
pub const MSG_NODES: u8 = 0x04;
pub const MSG_TALKREQ: u8 = 0x05;
pub const MSG_TALKRESP: u8 = 0x06;

pub const MAX_ENCODED_SIZE: usize = 1280;

pub const Error = error{
    InvalidMessage,
    OutOfMemory,
    InvalidEncoding,
    UnexpectedType,
    Overflow,
    BufferTooSmall,
};

// Message payloads are fixed-shape RLP lists. Reject both trailing outer RLP
// bytes and extra fields inside the list so malformed packets have one clear
// interpretation.
fn readMessageList(data: []const u8, expected_type: u8) Error!rlp.Reader {
    if (data.len < 1 or data[0] != expected_type) return Error.InvalidMessage;

    var r = rlp.Reader.init(data[1..]);
    const list = r.readList() catch return Error.InvalidEncoding;
    if (!r.atEnd()) return Error.InvalidEncoding;
    return list;
}

fn expectEnd(r: *const rlp.Reader) Error!void {
    if (!r.atEnd()) return Error.InvalidEncoding;
}

/// Discv5 request IDs are RLP byte arrays of length 0..8, and responses must
/// echo the exact byte sequence from the request. Keep the length alongside the
/// fixed backing storage so values like `01`, `01 00`, and `01 00 00 00` stay
/// distinct without allocating. The unused tail is zeroed so `ReqId` can be
/// used directly as a value key in hash maps.
pub const ReqId = struct {
    bytes: [8]u8,
    len: u8,

    pub fn fromSlice(s: []const u8) Error!ReqId {
        if (s.len > 8) return Error.InvalidMessage;
        var id = ReqId{ .bytes = [_]u8{0} ** 8, .len = @intCast(s.len) };
        @memcpy(id.bytes[0..s.len], s);
        return id;
    }

    pub fn slice(self: *const ReqId) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Ping = struct {
    req_id: ReqId,
    enr_seq: u64,

    pub fn encode(self: *const Ping, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const Ping, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeUint64Bounded(self.enr_seq);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_PING;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(data: []const u8) Error!Ping {
        var list = try readMessageList(data, MSG_PING);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const enr_seq = list.readUint64() catch return Error.InvalidEncoding;
        try expectEnd(&list);
        return Ping{ .req_id = req_id, .enr_seq = enr_seq };
    }
};

pub const Pong = struct {
    pub const RecipientIp = union(enum) {
        ip4: [4]u8,
        ip6: [16]u8,
    };

    req_id: ReqId,
    enr_seq: u64,
    recipient_ip: RecipientIp,
    recipient_port: u16,

    pub fn encode(self: *const Pong, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const Pong, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeUint64Bounded(self.enr_seq);
        switch (self.recipient_ip) {
            .ip4 => |ip| try w.writeBytesBounded(&ip),
            .ip6 => |ip| try w.writeBytesBounded(&ip),
        }
        try w.writeUint64Bounded(self.recipient_port);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_PONG;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(data: []const u8) Error!Pong {
        var list = try readMessageList(data, MSG_PONG);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const enr_seq = list.readUint64() catch return Error.InvalidEncoding;
        const ip_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const port_value = list.readUint64() catch return Error.InvalidEncoding;
        if (port_value > std.math.maxInt(u16)) return Error.InvalidMessage;
        const port: u16 = @intCast(port_value);
        try expectEnd(&list);
        return Pong{
            .req_id = req_id,
            .enr_seq = enr_seq,
            .recipient_ip = switch (ip_bytes.len) {
                4 => .{ .ip4 = ip_bytes[0..4].* },
                16 => .{ .ip6 = ip_bytes[0..16].* },
                else => return Error.InvalidMessage,
            },
            .recipient_port = port,
        };
    }
};

pub const FindNode = struct {
    req_id: ReqId,
    distances: []const u16,

    pub fn encode(self: *const FindNode, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const FindNode, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        const dist_start = try w.beginListBounded();
        for (self.distances) |d| {
            try w.writeUint64Bounded(d);
        }
        try w.finishList(dist_start);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_FINDNODE;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(alloc: Allocator, data: []const u8) Error!struct { msg: FindNode, distances: []u16 } {
        var stack_distances: [127]u16 = undefined;
        const msg = try decodeInto(data, &stack_distances);
        const dist_slice = try alloc.dupe(u16, msg.distances);
        return .{
            .msg = FindNode{ .req_id = msg.req_id, .distances = dist_slice },
            .distances = dist_slice,
        };
    }

    pub fn decodeInto(data: []const u8, distances_out: []u16) Error!FindNode {
        var list = try readMessageList(data, MSG_FINDNODE);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);

        var dist_list = list.readList() catch return Error.InvalidEncoding;
        var distances_len: usize = 0;
        while (!dist_list.atEnd()) {
            const d = dist_list.readUint64() catch return Error.InvalidEncoding;
            if (d > 256) return Error.InvalidMessage;
            if (distances_len >= distances_out.len) return Error.BufferTooSmall;
            distances_out[distances_len] = @intCast(d);
            distances_len += 1;
        }
        try expectEnd(&list);
        return FindNode{ .req_id = req_id, .distances = distances_out[0..distances_len] };
    }
};

pub const Nodes = struct {
    req_id: ReqId,
    total: u64,
    enrs: []const []const u8,

    pub fn encode(self: *const Nodes, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const Nodes, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeUint64Bounded(self.total);
        const enr_start = try w.beginListBounded();
        for (self.enrs) |enr| {
            try w.writeRawItemBounded(enr);
        }
        try w.finishList(enr_start);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_NODES;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(alloc: Allocator, data: []const u8) Error!struct { msg: Nodes, enrs: [][]u8 } {
        var stack_enrs: [16][]const u8 = undefined;
        const msg = try decodeInto(data, &stack_enrs);
        var enrs: std.ArrayListUnmanaged([]u8) = .empty;
        errdefer {
            for (enrs.items) |enr| alloc.free(enr);
            enrs.deinit(alloc);
        }
        for (msg.enrs) |enr| {
            try enrs.append(alloc, try alloc.dupe(u8, enr));
        }
        const owned = try enrs.toOwnedSlice(alloc);
        return .{
            .msg = .{ .req_id = msg.req_id, .total = msg.total, .enrs = owned },
            .enrs = owned,
        };
    }

    pub fn decodeInto(data: []const u8, enrs_out: [][]const u8) Error!Nodes {
        var list = try readMessageList(data, MSG_NODES);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const total = list.readUint64() catch return Error.InvalidEncoding;

        var enr_list = list.readList() catch return Error.InvalidEncoding;
        var enrs_len: usize = 0;
        while (!enr_list.atEnd()) {
            const enr_bytes = enr_list.readRawItem() catch return Error.InvalidEncoding;
            if (enrs_len >= enrs_out.len) return Error.BufferTooSmall;
            enrs_out[enrs_len] = enr_bytes;
            enrs_len += 1;
        }
        try expectEnd(&list);
        return Nodes{ .req_id = req_id, .total = total, .enrs = enrs_out[0..enrs_len] };
    }
};

pub const TalkReq = struct {
    req_id: ReqId,
    protocol: []const u8,
    request: []const u8,

    pub fn encode(self: *const TalkReq, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const TalkReq, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeBytesBounded(self.protocol);
        try w.writeBytesBounded(self.request);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_TALKREQ;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(data: []const u8) Error!TalkReq {
        var list = try readMessageList(data, MSG_TALKREQ);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const protocol = list.readBytes() catch return Error.InvalidEncoding;
        const request = list.readBytes() catch return Error.InvalidEncoding;
        try expectEnd(&list);
        return TalkReq{ .req_id = req_id, .protocol = protocol, .request = request };
    }
};

pub const TalkResp = struct {
    req_id: ReqId,
    response: []const u8,

    pub fn encode(self: *const TalkResp, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const TalkResp, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeBytesBounded(self.response);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_TALKRESP;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(data: []const u8) Error!TalkResp {
        var list = try readMessageList(data, MSG_TALKRESP);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const response = list.readBytes() catch return Error.InvalidEncoding;
        try expectEnd(&list);
        return TalkResp{ .req_id = req_id, .response = response };
    }
};

// =========== Tests ===========

fn appendTrailingByte(alloc: Allocator, encoded: []const u8) ![]u8 {
    const with_trailing = try alloc.alloc(u8, encoded.len + 1);
    @memcpy(with_trailing[0..encoded.len], encoded);
    with_trailing[encoded.len] = 0x80;
    return with_trailing;
}

fn appendExtraShortListField(alloc: Allocator, encoded: []const u8) ![]u8 {
    try std.testing.expect(encoded.len >= 2);
    try std.testing.expect(encoded[1] >= 0xc0 and encoded[1] < 0xf8);
    try std.testing.expect(encoded[1] < 0xf7);

    const with_extra = try alloc.alloc(u8, encoded.len + 1);
    @memcpy(with_extra[0..encoded.len], encoded);
    with_extra[1] += 1;
    with_extra[encoded.len] = 0x80;
    return with_extra;
}

test "discv5 messages: PING encode/decode" {
    const alloc = std.testing.allocator;
    const ping = Ping{
        .req_id = try ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x01 }),
        .enr_seq = 2,
    };
    const encoded = try ping.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try Ping.decode(encoded);
    try std.testing.expectEqual(@as(u64, 2), decoded.enr_seq);
    try std.testing.expectEqualSlices(u8, ping.req_id.slice(), decoded.req_id.slice());
}

test "discv5 messages accept empty request IDs" {
    const empty_req_id = try ReqId.fromSlice(&.{});
    try std.testing.expectEqual(@as(u8, 0), empty_req_id.len);
    try std.testing.expectEqual(@as(usize, 0), empty_req_id.slice().len);
    try std.testing.expectError(Error.InvalidMessage, ReqId.fromSlice(&([_]u8{0} ** 9)));

    var encoded_buf: [MAX_ENCODED_SIZE]u8 = undefined;

    const ping = Ping{ .req_id = empty_req_id, .enr_seq = 1 };
    const encoded_ping = try ping.encodeInto(&encoded_buf);
    const decoded_ping = try Ping.decode(encoded_ping);
    try std.testing.expectEqual(@as(usize, 0), decoded_ping.req_id.slice().len);

    const pong = Pong{
        .req_id = decoded_ping.req_id,
        .enr_seq = 1,
        .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } },
        .recipient_port = 9000,
    };
    const encoded_pong = try pong.encodeInto(&encoded_buf);
    const decoded_pong = try Pong.decode(encoded_pong);
    try std.testing.expectEqual(@as(usize, 0), decoded_pong.req_id.slice().len);

    const find_node = FindNode{ .req_id = empty_req_id, .distances = &.{1} };
    const encoded_find_node = try find_node.encodeInto(&encoded_buf);
    var distances_buf: [1]u16 = undefined;
    const decoded_find_node = try FindNode.decodeInto(encoded_find_node, &distances_buf);
    try std.testing.expectEqual(@as(usize, 0), decoded_find_node.req_id.slice().len);

    const nodes = Nodes{ .req_id = empty_req_id, .total = 1, .enrs = &.{} };
    const encoded_nodes = try nodes.encodeInto(&encoded_buf);
    var enrs_buf: [1][]const u8 = undefined;
    const decoded_nodes = try Nodes.decodeInto(encoded_nodes, &enrs_buf);
    try std.testing.expectEqual(@as(usize, 0), decoded_nodes.req_id.slice().len);

    const talk_req = TalkReq{ .req_id = empty_req_id, .protocol = "test", .request = "request" };
    const encoded_talk_req = try talk_req.encodeInto(&encoded_buf);
    const decoded_talk_req = try TalkReq.decode(encoded_talk_req);
    try std.testing.expectEqual(@as(usize, 0), decoded_talk_req.req_id.slice().len);

    const talk_resp = TalkResp{ .req_id = empty_req_id, .response = "response" };
    const encoded_talk_resp = try talk_resp.encodeInto(&encoded_buf);
    const decoded_talk_resp = try TalkResp.decode(encoded_talk_resp);
    try std.testing.expectEqual(@as(usize, 0), decoded_talk_resp.req_id.slice().len);
}

test "discv5 messages reject trailing bytes after outer RLP" {
    const alloc = std.testing.allocator;

    {
        const msg = Ping{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .enr_seq = 2,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        try std.testing.expectError(Error.InvalidEncoding, Ping.decode(with_trailing));
    }

    {
        const msg = Pong{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .enr_seq = 2,
            .recipient_ip = .{ .ip4 = [4]u8{ 127, 0, 0, 1 } },
            .recipient_port = 9000,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        try std.testing.expectError(Error.InvalidEncoding, Pong.decode(with_trailing));
    }

    {
        const distances = [_]u16{ 256, 255 };
        const msg = FindNode{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .distances = &distances,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        var distances_out: [2]u16 = undefined;
        try std.testing.expectError(Error.InvalidEncoding, FindNode.decodeInto(with_trailing, &distances_out));
    }

    {
        var enr_buf: [16]u8 = undefined;
        var w = rlp.Writer.initBuffer(&enr_buf);
        try w.writeBytesBounded("enr");
        const enr = w.bytes();
        const msg = Nodes{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .total = 1,
            .enrs = &.{enr},
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        var enrs_out: [1][]const u8 = undefined;
        try std.testing.expectError(Error.InvalidEncoding, Nodes.decodeInto(with_trailing, &enrs_out));
    }

    {
        const msg = TalkReq{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .protocol = "eth",
            .request = "hello",
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        try std.testing.expectError(Error.InvalidEncoding, TalkReq.decode(with_trailing));
    }

    {
        const msg = TalkResp{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .response = "hello",
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        try std.testing.expectError(Error.InvalidEncoding, TalkResp.decode(with_trailing));
    }
}

test "discv5 messages reject extra fields inside message list" {
    const alloc = std.testing.allocator;

    {
        const msg = Ping{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .enr_seq = 2,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        try std.testing.expectError(Error.InvalidEncoding, Ping.decode(with_extra));
    }

    {
        const msg = Pong{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .enr_seq = 2,
            .recipient_ip = .{ .ip4 = [4]u8{ 127, 0, 0, 1 } },
            .recipient_port = 9000,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        try std.testing.expectError(Error.InvalidEncoding, Pong.decode(with_extra));
    }

    {
        const distances = [_]u16{ 256, 255 };
        const msg = FindNode{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .distances = &distances,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        var distances_out: [2]u16 = undefined;
        try std.testing.expectError(Error.InvalidEncoding, FindNode.decodeInto(with_extra, &distances_out));
    }

    {
        var enr_buf: [16]u8 = undefined;
        var w = rlp.Writer.initBuffer(&enr_buf);
        try w.writeBytesBounded("enr");
        const enr = w.bytes();
        const msg = Nodes{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .total = 1,
            .enrs = &.{enr},
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        var enrs_out: [1][]const u8 = undefined;
        try std.testing.expectError(Error.InvalidEncoding, Nodes.decodeInto(with_extra, &enrs_out));
    }

    {
        const msg = TalkReq{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .protocol = "eth",
            .request = "hello",
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        try std.testing.expectError(Error.InvalidEncoding, TalkReq.decode(with_extra));
    }

    {
        const msg = TalkResp{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .response = "hello",
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        try std.testing.expectError(Error.InvalidEncoding, TalkResp.decode(with_extra));
    }
}

test "discv5 messages: PONG encode/decode" {
    const alloc = std.testing.allocator;
    const pong = Pong{
        .req_id = try ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x01 }),
        .enr_seq = 1,
        .recipient_ip = .{ .ip4 = [4]u8{ 127, 0, 0, 1 } },
        .recipient_port = 9000,
    };
    const encoded = try pong.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try Pong.decode(encoded);
    try std.testing.expectEqual(@as(u64, 1), decoded.enr_seq);
    try std.testing.expectEqual(@as(u16, 9000), decoded.recipient_port);
    try std.testing.expectEqualDeep(pong.recipient_ip, decoded.recipient_ip);
}

test "discv5 messages: PONG encode/decode IPv6" {
    const alloc = std.testing.allocator;
    const pong = Pong{
        .req_id = try ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x02 }),
        .enr_seq = 2,
        .recipient_ip = .{ .ip6 = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        .recipient_port = 9001,
    };
    const encoded = try pong.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try Pong.decode(encoded);
    try std.testing.expectEqual(@as(u64, 2), decoded.enr_seq);
    try std.testing.expectEqual(@as(u16, 9001), decoded.recipient_port);
    try std.testing.expectEqualDeep(pong.recipient_ip, decoded.recipient_ip);
}

test "discv5 messages: PONG rejects a non-canonical port integer" {
    const encoded = [_]u8{
        MSG_PONG,
        0xca,
        0x01,
        0x80,
        0x84,
        127,
        0,
        0,
        1,
        0x82,
        0,
        1,
    };
    try std.testing.expectError(Error.InvalidEncoding, Pong.decode(&encoded));
}

test "discv5 messages: FINDNODE encode/decode" {
    const alloc = std.testing.allocator;
    const distances = [_]u16{ 256, 255, 254 };
    const msg = FindNode{
        .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
        .distances = &distances,
    };
    const encoded = try msg.encode(alloc);
    defer alloc.free(encoded);

    const result = try FindNode.decode(alloc, encoded);
    defer alloc.free(result.distances);
    try std.testing.expectEqual(@as(usize, 3), result.distances.len);
    try std.testing.expectEqual(@as(u16, 256), result.distances[0]);
}

test "discv5 messages: TALKREQ encode/decode" {
    const alloc = std.testing.allocator;
    const req = TalkReq{
        .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
        .protocol = "eth",
        .request = "hello",
    };
    const encoded = try req.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try TalkReq.decode(encoded);
    try std.testing.expectEqualSlices(u8, "eth", decoded.protocol);
    try std.testing.expectEqualSlices(u8, "hello", decoded.request);
}

test "discv5 messages: NODES encode/decode" {
    const alloc = std.testing.allocator;
    const req_id = try ReqId.fromSlice("id");
    var enr_a_buf: [32]u8 = undefined;
    var w_a = rlp.Writer.initBuffer(&enr_a_buf);
    try w_a.writeBytesBounded("enr-a");
    const enr_a = try alloc.dupe(u8, w_a.bytes());
    defer alloc.free(enr_a);

    var enr_b_buf: [32]u8 = undefined;
    var w_b = rlp.Writer.initBuffer(&enr_b_buf);
    const list_start = try w_b.beginListBounded();
    try w_b.writeBytesBounded("enr-b");
    try w_b.finishList(list_start);
    const enr_b = try alloc.dupe(u8, w_b.bytes());
    defer alloc.free(enr_b);
    const msg = Nodes{
        .req_id = req_id,
        .total = 2,
        .enrs = &.{ enr_a, enr_b },
    };

    const encoded = try msg.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try Nodes.decode(alloc, encoded);
    defer {
        for (decoded.enrs) |enr| alloc.free(enr);
        alloc.free(decoded.enrs);
    }

    try std.testing.expectEqual(@as(u64, 2), decoded.msg.total);
    try std.testing.expectEqual(@as(usize, 2), decoded.enrs.len);
    try std.testing.expectEqualSlices(u8, enr_a, decoded.enrs[0]);
    try std.testing.expectEqualSlices(u8, enr_b, decoded.enrs[1]);
}

test "discv5 messages: NODES decode returns encoded ENR bytes" {
    const alloc = std.testing.allocator;
    const enr_mod = @import("../enr.zig");
    const hex_mod = @import("hex");
    const secp = @import("../secp256k1.zig");

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = enr_mod.Builder.init(alloc, key_pair, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;
    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    const req_id = try ReqId.fromSlice("id");
    const msg = Nodes{
        .req_id = req_id,
        .total = 1,
        .enrs = &.{enr_bytes},
    };

    const encoded = try msg.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try Nodes.decode(alloc, encoded);
    defer {
        for (decoded.enrs) |enr| alloc.free(enr);
        alloc.free(decoded.enrs);
    }

    try std.testing.expectEqual(@as(usize, 1), decoded.enrs.len);
    try std.testing.expectEqualSlices(u8, enr_bytes, decoded.enrs[0]);

    const parsed = try enr_mod.decode(decoded.enrs[0]);
    try std.testing.expect(parsed.nodeId() != null);
}
