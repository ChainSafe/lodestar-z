//! Discovery v5 message types

const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("rlp.zig");

pub const MSG_PING: u8 = 0x01;
pub const MSG_PONG: u8 = 0x02;
pub const MSG_FINDNODE: u8 = 0x03;
pub const MSG_NODES: u8 = 0x04;
pub const MSG_TALKREQ: u8 = 0x05;
pub const MSG_TALKRESP: u8 = 0x06;

pub const Error = error{
    InvalidMessage,
    OutOfMemory,
    InvalidEncoding,
    UnexpectedType,
    Overflow,
    BufferTooSmall,
};

pub const ReqId = struct {
    bytes: [8]u8,
    len: u8,

    pub fn fromSlice(s: []const u8) Error!ReqId {
        if (s.len == 0 or s.len > 8) return Error.InvalidMessage;
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
        var w = rlp.Writer.init(alloc);
        defer w.deinit();

        const list_start = try w.beginList();
        try w.writeBytes(self.req_id.slice());
        try w.writeUint64(self.enr_seq);
        try w.finishList(list_start);

        const rlp_bytes = w.bytes();
        const result = try alloc.alloc(u8, 1 + rlp_bytes.len);
        result[0] = MSG_PING;
        @memcpy(result[1..], rlp_bytes);
        return result;
    }

    pub fn decode(data: []const u8) Error!Ping {
        if (data.len < 1 or data[0] != MSG_PING) return Error.InvalidMessage;
        var r = rlp.Reader.init(data[1..]);
        var list = r.readList() catch return Error.InvalidEncoding;
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const enr_seq = list.readUint64() catch return Error.InvalidEncoding;
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
        var w = rlp.Writer.init(alloc);
        defer w.deinit();

        const list_start = try w.beginList();
        try w.writeBytes(self.req_id.slice());
        try w.writeUint64(self.enr_seq);
        switch (self.recipient_ip) {
            .ip4 => |ip| try w.writeBytes(&ip),
            .ip6 => |ip| try w.writeBytes(&ip),
        }
        const port = self.recipient_port;
        if (port == 0) {
            try w.writeUint64(0);
        } else if (port < 256) {
            try w.writeBytes(&[1]u8{@intCast(port)});
        } else {
            try w.writeBytes(&[2]u8{ @intCast(port >> 8), @intCast(port & 0xff) });
        }
        try w.finishList(list_start);

        const rlp_bytes = w.bytes();
        const result = try alloc.alloc(u8, 1 + rlp_bytes.len);
        result[0] = MSG_PONG;
        @memcpy(result[1..], rlp_bytes);
        return result;
    }

    pub fn decode(data: []const u8) Error!Pong {
        if (data.len < 1 or data[0] != MSG_PONG) return Error.InvalidMessage;
        var r = rlp.Reader.init(data[1..]);
        var list = r.readList() catch return Error.InvalidEncoding;
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const enr_seq = list.readUint64() catch return Error.InvalidEncoding;
        const ip_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const port_bytes = list.readBytes() catch return Error.InvalidEncoding;
        var port: u16 = 0;
        for (port_bytes) |b| port = (port << 8) | b;
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
        var w = rlp.Writer.init(alloc);
        defer w.deinit();

        const list_start = try w.beginList();
        try w.writeBytes(self.req_id.slice());
        const dist_start = try w.beginList();
        for (self.distances) |d| {
            try w.writeUint64(d);
        }
        try w.finishList(dist_start);
        try w.finishList(list_start);

        const rlp_bytes = w.bytes();
        const result = try alloc.alloc(u8, 1 + rlp_bytes.len);
        result[0] = MSG_FINDNODE;
        @memcpy(result[1..], rlp_bytes);
        return result;
    }

    pub fn decode(alloc: Allocator, data: []const u8) Error!struct { msg: FindNode, distances: []u16 } {
        if (data.len < 1 or data[0] != MSG_FINDNODE) return Error.InvalidMessage;
        var r = rlp.Reader.init(data[1..]);
        var list = r.readList() catch return Error.InvalidEncoding;
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);

        var dist_list = list.readList() catch return Error.InvalidEncoding;
        var distances: std.ArrayListUnmanaged(u16) = .empty;
        errdefer distances.deinit(alloc);
        while (!dist_list.atEnd()) {
            const d = dist_list.readUint64() catch return Error.InvalidEncoding;
            if (d > 256) return Error.InvalidMessage;
            try distances.append(alloc, @intCast(d));
        }
        const dist_slice = try distances.toOwnedSlice(alloc);
        return .{
            .msg = FindNode{ .req_id = req_id, .distances = dist_slice },
            .distances = dist_slice,
        };
    }
};

pub const Nodes = struct {
    req_id: ReqId,
    total: u64,
    enrs: []const []const u8,

    pub fn encode(self: *const Nodes, alloc: Allocator) ![]u8 {
        var w = rlp.Writer.init(alloc);
        defer w.deinit();

        const list_start = try w.beginList();
        try w.writeBytes(self.req_id.slice());
        try w.writeUint64(self.total);
        const enr_start = try w.beginList();
        for (self.enrs) |enr| {
            try w.writeBytes(enr);
        }
        try w.finishList(enr_start);
        try w.finishList(list_start);

        const rlp_bytes = w.bytes();
        const result = try alloc.alloc(u8, 1 + rlp_bytes.len);
        result[0] = MSG_NODES;
        @memcpy(result[1..], rlp_bytes);
        return result;
    }

    pub fn decode(alloc: Allocator, data: []const u8) Error!struct { msg: Nodes, enrs: [][]u8 } {
        if (data.len < 1 or data[0] != MSG_NODES) return Error.InvalidMessage;
        var r = rlp.Reader.init(data[1..]);
        var list = r.readList() catch return Error.InvalidEncoding;
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const total = list.readUint64() catch return Error.InvalidEncoding;

        var enr_list = list.readList() catch return Error.InvalidEncoding;
        var enrs: std.ArrayListUnmanaged([]u8) = .empty;
        errdefer {
            for (enrs.items) |enr| alloc.free(enr);
            enrs.deinit(alloc);
        }

        while (!enr_list.atEnd()) {
            const enr_bytes = enr_list.readBytes() catch return Error.InvalidEncoding;
            try enrs.append(alloc, try alloc.dupe(u8, enr_bytes));
        }
        const owned = try enrs.toOwnedSlice(alloc);
        return .{
            .msg = .{ .req_id = req_id, .total = total, .enrs = owned },
            .enrs = owned,
        };
    }
};

pub const TalkReq = struct {
    req_id: ReqId,
    protocol: []const u8,
    request: []const u8,

    pub fn encode(self: *const TalkReq, alloc: Allocator) ![]u8 {
        var w = rlp.Writer.init(alloc);
        defer w.deinit();

        const list_start = try w.beginList();
        try w.writeBytes(self.req_id.slice());
        try w.writeBytes(self.protocol);
        try w.writeBytes(self.request);
        try w.finishList(list_start);

        const rlp_bytes = w.bytes();
        const result = try alloc.alloc(u8, 1 + rlp_bytes.len);
        result[0] = MSG_TALKREQ;
        @memcpy(result[1..], rlp_bytes);
        return result;
    }

    pub fn decode(data: []const u8) Error!TalkReq {
        if (data.len < 1 or data[0] != MSG_TALKREQ) return Error.InvalidMessage;
        var r = rlp.Reader.init(data[1..]);
        var list = r.readList() catch return Error.InvalidEncoding;
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const protocol = list.readBytes() catch return Error.InvalidEncoding;
        const request = list.readBytes() catch return Error.InvalidEncoding;
        return TalkReq{ .req_id = req_id, .protocol = protocol, .request = request };
    }
};

pub const TalkResp = struct {
    req_id: ReqId,
    response: []const u8,

    pub fn encode(self: *const TalkResp, alloc: Allocator) ![]u8 {
        var w = rlp.Writer.init(alloc);
        defer w.deinit();

        const list_start = try w.beginList();
        try w.writeBytes(self.req_id.slice());
        try w.writeBytes(self.response);
        try w.finishList(list_start);

        const rlp_bytes = w.bytes();
        const result = try alloc.alloc(u8, 1 + rlp_bytes.len);
        result[0] = MSG_TALKRESP;
        @memcpy(result[1..], rlp_bytes);
        return result;
    }

    pub fn decode(data: []const u8) Error!TalkResp {
        if (data.len < 1 or data[0] != MSG_TALKRESP) return Error.InvalidMessage;
        var r = rlp.Reader.init(data[1..]);
        var list = r.readList() catch return Error.InvalidEncoding;
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const response = list.readBytes() catch return Error.InvalidEncoding;
        return TalkResp{ .req_id = req_id, .response = response };
    }
};

// =========== Tests ===========

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
    const enr_a = "enr-a";
    const enr_b = "enr-b";
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
    const enr_mod = @import("enr.zig");
    const hex_mod = @import("hex.zig");

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var builder = enr_mod.Builder.init(alloc, secret_key, 1);
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

    var parsed = try enr_mod.decode(alloc, decoded.enrs[0]);
    defer parsed.deinit();
    try std.testing.expect(parsed.nodeId() != null);
}
