//! Discovery v5 protocol handler

const std = @import("std");
const Allocator = std.mem.Allocator;
const NodeId = @import("enr.zig").NodeId;
const kbucket = @import("kbucket.zig");
const packet = @import("packet.zig");
const session_mod = @import("session.zig");
const messages = @import("messages.zig");
const transport_mod = @import("transport.zig");

pub const CHALLENGE_DATA_SIZE = 63;

pub const SessionState = enum {
    unknown,
    whoareyou_sent,
    established,
};

pub const Session = struct {
    node_id: NodeId,
    state: SessionState,
    challenge_data: [CHALLENGE_DATA_SIZE]u8,
    challenge_data_len: usize,
    initiator_key: [16]u8,
    recipient_key: [16]u8,
    next_nonce: [12]u8,
};

pub const Config = struct {
    local_secret_key: [32]u8,
    local_node_id: NodeId,
    listen_addr: transport_mod.Address,
};

pub const Protocol = struct {
    alloc: Allocator,
    config: Config,
    routing_table: kbucket.RoutingTable,
    sessions: std.AutoHashMap(NodeId, Session),
    rng: std.Random.DefaultPrng,

    pub fn init(alloc: Allocator, config: Config) !Protocol {
        var seed: u64 = 0;
        seed = 0xcafebabe;
        return .{
            .alloc = alloc,
            .config = config,
            .routing_table = kbucket.RoutingTable.init(alloc, config.local_node_id),
            .sessions = std.AutoHashMap(NodeId, Session).init(alloc),
            .rng = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn deinit(self: *Protocol) void {
        self.routing_table.deinit();
        self.sessions.deinit();
    }

    pub fn randomNonce(self: *Protocol) [12]u8 {
        var nonce: [12]u8 = undefined;
        self.rng.random().bytes(&nonce);
        return nonce;
    }

    pub fn randomReqId(self: *Protocol) messages.ReqId {
        var id: messages.ReqId = .{ .bytes = undefined, .len = 4 };
        self.rng.random().bytes(id.bytes[0..4]);
        return id;
    }

    /// Handle an incoming raw UDP packet
    pub fn handlePacket(
        self: *Protocol,
        raw: []const u8,
        from: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        var parsed = packet.decode(self.alloc, raw, &self.config.local_node_id) catch return;
        defer parsed.deinit();

        switch (parsed.static_header.flag) {
            packet.FLAG_MESSAGE => try self.handleMessage(&parsed, from, t),
            packet.FLAG_WHOAREYOU => try self.handleWhoareyou(&parsed, from, t),
            packet.FLAG_HANDSHAKE => try self.handleHandshake(&parsed, from, t),
            else => {},
        }
    }

    fn handleMessage(
        self: *Protocol,
        parsed: *packet.ParsedPacket,
        from: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        const authdata = parsed.authdata_raw;
        if (authdata.len < 32) return;
        const src_id: NodeId = authdata[0..32].*;

        if (self.sessions.get(src_id)) |s| {
            if (s.state == .established) {
                const pt = packet.decryptMessage(
                    self.alloc,
                    &s.recipient_key,
                    &parsed.static_header.nonce,
                    parsed.message_ciphertext,
                    &parsed.masking_iv,
                    parsed.header_raw,
                ) catch {
                    try self.sendWhoareyou(src_id, &parsed.static_header.nonce, from, t);
                    return;
                };
                defer self.alloc.free(pt);
                try self.dispatchMessage(pt, src_id, from, t);
                return;
            }
        }

        try self.sendWhoareyou(src_id, &parsed.static_header.nonce, from, t);
    }

    fn handleWhoareyou(
        self: *Protocol,
        parsed: *packet.ParsedPacket,
        from: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        _ = self;
        _ = parsed;
        _ = from;
        _ = t;
        // TODO: respond with handshake
    }

    fn handleHandshake(
        self: *Protocol,
        parsed: *packet.ParsedPacket,
        from: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        _ = from;
        _ = t;
        const authdata = parsed.authdata_raw;
        if (authdata.len < 34) return;

        const src_id: NodeId = authdata[0..32].*;
        const sig_size = authdata[32];
        const eph_key_size = authdata[33];

        if (authdata.len < @as(usize, 34) + sig_size + eph_key_size) return;

        const id_sig = authdata[34 .. 34 + sig_size];
        const eph_pubkey = authdata[34 + sig_size .. 34 + sig_size + eph_key_size];

        const s = self.sessions.get(src_id) orelse return;
        if (s.state != .whoareyou_sent) return;
        if (sig_size != 64 or eph_key_size != 33) return;

        const eph_pk: *const [33]u8 = eph_pubkey[0..33];
        const challenge = s.challenge_data[0..s.challenge_data_len];

        const keys = session_mod.deriveKeys(
            &self.config.local_secret_key,
            eph_pk,
            &src_id,
            &self.config.local_node_id,
            challenge,
        ) catch return;

        var new_session = s;
        new_session.state = .established;
        new_session.initiator_key = keys.recipient_key;
        new_session.recipient_key = keys.initiator_key;
        try self.sessions.put(src_id, new_session);

        _ = id_sig;
    }

    fn sendWhoareyou(
        self: *Protocol,
        src_id: NodeId,
        request_nonce: *const [12]u8,
        dest: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        var id_nonce: [16]u8 = undefined;
        self.rng.random().bytes(&id_nonce);

        var authdata: [24]u8 = undefined;
        @memcpy(authdata[0..16], &id_nonce);
        std.mem.writeInt(u64, authdata[16..24], 0, .big);

        var masking_iv: [16]u8 = undefined;
        self.rng.random().bytes(&masking_iv);

        const whoareyou_packet = try packet.encode(
            self.alloc,
            &masking_iv,
            &src_id,
            packet.FLAG_WHOAREYOU,
            request_nonce,
            &authdata,
            &[_]u8{},
        );
        defer self.alloc.free(whoareyou_packet);

        var s = Session{
            .node_id = src_id,
            .state = .whoareyou_sent,
            .challenge_data = undefined,
            .challenge_data_len = @min(whoareyou_packet.len, CHALLENGE_DATA_SIZE),
            .initiator_key = undefined,
            .recipient_key = undefined,
            .next_nonce = undefined,
        };
        @memcpy(s.challenge_data[0..s.challenge_data_len], whoareyou_packet[0..s.challenge_data_len]);
        try self.sessions.put(src_id, s);

        try t.send(dest, whoareyou_packet);
    }

    fn dispatchMessage(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        if (pt.len == 0) return;
        switch (pt[0]) {
            messages.MSG_PING => try self.handlePing(pt, from, from_addr, t),
            messages.MSG_FINDNODE => try self.handleFindNode(pt, from, from_addr, t),
            else => {},
        }
    }

    fn handlePing(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        const ping = messages.Ping.decode(pt) catch return;

        const pong = messages.Pong{
            .req_id = ping.req_id,
            .enr_seq = 0,
            .recipient_ip = from_addr.ip,
            .recipient_port = from_addr.port,
        };

        const s = self.sessions.get(from) orelse return;
        const nonce = self.randomNonce();
        const pong_bytes = try pong.encode(self.alloc);
        defer self.alloc.free(pong_bytes);

        var masking_iv: [16]u8 = undefined;
        self.rng.random().bytes(&masking_iv);
        const authdata: [32]u8 = self.config.local_node_id;

        const header_raw = try buildHeaderRaw(self.alloc, packet.FLAG_MESSAGE, &nonce, &authdata);
        defer self.alloc.free(header_raw);

        const ct = try packet.encryptMessage(
            self.alloc,
            &s.initiator_key,
            &nonce,
            pong_bytes,
            &masking_iv,
            header_raw,
        );
        defer self.alloc.free(ct);

        const pkt = try packet.encode(
            self.alloc,
            &masking_iv,
            &from,
            packet.FLAG_MESSAGE,
            &nonce,
            &authdata,
            ct,
        );
        defer self.alloc.free(pkt);

        try t.send(from_addr, pkt);
    }

    fn handleFindNode(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        const result = messages.FindNode.decode(self.alloc, pt) catch return;
        defer self.alloc.free(result.distances);

        const fn_msg = result.msg;

        const nodes_msg = messages.Nodes{
            .req_id = fn_msg.req_id,
            .total = 1,
            .enrs = &[_][]const u8{},
        };

        const s = self.sessions.get(from) orelse return;
        const nonce = self.randomNonce();
        const nodes_bytes = try nodes_msg.encode(self.alloc);
        defer self.alloc.free(nodes_bytes);

        var masking_iv: [16]u8 = undefined;
        self.rng.random().bytes(&masking_iv);
        const authdata: [32]u8 = self.config.local_node_id;

        const header_raw = try buildHeaderRaw(self.alloc, packet.FLAG_MESSAGE, &nonce, &authdata);
        defer self.alloc.free(header_raw);

        const ct = try packet.encryptMessage(
            self.alloc,
            &s.initiator_key,
            &nonce,
            nodes_bytes,
            &masking_iv,
            header_raw,
        );
        defer self.alloc.free(ct);

        const pkt = try packet.encode(
            self.alloc,
            &masking_iv,
            &from,
            packet.FLAG_MESSAGE,
            &nonce,
            &authdata,
            ct,
        );
        defer self.alloc.free(pkt);

        try t.send(from_addr, pkt);
    }

    pub fn addNode(self: *Protocol, node_id: NodeId, addr: transport_mod.Address) void {
        const entry = kbucket.Entry{
            .node_id = node_id,
            .addr = [6]u8{
                addr.ip[0], addr.ip[1], addr.ip[2], addr.ip[3],
                @intCast(addr.port >> 8), @intCast(addr.port & 0xff),
            },
            .last_seen = 0,
            .status = .connected,
        };
        _ = self.routing_table.insert(entry);
    }
};

fn buildHeaderRaw(
    alloc: Allocator,
    flag: u8,
    nonce: *const [12]u8,
    authdata: []const u8,
) ![]u8 {
    const total = packet.STATIC_HEADER_SIZE + authdata.len;
    const buf = try alloc.alloc(u8, total);
    @memcpy(buf[0..6], packet.PROTOCOL_ID);
    std.mem.writeInt(u16, buf[6..8], packet.VERSION, .big);
    buf[8] = flag;
    @memcpy(buf[9..21], nonce);
    std.mem.writeInt(u16, buf[21..23], @intCast(authdata.len), .big);
    @memcpy(buf[packet.STATIC_HEADER_SIZE..], authdata);
    return buf;
}

// =========== Tests ===========

test "discv5 protocol: basic init" {
    const alloc = std.testing.allocator;
    const secp = @import("secp256k1.zig");
    const hex = @import("hex.zig");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk = try secp.pubkeyFromSecret(&sk);
    const node_id = @import("enr.zig").nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(alloc, .{
        .local_secret_key = sk,
        .local_node_id = node_id,
        .listen_addr = .{ .ip = [4]u8{ 127, 0, 0, 1 }, .port = 9000 },
    });
    defer proto.deinit();

    try std.testing.expectEqual(@as(usize, 0), proto.routing_table.nodeCount());

    var node_id2: NodeId = [_]u8{0xbb} ** 32;
    node_id2[31] = 0x01;
    proto.addNode(node_id2, .{ .ip = [4]u8{ 192, 168, 1, 1 }, .port = 30303 });
    try std.testing.expectEqual(@as(usize, 1), proto.routing_table.nodeCount());
}
