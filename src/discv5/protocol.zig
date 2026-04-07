//! Discovery v5 protocol handler

const std = @import("std");
const Allocator = std.mem.Allocator;
const NodeId = @import("enr.zig").NodeId;
const kbucket = @import("kbucket.zig");
const packet = @import("packet.zig");
const session_mod = @import("session.zig");
const messages = @import("messages.zig");
const udp_socket = @import("udp_socket.zig");
const secp = @import("secp256k1.zig");
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Io = std.Io;
const Address = udp_socket.Address;
const UdpSocket = udp_socket.Socket;
const enr_mod = @import("enr.zig");

pub const CHALLENGE_DATA_SIZE = 63;

/// Maximum packet size per discv5 spec (IPv6 minimum MTU).
/// Packets larger than this are dropped to prevent amplification (CL-2020-06).
pub const MAX_PACKET_SIZE: usize = 1280;

/// Maximum number of concurrent sessions. Bounded to prevent memory exhaustion (CL-2020-01).
pub const MAX_SESSIONS: usize = 1024;

/// Maximum WHOAREYOU packets sent per source IP per second.
/// Limits amplification when an attacker floods us with garbage from spoofed IPs (CL-2020-08).
pub const MAX_WHOAREYOU_PER_SEC: u32 = 5;

/// Maximum ENRs returned in a single NODES response per the discv5 spec.
pub const MAX_NODES_RESPONSE: usize = 16;

/// Bounded ring buffer of recently seen nonces per session.
/// Provides replay protection without heap allocation (CL-2020-nonce).
/// Capacity of 32 is sufficient for typical burst rates; older entries are
/// evicted silently (a 96-byte nonce window per session).
pub const SEEN_NONCES_CAP: usize = 32;

pub const SeenNonces = struct {
    buf: [SEEN_NONCES_CAP][12]u8,
    len: usize,
    head: usize,

    pub fn init() SeenNonces {
        return .{ .buf = undefined, .len = 0, .head = 0 };
    }

    /// Returns true if nonce was already seen (replay).
    pub fn contains(self: *const SeenNonces, nonce: *const [12]u8) bool {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const idx = (self.head + SEEN_NONCES_CAP - self.len + i) % SEEN_NONCES_CAP;
            if (std.mem.eql(u8, &self.buf[idx], nonce)) return true;
        }
        return false;
    }

    /// Record a nonce. Evicts the oldest entry when the buffer is full.
    pub fn insert(self: *SeenNonces, nonce: *const [12]u8) void {
        self.buf[self.head] = nonce.*;
        self.head = (self.head + 1) % SEEN_NONCES_CAP;
        if (self.len < SEEN_NONCES_CAP) self.len += 1;
    }
};

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
    /// Ring buffer of seen nonces — replay protection (CL-2020-nonce).
    seen_nonces: SeenNonces,
};

/// A pending outgoing request awaiting a WHOAREYOU challenge.
/// When we send an ordinary message to a node without a session, the remote
/// responds with WHOAREYOU. We store the original message here so we can
/// re-send it inside the handshake response.
pub const PendingRequest = struct {
    sent_at_ns: i64,
    nonce: [12]u8,
    dest_node_id: NodeId,
    dest_pubkey: [33]u8,
    dest_addr: Address,
    message_plaintext: []u8,
    alloc: Allocator,

    fn deinit(self: *PendingRequest) void {
        self.alloc.free(self.message_plaintext);
    }
};

const ReqIdKey = struct {
    bytes: [8]u8,
    len: u8,

    fn fromReqId(req_id: messages.ReqId) ReqIdKey {
        var bytes = [_]u8{0} ** 8;
        @memcpy(bytes[0..req_id.len], req_id.bytes[0..req_id.len]);
        return .{
            .bytes = bytes,
            .len = req_id.len,
        };
    }

    fn toReqId(self: ReqIdKey) messages.ReqId {
        return .{
            .bytes = self.bytes,
            .len = self.len,
        };
    }
};

const RequestKey = struct {
    peer_id: NodeId,
    req_id: ReqIdKey,
};

const ActiveFindNodeRequest = struct {
    enrs: std.ArrayListUnmanaged([]u8) = .empty,
    total_responses: ?u64 = null,
    responses_received: u64 = 0,

    fn deinit(self: *ActiveFindNodeRequest, alloc: Allocator) void {
        for (self.enrs.items) |enr| alloc.free(enr);
        self.enrs.deinit(alloc);
    }
};

const ActiveRequestKind = union(enum) {
    ping: void,
    findnode: ActiveFindNodeRequest,
    talkreq: void,

    fn deinit(self: *ActiveRequestKind, alloc: Allocator) void {
        switch (self.*) {
            .ping => {},
            .findnode => |*findnode| findnode.deinit(alloc),
            .talkreq => {},
        }
    }
};

pub const RequestKind = enum {
    ping,
    findnode,
    talkreq,
};

const ActiveRequest = struct {
    started_at_ns: i64,
    kind: ActiveRequestKind,

    fn deinit(self: *ActiveRequest, alloc: Allocator) void {
        self.kind.deinit(alloc);
    }

    fn requestKind(self: *const ActiveRequest) RequestKind {
        return switch (self.kind) {
            .ping => .ping,
            .findnode => .findnode,
            .talkreq => .talkreq,
        };
    }
};

const AddressKey = struct {
    family: Address.Family,
    bytes: [16]u8,

    fn fromAddress(addr: Address) AddressKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes },
        };
    }
};

pub const PongEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
    req_id: messages.ReqId,
    enr_seq: u64,
    recipient_ip: messages.Pong.RecipientIp,
    recipient_port: u16,
};

pub const NodesEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
    req_id: messages.ReqId,
    enrs: [][]u8,

    fn deinit(self: *NodesEvent, alloc: Allocator) void {
        for (self.enrs) |enr| alloc.free(enr);
        alloc.free(self.enrs);
    }
};

pub const TalkReqEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
    req_id: messages.ReqId,
    protocol: []u8,
    request: []u8,

    fn deinit(self: *TalkReqEvent, alloc: Allocator) void {
        alloc.free(self.protocol);
        alloc.free(self.request);
    }
};

pub const TalkRespEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
    req_id: messages.ReqId,
    response: []u8,

    fn deinit(self: *TalkRespEvent, alloc: Allocator) void {
        alloc.free(self.response);
    }
};

pub const RequestTimeoutEvent = struct {
    peer_id: NodeId,
    req_id: messages.ReqId,
    kind: RequestKind,
};

pub const Event = union(enum) {
    pong: PongEvent,
    nodes: NodesEvent,
    talkreq: TalkReqEvent,
    talkresp: TalkRespEvent,
    request_timeout: RequestTimeoutEvent,

    pub fn deinit(self: *Event, alloc: Allocator) void {
        switch (self.*) {
            .pong => {},
            .nodes => |*nodes| nodes.deinit(alloc),
            .talkreq => |*talkreq| talkreq.deinit(alloc),
            .talkresp => |*talkresp| talkresp.deinit(alloc),
            .request_timeout => {},
        }
    }
};

pub const Config = struct {
    local_secret_key: [32]u8,
    local_node_id: NodeId,
    /// Pre-encoded local ENR (RLP bytes). Included in handshake when remote
    /// has a stale enr-seq.
    local_enr: ?[]const u8 = null,
    /// Sequence number of our local ENR.
    local_enr_seq: u64 = 0,
    /// Time after which outbound requests are considered failed and removed.
    request_timeout_ms: u64 = 1_000,
    /// Time a replacement node waits before evicting the stalest disconnected bucket entry.
    bucket_pending_timeout_ms: u64 = kbucket.BUCKET_PENDING_TIMEOUT_MS,
};

/// Per-IP rate-limit state for outgoing WHOAREYOU packets.
const WhoareyouRateEntry = struct {
    count: u32,
    window_start_ns: i128,
};

const NodeRecord = struct {
    pubkey: ?[33]u8,
    addr: Address,
    enr: ?[]u8,

    fn deinit(self: *NodeRecord, alloc: Allocator) void {
        if (self.enr) |enr| alloc.free(enr);
    }
};

pub const Protocol = struct {
    alloc: Allocator,
    io: Io,
    config: Config,
    routing_table: kbucket.RoutingTable,
    sessions: std.AutoHashMap(NodeId, Session),
    pending_requests: std.ArrayListUnmanaged(PendingRequest),
    whoareyou_rate: std.AutoHashMap(AddressKey, WhoareyouRateEntry),
    rng: std.Random.DefaultPrng,
    /// Known static public keys for peers, keyed by node-id.
    /// Required to verify id-nonce signatures in incoming handshakes.
    node_pubkeys: std.AutoHashMap(NodeId, [33]u8),
    node_records: std.AutoHashMap(NodeId, NodeRecord),
    active_requests: std.AutoHashMap(RequestKey, ActiveRequest),
    completed_events: std.ArrayListUnmanaged(Event),

    pub fn init(io: Io, alloc: Allocator, config: Config) !Protocol {
        var seed_bytes: [8]u8 = undefined;
        io.random(&seed_bytes);
        const seed = std.mem.readInt(u64, &seed_bytes, .little);
        return .{
            .alloc = alloc,
            .io = io,
            .config = config,
            .routing_table = kbucket.RoutingTable.init(alloc, config.local_node_id),
            .sessions = std.AutoHashMap(NodeId, Session).init(alloc),
            .pending_requests = .empty,
            .whoareyou_rate = std.AutoHashMap(AddressKey, WhoareyouRateEntry).init(alloc),
            .rng = std.Random.DefaultPrng.init(seed),
            .node_pubkeys = std.AutoHashMap(NodeId, [33]u8).init(alloc),
            .node_records = std.AutoHashMap(NodeId, NodeRecord).init(alloc),
            .active_requests = std.AutoHashMap(RequestKey, ActiveRequest).init(alloc),
            .completed_events = .empty,
        };
    }

    pub fn deinit(self: *Protocol) void {
        for (self.pending_requests.items) |*p| p.deinit();
        self.pending_requests.deinit(self.alloc);
        self.routing_table.deinit();
        self.sessions.deinit();
        self.whoareyou_rate.deinit();
        self.node_pubkeys.deinit();
        var it = self.node_records.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(self.alloc);
        self.node_records.deinit();
        var active_it = self.active_requests.iterator();
        while (active_it.next()) |entry| entry.value_ptr.deinit(self.alloc);
        self.active_requests.deinit();
        for (self.completed_events.items) |*event| event.deinit(self.alloc);
        self.completed_events.deinit(self.alloc);
    }

    /// Prune stale whoareyou_rate entries.
    ///
    /// Entries older than 60 seconds are removed. This prevents the per-IP
    /// rate-limit map from growing unboundedly when the node encounters many
    /// unique IPs over time (e.g., during DHT crawls or amplification attacks).
    ///
    /// Call periodically (e.g., every minute or at slot boundaries).
    pub fn pruneWhoareyouRate(self: *Protocol) void {
        const now_ns: i128 = @intCast(Io.Timestamp.now(self.io, .real).toNanoseconds());
        const max_age_ns: i128 = 60 * std.time.ns_per_s;

        var to_remove: std.ArrayListUnmanaged(AddressKey) = .empty;
        defer to_remove.deinit(self.alloc);

        var it = self.whoareyou_rate.iterator();
        while (it.next()) |entry| {
            if (now_ns - entry.value_ptr.window_start_ns > max_age_ns) {
                to_remove.append(self.alloc, entry.key_ptr.*) catch continue;
            }
        }
        for (to_remove.items) |key| {
            _ = self.whoareyou_rate.remove(key);
        }
    }

    pub fn randomNonce(self: *Protocol) [12]u8 {
        var nonce: [12]u8 = undefined;
        self.rng.random().bytes(&nonce);
        return nonce;
    }

    pub fn randomReqId(self: *Protocol) messages.ReqId {
        var id: messages.ReqId = .{ .bytes = [_]u8{0} ** 8, .len = 4 };
        self.rng.random().bytes(id.bytes[0..4]);
        return id;
    }

    pub fn popEvent(self: *Protocol) ?Event {
        if (self.completed_events.items.len == 0) return null;
        return self.completed_events.orderedRemove(0);
    }

    pub const KnownNode = struct {
        node_id: NodeId,
        pubkey: [33]u8,
        addr: Address,
    };

    pub fn getKnownNode(self: *const Protocol, node_id: *const NodeId) ?KnownNode {
        const record = self.node_records.get(node_id.*) orelse return null;
        const pubkey = record.pubkey orelse return null;
        return .{
            .node_id = node_id.*,
            .pubkey = pubkey,
            .addr = record.addr,
        };
    }

    pub fn hasActiveFindNodeRequest(self: *const Protocol, peer_id: *const NodeId) bool {
        var it = self.active_requests.iterator();
        while (it.next()) |entry| {
            if (!std.mem.eql(u8, &entry.key_ptr.peer_id, peer_id)) continue;
            if (entry.value_ptr.kind == .findnode) return true;
        }
        return false;
    }

    pub fn pruneExpiredState(self: *Protocol) void {
        const now_ns = self.currentTimestampNs();
        self.pruneExpiredActiveRequests(now_ns);
        self.pruneExpiredPendingRequests(now_ns);
        self.routing_table.prunePending(now_ns, self.config.bucket_pending_timeout_ms);
        self.pruneWhoareyouRate();
    }

    pub fn sendPing(
        self: *Protocol,
        dest_node_id: *const NodeId,
        dest_pubkey: *const [33]u8,
        dest_addr: Address,
        enr_seq: u64,
        socket: *const UdpSocket,
    ) !messages.ReqId {
        self.pruneExpiredState();
        const req_id = self.randomReqId();
        const ping = messages.Ping{
            .req_id = req_id,
            .enr_seq = enr_seq,
        };
        const ping_bytes = try ping.encode(self.alloc);
        defer self.alloc.free(ping_bytes);

        const key = RequestKey{
            .peer_id = dest_node_id.*,
            .req_id = ReqIdKey.fromReqId(req_id),
        };
        try self.active_requests.put(key, .{
            .started_at_ns = self.currentTimestampNs(),
            .kind = .{ .ping = {} },
        });
        errdefer {
            if (self.active_requests.fetchRemove(key)) |removed| {
                var value = removed.value;
                value.deinit(self.alloc);
            }
        }

        try self.sendRequest(dest_node_id, dest_pubkey, dest_addr, ping_bytes, socket);
        return req_id;
    }

    pub fn sendFindNode(
        self: *Protocol,
        dest_node_id: *const NodeId,
        dest_pubkey: *const [33]u8,
        dest_addr: Address,
        distances: []const u16,
        socket: *const UdpSocket,
    ) !messages.ReqId {
        self.pruneExpiredState();
        const req_id = self.randomReqId();
        const find_node = messages.FindNode{
            .req_id = req_id,
            .distances = distances,
        };
        const find_node_bytes = try find_node.encode(self.alloc);
        defer self.alloc.free(find_node_bytes);

        const key = RequestKey{
            .peer_id = dest_node_id.*,
            .req_id = ReqIdKey.fromReqId(req_id),
        };
        try self.active_requests.put(key, .{
            .started_at_ns = self.currentTimestampNs(),
            .kind = .{ .findnode = .{} },
        });
        errdefer {
            if (self.active_requests.fetchRemove(key)) |removed| {
                var value = removed.value;
                value.deinit(self.alloc);
            }
        }

        try self.sendRequest(dest_node_id, dest_pubkey, dest_addr, find_node_bytes, socket);
        return req_id;
    }

    pub fn sendTalkRequest(
        self: *Protocol,
        dest_node_id: *const NodeId,
        dest_pubkey: *const [33]u8,
        dest_addr: Address,
        protocol_name: []const u8,
        request: []const u8,
        socket: *const UdpSocket,
    ) !messages.ReqId {
        self.pruneExpiredState();
        const req_id = self.randomReqId();
        const talk_req = messages.TalkReq{
            .req_id = req_id,
            .protocol = protocol_name,
            .request = request,
        };
        const talk_req_bytes = try talk_req.encode(self.alloc);
        defer self.alloc.free(talk_req_bytes);

        const key = RequestKey{
            .peer_id = dest_node_id.*,
            .req_id = ReqIdKey.fromReqId(req_id),
        };
        try self.active_requests.put(key, .{
            .started_at_ns = self.currentTimestampNs(),
            .kind = .{ .talkreq = {} },
        });
        errdefer {
            if (self.active_requests.fetchRemove(key)) |removed| {
                var value = removed.value;
                value.deinit(self.alloc);
            }
        }

        try self.sendRequest(dest_node_id, dest_pubkey, dest_addr, talk_req_bytes, socket);
        return req_id;
    }

    pub fn sendTalkResponse(
        self: *Protocol,
        peer_id: NodeId,
        peer_addr: Address,
        req_id: messages.ReqId,
        response: []const u8,
        socket: *const UdpSocket,
    ) !void {
        const talk_resp = messages.TalkResp{
            .req_id = req_id,
            .response = response,
        };
        const talk_resp_bytes = try talk_resp.encode(self.alloc);
        defer self.alloc.free(talk_resp_bytes);
        try self.sendResponseMessage(peer_id, peer_addr, talk_resp_bytes, socket);
    }

    /// Send a request to a remote node. If we have an established session,
    /// the message is encrypted and sent immediately. Otherwise, we send an
    /// ordinary message (which will likely be challenged with WHOAREYOU) and
    /// store the request as pending so we can re-send it in the handshake.
    pub fn sendRequest(
        self: *Protocol,
        dest_node_id: *const NodeId,
        dest_pubkey: *const [33]u8,
        dest_addr: Address,
        msg_bytes: []const u8,
        socket: *const UdpSocket,
    ) !void {
        if (self.sessions.get(dest_node_id.*)) |s| {
            if (s.state == .established) {
                try self.sendOrdinaryMessage(dest_node_id, &s.initiator_key, dest_addr, msg_bytes, socket);
                return;
            }
        }

        // No established session — send ordinary message and store as pending.
        const nonce = self.randomNonce();
        var masking_iv: [16]u8 = undefined;
        self.rng.random().bytes(&masking_iv);
        const authdata: [32]u8 = self.config.local_node_id;

        // Use a zeroed key for the initial message (will be challenged).
        const zero_key = [_]u8{0} ** 16;

        const header_raw = try buildHeaderRaw(self.alloc, packet.FLAG_MESSAGE, &nonce, &authdata);
        defer self.alloc.free(header_raw);

        const ct = try packet.encryptMessage(
            self.alloc,
            &zero_key,
            &nonce,
            msg_bytes,
            &masking_iv,
            header_raw,
        );
        defer self.alloc.free(ct);

        const pkt = try packet.encode(
            self.alloc,
            &masking_iv,
            dest_node_id,
            packet.FLAG_MESSAGE,
            &nonce,
            &authdata,
            ct,
        );
        defer self.alloc.free(pkt);

        try socket.send(dest_addr, pkt);

        // Store the pending request so handleWhoareyou can find it.
        const pt_copy = try self.alloc.dupe(u8, msg_bytes);
        errdefer self.alloc.free(pt_copy);
        try self.pending_requests.append(self.alloc, .{
            .sent_at_ns = self.currentTimestampNs(),
            .nonce = nonce,
            .dest_node_id = dest_node_id.*,
            .dest_pubkey = dest_pubkey.*,
            .dest_addr = dest_addr,
            .message_plaintext = pt_copy,
            .alloc = self.alloc,
        });
    }

    /// Handle an incoming raw UDP packet
    pub fn handlePacket(
        self: *Protocol,
        raw: []const u8,
        from: Address,
        socket: *const UdpSocket,
    ) !void {
        self.pruneExpiredState();
        // Drop oversized packets before any decoding work (CL-2020-06, spec max = IPv6 min MTU).
        if (raw.len > MAX_PACKET_SIZE) return;

        var parsed = packet.decode(self.alloc, raw, &self.config.local_node_id) catch return;
        defer parsed.deinit();

        switch (parsed.static_header.flag) {
            packet.FLAG_MESSAGE => try self.handleMessage(&parsed, from, socket),
            packet.FLAG_WHOAREYOU => try self.handleWhoareyou(&parsed, from, socket),
            packet.FLAG_HANDSHAKE => try self.handleHandshake(&parsed, from, socket),
            else => {},
        }
    }

    fn handleMessage(
        self: *Protocol,
        parsed: *packet.ParsedPacket,
        from: Address,
        socket: *const UdpSocket,
    ) !void {
        const authdata = parsed.authdata_raw;
        if (authdata.len < 32) return;
        const src_id: NodeId = authdata[0..32].*;

        if (self.sessions.getPtr(src_id)) |s| {
            if (s.state == .established) {
                // Replay protection: drop packets with a nonce we've already processed.
                if (s.seen_nonces.contains(&parsed.static_header.nonce)) return;
                const pt = packet.decryptMessage(
                    self.alloc,
                    &s.recipient_key,
                    &parsed.static_header.nonce,
                    parsed.message_ciphertext,
                    &parsed.masking_iv,
                    parsed.header_raw,
                ) catch {
                    try self.sendWhoareyou(src_id, &parsed.static_header.nonce, from, socket);
                    return;
                };
                defer self.alloc.free(pt);
                // Record nonce only after successful decryption.
                s.seen_nonces.insert(&parsed.static_header.nonce);
                self.markNodeSeen(src_id, from, .connected);
                try self.dispatchMessage(pt, src_id, from, socket);
                return;
            }
        }

        try self.sendWhoareyou(src_id, &parsed.static_header.nonce, from, socket);
    }

    /// Handle a WHOAREYOU challenge from a remote node.
    ///
    /// When we send an ordinary message to a node that has no session with us,
    /// it responds with WHOAREYOU. We respond with a Handshake packet containing:
    ///
    ///   1. `id-signature` over SHA256(prefix || challenge_data || eph_pubkey || dest_node_id)
    ///   2. `eph-pubkey` — an ephemeral secp256k1 public key
    ///   3. Optional ENR if the remote's `enr-seq` field is stale
    ///   4. The original message, encrypted with newly derived session keys
    fn handleWhoareyou(
        self: *Protocol,
        parsed: *packet.ParsedPacket,
        from: Address,
        socket: *const UdpSocket,
    ) !void {
        const authdata = parsed.authdata_raw;
        // WHOAREYOU authdata = id_nonce (16) || enr_seq (8) = 24 bytes
        if (authdata.len < 24) return;

        // The nonce in the WHOAREYOU static header is the nonce of the message
        // packet that triggered the challenge — use it to find our pending request.
        const request_nonce = parsed.static_header.nonce;

        // Look up the pending request by matching the nonce.
        var pending_idx: ?usize = null;
        for (self.pending_requests.items, 0..) |pr, i| {
            if (std.mem.eql(u8, &pr.nonce, &request_nonce)) {
                pending_idx = i;
                break;
            }
        }

        const idx = pending_idx orelse {
            std.log.warn("discv5: WHOAREYOU for unknown nonce, ignoring", .{});
            return;
        };

        // Extract id_nonce and enr_seq from authdata.
        const enr_seq = std.mem.readInt(u64, authdata[16..24], .big);

        // Build challenge_data = masking_iv || static_header || authdata
        // This is the raw header data of the WHOAREYOU packet (before masking).
        // The packet module decodes header_raw as static_header || authdata.
        // challenge_data = packet[0 .. 16 + header_len], but we reconstruct
        // from the parsed components: masking_iv(16) || header_raw.
        const challenge_data_len = 16 + parsed.header_raw.len;
        const challenge_data = try self.alloc.alloc(u8, challenge_data_len);
        defer self.alloc.free(challenge_data);
        @memcpy(challenge_data[0..16], &parsed.masking_iv);
        @memcpy(challenge_data[16..], parsed.header_raw);

        // Retrieve the pending request.
        var pending = self.pending_requests.orderedRemove(idx);
        defer pending.deinit();

        // Generate a valid ephemeral secp256k1 keypair.
        // secp.pubkeyFromSecret calls secp256k1_ec_pubkey_create which rejects keys
        // that are zero or >= curve order. Retry on invalid key (extremely rare).
        var eph_seckey: [32]u8 = undefined;
        const eph_pubkey = blk: {
            var attempt: u8 = 0;
            while (attempt < 32) : (attempt += 1) {
                self.io.random(&eph_seckey);
                if (secp.pubkeyFromSecret(&eph_seckey)) |pk| break :blk pk else |_| {}
            }
            // Unreachable in practice; probability of failure is ~2^{-128} after 32 attempts.
            return error.EphemeralKeyGenFailed;
        };

        // Derive session keys: ECDH(eph_seckey, dest_pubkey) -> HKDF
        // node_id_a = our node_id (initiator), node_id_b = dest_node_id
        const keys = session_mod.deriveKeys(
            &eph_seckey,
            &pending.dest_pubkey,
            &self.config.local_node_id,
            &pending.dest_node_id,
            challenge_data,
        ) catch return;

        // Compute id-nonce signature.
        const id_sig = session_mod.signIdNonce(
            &self.config.local_secret_key,
            challenge_data,
            &eph_pubkey,
            &pending.dest_node_id,
        ) catch return;

        // Build authdata for handshake packet:
        //   authdata-head = src-id (32) || sig-size (1) || eph-key-size (1)
        //   authdata = authdata-head || id-signature (64) || eph-pubkey (33) || [record]
        const sig_size: u8 = 64;
        const eph_key_size: u8 = 33;

        // Determine if we need to include our ENR.
        const include_enr = (enr_seq < self.config.local_enr_seq) and (self.config.local_enr != null);
        const enr_bytes: []const u8 = if (include_enr) self.config.local_enr.? else &[_]u8{};

        const authdata_total: usize = 34 + sig_size + eph_key_size + enr_bytes.len;
        const handshake_authdata = try self.alloc.alloc(u8, authdata_total);
        defer self.alloc.free(handshake_authdata);

        // authdata-head
        @memcpy(handshake_authdata[0..32], &self.config.local_node_id);
        handshake_authdata[32] = sig_size;
        handshake_authdata[33] = eph_key_size;
        // id-signature
        @memcpy(handshake_authdata[34 .. 34 + sig_size], &id_sig);
        // eph-pubkey
        @memcpy(handshake_authdata[34 + sig_size .. 34 + sig_size + eph_key_size], &eph_pubkey);
        // optional ENR
        if (enr_bytes.len > 0) {
            @memcpy(handshake_authdata[34 + sig_size + eph_key_size ..], enr_bytes);
        }

        // Build the header for AES-GCM additional data.
        const nonce = self.randomNonce();
        var masking_iv: [16]u8 = undefined;
        self.rng.random().bytes(&masking_iv);

        const header_raw = try buildHeaderRaw(self.alloc, packet.FLAG_HANDSHAKE, &nonce, handshake_authdata);
        defer self.alloc.free(header_raw);

        // Encrypt the original pending message with the new initiator key.
        const ct = try packet.encryptMessage(
            self.alloc,
            &keys.initiator_key,
            &nonce,
            pending.message_plaintext,
            &masking_iv,
            header_raw,
        );
        defer self.alloc.free(ct);

        // Encode the full handshake packet.
        const handshake_pkt = try packet.encode(
            self.alloc,
            &masking_iv,
            &pending.dest_node_id,
            packet.FLAG_HANDSHAKE,
            &nonce,
            handshake_authdata,
            ct,
        );
        defer self.alloc.free(handshake_pkt);

        // Send the handshake packet.
        try socket.send(from, handshake_pkt);

        // Store the new session.
        try self.sessions.put(pending.dest_node_id, .{
            .node_id = pending.dest_node_id,
            .state = .established,
            .challenge_data = undefined,
            .challenge_data_len = 0,
            .initiator_key = keys.initiator_key,
            .recipient_key = keys.recipient_key,
            .seen_nonces = SeenNonces.init(),
        });
    }

    fn handleHandshake(
        self: *Protocol,
        parsed: *packet.ParsedPacket,
        from: Address,
        socket: *const UdpSocket,
    ) !void {
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

        // Resolve sender's static public key.
        // First check our known-peer map; fall back to an optional ENR in the handshake.
        const sender_pubkey: [33]u8 = blk: {
            if (self.node_pubkeys.get(src_id)) |pk| break :blk pk;
            // Try to extract pubkey from an optional ENR appended to the authdata.
            const enr_offset = 34 + @as(usize, sig_size) + @as(usize, eph_key_size);
            if (authdata.len > enr_offset) {
                const enr_bytes = authdata[enr_offset..];
                var parsed_enr = enr_mod.decode(self.alloc, enr_bytes) catch {
                    std.log.warn("discv5: handshake from unknown peer {any} has invalid ENR, rejecting", .{src_id});
                    return;
                };
                defer parsed_enr.deinit();
                const pk = parsed_enr.pubkey orelse {
                    std.log.warn("discv5: handshake ENR from {any} has no pubkey, rejecting", .{src_id});
                    return;
                };
                // Verify the ENR node-id matches the claimed src_id.
                const derived_id = enr_mod.nodeIdFromCompressedPubkey(&pk);
                if (!std.mem.eql(u8, &derived_id, &src_id)) {
                    std.log.warn("discv5: handshake ENR node-id mismatch, rejecting", .{});
                    return;
                }
                break :blk pk;
            }
            std.log.warn("discv5: handshake from unknown peer {any} with no ENR, rejecting", .{src_id});
            return;
        };

        // Verify id-signature: SHA256("discovery v5 identity proof" || challenge_data || eph_pubkey || local_node_id)
        const id_sig_fixed: *const [64]u8 = id_sig[0..64];
        session_mod.verifyIdSignature(id_sig_fixed, &sender_pubkey, challenge, eph_pk, &self.config.local_node_id) catch {
            std.log.warn("discv5: handshake id-signature verification failed for {any}, rejecting", .{src_id});
            return;
        };

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
        new_session.seen_nonces = SeenNonces.init();
        try self.sessions.put(src_id, new_session);

        const enr_offset = 34 + @as(usize, sig_size) + @as(usize, eph_key_size);
        const maybe_enr = if (authdata.len > enr_offset) authdata[enr_offset..] else null;
        self.storeNodeRecord(src_id, &sender_pubkey, from, maybe_enr);
        self.markNodeSeen(src_id, from, .connected);

        const pt = packet.decryptMessage(
            self.alloc,
            &keys.initiator_key,
            &parsed.static_header.nonce,
            parsed.message_ciphertext,
            &parsed.masking_iv,
            parsed.header_raw,
        ) catch return;
        defer self.alloc.free(pt);

        if (!new_session.seen_nonces.contains(&parsed.static_header.nonce)) {
            new_session.seen_nonces.insert(&parsed.static_header.nonce);
            try self.sessions.put(src_id, new_session);
            try self.dispatchMessage(pt, src_id, from, socket);
        }
    }

    fn sendWhoareyou(
        self: *Protocol,
        src_id: NodeId,
        request_nonce: *const [12]u8,
        dest: Address,
        socket: *const UdpSocket,
    ) !void {
        // Rate-limit WHOAREYOU responses per source IP to prevent amplification (CL-2020-08).
        const now_ns: i128 = @intCast(Io.Timestamp.now(self.io, .real).toNanoseconds());
        const gop = try self.whoareyou_rate.getOrPut(AddressKey.fromAddress(dest));
        if (gop.found_existing) {
            const elapsed_ns = now_ns - gop.value_ptr.window_start_ns;
            if (elapsed_ns < std.time.ns_per_s) {
                if (gop.value_ptr.count >= MAX_WHOAREYOU_PER_SEC) return; // rate-limit hit
                gop.value_ptr.count += 1;
            } else {
                gop.value_ptr.* = .{ .count = 1, .window_start_ns = now_ns };
            }
        } else {
            gop.value_ptr.* = .{ .count = 1, .window_start_ns = now_ns };
        }

        // Evict a session when the table is full (CL-2020-01).
        // Prefer evicting pending (whoareyou_sent) sessions first — they have no
        // established keying material and evicting them is safe. Only fall back to
        // an arbitrary entry if no pending sessions exist.
        if (self.sessions.count() >= MAX_SESSIONS) {
            var evict_key: ?NodeId = null;
            var it = self.sessions.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.state == .whoareyou_sent) {
                    evict_key = entry.key_ptr.*;
                    break;
                }
                if (evict_key == null) {
                    evict_key = entry.key_ptr.*;
                }
            }
            if (evict_key) |k| {
                _ = self.sessions.remove(k);
            }
        }

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

        // Build challenge_data from plaintext components:
        // challenge_data = masking_iv (16) || static_header (23) || authdata (24) = 63 bytes
        // Per spec: challenge_data must be the plaintext bytes, NOT the masked wire bytes.
        const header_raw_cd = try buildHeaderRaw(self.alloc, packet.FLAG_WHOAREYOU, request_nonce, &authdata);
        defer self.alloc.free(header_raw_cd);
        // total plaintext = 16 (masking_iv) + header_raw_cd.len
        const cd_total = 16 + header_raw_cd.len;
        var s = Session{
            .node_id = src_id,
            .state = .whoareyou_sent,
            .challenge_data = undefined,
            .challenge_data_len = @min(cd_total, CHALLENGE_DATA_SIZE),
            .initiator_key = undefined,
            .recipient_key = undefined,
            .seen_nonces = SeenNonces.init(),
        };
        @memcpy(s.challenge_data[0..16], &masking_iv);
        @memcpy(s.challenge_data[16..s.challenge_data_len], header_raw_cd[0 .. s.challenge_data_len - 16]);
        try self.sessions.put(src_id, s);

        try socket.send(dest, whoareyou_packet);
    }

    fn sendOrdinaryMessage(
        self: *Protocol,
        dest_node_id: *const NodeId,
        write_key: *const [16]u8,
        dest_addr: Address,
        msg_bytes: []const u8,
        socket: *const UdpSocket,
    ) !void {
        const nonce = self.randomNonce();
        var masking_iv: [16]u8 = undefined;
        self.rng.random().bytes(&masking_iv);
        const authdata: [32]u8 = self.config.local_node_id;

        const header_raw = try buildHeaderRaw(self.alloc, packet.FLAG_MESSAGE, &nonce, &authdata);
        defer self.alloc.free(header_raw);

        const ct = try packet.encryptMessage(
            self.alloc,
            write_key,
            &nonce,
            msg_bytes,
            &masking_iv,
            header_raw,
        );
        defer self.alloc.free(ct);

        const pkt = try packet.encode(
            self.alloc,
            &masking_iv,
            dest_node_id,
            packet.FLAG_MESSAGE,
            &nonce,
            &authdata,
            ct,
        );
        defer self.alloc.free(pkt);

        try socket.send(dest_addr, pkt);
    }

    fn storeNodeRecord(self: *Protocol, node_id: NodeId, pubkey: ?*const [33]u8, addr: Address, enr: ?[]const u8) void {
        const existing = self.node_records.get(node_id);
        var enr_copy = if (enr) |raw| self.alloc.dupe(u8, raw) catch return else null;
        errdefer if (enr_copy) |bytes| self.alloc.free(bytes);

        var effective_addr = addr;
        var keep_existing_enr = false;
        if (enr_copy) |incoming_enr| {
            if (existing) |record| {
                if (record.enr) |current_enr| {
                    var incoming = enr_mod.decode(self.alloc, incoming_enr) catch null;
                    defer if (incoming) |*parsed| parsed.deinit();
                    var current = enr_mod.decode(self.alloc, current_enr) catch null;
                    defer if (current) |*parsed| parsed.deinit();

                    if (incoming != null and current != null and incoming.?.seq <= current.?.seq) {
                        self.alloc.free(incoming_enr);
                        enr_copy = null;
                        keep_existing_enr = true;
                        effective_addr = record.addr;
                    }
                }
            }
        }

        if (pubkey) |pk| {
            self.node_pubkeys.put(node_id, pk.*) catch {};
        } else if (existing) |record| {
            if (record.pubkey) |known| {
                self.node_pubkeys.put(node_id, known) catch {};
            }
        }

        const merged = NodeRecord{
            .pubkey = if (pubkey) |pk| pk.* else if (existing) |record| record.pubkey else null,
            .addr = effective_addr,
            .enr = if (enr_copy != null)
                enr_copy
            else if (keep_existing_enr)
                if (existing) |record| record.enr else null
            else if (existing) |record|
                record.enr
            else
                null,
        };

        if (self.node_records.getPtr(node_id)) |record| {
            if (enr_copy != null) {
                if (record.enr) |old| self.alloc.free(old);
            }
            record.* = merged;
        } else {
            self.node_records.put(node_id, merged) catch {
                if (enr_copy) |bytes| self.alloc.free(bytes);
            };
        }
    }

    fn appendFindNodeEnr(self: *Protocol, records: *std.ArrayListUnmanaged([]const u8), node_id: NodeId) void {
        if (self.node_records.get(node_id)) |record| {
            if (record.enr) |enr| {
                records.append(self.alloc, enr) catch {};
            }
        }
    }

    fn activeRequestKey(peer_id: NodeId, req_id: messages.ReqId) RequestKey {
        return .{
            .peer_id = peer_id,
            .req_id = ReqIdKey.fromReqId(req_id),
        };
    }

    fn requestTimedOut(self: *const Protocol, started_at_ns: i64, now_ns: i64) bool {
        const elapsed_ns: i128 = @as(i128, now_ns) - @as(i128, started_at_ns);
        const timeout_ns: i128 = @as(i128, self.config.request_timeout_ms) * std.time.ns_per_ms;
        return elapsed_ns >= timeout_ns;
    }

    fn pruneExpiredActiveRequests(self: *Protocol, now_ns: i64) void {
        var expired: std.ArrayListUnmanaged(RequestKey) = .empty;
        defer expired.deinit(self.alloc);

        var it = self.active_requests.iterator();
        while (it.next()) |entry| {
            if (!self.requestTimedOut(entry.value_ptr.started_at_ns, now_ns)) continue;
            expired.append(self.alloc, entry.key_ptr.*) catch return;
        }

        for (expired.items) |key| {
            const removed = self.active_requests.fetchRemove(key) orelse continue;
            var request = removed.value;
            self.completed_events.append(self.alloc, .{
                .request_timeout = .{
                    .peer_id = key.peer_id,
                    .req_id = key.req_id.toReqId(),
                    .kind = request.requestKind(),
                },
            }) catch {};
            request.deinit(self.alloc);
        }
    }

    fn pruneExpiredPendingRequests(self: *Protocol, now_ns: i64) void {
        var i: usize = 0;
        while (i < self.pending_requests.items.len) {
            if (!self.requestTimedOut(self.pending_requests.items[i].sent_at_ns, now_ns)) {
                i += 1;
                continue;
            }

            var pending = self.pending_requests.orderedRemove(i);
            pending.deinit();
        }
    }

    fn currentTimestampNs(self: *const Protocol) i64 {
        return @intCast(Io.Timestamp.now(self.io, .real).toNanoseconds());
    }

    fn markNodeSeen(self: *Protocol, node_id: NodeId, addr: Address, status: kbucket.EntryStatus) void {
        const entry = kbucket.Entry{
            .node_id = node_id,
            .addr = addr,
            .last_seen = self.currentTimestampNs(),
            .status = status,
        };
        _ = self.routing_table.insert(entry);
    }

    fn rememberEnr(self: *Protocol, enr_bytes: []const u8) void {
        var parsed_enr = enr_mod.decode(self.alloc, enr_bytes) catch return;
        defer parsed_enr.deinit();

        const node_id = parsed_enr.nodeId() orelse return;
        if (std.mem.eql(u8, &node_id, &self.config.local_node_id)) return;

        const pubkey = parsed_enr.pubkey;
        const addr = if (parsed_enr.ip) |ip|
            if (parsed_enr.udp orelse parsed_enr.tcp) |port|
                Address{ .ip4 = .{ .bytes = ip, .port = port } }
            else if (parsed_enr.ip6) |ip6|
                if (parsed_enr.udp6) |port6|
                    Address{ .ip6 = .{ .bytes = ip6, .port = port6 } }
                else
                    return
            else
                return
        else if (parsed_enr.ip6) |ip6|
            if (parsed_enr.udp6) |port6|
                Address{ .ip6 = .{ .bytes = ip6, .port = port6 } }
            else
                return
        else
            return;

        self.storeNodeRecord(node_id, if (pubkey) |*pk| pk else null, addr, enr_bytes);
        self.markNodeSeen(node_id, addr, .disconnected);
    }

    fn sendResponseMessage(
        self: *Protocol,
        peer_id: NodeId,
        peer_addr: Address,
        plaintext: []const u8,
        socket: *const UdpSocket,
    ) !void {
        const s = self.sessions.get(peer_id) orelse return;
        try self.sendOrdinaryMessage(&peer_id, &s.initiator_key, peer_addr, plaintext, socket);
    }

    fn dispatchMessage(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const UdpSocket,
    ) !void {
        if (pt.len == 0) return;
        switch (pt[0]) {
            messages.MSG_PING => try self.handlePing(pt, from, from_addr, socket),
            messages.MSG_PONG => self.handlePong(pt, from, from_addr),
            messages.MSG_FINDNODE => try self.handleFindNode(pt, from, from_addr, socket),
            messages.MSG_NODES => self.handleNodes(pt, from, from_addr),
            messages.MSG_TALKREQ => self.handleTalkReq(pt, from, from_addr),
            messages.MSG_TALKRESP => self.handleTalkResp(pt, from, from_addr),
            else => {},
        }
    }

    fn handlePing(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const UdpSocket,
    ) !void {
        const ping = messages.Ping.decode(pt) catch return;

        const pong = messages.Pong{
            .req_id = ping.req_id,
            .enr_seq = self.config.local_enr_seq,
            .recipient_ip = switch (from_addr) {
                .ip4 => |ip4| .{ .ip4 = ip4.bytes },
                .ip6 => |ip6| .{ .ip6 = ip6.bytes },
            },
            .recipient_port = from_addr.getPort(),
        };

        const pong_bytes = try pong.encode(self.alloc);
        defer self.alloc.free(pong_bytes);
        try self.sendResponseMessage(from, from_addr, pong_bytes, socket);
    }

    fn handlePong(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
    ) void {
        const pong = messages.Pong.decode(pt) catch return;
        const key = activeRequestKey(from, pong.req_id);
        const removed = self.active_requests.fetchRemove(key) orelse return;
        var request = removed.value;
        defer request.deinit(self.alloc);
        if (request.kind != .ping) return;

        self.markNodeSeen(from, from_addr, .connected);
        self.completed_events.append(self.alloc, .{
            .pong = .{
                .peer_id = from,
                .peer_addr = from_addr,
                .req_id = pong.req_id,
                .enr_seq = pong.enr_seq,
                .recipient_ip = pong.recipient_ip,
                .recipient_port = pong.recipient_port,
            },
        }) catch {};
    }

    fn handleFindNode(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const UdpSocket,
    ) !void {
        const result = messages.FindNode.decode(self.alloc, pt) catch return;
        defer self.alloc.free(result.distances);

        const fn_msg = result.msg;

        var enr_refs: std.ArrayListUnmanaged([]const u8) = .empty;
        defer enr_refs.deinit(self.alloc);
        for (fn_msg.distances) |dist| {
            if (dist == 0) {
                if (self.config.local_enr) |local_enr| {
                    enr_refs.append(self.alloc, local_enr) catch {};
                }
                continue;
            }
            if (dist > 256) continue;
            const entries = self.routing_table.getBucket(@intCast(dist - 1));
            for (entries) |entry| {
                self.appendFindNodeEnr(&enr_refs, entry.node_id);
            }
        }

        const total_chunks: u64 = @max(@as(u64, @intCast(std.math.divCeil(usize, enr_refs.items.len, MAX_NODES_RESPONSE) catch 0)), 1);
        var chunk_index: usize = 0;
        while (chunk_index < total_chunks) : (chunk_index += 1) {
            const start = chunk_index * MAX_NODES_RESPONSE;
            const end = @min(start + MAX_NODES_RESPONSE, enr_refs.items.len);
            const nodes_msg = messages.Nodes{
                .req_id = fn_msg.req_id,
                .total = total_chunks,
                .enrs = enr_refs.items[start..end],
            };
            const nodes_bytes = try nodes_msg.encode(self.alloc);
            defer self.alloc.free(nodes_bytes);
            try self.sendResponseMessage(from, from_addr, nodes_bytes, socket);
        }
    }

    fn handleNodes(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
    ) void {
        const decoded = messages.Nodes.decode(self.alloc, pt) catch return;
        defer {
            for (decoded.enrs) |enr| self.alloc.free(enr);
            self.alloc.free(decoded.enrs);
        }

        if (decoded.msg.total == 0) return;

        const key = activeRequestKey(from, decoded.msg.req_id);
        const request = self.active_requests.getPtr(key) orelse return;
        if (request.kind != .findnode) return;

        var findnode = &request.kind.findnode;
        if (findnode.total_responses == null) {
            findnode.total_responses = decoded.msg.total;
        } else if (findnode.total_responses.? != decoded.msg.total) {
            return;
        }

        for (decoded.enrs) |enr| {
            self.rememberEnr(enr);
            findnode.enrs.append(self.alloc, self.alloc.dupe(u8, enr) catch continue) catch {};
        }
        findnode.responses_received += 1;
        self.markNodeSeen(from, from_addr, .connected);

        if (findnode.responses_received < findnode.total_responses.?) return;

        const removed = self.active_requests.fetchRemove(key) orelse return;
        var completed = removed.value;
        defer completed.deinit(self.alloc);
        if (completed.kind != .findnode) return;

        const owned_enrs = completed.kind.findnode.enrs.toOwnedSlice(self.alloc) catch return;
        completed.kind.findnode.enrs = .empty;
        self.completed_events.append(self.alloc, .{
            .nodes = .{
                .peer_id = from,
                .peer_addr = from_addr,
                .req_id = decoded.msg.req_id,
                .enrs = owned_enrs,
            },
        }) catch {
            for (owned_enrs) |enr| self.alloc.free(enr);
            self.alloc.free(owned_enrs);
        };
    }

    fn handleTalkReq(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
    ) void {
        const talk_req = messages.TalkReq.decode(pt) catch return;
        const protocol_name = self.alloc.dupe(u8, talk_req.protocol) catch return;
        const request = self.alloc.dupe(u8, talk_req.request) catch {
            self.alloc.free(protocol_name);
            return;
        };

        self.markNodeSeen(from, from_addr, .connected);
        self.completed_events.append(self.alloc, .{
            .talkreq = .{
                .peer_id = from,
                .peer_addr = from_addr,
                .req_id = talk_req.req_id,
                .protocol = protocol_name,
                .request = request,
            },
        }) catch {
            self.alloc.free(protocol_name);
            self.alloc.free(request);
        };
    }

    fn handleTalkResp(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
    ) void {
        const talk_resp = messages.TalkResp.decode(pt) catch return;
        const key = activeRequestKey(from, talk_resp.req_id);
        const removed = self.active_requests.fetchRemove(key) orelse return;
        var request = removed.value;
        defer request.deinit(self.alloc);
        if (request.kind != .talkreq) return;

        const response = self.alloc.dupe(u8, talk_resp.response) catch return;

        self.markNodeSeen(from, from_addr, .connected);
        self.completed_events.append(self.alloc, .{
            .talkresp = .{
                .peer_id = from,
                .peer_addr = from_addr,
                .req_id = talk_resp.req_id,
                .response = response,
            },
        }) catch self.alloc.free(response);
    }

    pub fn addNode(self: *Protocol, node_id: NodeId, pubkey: ?*const [33]u8, addr: Address, enr: ?[]const u8) void {
        self.storeNodeRecord(node_id, pubkey, addr, enr);
        self.markNodeSeen(node_id, addr, .disconnected);
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
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk = try secp.pubkeyFromSecret(&sk);
    const node_id = @import("enr.zig").nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_secret_key = sk,
        .local_node_id = node_id,
    });
    defer proto.deinit();

    try std.testing.expectEqual(@as(usize, 0), proto.routing_table.nodeCount());

    var node_id2: NodeId = [_]u8{0xbb} ** 32;
    node_id2[31] = 0x01;
    proto.addNode(node_id2, null, .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 30303 } }, null);
    try std.testing.expectEqual(@as(usize, 1), proto.routing_table.nodeCount());
}

test "discv5 protocol: WHOAREYOU handshake round-trip" {
    // Simulate: node A sends request -> node B responds WHOAREYOU -> node A
    //           builds handshake -> node B receives and establishes session.
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

    // Node A keys
    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_a = try secp.pubkeyFromSecret(&sk_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    // Node B keys
    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const pk_b = try secp.pubkeyFromSecret(&sk_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var socket_a = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close();
    var socket_b = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close();

    const addr_a = socket_a.address;
    const addr_b = socket_b.address;

    // Set up node A's protocol
    var proto_a = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_a,
        .local_node_id = node_id_a,
    });
    defer proto_a.deinit();

    // Set up node B's protocol
    var proto_b = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_b,
        .local_node_id = node_id_b,
    });
    defer proto_b.deinit();
    // Pre-register node A's static pubkey so B can verify A's id-nonce signature.
    proto_b.addNode(node_id_a, &pk_a, addr_a, null);

    // Step 1: Node A sends a PING to node B (no session exists).
    const ping = messages.Ping{
        .req_id = try messages.ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x01 }),
        .enr_seq = 1,
    };
    const ping_bytes = try ping.encode(alloc);
    defer alloc.free(ping_bytes);

    try proto_a.sendRequest(&node_id_b, &pk_b, addr_b, ping_bytes, &socket_a);

    // Verify node A sent one packet and stored a pending request.
    try std.testing.expectEqual(@as(usize, 1), proto_a.pending_requests.items.len);

    // Step 2: Node B receives the packet. Since no session exists, it responds
    // with WHOAREYOU.
    var recv_buf_b: [MAX_PACKET_SIZE]u8 = undefined;
    const inbound_a = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    // Node B should now have a session in whoareyou_sent state.
    const session_b = proto_b.sessions.get(node_id_a) orelse return error.NoSession;
    try std.testing.expectEqual(SessionState.whoareyou_sent, session_b.state);

    // Step 3: Node A receives the WHOAREYOU and responds with a handshake.
    var recv_buf_a: [MAX_PACKET_SIZE]u8 = undefined;
    const inbound_b = try socket_a.receiveTimeout(&recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound_b.data, inbound_b.from, &socket_a);

    // Node A should now have an established session.
    const session_a = proto_a.sessions.get(node_id_b) orelse return error.NoSession;
    try std.testing.expectEqual(SessionState.established, session_a.state);

    // The pending request should be consumed.
    try std.testing.expectEqual(@as(usize, 0), proto_a.pending_requests.items.len);

    // Step 4: Node B receives the handshake.
    const handshake = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    // Node B should now have an established session.
    const session_b2 = proto_b.sessions.get(node_id_a) orelse return error.NoSession;
    try std.testing.expectEqual(SessionState.established, session_b2.state);

    // Step 5: Node A receives B's post-handshake PONG.
    const pong_packet = try socket_a.receiveTimeout(&recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    var parsed_pong = try packet.decode(alloc, pong_packet.data, &node_id_a);
    defer parsed_pong.deinit();
    const pong_plaintext = try packet.decryptMessage(
        alloc,
        &session_a.recipient_key,
        &parsed_pong.static_header.nonce,
        parsed_pong.message_ciphertext,
        &parsed_pong.masking_iv,
        parsed_pong.header_raw,
    );
    defer alloc.free(pong_plaintext);
    const pong = try messages.Pong.decode(pong_plaintext);
    try std.testing.expectEqualSlices(u8, ping.req_id.slice(), pong.req_id.slice());
    try std.testing.expectEqual(addr_a.getPort(), pong.recipient_port);
    switch (addr_a) {
        .ip4 => |ip4| try std.testing.expectEqualDeep(messages.Pong.RecipientIp{ .ip4 = ip4.bytes }, pong.recipient_ip),
        .ip6 => |ip6| try std.testing.expectEqualDeep(messages.Pong.RecipientIp{ .ip6 = ip6.bytes }, pong.recipient_ip),
    }
}

test "discv5 protocol: FINDNODE assembles a completed NODES event" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_a = try secp.pubkeyFromSecret(&sk_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const pk_b = try secp.pubkeyFromSecret(&sk_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    const sk_c = hex.hexToBytesComptime(32, "7e8107fe766b7f1821c3a7fbc56d18f734f0ebf898f0b85f82412b6d1fa7f4d3");
    const pk_c = try secp.pubkeyFromSecret(&sk_c);
    const node_id_c = enr_mod.nodeIdFromCompressedPubkey(&pk_c);

    var socket_a = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close();
    var socket_b = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close();

    const addr_a = socket_a.address;
    const addr_b = socket_b.address;
    const addr_c = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30305 } };

    var a_builder = enr_mod.Builder.init(alloc, sk_a, 1);
    a_builder.ip = switch (addr_a) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => unreachable,
    };
    a_builder.udp = addr_a.getPort();
    const a_enr = try a_builder.encode();
    defer alloc.free(a_enr);

    var b_builder = enr_mod.Builder.init(alloc, sk_b, 1);
    b_builder.ip = switch (addr_b) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => unreachable,
    };
    b_builder.udp = addr_b.getPort();
    const b_enr = try b_builder.encode();
    defer alloc.free(b_enr);

    var c_builder = enr_mod.Builder.init(alloc, sk_c, 1);
    c_builder.ip = switch (addr_c) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => unreachable,
    };
    c_builder.udp = addr_c.getPort();
    const c_enr = try c_builder.encode();
    defer alloc.free(c_enr);

    var proto_a = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_a,
        .local_node_id = node_id_a,
        .local_enr = a_enr,
        .local_enr_seq = 1,
    });
    defer proto_a.deinit();

    var proto_b = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_b,
        .local_node_id = node_id_b,
        .local_enr = b_enr,
        .local_enr_seq = 1,
    });
    defer proto_b.deinit();

    proto_a.addNode(node_id_b, &pk_b, addr_b, b_enr);
    proto_b.addNode(node_id_a, &pk_a, addr_a, a_enr);
    proto_b.addNode(node_id_c, &pk_c, addr_c, c_enr);

    const c_distance = kbucket.logDistance(&node_id_b, &node_id_c) orelse return error.NoDistance;
    const distances = [_]u16{ 0, @as(u16, c_distance) + 1 };
    _ = try proto_a.sendFindNode(&node_id_b, &pk_b, addr_b, &distances, &socket_a);

    var recv_buf_a: [MAX_PACKET_SIZE]u8 = undefined;
    var recv_buf_b: [MAX_PACKET_SIZE]u8 = undefined;

    const inbound_a = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    const inbound_b = try socket_a.receiveTimeout(&recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound_b.data, inbound_b.from, &socket_a);

    const handshake = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    const nodes_packet = try socket_a.receiveTimeout(&recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(nodes_packet.data, nodes_packet.from, &socket_a);

    try std.testing.expectEqual(@as(usize, 0), proto_a.active_requests.count());

    var event = proto_a.popEvent() orelse return error.MissingNodesEvent;
    defer event.deinit(alloc);
    try std.testing.expect(event == .nodes);
    try std.testing.expectEqual(node_id_b, event.nodes.peer_id);
    try std.testing.expectEqual(@as(usize, 2), event.nodes.enrs.len);

    var saw_b = false;
    var saw_c = false;
    for (event.nodes.enrs) |raw_enr| {
        var parsed = try enr_mod.decode(alloc, raw_enr);
        defer parsed.deinit();
        const node_id = parsed.nodeId() orelse continue;
        if (std.mem.eql(u8, &node_id, &node_id_b)) saw_b = true;
        if (std.mem.eql(u8, &node_id, &node_id_c)) saw_c = true;
    }
    try std.testing.expect(saw_b);
    try std.testing.expect(saw_c);
}

test "discv5 protocol: TALKREQ/TALKRESP round-trip produces events" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_a = try secp.pubkeyFromSecret(&sk_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const pk_b = try secp.pubkeyFromSecret(&sk_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var socket_a = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close();
    var socket_b = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close();

    const addr_a = socket_a.address;
    const addr_b = socket_b.address;

    var proto_a = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_a,
        .local_node_id = node_id_a,
    });
    defer proto_a.deinit();

    var proto_b = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_b,
        .local_node_id = node_id_b,
    });
    defer proto_b.deinit();

    proto_a.addNode(node_id_b, &pk_b, addr_b, null);
    proto_b.addNode(node_id_a, &pk_a, addr_a, null);

    const req_id = try proto_a.sendTalkRequest(
        &node_id_b,
        &pk_b,
        addr_b,
        "/eth2/test",
        "ping",
        &socket_a,
    );

    var recv_buf_a: [MAX_PACKET_SIZE]u8 = undefined;
    var recv_buf_b: [MAX_PACKET_SIZE]u8 = undefined;

    const inbound_a = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    const inbound_b = try socket_a.receiveTimeout(&recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound_b.data, inbound_b.from, &socket_a);

    const handshake = try socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    var request_event = proto_b.popEvent() orelse return error.MissingTalkReqEvent;
    defer request_event.deinit(alloc);
    try std.testing.expect(request_event == .talkreq);
    try std.testing.expectEqual(node_id_a, request_event.talkreq.peer_id);
    try std.testing.expectEqualSlices(u8, req_id.slice(), request_event.talkreq.req_id.slice());
    try std.testing.expectEqualStrings("/eth2/test", request_event.talkreq.protocol);
    try std.testing.expectEqualStrings("ping", request_event.talkreq.request);

    try proto_b.sendTalkResponse(
        request_event.talkreq.peer_id,
        request_event.talkreq.peer_addr,
        request_event.talkreq.req_id,
        "pong",
        &socket_b,
    );

    const response_packet = try socket_a.receiveTimeout(&recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(response_packet.data, response_packet.from, &socket_a);

    var response_event = proto_a.popEvent() orelse return error.MissingTalkRespEvent;
    defer response_event.deinit(alloc);
    try std.testing.expect(response_event == .talkresp);
    try std.testing.expectEqual(node_id_b, response_event.talkresp.peer_id);
    try std.testing.expectEqualSlices(u8, req_id.slice(), response_event.talkresp.req_id.slice());
    try std.testing.expectEqualStrings("pong", response_event.talkresp.response);
}

test "discv5 protocol: request timeout prunes active and pending state" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_a = try secp.pubkeyFromSecret(&sk_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const pk_b = try secp.pubkeyFromSecret(&sk_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var socket_a = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close();

    var proto_a = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_a,
        .local_node_id = node_id_a,
        .request_timeout_ms = 1,
    });
    defer proto_a.deinit();

    const addr_b = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } };
    proto_a.addNode(node_id_b, &pk_b, addr_b, null);

    const req_id = try proto_a.sendPing(&node_id_b, &pk_b, addr_b, 1, &socket_a);
    try std.testing.expectEqual(@as(usize, 1), proto_a.active_requests.count());
    try std.testing.expectEqual(@as(usize, 1), proto_a.pending_requests.items.len);

    var active_it = proto_a.active_requests.iterator();
    while (active_it.next()) |entry| {
        entry.value_ptr.started_at_ns = 0;
    }
    for (proto_a.pending_requests.items) |*pending| {
        pending.sent_at_ns = 0;
    }

    proto_a.pruneExpiredState();

    try std.testing.expectEqual(@as(usize, 0), proto_a.active_requests.count());
    try std.testing.expectEqual(@as(usize, 0), proto_a.pending_requests.items.len);

    var event = proto_a.popEvent() orelse return error.MissingTimeoutEvent;
    defer event.deinit(alloc);
    try std.testing.expect(event == .request_timeout);
    try std.testing.expectEqual(node_id_b, event.request_timeout.peer_id);
    try std.testing.expectEqualSlices(u8, req_id.slice(), event.request_timeout.req_id.slice());
    try std.testing.expectEqual(RequestKind.ping, event.request_timeout.kind);
}

test "discv5 protocol: unsolicited WHOAREYOU is ignored" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex.zig");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_a = try secp.pubkeyFromSecret(&sk_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    var socket_a = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close();
    var socket_b = try UdpSocket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close();

    const addr_a = socket_a.address;

    var proto_a = try Protocol.init(io, alloc, .{
        .local_secret_key = sk_a,
        .local_node_id = node_id_a,
    });
    defer proto_a.deinit();

    var request_nonce: [12]u8 = [_]u8{0x42} ** 12;
    var id_nonce: [16]u8 = [_]u8{0x24} ** 16;
    var authdata: [24]u8 = undefined;
    @memcpy(authdata[0..16], &id_nonce);
    std.mem.writeInt(u64, authdata[16..24], 0, .big);
    var masking_iv: [16]u8 = [_]u8{0x11} ** 16;

    const whoareyou = try packet.encode(
        alloc,
        &masking_iv,
        &node_id_a,
        packet.FLAG_WHOAREYOU,
        &request_nonce,
        &authdata,
        &[_]u8{},
    );
    defer alloc.free(whoareyou);

    try socket_b.send(addr_a, whoareyou);

    var recv_buf_a: [MAX_PACKET_SIZE]u8 = undefined;
    const inbound = try socket_a.receiveTimeout(&recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound.data, inbound.from, &socket_a);

    try std.testing.expectEqual(@as(usize, 0), proto_a.pending_requests.items.len);
    try std.testing.expectEqual(@as(usize, 0), proto_a.active_requests.count());
    try std.testing.expectEqual(@as(usize, 0), proto_a.sessions.count());
    try std.testing.expect(proto_a.popEvent() == null);

    var recv_buf_b: [MAX_PACKET_SIZE]u8 = undefined;
    try std.testing.expectError(error.Timeout, socket_b.receiveTimeout(&recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(50),
            .clock = .awake,
        },
    }));
}
