//! Discovery v5 protocol handler

const std = @import("std");
const scoped_log = std.log.scoped(.discv5_protocol);
const Allocator = std.mem.Allocator;
const NodeId = @import("enr.zig").NodeId;
const kbucket = @import("kbucket.zig");
const packet = @import("protocol/packet.zig");
const session_mod = @import("protocol/session.zig");
const messages = @import("protocol/message.zig");
const metrics_mod = @import("metrics.zig");
const secp = @import("secp256k1.zig");
const protocol_events = @import("protocol/events.zig");
const request_tracker = @import("protocol/request_tracker.zig");
const protocol_state = @import("protocol/state.zig");
const event_queue_mod = @import("event_queue.zig");
const session_store_mod = @import("protocol/session_store.zig");
const contact_book_mod = @import("protocol/contact_book.zig");
const handshake_mod = @import("protocol/handshake.zig");
const util = @import("util.zig");
const Io = std.Io;
const net = Io.net;
const Address = net.IpAddress;
const enr_mod = @import("enr.zig");

const bindDatagramSocket = util.bindDatagramSocket;
const shortNodeId = util.shortNodeId;

pub const CHALLENGE_DATA_SIZE = packet.WHOAREYOU_CHALLENGE_DATA_SIZE;
pub const SEEN_NONCES_CAP: usize = protocol_state.SEEN_NONCES_CAP;
pub const SeenNonces = protocol_state.SeenNonces;
pub const SessionRecord = protocol_state.SessionRecord;
pub const ActiveChallenge = protocol_state.ActiveChallenge;
pub const RequestKind = request_tracker.RequestKind;
pub const RequestTracker = request_tracker.RequestTracker;
pub const PongEvent = protocol_events.PongEvent;
pub const NodesEvent = protocol_events.NodesEvent;
pub const TalkReqEvent = protocol_events.TalkReqEvent;
pub const TalkRespEvent = protocol_events.TalkRespEvent;
pub const RequestTimeoutEvent = protocol_events.RequestTimeoutEvent;
pub const Event = protocol_events.Event;

const ActiveFindNodeRequest = request_tracker.ActiveFindNodeRequest;
const ContactBook = contact_book_mod.ContactBook;
const Endpoint = request_tracker.Endpoint;
const PendingSessionKeys = protocol_state.PendingSessionKeys;
const ExpiredRequest = request_tracker.ExpiredRequest;
const SessionStore = session_store_mod.SessionStore;

/// Maximum packet size per discv5 spec (IPv6 minimum MTU).
/// Packets larger than this are dropped to prevent amplification (CL-2020-06).
pub const MAX_PACKET_SIZE: usize = packet.MAX_PACKET_SIZE;

/// Maximum number of concurrent sessions. Bounded to prevent memory exhaustion (CL-2020-01).
pub const MAX_SESSIONS: u32 = 2_000;

/// Maximum WHOAREYOU packets sent per source IP per second.
/// Limits amplification when an attacker floods us with garbage from spoofed IPs (CL-2020-08).
pub const MAX_WHOAREYOU_PER_SEC: u32 = 5;

/// Maximum ENRs returned in a single NODES response per the discv5 spec.
pub const MAX_NODES_RESPONSE: usize = 16;
const MAX_NODES_ENRS_PER_PACKET: usize = @max((MAX_PACKET_SIZE - 92) / enr_mod.MAX_ENR_SIZE, 1);
const MAX_NODES_RESPONSE_CHUNKS: usize = std.math.divCeil(usize, MAX_NODES_RESPONSE, MAX_NODES_ENRS_PER_PACKET) catch unreachable;
const SMALL_MESSAGE_BUFFER_SIZE: usize = 128;
const FINDNODE_MESSAGE_BUFFER_SIZE: usize = 512;
const MAX_HANDSHAKE_AUTHDATA_SIZE: usize = 34 + 64 + 33 + enr_mod.MAX_ENR_SIZE;

pub const Config = struct {
    local_key_pair: secp.KeyPair,
    local_node_id: NodeId,
    /// Pre-encoded local ENR (RLP bytes). Included in handshake when remote
    /// has a stale enr-seq.
    local_enr: ?[]const u8 = null,
    /// Sequence number of our local ENR.
    local_enr_seq: u64 = 0,
    /// Time after which outbound requests are considered failed and removed.
    request_timeout_ms: u64 = 1_000,
    /// Number of retry intervals before a request is failed.
    request_retries: u32 = 1,
    /// Maximum number of on-wire requests retained for retry/response matching.
    max_active_requests: usize = 1024,
    /// Maximum number of queued requests waiting behind session establishment.
    max_queued_requests: usize = 1024,
    /// Maximum queued requests for a single peer endpoint.
    max_queued_requests_per_endpoint: usize = 16,
    /// Maximum number of established sessions retained in the TTL/LRU cache.
    session_cache_capacity: u32 = MAX_SESSIONS,
    /// Time an established session remains in the TTL/LRU cache.
    session_timeout_ms: u64 = 86_400_000,
    /// Maximum number of active WHOAREYOU challenges retained for incoming handshakes.
    challenge_cache_capacity: usize = 1_024,
    /// Time a WHOAREYOU challenge remains usable for an incoming handshake.
    /// TS keeps active challenges for requestTimeout * 2 by default.
    challenge_timeout_ms: u64 = 2_000,
    /// Maximum distinct source IPs retained by the WHOAREYOU rate limiter.
    whoareyou_rate_capacity: usize = 4_096,
    /// Time source IP rate-limit state remains live after its most recent attempt.
    whoareyou_rate_ttl_ms: u64 = 60_000,
    /// Permit sessions from peers without a verified ENR/static key. Defaults to TS behavior.
    allow_unverified_sessions: bool = false,
    /// Time a replacement node waits before evicting the stalest disconnected bucket entry.
    bucket_pending_timeout_ms: u64 = kbucket.BUCKET_PENDING_TIMEOUT_MS,
};

pub const Protocol = struct {
    alloc: Allocator,
    io: Io,
    config: Config,
    routing_table: kbucket.RoutingTable,
    session_store: SessionStore,
    requests: RequestTracker,
    /// Peers with enough identity/contact information to send handshakes, but
    /// without a verified ENR suitable for the routing table.
    contacts: ContactBook,
    event_queue: event_queue_mod.EventQueue(Event) = .{},
    metrics: metrics_mod.ProtocolMetrics = .{},

    pub fn init(io: Io, alloc: Allocator, config: Config) !Protocol {
        if (config.session_cache_capacity == 0 or config.session_cache_capacity > MAX_SESSIONS) {
            return error.InvalidSessionCacheCapacity;
        }

        var routing_table = try kbucket.RoutingTable.init(alloc, config.local_node_id);
        errdefer routing_table.deinit(alloc);
        var session_store = try SessionStore.init(alloc, .{
            .session_cache_capacity = config.session_cache_capacity,
            .session_timeout_ms = config.session_timeout_ms,
            .challenge_cache_capacity = config.challenge_cache_capacity,
            .challenge_timeout_ms = config.challenge_timeout_ms,
            .whoareyou_rate_capacity = config.whoareyou_rate_capacity,
            .whoareyou_rate_ttl_ms = config.whoareyou_rate_ttl_ms,
            .max_whoareyou_per_sec = MAX_WHOAREYOU_PER_SEC,
        });
        errdefer session_store.deinit(alloc);

        scoped_log.debug(
            "protocol init node={s} sessions={d} challenges={d} active_requests={d} queued_requests={d}",
            .{
                &shortNodeId(&config.local_node_id),
                config.session_cache_capacity,
                config.challenge_cache_capacity,
                config.max_active_requests,
                config.max_queued_requests,
            },
        );

        return .{
            .alloc = alloc,
            .io = io,
            .config = config,
            .routing_table = routing_table,
            .session_store = session_store,
            .requests = RequestTracker.init(alloc, .{
                .max_active_requests = config.max_active_requests,
                .max_queued_requests = config.max_queued_requests,
                .max_queued_requests_per_endpoint = config.max_queued_requests_per_endpoint,
            }),
            .contacts = ContactBook.init(alloc, config.local_node_id, config.session_cache_capacity),
            .event_queue = .{},
            .metrics = .{},
        };
    }

    pub fn deinit(self: *Protocol) void {
        self.requests.deinit();
        self.session_store.deinit(self.alloc);
        self.contacts.deinit();
        self.event_queue.deinit(self.alloc);
        self.routing_table.deinit(self.alloc);
    }

    pub fn metricsSnapshot(self: *const Protocol) metrics_mod.ProtocolMetrics {
        return self.metrics;
    }

    fn noteSentMessage(self: *Protocol, msg_bytes: []const u8) void {
        if (msg_bytes.len == 0) return;
        if (metrics_mod.MessageType.fromByte(msg_bytes[0])) |message_type| {
            self.metrics.incSent(message_type);
        }
    }

    fn noteReceivedMessage(self: *Protocol, msg_bytes: []const u8) void {
        if (msg_bytes.len == 0) return;
        if (metrics_mod.MessageType.fromByte(msg_bytes[0])) |message_type| {
            self.metrics.incReceived(message_type);
        }
    }

    fn getSessionCopy(self: *Protocol, node_id: *const NodeId, addr: Address) ?SessionRecord {
        return self.session_store.getSession(.{ .node_id = node_id.*, .addr = addr }, self.currentTimestampNs());
    }

    fn putSession(self: *Protocol, node_id: *const NodeId, addr: Address, session: SessionRecord) void {
        self.session_store.putSession(.{ .node_id = node_id.*, .addr = addr }, session, self.currentTimestampNs());
    }

    pub fn activeSessionCount(self: *Protocol) usize {
        return self.session_store.sessionCount(self.currentTimestampNs());
    }

    fn getChallengeCopy(self: *Protocol, node_id: *const NodeId, addr: Address) ?ActiveChallenge {
        return self.session_store.getChallenge(.{ .node_id = node_id.*, .addr = addr }, self.currentTimestampNs());
    }

    fn putChallenge(self: *Protocol, node_id: *const NodeId, addr: Address, challenge: ActiveChallenge) void {
        self.session_store.putChallenge(.{ .node_id = node_id.*, .addr = addr }, challenge, self.currentTimestampNs());
    }

    fn deleteChallenge(self: *Protocol, node_id: *const NodeId, addr: Address) bool {
        return self.session_store.removeChallenge(.{ .node_id = node_id.*, .addr = addr });
    }

    pub fn randomNonce(self: *Protocol) [12]u8 {
        var nonce: [12]u8 = undefined;
        self.io.random(&nonce);
        return nonce;
    }

    pub fn randomReqId(self: *Protocol) messages.ReqId {
        var id: messages.ReqId = .{ .bytes = [_]u8{0} ** 8, .len = 4 };
        self.io.random(id.bytes[0..4]);
        return id;
    }

    pub fn popEvent(self: *Protocol) ?Event {
        return self.event_queue.pop();
    }

    pub const KnownNode = struct {
        node_id: NodeId,
        pubkey: [33]u8,
        addr: Address,
    };

    pub fn getKnownNode(self: *const Protocol, node_id: *const NodeId) ?KnownNode {
        if (self.routing_table.getEntryWithPending(node_id)) |entry| {
            return .{
                .node_id = entry.node_id,
                .pubkey = entry.pubkey,
                .addr = entry.addr,
            };
        }
        if (self.contacts.get(node_id.*)) |contact| {
            return .{
                .node_id = node_id.*,
                .pubkey = contact.pubkey,
                .addr = contact.addr,
            };
        }
        return null;
    }

    pub fn findEnr(self: *const Protocol, node_id: *const NodeId) ?[]const u8 {
        const entry = self.routing_table.getEntryWithPending(node_id) orelse return null;
        return entry.enr.slice();
    }

    pub fn hasActiveFindNodeRequest(self: *const Protocol, peer_id: *const NodeId) bool {
        return self.requests.hasActiveFindNodeRequest(peer_id);
    }

    pub fn pruneExpiredState(self: *Protocol) void {
        const now_ns = self.currentTimestampNs();
        self.pruneExpiredRequests(now_ns);
        self.routing_table.prunePending(now_ns, self.config.bucket_pending_timeout_ms);
    }

    pub fn sendPing(
        self: *Protocol,
        dest_node_id: *const NodeId,
        dest_pubkey: *const [33]u8,
        dest_addr: Address,
        enr_seq: u64,
        socket: *const net.Socket,
    ) !messages.ReqId {
        self.pruneExpiredState();
        const req_id = self.randomReqId();
        const ping = messages.Ping{
            .req_id = req_id,
            .enr_seq = enr_seq,
        };
        var ping_buf: [SMALL_MESSAGE_BUFFER_SIZE]u8 = undefined;
        const ping_bytes = try ping.encodeInto(&ping_buf);

        try self.sendRequest(dest_node_id, dest_pubkey, dest_addr, req_id, .ping, &.{}, ping_bytes, socket);
        return req_id;
    }

    pub fn sendFindNode(
        self: *Protocol,
        dest_node_id: *const NodeId,
        dest_pubkey: *const [33]u8,
        dest_addr: Address,
        distances: []const u16,
        socket: *const net.Socket,
    ) !messages.ReqId {
        self.pruneExpiredState();
        const req_id = self.randomReqId();
        const find_node = messages.FindNode{
            .req_id = req_id,
            .distances = distances,
        };
        var find_node_buf: [FINDNODE_MESSAGE_BUFFER_SIZE]u8 = undefined;
        const find_node_bytes = try find_node.encodeInto(&find_node_buf);

        try self.sendRequest(dest_node_id, dest_pubkey, dest_addr, req_id, .findnode, distances, find_node_bytes, socket);
        return req_id;
    }

    pub fn sendTalkRequest(
        self: *Protocol,
        dest_node_id: *const NodeId,
        dest_pubkey: *const [33]u8,
        dest_addr: Address,
        protocol_name: []const u8,
        request: []const u8,
        socket: *const net.Socket,
    ) !messages.ReqId {
        self.pruneExpiredState();
        const req_id = self.randomReqId();
        const talk_req = messages.TalkReq{
            .req_id = req_id,
            .protocol = protocol_name,
            .request = request,
        };
        var talk_req_buf: [MAX_PACKET_SIZE]u8 = undefined;
        const talk_req_bytes = try talk_req.encodeInto(&talk_req_buf);

        try self.sendRequest(dest_node_id, dest_pubkey, dest_addr, req_id, .talkreq, &.{}, talk_req_bytes, socket);
        return req_id;
    }

    pub fn sendTalkResponse(
        self: *Protocol,
        peer_id: NodeId,
        peer_addr: Address,
        req_id: messages.ReqId,
        response: []const u8,
        socket: *const net.Socket,
    ) !void {
        const talk_resp = messages.TalkResp{
            .req_id = req_id,
            .response = response,
        };
        var talk_resp_buf: [MAX_PACKET_SIZE]u8 = undefined;
        const talk_resp_bytes = try talk_resp.encodeInto(&talk_resp_buf);
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
        req_id: messages.ReqId,
        request_kind: RequestKind,
        distances: []const u16,
        msg_bytes: []const u8,
        socket: *const net.Socket,
    ) !void {
        const endpoint = Endpoint{ .node_id = dest_node_id.*, .addr = dest_addr };

        // If a session is already being established for this endpoint, queue the
        // request behind it instead of opening a second handshake.
        if (self.getSessionCopy(dest_node_id, dest_addr) == null and self.requests.shouldQueueForEndpoint(endpoint)) {
            scoped_log.debug("queueing {s} request req_id={x} to {any}; session establishment already in progress", .{
                @tagName(request_kind),
                req_id.slice(),
                dest_addr,
            });
            try self.requests.queueRequest(
                endpoint,
                dest_pubkey,
                req_id,
                request_kind,
                distances,
                msg_bytes,
                self.currentTimestampNs(),
            );
            return;
        }

        try self.dispatchOutbound(endpoint, dest_pubkey, req_id, request_kind, distances, msg_bytes, socket);
    }

    /// Encode, track, and transmit a request to `endpoint`: an authenticated
    /// ordinary message when a session exists, otherwise an unauthenticated probe
    /// to provoke a WHOAREYOU. On any failure the active-request entry is rolled
    /// back and the error is propagated so the caller can apply its own policy
    /// (fail-fast for fresh sends, re-queue for drained sends).
    fn dispatchOutbound(
        self: *Protocol,
        endpoint: Endpoint,
        dest_pubkey: *const [33]u8,
        req_id: messages.ReqId,
        request_kind: RequestKind,
        distances: []const u16,
        msg_bytes: []const u8,
        socket: *const net.Socket,
    ) !void {
        var pkt_buf: [MAX_PACKET_SIZE]u8 = undefined;
        if (self.getSessionCopy(&endpoint.node_id, endpoint.addr)) |s| {
            scoped_log.debug("sending {s} request req_id={x} to {any} using established session", .{
                @tagName(request_kind),
                req_id.slice(),
                endpoint.addr,
            });
            const encoded = try self.encodeMessageInto(&pkt_buf, &endpoint.node_id, &s.initiator_key, msg_bytes);
            try self.requests.putActiveAwaitingResponseWithChallenge(
                endpoint,
                req_id,
                request_kind,
                distances,
                socket,
                encoded.pkt,
                self.currentTimestampNs(),
                encoded.nonce,
                dest_pubkey,
                msg_bytes,
            );
            errdefer self.requests.cancelActive(endpoint, req_id);
            try socket.send(self.io, &endpoint.addr, encoded.pkt);
            self.noteSentMessage(msg_bytes);
            return;
        }

        // No established session — send an unauthenticated probe to provoke a
        // WHOAREYOU; the original plaintext is retransmitted in the handshake.
        const probe = try self.encodeProbePacketInto(&pkt_buf, &endpoint.node_id, msg_bytes);
        try self.requests.putActiveProbe(
            endpoint,
            req_id,
            request_kind,
            distances,
            socket,
            probe.pkt,
            self.currentTimestampNs(),
            probe.nonce,
            dest_pubkey,
            msg_bytes,
        );
        errdefer self.requests.cancelActive(endpoint, req_id);
        try socket.send(self.io, &endpoint.addr, probe.pkt);
        scoped_log.debug("sent unauthenticated {s} probe req_id={x} to {any} (msg_len={d})", .{
            @tagName(request_kind),
            req_id.slice(),
            endpoint.addr,
            msg_bytes.len,
        });
    }

    /// Handle an incoming raw UDP packet.
    /// Packet decoding unmasks the header in `raw` in place; callers should not
    /// reuse the same buffer expecting the original masked wire bytes.
    pub fn handlePacket(
        self: *Protocol,
        raw: []u8,
        from: Address,
        socket: *const net.Socket,
    ) !void {
        // Drop oversized packets before any decoding work (CL-2020-06, spec max = IPv6 min MTU).
        if (raw.len > MAX_PACKET_SIZE) {
            scoped_log.debug("dropping oversized packet len={d} from {any}", .{ raw.len, from });
            return;
        }

        var parsed = packet.decode(raw, &self.config.local_node_id) catch |err| {
            scoped_log.debug("dropping undecodable packet len={d} from {any}: {}", .{ raw.len, from, err });
            return;
        };

        switch (parsed.static_header.flag) {
            packet.FLAG_MESSAGE => try self.handleMessage(&parsed, from, socket),
            packet.FLAG_WHOAREYOU => try self.handleWhoareyou(&parsed, from, socket),
            packet.FLAG_HANDSHAKE => try self.handleHandshake(&parsed, from, socket),
            else => scoped_log.debug("dropping packet with unknown flag={d} from {any}", .{ parsed.static_header.flag, from }),
        }
    }

    fn handleMessage(
        self: *Protocol,
        parsed: *packet.ParsedPacket,
        from: Address,
        socket: *const net.Socket,
    ) !void {
        const authdata = parsed.authdata_raw;
        if (authdata.len < 32) {
            scoped_log.debug("dropping MESSAGE with short authdata len={d} from {any}", .{ authdata.len, from });
            return;
        }
        const src_id: NodeId = authdata[0..32].*;

        if (self.getSessionCopy(&src_id, from)) |session_copy| {
            var s = session_copy;
            // Replay protection: drop packets with a nonce we've already processed.
            if (s.seen_nonces.contains(&parsed.static_header.nonce)) {
                scoped_log.debug("dropping replayed MESSAGE nonce from node={s} addr={any}", .{
                    &shortNodeId(&src_id),
                    from,
                });
                return;
            }
            var plaintext_buf: [MAX_PACKET_SIZE]u8 = undefined;
            var ad_buf: [MAX_PACKET_SIZE]u8 = undefined;
            const decrypt_result = packet.decryptMessageInto(
                &plaintext_buf,
                &ad_buf,
                &s.recipient_key,
                &parsed.static_header.nonce,
                parsed.message_ciphertext,
                &parsed.masking_iv,
                parsed.header_raw,
            ) catch blk: {
                if (s.awaiting_recipient_key) |awaiting_key| {
                    const pt2 = packet.decryptMessageInto(
                        &plaintext_buf,
                        &ad_buf,
                        &awaiting_key,
                        &parsed.static_header.nonce,
                        parsed.message_ciphertext,
                        &parsed.masking_iv,
                        parsed.header_raw,
                    ) catch break :blk null;
                    s.recipient_key = awaiting_key;
                    if (s.awaiting_initiator_key) |awaiting_initiator| s.initiator_key = awaiting_initiator;
                    s.awaiting_recipient_key = null;
                    s.awaiting_initiator_key = null;
                    scoped_log.debug("activated pending session keys for node={s} addr={any}", .{
                        &shortNodeId(&src_id),
                        from,
                    });
                    break :blk pt2;
                }
                break :blk null;
            };
            const pt = decrypt_result orelse {
                scoped_log.debug("failed to decrypt MESSAGE from node={s} addr={any}; sending WHOAREYOU", .{
                    &shortNodeId(&src_id),
                    from,
                });
                try self.sendWhoareyou(src_id, &parsed.static_header.nonce, from, socket);
                return;
            };
            // Record nonce only after successful decryption.
            s.seen_nonces.insert(&parsed.static_header.nonce);
            self.putSession(&src_id, from, s);
            self.markNodeSeenAndPingEvictionCandidate(src_id, from, socket);
            try self.dispatchMessage(pt, src_id, from, socket);
            return;
        }

        const endpoint = Endpoint{ .node_id = src_id, .addr = from };
        if (self.requests.pendingSessionKeysForEndpoint(endpoint)) |pending_session| {
            var plaintext_buf: [MAX_PACKET_SIZE]u8 = undefined;
            var ad_buf: [MAX_PACKET_SIZE]u8 = undefined;
            const pt = packet.decryptMessageInto(
                &plaintext_buf,
                &ad_buf,
                &pending_session.recipient_key,
                &parsed.static_header.nonce,
                parsed.message_ciphertext,
                &parsed.masking_iv,
                parsed.header_raw,
            ) catch null;
            if (pt) |plaintext| {
                var s = SessionRecord{
                    .node_id = src_id,
                    .initiator_key = pending_session.initiator_key,
                    .recipient_key = pending_session.recipient_key,
                    .seen_nonces = SeenNonces.init(),
                };
                s.seen_nonces.insert(&parsed.static_header.nonce);
                self.putSession(&src_id, from, s);
                self.markNodeSeenAndPingEvictionCandidate(src_id, from, socket);
                scoped_log.debug("accepted first response with pending session keys from node={s} addr={any}", .{
                    &shortNodeId(&src_id),
                    from,
                });
                try self.dispatchMessage(plaintext, src_id, from, socket);
                return;
            }
        }

        scoped_log.debug("MESSAGE from node={s} addr={any} has no usable session; sending WHOAREYOU", .{
            &shortNodeId(&src_id),
            from,
        });
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
        socket: *const net.Socket,
    ) !void {
        const authdata = parsed.authdata_raw;
        // WHOAREYOU authdata = id_nonce (16) || enr_seq (8).
        if (authdata.len != packet.WHOAREYOU_AUTHDATA_SIZE) {
            scoped_log.debug("dropping WHOAREYOU with bad authdata len={d} from {any}", .{ authdata.len, from });
            return;
        }

        // The nonce in the WHOAREYOU static header is the nonce of the message
        // packet that triggered the challenge — use it to find our pending request.
        const request_nonce = parsed.static_header.nonce;

        const probe = self.requests.probeForChallenge(&request_nonce, from) orelse {
            scoped_log.debug("WHOAREYOU for unknown nonce (pending={d}, nonce={s}, from={any})", .{
                self.requests.pendingCount(),
                &std.fmt.bytesToHex(request_nonce, .lower),
                from,
            });
            return;
        };
        const probe_node_id = probe.endpoint.node_id;
        const probe_addr = probe.endpoint.addr;

        // Parse enr_seq from authdata to validate the WHOAREYOU layout.
        const remote_enr_seq = std.mem.readInt(u64, authdata[16..24], .big);
        scoped_log.debug("accepted WHOAREYOU for {s} req_id={x} from {any} remote_enr_seq={d}", .{
            @tagName(probe.request_kind),
            probe.req_id.slice(),
            from,
            remote_enr_seq,
        });

        // challenge_data = masking_iv || plaintext_static_header || plaintext_authdata.
        var challenge_data: [CHALLENGE_DATA_SIZE]u8 = undefined;
        @memcpy(challenge_data[0..16], &parsed.masking_iv);
        @memcpy(challenge_data[16..], parsed.header_raw);

        const eph_key_pair = secp.KeyPair.generate(self.io);
        const eph_pubkey = secp.compressedPubkey(&eph_key_pair);

        // Derive session keys: ECDH(ephemeral keypair, dest_pubkey) -> HKDF
        // node_id_a = our node_id (initiator), node_id_b = dest_node_id
        const keys = session_mod.deriveKeys(
            &eph_key_pair,
            probe.dest_pubkey,
            &self.config.local_node_id,
            &probe_node_id,
            &challenge_data,
        ) catch |err| {
            scoped_log.debug("failed to derive initiator session keys for {any}: {}", .{ from, err });
            return;
        };

        // Compute id-nonce signature.
        const id_sig = session_mod.signIdNonce(
            &self.config.local_key_pair,
            &challenge_data,
            &eph_pubkey,
            &probe_node_id,
        ) catch |err| {
            scoped_log.debug("failed to sign id nonce for {any}: {}", .{ from, err });
            return;
        };

        // Include our ENR only when the remote says it is stale, matching the TS session service.
        const include_enr = self.config.local_enr != null and remote_enr_seq < self.config.local_enr_seq;
        const enr_bytes: []const u8 = if (include_enr) self.config.local_enr.? else &[_]u8{};

        var handshake_authdata_buf: [MAX_HANDSHAKE_AUTHDATA_SIZE]u8 = undefined;
        const handshake_authdata = handshake_mod.buildAuthdata(
            &handshake_authdata_buf,
            self.config.local_node_id,
            &id_sig,
            &eph_pubkey,
            enr_bytes,
        ) catch |err| {
            scoped_log.debug("failed to build handshake authdata for {any}: {}", .{ from, err });
            return err;
        };

        const nonce = self.randomNonce();
        var masking_iv: [16]u8 = undefined;
        self.io.random(&masking_iv);

        var handshake_pkt_buf: [MAX_PACKET_SIZE]u8 = undefined;
        const handshake_pkt = try packet.encodeMessagePacketInto(&handshake_pkt_buf, .{
            .kind = .handshake,
            .masking_iv = &masking_iv,
            .recipient_node_id = &probe_node_id,
            .nonce = &nonce,
            .authdata = handshake_authdata,
            .write_key = &keys.initiator_key,
            .plaintext = probe.plaintext,
        });

        const pending_session = PendingSessionKeys{
            .initiator_key = keys.initiator_key,
            .recipient_key = keys.recipient_key,
        };

        var restore_session: ?SessionRecord = null;
        if (self.getSessionCopy(&probe_node_id, probe_addr)) |existing_session| {
            restore_session = existing_session;
            var session = existing_session;
            session.awaiting_initiator_key = keys.initiator_key;
            session.awaiting_recipient_key = keys.recipient_key;
            self.putSession(&probe_node_id, probe_addr, session);
        }
        errdefer if (restore_session) |session| {
            self.putSession(&probe_node_id, probe_addr, session);
        };

        try socket.send(self.io, &from, handshake_pkt);
        self.requests.acceptChallenge(
            probe.key,
            &request_nonce,
            from,
            handshake_pkt,
            pending_session,
            self.currentTimestampNs(),
        ) catch |err| {
            scoped_log.debug("failed to accept WHOAREYOU challenge from {any}: {}", .{ from, err });
            return err;
        };
        scoped_log.debug("sent handshake to {any} for {s} req_id={x} include_enr={}", .{
            from,
            @tagName(probe.request_kind),
            probe.req_id.slice(),
            include_enr,
        });
    }

    fn handleHandshake(
        self: *Protocol,
        parsed: *packet.ParsedPacket,
        from: Address,
        socket: *const net.Socket,
    ) !void {
        const ad = handshake_mod.parseAuthdata(parsed.authdata_raw) catch |err| {
            scoped_log.debug("dropping malformed HANDSHAKE from {any}: {}", .{ from, err });
            return;
        };
        const src_id = ad.src_id;

        const active_challenge = self.getChallengeCopy(&src_id, from) orelse {
            scoped_log.debug("dropping HANDSHAKE with no active challenge from node={s} addr={any}", .{
                &shortNodeId(&src_id),
                from,
            });
            return;
        };

        const challenge = active_challenge.challenge_data[0..];
        const maybe_enr = ad.maybe_enr;

        // Resolve the sender's static public key: prefer a known peer, otherwise
        // the optional ENR appended to the handshake authdata.
        const sender_pubkey: [33]u8 = if (self.getKnownNode(&src_id)) |known| known.pubkey else blk: {
            const enr_bytes = maybe_enr orelse {
                scoped_log.debug("handshake from unknown peer {any} with no ENR, rejecting", .{src_id});
                return;
            };
            const pk = handshake_mod.pubkeyFromEnr(enr_bytes, src_id) catch |err| {
                scoped_log.debug("handshake ENR from {any} rejected: {}", .{ src_id, err });
                return;
            };
            handshake_mod.verifyEnrEndpoint(enr_bytes, src_id, from, self.config.allow_unverified_sessions) catch |err| {
                scoped_log.debug("handshake ENR endpoint check for {any} failed: {}", .{ src_id, err });
                return;
            };
            break :blk pk;
        };

        // Endpoint-verify the advertised ENR (the optional record, else the one
        // cached with the challenge) regardless of whether the sender was known.
        if (maybe_enr) |enr_bytes| {
            handshake_mod.verifyEnrEndpoint(enr_bytes, src_id, from, self.config.allow_unverified_sessions) catch |err| {
                scoped_log.debug("handshake optional ENR endpoint check for node={s} addr={any} failed: {}", .{ &shortNodeId(&src_id), from, err });
                return;
            };
        } else if (active_challenge.remote_enr) |remote_enr| {
            handshake_mod.verifyEnrEndpoint(remote_enr[0..active_challenge.remote_enr_len], src_id, from, self.config.allow_unverified_sessions) catch |err| {
                scoped_log.debug("cached challenge ENR endpoint check for node={s} addr={any} failed: {}", .{ &shortNodeId(&src_id), from, err });
                return;
            };
        }

        // Verify id-signature: SHA256("discovery v5 identity proof" || challenge_data || eph_pubkey || local_node_id)
        session_mod.verifyIdSignature(ad.id_sig, &sender_pubkey, challenge, ad.eph_pubkey, &self.config.local_node_id) catch {
            scoped_log.debug("handshake id-signature verification failed for {any}, rejecting", .{src_id});
            return;
        };

        const keys = session_mod.deriveKeys(
            &self.config.local_key_pair,
            ad.eph_pubkey,
            &src_id,
            &self.config.local_node_id,
            challenge,
        ) catch |err| {
            scoped_log.debug("failed to derive recipient session keys for node={s} addr={any}: {}", .{
                &shortNodeId(&src_id),
                from,
                err,
            });
            return;
        };

        const existing_session = self.getSessionCopy(&src_id, from);

        var plaintext_buf: [MAX_PACKET_SIZE]u8 = undefined;
        var ad_buf: [MAX_PACKET_SIZE]u8 = undefined;
        const pt = packet.decryptMessageInto(
            &plaintext_buf,
            &ad_buf,
            &keys.initiator_key,
            &parsed.static_header.nonce,
            parsed.message_ciphertext,
            &parsed.masking_iv,
            parsed.header_raw,
        ) catch |err| {
            scoped_log.debug("failed to decrypt HANDSHAKE message from node={s} addr={any}: {}", .{
                &shortNodeId(&src_id),
                from,
                err,
            });
            return;
        };

        var new_session = existing_session orelse SessionRecord{
            .node_id = src_id,
            .initiator_key = keys.recipient_key,
            .recipient_key = keys.initiator_key,
            .seen_nonces = SeenNonces.init(),
        };
        if (new_session.seen_nonces.contains(&parsed.static_header.nonce)) {
            scoped_log.debug("dropping replayed HANDSHAKE nonce from node={s} addr={any}", .{
                &shortNodeId(&src_id),
                from,
            });
            return;
        }
        new_session.initiator_key = keys.recipient_key;
        new_session.recipient_key = keys.initiator_key;
        new_session.awaiting_initiator_key = null;
        new_session.awaiting_recipient_key = null;
        new_session.seen_nonces.insert(&parsed.static_header.nonce);

        _ = self.deleteChallenge(&src_id, from);
        self.putSession(&src_id, from, new_session);

        if (maybe_enr) |enr_bytes| {
            const entry = self.entryFromEnr(enr_bytes, .connected, from);
            if (entry) |routing_entry| {
                _ = self.insertEnrEntry(routing_entry);
            } else {
                self.contacts.remember(src_id, &sender_pubkey, from);
            }
        } else {
            self.contacts.remember(src_id, &sender_pubkey, from);
        }
        self.markNodeSeenAndPingEvictionCandidate(src_id, from, socket);
        scoped_log.debug("handshake established with node={s} addr={any} supplied_enr={}", .{
            &shortNodeId(&src_id),
            from,
            maybe_enr != null,
        });
        try self.dispatchMessage(pt, src_id, from, socket);
    }

    fn allowWhoareyou(self: *Protocol, dest: Address) bool {
        return self.session_store.allowWhoareyou(dest, self.currentTimestampNs());
    }

    fn sendWhoareyou(
        self: *Protocol,
        src_id: NodeId,
        request_nonce: *const [12]u8,
        dest: Address,
        socket: *const net.Socket,
    ) !void {
        // Keep the first live challenge for an endpoint. Replacing it based on
        // another unauthenticated packet lets source-spoofed traffic invalidate
        // the legitimate peer's in-flight identity proof.
        if (self.getChallengeCopy(&src_id, dest) != null) return;
        if (!self.allowWhoareyou(dest)) return;

        // Established-session capacity and tail eviction are handled by the session LRU.
        var id_nonce: [16]u8 = undefined;
        self.io.random(&id_nonce);

        var masking_iv: [16]u8 = undefined;
        self.io.random(&masking_iv);

        var challenge = ActiveChallenge{ .challenge_data = undefined };

        var remote_enr_seq: u64 = 0;
        if (self.routing_table.getEntry(&src_id)) |entry| {
            const remote_enr = entry.enrBytes();
            remote_enr_seq = entry.enr_seq;
            if (remote_enr.len <= enr_mod.MAX_ENR_SIZE) {
                var copy: [enr_mod.MAX_ENR_SIZE]u8 = undefined;
                @memcpy(copy[0..remote_enr.len], remote_enr);
                challenge.remote_enr = copy;
                challenge.remote_enr_len = @intCast(remote_enr.len);
            }
        }

        var whoareyou_buf: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
        const whoareyou_packet = try packet.encodeWhoareyouPacketInto(&whoareyou_buf, .{
            .masking_iv = &masking_iv,
            .recipient_node_id = &src_id,
            .request_nonce = request_nonce,
            .id_nonce = &id_nonce,
            .enr_seq = remote_enr_seq,
        }, &challenge.challenge_data);
        self.putChallenge(&src_id, dest, challenge);

        try socket.send(self.io, &dest, whoareyou_packet);
        scoped_log.debug("sent WHOAREYOU to node={s} addr={any} known_enr_seq={d}", .{
            &shortNodeId(&src_id),
            dest,
            remote_enr_seq,
        });
    }

    fn sendOrdinaryMessage(
        self: *Protocol,
        dest_node_id: *const NodeId,
        write_key: *const [16]u8,
        dest_addr: Address,
        msg_bytes: []const u8,
        socket: *const net.Socket,
    ) !void {
        var pkt_buf: [MAX_PACKET_SIZE]u8 = undefined;
        const encoded = try self.encodeMessageInto(&pkt_buf, dest_node_id, write_key, msg_bytes);

        try socket.send(self.io, &dest_addr, encoded.pkt);
        self.noteSentMessage(msg_bytes);
    }

    const EncodedMessage = struct {
        pkt: []u8,
        nonce: [packet.NONCE_SIZE]u8,
    };

    /// Encode an ordinary message packet under `write_key` into `out`, returning
    /// the packet bytes and the message nonce.
    fn encodeMessageInto(
        self: *Protocol,
        out: []u8,
        dest_node_id: *const NodeId,
        write_key: *const [16]u8,
        msg_bytes: []const u8,
    ) !EncodedMessage {
        const nonce = self.randomNonce();
        var masking_iv: [16]u8 = undefined;
        self.io.random(&masking_iv);
        const authdata: [32]u8 = self.config.local_node_id;

        const pkt = try packet.encodeMessagePacketInto(out, .{
            .kind = .ordinary,
            .masking_iv = &masking_iv,
            .recipient_node_id = dest_node_id,
            .nonce = &nonce,
            .authdata = &authdata,
            .write_key = write_key,
            .plaintext = msg_bytes,
        });
        return .{ .pkt = pkt, .nonce = nonce };
    }

    /// Encode an unauthenticated probe: the real request encrypted under a
    /// random throwaway key. The peer cannot decrypt it and should answer with
    /// WHOAREYOU, after which the original plaintext is retransmitted inside the
    /// authenticated handshake. The returned nonce is recorded to match the
    /// WHOAREYOU challenge.
    fn encodeProbePacketInto(
        self: *Protocol,
        out: []u8,
        dest_node_id: *const NodeId,
        msg_bytes: []const u8,
    ) !EncodedMessage {
        var fake_key: [16]u8 = undefined;
        self.io.random(&fake_key);
        return self.encodeMessageInto(out, dest_node_id, &fake_key, msg_bytes);
    }

    fn entryFromEnr(
        self: *Protocol,
        enr_bytes: []const u8,
        status: kbucket.EntryStatus,
        contact_addr: ?Address,
    ) ?kbucket.Entry {
        const parsed_enr = enr_mod.decode(enr_bytes) catch return null;
        const node_id = parsed_enr.nodeId() orelse return null;
        if (std.mem.eql(u8, &node_id, &self.config.local_node_id)) return null;
        const pubkey = parsed_enr.pubkey orelse return null;
        const addr = contact_addr orelse parsed_enr.udpAddress() orelse return null;
        const raw = enr_mod.RawEnr.init(enr_bytes) catch return null;

        return .{
            .node_id = node_id,
            .pubkey = pubkey,
            .addr = addr,
            .enr = raw,
            .enr_seq = parsed_enr.seq,
            .last_seen = self.currentTimestampNs(),
            .status = status,
        };
    }

    fn insertEnrEntry(self: *Protocol, incoming: kbucket.Entry) ?kbucket.Entry {
        var entry = incoming;
        if (self.routing_table.getEntryWithPending(&entry.node_id)) |existing| {
            if (existing.enr_seq >= entry.enr_seq) {
                scoped_log.debug("ignored stale ENR for node={s} known_seq={d} incoming_seq={d}", .{
                    &shortNodeId(&entry.node_id),
                    existing.enr_seq,
                    entry.enr_seq,
                });
                return null;
            }
            // Local trust applies to the node identity, so preserve it when a
            // newer, correctly signed ENR is learned through the network.
            entry.locally_trusted = existing.locally_trusted;
        }
        self.contacts.forget(entry.node_id);
        scoped_log.debug("inserted ENR for node={s} addr={any} seq={d} status={s}", .{
            &shortNodeId(&entry.node_id),
            entry.addr,
            entry.enr_seq,
            @tagName(entry.status),
        });
        return self.routing_table.insertDetailed(entry).pending_eviction;
    }

    fn appendRequestTimeout(self: *Protocol, expired: ExpiredRequest) void {
        scoped_log.debug("request timed out kind={s} req_id={x} node={s} addr={any}", .{
            @tagName(expired.kind),
            expired.req_id.slice(),
            &shortNodeId(&expired.endpoint.node_id),
            expired.endpoint.addr,
        });
        self.event_queue.push(self.alloc, .{
            .request_timeout = .{
                .peer_id = expired.endpoint.node_id,
                .req_id = expired.req_id,
                .kind = expired.kind,
            },
        }) catch {};
    }

    fn pruneExpiredRequests(self: *Protocol, now_ns: i64) void {
        var expired: std.ArrayListUnmanaged(ExpiredRequest) = .empty;
        defer expired.deinit(self.alloc);

        self.requests.pruneExpiredActive(
            self.io,
            now_ns,
            self.config.request_timeout_ms,
            self.config.request_retries,
            &expired,
        ) catch |err| {
            scoped_log.debug("failed to prune active requests: {}", .{err});
            return;
        };

        const active_expired_len = expired.items.len;
        var i: usize = 0;
        while (i < active_expired_len) : (i += 1) {
            if (expired.items[i].socket) |socket| {
                const endpoint = expired.items[i].endpoint;
                self.sendNextQueuedRequest(&endpoint.node_id, endpoint.addr, socket);
            }
        }

        self.requests.pruneExpiredQueued(now_ns, self.config.request_timeout_ms, &expired) catch |err| {
            scoped_log.debug("failed to prune queued requests: {}", .{err});
            return;
        };

        for (expired.items) |request| self.appendRequestTimeout(request);
    }

    fn restoreQueuedRequest(self: *Protocol, intent: request_tracker.RequestIntent) void {
        self.requests.pushFrontQueued(intent) catch {
            scoped_log.debug("failed to restore queued request kind={s} req_id={x} node={s} addr={any}; timing out", .{
                @tagName(intent.request_kind),
                intent.req_id.slice(),
                &shortNodeId(&intent.endpoint.node_id),
                intent.endpoint.addr,
            });
            self.appendRequestTimeout(.{
                .endpoint = intent.endpoint,
                .req_id = intent.req_id,
                .kind = intent.request_kind,
            });
        };
    }

    fn sendNextQueuedRequest(self: *Protocol, peer_id: *const NodeId, peer_addr: Address, socket: *const net.Socket) void {
        const endpoint = Endpoint{ .node_id = peer_id.*, .addr = peer_addr };
        const intent = (self.requests.popNextQueued(endpoint) catch |err| {
            scoped_log.debug("failed to pop queued request for node={s} addr={any}: {}", .{
                &shortNodeId(peer_id),
                peer_addr,
                err,
            });
            return;
        }) orelse return;

        // A drained request has nowhere left to wait: on any failure, push it back
        // to the front of the queue (or time it out) rather than dropping it.
        self.dispatchOutbound(
            intent.endpoint,
            &intent.dest_pubkey,
            intent.req_id,
            intent.request_kind,
            intent.distances(),
            intent.plaintextSlice(),
            socket,
        ) catch |err| {
            scoped_log.debug("failed to dispatch queued {s} request req_id={x} to {any}: {}", .{
                @tagName(intent.request_kind),
                intent.req_id.slice(),
                peer_addr,
                err,
            });
            self.restoreQueuedRequest(intent);
        };
    }

    fn currentTimestampNs(self: *const Protocol) i64 {
        return util.nowNs(self.io);
    }

    fn markNodeSeen(self: *Protocol, node_id: NodeId, addr: Address, status: kbucket.EntryStatus) ?kbucket.Entry {
        var entry = (self.routing_table.getEntryWithPending(&node_id) orelse return null).*;
        entry.addr = addr;
        entry.last_seen = self.currentTimestampNs();
        entry.status = status;
        const parsed = enr_mod.decode(entry.enrBytes()) catch return null;
        const advertised_addr = switch (addr) {
            .ip4 => parsed.udpAddress4(),
            .ip6 => parsed.udpAddress6(),
        };
        entry.relay_eligible = if (advertised_addr) |advertised| Address.eql(&advertised, &addr) else false;
        return self.routing_table.insertDetailed(entry).pending_eviction;
    }

    fn markNodeSeenAndPingEvictionCandidate(
        self: *Protocol,
        node_id: NodeId,
        addr: Address,
        socket: *const net.Socket,
    ) void {
        const candidate = self.markNodeSeen(node_id, addr, .connected) orelse return;
        const known = self.getKnownNode(&candidate.node_id) orelse return;
        scoped_log.debug("node={s} addr={any} became connected; pinging pending eviction candidate node={s} addr={any}", .{
            &shortNodeId(&node_id),
            addr,
            &shortNodeId(&candidate.node_id),
            candidate.addr,
        });
        _ = self.sendPing(&known.node_id, &known.pubkey, candidate.addr, self.config.local_enr_seq, socket) catch {};
    }

    fn rememberEnr(self: *Protocol, enr_bytes: []const u8) void {
        const entry = self.entryFromEnr(enr_bytes, .disconnected, null) orelse return;
        _ = self.insertEnrEntry(entry);
    }

    fn enrMatchesFindNodeRequest(
        enr_bytes: []const u8,
        responder_id: *const NodeId,
        request: *const ActiveFindNodeRequest,
    ) bool {
        const parsed_enr = enr_mod.decode(enr_bytes) catch return false;
        const node_id = parsed_enr.nodeId() orelse return false;
        const wire_distance: u16 = if (kbucket.logDistance(&node_id, responder_id)) |distance|
            @as(u16, distance) + 1
        else
            0;
        for (request.requested_distances[0..request.requested_distances_len]) |requested| {
            if (requested == wire_distance) return true;
        }
        return false;
    }

    fn knownEnrSeq(self: *Protocol, peer_id: NodeId) ?u64 {
        const entry = self.routing_table.getEntry(&peer_id) orelse return null;
        return entry.enr_seq;
    }

    fn maybeRequestEnrUpdate(
        self: *Protocol,
        peer_id: NodeId,
        peer_addr: Address,
        advertised_seq: u64,
        socket: *const net.Socket,
    ) void {
        const known_seq = self.knownEnrSeq(peer_id) orelse return;
        if (known_seq >= advertised_seq) return;
        if (self.hasActiveFindNodeRequest(&peer_id)) return;
        const known = self.getKnownNode(&peer_id) orelse return;
        const distances = [_]u16{0};
        scoped_log.debug("peer node={s} advertised newer ENR seq known={d} advertised={d}; requesting ENR", .{
            &shortNodeId(&peer_id),
            known_seq,
            advertised_seq,
        });
        _ = self.sendFindNode(&peer_id, &known.pubkey, peer_addr, &distances, socket) catch {};
    }

    fn sendResponseMessage(
        self: *Protocol,
        peer_id: NodeId,
        peer_addr: Address,
        plaintext: []const u8,
        socket: *const net.Socket,
    ) !void {
        const s = self.getSessionCopy(&peer_id, peer_addr) orelse return;
        scoped_log.debug("sending {s} response to node={s} addr={any}", .{
            if (plaintext.len == 0) "empty" else metrics_mod.messageLabel(plaintext[0]),
            &shortNodeId(&peer_id),
            peer_addr,
        });
        try self.sendOrdinaryMessage(&peer_id, &s.initiator_key, peer_addr, plaintext, socket);
    }

    fn dispatchMessage(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const net.Socket,
    ) !void {
        if (pt.len == 0) {
            scoped_log.debug("dropping empty plaintext message from node={s} addr={any}", .{
                &shortNodeId(&from),
                from_addr,
            });
            return;
        }
        scoped_log.debug("dispatching {s} from node={s} addr={any} len={d}", .{
            metrics_mod.messageLabel(pt[0]),
            &shortNodeId(&from),
            from_addr,
            pt.len,
        });
        switch (pt[0]) {
            messages.MSG_PING => try self.handlePing(pt, from, from_addr, socket),
            messages.MSG_PONG => self.handlePong(pt, from, from_addr, socket),
            messages.MSG_FINDNODE => try self.handleFindNode(pt, from, from_addr, socket),
            messages.MSG_NODES => self.handleNodes(pt, from, from_addr, socket),
            messages.MSG_TALKREQ => self.handleTalkReq(pt, from, from_addr, socket),
            messages.MSG_TALKRESP => self.handleTalkResp(pt, from, from_addr, socket),
            else => scoped_log.debug("ignoring unknown message type=0x{x:0>2} from node={s} addr={any}", .{
                pt[0],
                &shortNodeId(&from),
                from_addr,
            }),
        }
    }

    fn handlePing(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const net.Socket,
    ) !void {
        const ping = messages.Ping.decode(pt) catch |err| {
            scoped_log.debug("failed to decode PING from node={s} addr={any}: {}", .{
                &shortNodeId(&from),
                from_addr,
                err,
            });
            return;
        };
        self.noteReceivedMessage(pt);
        scoped_log.debug("received PING req_id={x} from node={s} addr={any} enr_seq={d}", .{
            ping.req_id.slice(),
            &shortNodeId(&from),
            from_addr,
            ping.enr_seq,
        });
        self.maybeRequestEnrUpdate(from, from_addr, ping.enr_seq, socket);

        const pong = messages.Pong{
            .req_id = ping.req_id,
            .enr_seq = self.config.local_enr_seq,
            .recipient_ip = switch (from_addr) {
                .ip4 => |ip4| .{ .ip4 = ip4.bytes },
                .ip6 => |ip6| .{ .ip6 = ip6.bytes },
            },
            .recipient_port = from_addr.getPort(),
        };

        var pong_buf: [SMALL_MESSAGE_BUFFER_SIZE]u8 = undefined;
        const pong_bytes = try pong.encodeInto(&pong_buf);
        try self.sendResponseMessage(from, from_addr, pong_bytes, socket);
    }

    fn handlePong(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const net.Socket,
    ) void {
        const pong = messages.Pong.decode(pt) catch |err| {
            scoped_log.debug("failed to decode PONG from node={s} addr={any}: {}", .{
                &shortNodeId(&from),
                from_addr,
                err,
            });
            return;
        };
        self.noteReceivedMessage(pt);
        const endpoint = Endpoint{ .node_id = from, .addr = from_addr };
        var request = self.requests.finishActiveExpectingKind(endpoint, pong.req_id, .ping) orelse {
            scoped_log.debug("received PONG with no matching PING request req_id={x} from node={s} addr={any}", .{
                pong.req_id.slice(),
                &shortNodeId(&from),
                from_addr,
            });
            return;
        };
        defer request.deinit(self.alloc);

        self.markNodeSeenAndPingEvictionCandidate(from, from_addr, socket);
        scoped_log.debug("received PONG req_id={x} from node={s} addr={any} enr_seq={d}", .{
            pong.req_id.slice(),
            &shortNodeId(&from),
            from_addr,
            pong.enr_seq,
        });
        self.event_queue.push(self.alloc, .{
            .pong = .{
                .peer_id = from,
                .peer_addr = from_addr,
                .req_id = pong.req_id,
                .enr_seq = pong.enr_seq,
                .recipient_ip = pong.recipient_ip,
                .recipient_port = pong.recipient_port,
            },
        }) catch {};
        self.sendNextQueuedRequest(&from, from_addr, socket);
    }

    fn handleFindNode(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const net.Socket,
    ) !void {
        var distances_buf: [127]u16 = undefined;
        const fn_msg = messages.FindNode.decodeInto(pt, &distances_buf) catch |err| {
            scoped_log.debug("failed to decode FINDNODE from node={s} addr={any}: {}", .{
                &shortNodeId(&from),
                from_addr,
                err,
            });
            return;
        };
        self.noteReceivedMessage(pt);

        var seen_distances = [_]bool{false} ** 257;
        var enr_refs_buf: [MAX_NODES_RESPONSE][]const u8 = undefined;
        var enr_refs = std.ArrayListUnmanaged([]const u8).initBuffer(&enr_refs_buf);
        for (fn_msg.distances) |dist| {
            if (!markFindNodeDistance(&seen_distances, dist)) continue;
            if (enr_refs.items.len >= enr_refs.capacity) break;
            if (dist == 0) {
                if (self.config.local_enr) |local_enr| {
                    enr_refs.appendAssumeCapacity(local_enr);
                }
                continue;
            }
            if (dist > 256) continue;
            const entries = self.routing_table.getBucket(@intCast(dist - 1));
            for (entries) |*entry| {
                if (!entry.locally_trusted and !entry.relay_eligible) continue;
                enr_refs.appendAssumeCapacity(entry.enrBytes());
                if (enr_refs.items.len >= enr_refs.capacity) break;
            }
        }

        const total_chunks: u64 = @max(@as(u64, @intCast(std.math.divCeil(usize, enr_refs.items.len, MAX_NODES_ENRS_PER_PACKET) catch 0)), 1);
        scoped_log.debug("received FINDNODE req_id={x} from node={s} addr={any} distances={d} response_enrs={d} chunks={d}", .{
            fn_msg.req_id.slice(),
            &shortNodeId(&from),
            from_addr,
            fn_msg.distances.len,
            enr_refs.items.len,
            total_chunks,
        });
        var chunk_index: usize = 0;
        while (chunk_index < total_chunks) : (chunk_index += 1) {
            const start = chunk_index * MAX_NODES_ENRS_PER_PACKET;
            const end = @min(start + MAX_NODES_ENRS_PER_PACKET, enr_refs.items.len);
            const nodes_msg = messages.Nodes{
                .req_id = fn_msg.req_id,
                .total = total_chunks,
                .enrs = enr_refs.items[start..end],
            };
            var nodes_buf: [MAX_PACKET_SIZE]u8 = undefined;
            const nodes_bytes = try nodes_msg.encodeInto(&nodes_buf);
            try self.sendResponseMessage(from, from_addr, nodes_bytes, socket);
        }
    }

    fn handleNodes(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const net.Socket,
    ) void {
        var enrs_buf: [MAX_NODES_RESPONSE][]const u8 = undefined;
        const decoded = messages.Nodes.decodeInto(pt, &enrs_buf) catch |err| {
            scoped_log.debug("failed to decode NODES from node={s} addr={any}: {}", .{
                &shortNodeId(&from),
                from_addr,
                err,
            });
            return;
        };

        if (decoded.total == 0) {
            scoped_log.debug("dropping NODES with total=0 from node={s} addr={any}", .{
                &shortNodeId(&from),
                from_addr,
            });
            return;
        }
        self.noteReceivedMessage(pt);

        const endpoint = Endpoint{ .node_id = from, .addr = from_addr };
        const request = self.requests.getActivePtr(endpoint, decoded.req_id) orelse {
            scoped_log.debug("received NODES for unknown request req_id={x} from node={s} addr={any}", .{
                decoded.req_id.slice(),
                &shortNodeId(&from),
                from_addr,
            });
            return;
        };
        if (request.kind != .findnode) {
            scoped_log.debug("received NODES for non-FINDNODE request req_id={x} from node={s} addr={any}", .{
                decoded.req_id.slice(),
                &shortNodeId(&from),
                from_addr,
            });
            return;
        }

        var findnode = &request.kind.findnode;
        const accepted_total = @min(decoded.total, @as(u64, MAX_NODES_RESPONSE_CHUNKS));
        if (findnode.total_responses == null) {
            findnode.total_responses = accepted_total;
        } else if (findnode.total_responses.? != accepted_total) {
            scoped_log.debug("dropping NODES with inconsistent total req_id={x} from node={s} addr={any} expected={d} got={d}", .{
                decoded.req_id.slice(),
                &shortNodeId(&from),
                from_addr,
                findnode.total_responses.?,
                accepted_total,
            });
            return;
        }

        var accepted_enrs: usize = 0;
        for (decoded.enrs) |enr| {
            if (findnode.enrs.items.len >= MAX_NODES_RESPONSE) break;
            if (!enrMatchesFindNodeRequest(enr, &from, findnode)) continue;
            self.rememberEnr(enr);
            const enr_copy = self.alloc.dupe(u8, enr) catch continue;
            findnode.enrs.append(self.alloc, enr_copy) catch {
                self.alloc.free(enr_copy);
                continue;
            };
            accepted_enrs += 1;
        }
        findnode.responses_received += 1;
        self.markNodeSeenAndPingEvictionCandidate(from, from_addr, socket);
        scoped_log.debug("received NODES chunk {d}/{d} req_id={x} from node={s} addr={any} decoded_enrs={d} accepted_enrs={d}", .{
            findnode.responses_received,
            findnode.total_responses.?,
            decoded.req_id.slice(),
            &shortNodeId(&from),
            from_addr,
            decoded.enrs.len,
            accepted_enrs,
        });

        if (findnode.responses_received < findnode.total_responses.?) return;

        var completed = self.requests.finishActive(endpoint, decoded.req_id) orelse return;
        defer completed.deinit(self.alloc);
        if (completed.kind != .findnode) return;

        const owned_enrs = completed.kind.findnode.enrs.toOwnedSlice(self.alloc) catch return;
        completed.kind.findnode.enrs = .empty;
        self.event_queue.push(self.alloc, .{
            .nodes = .{
                .peer_id = from,
                .peer_addr = from_addr,
                .req_id = decoded.req_id,
                .enrs = owned_enrs,
            },
        }) catch {
            for (owned_enrs) |enr| self.alloc.free(enr);
            self.alloc.free(owned_enrs);
        };
        self.sendNextQueuedRequest(&from, from_addr, socket);
        scoped_log.debug("completed NODES response req_id={x} from node={s} addr={any} with {d} ENRs", .{
            decoded.req_id.slice(),
            &shortNodeId(&from),
            from_addr,
            owned_enrs.len,
        });
    }

    fn handleTalkReq(
        self: *Protocol,
        pt: []const u8,
        from: NodeId,
        from_addr: Address,
        socket: *const net.Socket,
    ) void {
        const talk_req = messages.TalkReq.decode(pt) catch |err| {
            scoped_log.debug("failed to decode TALKREQ from node={s} addr={any}: {}", .{
                &shortNodeId(&from),
                from_addr,
                err,
            });
            return;
        };
        self.noteReceivedMessage(pt);
        const protocol_name = self.alloc.dupe(u8, talk_req.protocol) catch return;
        const request = self.alloc.dupe(u8, talk_req.request) catch {
            self.alloc.free(protocol_name);
            return;
        };

        self.markNodeSeenAndPingEvictionCandidate(from, from_addr, socket);
        scoped_log.debug("received TALKREQ req_id={x} from node={s} addr={any} protocol={s} request_len={d}", .{
            talk_req.req_id.slice(),
            &shortNodeId(&from),
            from_addr,
            talk_req.protocol,
            talk_req.request.len,
        });
        self.event_queue.push(self.alloc, .{
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
        socket: *const net.Socket,
    ) void {
        const talk_resp = messages.TalkResp.decode(pt) catch |err| {
            scoped_log.debug("failed to decode TALKRESP from node={s} addr={any}: {}", .{
                &shortNodeId(&from),
                from_addr,
                err,
            });
            return;
        };
        self.noteReceivedMessage(pt);
        const endpoint = Endpoint{ .node_id = from, .addr = from_addr };
        var request = self.requests.finishActiveExpectingKind(endpoint, talk_resp.req_id, .talkreq) orelse {
            scoped_log.debug("received TALKRESP with no matching TALKREQ request req_id={x} from node={s} addr={any}", .{
                talk_resp.req_id.slice(),
                &shortNodeId(&from),
                from_addr,
            });
            return;
        };
        defer request.deinit(self.alloc);

        const response = self.alloc.dupe(u8, talk_resp.response) catch return;

        self.markNodeSeenAndPingEvictionCandidate(from, from_addr, socket);
        scoped_log.debug("received TALKRESP req_id={x} from node={s} addr={any} response_len={d}", .{
            talk_resp.req_id.slice(),
            &shortNodeId(&from),
            from_addr,
            talk_resp.response.len,
        });
        self.event_queue.push(self.alloc, .{
            .talkresp = .{
                .peer_id = from,
                .peer_addr = from_addr,
                .req_id = talk_resp.req_id,
                .response = response,
            },
        }) catch self.alloc.free(response);
        self.sendNextQueuedRequest(&from, from_addr, socket);
    }

    pub fn addNode(self: *Protocol, node_id: NodeId, pubkey: ?*const [33]u8, addr: Address, enr: ?[]const u8) void {
        if (enr) |enr_bytes| {
            if (self.entryFromEnr(enr_bytes, .disconnected, addr)) |decoded_entry| {
                var entry = decoded_entry;
                if (!std.mem.eql(u8, &entry.node_id, &node_id)) {
                    scoped_log.debug("ignoring addNode ENR/node-id mismatch expected={s} got={s} addr={any}", .{
                        &shortNodeId(&node_id),
                        &shortNodeId(&entry.node_id),
                        addr,
                    });
                    return;
                }
                if (pubkey) |pk| {
                    if (!std.mem.eql(u8, &entry.pubkey, pk)) {
                        scoped_log.debug("ignoring addNode ENR/pubkey mismatch node={s} addr={any}", .{
                            &shortNodeId(&node_id),
                            addr,
                        });
                        return;
                    }
                }
                // addNode is a local trust decision (for example, a configured
                // bootnode), unlike ENRs learned from an untrusted NODES reply.
                // Promote an equal/newer record already learned for this node;
                // the normal ENR insertion path intentionally ignores stale or
                // equal sequences and would otherwise lose the trust decision.
                if (self.routing_table.getEntryWithPending(&node_id)) |existing| {
                    if (existing.enr_seq >= entry.enr_seq) {
                        var trusted = existing.*;
                        trusted.locally_trusted = true;
                        trusted.relay_eligible = true;
                        _ = self.routing_table.insertDetailed(trusted);
                        return;
                    }
                }
                entry.locally_trusted = true;
                entry.relay_eligible = true;
                _ = self.insertEnrEntry(entry);
                return;
            }
            scoped_log.debug("addNode ENR was unusable; falling back to contact node={s} addr={any}", .{
                &shortNodeId(&node_id),
                addr,
            });
        }
        self.contacts.remember(node_id, pubkey, addr);
    }
};

fn markFindNodeDistance(seen: *[257]bool, distance: u16) bool {
    if (distance > 256 or seen[distance]) return false;
    seen[distance] = true;
    return true;
}

// =========== Tests ===========

test "maximum NODES response fits the accepted chunk bound" {
    const required = try std.math.divCeil(usize, MAX_NODES_RESPONSE, MAX_NODES_ENRS_PER_PACKET);
    try std.testing.expect(required <= MAX_NODES_RESPONSE_CHUNKS);
}

test "FINDNODE distance deduplication accepts each valid distance once" {
    var seen = [_]bool{false} ** 257;
    try std.testing.expect(markFindNodeDistance(&seen, 0));
    try std.testing.expect(!markFindNodeDistance(&seen, 0));
    try std.testing.expect(markFindNodeDistance(&seen, 256));
    try std.testing.expect(!markFindNodeDistance(&seen, 256));
    try std.testing.expect(!markFindNodeDistance(&seen, 257));
}

test "discv5 protocol: basic init" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = @import("enr.zig").nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
    });
    defer proto.deinit();

    try std.testing.expectEqual(@as(usize, 0), proto.routing_table.nodeCount());

    var node_id2: NodeId = [_]u8{0xbb} ** 32;
    node_id2[31] = 0x01;
    proto.addNode(node_id2, null, .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 30303 } }, null);
    try std.testing.expectEqual(@as(usize, 0), proto.routing_table.nodeCount());
}

test "discv5 protocol: session cache capacity is bounded" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const secret_key = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    const pubkey = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pubkey);

    const default_config = Config{ .local_key_pair = key_pair, .local_node_id = node_id };
    try std.testing.expectEqual(MAX_SESSIONS, default_config.session_cache_capacity);

    try std.testing.expectError(error.InvalidSessionCacheCapacity, Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .session_cache_capacity = 0,
    }));
    try std.testing.expectError(error.InvalidSessionCacheCapacity, Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .session_cache_capacity = MAX_SESSIONS + 1,
    }));
}

test "discv5 protocol metrics classify sent and received message counters" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;

    const sk = [_]u8{0x01} ** 32;
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
    });
    defer proto.deinit();

    proto.noteSentMessage(&[_]u8{ messages.MSG_PING, 0x00 });
    proto.noteSentMessage(&[_]u8{ messages.MSG_TALKRESP, 0x00 });

    var socket = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket.close(io);
    try proto.dispatchMessage(&[_]u8{messages.MSG_PING}, node_id, socket.address, &socket);
    try proto.dispatchMessage(&[_]u8{0xff}, node_id, socket.address, &socket);

    const valid_ping = messages.Ping{
        .req_id = try messages.ReqId.fromSlice(&[_]u8{0x01}),
        .enr_seq = 1,
    };
    const valid_ping_bytes = try valid_ping.encode(alloc);
    defer alloc.free(valid_ping_bytes);
    try proto.dispatchMessage(valid_ping_bytes, node_id, socket.address, &socket);

    const snapshot = proto.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), snapshot.sent_message_count[metrics_mod.MessageType.ping.index()]);
    try std.testing.expectEqual(@as(u64, 1), snapshot.sent_message_count[metrics_mod.MessageType.talkresp.index()]);
    try std.testing.expectEqual(@as(u64, 1), snapshot.rcvd_message_count[metrics_mod.MessageType.ping.index()]);
    try std.testing.expectEqual(@as(u64, 0), snapshot.rcvd_message_count[metrics_mod.MessageType.talkreq.index()]);
}

test "discv5 protocol: WHOAREYOU handshake round-trip" {
    // Simulate: node A sends request -> node B responds WHOAREYOU -> node A
    //           builds handshake -> node B receives and establishes session.
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    // Node A keys
    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_a = try secp.keyPairFromSecret(&sk_a);
    const pk_a = secp.compressedPubkey(&key_pair_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    // Node B keys
    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair_b = try secp.keyPairFromSecret(&sk_b);
    const pk_b = secp.compressedPubkey(&key_pair_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var socket_a = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close(io);
    var socket_b = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close(io);

    const addr_a = socket_a.address;
    const addr_b = socket_b.address;

    // Set up node A's protocol
    var proto_a = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_a,
        .local_node_id = node_id_a,
    });
    defer proto_a.deinit();

    // Set up node B's protocol
    var proto_b = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_b,
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

    try proto_a.sendRequest(&node_id_b, &pk_b, addr_b, ping.req_id, .ping, &.{}, ping_bytes, &socket_a);

    // Verify node A sent one packet and stored a pending request.
    try std.testing.expectEqual(@as(usize, 1), proto_a.requests.pendingCount());

    // Step 2: Node B receives the packet. Since no session exists, it responds
    // with WHOAREYOU.
    var recv_buf_b: [MAX_PACKET_SIZE]u8 = undefined;
    const inbound_a = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    // Node B should now have an active challenge separate from established sessions.
    try std.testing.expect(proto_b.getChallengeCopy(&node_id_a, addr_a) != null);
    try std.testing.expect(proto_b.getSessionCopy(&node_id_a, addr_a) == null);

    // A second unauthenticated MESSAGE from the same claimed endpoint must not
    // replace the live challenge and invalidate the legitimate handshake.
    const original_challenge = proto_b.getChallengeCopy(&node_id_a, addr_a).?;
    var duplicate_probe_buf: [MAX_PACKET_SIZE]u8 = undefined;
    const duplicate_probe = try proto_a.encodeProbePacketInto(&duplicate_probe_buf, &node_id_b, ping_bytes);
    try socket_a.send(io, &addr_b, duplicate_probe.pkt);
    const duplicate_inbound = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{ .raw = Io.Duration.fromMilliseconds(250), .clock = .awake },
    });
    try proto_b.handlePacket(duplicate_inbound.data, duplicate_inbound.from, &socket_b);
    const retained_challenge = proto_b.getChallengeCopy(&node_id_a, addr_a).?;
    try std.testing.expectEqualSlices(u8, &original_challenge.challenge_data, &retained_challenge.challenge_data);

    // Step 3: Node A receives the WHOAREYOU and responds with a handshake.
    var recv_buf_a: [MAX_PACKET_SIZE]u8 = undefined;
    const inbound_b = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound_b.data, inbound_b.from, &socket_a);

    // Node A keeps provisional keys on the active request only; the session
    // cache remains established-only until B proves it accepted the handshake.
    try std.testing.expect(proto_a.getSessionCopy(&node_id_b, addr_b) == null);

    // The pending request should be consumed.
    try std.testing.expectEqual(@as(usize, 0), proto_a.requests.pendingCount());

    const queued_req_id = try proto_a.sendPing(
        &node_id_b,
        &pk_b,
        addr_b,
        1,
        &socket_a,
    );
    try std.testing.expect(queued_req_id.len > 0);

    // Step 4: Node B receives the handshake.
    const handshake = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    // Node B should now have an established session.
    try std.testing.expect(proto_b.getSessionCopy(&node_id_a, addr_a) != null);

    // Step 5: Node A receives B's post-handshake PONG.
    const pong_packet = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(pong_packet.data, pong_packet.from, &socket_a);

    try std.testing.expect(proto_a.getSessionCopy(&node_id_b, addr_b) != null);

    // Drain the request that was queued behind the initial handshake.
    const queued_ping = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{ .raw = Io.Duration.fromMilliseconds(250), .clock = .awake },
    });
    try proto_b.handlePacket(queued_ping.data, queued_ping.from, &socket_b);
    const queued_pong = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{ .raw = Io.Duration.fromMilliseconds(250), .clock = .awake },
    });
    try proto_a.handlePacket(queued_pong.data, queued_pong.from, &socket_a);
    try std.testing.expect(proto_a.requests.getActivePtr(.{ .node_id = node_id_b, .addr = addr_b }, queued_req_id) == null);

    // If B forgets the established session, A's next authenticated request is
    // challenged and must rekey instead of remaining stuck on stale keys.
    try std.testing.expect(proto_b.session_store.removeSession(.{ .node_id = node_id_a, .addr = addr_a }));
    const rekey_req_id = try proto_a.sendPing(&node_id_b, &pk_b, addr_b, 1, &socket_a);

    const stale_message = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{ .raw = Io.Duration.fromMilliseconds(250), .clock = .awake },
    });
    try proto_b.handlePacket(stale_message.data, stale_message.from, &socket_b);

    const rekey_challenge = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{ .raw = Io.Duration.fromMilliseconds(250), .clock = .awake },
    });
    try proto_a.handlePacket(rekey_challenge.data, rekey_challenge.from, &socket_a);

    const rekey_handshake = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{ .raw = Io.Duration.fromMilliseconds(250), .clock = .awake },
    });
    try proto_b.handlePacket(rekey_handshake.data, rekey_handshake.from, &socket_b);
    try std.testing.expect(proto_b.getChallengeCopy(&node_id_a, addr_a) == null);
    try std.testing.expect(proto_b.getSessionCopy(&node_id_a, addr_a) != null);
    try std.testing.expectEqual(@as(u64, 3), proto_b.metricsSnapshot().sent_message_count[metrics_mod.MessageType.pong.index()]);

    const rekey_pong = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{ .raw = Io.Duration.fromMilliseconds(250), .clock = .awake },
    });
    try proto_a.handlePacket(rekey_pong.data, rekey_pong.from, &socket_a);

    try std.testing.expect(proto_a.getSessionCopy(&node_id_b, addr_b) != null);
    try std.testing.expect(proto_b.getSessionCopy(&node_id_a, addr_a) != null);
    try std.testing.expect(proto_a.requests.getActivePtr(.{ .node_id = node_id_b, .addr = addr_b }, rekey_req_id) == null);
}

test "discv5 protocol: FINDNODE only relays trusted or liveness-verified ENRs" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_a = try secp.keyPairFromSecret(&sk_a);
    const pk_a = secp.compressedPubkey(&key_pair_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair_b = try secp.keyPairFromSecret(&sk_b);
    const pk_b = secp.compressedPubkey(&key_pair_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    const sk_c = hex.hexToBytesComptime(32, "7e8107fe766b7f1821c3a7fbc56d18f734f0ebf898f0b85f82412b6d1fa7f4d3");
    const key_pair_c = try secp.keyPairFromSecret(&sk_c);
    const pk_c = secp.compressedPubkey(&key_pair_c);
    const node_id_c = enr_mod.nodeIdFromCompressedPubkey(&pk_c);

    var socket_a = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close(io);
    var socket_b = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close(io);

    const addr_a = socket_a.address;
    const addr_b = socket_b.address;
    const addr_c = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30305 } };

    var a_builder = enr_mod.Builder.init(alloc, key_pair_a, 1);
    a_builder.ip = switch (addr_a) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => unreachable,
    };
    a_builder.udp = addr_a.getPort();
    const a_enr = try a_builder.encode();
    defer alloc.free(a_enr);

    var b_builder = enr_mod.Builder.init(alloc, key_pair_b, 1);
    b_builder.ip = switch (addr_b) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => unreachable,
    };
    b_builder.udp = addr_b.getPort();
    const b_enr = try b_builder.encode();
    defer alloc.free(b_enr);

    var c_builder = enr_mod.Builder.init(alloc, key_pair_c, 1);
    c_builder.ip = switch (addr_c) {
        .ip4 => |ip4| ip4.bytes,
        .ip6 => unreachable,
    };
    c_builder.udp = addr_c.getPort();
    const c_enr = try c_builder.encode();
    defer alloc.free(c_enr);

    var proto_a = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_a,
        .local_node_id = node_id_a,
        .local_enr = a_enr,
        .local_enr_seq = 1,
    });
    defer proto_a.deinit();

    var proto_b = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_b,
        .local_node_id = node_id_b,
        .local_enr = b_enr,
        .local_enr_seq = 1,
    });
    defer proto_b.deinit();

    proto_a.addNode(node_id_b, &pk_b, addr_b, b_enr);
    proto_b.addNode(node_id_a, &pk_a, addr_a, a_enr);
    // Model an ENR learned from an untrusted NODES response. Locally configured
    // entries use addNode and are eligible for relay immediately.
    proto_b.rememberEnr(c_enr);
    try std.testing.expect(proto_a.routing_table.getEntry(&node_id_b).?.relay_eligible);
    try std.testing.expect(!proto_b.routing_table.getEntry(&node_id_c).?.relay_eligible);

    const c_distance = kbucket.logDistance(&node_id_b, &node_id_c) orelse return error.NoDistance;
    const distances = [_]u16{ 0, @as(u16, c_distance) + 1 };
    _ = try proto_a.sendFindNode(&node_id_b, &pk_b, addr_b, &distances, &socket_a);

    var recv_buf_a: [MAX_PACKET_SIZE]u8 = undefined;
    var recv_buf_b: [MAX_PACKET_SIZE]u8 = undefined;

    const inbound_a = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    const inbound_b = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound_b.data, inbound_b.from, &socket_a);

    const handshake = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(handshake.data, handshake.from, &socket_b);

    const nodes_packet = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(nodes_packet.data, nodes_packet.from, &socket_a);

    try std.testing.expectEqual(@as(usize, 0), proto_a.requests.activeCount());

    var event = proto_a.popEvent() orelse return error.MissingNodesEvent;
    defer event.deinit(alloc);
    try std.testing.expect(event == .nodes);
    try std.testing.expectEqual(node_id_b, event.nodes.peer_id);
    try std.testing.expectEqual(@as(usize, 1), event.nodes.enrs.len);

    var saw_b = false;
    var saw_c = false;
    for (event.nodes.enrs) |raw_enr| {
        const parsed = try enr_mod.decode(raw_enr);
        const node_id = parsed.nodeId() orelse continue;
        if (std.mem.eql(u8, &node_id, &node_id_b)) saw_b = true;
        if (std.mem.eql(u8, &node_id, &node_id_c)) saw_c = true;
    }
    try std.testing.expect(saw_b);
    try std.testing.expect(!saw_c);

    const mismatched_c_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30306 } };
    _ = proto_b.markNodeSeen(node_id_c, mismatched_c_addr, .connected);
    try std.testing.expect(!proto_b.routing_table.getEntry(&node_id_c).?.relay_eligible);

    _ = proto_b.markNodeSeen(node_id_c, addr_c, .connected);
    try std.testing.expect(proto_b.routing_table.getEntry(&node_id_c).?.relay_eligible);
    var learned_c = proto_b.routing_table.getEntry(&node_id_c).?.*;
    learned_c.relay_eligible = false;
    learned_c.locally_trusted = false;
    try std.testing.expect(proto_b.routing_table.insert(learned_c));

    // A later local trust decision must promote an already learned equal-sequence
    // ENR instead of being discarded by the normal stale-ENR check.
    proto_b.addNode(node_id_c, &pk_c, addr_c, c_enr);
    try std.testing.expect(proto_b.routing_table.getEntry(&node_id_c).?.relay_eligible);

    _ = try proto_a.sendFindNode(&node_id_b, &pk_b, addr_b, &distances, &socket_a);

    const verified_request = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(verified_request.data, verified_request.from, &socket_b);

    const verified_response = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(verified_response.data, verified_response.from, &socket_a);

    var verified_event = proto_a.popEvent() orelse return error.MissingNodesEvent;
    defer verified_event.deinit(alloc);
    try std.testing.expect(verified_event == .nodes);
    try std.testing.expectEqual(@as(usize, 2), verified_event.nodes.enrs.len);

    saw_c = false;
    for (verified_event.nodes.enrs) |raw_enr| {
        const parsed = try enr_mod.decode(raw_enr);
        const node_id = parsed.nodeId() orelse continue;
        if (std.mem.eql(u8, &node_id, &node_id_c)) saw_c = true;
    }
    try std.testing.expect(saw_c);
}

test "discv5 protocol: TALKREQ/TALKRESP round-trip produces events" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_a = try secp.keyPairFromSecret(&sk_a);
    const pk_a = secp.compressedPubkey(&key_pair_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair_b = try secp.keyPairFromSecret(&sk_b);
    const pk_b = secp.compressedPubkey(&key_pair_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var socket_a = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close(io);
    var socket_b = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close(io);

    const addr_a = socket_a.address;
    const addr_b = socket_b.address;

    var proto_a = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_a,
        .local_node_id = node_id_a,
    });
    defer proto_a.deinit();

    var proto_b = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_b,
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

    const inbound_a = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    const inbound_b = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound_b.data, inbound_b.from, &socket_a);

    const handshake = try socket_b.receiveTimeout(io, &recv_buf_b, .{
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

    const response_packet = try socket_a.receiveTimeout(io, &recv_buf_a, .{
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
    const hex = @import("hex");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_a = try secp.keyPairFromSecret(&sk_a);
    const pk_a = secp.compressedPubkey(&key_pair_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair_b = try secp.keyPairFromSecret(&sk_b);
    const pk_b = secp.compressedPubkey(&key_pair_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var socket_a = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close(io);

    var proto_a = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_a,
        .local_node_id = node_id_a,
        .request_timeout_ms = 1,
        .request_retries = 0,
    });
    defer proto_a.deinit();

    const addr_b = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } };
    proto_a.addNode(node_id_b, &pk_b, addr_b, null);

    const req_id = try proto_a.sendPing(&node_id_b, &pk_b, addr_b, 1, &socket_a);
    try std.testing.expectEqual(@as(usize, 1), proto_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), proto_a.requests.pendingCount());

    proto_a.requests.forceAllActiveStartedAtForTest(0);

    proto_a.pruneExpiredState();

    try std.testing.expectEqual(@as(usize, 0), proto_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), proto_a.requests.pendingCount());

    var event = proto_a.popEvent() orelse return error.MissingTimeoutEvent;
    defer event.deinit(alloc);
    try std.testing.expect(event == .request_timeout);
    try std.testing.expectEqual(node_id_b, event.request_timeout.peer_id);
    try std.testing.expectEqualSlices(u8, req_id.slice(), event.request_timeout.req_id.slice());
    try std.testing.expectEqual(RequestKind.ping, event.request_timeout.kind);
}

test "discv5 protocol: WHOAREYOU requires matching pending nonce and address" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_a = try secp.keyPairFromSecret(&sk_a);
    const pk_a = secp.compressedPubkey(&key_pair_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const key_pair_b = try secp.keyPairFromSecret(&sk_b);
    const pk_b = secp.compressedPubkey(&key_pair_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    var socket_a = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close(io);
    var socket_b = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close(io);

    const addr_a = socket_a.address;
    const addr_b = socket_b.address;

    var proto_a = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_a,
        .local_node_id = node_id_a,
    });
    defer proto_a.deinit();

    var proto_b = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_b,
        .local_node_id = node_id_b,
    });
    defer proto_b.deinit();
    proto_b.addNode(node_id_a, &pk_a, addr_a, null);

    const ping = messages.Ping{
        .req_id = try messages.ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x01 }),
        .enr_seq = 1,
    };
    const ping_bytes = try ping.encode(alloc);
    defer alloc.free(ping_bytes);

    try proto_a.sendRequest(&node_id_b, &pk_b, addr_b, ping.req_id, .ping, &.{}, ping_bytes, &socket_a);
    try std.testing.expectEqual(@as(usize, 1), proto_a.requests.pendingCount());

    // Simulate a stale pending nonce while keeping the destination address
    // intact. Gold TS behavior rejects this rather than falling back to address.
    try std.testing.expect(proto_a.requests.forceFirstProbeNonceForTest([_]u8{0xaa} ** 12));

    var recv_buf_b: [MAX_PACKET_SIZE]u8 = undefined;
    const inbound_a = try socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_b.handlePacket(inbound_a.data, inbound_a.from, &socket_b);

    var recv_buf_a: [MAX_PACKET_SIZE]u8 = undefined;
    const inbound_b = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound_b.data, inbound_b.from, &socket_a);

    try std.testing.expect(proto_a.getSessionCopy(&node_id_b, addr_b) == null);
    try std.testing.expectEqual(@as(usize, 1), proto_a.requests.pendingCount());
}

test "discv5 protocol: unsolicited WHOAREYOU is ignored" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair_a = try secp.keyPairFromSecret(&sk_a);
    const pk_a = secp.compressedPubkey(&key_pair_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    var socket_a = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_a.close(io);
    var socket_b = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket_b.close(io);

    const addr_a = socket_a.address;

    var proto_a = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair_a,
        .local_node_id = node_id_a,
    });
    defer proto_a.deinit();

    var request_nonce: [12]u8 = [_]u8{0x42} ** 12;
    var id_nonce: [16]u8 = [_]u8{0x24} ** 16;
    var masking_iv: [16]u8 = [_]u8{0x11} ** 16;

    var whoareyou_buf: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const whoareyou = try packet.encodeWhoareyouPacketInto(&whoareyou_buf, .{
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id_a,
        .request_nonce = &request_nonce,
        .id_nonce = &id_nonce,
        .enr_seq = 0,
    }, null);

    try socket_b.send(io, &addr_a, whoareyou);

    var recv_buf_a: [MAX_PACKET_SIZE]u8 = undefined;
    const inbound = try socket_a.receiveTimeout(io, &recv_buf_a, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(250),
            .clock = .awake,
        },
    });
    try proto_a.handlePacket(inbound.data, inbound.from, &socket_a);

    try std.testing.expectEqual(@as(usize, 0), proto_a.requests.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), proto_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), proto_a.activeSessionCount());
    try std.testing.expect(proto_a.popEvent() == null);

    var recv_buf_b: [MAX_PACKET_SIZE]u8 = undefined;
    try std.testing.expectError(error.Timeout, socket_b.receiveTimeout(io, &recv_buf_b, .{
        .duration = .{
            .raw = Io.Duration.fromMilliseconds(50),
            .clock = .awake,
        },
    }));
}

test "discv5 protocol: WHOAREYOU rate limiter is bounded" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;

    const sk = [_]u8{0x01} ** 32;
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .whoareyou_rate_capacity = 2,
    });
    defer proto.deinit();

    const addr_a = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } };
    const addr_b = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 30303 } };
    const addr_c = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 30303 } };

    var i: u32 = 0;
    while (i < MAX_WHOAREYOU_PER_SEC) : (i += 1) {
        try std.testing.expect(proto.allowWhoareyou(addr_a));
    }
    try std.testing.expect(!proto.allowWhoareyou(addr_a));

    try std.testing.expect(proto.allowWhoareyou(addr_b));
    try std.testing.expect(proto.allowWhoareyou(addr_c));
    try std.testing.expectEqual(@as(usize, 2), proto.session_store.whoareyou_rate.count());
}

test "discv5 protocol: handlePacket does not prune expired state" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
    });
    defer proto.deinit();

    var socket = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket.close(io);

    const peer_id = [_]u8{0x55} ** 32;
    const req_id = try messages.ReqId.fromSlice(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    try proto.requests.putActiveAwaitingResponse(
        Endpoint{ .node_id = peer_id, .addr = socket.address },
        req_id,
        .ping,
        &.{},
        &socket,
        &[_]u8{0x99},
        0,
        null,
    );

    var raw = [_]u8{0x00};
    try proto.handlePacket(&raw, socket.address, &socket);

    try std.testing.expectEqual(@as(usize, 1), proto.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), proto.event_queue.pending());
}

test "discv5 protocol: request retries delay timeout event" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .request_timeout_ms = 1,
        .request_retries = 1,
    });
    defer proto.deinit();

    const peer_id = [_]u8{0x33} ** 32;
    const req_id = try messages.ReqId.fromSlice(&[_]u8{ 0x0a, 0x0b, 0x0c, 0x0d });
    var socket = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket.close(io);
    const endpoint = Endpoint{ .node_id = peer_id, .addr = socket.address };
    try proto.requests.putActiveAwaitingResponse(
        endpoint,
        req_id,
        .ping,
        &.{},
        &socket,
        &[_]u8{0x99},
        0,
        null,
    );

    proto.pruneExpiredRequests(std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), proto.requests.activeCount());
    try std.testing.expect(proto.popEvent() == null);
    const retried = proto.requests.getActivePtr(endpoint, req_id) orelse return error.MissingRetriedRequest;
    try std.testing.expectEqual(@as(u32, 1), retried.attempts);

    proto.pruneExpiredRequests(2 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 0), proto.requests.activeCount());
    var event = proto.popEvent() orelse return error.MissingTimeoutEvent;
    defer event.deinit(alloc);
    try std.testing.expect(event == .request_timeout);
    try std.testing.expectEqual(RequestKind.ping, event.request_timeout.kind);
    try std.testing.expectEqualSlices(u8, req_id.slice(), event.request_timeout.req_id.slice());
}

test "discv5 protocol: active timeout advances queued request as new probe" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .request_timeout_ms = 1,
        .request_retries = 0,
    });
    defer proto.deinit();

    var socket = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket.close(io);

    const peer_id = [_]u8{0x45} ** 32;
    const peer_pk = [_]u8{0x02} ++ [_]u8{0x45} ** 32;
    const endpoint = Endpoint{ .node_id = peer_id, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } } };
    const active_req_id = try messages.ReqId.fromSlice(&[_]u8{0x01});
    const queued_req_id = try messages.ReqId.fromSlice(&[_]u8{0x02});
    const plaintext = [_]u8{ messages.MSG_PING, 0x01, 0x02 };

    try proto.requests.putActiveProbe(
        endpoint,
        active_req_id,
        .ping,
        &.{},
        &socket,
        &[_]u8{0x99},
        0,
        [_]u8{0xbb} ** packet.NONCE_SIZE,
        &peer_pk,
        &plaintext,
    );
    try proto.requests.queueRequest(endpoint, &peer_pk, queued_req_id, .ping, &.{}, &plaintext, 0);

    proto.pruneExpiredRequests(std.time.ns_per_ms);

    try std.testing.expectEqual(@as(usize, 1), proto.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), proto.requests.pendingCount());
    var event = proto.popEvent() orelse return error.MissingTimeoutEvent;
    defer event.deinit(alloc);
    try std.testing.expect(event == .request_timeout);
    try std.testing.expectEqualSlices(u8, active_req_id.slice(), event.request_timeout.req_id.slice());
}

test "discv5 protocol: explicit queued request drop emits timeout events" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const node_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .request_timeout_ms = 1,
        .request_retries = 1,
    });
    defer proto.deinit();

    const peer_id = [_]u8{0x44} ** 32;
    const peer_pk = [_]u8{0x02} ++ [_]u8{0x44} ** 32;
    const endpoint = Endpoint{ .node_id = peer_id, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } } };
    try proto.requests.queueRequest(
        endpoint,
        &peer_pk,
        try messages.ReqId.fromSlice(&[_]u8{0x01}),
        .ping,
        &.{},
        &[_]u8{ messages.MSG_PING, 0x01, 0x02, 0x03 },
        0,
    );

    var expired: std.ArrayListUnmanaged(ExpiredRequest) = .empty;
    defer expired.deinit(alloc);
    try proto.requests.dropQueuedForEndpoint(endpoint, &expired);
    for (expired.items) |request| proto.appendRequestTimeout(request);
    try std.testing.expectEqual(@as(usize, 0), proto.requests.pendingCount());
    var event = proto.popEvent() orelse return error.MissingTimeoutEvent;
    defer event.deinit(alloc);
    try std.testing.expect(event == .request_timeout);
    try std.testing.expectEqual(RequestKind.ping, event.request_timeout.kind);
}

test "discv5 protocol: session cache expires by TTL and bounds by LRU capacity" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const local_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var ttl_proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = local_id,
        .session_timeout_ms = 1,
        .session_cache_capacity = 4,
    });
    defer ttl_proto.deinit();

    const ttl_peer = [_]u8{0x11} ** 32;
    const ttl_addr = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 30303 } };
    ttl_proto.putSession(&ttl_peer, ttl_addr, .{
        .node_id = ttl_peer,
        .initiator_key = [_]u8{0x01} ** 16,
        .recipient_key = [_]u8{0x02} ** 16,
        .seen_nonces = SeenNonces.init(),
    });
    try std.testing.expect(ttl_proto.getSessionCopy(&ttl_peer, ttl_addr) != null);
    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1100), .awake);
    try std.testing.expect(ttl_proto.getSessionCopy(&ttl_peer, ttl_addr) == null);

    var lru_proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = local_id,
        .session_cache_capacity = 2,
    });
    defer lru_proto.deinit();

    inline for (0..3) |i| {
        var peer = [_]u8{@as(u8, @intCast(0x20 + i))} ** 32;
        const peer_addr = Address{ .ip4 = .{
            .bytes = .{ 127, 0, 0, 1 },
            .port = @as(u16, @intCast(30310 + i)),
        } };
        lru_proto.putSession(&peer, peer_addr, .{
            .node_id = peer,
            .initiator_key = [_]u8{@as(u8, @intCast(i + 1))} ** 16,
            .recipient_key = [_]u8{@as(u8, @intCast(i + 11))} ** 16,
            .seen_nonces = SeenNonces.init(),
        });
    }
    try std.testing.expect(lru_proto.activeSessionCount() <= 2);
}

test "discv5 protocol: endpoint caches use semantic address identity" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const local_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = local_id,
    });
    defer proto.deinit();

    const peer = [_]u8{0x55} ** 32;
    const addr_a = Address{ .ip6 = .{
        .bytes = [_]u8{0xaa} ** 16,
        .port = 30303,
        .flow = 1,
    } };
    const addr_b = Address{ .ip6 = .{
        .bytes = [_]u8{0xaa} ** 16,
        .port = 30303,
        .flow = 2,
    } };

    proto.putSession(&peer, addr_a, .{
        .node_id = peer,
        .initiator_key = [_]u8{0x01} ** 16,
        .recipient_key = [_]u8{0x02} ** 16,
        .seen_nonces = SeenNonces.init(),
    });
    try std.testing.expect(proto.getSessionCopy(&peer, addr_b) != null);

    proto.putChallenge(&peer, addr_a, .{
        .challenge_data = [_]u8{0x03} ** CHALLENGE_DATA_SIZE,
    });
    try std.testing.expect(proto.getChallengeCopy(&peer, addr_b) != null);
}

test "discv5 protocol: WHOAREYOU challenge state is separate from established session cache" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const hex = @import("hex");

    const sk = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const key_pair = try secp.keyPairFromSecret(&sk);
    const pk = secp.compressedPubkey(&key_pair);
    const local_id = enr_mod.nodeIdFromCompressedPubkey(&pk);

    var proto = try Protocol.init(io, alloc, .{
        .local_key_pair = key_pair,
        .local_node_id = local_id,
    });
    defer proto.deinit();

    var socket = try bindDatagramSocket(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer socket.close(io);

    const peer = [_]u8{0x66} ** 32;
    const nonce = [_]u8{0x77} ** 12;
    try proto.sendWhoareyou(peer, &nonce, socket.address, &socket);

    try std.testing.expect(proto.getSessionCopy(&peer, socket.address) == null);
    const challenge = proto.getChallengeCopy(&peer, socket.address) orelse return error.MissingChallenge;
    try std.testing.expect(!std.mem.allEqual(u8, &challenge.challenge_data, 0));
}
