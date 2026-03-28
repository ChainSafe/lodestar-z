//! Discovery v5 protocol handler

const std = @import("std");
const Allocator = std.mem.Allocator;
const NodeId = @import("enr.zig").NodeId;
const kbucket = @import("kbucket.zig");
const packet = @import("packet.zig");
const session_mod = @import("session.zig");
const messages = @import("messages.zig");
const transport_mod = @import("transport.zig");
const secp = @import("secp256k1.zig");
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

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

/// A pending outgoing request awaiting a WHOAREYOU challenge.
/// When we send an ordinary message to a node without a session, the remote
/// responds with WHOAREYOU. We store the original message here so we can
/// re-send it inside the handshake response.
pub const PendingRequest = struct {
    nonce: [12]u8,
    dest_node_id: NodeId,
    dest_pubkey: [33]u8,
    dest_addr: transport_mod.Address,
    message_plaintext: []u8,
    alloc: Allocator,

    fn deinit(self: *PendingRequest) void {
        self.alloc.free(self.message_plaintext);
    }
};

pub const Config = struct {
    local_secret_key: [32]u8,
    local_node_id: NodeId,
    listen_addr: transport_mod.Address,
    /// Pre-encoded local ENR (RLP bytes). Included in handshake when remote
    /// has a stale enr-seq.
    local_enr: ?[]const u8 = null,
    /// Sequence number of our local ENR.
    local_enr_seq: u64 = 0,
};

/// Per-IP rate-limit state for outgoing WHOAREYOU packets.
const WhoareyouRateEntry = struct {
    count: u32,
    window_start_ns: i128,
};

pub const Protocol = struct {
    alloc: Allocator,
    config: Config,
    routing_table: kbucket.RoutingTable,
    sessions: std.AutoHashMap(NodeId, Session),
    pending_requests: std.ArrayList(PendingRequest),
    whoareyou_rate: std.AutoHashMap([4]u8, WhoareyouRateEntry),
    rng: std.Random.DefaultPrng,
    /// Known static public keys for peers, keyed by node-id.
    /// Required to verify id-nonce signatures in incoming handshakes.
    node_pubkeys: std.AutoHashMap(NodeId, [33]u8),

    pub fn init(alloc: Allocator, config: Config) !Protocol {
        var seed_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&seed_bytes);
        const seed = std.mem.readInt(u64, &seed_bytes, .little);
        return .{
            .alloc = alloc,
            .config = config,
            .routing_table = kbucket.RoutingTable.init(alloc, config.local_node_id),
            .sessions = std.AutoHashMap(NodeId, Session).init(alloc),
            .pending_requests = .empty,
            .whoareyou_rate = std.AutoHashMap([4]u8, WhoareyouRateEntry).init(alloc),
            .rng = std.Random.DefaultPrng.init(seed),
            .node_pubkeys = std.AutoHashMap(NodeId, [33]u8).init(alloc),
        };
    }

    pub fn deinit(self: *Protocol) void {
        for (self.pending_requests.items) |*p| p.deinit();
        self.pending_requests.deinit(self.alloc);
        self.routing_table.deinit();
        self.sessions.deinit();
        self.whoareyou_rate.deinit();
        self.node_pubkeys.deinit();
    }

    /// Prune stale whoareyou_rate entries.
    ///
    /// Entries older than 60 seconds are removed. This prevents the per-IP
    /// rate-limit map from growing unboundedly when the node encounters many
    /// unique IPs over time (e.g., during DHT crawls or amplification attacks).
    ///
    /// Call periodically (e.g., every minute or at slot boundaries).
    pub fn pruneWhoareyouRate(self: *Protocol) void {
        const now_ns = std.time.nanoTimestamp();
        const max_age_ns: i128 = 60 * std.time.ns_per_s;

        var to_remove = std.ArrayList([4]u8).init(self.alloc);
        defer to_remove.deinit();

        var it = self.whoareyou_rate.iterator();
        while (it.next()) |entry| {
            if (now_ns - entry.value_ptr.window_start_ns > max_age_ns) {
                to_remove.append(entry.key_ptr.*) catch continue;
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
        var id: messages.ReqId = .{ .bytes = undefined, .len = 4 };
        self.rng.random().bytes(id.bytes[0..4]);
        return id;
    }

    /// Send a request to a remote node. If we have an established session,
    /// the message is encrypted and sent immediately. Otherwise, we send an
    /// ordinary message (which will likely be challenged with WHOAREYOU) and
    /// store the request as pending so we can re-send it in the handshake.
    pub fn sendRequest(
        self: *Protocol,
        dest_node_id: *const NodeId,
        dest_pubkey: *const [33]u8,
        dest_addr: transport_mod.Address,
        msg_bytes: []const u8,
        t: transport_mod.Transport,
    ) !void {
        if (self.sessions.get(dest_node_id.*)) |s| {
            if (s.state == .established) {
                try self.sendOrdinaryMessage(dest_node_id, &s.initiator_key, dest_addr, msg_bytes, t);
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

        try t.send(dest_addr, pkt);

        // Store the pending request so handleWhoareyou can find it.
        const pt_copy = try self.alloc.dupe(u8, msg_bytes);
        errdefer self.alloc.free(pt_copy);
        try self.pending_requests.append(self.alloc, .{
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
        from: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        // Drop oversized packets before any decoding work (CL-2020-06, spec max = IPv6 min MTU).
        if (raw.len > MAX_PACKET_SIZE) return;

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
        from: transport_mod.Address,
        t: transport_mod.Transport,
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
                std.crypto.random.bytes(&eph_seckey);
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
        try t.send(from, handshake_pkt);

        // Store the new session.
        try self.sessions.put(pending.dest_node_id, .{
            .node_id = pending.dest_node_id,
            .state = .established,
            .challenge_data = undefined,
            .challenge_data_len = 0,
            .initiator_key = keys.initiator_key,
            .recipient_key = keys.recipient_key,
            .next_nonce = nonce,
        });
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

        // Resolve sender's static public key.
        // First check our known-peer map; fall back to an optional ENR in the handshake.
        const sender_pubkey: [33]u8 = blk: {
            if (self.node_pubkeys.get(src_id)) |pk| break :blk pk;
            // Try to extract pubkey from an optional ENR appended to the authdata.
            const enr_offset = 34 + @as(usize, sig_size) + @as(usize, eph_key_size);
            if (authdata.len > enr_offset) {
                const enr_bytes = authdata[enr_offset..];
                const enr_mod = @import("enr.zig");
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
        try self.sessions.put(src_id, new_session);
    }

    fn sendWhoareyou(
        self: *Protocol,
        src_id: NodeId,
        request_nonce: *const [12]u8,
        dest: transport_mod.Address,
        t: transport_mod.Transport,
    ) !void {
        // Rate-limit WHOAREYOU responses per source IP to prevent amplification (CL-2020-08).
        const now_ns = std.time.nanoTimestamp();
        const gop = try self.whoareyou_rate.getOrPut(dest.ip);
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
            .next_nonce = undefined,
        };
        @memcpy(s.challenge_data[0..16], &masking_iv);
        @memcpy(s.challenge_data[16..s.challenge_data_len], header_raw_cd[0 .. s.challenge_data_len - 16]);
        try self.sessions.put(src_id, s);

        try t.send(dest, whoareyou_packet);
    }

    fn sendOrdinaryMessage(
        self: *Protocol,
        dest_node_id: *const NodeId,
        write_key: *const [16]u8,
        dest_addr: transport_mod.Address,
        msg_bytes: []const u8,
        t: transport_mod.Transport,
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

        try t.send(dest_addr, pkt);
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

        // Query routing table for nodes at requested distances and build ENR list.
        // Per discv5 spec, cap at MAX_NODES_RESPONSE (16) total.
        var enr_list: [MAX_NODES_RESPONSE][]const u8 = undefined;
        var enr_count: usize = 0;
        var alloc_count: usize = 0;

        for (fn_msg.distances) |dist| {
            // Distance 256 is reserved in discv5 (would mean "all nodes"); skip it.
            if (dist > 255) continue;
            const entries = self.routing_table.getBucket(@intCast(dist));
            for (entries) |entry| {
                if (enr_count >= MAX_NODES_RESPONSE) break;
                // Encode each node as its raw addr bytes (6 bytes: ip4 + port).
                // Full RLP-encoded ENR is a follow-up; addr bytes ensure we contribute to the DHT.
                const encoded = self.alloc.dupe(u8, &entry.addr) catch continue;
                enr_list[enr_count] = encoded;
                enr_count += 1;
                alloc_count += 1;
            }
            if (enr_count >= MAX_NODES_RESPONSE) break;
        }

        const enr_slice = enr_list[0..enr_count];
        defer {
            for (enr_list[0..alloc_count]) |e| self.alloc.free(e);
        }

        const nodes_msg = messages.Nodes{
            .req_id = fn_msg.req_id,
            .total = 1,
            .enrs = enr_slice,
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

    pub fn addNode(self: *Protocol, node_id: NodeId, pubkey: ?*const [33]u8, addr: transport_mod.Address) void {
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
        if (pubkey) |pk| {
            self.node_pubkeys.put(node_id, pk.*) catch {};
        }
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
    proto.addNode(node_id2, null, .{ .ip = [4]u8{ 192, 168, 1, 1 }, .port = 30303 });
    try std.testing.expectEqual(@as(usize, 1), proto.routing_table.nodeCount());
}

test "discv5 protocol: WHOAREYOU handshake round-trip" {
    // Simulate: node A sends request -> node B responds WHOAREYOU -> node A
    //           builds handshake -> node B receives and establishes session.
    const alloc = std.testing.allocator;
    const hex = @import("hex.zig");
    const enr_mod = @import("enr.zig");

    // Node A keys
    const sk_a = hex.hexToBytesComptime(32, "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f");
    const pk_a = try secp.pubkeyFromSecret(&sk_a);
    const node_id_a = enr_mod.nodeIdFromCompressedPubkey(&pk_a);

    // Node B keys
    const sk_b = hex.hexToBytesComptime(32, "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb14571f7");
    const pk_b = try secp.pubkeyFromSecret(&sk_b);
    const node_id_b = enr_mod.nodeIdFromCompressedPubkey(&pk_b);

    const addr_a = transport_mod.Address{ .ip = [4]u8{ 127, 0, 0, 1 }, .port = 9000 };
    const addr_b = transport_mod.Address{ .ip = [4]u8{ 127, 0, 0, 1 }, .port = 9001 };

    // Set up node A's protocol
    var proto_a = try Protocol.init(alloc, .{
        .local_secret_key = sk_a,
        .local_node_id = node_id_a,
        .listen_addr = addr_a,
    });
    defer proto_a.deinit();

    // Set up node B's protocol
    var proto_b = try Protocol.init(alloc, .{
        .local_secret_key = sk_b,
        .local_node_id = node_id_b,
        .listen_addr = addr_b,
    });
    defer proto_b.deinit();
    // Pre-register node A's static pubkey so B can verify A's id-nonce signature.
    proto_b.addNode(node_id_a, &pk_a, addr_a);

    // Transport mocks
    var mock_a = transport_mod.MockTransport.init(alloc, addr_a);
    defer mock_a.deinit();
    var mock_b = transport_mod.MockTransport.init(alloc, addr_b);
    defer mock_b.deinit();

    const t_a = mock_a.transport();
    const t_b = mock_b.transport();

    // Step 1: Node A sends a PING to node B (no session exists).
    const ping = messages.Ping{
        .req_id = try messages.ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x01 }),
        .enr_seq = 1,
    };
    const ping_bytes = try ping.encode(alloc);
    defer alloc.free(ping_bytes);

    try proto_a.sendRequest(&node_id_b, &pk_b, addr_b, ping_bytes, t_a);

    // Verify node A sent one packet and stored a pending request.
    try std.testing.expectEqual(@as(usize, 1), mock_a.sent.items.len);
    try std.testing.expectEqual(@as(usize, 1), proto_a.pending_requests.items.len);

    // Step 2: Node B receives the packet. Since no session exists, it responds
    // with WHOAREYOU.
    const pkt1 = mock_a.sent.items[0].data;
    try proto_b.handlePacket(pkt1, addr_a, t_b);

    // Node B should have sent a WHOAREYOU back.
    try std.testing.expectEqual(@as(usize, 1), mock_b.sent.items.len);

    // Node B should now have a session in whoareyou_sent state.
    const session_b = proto_b.sessions.get(node_id_a) orelse return error.NoSession;
    try std.testing.expectEqual(SessionState.whoareyou_sent, session_b.state);

    // Step 3: Node A receives the WHOAREYOU and responds with a handshake.
    const whoareyou_pkt = mock_b.sent.items[0].data;
    try proto_a.handlePacket(whoareyou_pkt, addr_b, t_a);

    // Node A should have sent a handshake packet.
    try std.testing.expectEqual(@as(usize, 2), mock_a.sent.items.len);

    // Node A should now have an established session.
    const session_a = proto_a.sessions.get(node_id_b) orelse return error.NoSession;
    try std.testing.expectEqual(SessionState.established, session_a.state);

    // The pending request should be consumed.
    try std.testing.expectEqual(@as(usize, 0), proto_a.pending_requests.items.len);

    // Step 4: Node B receives the handshake.
    const handshake_pkt = mock_a.sent.items[1].data;
    try proto_b.handlePacket(handshake_pkt, addr_a, t_b);

    // Node B should now have an established session.
    const session_b2 = proto_b.sessions.get(node_id_a) orelse return error.NoSession;
    try std.testing.expectEqual(SessionState.established, session_b2.state);
}
