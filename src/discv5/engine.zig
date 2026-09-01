const std = @import("std");
const calls_mod = @import("calls.zig");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const handshake = @import("identity/handshake.zig");
const protocol = @import("protocol.zig");
const routing_mod = @import("routing.zig");
const session_mod = @import("session.zig");
const standard_response = @import("standard_response.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const message = @import("wire/message.zig");
const packet = @import("wire/packet.zig");

pub const Error = calls_mod.Error || crypto.Error || enr.Error || packet.Error ||
    routing_mod.Error || routing_mod.InitError || session_mod.Error || standard_response.Error || error{
    ApplicationResponseRequired,
    ClockOverflow,
    InvalidLocalRecord,
    InvalidRemoteRecord,
    InvalidTimeout,
    MissingCall,
    MissingIdentity,
    MissingSession,
    RequestTooLargeForHandshake,
    SessionRequired,
    UnexpectedChallenge,
    UnexpectedHandshake,
};

pub const StandardResponse = standard_response.Plan;

pub const StartEntropy = struct {
    masking_iv: [constants.masking_iv_size]u8,
    nonce: [constants.nonce_size]u8,
    nonce_tail: [8]u8,
    sessionless_key: [16]u8,
};

pub const ReceiveEntropy = struct {
    challenge_masking_iv: [constants.masking_iv_size]u8,
    id_nonce: [constants.id_nonce_size]u8,
    handshake_masking_iv: [constants.masking_iv_size]u8,
    handshake_nonce_tail: [8]u8,
    ephemeral_secret: [32]u8,
};

pub const StartResult = struct {
    handle: calls_mod.Handle,
    packet_length: u16,
};

pub const RevalidationStart = struct {
    peer: types.Endpoint,
    call: StartResult,
};

pub const TickResult = struct {
    calls: usize,
    maintenance_calls: usize,
    challenges: usize,
    sessions: usize,
};

pub const Request = union(enum) {
    ping: message.Ping,
    find_node: message.FindNode,
    talk_request: message.TalkRequest,
};

pub const AuthenticatedRequest = struct {
    peer: types.Endpoint,
    message: Request,
    record: ?enr.Record,
};

pub const AuthenticatedResponse = struct {
    peer: types.Endpoint,
    matched: calls_mod.Matched,
    record: ?enr.Record,
    node_records: []const enr.Record,
};

pub const Event = union(enum) {
    none,
    request: AuthenticatedRequest,
    response: AuthenticatedResponse,
};

pub const Outcome = struct {
    packet_length: u16 = 0,
    event: Event = .none,
};

pub const Scratch = struct {
    packet_decode: packet.DecodeScratch = .{},
    packet_decrypt: packet.DecryptScratch = .{},
    message_decode: message.DecodeScratch = .{},
    node_records: [protocol.findnode_result_max]enr.Record = undefined,
    node_ids: [protocol.findnode_result_max]types.NodeId = undefined,
};

pub const ReceiveArgs = struct {
    now_ms: u64,
    entropy: ReceiveEntropy,
};

const OutboundHandshake = struct {
    peer: types.Endpoint,
    handle: calls_mod.Handle,
    keys: *const handshake.Keys,
    signature: [64]u8,
    ephemeral_public_key: [33]u8,
    nonce: [constants.nonce_size]u8,
    local_enr: []const u8,
    deadline_ms: u64,
};

pub const Config = struct {
    session_capacity: usize = 1_024,
    challenge_capacity: usize = 64,
    call_capacity: usize = 64,
    request_timeout_ms: u64 = 1_000,
    challenge_timeout_ms: u64 = 1_000,
    session_idle_timeout_ms: u64 = 86_400_000,
};

pub const Engine = struct {
    const Self = @This();

    local_key: crypto.KeyPair,
    local_record: enr.Record,
    config: Config,
    sessions: session_mod.Store,
    calls: calls_mod.Table,
    routing: routing_mod.Table,

    pub fn init(
        self: *Self,
        allocator: std.mem.Allocator,
        local_key: crypto.KeyPair,
        local_record: enr.Record,
    ) Error!void {
        return self.initWithConfig(allocator, local_key, local_record, .{});
    }

    pub fn initWithConfig(
        self: *Self,
        allocator: std.mem.Allocator,
        local_key: crypto.KeyPair,
        local_record: enr.Record,
        config: Config,
    ) Error!void {
        const public_key = crypto.compressedPublicKey(&local_key);
        if (!std.mem.eql(u8, &public_key, &local_record.public_key))
            return Error.InvalidLocalRecord;
        if (config.request_timeout_ms == 0 or config.challenge_timeout_ms == 0 or
            config.session_idle_timeout_ms == 0) return Error.InvalidTimeout;
        try self.sessions.init(
            allocator,
            config.session_capacity,
            config.challenge_capacity,
        );
        errdefer self.sessions.deinit();
        try self.calls.init(allocator, config.call_capacity);
        errdefer self.calls.deinit();
        try self.routing.init(allocator, local_record.node_id);
        self.config = config;
        self.local_key = local_key;
        self.local_record = local_record;
    }

    pub fn deinit(self: *Self) void {
        self.routing.deinit();
        self.calls.deinit();
        self.sessions.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.local_key));
    }

    pub fn startCall(
        self: *Self,
        out: []u8,
        peer: types.Endpoint,
        remote_record: *const enr.Record,
        request: *const message.Message,
        now_ms: u64,
        entropy: StartEntropy,
    ) Error!StartResult {
        if (!std.mem.eql(u8, &peer.node_id, &remote_record.node_id))
            return Error.InvalidRemoteRecord;
        return self.beginCall(
            out,
            peer,
            &remote_record.public_key,
            request,
            now_ms,
            entropy,
            .caller,
        );
    }

    pub fn startRevalidation(
        self: *Self,
        out: []u8,
        request_id: message.RequestId,
        now_ms: u64,
        entropy: StartEntropy,
    ) Error!?RevalidationStart {
        const target = self.routing.revalidationTarget() orelse return null;
        const request = message.Message{ .ping = .{
            .request_id = request_id,
            .enr_sequence = self.local_record.sequence,
        } };
        const call = try self.beginCall(
            out,
            target.peer,
            &target.record.public_key,
            &request,
            now_ms,
            entropy,
            .routing_revalidation,
        );
        return .{ .peer = target.peer, .call = call };
    }

    fn beginCall(
        self: *Self,
        out: []u8,
        peer: types.Endpoint,
        remote_public_key: *const [33]u8,
        request: *const message.Message,
        now_ms: u64,
        entropy: StartEntropy,
        owner: calls_mod.Owner,
    ) Error!StartResult {
        const deadline_ms = try deadline(now_ms, self.config.request_timeout_ms);
        const has_session = self.sessions.hasSession(peer);
        const request_capacity = if (has_session)
            constants.ordinary_plaintext_size_max
        else
            try packet.handshakePlaintextCapacity(self.local_record.length);
        const handle = self.calls.begin(
            peer,
            remote_public_key,
            request,
            deadline_ms,
            request_capacity,
            owner,
        ) catch |err| switch (err) {
            calls_mod.Error.RequestTooLarge => return if (has_session)
                err
            else
                Error.SessionRequired,
            else => return err,
        };
        errdefer {
            const cancelled = self.calls.cancel(handle);
            std.debug.assert(cancelled);
        }
        const plaintext = self.calls.requestBytes(handle) orelse return Error.MissingCall;
        if (out.len < try packet.ordinaryPacketLength(plaintext.len))
            return Error.BufferTooSmall;
        var outbound = try self.sessions.outbound(peer, &entropy.nonce_tail, now_ms);
        defer if (outbound) |*active| {
            std.crypto.secureZero(u8, std.mem.asBytes(active));
        };
        const write_key = if (outbound) |*active| &active.write_key else &entropy.sessionless_key;
        const nonce = if (outbound) |*active| &active.nonce else &entropy.nonce;
        try self.calls.markSent(handle, nonce, deadline_ms);
        const encoded = try packet.encodeOrdinary(out, .{
            .packet = .{
                .masking_iv = &entropy.masking_iv,
                .recipient_id = &peer.node_id,
                .nonce = nonce,
                .write_key = write_key,
                .plaintext = plaintext,
            },
            .source_id = &self.local_record.node_id,
        });
        return .{ .handle = handle, .packet_length = @intCast(encoded.len) };
    }

    pub fn sendResponse(
        self: *Self,
        out: []u8,
        peer: types.Endpoint,
        response: *const message.Message,
        now_ms: u64,
        entropy: StartEntropy,
    ) Error!u16 {
        try validateResponse(response);
        return self.sendPreparedResponse(out, peer, response, now_ms, entropy);
    }

    pub fn prepareStandardResponse(
        self: *const Self,
        request: *const AuthenticatedRequest,
        response: *StandardResponse,
    ) Error!void {
        return switch (request.message) {
            .ping => |ping| standard_response.preparePong(
                response,
                request.peer,
                ping.request_id,
                self.local_record.sequence,
            ),
            .find_node => |find_node| blk: {
                const records = try self.findNodes(
                    request.peer.address,
                    find_node.distances,
                    &response.records,
                );
                break :blk try standard_response.prepareNodes(
                    response,
                    request.peer,
                    find_node.request_id,
                    records.len,
                );
            },
            .talk_request => Error.ApplicationResponseRequired,
        };
    }

    pub fn sendNextStandardResponse(
        self: *Self,
        out: []u8,
        response: *StandardResponse,
        now_ms: u64,
        entropy: StartEntropy,
    ) Error!?u16 {
        var raw_records: standard_response.RawRecords = undefined;
        const message_response = response.next(&raw_records) orelse return null;
        const packet_length = try self.sendPreparedResponse(
            out,
            response.peer,
            &message_response,
            now_ms,
            entropy,
        );
        response.markSent();
        return packet_length;
    }

    fn sendPreparedResponse(
        self: *Self,
        out: []u8,
        peer: types.Endpoint,
        response: *const message.Message,
        now_ms: u64,
        entropy: StartEntropy,
    ) Error!u16 {
        var plaintext_buffer: [constants.ordinary_plaintext_size_max]u8 = undefined;
        const plaintext = try response.encode(&plaintext_buffer);
        if (out.len < try packet.ordinaryPacketLength(plaintext.len))
            return Error.BufferTooSmall;
        var outbound = (try self.sessions.outbound(
            peer,
            &entropy.nonce_tail,
            now_ms,
        )) orelse return Error.MissingSession;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&outbound));
        const encoded = try packet.encodeOrdinary(out, .{
            .packet = .{
                .masking_iv = &entropy.masking_iv,
                .recipient_id = &peer.node_id,
                .nonce = &outbound.nonce,
                .write_key = &outbound.write_key,
                .plaintext = plaintext,
            },
            .source_id = &self.local_record.node_id,
        });
        return @intCast(encoded.len);
    }

    pub fn receive(
        self: *Self,
        out: []u8,
        raw: []const u8,
        from: types.Address,
        args: ReceiveArgs,
        scratch: *Scratch,
    ) Error!Outcome {
        const decoded = try packet.decode(
            raw,
            &self.local_record.node_id,
            &scratch.packet_decode,
        );
        return switch (decoded.form) {
            .message => |ordinary| self.receiveOrdinary(
                out,
                &decoded,
                ordinary.source_id,
                from,
                args,
                scratch,
            ),
            .whoareyou => self.receiveWho(out, &decoded, from, args),
            .handshake => self.receiveHandshake(&decoded, from, args, scratch),
        };
    }

    pub fn tick(
        self: *Self,
        now_ms: u64,
        expired_calls: []calls_mod.Expired,
    ) TickResult {
        const expired_count = self.calls.expire(now_ms, expired_calls);
        var caller_count: usize = 0;
        var maintenance_count: usize = 0;
        for (expired_calls[0..expired_count]) |expired| switch (expired.owner) {
            .caller => {
                expired_calls[caller_count] = expired;
                caller_count += 1;
            },
            .routing_revalidation => {
                _ = self.routing.resolveRevalidation(
                    &expired.peer.node_id,
                    false,
                    now_ms,
                ) catch |err| switch (err) {
                    routing_mod.Error.NoPendingRevalidation => {},
                    else => unreachable,
                };
                maintenance_count += 1;
            },
        };
        return .{
            .calls = caller_count,
            .maintenance_calls = maintenance_count,
            .challenges = self.sessions.expireChallenges(
                now_ms,
                self.config.challenge_timeout_ms,
            ),
            .sessions = self.sessions.expireSessions(
                now_ms,
                self.config.session_idle_timeout_ms,
            ),
        };
    }

    pub fn cancelCall(self: *Self, handle: calls_mod.Handle) bool {
        return self.calls.cancel(handle);
    }

    pub fn confirmPeer(
        self: *Self,
        peer: *const types.Endpoint,
        record: *const enr.Record,
        now_ms: u64,
    ) routing_mod.Error!routing_mod.PutResult {
        return self.routing.upsertVerified(peer, record, now_ms);
    }

    pub fn findNodes(
        self: *const Self,
        requester: types.Address,
        distances: []const u16,
        out: []enr.Record,
    ) routing_mod.Error![]enr.Record {
        return self.routing.findNodes(&self.local_record, requester, distances, out);
    }

    pub fn closestNodes(
        self: *const Self,
        target: *const types.NodeId,
        out: []routing_mod.Entry,
    ) []routing_mod.Entry {
        return self.routing.closest(target, out);
    }

    pub fn hasPendingRevalidation(self: *const Self) bool {
        return self.routing.revalidationTarget() != null;
    }

    fn receiveOrdinary(
        self: *Self,
        out: []u8,
        decoded: *const packet.Packet,
        source_id: types.NodeId,
        from: types.Address,
        args: ReceiveArgs,
        scratch: *Scratch,
    ) Error!Outcome {
        const peer = types.Endpoint{ .node_id = source_id, .address = from };
        var read_key = self.sessions.readKey(peer) orelse
            return self.issueChallenge(out, decoded, peer, args);
        defer std.crypto.secureZero(u8, &read_key);
        const plaintext = packet.decrypt(
            decoded,
            &read_key,
            &scratch.packet_decrypt,
        ) catch |err| switch (err) {
            packet.Error.DecryptionFailed => return self.issueChallenge(out, decoded, peer, args),
            else => return err,
        };
        const touched = self.sessions.touch(peer, args.now_ms);
        std.debug.assert(touched);
        const decoded_message = try message.Message.decode(
            plaintext,
            &scratch.message_decode,
        );
        const event = try self.dispatch(
            peer,
            decoded_message,
            null,
            args.now_ms,
            scratch,
        );
        self.routeAuthenticated(peer, null, args.now_ms);
        return .{ .event = event };
    }

    fn issueChallenge(
        self: *Self,
        out: []u8,
        decoded: *const packet.Packet,
        peer: types.Endpoint,
        args: ReceiveArgs,
    ) Error!Outcome {
        var challenge_data: [constants.whoareyou_packet_size]u8 = undefined;
        const known_sequence = if (self.routing.get(&peer.node_id)) |entry|
            entry.record.sequence
        else
            0;
        const encoded = try packet.encodeWhoareyou(out, .{
            .masking_iv = &args.entropy.challenge_masking_iv,
            .recipient_id = &peer.node_id,
            .request_nonce = &decoded.static_header.nonce,
            .id_nonce = &args.entropy.id_nonce,
            .enr_sequence = known_sequence,
        }, &challenge_data);
        if (!self.sessions.putChallenge(peer, &challenge_data, args.now_ms))
            return .{};
        return .{ .packet_length = @intCast(encoded.len) };
    }

    fn receiveWho(
        self: *Self,
        out: []u8,
        decoded: *const packet.Packet,
        from: types.Address,
        args: ReceiveArgs,
    ) Error!Outcome {
        const handle = (try self.calls.acceptChallenge(
            from,
            &decoded.static_header.nonce,
            args.now_ms,
        )) orelse return Error.UnexpectedChallenge;
        errdefer {
            const cancelled = self.calls.cancel(handle);
            std.debug.assert(cancelled);
        }
        const peer = self.calls.endpoint(handle) orelse return Error.MissingCall;
        const remote_public_key = self.calls.remotePublicKey(handle) orelse
            return Error.MissingCall;
        const local_enr = if (decoded.form.whoareyou.enr_sequence < self.local_record.sequence)
            self.local_record.slice()
        else
            &.{};
        const plaintext = self.calls.requestBytes(handle) orelse return Error.MissingCall;
        if (plaintext.len > try packet.handshakePlaintextCapacity(local_enr.len))
            return Error.RequestTooLargeForHandshake;
        const response_deadline = try deadline(
            args.now_ms,
            self.config.request_timeout_ms,
        );
        const challenge_data = try challengeData(decoded);
        var ephemeral_key = try crypto.keyPairFromSecret(
            &args.entropy.ephemeral_secret,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&ephemeral_key));
        const ephemeral_public_key = crypto.compressedPublicKey(&ephemeral_key);
        var keys = try handshake.deriveKeys(
            &ephemeral_key,
            &remote_public_key,
            &self.local_record.node_id,
            &peer.node_id,
            &challenge_data,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));
        const signature = try handshake.signProof(
            &self.local_key,
            &challenge_data,
            &ephemeral_public_key,
            &peer.node_id,
        );
        return self.sendHandshake(out, args, .{
            .peer = peer,
            .handle = handle,
            .keys = &keys,
            .signature = signature,
            .ephemeral_public_key = ephemeral_public_key,
            .nonce = session_mod.makeNonce(
                session_mod.first_nonce_counter,
                &args.entropy.handshake_nonce_tail,
            ),
            .local_enr = local_enr,
            .deadline_ms = response_deadline,
        });
    }

    fn sendHandshake(
        self: *Self,
        out: []u8,
        args: ReceiveArgs,
        prepared: OutboundHandshake,
    ) Error!Outcome {
        var authdata_buffer: [constants.handshake_authdata_size_max]u8 = undefined;
        const authdata = try packet.buildHandshakeAuthdata(&authdata_buffer, .{
            .source_id = &self.local_record.node_id,
            .id_signature = &prepared.signature,
            .ephemeral_key = &prepared.ephemeral_public_key,
            .enr = prepared.local_enr,
        });
        const plaintext = self.calls.requestBytes(prepared.handle) orelse
            return Error.MissingCall;
        const encoded = try packet.encodeHandshake(out, .{
            .packet = .{
                .masking_iv = &args.entropy.handshake_masking_iv,
                .recipient_id = &prepared.peer.node_id,
                .nonce = &prepared.nonce,
                .write_key = &prepared.keys.initiator,
                .plaintext = plaintext,
            },
            .authdata = authdata,
        });
        try self.calls.markSent(
            prepared.handle,
            &prepared.nonce,
            prepared.deadline_ms,
        );
        var active = session_mod.Session{
            .read_key = prepared.keys.recipient,
            .write_key = prepared.keys.initiator,
            .nonce_counter = session_mod.first_nonce_counter,
        };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&active));
        self.sessions.install(prepared.peer, &active, args.now_ms);
        return .{ .packet_length = @intCast(encoded.len) };
    }

    fn receiveHandshake(
        self: *Self,
        decoded: *const packet.Packet,
        from: types.Address,
        args: ReceiveArgs,
        scratch: *Scratch,
    ) Error!Outcome {
        const authdata = decoded.form.handshake;
        const peer = types.Endpoint{ .node_id = authdata.source_id, .address = from };
        const challenge = self.sessions.getChallenge(peer) orelse
            return Error.UnexpectedHandshake;
        const known_record: ?enr.Record = if (self.routing.get(&peer.node_id)) |entry|
            entry.record
        else
            null;
        const records = try selectRecord(authdata.enr, known_record, &peer.node_id);
        try handshake.verifyProof(
            authdata.id_signature,
            &records.selected.public_key,
            &challenge.data,
            authdata.ephemeral_key,
            &self.local_record.node_id,
        );
        var keys = try handshake.deriveKeys(
            &self.local_key,
            authdata.ephemeral_key,
            &peer.node_id,
            &self.local_record.node_id,
            &challenge.data,
        );
        defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));
        const plaintext = try packet.decrypt(
            decoded,
            &keys.initiator,
            &scratch.packet_decrypt,
        );
        const decoded_message = try message.Message.decode(
            plaintext,
            &scratch.message_decode,
        );
        const event = try self.dispatch(
            peer,
            decoded_message,
            records.update,
            args.now_ms,
            scratch,
        );
        var active = session_mod.Session{
            .read_key = keys.initiator,
            .write_key = keys.recipient,
        };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&active));
        self.sessions.install(peer, &active, args.now_ms);
        self.routeAuthenticated(peer, &records.selected, args.now_ms);
        return .{ .event = event };
    }

    fn dispatch(
        self: *Self,
        peer: types.Endpoint,
        decoded: message.Message,
        record: ?enr.Record,
        now_ms: u64,
        scratch: *Scratch,
    ) Error!Event {
        return switch (decoded) {
            .ping => |ping| requestEvent(peer, .{ .ping = ping }, record),
            .find_node => |find_node| requestEvent(peer, .{ .find_node = find_node }, record),
            .talk_request => |talk| requestEvent(peer, .{ .talk_request = talk }, record),
            .pong, .nodes, .talk_response => self.dispatchResponse(
                peer,
                decoded,
                record,
                now_ms,
                scratch,
            ),
        };
    }

    fn dispatchResponse(
        self: *Self,
        peer: types.Endpoint,
        decoded: message.Message,
        record: ?enr.Record,
        now_ms: u64,
        scratch: *Scratch,
    ) Error!Event {
        const handle = try self.calls.match(peer, &decoded, now_ms);
        const parsed_records = switch (decoded) {
            .nodes => |nodes| try validateNodeRecords(nodes.enrs, scratch),
            else => &.{},
        };
        const match_result = try self.calls.accept(
            handle,
            &decoded,
            scratch.node_ids[0..parsed_records.len],
        );
        if (match_result.owner == .routing_revalidation) {
            std.debug.assert(match_result.matched.terminal);
            std.debug.assert(match_result.matched.response == .pong);
            return .none;
        }
        var matched = match_result.matched;
        const node_records = if (parsed_records.len == 0)
            parsed_records
        else blk: {
            const filtered = retainAcceptedNodeRecords(
                decoded.nodes.enrs,
                parsed_records,
                match_result.accepted_nodes,
                scratch,
            );
            matched.response.nodes.enrs = filtered.raw;
            break :blk filtered.records;
        };
        return .{ .response = .{
            .peer = peer,
            .matched = matched,
            .record = record,
            .node_records = node_records,
        } };
    }

    fn routeAuthenticated(
        self: *Self,
        peer: types.Endpoint,
        supplied_record: ?*const enr.Record,
        now_ms: u64,
    ) void {
        var stored_record: ?enr.Record = null;
        const record = supplied_record orelse blk: {
            const entry = self.routing.get(&peer.node_id) orelse return;
            stored_record = entry.record;
            break :blk &stored_record.?;
        };
        _ = self.routing.upsertVerified(&peer, record, now_ms) catch return;
    }
};

fn requestEvent(peer: types.Endpoint, request: Request, record: ?enr.Record) Event {
    return .{ .request = .{ .peer = peer, .message = request, .record = record } };
}

fn validateNodeRecords(raw_records: []const []const u8, scratch: *Scratch) Error![]const enr.Record {
    if (raw_records.len > scratch.node_records.len) return Error.InvalidMessage;
    for (raw_records, scratch.node_records[0..raw_records.len]) |raw, *record| {
        record.* = try enr.Record.init(raw);
    }
    for (scratch.node_records[0..raw_records.len], scratch.node_ids[0..raw_records.len]) |
        *record,
        *node_id,
    | node_id.* = record.node_id;
    return scratch.node_records[0..raw_records.len];
}

const FilteredNodeRecords = struct {
    raw: []const []const u8,
    records: []const enr.Record,
};

fn retainAcceptedNodeRecords(
    raw_records: []const []const u8,
    parsed_records: []const enr.Record,
    accepted: calls_mod.AcceptedNodes,
    scratch: *Scratch,
) FilteredNodeRecords {
    std.debug.assert(raw_records.len == parsed_records.len);
    var retained: usize = 0;
    for (raw_records, parsed_records, 0..) |raw, record, index| {
        if (!accepted.isSet(index)) continue;
        scratch.message_decode.enrs[retained] = raw;
        scratch.node_records[retained] = record;
        retained += 1;
    }
    return .{
        .raw = scratch.message_decode.enrs[0..retained],
        .records = scratch.node_records[0..retained],
    };
}

const SelectedRecord = struct {
    selected: enr.Record,
    update: ?enr.Record,
};

fn selectRecord(
    encoded: ?[]const u8,
    known: ?enr.Record,
    expected_id: *const types.NodeId,
) Error!SelectedRecord {
    const provided = if (encoded) |raw| try enr.Record.init(raw) else null;
    if (provided) |record| if (!std.mem.eql(u8, &record.node_id, expected_id))
        return Error.InvalidRemoteRecord;
    const update = if (provided) |record|
        if (known) |known_record|
            if (record.sequence > known_record.sequence) record else null
        else
            record
    else
        null;
    const selected = update orelse known orelse return Error.MissingIdentity;
    return .{ .selected = selected, .update = update };
}

fn challengeData(
    decoded: *const packet.Packet,
) Error![constants.whoareyou_packet_size]u8 {
    if (decoded.header.len + constants.masking_iv_size != constants.whoareyou_packet_size)
        return Error.InvalidPacket;
    var data: [constants.whoareyou_packet_size]u8 = undefined;
    @memcpy(data[0..constants.masking_iv_size], &decoded.masking_iv);
    @memcpy(data[constants.masking_iv_size..], decoded.header);
    return data;
}

fn deadline(now_ms: u64, timeout_ms: u64) Error!u64 {
    if (timeout_ms == 0) return Error.InvalidTimeout;
    return std.math.add(u64, now_ms, timeout_ms) catch Error.ClockOverflow;
}

fn validateResponse(value: *const message.Message) Error!void {
    switch (value.*) {
        .pong, .talk_response => {},
        .nodes => |nodes| {
            if (nodes.total == 0 or nodes.total > protocol.findnode_response_packets_max)
                return Error.InvalidResponseCount;
            if (nodes.enrs.len > protocol.findnode_result_max)
                return Error.InvalidMessage;
            for (nodes.enrs) |raw| _ = try enr.Record.init(raw);
        },
        else => return Error.UnexpectedResponse,
    }
}

comptime {
    std.debug.assert(@sizeOf(Engine) <= 1_024);
}

test "NODES record validation rejects malformed ENRs before publication" {
    var scratch: Scratch = .{};
    const raw = [_][]const u8{&.{0xc0}};
    try std.testing.expectError(
        enr.Error.InvalidRecord,
        validateNodeRecords(&raw, &scratch),
    );
}

test "unsolicited NODES fails before record validation" {
    var core: Engine = undefined;
    try core.calls.init(std.testing.allocator, 1);
    defer core.calls.deinit();
    const peer = types.Endpoint{
        .node_id = [_]u8{0x11} ** 32,
        .address = .{ .ip4 = .{ .octets = .{ 127, 0, 0, 1 }, .port = 9_001 } },
    };
    const raw = [_][]const u8{&.{0xc0}};
    const response = message.Message{ .nodes = .{
        .request_id = try message.RequestId.init(&.{0x01}),
        .total = 1,
        .enrs = &raw,
    } };
    var scratch: Scratch = .{};
    try std.testing.expectError(
        calls_mod.Error.UnknownCall,
        core.dispatchResponse(peer, response, null, 0, &scratch),
    );
}
