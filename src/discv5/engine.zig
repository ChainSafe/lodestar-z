const std = @import("std");
const calls_mod = @import("calls.zig");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const handshake = @import("identity/handshake.zig");
const protocol = @import("protocol.zig");
const session_mod = @import("session.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const message = @import("wire/message.zig");
const packet = @import("wire/packet.zig");

pub const Error = calls_mod.Error || crypto.Error || enr.Error || message.Error ||
    packet.Error || session_mod.Error || error{
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

pub const AuthenticatedRequest = struct {
    peer: types.Endpoint,
    message: message.Message,
    record: ?enr.Record,
};

pub const AuthenticatedResponse = struct {
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
    known_record: ?*const enr.Record,
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
        self.config = config;
        self.local_key = local_key;
        self.local_record = local_record;
    }

    pub fn deinit(self: *Self) void {
        self.calls.deinit();
        self.sessions.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.local_key));
    }

    pub fn startCall(
        self: *Self,
        out: []u8,
        peer: types.Endpoint,
        request: *const message.Message,
        now_ms: u64,
        entropy: StartEntropy,
    ) Error!StartResult {
        const deadline_ms = try deadline(now_ms, self.config.request_timeout_ms);
        const has_session = self.sessions.hasSession(peer);
        const request_capacity = if (has_session)
            constants.ordinary_plaintext_size_max
        else
            try packet.handshakePlaintextCapacity(self.local_record.length);
        const handle = self.calls.begin(
            peer,
            request,
            deadline_ms,
            request_capacity,
        ) catch |err| switch (err) {
            calls_mod.Error.RequestTooLarge => if (has_session)
                return err
            else
                return Error.SessionRequired,
            else => return err,
        };
        errdefer {
            const cancelled = self.calls.cancel(handle);
            std.debug.assert(cancelled);
        }
        const plaintext = self.calls.requestBytes(handle) orelse return Error.MissingCall;
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
        var plaintext_buffer: [constants.ordinary_plaintext_size_max]u8 = undefined;
        const plaintext = try response.encode(&plaintext_buffer);
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
        expired_calls: []calls_mod.Handle,
    ) struct { calls: usize, challenges: usize, sessions: usize } {
        return .{
            .calls = self.calls.expire(now_ms, expired_calls),
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
        return .{ .event = try self.dispatch(
            peer,
            decoded_message,
            null,
            args.now_ms,
            scratch,
        ) };
    }

    fn issueChallenge(
        self: *Self,
        out: []u8,
        decoded: *const packet.Packet,
        peer: types.Endpoint,
        args: ReceiveArgs,
    ) Error!Outcome {
        var challenge_data: [constants.whoareyou_packet_size]u8 = undefined;
        const known_sequence = if (args.known_record) |record| blk: {
            if (!std.mem.eql(u8, &record.node_id, &peer.node_id))
                return Error.InvalidRemoteRecord;
            break :blk record.sequence;
        } else 0;
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
        const remote_record = args.known_record orelse return Error.MissingIdentity;
        if (!std.mem.eql(u8, &remote_record.node_id, &peer.node_id))
            return Error.InvalidRemoteRecord;
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
            &remote_record.public_key,
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
        const records = try selectRecord(authdata.enr, args.known_record, &peer.node_id);
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
            .ping, .find_node, .talk_request => .{ .request = .{
                .peer = peer,
                .message = decoded,
                .record = record,
            } },
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
        try self.calls.preflight(peer, &decoded, now_ms);
        const parsed_records = switch (decoded) {
            .nodes => |nodes| try validateNodeRecords(nodes.enrs, scratch),
            else => &.{},
        };
        const match_result = try self.calls.accept(
            peer,
            &decoded,
            now_ms,
            scratch.node_ids[0..parsed_records.len],
        );
        var matched = match_result.matched;
        const node_records = if (parsed_records.len == 0)
            parsed_records
        else blk: {
            const filtered = retainAcceptedNodeRecords(
                decoded.nodes.enrs,
                parsed_records,
                match_result.accepted_node_mask,
                scratch,
            );
            matched.response.nodes.enrs = filtered.raw;
            break :blk filtered.records;
        };
        return .{ .response = .{
            .matched = matched,
            .record = record,
            .node_records = node_records,
        } };
    }
};

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
    accepted: u16,
    scratch: *Scratch,
) FilteredNodeRecords {
    std.debug.assert(raw_records.len == parsed_records.len);
    var retained: usize = 0;
    for (raw_records, parsed_records, 0..) |raw, record, index| {
        if (accepted & (@as(u16, 1) << @intCast(index)) == 0) continue;
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
    known: ?*const enr.Record,
    expected_id: *const types.NodeId,
) Error!SelectedRecord {
    const provided = if (encoded) |raw| try enr.Record.init(raw) else null;
    if (provided) |record| if (!std.mem.eql(u8, &record.node_id, expected_id))
        return Error.InvalidRemoteRecord;
    if (known) |record| if (!std.mem.eql(u8, &record.node_id, expected_id))
        return Error.InvalidRemoteRecord;
    const update = if (provided) |record|
        if (known) |known_record|
            if (record.sequence > known_record.sequence) record else null
        else
            record
    else
        null;
    const selected = update orelse if (known) |record|
        record.*
    else
        return Error.MissingIdentity;
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
