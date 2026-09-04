//! A Channel is the authentication boundary. It turns a datagram into plaintext from a known
//! peer, or into a handshake step. It owns the local key, sessions, and challenges, and it never
//! sees calls or routing.

const std = @import("std");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const handshake = @import("identity/handshake.zig");
const SessionStore = @import("SessionStore.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const packet = @import("wire/packet.zig");

pub const Error = crypto.Error || enr.Error || packet.Error || SessionStore.Error || error{
    InvalidLocalRecord,
    MissingSession,
    RequestTooLargeForHandshake,
    StaleLocalRecord,
};

pub const InitError = SessionStore.InitError || error{ InvalidLocalRecord, InvalidTimeout };

const IdentityError = enr.Error || error{
    InvalidRemoteRecord,
    MissingIdentity,
};

pub const KnownIdentity = SessionStore.KnownIdentity;

pub const Config = struct {
    session_capacity: usize,
    challenge_capacity: usize,
    challenge_timeout_ms: u64,
    session_idle_timeout_ms: u64,
};

pub const SealEntropy = struct {
    masking_iv: [constants.masking_iv_size]u8,
    nonce: [constants.nonce_size]u8,
    nonce_tail: [8]u8,
    sessionless_key: [16]u8,
};

pub const ChallengeEntropy = struct {
    masking_iv: [constants.masking_iv_size]u8,
    id_nonce: [constants.id_nonce_size]u8,
};

pub const HandshakeEntropy = struct {
    masking_iv: [constants.masking_iv_size]u8,
    nonce_tail: [8]u8,
    ephemeral_secret: [32]u8,
};

pub const Sealed = struct {
    packet_length: u16,
    /// The nonce the packet carries. The call table uses it to match a WHOAREYOU to the call.
    nonce: [constants.nonce_size]u8,
};

pub const Authenticated = struct {
    peer: types.Endpoint,
    nonce: [constants.nonce_size]u8,
    plaintext: []const u8,
    record: ?enr.Record,
};

pub const Unauthenticated = struct {
    peer: types.Endpoint,
    request_nonce: [constants.nonce_size]u8,
};

pub const Whoareyou = struct {
    from: types.Address,
    request_nonce: [constants.nonce_size]u8,
    /// The unmasked 63-byte WHOAREYOU packet, which both sides use as the key agreement salt.
    challenge_data: [constants.whoareyou_packet_size]u8,
    enr_sequence: u64,
};

/// The classification of one datagram. Only `authenticated` carries plaintext, and that
/// plaintext borrows scratch until the next receive.
pub const Inbound = union(enum) {
    authenticated: Authenticated,
    unauthenticated: Unauthenticated,
    whoareyou: Whoareyou,
    rejected: types.RejectReason,
};

pub const HandshakeArgs = struct {
    peer: types.Endpoint,
    remote_public_key: *const [33]u8,
    plaintext: []const u8,
    challenge_data: *const [constants.whoareyou_packet_size]u8,
    enr_sequence: u64,
    entropy: *const HandshakeEntropy,
    now_ms: u64,
};

pub const Expired = struct {
    challenges: usize,
    sessions: usize,
};

pub const Scratch = struct {
    packet_decode: packet.DecodeScratch = .{},
    packet_decrypt: packet.DecryptScratch = .{},
};

const Identity = struct {
    public_key: [33]u8,
    update: ?enr.Record,
};

const Channel = @This();

local_key: crypto.KeyPair,
local_record: enr.Record,
config: Config,
sessions: SessionStore,

pub fn init(
    self: *Channel,
    allocator: std.mem.Allocator,
    local_key: crypto.KeyPair,
    local_record: enr.Record,
    config: Config,
) InitError!void {
    const public_key = crypto.compressedPublicKey(&local_key);
    if (!std.mem.eql(u8, &public_key, &local_record.public_key))
        return InitError.InvalidLocalRecord;
    if (config.challenge_timeout_ms == 0 or config.session_idle_timeout_ms == 0)
        return InitError.InvalidTimeout;
    try self.sessions.init(allocator, config.session_capacity, config.challenge_capacity);
    self.local_key = local_key;
    self.local_record = local_record;
    self.config = config;
}

pub fn deinit(self: *Channel, allocator: std.mem.Allocator) void {
    self.sessions.deinit(allocator);
    std.crypto.secureZero(u8, std.mem.asBytes(&self.local_key));
    self.* = undefined;
}

pub fn hasSession(self: *const Channel, peer: types.Endpoint) bool {
    return self.sessions.hasSession(peer);
}

pub fn updateLocalRecord(self: *Channel, record: *const enr.Record) Error!void {
    if (record.length > record.bytes.len) return Error.InvalidLocalRecord;
    const verified = enr.Record.init(record.slice()) catch return Error.InvalidLocalRecord;
    const public_key = crypto.compressedPublicKey(&self.local_key);
    if (!std.mem.eql(u8, &public_key, &verified.public_key)) return Error.InvalidLocalRecord;
    if (verified.sequence <= self.local_record.sequence) return Error.StaleLocalRecord;
    self.local_record = verified;
}

/// Returns the largest request `seal` can send to `peer` right now. With a session that is the
/// full plaintext size, and without one it is what fits beside the local ENR in a handshake.
pub fn requestCapacity(self: *const Channel, peer: types.Endpoint) Error!usize {
    if (self.sessions.hasSession(peer)) return constants.ordinary_plaintext_size_max;
    return packet.handshakePlaintextCapacity(self.local_record.length);
}

/// Encrypts with the session for `peer`. Without a session it uses `entropy.sessionless_key`,
/// which the recipient cannot decrypt and so must challenge.
pub fn seal(
    self: *Channel,
    out: []u8,
    peer: types.Endpoint,
    plaintext: []const u8,
    entropy: *const SealEntropy,
    now_ms: u64,
) Error!Sealed {
    if (out.len < try packet.ordinaryPacketLength(plaintext.len))
        return Error.BufferTooSmall;
    var outbound = try self.sessions.outbound(peer, &entropy.nonce_tail, now_ms);
    defer if (outbound) |*active| {
        std.crypto.secureZero(u8, std.mem.asBytes(active));
    };
    const write_key = if (outbound) |*active| &active.write_key else &entropy.sessionless_key;
    const nonce = if (outbound) |*active| &active.nonce else &entropy.nonce;
    return self.encodeOrdinary(out, peer, &entropy.masking_iv, nonce, write_key, plaintext);
}

/// Encrypts like `seal` but fails without a session, because responses never go out
/// unauthenticated.
pub fn sealEstablished(
    self: *Channel,
    out: []u8,
    peer: types.Endpoint,
    plaintext: []const u8,
    entropy: *const SealEntropy,
    now_ms: u64,
) Error!Sealed {
    if (out.len < try packet.ordinaryPacketLength(plaintext.len))
        return Error.BufferTooSmall;
    var outbound = (try self.sessions.outbound(peer, &entropy.nonce_tail, now_ms)) orelse
        return Error.MissingSession;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&outbound));
    return self.encodeOrdinary(
        out,
        peer,
        &entropy.masking_iv,
        &outbound.nonce,
        &outbound.write_key,
        plaintext,
    );
}

/// Classifies one datagram. This never fails, since every peer-caused problem is reported as
/// `rejected`.
pub fn receive(
    self: *Channel,
    raw: []const u8,
    from: types.Address,
    now_ms: u64,
    scratch: *Scratch,
) Inbound {
    const decoded = packet.decode(raw, &self.local_record.node_id, &scratch.packet_decode) catch
        return rejected(.malformed_packet);
    return switch (decoded.form) {
        .message => |ordinary| self.receiveOrdinary(
            &decoded,
            .{ .node_id = ordinary.source_id, .address = from },
            now_ms,
            scratch,
        ),
        .whoareyou => |who| .{ .whoareyou = .{
            .from = from,
            .request_nonce = decoded.static_header.nonce,
            .challenge_data = challengeData(&decoded),
            .enr_sequence = who.enr_sequence,
        } },
        .handshake => |authdata| self.receiveHandshake(
            &decoded,
            authdata,
            .{ .node_id = authdata.source_id, .address = from },
            now_ms,
            scratch,
        ),
    };
}

/// Sends a WHOAREYOU for the packet that carried `request_nonce`. Returns null when a challenge
/// for `peer` is already pending. `known` sets the ENR sequence to ask for and the key to verify
/// the handshake against.
pub fn challenge(
    self: *Channel,
    out: []u8,
    peer: types.Endpoint,
    request_nonce: *const [constants.nonce_size]u8,
    known: ?KnownIdentity,
    entropy: *const ChallengeEntropy,
    now_ms: u64,
) Error!?u16 {
    var challenge_data: [constants.whoareyou_packet_size]u8 = undefined;
    const encoded = try packet.encodeWhoareyou(out, .{
        .masking_iv = &entropy.masking_iv,
        .recipient_id = &peer.node_id,
        .request_nonce = request_nonce,
        .id_nonce = &entropy.id_nonce,
        .enr_sequence = if (known) |identity| identity.sequence else 0,
    }, &challenge_data);
    if (!self.sessions.putChallenge(peer, &challenge_data, known, now_ms)) return null;
    return @intCast(encoded.len);
}

/// Completes the local side of the handshake and installs the session. The local ENR is
/// included only when the challenger's `enr_sequence` is stale.
pub fn answerChallenge(self: *Channel, out: []u8, args: HandshakeArgs) Error!Sealed {
    const local_enr: []const u8 = if (args.enr_sequence < self.local_record.sequence)
        self.local_record.slice()
    else
        &.{};
    if (args.plaintext.len > try packet.handshakePlaintextCapacity(local_enr.len))
        return Error.RequestTooLargeForHandshake;
    var ephemeral_key = try crypto.keyPairFromSecret(&args.entropy.ephemeral_secret);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ephemeral_key));
    const ephemeral_public_key = crypto.compressedPublicKey(&ephemeral_key);
    var keys = try handshake.deriveKeys(
        &ephemeral_key,
        args.remote_public_key,
        &self.local_record.node_id,
        &args.peer.node_id,
        args.challenge_data,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));
    const signature = try handshake.signProof(
        &self.local_key,
        args.challenge_data,
        &ephemeral_public_key,
        &args.peer.node_id,
    );
    var authdata_buffer: [constants.handshake_authdata_size_max]u8 = undefined;
    const authdata = try packet.buildHandshakeAuthdata(&authdata_buffer, .{
        .source_id = &self.local_record.node_id,
        .id_signature = &signature,
        .ephemeral_key = &ephemeral_public_key,
        .enr = local_enr,
    });
    const nonce = handshakeNonce(args.entropy);
    const encoded = try packet.encodeHandshake(out, .{
        .packet = .{
            .masking_iv = &args.entropy.masking_iv,
            .recipient_id = &args.peer.node_id,
            .nonce = &nonce,
            .write_key = &keys.initiator,
            .plaintext = args.plaintext,
        },
        .authdata = authdata,
    });
    var active = SessionStore.Session{
        .read_key = keys.recipient,
        .write_key = keys.initiator,
        .nonce_counter = SessionStore.first_nonce_counter,
    };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&active));
    self.sessions.install(args.peer, &active, args.now_ms);
    return .{ .packet_length = @intCast(encoded.len), .nonce = nonce };
}

pub fn expire(self: *Channel, now_ms: u64) Expired {
    return .{
        .challenges = self.sessions.expireChallenges(now_ms, self.config.challenge_timeout_ms),
        .sessions = self.sessions.expireSessions(now_ms, self.config.session_idle_timeout_ms),
    };
}

pub fn nextDeadlineMs(self: *const Channel) ?u64 {
    return self.sessions.nextDeadlineMs(
        self.config.challenge_timeout_ms,
        self.config.session_idle_timeout_ms,
    );
}

fn receiveOrdinary(
    self: *Channel,
    decoded: *const packet.Packet,
    peer: types.Endpoint,
    now_ms: u64,
    scratch: *Scratch,
) Inbound {
    var read_key = self.sessions.readKey(peer) orelse return unauthenticated(decoded, peer);
    defer std.crypto.secureZero(u8, &read_key);
    const plaintext = packet.decrypt(
        decoded,
        &read_key,
        &scratch.packet_decrypt,
    ) catch |err| retry: switch (err) {
        packet.Error.DecryptionFailed => {
            var alternate_key = self.sessions.alternateReadKey(peer) orelse
                return unauthenticated(decoded, peer);
            defer std.crypto.secureZero(u8, &alternate_key);
            break :retry packet.decrypt(decoded, &alternate_key, &scratch.packet_decrypt) catch |alternate_err|
                return switch (alternate_err) {
                    packet.Error.DecryptionFailed => unauthenticated(decoded, peer),
                    else => rejected(.malformed_packet),
                };
        },
        else => return rejected(.malformed_packet),
    };
    const touched = self.sessions.touch(peer, now_ms);
    std.debug.assert(touched);
    return .{ .authenticated = .{
        .peer = peer,
        .nonce = decoded.static_header.nonce,
        .plaintext = plaintext,
        .record = null,
    } };
}

fn receiveHandshake(
    self: *Channel,
    decoded: *const packet.Packet,
    authdata: packet.HandshakeAuthdata,
    peer: types.Endpoint,
    now_ms: u64,
    scratch: *Scratch,
) Inbound {
    const stored = self.sessions.getChallenge(peer) orelse
        return rejected(.unexpected_handshake);
    const identity = selectIdentity(authdata.enr, stored.known, &peer.node_id) catch |err|
        return rejected(switch (err) {
            IdentityError.MissingIdentity => .invalid_handshake,
            else => .invalid_record,
        });
    handshake.verifyProof(
        authdata.id_signature,
        &identity.public_key,
        &stored.data,
        authdata.ephemeral_key,
        &self.local_record.node_id,
    ) catch return rejected(.invalid_handshake);
    var keys = handshake.deriveKeys(
        &self.local_key,
        authdata.ephemeral_key,
        &peer.node_id,
        &self.local_record.node_id,
        &stored.data,
    ) catch return rejected(.invalid_handshake);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));
    const plaintext = packet.decrypt(decoded, &keys.initiator, &scratch.packet_decrypt) catch
        return rejected(.invalid_handshake);
    var active = SessionStore.Session{
        .read_key = keys.initiator,
        .write_key = keys.recipient,
    };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&active));
    self.sessions.install(peer, &active, now_ms);
    self.sessions.removeChallenge(peer);
    return .{ .authenticated = .{
        .peer = peer,
        .nonce = decoded.static_header.nonce,
        .plaintext = plaintext,
        .record = identity.update,
    } };
}

fn encodeOrdinary(
    self: *const Channel,
    out: []u8,
    peer: types.Endpoint,
    masking_iv: *const [constants.masking_iv_size]u8,
    nonce: *const [constants.nonce_size]u8,
    write_key: *const [16]u8,
    plaintext: []const u8,
) Error!Sealed {
    const encoded = try packet.encodeOrdinary(out, .{
        .packet = .{
            .masking_iv = masking_iv,
            .recipient_id = &peer.node_id,
            .nonce = nonce,
            .write_key = write_key,
            .plaintext = plaintext,
        },
        .source_id = &self.local_record.node_id,
    });
    return .{ .packet_length = @intCast(encoded.len), .nonce = nonce.* };
}

/// Returns the nonce `answerChallenge` will use for `entropy`, so a caller can reserve it first.
pub fn handshakeNonce(entropy: *const HandshakeEntropy) [constants.nonce_size]u8 {
    return SessionStore.makeNonce(SessionStore.first_nonce_counter, &entropy.nonce_tail);
}

fn rejected(reason: types.RejectReason) Inbound {
    return .{ .rejected = reason };
}

fn unauthenticated(decoded: *const packet.Packet, peer: types.Endpoint) Inbound {
    return .{ .unauthenticated = .{
        .peer = peer,
        .request_nonce = decoded.static_header.nonce,
    } };
}

fn selectIdentity(
    encoded: ?[]const u8,
    known: ?KnownIdentity,
    expected_id: *const types.NodeId,
) IdentityError!Identity {
    if (encoded) |raw| {
        const record = try enr.Record.init(raw);
        if (!std.mem.eql(u8, &record.node_id, expected_id)) {
            return IdentityError.InvalidRemoteRecord;
        }
        const newer = if (known) |identity| record.sequence > identity.sequence else true;
        if (newer) return .{ .public_key = record.public_key, .update = record };
    }
    const identity = known orelse return IdentityError.MissingIdentity;
    return .{ .public_key = identity.public_key, .update = null };
}

fn challengeData(decoded: *const packet.Packet) [constants.whoareyou_packet_size]u8 {
    const header_length = decoded.header.len + constants.masking_iv_size;
    std.debug.assert(header_length == constants.whoareyou_packet_size);
    var data: [constants.whoareyou_packet_size]u8 = undefined;
    @memcpy(data[0..constants.masking_iv_size], &decoded.masking_iv);
    @memcpy(data[constants.masking_iv_size..], decoded.header);
    return data;
}

comptime {
    std.debug.assert(@sizeOf(Channel) <= 896);
}
