const std = @import("std");
const CallTable = @import("CallTable.zig");
const Channel = @import("Channel.zig");
const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const RoutingTable = @import("RoutingTable.zig");
const ResponsePlan = @import("ResponsePlan.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const message = @import("wire/message.zig");

pub const Error = CallTable.Error || Channel.Error || RoutingTable.Error ||
    RoutingTable.InitError || ResponsePlan.Error || error{
    ApplicationResponseRequired,
    ClockOverflow,
    MissingCall,
    SessionRequired,
    UnexpectedChallenge,
};

pub const StartEntropy = Channel.SealEntropy;

pub const ReceiveEntropy = struct {
    challenge: Channel.ChallengeEntropy,
    handshake: Channel.HandshakeEntropy,
};

pub const StartResult = struct {
    handle: CallTable.Handle,
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
    matched: CallTable.Matched,
    record: ?enr.Record,
    node_records: []const enr.Record,
};

pub const Event = union(enum) {
    none,
    request: AuthenticatedRequest,
    response: AuthenticatedResponse,
};

pub const Accepted = struct {
    packet_length: u16 = 0,
    event: Event = .none,
};

/// Peer-caused conditions arrive as `rejected`; an error from `receive` is a local failure.
pub const Outcome = union(enum) {
    accepted: Accepted,
    rejected: types.RejectReason,
};

pub const Scratch = struct {
    channel: Channel.Scratch = .{},
    message_decode: message.DecodeScratch = .{},
    node_records: [types.findnode_result_max]enr.Record = undefined,
    node_ids: [types.findnode_result_max]types.NodeId = undefined,
};

pub const ReceiveArgs = struct {
    now_ms: u64,
    entropy: ReceiveEntropy,
};

pub const Config = struct {
    session_capacity: usize = 1_024,
    challenge_capacity: usize = 64,
    call_capacity: usize = 64,
    request_timeout_ms: u64 = 1_000,
    challenge_timeout_ms: u64 = 1_000,
    session_idle_timeout_ms: u64 = 86_400_000,
};

const Engine = @This();

config: Config,
channel: Channel,
calls: CallTable,
routing: RoutingTable,

pub fn init(
    self: *Engine,
    allocator: std.mem.Allocator,
    local_key: crypto.KeyPair,
    local_record: enr.Record,
) Error!void {
    return self.initWithConfig(allocator, local_key, local_record, .{});
}

pub fn initWithConfig(
    self: *Engine,
    allocator: std.mem.Allocator,
    local_key: crypto.KeyPair,
    local_record: enr.Record,
    config: Config,
) Error!void {
    if (config.request_timeout_ms == 0) return Error.InvalidTimeout;
    try self.channel.init(allocator, local_key, local_record, .{
        .session_capacity = config.session_capacity,
        .challenge_capacity = config.challenge_capacity,
        .challenge_timeout_ms = config.challenge_timeout_ms,
        .session_idle_timeout_ms = config.session_idle_timeout_ms,
    });
    errdefer self.channel.deinit(allocator);
    try self.calls.init(allocator, config.call_capacity);
    errdefer self.calls.deinit(allocator);
    try self.routing.init(allocator, local_record.node_id);
    self.config = config;
}

pub fn deinit(self: *Engine, allocator: std.mem.Allocator) void {
    self.routing.deinit(allocator);
    self.calls.deinit(allocator);
    self.channel.deinit(allocator);
    self.* = undefined;
}

pub fn localRecord(self: *const Engine) *const enr.Record {
    return &self.channel.local_record;
}

pub fn peerCount(self: *const Engine) usize {
    return self.routing.count();
}

pub fn startCall(
    self: *Engine,
    out: []u8,
    peer: types.Endpoint,
    remote_record: *const enr.Record,
    request: *const message.Message,
    now_ms: u64,
    entropy: *const StartEntropy,
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
    self: *Engine,
    out: []u8,
    request_id: message.RequestId,
    now_ms: u64,
    entropy: *const StartEntropy,
) Error!?RevalidationStart {
    const target = self.routing.revalidationTarget() orelse return null;
    const request = message.Message{ .ping = .{
        .request_id = request_id,
        .enr_sequence = self.channel.local_record.sequence,
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
    self: *Engine,
    out: []u8,
    peer: types.Endpoint,
    remote_public_key: *const [33]u8,
    request: *const message.Message,
    now_ms: u64,
    entropy: *const StartEntropy,
    owner: CallTable.Owner,
) Error!StartResult {
    const deadline_ms = try deadline(now_ms, self.config.request_timeout_ms);
    const handle = self.calls.begin(
        peer,
        remote_public_key,
        request,
        deadline_ms,
        try self.channel.requestCapacity(peer),
        owner,
    ) catch |err| switch (err) {
        CallTable.Error.RequestTooLarge => return if (self.channel.hasSession(peer))
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
    const sealed = try self.channel.seal(out, peer, plaintext, entropy, now_ms);
    try self.calls.markSent(handle, &sealed.nonce, deadline_ms);
    return .{ .handle = handle, .packet_length = sealed.packet_length };
}

pub fn sendResponse(
    self: *Engine,
    out: []u8,
    peer: types.Endpoint,
    response: *const message.Message,
    now_ms: u64,
    entropy: *const StartEntropy,
) Error!u16 {
    try validateResponse(response);
    return self.sendPreparedResponse(out, peer, response, now_ms, entropy);
}

pub fn prepareStandardResponse(
    self: *const Engine,
    request: *const AuthenticatedRequest,
    response: *ResponsePlan,
) Error!void {
    return switch (request.message) {
        .ping => |ping| response.preparePong(
            request.peer,
            ping.request_id,
            self.channel.local_record.sequence,
        ),
        .find_node => |find_node| blk: {
            const records = try self.findNodes(
                request.peer.address,
                find_node.distances,
                &response.records,
            );
            break :blk try response.prepareNodes(
                request.peer,
                find_node.request_id,
                records.len,
            );
        },
        .talk_request => Error.ApplicationResponseRequired,
    };
}

pub fn sendNextStandardResponse(
    self: *Engine,
    out: []u8,
    response: *ResponsePlan,
    now_ms: u64,
    entropy: *const StartEntropy,
) Error!?u16 {
    var raw_records: ResponsePlan.RawRecords = undefined;
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
    self: *Engine,
    out: []u8,
    peer: types.Endpoint,
    response: *const message.Message,
    now_ms: u64,
    entropy: *const StartEntropy,
) Error!u16 {
    var plaintext_buffer: [constants.ordinary_plaintext_size_max]u8 = undefined;
    const plaintext = try response.encode(&plaintext_buffer);
    const sealed = try self.channel.sealEstablished(out, peer, plaintext, entropy, now_ms);
    return sealed.packet_length;
}

pub fn receive(
    self: *Engine,
    out: []u8,
    raw: []const u8,
    from: types.Address,
    args: ReceiveArgs,
    scratch: *Scratch,
) Error!Outcome {
    return self.process(out, raw, from, args, scratch) catch |err| {
        const reason = rejectReason(err) orelse return err;
        return .{ .rejected = reason };
    };
}

fn process(
    self: *Engine,
    out: []u8,
    raw: []const u8,
    from: types.Address,
    args: ReceiveArgs,
    scratch: *Scratch,
) Error!Outcome {
    return switch (self.channel.receive(raw, from, args.now_ms, &scratch.channel)) {
        .authenticated => |authenticated| self.receiveAuthenticated(
            authenticated,
            args.now_ms,
            scratch,
        ),
        .unauthenticated => |unauthenticated| self.issueChallenge(out, unauthenticated, args),
        .whoareyou => |whoareyou| self.recoverCall(out, whoareyou, args),
        .rejected => |reason| .{ .rejected = reason },
    };
}

pub fn tick(
    self: *Engine,
    now_ms: u64,
    expired_calls: []CallTable.Expired,
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
                RoutingTable.Error.NoPendingRevalidation => {},
                else => unreachable,
            };
            maintenance_count += 1;
        },
    };
    const expired = self.channel.expire(now_ms);
    return .{
        .calls = caller_count,
        .maintenance_calls = maintenance_count,
        .challenges = expired.challenges,
        .sessions = expired.sessions,
    };
}

pub fn cancelCall(self: *Engine, handle: CallTable.Handle) bool {
    return self.calls.cancel(handle);
}

pub fn confirmPeer(
    self: *Engine,
    peer: *const types.Endpoint,
    record: *const enr.Record,
    now_ms: u64,
) RoutingTable.Error!RoutingTable.PutResult {
    return self.routing.upsertVerified(peer, record, now_ms);
}

pub fn findNodes(
    self: *const Engine,
    requester: types.Address,
    distances: []const u16,
    out: []enr.Record,
) RoutingTable.Error![]enr.Record {
    return self.routing.findNodes(&self.channel.local_record, requester, distances, out);
}

pub fn closestNodes(
    self: *const Engine,
    target: *const types.NodeId,
    out: []RoutingTable.Entry,
) []RoutingTable.Entry {
    return self.routing.closest(target, out);
}

pub fn hasPendingRevalidation(self: *const Engine) bool {
    return self.routing.revalidationTarget() != null;
}

fn receiveAuthenticated(
    self: *Engine,
    authenticated: Channel.Authenticated,
    now_ms: u64,
    scratch: *Scratch,
) Error!Outcome {
    const decoded = try message.Message.decode(
        authenticated.plaintext,
        &scratch.message_decode,
    );
    const event = try self.dispatch(
        authenticated.peer,
        decoded,
        authenticated.record,
        now_ms,
        scratch,
    );
    self.routeAuthenticated(authenticated.peer, authenticated.record, now_ms);
    return .{ .accepted = .{ .event = event } };
}

fn issueChallenge(
    self: *Engine,
    out: []u8,
    unauthenticated: Channel.Unauthenticated,
    args: ReceiveArgs,
) Error!Outcome {
    const packet_length = try self.channel.challenge(
        out,
        unauthenticated.peer,
        &unauthenticated.request_nonce,
        self.knownIdentity(&unauthenticated.peer.node_id),
        &args.entropy.challenge,
        args.now_ms,
    );
    return .{ .accepted = .{ .packet_length = packet_length orelse 0 } };
}

fn knownIdentity(self: *const Engine, node_id: *const types.NodeId) ?Channel.KnownIdentity {
    const entry = self.routing.get(node_id) orelse return null;
    return .{ .sequence = entry.record.sequence, .public_key = entry.record.public_key };
}

fn recoverCall(
    self: *Engine,
    out: []u8,
    whoareyou: Channel.Whoareyou,
    args: ReceiveArgs,
) Error!Outcome {
    const handle = (try self.calls.acceptChallenge(
        whoareyou.from,
        &whoareyou.request_nonce,
        args.now_ms,
    )) orelse return Error.UnexpectedChallenge;
    errdefer {
        const cancelled = self.calls.cancel(handle);
        std.debug.assert(cancelled);
    }
    const peer = self.calls.endpoint(handle) orelse return Error.MissingCall;
    const remote_public_key = self.calls.remotePublicKey(handle) orelse
        return Error.MissingCall;
    const plaintext = self.calls.requestBytes(handle) orelse return Error.MissingCall;
    const deadline_ms = try deadline(args.now_ms, self.config.request_timeout_ms);
    try self.calls.markSent(
        handle,
        &Channel.handshakeNonce(&args.entropy.handshake),
        deadline_ms,
    );
    const sealed = try self.channel.answerChallenge(out, .{
        .peer = peer,
        .remote_public_key = &remote_public_key,
        .plaintext = plaintext,
        .challenge_data = &whoareyou.challenge_data,
        .enr_sequence = whoareyou.enr_sequence,
        .entropy = &args.entropy.handshake,
        .now_ms = args.now_ms,
    });
    return .{ .accepted = .{ .packet_length = sealed.packet_length } };
}

fn dispatch(
    self: *Engine,
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
    self: *Engine,
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
    self: *Engine,
    peer: types.Endpoint,
    supplied_record: ?enr.Record,
    now_ms: u64,
) void {
    const record = supplied_record orelse
        (self.routing.get(&peer.node_id) orelse return).record;
    _ = self.routing.upsertVerified(&peer, &record, now_ms) catch return;
}

fn rejectReason(err: Error) ?types.RejectReason {
    return switch (err) {
        Error.InvalidMessage,
        Error.UnsupportedMessage,
        Error.InvalidEncoding,
        Error.Overflow,
        Error.UnexpectedType,
        => .malformed_message,
        Error.InvalidRecord,
        Error.TooManyFields,
        Error.UnsupportedScheme,
        Error.InvalidSignature,
        Error.InvalidPublicKey,
        Error.InvalidRemoteRecord,
        => .invalid_record,
        Error.UnexpectedChallenge, Error.HandshakeAttempted => .unexpected_challenge,
        Error.RequestTooLargeForHandshake => .request_too_large,
        Error.UnknownCall,
        Error.CallExpired,
        Error.RequestIdMismatch,
        Error.UnexpectedResponse,
        => .unsolicited_response,
        Error.InvalidResponseCount, Error.InvalidNodeCount => .invalid_response,
        else => null,
    };
}

fn requestEvent(peer: types.Endpoint, request: Request, record: ?enr.Record) Event {
    return .{ .request = .{ .peer = peer, .message = request, .record = record } };
}

fn validateNodeRecords(
    raw_records: []const []const u8,
    scratch: *Scratch,
) Error![]const enr.Record {
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
    accepted: CallTable.AcceptedNodes,
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

fn deadline(now_ms: u64, timeout_ms: u64) Error!u64 {
    if (timeout_ms == 0) return Error.InvalidTimeout;
    return std.math.add(u64, now_ms, timeout_ms) catch Error.ClockOverflow;
}

fn validateResponse(value: *const message.Message) Error!void {
    switch (value.*) {
        .pong, .talk_response => {},
        .nodes => |nodes| {
            if (nodes.total == 0 or nodes.total > types.findnode_response_packets_max)
                return Error.InvalidResponseCount;
            if (nodes.enrs.len > types.findnode_result_max)
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
    defer core.calls.deinit(std.testing.allocator);
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
        CallTable.Error.UnknownCall,
        core.dispatchResponse(peer, response, null, 0, &scratch),
    );
}
