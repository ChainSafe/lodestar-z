const std = @import("std");
const napi = @import("zapi:zapi").napi;
const js = @import("zapi:zapi").js;
const peer_manager = @import("peer_manager");
const napi_io = @import("./io.zig");

/// Wall-clock time in Unix milliseconds, sourced from the shared `std.Io`.
fn currentMillis() i64 {
    return std.Io.Timestamp.now(napi_io.get(), .real).toMilliseconds();
}

const PeerManager = peer_manager.PeerManager;
const Config = peer_manager.Config;
const Status = peer_manager.Status;
const Metadata = peer_manager.Metadata;
const Action = peer_manager.Action;
const Direction = peer_manager.Direction;
const ForkName = peer_manager.ForkName;
const PeerAction = peer_manager.PeerAction;
const GoodbyeReasonCode = peer_manager.GoodbyeReasonCode;
const GossipScoreUpdate = peer_manager.GossipScoreUpdate;
const RequestedSubnet = peer_manager.RequestedSubnet;
const parseExternalPeerActionName = peer_manager.parseExternalPeerActionName;

/// Allocator for internal allocations.
const allocator = std.heap.page_allocator;

pub const State = struct {
    manager: ?PeerManager = null,

    pub fn init(self: *State, config: Config) !void {
        if (self.manager != null) return error.AlreadyInitialized;
        self.manager = try PeerManager.init(
            allocator,
            config,
            currentMillis,
        );
    }

    pub fn deinit(self: *State) void {
        if (self.manager) |*m| {
            m.deinit();
            self.manager = null;
        }
    }
};

pub var state: State = .{};

// ── Helpers ──────────────────────────────────────────────────────────

fn getManager() !*PeerManager {
    if (state.manager) |*m| return m;
    return error.PeerManagerNotInitialized;
}

fn configFromObject(env: napi.Env, obj: napi.Value) !Config {
    _ = env;
    var config: Config = .{
        .gossipsub_negative_score_weight = undefined,
        .gossipsub_positive_score_weight = undefined,
        .negative_gossip_score_ignore_threshold = undefined,
        .initial_fork_name = undefined,
    };

    // Required numeric fields
    config.target_peers = try (try obj.getNamedProperty("targetPeers")).getValueUint32();
    config.max_peers = try (try obj.getNamedProperty("maxPeers")).getValueUint32();
    config.target_group_peers = try (try obj.getNamedProperty("targetGroupPeers")).getValueUint32();
    config.ping_interval_inbound_ms = try (try obj.getNamedProperty("pingIntervalInboundMs")).getValueInt64();
    config.ping_interval_outbound_ms = try (try obj.getNamedProperty("pingIntervalOutboundMs")).getValueInt64();
    config.status_interval_ms = try (try obj.getNamedProperty("statusIntervalMs")).getValueInt64();
    config.status_inbound_grace_period_ms = try (try obj.getNamedProperty("statusInboundGracePeriodMs")).getValueInt64();
    config.gossipsub_negative_score_weight = try (try obj.getNamedProperty("gossipsubNegativeScoreWeight")).getValueDouble();
    config.gossipsub_positive_score_weight = try (try obj.getNamedProperty("gossipsubPositiveScoreWeight")).getValueDouble();
    config.negative_gossip_score_ignore_threshold = try (try obj.getNamedProperty("negativeGossipScoreIgnoreThreshold")).getValueDouble();
    config.number_of_custody_groups = try (try obj.getNamedProperty("numberOfCustodyGroups")).getValueUint32();
    config.custody_requirement = @intCast(try (try obj.getNamedProperty("custodyRequirement")).getValueInt64());
    config.samples_per_slot = @intCast(try (try obj.getNamedProperty("samplesPerSlot")).getValueInt64());
    config.slots_per_epoch = @intCast(try (try obj.getNamedProperty("slotsPerEpoch")).getValueInt64());

    // Boolean
    config.disable_peer_scoring = try (try obj.getNamedProperty("disablePeerScoring")).getValueBool();

    // Fork name (string → enum)
    var fork_buf: [32]u8 = undefined;
    const fork_str = try (try obj.getNamedProperty("initialForkName")).getValueStringUtf8(&fork_buf);
    config.initial_fork_name = std.meta.stringToEnum(ForkName, fork_str) orelse
        return error.InvalidForkName;

    return config;
}

fn statusFromObject(_: napi.Env, obj: napi.Value) !Status {
    var status: Status = undefined;

    const fork_digest_info = try (try obj.getNamedProperty("forkDigest")).getTypedarrayInfo();
    if (fork_digest_info.data.len != 4) return error.InvalidForkDigestLength;
    @memcpy(&status.fork_digest, fork_digest_info.data[0..4]);

    const finalized_root_info = try (try obj.getNamedProperty("finalizedRoot")).getTypedarrayInfo();
    if (finalized_root_info.data.len != 32) return error.InvalidFinalizedRootLength;
    @memcpy(&status.finalized_root, finalized_root_info.data[0..32]);

    status.finalized_epoch = @intCast(try (try obj.getNamedProperty("finalizedEpoch")).getValueInt64());

    const head_root_info = try (try obj.getNamedProperty("headRoot")).getTypedarrayInfo();
    if (head_root_info.data.len != 32) return error.InvalidHeadRootLength;
    @memcpy(&status.head_root, head_root_info.data[0..32]);

    status.head_slot = @intCast(try (try obj.getNamedProperty("headSlot")).getValueInt64());

    const eas_value = try obj.getNamedProperty("earliestAvailableSlot");
    const eas_type = try eas_value.typeof();
    if (eas_type == .undefined or eas_type == .null) {
        status.earliest_available_slot = null;
    } else {
        status.earliest_available_slot = @intCast(try eas_value.getValueInt64());
    }

    return status;
}

fn actionsToNapiArray(env: napi.Env, actions: []const Action) !napi.Value {
    const arr = try env.createArrayWithLength(actions.len);
    for (actions, 0..) |action, i| {
        const obj = try actionToNapiObject(env, action);
        try arr.setElement(@intCast(i), obj);
    }
    return arr;
}

fn actionToNapiObject(env: napi.Env, action: Action) !napi.Value {
    const obj = try env.createObject();
    switch (action) {
        .send_ping => |peer_id| {
            try obj.setNamedProperty("type", try env.createStringUtf8("send_ping"));
            try obj.setNamedProperty("peerId", try env.createStringUtf8(peer_id));
        },
        .send_status => |peer_id| {
            try obj.setNamedProperty("type", try env.createStringUtf8("send_status"));
            try obj.setNamedProperty("peerId", try env.createStringUtf8(peer_id));
        },
        .send_goodbye => |g| {
            try obj.setNamedProperty("type", try env.createStringUtf8("send_goodbye"));
            try obj.setNamedProperty("peerId", try env.createStringUtf8(g.peer_id));
            try obj.setNamedProperty("reason", try env.createUint32(@intCast(@intFromEnum(g.reason))));
        },
        .request_metadata => |peer_id| {
            try obj.setNamedProperty("type", try env.createStringUtf8("request_metadata"));
            try obj.setNamedProperty("peerId", try env.createStringUtf8(peer_id));
        },
        .disconnect_peer => |peer_id| {
            try obj.setNamedProperty("type", try env.createStringUtf8("disconnect_peer"));
            try obj.setNamedProperty("peerId", try env.createStringUtf8(peer_id));
        },
        .request_discovery => |dr| {
            try obj.setNamedProperty("type", try env.createStringUtf8("request_discovery"));
            try obj.setNamedProperty("peersToConnect", try env.createUint32(dr.peers_to_connect));

            const attnet_arr = try env.createArrayWithLength(dr.attnet_queries.len);
            for (dr.attnet_queries, 0..) |q, j| {
                const qobj = try env.createObject();
                try qobj.setNamedProperty("subnet", try env.createUint32(q.subnet));
                try qobj.setNamedProperty("toSlot", try env.createInt64(@intCast(q.to_slot)));
                try qobj.setNamedProperty("maxPeersToDiscover", try env.createUint32(q.max_peers_to_discover));
                try attnet_arr.setElement(@intCast(j), qobj);
            }
            try obj.setNamedProperty("attnetQueries", attnet_arr);

            const syncnet_arr = try env.createArrayWithLength(dr.syncnet_queries.len);
            for (dr.syncnet_queries, 0..) |q, j| {
                const qobj = try env.createObject();
                try qobj.setNamedProperty("subnet", try env.createUint32(q.subnet));
                try qobj.setNamedProperty("toSlot", try env.createInt64(@intCast(q.to_slot)));
                try qobj.setNamedProperty("maxPeersToDiscover", try env.createUint32(q.max_peers_to_discover));
                try syncnet_arr.setElement(@intCast(j), qobj);
            }
            try obj.setNamedProperty("syncnetQueries", syncnet_arr);

            const custody_arr = try env.createArrayWithLength(dr.custody_group_queries.len);
            for (dr.custody_group_queries, 0..) |q, j| {
                const qobj = try env.createObject();
                try qobj.setNamedProperty("group", try env.createUint32(q.group));
                try qobj.setNamedProperty("maxPeersToDiscover", try env.createUint32(q.max_peers_to_discover));
                try custody_arr.setElement(@intCast(j), qobj);
            }
            try obj.setNamedProperty("custodyGroupQueries", custody_arr);
        },
        .tag_peer_relevant => |peer_id| {
            try obj.setNamedProperty("type", try env.createStringUtf8("tag_peer_relevant"));
            try obj.setNamedProperty("peerId", try env.createStringUtf8(peer_id));
        },
        .emit_peer_connected => |c| {
            try obj.setNamedProperty("type", try env.createStringUtf8("emit_peer_connected"));
            try obj.setNamedProperty("peerId", try env.createStringUtf8(c.peer_id));
            try obj.setNamedProperty("direction", try env.createStringUtf8(@tagName(c.direction)));
        },
        .emit_peer_disconnected => |peer_id| {
            try obj.setNamedProperty("type", try env.createStringUtf8("emit_peer_disconnected"));
            try obj.setNamedProperty("peerId", try env.createStringUtf8(peer_id));
        },
    }
    return obj;
}

/// Upper bound on a peer id string. libp2p peer ids are ~46-60 chars; this is a
/// generous ceiling that lets us reject (rather than silently truncate) anything
/// unexpectedly long. The +1 in the buffers leaves room for N-API's NUL.
const max_peer_id_len = 128;

/// Reads a JS string argument into allocator-owned `[]u8` peer id memory.
/// Returns `error.PeerIdTooLong` rather than truncating. Caller owns the memory.
fn dupePeerId(value: js.String) ![]u8 {
    if (try value.len() > max_peer_id_len) return error.PeerIdTooLong;
    var buf: [max_peer_id_len + 1]u8 = undefined;
    const peer_id = try value.toSlice(&buf);
    return allocator.dupe(u8, peer_id);
}

/// Reads a peer id from a `napi.Value` (e.g. an array element's property) into
/// allocator-owned memory. Returns `error.PeerIdTooLong` rather than truncating.
/// Caller owns the returned memory.
fn readOwnedPeerId(value: napi.Value) ![]u8 {
    return dupePeerId(.{ .val = value });
}

fn parsePeerActionName(action_name: []const u8) ?PeerAction {
    return parseExternalPeerActionName(action_name);
}

fn parseOptionalU32Array(value: napi.Value) !?[]u32 {
    const value_type = try value.typeof();
    if (value_type == .undefined or value_type == .null) {
        return null;
    }

    const len = try value.getArrayLength();
    const items = try allocator.alloc(u32, len);
    errdefer allocator.free(items);

    for (0..len) |i| {
        const elem = try value.getElement(@intCast(i));
        items[i] = try elem.getValueUint32();
    }

    return items;
}

// ── Lifecycle ────────────────────────────────────────────────────────

/// JS: peerManager.init(config)
pub fn init(config_arg: js.Value) !void {
    const config_obj = try config_arg.toValue().coerceToObject();
    const config = try configFromObject(js.env(), config_obj);
    try state.init(config);
}

/// JS: peerManager.close()
pub fn close() !void {
    state.deinit();
}

// ── Tick Functions ───────────────────────────────────────────────────

/// JS: peerManager.heartbeat(currentSlot, localStatus)
pub fn heartbeat(current_slot: js.Number, local_status: js.Value) !napi.Value {
    const m = try getManager();
    const slot: u64 = @intCast(try current_slot.toI64());
    const local = try statusFromObject(js.env(), try local_status.toValue().coerceToObject());
    const actions = try m.heartbeat(slot, local);
    return actionsToNapiArray(js.env(), actions);
}

/// JS: peerManager.checkPingAndStatus()
pub fn checkPingAndStatus() !napi.Value {
    const m = try getManager();
    const actions = try m.checkPingAndStatus();
    return actionsToNapiArray(js.env(), actions);
}

// ── Event Handlers ───────────────────────────────────────────────────

/// JS: peerManager.onConnectionOpen(peerId, direction)
pub fn onConnectionOpen(peer_id_arg: js.String, direction_arg: js.String) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    var dir_buf: [16]u8 = undefined;
    const dir_str = try direction_arg.toSlice(&dir_buf);
    const direction = std.meta.stringToEnum(Direction, dir_str) orelse
        return error.InvalidDirection;
    const actions = try m.onConnectionOpen(peer_id, direction);
    return actionsToNapiArray(js.env(), actions);
}

/// JS: peerManager.onConnectionClose(peerId)
pub fn onConnectionClose(peer_id_arg: js.String) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const actions = try m.onConnectionClose(peer_id);
    return actionsToNapiArray(js.env(), actions);
}

/// JS: peerManager.onStatusReceived(peerId, remoteStatus, localStatus, currentSlot)
pub fn onStatusReceived(
    peer_id_arg: js.String,
    remote_status: js.Value,
    local_status: js.Value,
    current_slot: js.Number,
) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const remote = try statusFromObject(js.env(), try remote_status.toValue().coerceToObject());
    const local = try statusFromObject(js.env(), try local_status.toValue().coerceToObject());
    const slot: u64 = @intCast(try current_slot.toI64());
    const actions = try m.onStatusReceived(peer_id, remote, local, slot);
    return actionsToNapiArray(js.env(), actions);
}

/// JS: peerManager.onMetadataReceived(peerId, metadata)
pub fn onMetadataReceived(peer_id_arg: js.String, metadata_arg: js.Value) !void {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const md_obj = try metadata_arg.toValue().coerceToObject();

    var metadata: Metadata = undefined;
    metadata.seq_number = @intCast(try (try md_obj.getNamedProperty("seqNumber")).getValueInt64());

    const attnets_info = try (try md_obj.getNamedProperty("attnets")).getTypedarrayInfo();
    if (attnets_info.data.len != 8) return error.InvalidAttnetsLength;
    @memcpy(&metadata.attnets, attnets_info.data[0..8]);

    const syncnets_info = try (try md_obj.getNamedProperty("syncnets")).getTypedarrayInfo();
    if (syncnets_info.data.len != 1) return error.InvalidSyncnetsLength;
    @memcpy(&metadata.syncnets, syncnets_info.data[0..1]);

    metadata.custody_group_count = @intCast(try (try md_obj.getNamedProperty("custodyGroupCount")).getValueInt64());
    metadata.custody_groups = try parseOptionalU32Array(try md_obj.getNamedProperty("custodyGroups"));
    errdefer if (metadata.custody_groups) |groups| allocator.free(groups);
    metadata.sampling_groups = try parseOptionalU32Array(try md_obj.getNamedProperty("samplingGroups"));
    errdefer if (metadata.sampling_groups) |groups| allocator.free(groups);

    m.onMetadataReceived(peer_id, metadata);
}

/// JS: peerManager.onMessageReceived(peerId)
pub fn onMessageReceived(peer_id_arg: js.String) !void {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    m.onMessageReceived(peer_id);
}

/// JS: peerManager.onGoodbye(peerId, reason)
pub fn onGoodbye(peer_id_arg: js.String, reason_arg: js.Number) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const reason_raw: u64 = @intCast(try reason_arg.toI64());
    const reason: GoodbyeReasonCode = @enumFromInt(reason_raw);
    const actions = try m.onGoodbye(peer_id, reason);
    return actionsToNapiArray(js.env(), actions);
}

/// JS: peerManager.onPing(peerId, seqNumber)
pub fn onPing(peer_id_arg: js.String, seq_number_arg: js.Number) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const seq_number: u64 = @intCast(try seq_number_arg.toI64());
    const actions = try m.onPing(peer_id, seq_number);
    return actionsToNapiArray(js.env(), actions);
}

// ── Score Mutations ──────────────────────────────────────────────────

/// JS: peerManager.reportPeer(peerId, action)
pub fn reportPeer(peer_id_arg: js.String, action_arg: js.String) !void {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    var action_buf: [32]u8 = undefined;
    const action_str = try action_arg.toSlice(&action_buf);
    const action = parsePeerActionName(action_str) orelse
        return error.InvalidPeerAction;
    m.reportPeer(peer_id, action);
}

/// JS: peerManager.updateGossipScores(scores)
pub fn updateGossipScores(scores_arg: js.Value) !void {
    const m = try getManager();
    const arr = scores_arg.toValue();
    const len = try arr.getArrayLength();
    const scores = try allocator.alloc(GossipScoreUpdate, len);
    defer allocator.free(scores);
    const peer_ids = try allocator.alloc([]u8, len);
    defer allocator.free(peer_ids);
    var initialized: usize = 0;
    errdefer {
        for (peer_ids[0..initialized]) |pid| allocator.free(pid);
    }

    for (0..len) |i| {
        const entry = try arr.getElement(@intCast(i));
        peer_ids[i] = try readOwnedPeerId(try entry.getNamedProperty("peerId"));
        initialized += 1;
        scores[i] = .{
            .peer_id = peer_ids[i],
            .new_score = try (try entry.getNamedProperty("score")).getValueDouble(),
        };
    }
    m.updateGossipScores(scores);
    for (peer_ids) |pid| allocator.free(pid);
}

// ── Configuration Updates ────────────────────────────────────────────

/// JS: peerManager.setSubnetRequirements(attnets, syncnets)
pub fn setSubnetRequirements(attnets_arg: js.Value, syncnets_arg: js.Value) !void {
    const m = try getManager();

    const attnets_arr = attnets_arg.toValue();
    const attnets_len = try attnets_arr.getArrayLength();
    const attnets = try allocator.alloc(RequestedSubnet, attnets_len);
    defer allocator.free(attnets);
    for (0..attnets_len) |i| {
        const entry = try attnets_arr.getElement(@intCast(i));
        attnets[i] = .{
            .subnet = try (try entry.getNamedProperty("subnet")).getValueUint32(),
            .to_slot = @intCast(try (try entry.getNamedProperty("toSlot")).getValueInt64()),
        };
    }

    const syncnets_arr = syncnets_arg.toValue();
    const syncnets_len = try syncnets_arr.getArrayLength();
    const syncnets = try allocator.alloc(RequestedSubnet, syncnets_len);
    defer allocator.free(syncnets);
    for (0..syncnets_len) |i| {
        const entry = try syncnets_arr.getElement(@intCast(i));
        syncnets[i] = .{
            .subnet = try (try entry.getNamedProperty("subnet")).getValueUint32(),
            .to_slot = @intCast(try (try entry.getNamedProperty("toSlot")).getValueInt64()),
        };
    }

    try m.setSubnetRequirements(attnets, syncnets);
}

/// JS: peerManager.setForkName(forkName)
pub fn setForkName(fork_name_arg: js.String) !void {
    const m = try getManager();
    var fork_buf: [32]u8 = undefined;
    const fork_str = try fork_name_arg.toSlice(&fork_buf);
    const fork_name = std.meta.stringToEnum(ForkName, fork_str) orelse
        return error.InvalidForkName;
    m.setForkName(fork_name);
}

/// JS: peerManager.setSamplingGroups(groups)
pub fn setSamplingGroups(groups_arg: js.Value) !void {
    const m = try getManager();
    const arr = groups_arg.toValue();
    const len = try arr.getArrayLength();
    const groups = try allocator.alloc(u32, len);
    defer allocator.free(groups);
    for (0..len) |i| {
        const elem = try arr.getElement(@intCast(i));
        groups[i] = try elem.getValueUint32();
    }
    try m.setSamplingGroups(groups);
}

// ── Queries ──────────────────────────────────────────────────────────

/// JS: peerManager.getConnectedPeerCount() → number
pub fn getConnectedPeerCount() !napi.Value {
    const m = try getManager();
    return js.env().createUint32(m.getConnectedPeerCount());
}

/// JS: peerManager.getConnectedPeers() → string[]
pub fn getConnectedPeers() !napi.Value {
    const m = try getManager();
    const peers = try m.getConnectedPeers(allocator);
    defer allocator.free(peers);

    const env = js.env();
    const arr = try env.createArrayWithLength(@intCast(peers.len));
    for (peers, 0..) |peer_id, idx| {
        try arr.setElement(@intCast(idx), try env.createStringUtf8(peer_id));
    }
    return arr;
}

/// JS: peerManager.getPeerData(peerId) → PeerData | null
pub fn getPeerData(peer_id_arg: js.String) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const env = js.env();
    const peer = m.getPeerData(peer_id) orelse return env.getNull();

    const obj = try env.createObject();
    try obj.setNamedProperty("peerId", try env.createStringUtf8(peer.peer_id));
    try obj.setNamedProperty("direction", try env.createStringUtf8(@tagName(peer.direction)));
    try obj.setNamedProperty("relevantStatus", try env.createStringUtf8(@tagName(peer.relevant_status)));
    try obj.setNamedProperty("connectedUnixTsMs", try env.createInt64(peer.connected_unix_ts_ms));
    try obj.setNamedProperty("lastReceivedMsgUnixTsMs", try env.createInt64(peer.last_received_msg_unix_ts_ms));
    try obj.setNamedProperty("lastStatusUnixTsMs", try env.createInt64(peer.last_status_unix_ts_ms));

    if (peer.agent_version) |av| {
        try obj.setNamedProperty("agentVersion", try env.createStringUtf8(av));
    } else {
        try obj.setNamedProperty("agentVersion", try env.getNull());
    }

    if (peer.agent_client) |ac| {
        try obj.setNamedProperty("agentClient", try env.createStringUtf8(@tagName(ac)));
    } else {
        try obj.setNamedProperty("agentClient", try env.getNull());
    }

    if (peer.encoding_preference) |enc| {
        try obj.setNamedProperty("encodingPreference", try env.createStringUtf8(@tagName(enc)));
    } else {
        try obj.setNamedProperty("encodingPreference", try env.getNull());
    }

    return obj;
}

/// JS: peerManager.getEncodingPreference(peerId) → string | null
pub fn getEncodingPreference(peer_id_arg: js.String) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const env = js.env();
    const encoding = m.getEncodingPreference(peer_id) orelse return env.getNull();
    return env.createStringUtf8(@tagName(encoding));
}

/// JS: peerManager.getPeerKind(peerId) → string | null
pub fn getPeerKind(peer_id_arg: js.String) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const env = js.env();
    const kind = m.getPeerKind(peer_id) orelse return env.getNull();
    return env.createStringUtf8(@tagName(kind));
}

/// JS: peerManager.getAgentVersion(peerId) → string | null
pub fn getAgentVersion(peer_id_arg: js.String) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    const env = js.env();
    const av = m.getAgentVersion(peer_id) orelse return env.getNull();
    return env.createStringUtf8(av);
}

/// JS: peerManager.getPeerScore(peerId) → number
pub fn getPeerScore(peer_id_arg: js.String) !napi.Value {
    const m = try getManager();
    const peer_id = try dupePeerId(peer_id_arg);
    defer allocator.free(peer_id);
    return js.env().createDouble(m.getPeerScore(peer_id));
}

test "parsePeerActionName accepts Lodestar JS action names" {
    try std.testing.expectEqual(PeerAction.mid_tolerance, parsePeerActionName("MidToleranceError").?);
    try std.testing.expectEqual(PeerAction.low_tolerance, parsePeerActionName("LowToleranceError").?);
    try std.testing.expectEqual(PeerAction.high_tolerance, parsePeerActionName("HighToleranceError").?);
    try std.testing.expectEqual(PeerAction.fatal, parsePeerActionName("Fatal").?);
}

test "parsePeerActionName accepts Zig enum names" {
    try std.testing.expectEqual(PeerAction.mid_tolerance, parsePeerActionName("mid_tolerance").?);
    try std.testing.expectEqual(PeerAction.fatal, parsePeerActionName("fatal").?);
    try std.testing.expect(parsePeerActionName("not-a-real-action") == null);
}
