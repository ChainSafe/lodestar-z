const std = @import("std");
const napi = @import("zapi:napi");
const peer_manager = @import("peer_manager");

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

/// Allocator for internal allocations.
const allocator = std.heap.page_allocator;

pub const State = struct {
    manager: ?PeerManager = null,

    pub fn init(self: *State, config: Config) !void {
        if (self.manager != null) return error.AlreadyInitialized;
        self.manager = try PeerManager.init(
            allocator,
            config,
            std.time.milliTimestamp,
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
    config.custody_requirement = try (try obj.getNamedProperty("custodyRequirement")).getValueUint64();
    config.samples_per_slot = try (try obj.getNamedProperty("samplesPerSlot")).getValueUint64();
    config.slots_per_epoch = try (try obj.getNamedProperty("slotsPerEpoch")).getValueUint64();

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

    status.finalized_epoch = try (try obj.getNamedProperty("finalizedEpoch")).getValueUint64();

    const head_root_info = try (try obj.getNamedProperty("headRoot")).getTypedarrayInfo();
    if (head_root_info.data.len != 32) return error.InvalidHeadRootLength;
    @memcpy(&status.head_root, head_root_info.data[0..32]);

    status.head_slot = try (try obj.getNamedProperty("headSlot")).getValueUint64();

    const eas_value = try obj.getNamedProperty("earliestAvailableSlot");
    const eas_type = try eas_value.typeOf();
    if (eas_type == .undefined or eas_type == .null) {
        status.earliest_available_slot = null;
    } else {
        status.earliest_available_slot = try eas_value.getValueUint64();
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

fn readPeerId(value: napi.Value) ![]const u8 {
    var buf: [128]u8 = undefined;
    return try value.getValueStringUtf8(&buf);
}

// ── Lifecycle ────────────────────────────────────────────────────────

pub fn PeerManager_init(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const config_obj = try cb.arg(0).coerceToObject();
    const config = try configFromObject(env, config_obj);
    try state.init(config);
    return env.getUndefined();
}

pub fn PeerManager_close(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    state.deinit();
    return env.getUndefined();
}

// ── Tick Functions ───────────────────────────────────────────────────

pub fn PeerManager_heartbeat(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const m = try getManager();
    const current_slot = try cb.arg(0).getValueUint64();
    const local_status = try statusFromObject(env, try cb.arg(1).coerceToObject());
    const actions = try m.heartbeat(current_slot, local_status);
    return actionsToNapiArray(env, actions);
}

pub fn PeerManager_checkPingAndStatus(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    const m = try getManager();
    const actions = try m.checkPingAndStatus();
    return actionsToNapiArray(env, actions);
}

// ── Event Handlers ───────────────────────────────────────────────────

pub fn PeerManager_onConnectionOpen(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    var dir_buf: [16]u8 = undefined;
    const dir_str = try cb.arg(1).getValueStringUtf8(&dir_buf);
    const direction = std.meta.stringToEnum(Direction, dir_str) orelse
        return error.InvalidDirection;
    const actions = try m.onConnectionOpen(peer_id, direction);
    return actionsToNapiArray(env, actions);
}

pub fn PeerManager_onConnectionClose(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    const actions = try m.onConnectionClose(peer_id);
    return actionsToNapiArray(env, actions);
}

pub fn PeerManager_onStatusReceived(env: napi.Env, cb: napi.CallbackInfo(4)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    const remote_status = try statusFromObject(env, try cb.arg(1).coerceToObject());
    const local_status = try statusFromObject(env, try cb.arg(2).coerceToObject());
    const current_slot = try cb.arg(3).getValueUint64();
    const actions = try m.onStatusReceived(peer_id, remote_status, local_status, current_slot);
    return actionsToNapiArray(env, actions);
}

pub fn PeerManager_onMetadataReceived(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    const md_obj = try cb.arg(1).coerceToObject();

    var metadata: Metadata = undefined;
    metadata.seq_number = try (try md_obj.getNamedProperty("seqNumber")).getValueUint64();

    const attnets_info = try (try md_obj.getNamedProperty("attnets")).getTypedarrayInfo();
    if (attnets_info.data.len != 8) return error.InvalidAttnetsLength;
    @memcpy(&metadata.attnets, attnets_info.data[0..8]);

    const syncnets_info = try (try md_obj.getNamedProperty("syncnets")).getTypedarrayInfo();
    if (syncnets_info.data.len != 1) return error.InvalidSyncnetsLength;
    @memcpy(&metadata.syncnets, syncnets_info.data[0..1]);

    metadata.custody_group_count = try (try md_obj.getNamedProperty("custodyGroupCount")).getValueUint64();
    metadata.custody_groups = null;
    metadata.sampling_groups = null;

    m.onMetadataReceived(peer_id, metadata);
    return env.getUndefined();
}

pub fn PeerManager_onMessageReceived(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    m.onMessageReceived(peer_id);
    return env.getUndefined();
}

pub fn PeerManager_onGoodbye(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    const reason_raw = try cb.arg(1).getValueUint64();
    const reason: GoodbyeReasonCode = @enumFromInt(reason_raw);
    const actions = try m.onGoodbye(peer_id, reason);
    return actionsToNapiArray(env, actions);
}

pub fn PeerManager_onPing(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    const seq_number = try cb.arg(1).getValueUint64();
    const actions = try m.onPing(peer_id, seq_number);
    return actionsToNapiArray(env, actions);
}

// ── Score Mutations ──────────────────────────────────────────────────

pub fn PeerManager_reportPeer(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    var action_buf: [32]u8 = undefined;
    const action_str = try cb.arg(1).getValueStringUtf8(&action_buf);
    const action = std.meta.stringToEnum(PeerAction, action_str) orelse
        return error.InvalidPeerAction;
    m.reportPeer(peer_id, action);
    return env.getUndefined();
}

pub fn PeerManager_updateGossipScores(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const arr = cb.arg(0);
    const len = try arr.getArrayLength();
    const scores = try allocator.alloc(GossipScoreUpdate, len);
    defer allocator.free(scores);

    for (0..len) |i| {
        const entry = try arr.getElement(@intCast(i));
        var pid_buf: [128]u8 = undefined;
        const pid = try (try entry.getNamedProperty("peerId")).getValueStringUtf8(&pid_buf);
        scores[i] = .{
            .peer_id = pid,
            .new_score = try (try entry.getNamedProperty("score")).getValueDouble(),
        };
    }
    m.updateGossipScores(scores);
    return env.getUndefined();
}

// ── Configuration Updates ────────────────────────────────────────────

pub fn PeerManager_setSubnetRequirements(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const m = try getManager();

    const attnets_arr = cb.arg(0);
    const attnets_len = try attnets_arr.getArrayLength();
    const attnets = try allocator.alloc(RequestedSubnet, attnets_len);
    defer allocator.free(attnets);
    for (0..attnets_len) |i| {
        const entry = try attnets_arr.getElement(@intCast(i));
        attnets[i] = .{
            .subnet = try (try entry.getNamedProperty("subnet")).getValueUint32(),
            .to_slot = try (try entry.getNamedProperty("toSlot")).getValueUint64(),
        };
    }

    const syncnets_arr = cb.arg(1);
    const syncnets_len = try syncnets_arr.getArrayLength();
    const syncnets = try allocator.alloc(RequestedSubnet, syncnets_len);
    defer allocator.free(syncnets);
    for (0..syncnets_len) |i| {
        const entry = try syncnets_arr.getElement(@intCast(i));
        syncnets[i] = .{
            .subnet = try (try entry.getNamedProperty("subnet")).getValueUint32(),
            .to_slot = try (try entry.getNamedProperty("toSlot")).getValueUint64(),
        };
    }

    try m.setSubnetRequirements(attnets, syncnets);
    return env.getUndefined();
}

pub fn PeerManager_setForkName(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    var fork_buf: [32]u8 = undefined;
    const fork_str = try cb.arg(0).getValueStringUtf8(&fork_buf);
    const fork_name = std.meta.stringToEnum(ForkName, fork_str) orelse
        return error.InvalidForkName;
    m.setForkName(fork_name);
    return env.getUndefined();
}

pub fn PeerManager_setSamplingGroups(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const arr = cb.arg(0);
    const len = try arr.getArrayLength();
    const groups = try allocator.alloc(u32, len);
    defer allocator.free(groups);
    for (0..len) |i| {
        const elem = try arr.getElement(@intCast(i));
        groups[i] = try elem.getValueUint32();
    }
    try m.setSamplingGroups(groups);
    return env.getUndefined();
}

// ── Queries ──────────────────────────────────────────────────────────

pub fn PeerManager_getConnectedPeerCount(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    const m = try getManager();
    return env.createUint32(m.getConnectedPeerCount());
}

pub fn PeerManager_getConnectedPeers(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    const m = try getManager();
    var iter = m.store.iterPeers();
    var count: u32 = 0;
    // Count first to create array with correct length.
    var iter_count = m.store.iterPeers();
    while (iter_count.next()) |_| count += 1;

    const arr = try env.createArrayWithLength(count);
    var idx: u32 = 0;
    while (iter.next()) |entry| {
        try arr.setElement(idx, try env.createStringUtf8(entry.value_ptr.peer_id));
        idx += 1;
    }
    return arr;
}

pub fn PeerManager_getPeerData(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
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

pub fn PeerManager_getEncodingPreference(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    const encoding = m.getEncodingPreference(peer_id) orelse return env.getNull();
    return env.createStringUtf8(@tagName(encoding));
}

pub fn PeerManager_getPeerKind(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    const kind = m.getPeerKind(peer_id) orelse return env.getNull();
    return env.createStringUtf8(@tagName(kind));
}

pub fn PeerManager_getAgentVersion(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    const av = m.getAgentVersion(peer_id) orelse return env.getNull();
    return env.createStringUtf8(av);
}

pub fn PeerManager_getPeerScore(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const m = try getManager();
    const peer_id = try readPeerId(cb.arg(0));
    return env.createDouble(m.getPeerScore(peer_id));
}

// ── Registration ─────────────────────────────────────────────────────

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const pm_obj = try env.createObject();

    // Lifecycle
    try pm_obj.setNamedProperty("init", try env.createFunction("init", 1, PeerManager_init, null));
    try pm_obj.setNamedProperty("close", try env.createFunction("close", 0, PeerManager_close, null));

    // Tick
    try pm_obj.setNamedProperty("heartbeat", try env.createFunction("heartbeat", 2, PeerManager_heartbeat, null));
    try pm_obj.setNamedProperty("checkPingAndStatus", try env.createFunction("checkPingAndStatus", 0, PeerManager_checkPingAndStatus, null));

    // Event handlers
    try pm_obj.setNamedProperty("onConnectionOpen", try env.createFunction("onConnectionOpen", 2, PeerManager_onConnectionOpen, null));
    try pm_obj.setNamedProperty("onConnectionClose", try env.createFunction("onConnectionClose", 1, PeerManager_onConnectionClose, null));
    try pm_obj.setNamedProperty("onStatusReceived", try env.createFunction("onStatusReceived", 4, PeerManager_onStatusReceived, null));
    try pm_obj.setNamedProperty("onMetadataReceived", try env.createFunction("onMetadataReceived", 2, PeerManager_onMetadataReceived, null));
    try pm_obj.setNamedProperty("onMessageReceived", try env.createFunction("onMessageReceived", 1, PeerManager_onMessageReceived, null));
    try pm_obj.setNamedProperty("onGoodbye", try env.createFunction("onGoodbye", 2, PeerManager_onGoodbye, null));
    try pm_obj.setNamedProperty("onPing", try env.createFunction("onPing", 2, PeerManager_onPing, null));

    // Score mutations
    try pm_obj.setNamedProperty("reportPeer", try env.createFunction("reportPeer", 2, PeerManager_reportPeer, null));
    try pm_obj.setNamedProperty("updateGossipScores", try env.createFunction("updateGossipScores", 1, PeerManager_updateGossipScores, null));

    // Configuration
    try pm_obj.setNamedProperty("setSubnetRequirements", try env.createFunction("setSubnetRequirements", 2, PeerManager_setSubnetRequirements, null));
    try pm_obj.setNamedProperty("setForkName", try env.createFunction("setForkName", 1, PeerManager_setForkName, null));
    try pm_obj.setNamedProperty("setSamplingGroups", try env.createFunction("setSamplingGroups", 1, PeerManager_setSamplingGroups, null));

    // Queries
    try pm_obj.setNamedProperty("getConnectedPeerCount", try env.createFunction("getConnectedPeerCount", 0, PeerManager_getConnectedPeerCount, null));
    try pm_obj.setNamedProperty("getConnectedPeers", try env.createFunction("getConnectedPeers", 0, PeerManager_getConnectedPeers, null));
    try pm_obj.setNamedProperty("getPeerData", try env.createFunction("getPeerData", 1, PeerManager_getPeerData, null));
    try pm_obj.setNamedProperty("getEncodingPreference", try env.createFunction("getEncodingPreference", 1, PeerManager_getEncodingPreference, null));
    try pm_obj.setNamedProperty("getPeerKind", try env.createFunction("getPeerKind", 1, PeerManager_getPeerKind, null));
    try pm_obj.setNamedProperty("getAgentVersion", try env.createFunction("getAgentVersion", 1, PeerManager_getAgentVersion, null));
    try pm_obj.setNamedProperty("getPeerScore", try env.createFunction("getPeerScore", 1, PeerManager_getPeerScore, null));

    try exports.setNamedProperty("peerManager", pm_obj);
}
