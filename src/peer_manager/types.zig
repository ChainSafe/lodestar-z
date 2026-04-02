const std = @import("std");
const constants = @import("constants.zig");

// --- Core Type Aliases ---

pub const PeerIdStr = []const u8;

// --- Enums ---

pub const Direction = enum {
    inbound,
    outbound,
};

pub const RelevantPeerStatus = enum {
    unknown,
    relevant,
    irrelevant,
};

pub const ScoreState = enum {
    healthy,
    disconnected,
    banned,
};

pub const Encoding = enum {
    ssz,
    ssz_snappy,
};

pub const ForkName = enum {
    phase0,
    altair,
    bellatrix,
    capella,
    deneb,
    electra,
    fulu,
    gloas,
    heze,

    pub fn isPostFulu(self: ForkName) bool {
        return @intFromEnum(self) >= @intFromEnum(ForkName.fulu);
    }
};

pub const ClientKind = enum {
    lighthouse,
    nimbus,
    teku,
    prysm,
    lodestar,
    grandine,
    unknown,
};

/// Port of getKnownClientFromAgentVersion() from client.ts.
/// Returns null for unrecognized agents (not ClientKind.unknown).
pub fn getKnownClientFromAgentVersion(agent_version: []const u8) ?ClientKind {
    const slash_index = std.mem.indexOfScalar(u8, agent_version, '/');
    const agent = if (slash_index) |idx| agent_version[0..idx] else agent_version;

    if (std.ascii.eqlIgnoreCase(agent, "lighthouse")) return .lighthouse;
    if (std.ascii.eqlIgnoreCase(agent, "teku")) return .teku;
    if (std.ascii.eqlIgnoreCase(agent, "prysm")) return .prysm;
    if (std.ascii.eqlIgnoreCase(agent, "nimbus")) return .nimbus;
    if (std.ascii.eqlIgnoreCase(agent, "grandine")) return .grandine;
    if (std.ascii.eqlIgnoreCase(agent, "lodestar")) return .lodestar;
    if (std.ascii.eqlIgnoreCase(agent, "js-libp2p")) return .lodestar;

    return null;
}

pub const PeerAction = enum {
    fatal,
    low_tolerance,
    mid_tolerance,
    high_tolerance,

    /// Returns the score delta for this action.
    /// Port of peerActionScore from score/store.ts.
    pub fn scoreDelta(self: PeerAction) f64 {
        return switch (self) {
            .fatal => -(constants.MAX_SCORE - constants.MIN_SCORE),
            .low_tolerance => -10,
            .mid_tolerance => -5,
            .high_tolerance => -1,
        };
    }
};

pub const GoodbyeReasonCode = enum(u64) {
    client_shutdown = 1,
    irrelevant_network = 2,
    @"error" = 3,
    too_many_peers = 129,
    score_too_low = 250,
    banned = 251,
    inbound_disconnect = 252,
    _,
};

pub const ExcessPeerDisconnectReason = enum {
    low_score,
    no_long_lived_subnet,
    too_grouped_subnet,
    find_better_peers,
};

// --- Protocol Structs ---

pub const Status = struct {
    fork_digest: [4]u8,
    finalized_root: [32]u8,
    finalized_epoch: u64,
    head_root: [32]u8,
    head_slot: u64,
    /// Post-fulu only. Null for pre-fulu peers.
    earliest_available_slot: ?u64,
};

pub const Metadata = struct {
    seq_number: u64,
    /// 64-bit bitvector for attestation subnets.
    attnets: [8]u8,
    /// 4-bit bitvector for sync subnets (padded to 1 byte).
    syncnets: [1]u8,
    custody_group_count: u64,
    /// Allocator-owned, computed from node_id + custody_group_count.
    custody_groups: ?[]u32,
    /// Allocator-owned, computed from node_id + max(samples_per_slot, custody_group_count).
    sampling_groups: ?[]u32,
};

pub const PeerData = struct {
    /// Borrowed reference to the HashMap key. Do not free.
    peer_id: PeerIdStr,
    direction: Direction,
    status: ?Status,
    metadata: ?Metadata,
    relevant_status: RelevantPeerStatus,
    connected_unix_ts_ms: i64,
    last_received_msg_unix_ts_ms: i64,
    last_status_unix_ts_ms: i64,
    /// Allocator-owned string. Freed on peer removal or update.
    agent_version: ?[]const u8,
    agent_client: ?ClientKind,
    node_id: ?[32]u8,
    encoding_preference: ?Encoding,
};

pub const PeerScoreData = struct {
    lodestar_score: f64 = constants.DEFAULT_SCORE,
    gossip_score: f64 = constants.DEFAULT_SCORE,
    ignore_negative_gossip_score: bool = false,
    /// Computed final score from lodestar + gossip.
    score: f64 = constants.DEFAULT_SCORE,
    /// Last update timestamp. Set to future for cooldown/ban periods.
    last_update_ms: i64,
};

// --- Action Types ---

pub const Action = union(enum) {
    send_ping: PeerIdStr,
    send_status: PeerIdStr,
    send_goodbye: struct { peer_id: PeerIdStr, reason: GoodbyeReasonCode },
    request_metadata: PeerIdStr,
    disconnect_peer: PeerIdStr,
    request_discovery: DiscoveryRequest,
    tag_peer_relevant: PeerIdStr,
    emit_peer_connected: struct { peer_id: PeerIdStr, direction: Direction },
    emit_peer_disconnected: PeerIdStr,
};

pub const DiscoveryRequest = struct {
    peers_to_connect: u32,
    attnet_queries: []SubnetQuery,
    syncnet_queries: []SubnetQuery,
    custody_group_queries: []CustodyGroupQuery,
};

pub const SubnetQuery = struct {
    subnet: u32,
    to_slot: u64,
    max_peers_to_discover: u32,
};

pub const CustodyGroupQuery = struct {
    group: u32,
    max_peers_to_discover: u32,
};

pub const RequestedSubnet = struct {
    subnet: u32,
    to_slot: u64,
};

pub const PeerDisconnect = struct {
    peer_id: PeerIdStr,
    reason: ExcessPeerDisconnectReason,
};

pub const GossipScoreUpdate = struct {
    peer_id: []const u8,
    new_score: f64,
};

// --- Relevance Result ---

pub const IrrelevantPeerResult = union(enum) {
    incompatible_forks: struct { ours: [4]u8, theirs: [4]u8 },
    different_clocks: struct { slot_diff: i64 },
    different_finalized: struct { expected_root: [32]u8, remote_root: [32]u8 },
    no_earliest_available_slot: void,
};

// --- Config ---

pub const Config = struct {
    target_peers: u32 = 200,
    max_peers: u32 = 210,
    target_group_peers: u32 = 6,
    ping_interval_inbound_ms: i64 = 15_000,
    ping_interval_outbound_ms: i64 = 20_000,
    status_interval_ms: i64 = 300_000,
    status_inbound_grace_period_ms: i64 = 15_000,
    /// Gossipsub score weights. Both are equal, derived by the JS caller as:
    /// (MIN_SCORE_BEFORE_DISCONNECT + 1) / gossipScoreThresholds.graylistThreshold
    gossipsub_negative_score_weight: f64,
    gossipsub_positive_score_weight: f64,
    /// Threshold below which negative gossipsub scores are never ignored.
    /// Derived from gossipsub scoring parameters by the JS caller.
    negative_gossip_score_ignore_threshold: f64,
    disable_peer_scoring: bool = false,
    initial_fork_name: ForkName,
    number_of_custody_groups: u32 = 128,
    custody_requirement: u64 = 4,
    samples_per_slot: u64 = 8,
    slots_per_epoch: u64 = 32,
};

// --- Bitvector Helpers ---

/// Extract set bit indices from a 64-bit attestation subnet bitvector.
/// Returns stack-allocated bounded array — no heap allocation.
pub fn getAttnetsActiveBits(attnets: [8]u8) std.BoundedArray(u8, 64) {
    var result = std.BoundedArray(u8, 64){};
    for (attnets, 0..) |byte, byte_idx| {
        var b = byte;
        var bit_idx: u4 = 0;
        while (b != 0) : (bit_idx += 1) {
            if (b & 1 == 1) {
                result.appendAssumeCapacity(@intCast(byte_idx * 8 + bit_idx));
            }
            b >>= 1;
        }
    }
    return result;
}

/// Extract set bit indices from a sync subnet bitvector (up to 8 bits).
pub fn getSyncnetsActiveBits(syncnets: [1]u8) std.BoundedArray(u8, 8) {
    var result = std.BoundedArray(u8, 8){};
    var b = syncnets[0];
    var bit_idx: u4 = 0;
    while (b != 0) : (bit_idx += 1) {
        if (b & 1 == 1) {
            result.appendAssumeCapacity(bit_idx);
        }
        b >>= 1;
    }
    return result;
}

// --- Tests ---

test "getKnownClientFromAgentVersion" {
    try std.testing.expectEqual(ClientKind.lighthouse, getKnownClientFromAgentVersion("Lighthouse/v4.5.0").?);
    try std.testing.expectEqual(ClientKind.teku, getKnownClientFromAgentVersion("teku/v23.1.0").?);
    try std.testing.expectEqual(ClientKind.prysm, getKnownClientFromAgentVersion("Prysm/v4.0.0").?);
    try std.testing.expectEqual(ClientKind.nimbus, getKnownClientFromAgentVersion("nimbus").?);
    try std.testing.expectEqual(ClientKind.lodestar, getKnownClientFromAgentVersion("Lodestar/v1.0.0").?);
    try std.testing.expectEqual(ClientKind.lodestar, getKnownClientFromAgentVersion("js-libp2p/0.42.0").?);
    try std.testing.expectEqual(ClientKind.grandine, getKnownClientFromAgentVersion("Grandine/v0.3.0").?);
    try std.testing.expect(getKnownClientFromAgentVersion("UnknownClient/v1.0") == null);
}

test "getAttnetsActiveBits" {
    // Bit 0 and bit 8 set
    const attnets = [8]u8{ 0x01, 0x01, 0, 0, 0, 0, 0, 0 };
    const bits = getAttnetsActiveBits(attnets);
    try std.testing.expectEqual(@as(usize, 2), bits.len);
    try std.testing.expectEqual(@as(u8, 0), bits.buffer[0]);
    try std.testing.expectEqual(@as(u8, 8), bits.buffer[1]);
}

test "getSyncnetsActiveBits" {
    // Bits 0, 2 set
    const syncnets = [1]u8{0x05};
    const bits = getSyncnetsActiveBits(syncnets);
    try std.testing.expectEqual(@as(usize, 2), bits.len);
    try std.testing.expectEqual(@as(u8, 0), bits.buffer[0]);
    try std.testing.expectEqual(@as(u8, 2), bits.buffer[1]);
}

test "getAttnetsActiveBits empty" {
    const attnets = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const bits = getAttnetsActiveBits(attnets);
    try std.testing.expectEqual(@as(usize, 0), bits.len);
}

test "ForkName.isPostFulu" {
    try std.testing.expect(!ForkName.deneb.isPostFulu());
    try std.testing.expect(!ForkName.electra.isPostFulu());
    try std.testing.expect(ForkName.fulu.isPostFulu());
    try std.testing.expect(ForkName.gloas.isPostFulu());
}

test "PeerAction.scoreDelta" {
    try std.testing.expectEqual(@as(f64, -200), PeerAction.fatal.scoreDelta());
    try std.testing.expectEqual(@as(f64, -10), PeerAction.low_tolerance.scoreDelta());
    try std.testing.expectEqual(@as(f64, -5), PeerAction.mid_tolerance.scoreDelta());
    try std.testing.expectEqual(@as(f64, -1), PeerAction.high_tolerance.scoreDelta());
}
