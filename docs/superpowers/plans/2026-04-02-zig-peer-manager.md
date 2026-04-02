# Zig Peer Manager Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a Zig peer manager module for lodestar-z, porting the peer lifecycle, scoring, prioritization, and connection logic from Lodestar's TypeScript implementation.

**Architecture:** Bottom-up layered build — types/constants first, then PeerStore (data), PeerScorer (scoring), pure functions (relevance, prioritization), PeerManager (orchestrator), NAPI bindings. Each layer is independently testable. All algorithm code is line-by-line translated from the TS source at `docs/superpowers/reference/lodestar-ts-peer-manager.md`.

**Tech Stack:** Zig (std library only), zapi (NAPI wrapper), pnpm/vitest (TS integration tests)

**Spec:** `docs/superpowers/specs/2026-04-02-zig-peer-manager-design.md`
**TS Reference:** `docs/superpowers/reference/lodestar-ts-peer-manager.md`
**Style Guide:** `.gemini/styleguide.md` (TigerStyle — max 70-line functions, assert-heavy, snake_case)

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/peer_manager/constants.zig` | Create | Score thresholds, intervals, ratios |
| `src/peer_manager/types.zig` | Create | All shared types, enums, structs, helpers |
| `src/peer_manager/store.zig` | Create | PeerStore — HashMap-backed peer data storage |
| `src/peer_manager/scorer.zig` | Create | PeerScorer — score tracking, decay, gossipsub blending |
| `src/peer_manager/relevance.zig` | Create | assertPeerRelevance pure function |
| `src/peer_manager/prioritize.zig` | Create | prioritizePeers algorithm + helpers |
| `src/peer_manager/manager.zig` | Create | PeerManager — orchestrator composing all layers |
| `src/peer_manager/root.zig` | Create | Module entry point, re-exports |
| `build.zig` | Modify | Register peer_manager module + test step |
| `bindings/napi/peer_manager.zig` | Create | NAPI binding layer |
| `bindings/napi/root.zig` | Modify | Register peer_manager bindings |
| `bindings/test/peer_manager.test.ts` | Create | TypeScript integration tests |

---

## Chunk 1: Foundation — Types, Constants, Build Scaffolding

### Task 1: Create constants.zig

**Files:**
- Create: `src/peer_manager/constants.zig`

- [ ] **Step 1: Create `src/peer_manager/constants.zig`**

Port all constants from TS `score/constants.ts` and `peerManager.ts`. Refer to spec section 1.

```zig
const std = @import("std");

// --- Score Thresholds (port of score/constants.ts) ---

/// The default score for new peers.
pub const DEFAULT_SCORE: f64 = 0;
/// The minimum reputation before a peer is disconnected.
pub const MIN_SCORE_BEFORE_DISCONNECT: f64 = -20;
/// The minimum reputation before a peer is banned.
pub const MIN_SCORE_BEFORE_BAN: f64 = -50;
/// If a peer has a lodestar score below this, all other score parts are ignored
/// and the peer is banned regardless.
pub const MIN_LODESTAR_SCORE_BEFORE_BAN: f64 = -60.0;
/// The maximum score a peer can obtain.
pub const MAX_SCORE: f64 = 100;
/// The minimum score a peer can obtain.
pub const MIN_SCORE: f64 = -100;
/// Drop score if absolute value is below this threshold.
pub const SCORE_THRESHOLD: f64 = 1;
/// The halflife of a peer's score in milliseconds (10 minutes).
pub const SCORE_HALFLIFE_MS: f64 = 10 * 60 * 1000;
/// Precomputed decay constant: -ln(2) / SCORE_HALFLIFE_MS.
pub const HALFLIFE_DECAY_MS: f64 = -@log(2.0) / SCORE_HALFLIFE_MS;
/// Milliseconds to ban a peer before their score begins to decay (30 minutes).
pub const COOL_DOWN_BEFORE_DECAY_MS: i64 = 30 * 60 * 1000;
/// Maximum entries in the scores map.
pub const MAX_SCORE_ENTRIES: u32 = 1000;
/// Returned when no cooldown is applied.
pub const NO_COOL_DOWN_APPLIED: i64 = -1;

// --- Peer Manager Intervals (port of peerManager.ts) ---

/// Ping interval for inbound peers (15 seconds).
pub const PING_INTERVAL_INBOUND_MS: i64 = 15 * 1000;
/// Ping interval for outbound peers (20 seconds).
pub const PING_INTERVAL_OUTBOUND_MS: i64 = 20 * 1000;
/// Status exchange interval (5 minutes).
pub const STATUS_INTERVAL_MS: i64 = 5 * 60 * 1000;
/// Grace period for inbound STATUS (15 seconds).
pub const STATUS_INBOUND_GRACE_PERIOD_MS: i64 = 15 * 1000;
/// A peer is considered long connection if >= 1 day.
pub const LONG_PEER_CONNECTION_MS: i64 = 24 * 60 * 60 * 1000;
/// Recommended heartbeat call interval for NAPI callers (30 seconds).
/// Not used by the Zig module itself (tick-driven).
pub const HEARTBEAT_INTERVAL_MS: i64 = 30 * 1000;
/// Recommended check-ping-status call interval for NAPI callers (10 seconds).
/// Not used by the Zig module itself (tick-driven).
pub const CHECK_PING_STATUS_INTERVAL: i64 = 10 * 1000;

// --- Prioritization Constants (port of prioritizePeers.ts) ---

/// Target number of peers per active long-lived subnet.
pub const TARGET_SUBNET_PEERS: u32 = 6;
/// Target peers per non-sampling custody group (PeerDAS).
pub const TARGET_GROUP_PEERS_PER_SUBNET: u32 = 4;
/// Minimum peers per active sync committee to avoid pruning.
pub const MIN_SYNC_COMMITTEE_PEERS: u32 = 2;
/// Score threshold below which peers are pruned when over target.
pub const LOW_SCORE_TO_PRUNE_IF_TOO_MANY_PEERS: f64 = -2;
/// Overshoot factor for connection attempts (low success rate ~33%).
pub const PEERS_TO_CONNECT_OVERSHOOT_FACTOR: u32 = 3;
/// Minimum ratio of outbound peers to maintain.
pub const OUTBOUND_PEERS_RATIO: f64 = 0.1;
/// Tolerance for remote peer's head slot being ahead of ours.
pub const FUTURE_SLOT_TOLERANCE: u64 = 1;
/// Fraction of peers allowed to have negative gossipsub scores without penalty.
pub const ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR: f64 = 0.1;
/// Fraction of additional peers to prune during starvation.
pub const STARVATION_PRUNE_RATIO: f64 = 0.05;

test {
    // Verify the decay constant is computed correctly.
    const expected = -@log(2.0) / (10.0 * 60.0 * 1000.0);
    try std.testing.expectApproxEqAbs(expected, HALFLIFE_DECAY_MS, 1e-20);
}
```

- [ ] **Step 2: Verify it compiles**

Run: `zig build-lib src/peer_manager/constants.zig --name constants_check 2>&1; echo "exit: $?"`
Expected: Compiles without errors (exit 0). Clean up: `rm -f constants_check*`

- [ ] **Step 3: Commit**

```bash
git add src/peer_manager/constants.zig
git commit -m "feat(peer_manager): add constants.zig with score thresholds and intervals"
```

---

### Task 2: Create types.zig

**Files:**
- Create: `src/peer_manager/types.zig`

- [ ] **Step 1: Create `src/peer_manager/types.zig`**

All shared types from spec section 2. This is a large file — write the full implementation. Port `getKnownClientFromAgentVersion` from TS `client.ts` and bitvector helpers.

```zig
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
```

- [ ] **Step 2: Verify it compiles and tests pass**

Run: `zig test src/peer_manager/types.zig 2>&1 | tail -5`
Expected: `All 6 tests passed.`

- [ ] **Step 3: Commit**

```bash
git add src/peer_manager/types.zig
git commit -m "feat(peer_manager): add types.zig with all shared types and helpers"
```

---

### Task 3: Create root.zig and register in build.zig

**Files:**
- Create: `src/peer_manager/root.zig`
- Modify: `build.zig`

- [ ] **Step 1: Create `src/peer_manager/root.zig`**

Minimal re-exports for now. More will be added as layers are built.

```zig
const types_ = @import("types.zig");

// Types
pub const PeerIdStr = types_.PeerIdStr;
pub const Direction = types_.Direction;
pub const RelevantPeerStatus = types_.RelevantPeerStatus;
pub const ScoreState = types_.ScoreState;
pub const Encoding = types_.Encoding;
pub const ForkName = types_.ForkName;
pub const ClientKind = types_.ClientKind;
pub const PeerAction = types_.PeerAction;
pub const GoodbyeReasonCode = types_.GoodbyeReasonCode;
pub const ExcessPeerDisconnectReason = types_.ExcessPeerDisconnectReason;
pub const Status = types_.Status;
pub const Metadata = types_.Metadata;
pub const PeerData = types_.PeerData;
pub const PeerScoreData = types_.PeerScoreData;
pub const Action = types_.Action;
pub const DiscoveryRequest = types_.DiscoveryRequest;
pub const SubnetQuery = types_.SubnetQuery;
pub const CustodyGroupQuery = types_.CustodyGroupQuery;
pub const RequestedSubnet = types_.RequestedSubnet;
pub const PeerDisconnect = types_.PeerDisconnect;
pub const GossipScoreUpdate = types_.GossipScoreUpdate;
pub const IrrelevantPeerResult = types_.IrrelevantPeerResult;
pub const Config = types_.Config;
pub const getKnownClientFromAgentVersion = types_.getKnownClientFromAgentVersion;
pub const getAttnetsActiveBits = types_.getAttnetsActiveBits;
pub const getSyncnetsActiveBits = types_.getSyncnetsActiveBits;

// Constants
pub const constants = @import("constants.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
```

- [ ] **Step 2: Register module and test step in `build.zig`**

Find the module registration section (after the last `b.modules.put` call) and add:

```zig
const module_peer_manager = b.createModule(.{
    .root_source_file = b.path("src/peer_manager/root.zig"),
    .target = target,
    .optimize = optimize,
});
b.modules.put(b.dupe("peer_manager"), module_peer_manager) catch @panic("OOM");
```

Find the test registration section (after the last `tls_run_test.dependOn` call) and add:

```zig
const test_peer_manager = b.addTest(.{
    .name = "peer_manager",
    .root_module = module_peer_manager,
    .filters = b.option([][]const u8, "peer_manager.filters", "peer_manager test filters") orelse &[_][]const u8{},
});
const install_test_peer_manager = b.addInstallArtifact(test_peer_manager, .{});
const tls_install_test_peer_manager = b.step("build-test:peer_manager", "Install the peer_manager test");
tls_install_test_peer_manager.dependOn(&install_test_peer_manager.step);

const run_test_peer_manager = b.addRunArtifact(test_peer_manager);
const tls_run_test_peer_manager = b.step("test:peer_manager", "Run the peer_manager test");
tls_run_test_peer_manager.dependOn(&run_test_peer_manager.step);
tls_run_test.dependOn(&run_test_peer_manager.step);
```

- [ ] **Step 3: Verify build and tests pass**

Run: `zig build test:peer_manager 2>&1 | tail -5`
Expected: All tests pass (types.zig tests + constants.zig tests run via `refAllDecls`).

- [ ] **Step 4: Commit**

```bash
git add src/peer_manager/root.zig build.zig
git commit -m "feat(peer_manager): add root.zig and register module in build.zig"
```

---

## Chunk 2: PeerStore

### Task 4: Implement PeerStore

**Files:**
- Create: `src/peer_manager/store.zig`
- Modify: `src/peer_manager/root.zig` (add re-export)

**Reference:** Spec section 3. TS `peers/peersData.ts` and `peerManager.ts:trackLibp2pConnection` (lines 812-816 in TS reference).

- [ ] **Step 1: Write failing tests for PeerStore**

Add at the bottom of `src/peer_manager/store.zig`:

```zig
const std = @import("std");
const types = @import("types.zig");
const constants = @import("constants.zig");

const Allocator = std.mem.Allocator;
const PeerData = types.PeerData;
const Direction = types.Direction;
const Status = types.Status;
const Metadata = types.Metadata;
const Encoding = types.Encoding;
const RelevantPeerStatus = types.RelevantPeerStatus;
const Config = types.Config;
const ClientKind = types.ClientKind;

pub const PeerStore = struct {
    // TODO: implement
};

// --- Tests ---

fn testConfig() Config {
    return .{
        .gossipsub_negative_score_weight = -0.1,
        .gossipsub_positive_score_weight = 0.1,
        .negative_gossip_score_ignore_threshold = -100,
        .initial_fork_name = .deneb,
    };
}

test "addPeer and getConnectedPeerCount" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();

    try store.addPeer("peer1", .outbound, 1000, testConfig());
    try std.testing.expectEqual(@as(u32, 1), store.getConnectedPeerCount());

    try store.addPeer("peer2", .inbound, 1000, testConfig());
    try std.testing.expectEqual(@as(u32, 2), store.getConnectedPeerCount());
}

test "addPeer duplicate returns error" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();

    try store.addPeer("peer1", .outbound, 1000, testConfig());
    try std.testing.expectError(error.PeerAlreadyExists, store.addPeer("peer1", .inbound, 2000, testConfig()));
    try std.testing.expectEqual(@as(u32, 1), store.getConnectedPeerCount());
}

test "addPeer sets direction-dependent timestamps" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();
    const config = testConfig();

    // Outbound: last_received_msg = 0, last_status = 0
    try store.addPeer("out1", .outbound, 5000, config);
    const out_data = store.getPeerData("out1").?;
    try std.testing.expectEqual(@as(i64, 5000), out_data.connected_unix_ts_ms);
    try std.testing.expectEqual(@as(i64, 0), out_data.last_received_msg_unix_ts_ms);
    try std.testing.expectEqual(@as(i64, 0), out_data.last_status_unix_ts_ms);

    // Inbound: last_received_msg = now, last_status = now - status_interval + grace_period
    try store.addPeer("in1", .inbound, 5000, config);
    const in_data = store.getPeerData("in1").?;
    try std.testing.expectEqual(@as(i64, 5000), in_data.connected_unix_ts_ms);
    try std.testing.expectEqual(@as(i64, 5000), in_data.last_received_msg_unix_ts_ms);
    const expected_last_status = 5000 - config.status_interval_ms + config.status_inbound_grace_period_ms;
    try std.testing.expectEqual(expected_last_status, in_data.last_status_unix_ts_ms);
}

test "removePeer frees owned memory" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();

    try store.addPeer("peer1", .outbound, 1000, testConfig());
    try store.setAgentVersion("peer1", "Lighthouse/v4.0.0");
    store.removePeer("peer1");
    try std.testing.expectEqual(@as(u32, 0), store.getConnectedPeerCount());
    try std.testing.expect(store.getPeerData("peer1") == null);
}

test "removePeer nonexistent is no-op" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();
    store.removePeer("nonexistent");
}

test "setAgentVersion frees previous" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();

    try store.addPeer("peer1", .outbound, 1000, testConfig());
    try store.setAgentVersion("peer1", "Lighthouse/v4.0.0");
    try store.setAgentVersion("peer1", "Teku/v23.0.0");

    const data = store.getPeerData("peer1").?;
    try std.testing.expectEqualStrings("Teku/v23.0.0", data.agent_version.?);
    // No leak detected by testing.allocator means previous was freed.
}

test "updateStatus round-trip" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();

    try store.addPeer("peer1", .outbound, 1000, testConfig());
    const status = Status{
        .fork_digest = .{ 1, 2, 3, 4 },
        .finalized_root = [_]u8{0xAA} ** 32,
        .finalized_epoch = 100,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 3200,
        .earliest_available_slot = null,
    };
    store.updateStatus("peer1", status);

    const data = store.getPeerData("peer1").?;
    try std.testing.expectEqual(@as(u64, 100), data.status.?.finalized_epoch);
    try std.testing.expectEqual(@as(u64, 3200), data.status.?.head_slot);
}

test "contains" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();

    try std.testing.expect(!store.contains("peer1"));
    try store.addPeer("peer1", .outbound, 1000, testConfig());
    try std.testing.expect(store.contains("peer1"));
}

test "iterPeers" {
    const allocator = std.testing.allocator;
    var store = PeerStore.init(allocator);
    defer store.deinit();

    try store.addPeer("peer1", .outbound, 1000, testConfig());
    try store.addPeer("peer2", .inbound, 2000, testConfig());

    var count: u32 = 0;
    var iter = store.iterPeers();
    while (iter.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(u32, 2), count);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test:peer_manager -- --test-filter "addPeer and getConnectedPeerCount" 2>&1 | tail -3`
Expected: FAIL (PeerStore has no `init`, etc.)

- [ ] **Step 3: Implement PeerStore**

Replace the `PeerStore` struct stub with the full implementation:

```zig
pub const PeerStore = struct {
    allocator: Allocator,
    peers: std.StringHashMap(PeerData),

    pub fn init(allocator: Allocator) PeerStore {
        return .{
            .allocator = allocator,
            .peers = std.StringHashMap(PeerData).init(allocator),
        };
    }

    pub fn deinit(self: *PeerStore) void {
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            self.freePeerOwnedMemory(entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.peers.deinit();
    }

    /// Add a peer with direction-dependent initial timestamps.
    /// Port of trackLibp2pConnection (peerManager.ts:812-816).
    pub fn addPeer(
        self: *PeerStore,
        peer_id: []const u8,
        direction: Direction,
        now_ms: i64,
        config: Config,
    ) !void {
        if (self.peers.contains(peer_id)) return error.PeerAlreadyExists;

        const key = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(key);

        const last_received = if (direction == .inbound) now_ms else @as(i64, 0);
        const last_status = if (direction == .inbound)
            now_ms - config.status_interval_ms + config.status_inbound_grace_period_ms
        else
            @as(i64, 0);

        try self.peers.put(key, PeerData{
            .peer_id = key,
            .direction = direction,
            .status = null,
            .metadata = null,
            .relevant_status = .unknown,
            .connected_unix_ts_ms = now_ms,
            .last_received_msg_unix_ts_ms = last_received,
            .last_status_unix_ts_ms = last_status,
            .agent_version = null,
            .agent_client = null,
            .node_id = null,
            .encoding_preference = null,
        });
    }

    pub fn removePeer(self: *PeerStore, peer_id: []const u8) void {
        if (self.peers.fetchRemove(peer_id)) |entry| {
            var data = entry.value;
            self.freePeerOwnedMemory(&data);
            self.allocator.free(entry.key);
        }
    }

    pub fn contains(self: *const PeerStore, peer_id: []const u8) bool {
        return self.peers.contains(peer_id);
    }

    pub fn getPeerData(self: *const PeerStore, peer_id: []const u8) ?*PeerData {
        return self.peers.getPtr(peer_id);
    }

    pub fn getConnectedPeerCount(self: *const PeerStore) u32 {
        return @intCast(self.peers.count());
    }

    pub fn updateStatus(self: *PeerStore, peer_id: []const u8, status: Status) void {
        if (self.peers.getPtr(peer_id)) |data| {
            data.status = status;
        }
    }

    pub fn updateMetadata(self: *PeerStore, peer_id: []const u8, metadata: Metadata) void {
        if (self.peers.getPtr(peer_id)) |data| {
            self.freeMetadataSlices(data);
            data.metadata = metadata;
        }
    }

    pub fn setAgentVersion(self: *PeerStore, peer_id: []const u8, version: []const u8) !void {
        if (self.peers.getPtr(peer_id)) |data| {
            if (data.agent_version) |old| self.allocator.free(old);
            data.agent_version = try self.allocator.dupe(u8, version);
            data.agent_client = types.getKnownClientFromAgentVersion(version);
        }
    }

    pub fn setEncodingPreference(self: *PeerStore, peer_id: []const u8, encoding: Encoding) void {
        if (self.peers.getPtr(peer_id)) |data| {
            data.encoding_preference = encoding;
        }
    }

    pub fn updateLastReceivedMsg(self: *PeerStore, peer_id: []const u8, now_ms: i64) void {
        if (self.peers.getPtr(peer_id)) |data| {
            data.last_received_msg_unix_ts_ms = now_ms;
        }
    }

    pub fn updateLastStatus(self: *PeerStore, peer_id: []const u8, now_ms: i64) void {
        if (self.peers.getPtr(peer_id)) |data| {
            data.last_status_unix_ts_ms = now_ms;
        }
    }

    pub fn iterPeers(self: *const PeerStore) std.StringHashMap(PeerData).Iterator {
        return self.peers.iterator();
    }

    fn freeMetadataSlices(self: *PeerStore, data: *PeerData) void {
        if (data.metadata) |md| {
            if (md.custody_groups) |cg| self.allocator.free(cg);
            if (md.sampling_groups) |sg| self.allocator.free(sg);
        }
    }

    fn freePeerOwnedMemory(self: *PeerStore, data: *PeerData) void {
        if (data.agent_version) |av| self.allocator.free(av);
        self.freeMetadataSlices(data);
    }
};
```

- [ ] **Step 4: Run all store tests**

Run: `zig build test:peer_manager 2>&1 | tail -3`
Expected: All tests pass with no leaks.

- [ ] **Step 5: Add PeerStore re-export to root.zig**

Add to `src/peer_manager/root.zig`:

```zig
pub const PeerStore = @import("store.zig").PeerStore;
```

- [ ] **Step 6: Run full module tests**

Run: `zig build test:peer_manager 2>&1 | tail -3`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/peer_manager/store.zig src/peer_manager/root.zig
git commit -m "feat(peer_manager): add PeerStore with HashMap-backed peer data storage"
```

---

## Chunk 3: PeerScorer

### Task 5: Implement PeerScorer

**Files:**
- Create: `src/peer_manager/scorer.zig`
- Modify: `src/peer_manager/root.zig` (add re-export)

**Reference:** Spec section 4. TS `score/score.ts` (RealScore), `score/store.ts` (PeerRpcScoreStore), `score/utils.ts`.

- [ ] **Step 1: Write failing tests for PeerScorer**

Create `src/peer_manager/scorer.zig` with the test block and a stub struct. Tests cover: report actions, decay, ban transitions, cooldowns, gossipsub blending, disable_peer_scoring mode.

The tests should use a fake clock:

```zig
// At top of file, after imports
var test_clock_value: i64 = 0;
fn testClock() i64 {
    return test_clock_value;
}

fn testConfig() Config {
    return .{
        .gossipsub_negative_score_weight = -0.5,
        .gossipsub_positive_score_weight = 0.5,
        .negative_gossip_score_ignore_threshold = -100,
        .initial_fork_name = .deneb,
    };
}
```

Key tests to write (each as a separate `test` block):

- `test "reportPeer fatal results in ban"` — report `.fatal`, verify `getScoreState == .banned`
- `test "reportPeer score clamping"` — report multiple `.low_tolerance`, verify score never below `MIN_SCORE`
- `test "decayScores exponential decay"` — set score to -50, advance clock by SCORE_HALFLIFE_MS, decay, verify score is approximately -25
- `test "decayScores does not decay during cooldown"` — ban peer, advance clock less than cooldown, verify score unchanged
- `test "isCoolingDown during ban period"` — report fatal, verify `isCoolingDown` is true, advance past cooldown, verify false
- `test "applyReconnectionCoolDown"` — apply each goodbye reason, verify correct cooldown durations
- `test "gossipsub positive score blending"` — set positive gossip score, verify it adds to final score
- `test "gossipsub negative score ignored for top peers"` — verify `ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR` logic
- `test "MIN_LODESTAR_SCORE_BEFORE_BAN ignores gossip"` — set lodestar below -60, verify gossip ignored
- `test "disable_peer_scoring returns MAX_SCORE"` — init with `disable_peer_scoring = true`, verify all queries return max
- `test "decayScores prunes below threshold"` — set small score, decay until below threshold, verify entry removed
- `test "scoreToState transitions"` — verify score->state mapping at boundaries

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test:peer_manager -- --test-filter "reportPeer fatal" 2>&1 | tail -3`
Expected: FAIL

- [ ] **Step 3: Implement PeerScorer**

Full implementation in `src/peer_manager/scorer.zig`. Key internal methods:

- `getOrCreateScore` — looks up or inserts a new `PeerScoreData` with duped key
- `recomputeScore` — port of `score.ts:recomputeScore` (spec lines 435-443)
- `setLodestarScore` — wrapper that calls `recomputeScore` and checks ban transition
- `scoreToState` — port of `score/utils.ts:scoreToState`
- `reportPeer` — gets/creates score, adds delta, clamps, calls `setLodestarScore`
- `decayScores` — prune to MAX_SCORE_ENTRIES, then decay each entry with `exp(HALFLIFE_DECAY_MS * elapsed)`
- `updateGossipScores` — sort descending, compute ignore count, update each
- `applyReconnectionCoolDown` — switch on reason, set `last_update_ms` to future
- `isCoolingDown` — `clock_fn() < last_update_ms`

- [ ] **Step 4: Run all scorer tests**

Run: `zig build test:peer_manager 2>&1 | tail -3`
Expected: All tests pass with no leaks.

- [ ] **Step 5: Add PeerScorer re-export to root.zig**

Add to `src/peer_manager/root.zig`:

```zig
pub const PeerScorer = @import("scorer.zig").PeerScorer;
```

- [ ] **Step 6: Run full module tests**

Run: `zig build test:peer_manager 2>&1 | tail -3`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/peer_manager/scorer.zig src/peer_manager/root.zig
git commit -m "feat(peer_manager): add PeerScorer with decay, gossipsub blending, and cooldowns"
```

---

## Chunk 4: Pure Functions — Relevance and Prioritization

### Task 6: Implement assertPeerRelevance

**Files:**
- Create: `src/peer_manager/relevance.zig`
- Modify: `src/peer_manager/root.zig` (add re-export)

**Reference:** Spec section 5. TS `utils/assertPeerRelevance.ts`.

- [ ] **Step 1: Write failing tests**

Create `src/peer_manager/relevance.zig` with tests covering all 4 irrelevant reasons + happy path:

```zig
test "relevant peer returns null" {
    // Same fork digest, close slot, same finalized root
}

test "incompatible forks" {
    // Different fork_digest
}

test "different clocks — remote too far ahead" {
    // remote.head_slot > current_slot + FUTURE_SLOT_TOLERANCE
}

test "different finalized — same epoch different root" {
    // Same finalized_epoch, different non-zero roots
}

test "different finalized — both zero roots is fine" {
    // Same finalized_epoch, both zero roots => relevant
}

test "no earliest available slot — post fulu" {
    // fork_name = .fulu, earliest_available_slot = null => irrelevant
}

test "no earliest available slot — pre fulu is fine" {
    // fork_name = .deneb, earliest_available_slot = null => relevant
}

test "different clocks — exact tolerance is ok" {
    // remote.head_slot == current_slot + FUTURE_SLOT_TOLERANCE => relevant (not >)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test:peer_manager -- --test-filter "relevant peer" 2>&1 | tail -3`
Expected: FAIL

- [ ] **Step 3: Implement assertPeerRelevance**

Line-by-line port from TS. ~50 lines of logic + `isZeroRoot` helper. The 4 checks in order:

1. `!std.mem.eql(u8, &local.fork_digest, &remote.fork_digest)` → `incompatible_forks`
2. Compute `slot_diff = @as(i64, @intCast(remote.head_slot)) - @as(i64, @intCast(@max(current_slot, 0)))`. If `slot_diff > FUTURE_SLOT_TOLERANCE` → `different_clocks`
3. If `remote.finalized_epoch <= local.finalized_epoch` and both roots non-zero and same epoch: compare roots → `different_finalized`
4. If `fork_name.isPostFulu()` and `remote.earliest_available_slot == null` → `no_earliest_available_slot`

- [ ] **Step 4: Run all relevance tests**

Run: `zig build test:peer_manager -- --test-filter "relevant\|incompatible\|different\|earliest" 2>&1 | tail -5`
Expected: All tests pass.

- [ ] **Step 5: Add re-export to root.zig**

```zig
pub const assertPeerRelevance = @import("relevance.zig").assertPeerRelevance;
```

- [ ] **Step 6: Commit**

```bash
git add src/peer_manager/relevance.zig src/peer_manager/root.zig
git commit -m "feat(peer_manager): add assertPeerRelevance with 4-check relevance validation"
```

---

### Task 7: Implement prioritizePeers

**Files:**
- Create: `src/peer_manager/prioritize.zig`
- Modify: `src/peer_manager/root.zig` (add re-export)

**Reference:** Spec section 6. TS `utils/prioritizePeers.ts` (~627 lines). This is the largest single task.

- [ ] **Step 1: Write failing tests**

Key test cases to port from TS behavior:

```zig
test "below target peers — returns peers_to_connect with overshoot" {
    // 50 connected, target 100, max 110 => peers_to_connect = min(3*50, 110-50) = 60
}

test "at target peers — no connect no disconnect" {
    // Exactly at target => peers_to_connect = 0, no disconnects
}

test "above target peers — disconnects excess" {
    // 120 connected, target 100 => disconnect ~20
}

test "subnet queries generated for under-covered attnets" {
    // Active attnet with < TARGET_SUBNET_PEERS peers => query generated
}

test "pruning order — no subnet peers pruned first" {
    // Peers with no attnets/syncnets are pruned before peers with subnets
}

test "outbound peers protected from pruning" {
    // Outbound peers up to OUTBOUND_PEERS_RATIO are not pruned
}

test "starvation prunes extra peers" {
    // starved = true => prune additional STARVATION_PRUNE_RATIO * target_peers
}

test "custody group queries post-fulu" {
    // With our_sampling_groups set, under-covered groups produce queries
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test:peer_manager -- --test-filter "below target" 2>&1 | tail -3`
Expected: FAIL

- [ ] **Step 3: Implement prioritizePeers**

Line-by-line port of the TS. Internal structure:

1. `PeerInfo` struct — enriched peer data with computed fields (status_score, attnet indices, etc.)
2. `computeStatusScore` — returns `CLOSE_TO_US` (-1) or `FAR_AHEAD` (0)
3. `requestSubnetPeers` — counts per-subnet coverage, generates queries, builds duties map
4. `pruneExcessPeers` — 4-phase pruning (no-subnet, low-score, too-grouped, find-better)
5. `sortPeersToPrune` — shuffle + multi-key sort
6. `findMaxPeersSubnet`, `findPeerToRemove` — helpers for too-grouped pruning
7. Main `prioritizePeers` — orchestrates all of the above

For the shuffle in `sortPeersToPrune`, use `std.Random.DefaultPrng` seeded with a timestamp or a passed-in seed. For test determinism, the seed can be controlled.

This file will be ~500-600 lines. Break internal functions to stay under 70 lines each per TigerStyle.

- [ ] **Step 4: Run all prioritize tests**

Run: `zig build test:peer_manager 2>&1 | tail -3`
Expected: All tests pass.

- [ ] **Step 5: Add re-export to root.zig**

```zig
pub const prioritizePeers = @import("prioritize.zig").prioritizePeers;
pub const PrioritizePeersResult = @import("prioritize.zig").PrioritizePeersResult;
pub const PrioritizePeersInput = @import("prioritize.zig").PrioritizePeersInput;
pub const PrioritizePeersOpts = @import("prioritize.zig").PrioritizePeersOpts;
```

- [ ] **Step 6: Commit**

```bash
git add src/peer_manager/prioritize.zig src/peer_manager/root.zig
git commit -m "feat(peer_manager): add prioritizePeers with subnet-aware connect/disconnect logic"
```

---

## Chunk 5: PeerManager Orchestrator

### Task 8: Implement PeerManager

**Files:**
- Create: `src/peer_manager/manager.zig`
- Modify: `src/peer_manager/root.zig` (add re-export)

**Reference:** Spec section 7. TS `peerManager.ts` (logic-only portions).

- [ ] **Step 1: Write failing tests**

Key tests using a fake clock and controlled peer state:

```zig
var test_clock_value: i64 = 0;
fn testClock() i64 {
    return test_clock_value;
}

test "onConnectionOpen — outbound emits ping and status" {
    // Connect outbound peer, verify actions contain send_ping and send_status
}

test "onConnectionOpen — duplicate is no-op" {
    // Connect same peer twice, second returns empty actions
}

test "onConnectionClose — inbound applies cooldown" {
    // Connect inbound peer, close it, verify scorer has cooldown applied
}

test "onConnectionClose — emits disconnect event" {
    // Connect and close, verify emit_peer_disconnected in actions
}

test "onStatusReceived — relevant peer emits tag and connected" {
    // Send matching status, verify tag_peer_relevant and emit_peer_connected
}

test "onStatusReceived — irrelevant peer emits goodbye" {
    // Send status with different fork digest, verify send_goodbye + disconnect_peer
}

test "onPing — higher seq triggers metadata request" {
    // Set metadata with seq 5, receive ping with seq 10, verify request_metadata
}

test "onGoodbye — emits disconnect only" {
    // Receive goodbye, verify only disconnect_peer (no cooldown)
}

test "checkPingAndStatus — inbound past interval emits ping" {
    // Connect inbound, advance clock past PING_INTERVAL_INBOUND_MS, verify send_ping
}

test "checkPingAndStatus — outbound past interval emits ping" {
    // Connect outbound, advance clock past PING_INTERVAL_OUTBOUND_MS, verify send_ping
}

test "checkPingAndStatus — past status interval emits status" {
    // Advance clock past STATUS_INTERVAL_MS, verify send_status
}

test "heartbeat — banned peer gets goodbye" {
    // Report peer fatal, call heartbeat, verify send_goodbye(banned) + disconnect_peer
}

test "heartbeat — below target triggers discovery" {
    // Few connected peers, verify request_discovery action
}

test "full lifecycle" {
    // connect → status → metadata → ping → heartbeat → disconnect
    // verify correct actions at each step
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test:peer_manager -- --test-filter "onConnectionOpen" 2>&1 | tail -3`
Expected: FAIL

- [ ] **Step 3: Implement PeerManager**

Full implementation in `src/peer_manager/manager.zig`. Key methods:

- `init` / `deinit` — create store, scorer, action buffer, state
- `heartbeat` — decay scores, check bans, call prioritizePeers, emit actions
- `checkPingAndStatus` — iterate peers, check timing thresholds
- `onConnectionOpen` — add to store with timestamps, emit outbound handshake actions
- `onConnectionClose` — apply inbound cooldown, remove peer, emit disconnect
- `onStatusReceived` — update store, check relevance, emit tag/goodbye
- `onPing` — check seq_number, emit metadata request
- `onGoodbye` — emit disconnect only
- `onMetadataReceived` — delegate to store
- `onMessageReceived` — update last_received timestamp
- `reportPeer` / `updateGossipScores` — delegate to scorer
- `setSubnetRequirements` / `setForkName` / `setSamplingGroups` — update state
- All query methods — delegate to store/scorer

Each method clears and returns the shared action buffer.

- [ ] **Step 4: Run all manager tests**

Run: `zig build test:peer_manager 2>&1 | tail -3`
Expected: All tests pass.

- [ ] **Step 5: Add PeerManager re-export to root.zig**

```zig
pub const PeerManager = @import("manager.zig").PeerManager;
```

- [ ] **Step 6: Run full module tests**

Run: `zig build test:peer_manager 2>&1 | tail -3`
Expected: All tests pass. This is the final Zig-only validation.

- [ ] **Step 7: Commit**

```bash
git add src/peer_manager/manager.zig src/peer_manager/root.zig
git commit -m "feat(peer_manager): add PeerManager orchestrating store, scorer, and prioritization"
```

---

## Chunk 6: NAPI Bindings and TypeScript Integration Tests

### Task 9: Implement NAPI bindings

**Files:**
- Create: `bindings/napi/peer_manager.zig`
- Modify: `bindings/napi/root.zig` (add registration)
- Modify: `build.zig` (add peer_manager import to bindings module)

**Reference:** Spec section 8. Existing pattern in `bindings/napi/pool.zig`, `bindings/napi/config.zig`.

- [ ] **Step 1: Add peer_manager module import to bindings in build.zig**

Find where `module_bindings` has its `addImport` calls and add:

```zig
module_bindings.addImport("peer_manager", module_peer_manager);
```

- [ ] **Step 2: Create `bindings/napi/peer_manager.zig`**

Follow the existing pattern from `bindings/napi/pool.zig`:

1. `State` struct with `manager: ?PeerManager = null`, `init`, `deinit`
2. `pub var state: State = .{};`
3. Binding functions with signature `fn(napi.Env, napi.CallbackInfo(N)) !napi.Value`
4. `register(env, exports)` function that creates a `peerManager` JS object and sets all named properties

Key helpers to implement:
- `configFromObject(env, obj)` — reads Config fields from JS object using `inline for (std.meta.fields(Config))` pattern
- `statusFromObject(env, obj)` — reads Status from JS object (Uint8Arrays for digests/roots, numbers for epochs/slots)
- `actionsToNapiArray(env, actions)` — converts `[]const Action` to JS array of `{type, peerId, ...}` objects

Start with lifecycle + tick functions + queries. Event handlers follow the same pattern.

- [ ] **Step 3: Add registration to `bindings/napi/root.zig`**

Add import at top:
```zig
const peer_manager = @import("./peer_manager.zig");
```

In the `register` function, add after the last `try *.register(env, exports)` call:
```zig
try peer_manager.register(env, exports);
```

In the `env_refcount.fetchAdd` block (first env init), add:
```zig
// No global state init needed — peer_manager.state.init() is called via NAPI init()
```

In the `EnvCleanup.hook` (last env cleanup), add:
```zig
peer_manager.state.deinit();
```

- [ ] **Step 4: Build the bindings library**

Run: `zig build build-lib:bindings 2>&1 | tail -5`
Expected: Compiles without errors.

- [ ] **Step 5: Commit**

```bash
git add bindings/napi/peer_manager.zig bindings/napi/root.zig build.zig
git commit -m "feat(peer_manager): add NAPI bindings for peer manager"
```

---

### Task 10: Write TypeScript integration tests

**Files:**
- Create: `bindings/test/peer_manager.test.ts`

**Reference:** Spec section 8 tests. Pattern from existing test files in `bindings/test/`.

- [ ] **Step 1: Check existing test patterns**

Read an existing test file to understand the import/setup pattern:

```bash
ls bindings/test/
```

- [ ] **Step 2: Create `bindings/test/peer_manager.test.ts`**

```typescript
import {describe, it, expect} from "vitest";
// Import pattern depends on existing bindings — check how other tests import

describe("peerManager", () => {
  const config = {
    targetPeers: 10,
    maxPeers: 15,
    targetGroupPeers: 6,
    pingIntervalInboundMs: 15000,
    pingIntervalOutboundMs: 20000,
    statusIntervalMs: 300000,
    statusInboundGracePeriodMs: 15000,
    gossipsubNegativeScoreWeight: -0.5,
    gossipsubPositiveScoreWeight: 0.5,
    negativeGossipScoreIgnoreThreshold: -100,
    disablePeerScoring: false,
    initialForkName: "deneb",
    numberOfCustodyGroups: 128,
    custodyRequirement: 4,
    samplesPerSlot: 8,
    slotsPerEpoch: 32,
  };

  it("init and close without error", () => {
    // bindings.peerManager.init(config);
    // bindings.peerManager.close();
  });

  it("onConnectionOpen increases peer count", () => {
    // bindings.peerManager.init(config);
    // bindings.peerManager.onConnectionOpen("peer1", "outbound");
    // expect(bindings.peerManager.getConnectedPeerCount()).toBe(1);
    // bindings.peerManager.close();
  });

  it("heartbeat returns action array", () => {
    // bindings.peerManager.init(config);
    // bindings.peerManager.onConnectionOpen("peer1", "outbound");
    // const actions = bindings.peerManager.heartbeat(100, localStatus);
    // expect(Array.isArray(actions)).toBe(true);
    // bindings.peerManager.close();
  });

  it("getPeerData returns correct data after status update", () => {
    // Connect peer, send status, verify getPeerData returns it
  });

  it("reportPeer reflects in getPeerScore", () => {
    // Connect peer, report with mid_tolerance, verify score < 0
  });

  it("round-trip: connect → status → heartbeat", () => {
    // Full flow: connect outbound, send status, call heartbeat
    // Verify actions are reasonable (no disconnects for healthy peer)
  });
});
```

> **Note**: The exact import path and binding object shape depend on how the existing tests import. Check `bindings/test/*.test.ts` for the pattern. Adapt the test code above to match.

- [ ] **Step 3: Run TS tests**

Run: `pnpm test -- --filter peer_manager 2>&1 | tail -10`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add bindings/test/peer_manager.test.ts
git commit -m "test(peer_manager): add TypeScript integration tests for NAPI bindings"
```

---

## Final Validation

- [ ] **Run all Zig tests**

```bash
zig build test:peer_manager 2>&1 | tail -5
```
Expected: All pass, no leaks.

- [ ] **Run all Zig tests with filter**

```bash
zig build test:peer_manager -Dpeer_manager.filters="PeerStore" 2>&1 | tail -5
zig build test:peer_manager -Dpeer_manager.filters="PeerScorer" 2>&1 | tail -5
zig build test:peer_manager -Dpeer_manager.filters="assertPeerRelevance" 2>&1 | tail -5
zig build test:peer_manager -Dpeer_manager.filters="prioritizePeers" 2>&1 | tail -5
zig build test:peer_manager -Dpeer_manager.filters="PeerManager" 2>&1 | tail -5
```

- [ ] **Build bindings in release mode**

```bash
zig build build-lib:bindings -Doptimize=ReleaseSafe 2>&1 | tail -5
```
Expected: Compiles without errors.

- [ ] **Run TypeScript tests**

```bash
pnpm test 2>&1 | tail -10
```
Expected: All tests pass including peer_manager.

- [ ] **Verify no function exceeds 70 lines (TigerStyle)**

```bash
# Quick check — count lines between fn declarations
grep -c "pub fn\|fn " src/peer_manager/*.zig
```
Review any file with high function count to verify compliance.
