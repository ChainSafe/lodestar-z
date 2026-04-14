const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const constants = @import("constants.zig");
const store_mod = @import("store.zig");
const scorer_mod = @import("scorer.zig");
const relevance_mod = @import("relevance.zig");
const prioritize_mod = @import("prioritize.zig");

const PeerStore = store_mod.PeerStore;
const PeerScorer = scorer_mod.PeerScorer;
const assertPeerRelevance = relevance_mod.assertPeerRelevance;
const prioritizePeers = prioritize_mod.prioritizePeers;

const Action = types.Action;
const Config = types.Config;
const Direction = types.Direction;
const ForkName = types.ForkName;
const Status = types.Status;
const Metadata = types.Metadata;
const PeerData = types.PeerData;
const PeerAction = types.PeerAction;
const Encoding = types.Encoding;
const ClientKind = types.ClientKind;
const GoodbyeReasonCode = types.GoodbyeReasonCode;
const GossipScoreUpdate = types.GossipScoreUpdate;
const RequestedSubnet = types.RequestedSubnet;
const CustodyGroupQuery = types.CustodyGroupQuery;
const PrioritizePeersInput = prioritize_mod.PrioritizePeersInput;
const PrioritizePeersOpts = prioritize_mod.PrioritizePeersOpts;
const ScoreState = types.ScoreState;

pub const PeerManager = struct {
    allocator: Allocator,
    store: PeerStore,
    scorer: PeerScorer,
    config: Config,
    clock_fn: *const fn () i64,

    // Mutable state
    current_fork_name: ForkName,
    last_heartbeat_slot: u64,
    active_attnets: std.ArrayList(RequestedSubnet),
    active_syncnets: std.ArrayList(RequestedSubnet),
    our_sampling_groups: ?[]u32,

    // Reusable action buffer
    actions: std.ArrayList(Action),
    discovery_attnet_queries: std.ArrayList(types.SubnetQuery),
    discovery_syncnet_queries: std.ArrayList(types.SubnetQuery),
    discovery_custody_group_queries: std.ArrayList(CustodyGroupQuery),

    pub fn init(
        allocator: Allocator,
        config: Config,
        clock_fn: *const fn () i64,
    ) !PeerManager {
        return .{
            .allocator = allocator,
            .store = PeerStore.init(allocator),
            .scorer = PeerScorer.init(allocator, config, clock_fn),
            .config = config,
            .clock_fn = clock_fn,
            .current_fork_name = config.initial_fork_name,
            .last_heartbeat_slot = 0,
            .active_attnets = std.ArrayList(RequestedSubnet).init(allocator),
            .active_syncnets = std.ArrayList(RequestedSubnet).init(allocator),
            .our_sampling_groups = null,
            .actions = std.ArrayList(Action).init(allocator),
            .discovery_attnet_queries = std.ArrayList(types.SubnetQuery).init(allocator),
            .discovery_syncnet_queries = std.ArrayList(types.SubnetQuery).init(allocator),
            .discovery_custody_group_queries = std.ArrayList(CustodyGroupQuery).init(allocator),
        };
    }

    pub fn deinit(self: *PeerManager) void {
        self.store.deinit();
        self.scorer.deinit();
        self.active_attnets.deinit();
        self.active_syncnets.deinit();
        if (self.our_sampling_groups) |g| self.allocator.free(g);
        self.actions.deinit();
        self.discovery_attnet_queries.deinit();
        self.discovery_syncnet_queries.deinit();
        self.discovery_custody_group_queries.deinit();
    }

    // ── Tick Functions ──────────────────────────────────────────────

    pub fn heartbeat(
        self: *PeerManager,
        current_slot: u64,
        local_status: Status,
    ) ![]const Action {
        self.resetActionState();
        self.scorer.decayScores();
        try self.evictBadPeers();
        const starved = self.detectStarvation(current_slot);
        try self.runPrioritization(local_status, starved);
        self.last_heartbeat_slot = current_slot;
        return self.actions.items;
    }

    pub fn checkPingAndStatus(self: *PeerManager) ![]const Action {
        self.resetActionState();
        const now = self.clock_fn();
        var iter = self.store.iterPeers();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            try self.checkPeerTimers(peer, now);
        }
        return self.actions.items;
    }

    // ── Event Handlers ──────────────────────────────────────────────

    pub fn onConnectionOpen(
        self: *PeerManager,
        peer_id: []const u8,
        direction: Direction,
    ) ![]const Action {
        self.resetActionState();
        if (self.store.contains(peer_id)) return self.actions.items;

        self.store.addPeer(
            peer_id,
            direction,
            self.clock_fn(),
            self.config,
        ) catch |err| switch (err) {
            error.PeerAlreadyExists => {}, // Already guarded by contains check before, so this should not be reached
            error.OutOfMemory => return err, // Propagate fatal OOM error
        };

        if (direction == .outbound) {
            try self.actions.append(.{ .send_ping = peer_id });
            try self.actions.append(.{ .send_status = peer_id });
        }
        return self.actions.items;
    }

    pub fn onConnectionClose(
        self: *PeerManager,
        peer_id: []const u8,
    ) ![]const Action {
        self.resetActionState();
        const peer = self.store.getPeerData(peer_id) orelse
            return self.actions.items;

        if (peer.direction == .inbound) {
            _ = self.scorer.applyReconnectionCoolDown(
                peer_id,
                .inbound_disconnect,
            );
        }
        self.store.removePeer(peer_id);
        try self.actions.append(.{ .emit_peer_disconnected = peer_id });
        return self.actions.items;
    }

    pub fn onStatusReceived(
        self: *PeerManager,
        peer_id: []const u8,
        remote_status: Status,
        local_status: Status,
        current_slot: u64,
    ) ![]const Action {
        self.resetActionState();
        self.store.updateStatus(peer_id, remote_status);
        self.store.updateLastStatus(peer_id, self.clock_fn());

        const irrelevant = assertPeerRelevance(
            self.current_fork_name,
            remote_status,
            local_status,
            current_slot,
        );

        const peer = self.store.getPeerData(peer_id) orelse
            return self.actions.items;

        if (irrelevant != null) {
            peer.relevant_status = .irrelevant;
            try self.actions.append(.{ .send_goodbye = .{
                .peer_id = peer_id,
                .reason = .irrelevant_network,
            } });
            try self.actions.append(.{ .disconnect_peer = peer_id });
        } else if (peer.relevant_status != .relevant) {
            peer.relevant_status = .relevant;
            try self.actions.append(.{ .tag_peer_relevant = peer_id });
            try self.actions.append(.{ .emit_peer_connected = .{
                .peer_id = peer_id,
                .direction = peer.direction,
            } });
        }
        return self.actions.items;
    }

    pub fn onMetadataReceived(
        self: *PeerManager,
        peer_id: []const u8,
        metadata: Metadata,
    ) void {
        self.store.updateMetadata(peer_id, metadata);
    }

    pub fn onMessageReceived(
        self: *PeerManager,
        peer_id: []const u8,
    ) void {
        self.store.updateLastReceivedMsg(peer_id, self.clock_fn());
    }

    pub fn onGoodbye(
        self: *PeerManager,
        peer_id: []const u8,
        reason: GoodbyeReasonCode,
    ) ![]const Action {
        self.resetActionState();
        _ = self.scorer.applyReconnectionCoolDown(peer_id, reason);
        try self.actions.append(.{ .disconnect_peer = peer_id });
        return self.actions.items;
    }

    pub fn onPing(
        self: *PeerManager,
        peer_id: []const u8,
        seq_number: u64,
    ) ![]const Action {
        self.resetActionState();
        const peer = self.store.getPeerData(peer_id) orelse
            return self.actions.items;

        const need_metadata = if (peer.metadata) |md|
            seq_number > md.seq_number
        else
            true;

        if (need_metadata) {
            try self.actions.append(.{ .request_metadata = peer_id });
        }
        return self.actions.items;
    }

    // ── Score Mutations ─────────────────────────────────────────────

    pub fn reportPeer(
        self: *PeerManager,
        peer_id: []const u8,
        action: PeerAction,
    ) void {
        self.scorer.reportPeer(peer_id, action);
    }

    pub fn updateGossipScores(
        self: *PeerManager,
        scores: []const GossipScoreUpdate,
    ) void {
        self.scorer.updateGossipScores(scores);
    }

    // ── Configuration Updates ───────────────────────────────────────

    pub fn setSubnetRequirements(
        self: *PeerManager,
        attnets: []const RequestedSubnet,
        syncnets: []const RequestedSubnet,
    ) !void {
        self.active_attnets.clearRetainingCapacity();
        try self.active_attnets.appendSlice(attnets);
        self.active_syncnets.clearRetainingCapacity();
        try self.active_syncnets.appendSlice(syncnets);
    }

    pub fn setForkName(self: *PeerManager, fork_name: ForkName) void {
        self.current_fork_name = fork_name;
    }

    pub fn setSamplingGroups(self: *PeerManager, groups: []const u32) !void {
        if (self.our_sampling_groups) |old| self.allocator.free(old);
        self.our_sampling_groups = try self.allocator.dupe(u32, groups);
    }

    // ── Queries ─────────────────────────────────────────────────────

    pub fn getPeerData(
        self: *const PeerManager,
        peer_id: []const u8,
    ) ?*const PeerData {
        return self.store.getPeerData(peer_id);
    }

    pub fn getConnectedPeerCount(self: *const PeerManager) u32 {
        return self.store.getConnectedPeerCount();
    }

    pub fn getConnectedPeers(
        self: *const PeerManager,
        allocator: Allocator,
    ) ![]const []const u8 {
        return self.store.getConnectedPeers(allocator);
    }

    pub fn getEncodingPreference(
        self: *const PeerManager,
        peer_id: []const u8,
    ) ?Encoding {
        return self.store.getEncodingPreference(peer_id);
    }

    pub fn getPeerKind(
        self: *const PeerManager,
        peer_id: []const u8,
    ) ?ClientKind {
        return self.store.getPeerKind(peer_id);
    }

    pub fn getAgentVersion(
        self: *const PeerManager,
        peer_id: []const u8,
    ) ?[]const u8 {
        return self.store.getAgentVersion(peer_id);
    }

    pub fn getPeerScore(
        self: *const PeerManager,
        peer_id: []const u8,
    ) f64 {
        return self.scorer.getScore(peer_id);
    }

    // ── Internal Helpers ────────────────────────────────────────────

    /// Evict peers whose score state is banned or disconnected.
    fn evictBadPeers(self: *PeerManager) !void {
        var iter = self.store.iterPeers();
        while (iter.next()) |entry| {
            const peer_id = entry.key_ptr.*;
            const state = self.scorer.getScoreState(peer_id);
            switch (state) {
                .banned => {
                    try self.actions.append(.{ .send_goodbye = .{
                        .peer_id = peer_id,
                        .reason = .banned,
                    } });
                    try self.actions.append(.{
                        .disconnect_peer = peer_id,
                    });
                },
                .disconnected => {
                    try self.actions.append(.{ .send_goodbye = .{
                        .peer_id = peer_id,
                        .reason = .score_too_low,
                    } });
                    try self.actions.append(.{
                        .disconnect_peer = peer_id,
                    });
                },
                .healthy => {},
            }
        }
    }

    /// Detect if the heartbeat has stalled (same slot for >2 epochs).
    fn detectStarvation(self: *const PeerManager, current_slot: u64) bool {
        if (current_slot == 0) return false;
        const EPOCHS_IN_SLOTS = 32; // Assuming 32 slots per epoch as per Ethereum spec
        const STARVATION_EPOCHS = 2;

        if (self.last_heartbeat_slot == 0) return false; // Initial state, no starvation.

        // Starvation logic: if current_slot is not advancing past 2 epochs from the last heartbeat.
        return (current_slot - self.last_heartbeat_slot) <= (STARVATION_EPOCHS * EPOCHS_IN_SLOTS);
    }

    /// Build inputs, run prioritizePeers, convert result to actions.
    fn runPrioritization(
        self: *PeerManager,
        local_status: Status,
        starved: bool,
    ) !void {
        var inputs = std.ArrayList(PrioritizePeersInput).init(
            self.allocator,
        );
        defer inputs.deinit();
        try self.buildPrioritizeInputs(&inputs);

        const opts = PrioritizePeersOpts{
            .target_peers = self.config.target_peers,
            .max_peers = self.config.max_peers,
            .target_group_peers = self.config.target_group_peers,
            .local_status = local_status,
            .starved = starved,
            .starvation_prune_ratio = constants.STARVATION_PRUNE_RATIO,
            .starvation_threshold_slots = self.config.slots_per_epoch * 2,
            .number_of_custody_groups = self.config.number_of_custody_groups,
        };

        var result = try prioritizePeers(
            self.allocator,
            inputs.items,
            self.active_attnets.items,
            self.active_syncnets.items,
            self.our_sampling_groups,
            opts,
        );
        defer result.deinit();

        try self.convertPrioritizeResult(&result);
    }

    /// Populate the input array from store + scorer data.
    fn buildPrioritizeInputs(
        self: *PeerManager,
        inputs: *std.ArrayList(PrioritizePeersInput),
    ) !void {
        var iter = self.store.iterPeers();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            try inputs.append(.{
                .peer_id = peer.peer_id,
                .direction = peer.direction,
                .status = peer.status,
                .attnets = if (peer.metadata) |md| md.attnets else null,
                .syncnets = if (peer.metadata) |md| md.syncnets else null,
                .sampling_groups = if (peer.metadata) |md|
                    md.sampling_groups
                else
                    null,
                .score = self.scorer.getScore(peer.peer_id),
            });
        }
    }

    /// Convert prioritize result into actions.
    fn convertPrioritizeResult(
        self: *PeerManager,
        result: *prioritize_mod.PrioritizePeersResult,
    ) !void {
        for (result.peers_to_disconnect.items) |disc| {
            try self.actions.append(.{ .send_goodbye = .{
                .peer_id = disc.peer_id,
                .reason = .too_many_peers,
            } });
            try self.actions.append(.{ .disconnect_peer = disc.peer_id });
        }

        if (result.peers_to_connect > 0) {
            try self.discovery_attnet_queries.appendSlice(result.attnet_queries.items);
            try self.discovery_syncnet_queries.appendSlice(result.syncnet_queries.items);

            var custody_iter = result.custody_group_queries.iterator();
            while (custody_iter.next()) |entry| {
                try self.discovery_custody_group_queries.append(.{
                    .group = entry.key_ptr.*,
                    .max_peers_to_discover = entry.value_ptr.*,
                });
            }
            std.mem.sort(
                CustodyGroupQuery,
                self.discovery_custody_group_queries.items,
                {},
                struct {
                    fn lessThan(_: void, a: CustodyGroupQuery, b: CustodyGroupQuery) bool {
                        return a.group < b.group;
                    }
                }.lessThan,
            );

            try self.actions.append(.{
                .request_discovery = .{
                    .peers_to_connect = result.peers_to_connect,
                    .attnet_queries = self.discovery_attnet_queries.items,
                    .syncnet_queries = self.discovery_syncnet_queries.items,
                    .custody_group_queries = self.discovery_custody_group_queries.items,
                },
            });
        }
    }

    fn resetActionState(self: *PeerManager) void {
        self.actions.clearRetainingCapacity();
        self.discovery_attnet_queries.clearRetainingCapacity();
        self.discovery_syncnet_queries.clearRetainingCapacity();
        self.discovery_custody_group_queries.clearRetainingCapacity();
    }

    /// Check ping and status timers for a single peer.
    fn checkPeerTimers(
        self: *PeerManager,
        peer: *const PeerData,
        now: i64,
    ) !void {
        const ping_interval: i64 = switch (peer.direction) {
            .inbound => self.config.ping_interval_inbound_ms,
            .outbound => self.config.ping_interval_outbound_ms,
        };
        if (now - peer.last_received_msg_unix_ts_ms > ping_interval) {
            try self.actions.append(.{ .send_ping = peer.peer_id });
        }
        if (peer.direction == .inbound and
            peer.status == null and
            now - peer.connected_unix_ts_ms > self.config.status_inbound_grace_period_ms)
        {
            try self.actions.append(.{ .disconnect_peer = peer.peer_id });
            return;
        }
        if (now - peer.last_status_unix_ts_ms > self.config.status_interval_ms) {
            try self.actions.append(.{ .send_status = peer.peer_id });
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

var test_clock_value: i64 = 0;

fn testClock() i64 {
    return test_clock_value;
}

fn testConfig() Config {
    return .{
        .target_peers = 50,
        .max_peers = 60,
        .gossipsub_negative_score_weight = 1.0,
        .gossipsub_positive_score_weight = 1.0,
        .negative_gossip_score_ignore_threshold = -100.0,
        .initial_fork_name = .deneb,
    };
}

fn makeLocalStatus() Status {
    return .{
        .fork_digest = .{ 0xAA, 0xBB, 0xCC, 0xDD },
        .finalized_root = [_]u8{1} ** 32,
        .finalized_epoch = 10,
        .head_root = [_]u8{2} ** 32,
        .head_slot = 320,
        .earliest_available_slot = null,
    };
}

test "onConnectionOpen — outbound emits ping and status" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    const actions = try pm.onConnectionOpen("peer-a", .outbound);
    try std.testing.expectEqual(@as(usize, 2), actions.len);
    try std.testing.expect(actions[0] == .send_ping);
    try std.testing.expect(actions[1] == .send_status);
    try std.testing.expectEqual(@as(u32, 1), pm.getConnectedPeerCount());
}

test "onConnectionOpen — duplicate is no-op" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    const actions = try pm.onConnectionOpen("peer-a", .inbound);
    try std.testing.expectEqual(@as(usize, 0), actions.len);
    try std.testing.expectEqual(@as(u32, 1), pm.getConnectedPeerCount());
}

test "onConnectionClose — inbound applies cooldown" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .inbound);
    _ = try pm.onConnectionClose("peer-a");
    // Cooldown was applied — scorer should show cooling down.
    try std.testing.expect(pm.scorer.isCoolingDown("peer-a"));
}

test "onConnectionClose — emits disconnect event" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    const actions = try pm.onConnectionClose("peer-a");
    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expect(actions[0] == .emit_peer_disconnected);
    try std.testing.expectEqual(@as(u32, 0), pm.getConnectedPeerCount());
}

test "onStatusReceived — relevant peer emits tag and connected" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    const local = makeLocalStatus();
    // Remote status matches local — should be relevant.
    const remote = Status{
        .fork_digest = local.fork_digest,
        .finalized_root = local.finalized_root,
        .finalized_epoch = local.finalized_epoch,
        .head_root = [_]u8{3} ** 32,
        .head_slot = local.head_slot,
        .earliest_available_slot = null,
    };
    const actions = try pm.onStatusReceived("peer-a", remote, local, 320);
    try std.testing.expectEqual(@as(usize, 2), actions.len);
    try std.testing.expect(actions[0] == .tag_peer_relevant);
    try std.testing.expect(actions[1] == .emit_peer_connected);
}

test "onStatusReceived — irrelevant peer emits goodbye" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    const local = makeLocalStatus();
    // Different fork digest — irrelevant.
    const remote = Status{
        .fork_digest = .{ 0x11, 0x22, 0x33, 0x44 },
        .finalized_root = local.finalized_root,
        .finalized_epoch = local.finalized_epoch,
        .head_root = [_]u8{3} ** 32,
        .head_slot = local.head_slot,
        .earliest_available_slot = null,
    };
    const actions = try pm.onStatusReceived("peer-a", remote, local, 320);
    try std.testing.expectEqual(@as(usize, 2), actions.len);
    try std.testing.expect(actions[0] == .send_goodbye);
    try std.testing.expect(actions[1] == .disconnect_peer);
}

test "onPing — higher seq triggers metadata request" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    // No metadata yet — any seq should trigger request.
    const actions = try pm.onPing("peer-a", 1);
    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expect(actions[0] == .request_metadata);

    // Set metadata with seq_number=5
    pm.onMetadataReceived("peer-a", .{
        .seq_number = 5,
        .attnets = [_]u8{0} ** 8,
        .syncnets = [_]u8{0},
        .custody_group_count = 0,
        .custody_groups = null,
        .sampling_groups = null,
    });

    // Ping with lower seq — no request.
    const actions2 = try pm.onPing("peer-a", 3);
    try std.testing.expectEqual(@as(usize, 0), actions2.len);

    // Ping with higher seq — request.
    const actions3 = try pm.onPing("peer-a", 6);
    try std.testing.expectEqual(@as(usize, 1), actions3.len);
    try std.testing.expect(actions3[0] == .request_metadata);
}

test "onGoodbye — emits disconnect only" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    const actions = try pm.onGoodbye("peer-a", .client_shutdown);
    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expect(actions[0] == .disconnect_peer);
}

test "checkPingAndStatus — inbound past interval emits ping" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .inbound);
    // Advance clock past inbound ping interval (15s).
    test_clock_value = 1000 + pm.config.ping_interval_inbound_ms + 1;
    const actions = try pm.checkPingAndStatus();

    var has_ping = false;
    for (actions) |a| {
        if (a == .send_ping) has_ping = true;
    }
    try std.testing.expect(has_ping);
}

test "checkPingAndStatus — outbound past interval emits ping" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    // Outbound initial last_received_msg = 0, so any time > ping interval triggers.
    test_clock_value = pm.config.ping_interval_outbound_ms + 1;
    const actions = try pm.checkPingAndStatus();

    var has_ping = false;
    for (actions) |a| {
        if (a == .send_ping) has_ping = true;
    }
    try std.testing.expect(has_ping);
}

test "checkPingAndStatus — past status interval emits status" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    // Outbound initial last_status = 0, so any time > status_interval triggers.
    test_clock_value = pm.config.status_interval_ms + 1;
    const actions = try pm.checkPingAndStatus();

    var has_status = false;
    for (actions) |a| {
        if (a == .send_status) has_status = true;
    }
    try std.testing.expect(has_status);
}

test "checkPingAndStatus — inbound peer without status disconnects after grace period" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .inbound);
    test_clock_value = 1000 + pm.config.status_inbound_grace_period_ms + 1;
    const actions = try pm.checkPingAndStatus();

    var has_disconnect = false;
    var has_status = false;
    for (actions) |a| {
        if (a == .disconnect_peer) has_disconnect = true;
        if (a == .send_status) has_status = true;
    }

    try std.testing.expect(has_disconnect);
    try std.testing.expect(!has_status);
}

test "getConnectedPeers returns all peer ids" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    _ = try pm.onConnectionOpen("peer-b", .inbound);

    const peers = try pm.getConnectedPeers(std.testing.allocator);
    defer std.testing.allocator.free(peers);

    try std.testing.expectEqual(@as(usize, 2), peers.len);
    var found_peer_a = false;
    var found_peer_b = false;
    for (peers) |peer_id| {
        if (std.mem.eql(u8, peer_id, "peer-a")) found_peer_a = true;
        if (std.mem.eql(u8, peer_id, "peer-b")) found_peer_b = true;
    }

    try std.testing.expect(found_peer_a);
    try std.testing.expect(found_peer_b);
}

test "heartbeat — banned peer gets goodbye" {
    test_clock_value = 0;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    // Drive score to banned.
    pm.reportPeer("peer-a", .fatal);

    const actions = try pm.heartbeat(100, makeLocalStatus());

    var has_goodbye = false;
    var has_disconnect = false;
    for (actions) |a| {
        switch (a) {
            .send_goodbye => |g| {
                if (g.reason == .banned) has_goodbye = true;
            },
            .disconnect_peer => has_disconnect = true,
            else => {},
        }
    }
    try std.testing.expect(has_goodbye);
    try std.testing.expect(has_disconnect);
}

test "heartbeat — below target triggers discovery" {
    test_clock_value = 0;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    // Add fewer peers than target (target=50, add 1).
    _ = try pm.onConnectionOpen("peer-a", .outbound);

    const actions = try pm.heartbeat(100, makeLocalStatus());

    var has_discovery = false;
    for (actions) |a| {
        if (a == .request_discovery) has_discovery = true;
    }
    try std.testing.expect(has_discovery);
}

test "heartbeat — discovery carries custody group queries" {
    test_clock_value = 0;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    try pm.setSamplingGroups(&.{ 0, 1, 2 });

    const actions = try pm.heartbeat(100, makeLocalStatus());

    var found_discovery = false;
    for (actions) |action| {
        switch (action) {
            .request_discovery => |discovery| {
                found_discovery = true;
                try std.testing.expect(discovery.custody_group_queries.len > 0);
            },
            else => {},
        }
    }

    try std.testing.expect(found_discovery);
}
