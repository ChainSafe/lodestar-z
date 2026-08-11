const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const constants = @import("constants.zig");
const store_mod = @import("store.zig");
const scorer_mod = @import("scorer.zig");
const relevance_mod = @import("relevance.zig");
const prioritize_mod = @import("prioritize.zig");
const metrics = @import("metrics.zig");

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
    /// Our head slot at the previous heartbeat; null before the first one.
    /// Used for starvation detection.
    last_head_slot: ?u64,
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
            .last_head_slot = null,
            .active_attnets = .empty,
            .active_syncnets = .empty,
            .our_sampling_groups = null,
            .actions = .empty,
            .discovery_attnet_queries = .empty,
            .discovery_syncnet_queries = .empty,
            .discovery_custody_group_queries = .empty,
        };
    }

    pub fn deinit(self: *PeerManager) void {
        self.store.deinit();
        self.scorer.deinit();
        self.active_attnets.deinit(self.allocator);
        self.active_syncnets.deinit(self.allocator);
        if (self.our_sampling_groups) |g| self.allocator.free(g);
        self.actions.deinit(self.allocator);
        self.discovery_attnet_queries.deinit(self.allocator);
        self.discovery_syncnet_queries.deinit(self.allocator);
        self.discovery_custody_group_queries.deinit(self.allocator);
    }

    // ── Tick Functions ──────────────────────────────────────────────

    pub fn heartbeat(
        self: *PeerManager,
        current_slot: u64,
        local_status: Status,
    ) ![]const Action {
        self.resetActionState();
        const timer = metrics.startTimer();
        defer metrics.observeHeartbeatDuration(timer);
        self.scorer.decayScores();
        try self.evictBadPeers();
        const starved = self.detectStarvation(current_slot, local_status);
        metrics.setStarved(starved);
        self.last_head_slot = local_status.head_slot;
        try self.runPrioritization(local_status, starved);
        metrics.setConnectedPeersMapSize(self.store.getConnectedPeerCount());
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

    /// Force an immediate status round for the given peers. Port of TS
    /// reStatusPeers: reset each peer's status timer, then run the ping/status
    /// timer check so a fresh status is requested (used by sync when a target
    /// is reached). Untracked peer ids are ignored.
    pub fn reStatusPeers(self: *PeerManager, peer_ids: []const []const u8) ![]const Action {
        for (peer_ids) |peer_id| {
            self.store.updateLastStatus(peer_id, 0);
        }
        return self.checkPingAndStatus();
    }

    /// Goodbye + disconnect every connected peer with CLIENT_SHUTDOWN. Port of
    /// TS goodbyeAndDisconnectAllPeers, used on graceful shutdown.
    pub fn goodbyeAndDisconnectAllPeers(self: *PeerManager) ![]const Action {
        self.resetActionState();
        var iter = self.store.iterPeers();
        while (iter.next()) |entry| {
            const peer_id = entry.value_ptr.peer_id;
            _ = self.scorer.applyReconnectionCoolDown(peer_id, .client_shutdown);
            try self.actions.append(self.allocator, .{ .send_goodbye = .{
                .peer_id = peer_id,
                .reason = .client_shutdown,
            } });
            try self.actions.append(self.allocator, .{ .disconnect_peer = peer_id });
        }
        return self.actions.items;
    }

    /// Reconcile the peer store against the authoritative set of connected peer
    /// ids (from libp2p), dropping entries left behind by missed disconnect
    /// events. Port of the TS heartbeat prune: only runs when the store has
    /// grown more than 10% beyond the real set. Returns the number pruned so
    /// the caller can record the leaked-connection metric.
    pub fn reconcileConnectedPeers(self: *PeerManager, connected_peer_ids: []const []const u8) !u32 {
        const store_count: f64 = @floatFromInt(self.store.getConnectedPeerCount());
        const actual_count: f64 = @floatFromInt(connected_peer_ids.len);
        if (store_count <= actual_count * 1.1) return 0;
        return self.store.pruneNotIn(connected_peer_ids);
    }

    // ── Event Handlers ──────────────────────────────────────────────

    pub fn onConnectionOpen(
        self: *PeerManager,
        peer_id: []const u8,
        direction: Direction,
    ) ![]const Action {
        self.resetActionState();

        // libp2p may open a second connection to a peer we already track (e.g.
        // an inbound connection followed by our own outbound dial). Overwrite the
        // direction but keep the existing timestamps/status; as on a first
        // connection, only an outbound connection triggers an immediate handshake.
        if (self.store.getPeerData(peer_id)) |peer| {
            peer.connection_count += 1;
            peer.direction = direction;
            if (direction == .outbound) {
                try self.actions.append(self.allocator, .{ .send_ping = peer_id });
                try self.actions.append(self.allocator, .{ .send_status = peer_id });
            }
            return self.actions.items;
        }

        self.store.addPeer(
            peer_id,
            direction,
            self.clock_fn(),
            self.config,
        ) catch |err| switch (err) {
            error.PeerAlreadyExists => {}, // Already guarded by the getPeerData check above.
            error.OutOfMemory => return err, // Propagate fatal OOM error
        };

        if (direction == .outbound) {
            try self.actions.append(self.allocator, .{ .send_ping = peer_id });
            try self.actions.append(self.allocator, .{ .send_status = peer_id });
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

        // Tear down only when the last connection closes. TS ignores the
        // disconnect event while another connection to the peer is still open.
        if (peer.connection_count > 1) {
            peer.connection_count -= 1;
            return self.actions.items;
        }

        if (peer.direction == .inbound) {
            // Extend-only: a longer goodbye-reason cooldown (applied when the
            // send_goodbye action was emitted) must survive the disconnect
            // event that follows it.
            _ = self.scorer.applyReconnectionCoolDownIfLonger(
                peer_id,
                .inbound_disconnect,
            );
        }
        // Mirror TS: remove the relevant-peer tag on disconnect. Only needed if
        // the peer was tagged (untagging is otherwise a no-op).
        if (peer.relevant_status == .relevant) {
            try self.actions.append(self.allocator, .{ .untag_peer_relevant = peer_id });
        }
        self.store.removePeer(peer_id);
        try self.actions.append(self.allocator, .{ .emit_peer_disconnected = peer_id });
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
        if (irrelevant) |reason| {
            metrics.recordRelevanceCheck(metrics.relevanceResultLabel(reason));
        } else {
            metrics.recordRelevanceCheck(.relevant);
        }

        // The peer may be untracked if a status races ahead of connection-open.
        const maybe_peer = self.store.getPeerData(peer_id);

        if (irrelevant != null) {
            // TS goodbyeAndDisconnect is not gated on peerData: disconnect an
            // irrelevant peer even if untracked, and apply the goodbye-reason
            // cooldown (240 min for irrelevant_network) so Discovery won't re-dial.
            if (maybe_peer) |peer| peer.relevant_status = .irrelevant;
            _ = self.scorer.applyReconnectionCoolDown(peer_id, .irrelevant_network);
            try self.actions.append(self.allocator, .{ .send_goodbye = .{
                .peer_id = peer_id,
                .reason = .irrelevant_network,
            } });
            try self.actions.append(self.allocator, .{ .disconnect_peer = peer_id });
            return self.actions.items;
        }

        // Relevant path needs a tracked peer: emitting peerConnected requires the
        // peer's direction, and an untracked peer has no connection to report.
        const peer = maybe_peer orelse return self.actions.items;
        if (peer.relevant_status != .relevant) {
            peer.relevant_status = .relevant;
            try self.actions.append(self.allocator, .{ .tag_peer_relevant = peer_id });
        }
        // TS emits peerConnected on EVERY status from a relevant peer —
        // the sync layer consumes repeated events to refresh peer status.
        try self.actions.append(self.allocator, .{ .emit_peer_connected = .{
            .peer_id = peer_id,
            .direction = peer.direction,
        } });
        // TS runs identify once a relevant status proves the connection is
        // usable, and only until the agent version is known. The host executes
        // identify and reports the result via setAgentVersion.
        if (peer.agent_version == null) {
            try self.actions.append(self.allocator, .{ .identify_peer = peer_id });
        }
        return self.actions.items;
    }

    pub fn onMetadataReceived(
        self: *PeerManager,
        peer_id: []const u8,
        metadata: Metadata,
    ) ![]const Action {
        self.resetActionState();

        // Capture the prior custody group count before the metadata is overwritten.
        const old_custody_group_count: ?u64 = if (self.store.getPeerData(peer_id)) |peer|
            if (peer.metadata) |md| md.custody_group_count else null
        else
            null;

        self.store.updateMetadata(peer_id, metadata);

        // TS re-requests STATUS when metadata is first seen or the custody group
        // count changed, so the sync layer re-derives custody columns from a fresh
        // status. Only meaningful for a tracked peer (updateMetadata no-ops otherwise).
        if (self.store.contains(peer_id) and
            (old_custody_group_count == null or
                old_custody_group_count.? != metadata.custody_group_count))
        {
            try self.actions.append(self.allocator, .{ .send_status = peer_id });
        }
        return self.actions.items;
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
        // The remote-supplied reason must not drive our own reconnection
        // cooldown (TS only disconnects here; the inbound-disconnect cooldown
        // is applied by onConnectionClose when the connection actually drops).
        _ = reason;
        self.resetActionState();
        try self.actions.append(self.allocator, .{ .disconnect_peer = peer_id });
        return self.actions.items;
    }

    pub fn onPing(
        self: *PeerManager,
        peer_id: []const u8,
        seq_number: u64,
    ) ![]const Action {
        self.resetActionState();

        // TS requests metadata whenever the sequence number is unknown or newer,
        // even for an untracked peer (connectedPeers.get(...)?.metadata is
        // undefined → request).
        const need_metadata = if (self.store.getPeerData(peer_id)) |peer|
            if (peer.metadata) |md| seq_number > md.seq_number else true
        else
            true;

        if (need_metadata) {
            try self.actions.append(self.allocator, .{ .request_metadata = peer_id });
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
        try self.active_attnets.appendSlice(self.allocator, attnets);
        self.active_syncnets.clearRetainingCapacity();
        try self.active_syncnets.appendSlice(self.allocator, syncnets);
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

    /// Records the agent version reported by the identify protocol (host-driven,
    /// in response to an `identify_peer` action). Derives the client kind from it.
    pub fn setAgentVersion(self: *PeerManager, peer_id: []const u8, version: []const u8) !void {
        try self.store.setAgentVersion(peer_id, version);
    }

    /// Records the ReqResp encoding preference observed for a peer (host-driven).
    pub fn setEncodingPreference(self: *PeerManager, peer_id: []const u8, encoding: Encoding) void {
        self.store.setEncodingPreference(peer_id, encoding);
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
                    metrics.recordPeerPruned(.banned);
                    try self.actions.append(self.allocator, .{ .send_goodbye = .{
                        .peer_id = peer_id,
                        .reason = .banned,
                    } });
                    try self.actions.append(self.allocator, .{
                        .disconnect_peer = peer_id,
                    });
                },
                .disconnected => {
                    metrics.recordPeerPruned(.score_too_low);
                    try self.actions.append(self.allocator, .{ .send_goodbye = .{
                        .peer_id = peer_id,
                        .reason = .score_too_low,
                    } });
                    try self.actions.append(self.allocator, .{
                        .disconnect_peer = peer_id,
                    });
                },
                .healthy => {},
            }
        }
    }

    /// Detect if we are starved of data while syncing. Port of the TS
    /// heartbeat check: starved when our head has not advanced since the
    /// previous heartbeat AND the head has fallen more than the starvation
    /// threshold behind the wall-clock slot.
    fn detectStarvation(
        self: *const PeerManager,
        current_slot: u64,
        local_status: Status,
    ) bool {
        // No previous heartbeat to compare against.
        const last_head_slot = self.last_head_slot orelse return false;

        const threshold: u64 = self.config.slots_per_epoch * 2;
        return
        // While syncing progress is happening, we aren't starved.
        local_status.head_slot == last_head_slot and
            // If the head falls behind the threshold, we are starved.
            current_slot -| local_status.head_slot > threshold;
    }

    /// Build inputs, run prioritizePeers, convert result to actions.
    fn runPrioritization(
        self: *PeerManager,
        local_status: Status,
        starved: bool,
    ) !void {
        var inputs: std.ArrayList(PrioritizePeersInput) = .empty;
        defer inputs.deinit(self.allocator);
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

        metrics.observePeersEvaluated(@intCast(inputs.items.len));
        const prioritize_timer = metrics.startTimer();
        var result = try prioritizePeers(
            self.allocator,
            inputs.items,
            self.active_attnets.items,
            self.active_syncnets.items,
            self.our_sampling_groups,
            opts,
        );
        metrics.observePrioritizeDuration(prioritize_timer);
        defer result.deinit();

        try self.convertPrioritizeResult(&result);
    }

    /// Populate the input array from store + scorer data.
    ///
    /// Only healthy peers are evaluated by prioritization; banned/disconnected
    /// peers are already handled by `evictBadPeers` this heartbeat. Mirrors the
    /// TS `connectedHealthyPeers` set passed to `prioritizePeers`.
    fn buildPrioritizeInputs(
        self: *PeerManager,
        inputs: *std.ArrayList(PrioritizePeersInput),
    ) !void {
        var iter = self.store.iterPeers();
        while (iter.next()) |entry| {
            const peer = entry.value_ptr;
            if (self.scorer.getScoreState(peer.peer_id) != .healthy) continue;
            try inputs.append(self.allocator, .{
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
            metrics.recordPeerPruned(metrics.pruneReasonFromExcess(disc.reason));
            // TS goodbyeAndDisconnect applies the goodbye-reason cooldown
            // (5 min for too_many_peers) so Discovery won't re-dial.
            _ = self.scorer.applyReconnectionCoolDown(disc.peer_id, .too_many_peers);
            try self.actions.append(self.allocator, .{ .send_goodbye = .{
                .peer_id = disc.peer_id,
                .reason = .too_many_peers,
            } });
            try self.actions.append(self.allocator, .{ .disconnect_peer = disc.peer_id });
        }

        // Subnet/custody discovery must run even at or above targetPeers: duty
        // subnet and custody-group peers are allowed above the peer limit.
        try self.discovery_attnet_queries.appendSlice(self.allocator, result.attnet_queries.items);
        try self.discovery_syncnet_queries.appendSlice(self.allocator, result.syncnet_queries.items);

        var custody_iter = result.custody_group_queries.iterator();
        while (custody_iter.next()) |entry| {
            try self.discovery_custody_group_queries.append(self.allocator, .{
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

        const has_subnet_queries = self.discovery_attnet_queries.items.len > 0 or
            self.discovery_syncnet_queries.items.len > 0 or
            self.discovery_custody_group_queries.items.len > 0;

        if (result.peers_to_connect > 0 or has_subnet_queries) {
            try self.actions.append(self.allocator, .{
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
            try self.actions.append(self.allocator, .{ .send_ping = peer.peer_id });
        }
        // Inbound peers get their first status request after the grace period
        // via the seeded last_status timestamp — never a disconnect (TS
        // pingAndStatusTimeouts only ever requests, it does not prune).
        if (now - peer.last_status_unix_ts_ms > self.config.status_interval_ms) {
            try self.actions.append(self.allocator, .{ .send_status = peer.peer_id });
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

test "onConnectionOpen — second connection updates direction" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    // Inbound first, then our outbound dial: direction is overwritten and the
    // outbound connection triggers an immediate ping + status. No new peer entry.
    _ = try pm.onConnectionOpen("peer-a", .inbound);
    const actions = try pm.onConnectionOpen("peer-a", .outbound);
    try std.testing.expectEqual(@as(u32, 1), pm.getConnectedPeerCount());
    try std.testing.expectEqual(Direction.outbound, pm.store.getPeerData("peer-a").?.direction);
    try std.testing.expectEqual(@as(usize, 2), actions.len);
    try std.testing.expect(actions[0] == .send_ping);
    try std.testing.expect(actions[1] == .send_status);

    // A subsequent inbound connection overwrites direction without a handshake.
    const actions2 = try pm.onConnectionOpen("peer-a", .inbound);
    try std.testing.expectEqual(Direction.inbound, pm.store.getPeerData("peer-a").?.direction);
    try std.testing.expectEqual(@as(usize, 0), actions2.len);
}

test "onConnectionClose — only tears down on the last connection" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    // Two open connections to the same peer.
    _ = try pm.onConnectionOpen("peer-a", .inbound);
    _ = try pm.onConnectionOpen("peer-a", .outbound);
    try std.testing.expectEqual(@as(u32, 1), pm.getConnectedPeerCount());

    // First close: another connection remains → no teardown, peer stays.
    const first = try pm.onConnectionClose("peer-a");
    try std.testing.expectEqual(@as(usize, 0), first.len);
    try std.testing.expectEqual(@as(u32, 1), pm.getConnectedPeerCount());

    // Second close: last connection → teardown + disconnect event.
    const second = try pm.onConnectionClose("peer-a");
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expect(second[0] == .emit_peer_disconnected);
    try std.testing.expectEqual(@as(u32, 0), pm.getConnectedPeerCount());
}

test "onConnectionClose — untags a previously relevant peer" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    const local = makeLocalStatus();
    // Relevant status tags the peer.
    _ = try pm.onStatusReceived("peer-a", local, local, 320);

    const actions = try pm.onConnectionClose("peer-a");
    var has_untag = false;
    var has_disconnect = false;
    for (actions) |a| {
        if (a == .untag_peer_relevant) has_untag = true;
        if (a == .emit_peer_disconnected) has_disconnect = true;
    }
    try std.testing.expect(has_untag);
    try std.testing.expect(has_disconnect);
}

test "onConnectionClose — no untag for a never-tagged peer" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    const actions = try pm.onConnectionClose("peer-a");
    for (actions) |a| try std.testing.expect(a != .untag_peer_relevant);
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
    // First relevant status: tag, peer-connected, and identify (agent unknown).
    const actions = try pm.onStatusReceived("peer-a", remote, local, 320);
    try std.testing.expectEqual(@as(usize, 3), actions.len);
    try std.testing.expect(actions[0] == .tag_peer_relevant);
    try std.testing.expect(actions[1] == .emit_peer_connected);
    try std.testing.expect(actions[2] == .identify_peer);

    // Once the agent version is known, identify is no longer requested; the
    // sync layer still gets a peer-connected on every status, but tag runs once.
    try pm.setAgentVersion("peer-a", "Lighthouse/v5.0.0");
    const actions2 = try pm.onStatusReceived("peer-a", remote, local, 320);
    try std.testing.expectEqual(@as(usize, 1), actions2.len);
    try std.testing.expect(actions2[0] == .emit_peer_connected);
}

test "setAgentVersion — populates agent version and derived client kind" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    try std.testing.expect(pm.getAgentVersion("peer-a") == null);

    try pm.setAgentVersion("peer-a", "Lighthouse/v5.0.0");
    try std.testing.expectEqualStrings("Lighthouse/v5.0.0", pm.getAgentVersion("peer-a").?);
    try std.testing.expectEqual(types.ClientKind.lighthouse, pm.getPeerKind("peer-a").?);

    pm.setEncodingPreference("peer-a", .ssz_snappy);
    try std.testing.expectEqual(types.Encoding.ssz_snappy, pm.getEncodingPreference("peer-a").?);
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

test "onStatusReceived — irrelevant cooldown survives the disconnect event" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .inbound);
    const local = makeLocalStatus();
    const remote = Status{
        .fork_digest = .{ 0x11, 0x22, 0x33, 0x44 },
        .finalized_root = local.finalized_root,
        .finalized_epoch = local.finalized_epoch,
        .head_root = [_]u8{3} ** 32,
        .head_slot = local.head_slot,
        .earliest_available_slot = null,
    };
    _ = try pm.onStatusReceived("peer-a", remote, local, 320);

    // The 240-minute irrelevant_network cooldown was applied on emission.
    try std.testing.expect(pm.scorer.isCoolingDown("peer-a"));
    const until_before = pm.scorer.scores.get("peer-a").?.last_update_ms;
    try std.testing.expectEqual(@as(i64, 1000 + 240 * 60 * 1000), until_before);

    // The inbound-disconnect cooldown (5 min) that follows the caller's
    // disconnect must not shorten it.
    _ = try pm.onConnectionClose("peer-a");
    const until_after = pm.scorer.scores.get("peer-a").?.last_update_ms;
    try std.testing.expectEqual(until_before, until_after);
}

test "detectStarvation — stalled head behind clock" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    const local = makeLocalStatus(); // head_slot = 320
    const threshold = pm.config.slots_per_epoch * 2; // 64

    // First heartbeat: no baseline yet.
    try std.testing.expect(!pm.detectStarvation(10_000, local));
    pm.last_head_slot = local.head_slot;

    // Head stalled and further than the threshold behind the clock → starved.
    try std.testing.expect(pm.detectStarvation(local.head_slot + threshold + 1, local));
    // Head stalled but within the threshold → not starved.
    try std.testing.expect(!pm.detectStarvation(local.head_slot + threshold, local));
    // Head advanced since the last heartbeat → not starved.
    pm.last_head_slot = local.head_slot - 1;
    try std.testing.expect(!pm.detectStarvation(local.head_slot + threshold + 1, local));
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
    _ = try pm.onMetadataReceived("peer-a", .{
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

test "onPing — untracked peer still requests metadata" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    // No connection was opened for this peer.
    const actions = try pm.onPing("peer-unknown", 1);
    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expect(actions[0] == .request_metadata);
}

fn metadataWithCustody(seq: u64, custody_group_count: u64) Metadata {
    return .{
        .seq_number = seq,
        .attnets = [_]u8{0} ** 8,
        .syncnets = [_]u8{0},
        .custody_group_count = custody_group_count,
        .custody_groups = null,
        .sampling_groups = null,
    };
}

test "onMetadataReceived — re-requests status on first metadata and custody change" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);

    // First metadata → status re-request.
    const a1 = try pm.onMetadataReceived("peer-a", metadataWithCustody(1, 4));
    try std.testing.expectEqual(@as(usize, 1), a1.len);
    try std.testing.expect(a1[0] == .send_status);

    // Same custody group count → no re-request.
    const a2 = try pm.onMetadataReceived("peer-a", metadataWithCustody(2, 4));
    try std.testing.expectEqual(@as(usize, 0), a2.len);

    // Changed custody group count → status re-request.
    const a3 = try pm.onMetadataReceived("peer-a", metadataWithCustody(3, 8));
    try std.testing.expectEqual(@as(usize, 1), a3.len);
    try std.testing.expect(a3[0] == .send_status);
}

test "onMetadataReceived — untracked peer emits nothing" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    const actions = try pm.onMetadataReceived("peer-unknown", metadataWithCustody(1, 4));
    try std.testing.expectEqual(@as(usize, 0), actions.len);
}

test "onStatusReceived — untracked irrelevant peer is still disconnected" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    // No connection opened; a status races ahead. Different fork digest → irrelevant.
    const local = makeLocalStatus();
    const remote = Status{
        .fork_digest = .{ 0x11, 0x22, 0x33, 0x44 },
        .finalized_root = local.finalized_root,
        .finalized_epoch = local.finalized_epoch,
        .head_root = [_]u8{3} ** 32,
        .head_slot = local.head_slot,
        .earliest_available_slot = null,
    };
    const actions = try pm.onStatusReceived("peer-unknown", remote, local, 320);
    try std.testing.expectEqual(@as(usize, 2), actions.len);
    try std.testing.expect(actions[0] == .send_goodbye);
    try std.testing.expect(actions[1] == .disconnect_peer);
    try std.testing.expect(pm.scorer.isCoolingDown("peer-unknown"));
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

test "reStatusPeers — forces a status request for the named peers" {
    // Clock must exceed the status interval so a reset last_status (0) crosses it.
    test_clock_value = 1_000_000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    const local = makeLocalStatus();
    // Satisfies the status timer (last_status = now).
    _ = try pm.onStatusReceived("peer-a", local, local, 320);

    // With the status timer satisfied, a plain timer check emits no status.
    const before = try pm.checkPingAndStatus();
    for (before) |a| try std.testing.expect(a != .send_status);

    // reStatusPeers resets the timer and re-requests status.
    const ids = [_][]const u8{"peer-a"};
    const actions = try pm.reStatusPeers(&ids);
    var has_status = false;
    for (actions) |a| {
        if (a == .send_status) has_status = true;
    }
    try std.testing.expect(has_status);
}

test "reconcileConnectedPeers — prunes leaked entries beyond the 10% threshold" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    _ = try pm.onConnectionOpen("peer-b", .outbound);
    _ = try pm.onConnectionOpen("peer-c", .outbound);

    // Authoritative set still lists all three (within threshold) → no prune.
    const all = [_][]const u8{ "peer-a", "peer-b", "peer-c" };
    try std.testing.expectEqual(@as(u32, 0), try pm.reconcileConnectedPeers(&all));
    try std.testing.expectEqual(@as(u32, 3), pm.getConnectedPeerCount());

    // Only one peer really connected: store (3) > 1 * 1.1 → prune the two leaks.
    const one = [_][]const u8{"peer-b"};
    try std.testing.expectEqual(@as(u32, 2), try pm.reconcileConnectedPeers(&one));
    try std.testing.expectEqual(@as(u32, 1), pm.getConnectedPeerCount());
    try std.testing.expect(pm.store.contains("peer-b"));
    try std.testing.expect(!pm.store.contains("peer-a"));
}

test "goodbyeAndDisconnectAllPeers — goodbye + disconnect for every peer" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .outbound);
    _ = try pm.onConnectionOpen("peer-b", .inbound);

    const actions = try pm.goodbyeAndDisconnectAllPeers();
    // Two actions (goodbye + disconnect) per peer.
    try std.testing.expectEqual(@as(usize, 4), actions.len);
    var goodbyes: usize = 0;
    var disconnects: usize = 0;
    for (actions) |a| switch (a) {
        .send_goodbye => |g| {
            goodbyes += 1;
            try std.testing.expectEqual(GoodbyeReasonCode.client_shutdown, g.reason);
        },
        .disconnect_peer => disconnects += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 2), goodbyes);
    try std.testing.expectEqual(@as(usize, 2), disconnects);
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

test "checkPingAndStatus — inbound peer gets status request after grace period" {
    test_clock_value = 1000;
    var pm = try PeerManager.init(std.testing.allocator, testConfig(), &testClock);
    defer pm.deinit();

    _ = try pm.onConnectionOpen("peer-a", .inbound);

    // Within the grace period: no status request yet.
    test_clock_value = 1000 + pm.config.status_inbound_grace_period_ms - 1;
    var actions = try pm.checkPingAndStatus();
    for (actions) |a| {
        try std.testing.expect(a != .send_status);
        try std.testing.expect(a != .disconnect_peer);
    }

    // Past the grace period: the seeded last_status timestamp fires a status
    // request — never a disconnect (TS pingAndStatusTimeouts only requests).
    test_clock_value = 1000 + pm.config.status_inbound_grace_period_ms + 1;
    actions = try pm.checkPingAndStatus();

    var has_disconnect = false;
    var has_status = false;
    for (actions) |a| {
        if (a == .disconnect_peer) has_disconnect = true;
        if (a == .send_status) has_status = true;
    }

    try std.testing.expect(!has_disconnect);
    try std.testing.expect(has_status);
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
