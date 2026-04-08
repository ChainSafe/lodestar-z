//! Multi-node deterministic cluster simulation.
//!
//! Ties together N SimNodeHarness instances (each wrapping a BeaconNode)
//! connected via SimNetwork with cluster-wide invariant checking.
//! Proves that identical blocks produce identical state roots across nodes,
//! and that network faults cause graceful degradation — never safety violations.
//!
//! V1 simplifications:
//!   - Single chain per node (no fork tracking).
//!   - Out-of-order / wrong-parent blocks are dropped.
//!   - Attestations are tracked but not processed through STFN.
//!   - Key value: N nodes × same blocks × same order = identical state roots.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const config_mod = @import("config");
const fork_types = @import("fork_types");
const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;

const node_pkg = @import("node");
const BeaconNode = node_pkg.BeaconNode;
const reqresp_callbacks = node_pkg.reqresp_callbacks_mod;
const identity_mod = node_pkg.identity;
const sim_node_harness = @import("sim_node_harness.zig");
const SimNodeHarness = sim_node_harness.SimNodeHarness;
const SyncPeer = sim_node_harness.SyncPeer;
const sim_network = @import("sim_network.zig");
const SimNetwork = sim_network.SimNetwork;
const ClusterInvariantChecker = @import("cluster_invariant_checker.zig").ClusterInvariantChecker;

const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

pub const ClusterConfig = struct {
    num_nodes: u8 = 4,
    seed: u64 = 42,
    /// Network fault configuration.
    network: sim_network.Config = .{},
    /// Probability that the proposer is offline (skip slot) [0.0 - 1.0].
    proposer_offline_rate: f64 = 0.0,
    /// Number of validators in the test state.
    validator_count: usize = 64,
    /// Fraction of validators producing attestations [0.0 - 1.0].
    participation_rate: f64 = 0.0,
};

pub const TickResult = struct {
    slot: u64,
    proposer_node: u8,
    block_produced: bool,
    nodes_received_block: u8,
    epoch_transition: bool,
};

pub const RunResult = struct {
    slots_processed: u64,
    blocks_produced: u64,
    finalized_epoch: u64,
    safety_violations: u64,
    liveness_stalls: u64,
    state_divergences: u64,
};

pub const SimCluster = struct {
    allocator: Allocator,
    prng: std.Random.DefaultPrng,

    /// Heap-allocated so SimNetwork's pointer stays stable.
    net_prng: *std.Random.DefaultPrng,
    network: SimNetwork,

    /// Array of simulated node harnesses.
    nodes: []SimNodeHarness,
    num_nodes: u8,

    /// Global invariant checker (cross-node).
    checker: ClusterInvariantChecker,

    /// Current slot (last processed).
    current_slot: u64,

    /// Offline rate for proposers.
    proposer_offline_rate: f64,

    /// Attestation participation rate.
    participation_rate: f64,

    /// Stats.
    total_slots: u64 = 0,
    total_blocks: u64 = 0,

    /// Track which nodes processed each slot (for invariant checking).
    nodes_processed: []bool,

    /// Shared consensus config borrowed by every simulated node builder.
    primary_config: *config_mod.BeaconConfig,

    /// BeaconNode pointers (owned, one per harness).
    beacon_nodes: []*BeaconNode,

    pub fn init(allocator: Allocator, config: ClusterConfig) !SimCluster {
        var cluster_prng = std.Random.DefaultPrng.init(config.seed);

        const net_prng = try allocator.create(std.Random.DefaultPrng);
        net_prng.* = std.Random.DefaultPrng.init(config.seed +% 100);

        const primary_config = try @import("sim_test_harness.zig").createTestConfig(allocator, config.validator_count);
        errdefer allocator.destroy(primary_config);

        // Allocate node arrays.
        const nodes = try allocator.alloc(SimNodeHarness, config.num_nodes);
        errdefer allocator.free(nodes);
        const beacon_nodes = try allocator.alloc(*BeaconNode, config.num_nodes);
        errdefer allocator.free(beacon_nodes);
        const nodes_processed = try allocator.alloc(bool, config.num_nodes);
        @memset(nodes_processed, false);

        // Node 0: initialize from the shared published anchor state.
        const seed_0 = cluster_prng.random().int(u64);
        const bn0_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
        var bn0_builder = try BeaconNode.Builder.init(allocator, std.testing.io, primary_config, .{
            .options = .{ .engine_mock = true },
            .node_identity = bn0_identity,
        });
        errdefer bn0_builder.deinit();
        const bn0_anchor = try @import("sim_test_harness.zig").createPublishedAnchorState(
            allocator,
            bn0_builder.sharedStateGraph(),
            config.validator_count,
        );
        const start_slot = try bn0_anchor.state.slot();
        const bn0 = try @import("sim_test_harness.zig").finishBuilderFromPublishedAnchor(&bn0_builder, bn0_anchor);
        beacon_nodes[0] = bn0;
        nodes[0] = SimNodeHarness.init(allocator, bn0, seed_0);
        nodes[0].participation_rate = config.participation_rate;

        // Nodes 1..N: each gets the same published anchor state shape.
        for (1..config.num_nodes) |i| {
            const seed_i = cluster_prng.random().int(u64);
            const bn_i_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
            var bn_i_builder = try BeaconNode.Builder.init(allocator, std.testing.io, primary_config, .{
                .options = .{ .engine_mock = true },
                .node_identity = bn_i_identity,
            });
            errdefer bn_i_builder.deinit();
            const anchor_i = try @import("sim_test_harness.zig").createPublishedAnchorState(
                allocator,
                bn_i_builder.sharedStateGraph(),
                config.validator_count,
            );
            const bn_i = try @import("sim_test_harness.zig").finishBuilderFromPublishedAnchor(&bn_i_builder, anchor_i);
            beacon_nodes[i] = bn_i;
            nodes[i] = SimNodeHarness.init(allocator, bn_i, seed_i);
            nodes[i].participation_rate = config.participation_rate;
        }

        const checker = try ClusterInvariantChecker.init(allocator, config.num_nodes);

        var self = SimCluster{
            .allocator = allocator,
            .prng = cluster_prng,
            .net_prng = net_prng,
            .network = SimNetwork.init(allocator, net_prng, config.network),
            .nodes = nodes,
            .num_nodes = config.num_nodes,
            .checker = checker,
            .current_slot = start_slot,
            .proposer_offline_rate = config.proposer_offline_rate,
            .participation_rate = config.participation_rate,
            .nodes_processed = nodes_processed,
            .primary_config = primary_config,
            .beacon_nodes = beacon_nodes,
        };
        errdefer self.deinit();
        try self.connectAllPeers();
        return self;
    }

    pub fn deinit(self: *SimCluster) void {
        // Free each harness (checker etc.) then its BeaconNode.
        for (0..self.num_nodes) |i| {
            self.nodes[i].deinit();
            self.beacon_nodes[i].deinit();
        }

        state_transition.deinitStateTransition();

        self.allocator.destroy(self.primary_config);

        self.checker.deinit();
        self.network.deinit();
        self.allocator.destroy(self.net_prng);
        self.allocator.free(self.nodes);
        self.allocator.free(self.beacon_nodes);
        self.allocator.free(self.nodes_processed);
    }

    /// Advance all nodes by one slot.
    ///
    /// 1. Determine if proposer is offline (deterministic skip).
    /// 2. Each node processes the slot (block or skip).
    /// 3. Record state roots and check cluster invariants.
    pub fn tick(self: *SimCluster) !TickResult {
        const target_slot = self.current_slot + 1;
        const proposer_node: u8 = @intCast(target_slot % self.num_nodes);
        const current_epoch = computeEpochAtSlot(self.current_slot);
        const target_epoch = computeEpochAtSlot(target_slot);
        const is_epoch_transition = target_epoch != current_epoch;

        const proposer_offline = self.shouldSkip();

        @memset(self.nodes_processed, false);

        var node_imported = [_]bool{false} ** 256;
        if (!proposer_offline) {
            const proposer_index: usize = @intCast(proposer_node);
            const produced = try self.nodes[proposer_index].produceNextSlotBlockBytes();
            defer self.allocator.free(produced.bytes);

            const send_time_ns = self.nodes[proposer_index].sim_io.monotonic_ns;
            const slot_deadline_ns = send_time_ns + self.nodes[proposer_index].clock.seconds_per_slot * std.time.ns_per_s;

            for (0..self.num_nodes) |to| {
                _ = try self.network.send(
                    proposer_node,
                    @intCast(to),
                    produced.bytes,
                    .gossip,
                    send_time_ns,
                );
            }

            try self.scheduleStatusMaintenanceRequests(send_time_ns);
            try self.drainNetworkUntil(slot_deadline_ns, &node_imported);
        }

        var nodes_received: u8 = 0;
        for (0..self.num_nodes) |i| {
            var peers_buf: [256]SyncPeer = undefined;
            const peer_count = self.collectReachablePeers(i, &peers_buf);
            _ = try self.nodes[i].driveSyncWithPeers(peers_buf[0..peer_count]);

            if (!node_imported[i]) {
                node_imported[i] = (try self.nodes[i].currentSlot()) >= target_slot;
            }

            const head_slot = try self.nodes[i].currentSlot();
            if (head_slot < target_slot) {
                try self.nodes[i].advanceEmptyToSlot(target_slot);
            }

            const result = try self.nodes[i].observeSlot(target_slot, node_imported[i]);
            self.nodes_processed[i] = true;
            if (node_imported[i]) nodes_received += 1;

            const fin_epoch = self.nodes[i].checker.finalized_epoch;
            try self.checker.recordNodeState(
                @intCast(i),
                result.slot,
                result.state_root,
                fin_epoch,
            );
        }

        try self.checker.checkTick(target_slot, self.nodes_processed);

        self.current_slot = target_slot;
        self.total_slots += 1;
        if (!proposer_offline) self.total_blocks += 1;

        return .{
            .slot = target_slot,
            .proposer_node = proposer_node,
            .block_produced = !proposer_offline,
            .nodes_received_block = nodes_received,
            .epoch_transition = is_epoch_transition,
        };
    }

    /// Run N slots.
    pub fn run(self: *SimCluster, num_slots: u64) !RunResult {
        for (0..num_slots) |_| {
            _ = try self.tick();
        }
        return self.getRunResult();
    }

    /// Run until finality advances past epoch 0, or max_slots is reached.
    pub fn runUntilFinality(self: *SimCluster, max_slots: u64) !RunResult {
        for (0..max_slots) |_| {
            _ = try self.tick();

            for (self.checker.node_finalized_epochs) |e| {
                if (e > 0) return self.getRunResult();
            }
        }
        return self.getRunResult();
    }

    /// Get the current RunResult.
    pub fn getRunResult(self: *const SimCluster) RunResult {
        var max_finalized: u64 = 0;
        for (self.checker.node_finalized_epochs) |e| {
            max_finalized = @max(max_finalized, e);
        }

        return .{
            .slots_processed = self.total_slots,
            .blocks_produced = self.total_blocks,
            .finalized_epoch = max_finalized,
            .safety_violations = self.checker.safety_violations,
            .liveness_stalls = self.checker.liveness_stalls,
            .state_divergences = self.checker.state_divergences,
        };
    }

    fn scheduleStatusMaintenanceRequests(self: *SimCluster, current_time_ns: u64) !void {
        const now_ms = current_time_ns / std.time.ns_per_ms;

        for (0..self.num_nodes) |node_idx| {
            const pm = self.beacon_nodes[node_idx].peer_manager orelse continue;
            var actions = pm.maintenance(now_ms, .{}) catch continue;
            defer actions.deinit(self.allocator);

            var request_bytes: [StatusMessage.fixed_size]u8 = undefined;
            const local_status = self.beacon_nodes[node_idx].getStatus();
            _ = StatusMessage.serializeIntoBytes(&local_status, &request_bytes);

            for (actions.peers_to_restatus) |peer_id| {
                const peer_idx = self.findNodeIndexByPeerId(peer_id) orelse continue;
                if (self.network.partition_set[node_idx][peer_idx] or self.network.partition_set[peer_idx][node_idx]) {
                    continue;
                }
                _ = try self.network.send(
                    @intCast(node_idx),
                    @intCast(peer_idx),
                    &request_bytes,
                    .req_resp_request,
                    current_time_ns,
                );
            }
        }
    }

    fn drainNetworkUntil(self: *SimCluster, deadline_ns: u64, node_imported: *[256]bool) !void {
        var iterations: usize = 0;
        while (iterations < 32) : (iterations += 1) {
            const delivered = try self.network.tick(deadline_ns);
            if (delivered.len == 0) break;

            for (delivered) |msg| {
                defer self.allocator.free(msg.data);

                const to: usize = @intCast(msg.to);
                switch (msg.message_type) {
                    .gossip => {
                        const imported = try self.nodes[to].importExternalBlockBytes(msg.data, .gossip);
                        node_imported[to] = node_imported[to] or imported;
                    },
                    .gossip_attestation => {},
                    .req_resp_request => try self.handleReqRespRequest(msg),
                    .req_resp_response => try self.handleReqRespResponse(msg),
                }
            }
        }
    }

    fn handleReqRespRequest(self: *SimCluster, msg: sim_network.DeliveredMessage) !void {
        const to: usize = @intCast(msg.to);
        const chunks = self.beacon_nodes[to].onReqResp(.status, msg.data) catch |err| {
            const response_bytes = try sim_network.encodeReqRespResponse(self.allocator, .server_error, @errorName(err));
            defer self.allocator.free(response_bytes);
            _ = try self.network.send(msg.to, msg.from, response_bytes, .req_resp_response, msg.deliver_at_ns);
            return;
        };
        defer networking.freeResponseChunks(self.beacon_nodes[to].allocator, chunks);

        const chunk = if (chunks.len == 1) chunks[0] else networking.ResponseChunk{
            .result = .server_error,
            .context_bytes = null,
            .ssz_payload = "unexpected_status_chunk_count",
        };
        const response_bytes = try sim_network.encodeReqRespResponse(self.allocator, chunk.result, chunk.ssz_payload);
        defer self.allocator.free(response_bytes);
        _ = try self.network.send(msg.to, msg.from, response_bytes, .req_resp_response, msg.deliver_at_ns);
    }

    fn handleReqRespResponse(self: *SimCluster, msg: sim_network.DeliveredMessage) !void {
        const to: usize = @intCast(msg.to);
        const from: usize = @intCast(msg.from);
        const decoded = sim_network.decodeReqRespResponse(msg.data) catch return;
        if (decoded.result != .success) return;

        var peer_status: StatusMessage.Type = undefined;
        StatusMessage.deserializeFromBytes(decoded.payload, &peer_status) catch return;
        _ = reqresp_callbacks.handlePeerStatusAtTime(
            self.beacon_nodes[to],
            self.beacon_nodes[from].api_node_identity.peer_id,
            peer_status,
            null,
            msg.deliver_at_ns / std.time.ns_per_ms,
        );
    }

    fn findNodeIndexByPeerId(self: *const SimCluster, peer_id: []const u8) ?usize {
        for (0..self.num_nodes) |idx| {
            if (std.mem.eql(u8, self.beacon_nodes[idx].api_node_identity.peer_id, peer_id)) {
                return idx;
            }
        }
        return null;
    }

    /// Create a network partition between two groups of nodes.
    pub fn partitionGroups(self: *SimCluster, group_a: []const u8, group_b: []const u8) void {
        for (group_a) |a| {
            for (group_b) |b| {
                self.network.partition(a, b);
                self.disconnectPeerPair(a, b);
            }
        }
    }

    /// Heal all network partitions.
    pub fn healAllPartitions(self: *SimCluster) void {
        self.network.healAll();
        self.reconnectAllPeers() catch {};
    }

    fn connectAllPeers(self: *SimCluster) !void {
        for (0..self.num_nodes) |a| {
            for (a + 1..self.num_nodes) |b| {
                try self.reconnectPeerPair(@intCast(a), @intCast(b));
            }
        }
    }

    fn reconnectAllPeers(self: *SimCluster) !void {
        for (0..self.num_nodes) |a| {
            for (a + 1..self.num_nodes) |b| {
                if (self.network.partition_set[a][b] or self.network.partition_set[b][a]) continue;
                try self.reconnectPeerPair(@intCast(a), @intCast(b));
            }
        }
    }

    fn reconnectPeerPair(self: *SimCluster, a: u8, b: u8) !void {
        const a_idx: usize = @intCast(a);
        const b_idx: usize = @intCast(b);
        try self.nodes[a_idx].connectPeer(.{
            .peer_id = self.beacon_nodes[b_idx].api_node_identity.peer_id,
            .node = self.beacon_nodes[b_idx],
        });
        try self.nodes[b_idx].connectPeer(.{
            .peer_id = self.beacon_nodes[a_idx].api_node_identity.peer_id,
            .node = self.beacon_nodes[a_idx],
        });
    }

    fn disconnectPeerPair(self: *SimCluster, a: u8, b: u8) void {
        const a_idx: usize = @intCast(a);
        const b_idx: usize = @intCast(b);
        self.nodes[a_idx].disconnectPeer(self.beacon_nodes[b_idx].api_node_identity.peer_id);
        self.nodes[b_idx].disconnectPeer(self.beacon_nodes[a_idx].api_node_identity.peer_id);
    }

    fn collectReachablePeers(
        self: *const SimCluster,
        node_idx: usize,
        buf: *[256]SyncPeer,
    ) usize {
        var count: usize = 0;
        for (0..self.num_nodes) |peer_idx| {
            if (peer_idx == node_idx) continue;
            if (self.network.partition_set[node_idx][peer_idx] or self.network.partition_set[peer_idx][node_idx]) {
                continue;
            }

            buf[count] = .{
                .peer_id = self.beacon_nodes[peer_idx].api_node_identity.peer_id,
                .node = self.beacon_nodes[peer_idx],
            };
            count += 1;
        }
        return count;
    }

    fn shouldSkip(self: *SimCluster) bool {
        if (self.proposer_offline_rate <= 0.0) return false;

        const val: f64 = @as(f64, @floatFromInt(self.prng.random().int(u32))) /
            @as(f64, @floatFromInt(std.math.maxInt(u32)));
        return val < self.proposer_offline_rate;
    }
};
