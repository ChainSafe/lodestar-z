//! Shared simulated topology and transport helpers.
//!
//! This layer owns the deterministic peer graph semantics used by higher-level
//! harnesses: peer wiring, partitions, status maintenance, req/resp delivery,
//! and gossip block ingress. It deliberately does not own slot advancement or
//! validator behavior.

const std = @import("std");
const Allocator = std.mem.Allocator;

const networking = @import("networking");
const StatusMessage = networking.messages.StatusMessage;
const reqresp_callbacks = @import("node").reqresp_callbacks_mod;

const sim_network = @import("sim_network.zig");
const SimNetwork = sim_network.SimNetwork;
const SimNodeHarness = @import("sim_node_harness.zig").SimNodeHarness;
const SyncPeer = @import("sim_node_harness.zig").SyncPeer;
const BeaconNode = @import("node").BeaconNode;

pub const AttestationImportFn = *const fn (ctx: *anyopaque, node_idx: usize, bytes: []const u8) void;

pub const SimTopology = struct {
    allocator: Allocator,
    nodes: []SimNodeHarness,
    beacon_nodes: []*BeaconNode,
    network: *SimNetwork,
    crashed_nodes: ?[]const bool = null,
    attestation_import_ctx: ?*anyopaque = null,
    attestation_import_fn: ?AttestationImportFn = null,

    pub fn init(
        allocator: Allocator,
        nodes: []SimNodeHarness,
        beacon_nodes: []*BeaconNode,
        network: *SimNetwork,
        crashed_nodes: ?[]const bool,
    ) SimTopology {
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .beacon_nodes = beacon_nodes,
            .network = network,
            .crashed_nodes = crashed_nodes,
        };
    }

    pub fn withAttestationImporter(
        self: SimTopology,
        ctx: *anyopaque,
        import_fn: AttestationImportFn,
    ) SimTopology {
        var topology = self;
        topology.attestation_import_ctx = ctx;
        topology.attestation_import_fn = import_fn;
        return topology;
    }

    pub fn connectAllPeers(self: *SimTopology) !void {
        for (0..self.nodes.len) |a| {
            for (a + 1..self.nodes.len) |b| {
                try self.reconnectPeerPair(@intCast(a), @intCast(b));
            }
        }
    }

    pub fn reconnectAllReachablePeers(self: *SimTopology) void {
        for (0..self.nodes.len) |a| {
            for (a + 1..self.nodes.len) |b| {
                if (self.network.partition_set[a][b] or self.network.partition_set[b][a]) continue;
                self.reconnectPeerPair(@intCast(a), @intCast(b)) catch {};
            }
        }
    }

    pub fn reconnectPeerPair(self: *SimTopology, a: u8, b: u8) !void {
        if (!self.isNodeActive(a) or !self.isNodeActive(b)) return;

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

    pub fn disconnectPeerPair(self: *SimTopology, a: u8, b: u8) void {
        const a_idx: usize = @intCast(a);
        const b_idx: usize = @intCast(b);
        self.nodes[a_idx].disconnectPeer(self.beacon_nodes[b_idx].api_node_identity.peer_id);
        self.nodes[b_idx].disconnectPeer(self.beacon_nodes[a_idx].api_node_identity.peer_id);
    }

    pub fn partitionGroups(self: *SimTopology, group_a: []const u8, group_b: []const u8) void {
        for (group_a) |a| {
            for (group_b) |b| {
                self.network.partition(a, b);
                self.disconnectPeerPair(a, b);
            }
        }
    }

    pub fn healAllPartitions(self: *SimTopology) void {
        self.network.healAll();
        self.reconnectAllReachablePeers();
    }

    pub fn disconnectNode(self: *SimTopology, node_id: u8) void {
        for (0..self.nodes.len) |i| {
            if (i == node_id) continue;
            self.network.partition(node_id, @intCast(i));
            self.disconnectPeerPair(node_id, @intCast(i));
        }
    }

    pub fn reconnectNode(self: *SimTopology, node_id: u8) void {
        for (0..self.nodes.len) |i| {
            if (i == node_id) continue;
            self.network.heal(node_id, @intCast(i));
            self.reconnectPeerPair(node_id, @intCast(i)) catch {};
        }
    }

    pub fn collectReachablePeers(
        self: *const SimTopology,
        node_idx: usize,
        buf: *[256]SyncPeer,
    ) usize {
        var count: usize = 0;
        for (0..self.nodes.len) |peer_idx| {
            if (peer_idx == node_idx) continue;
            if (!self.isNodeActive(@intCast(peer_idx))) continue;
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

    pub fn scheduleStatusMaintenanceRequests(self: *SimTopology, current_time_ns: u64) !void {
        const now_ms = current_time_ns / std.time.ns_per_ms;

        for (0..self.nodes.len) |node_idx| {
            if (!self.isNodeActive(@intCast(node_idx))) continue;

            const pm = self.beacon_nodes[node_idx].peer_manager orelse continue;
            var actions = pm.maintenance(now_ms, .{}) catch continue;
            defer actions.deinit(self.allocator);

            var request_bytes: [StatusMessage.fixed_size]u8 = undefined;
            const local_status = self.beacon_nodes[node_idx].getStatus();
            _ = StatusMessage.serializeIntoBytes(&local_status, &request_bytes);

            for (actions.peers_to_restatus) |peer_id| {
                const peer_idx = self.findNodeIndexByPeerId(peer_id) orelse continue;
                if (!self.isNodeActive(@intCast(peer_idx))) continue;
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

    pub fn drainNetworkUntil(
        self: *SimTopology,
        deadline_ns: u64,
        node_imported: []bool,
    ) !void {
        var iterations: usize = 0;
        while (iterations < 32) : (iterations += 1) {
            const delivered = try self.network.tick(deadline_ns);
            if (delivered.len == 0) break;

            for (delivered) |msg| {
                defer self.allocator.free(msg.data);

                const to: usize = @intCast(msg.to);
                switch (msg.message_type) {
                    .gossip => {
                        if (!self.isNodeActive(msg.to)) continue;
                        const imported = try self.nodes[to].importExternalBlockBytes(msg.data, .gossip);
                        node_imported[to] = node_imported[to] or imported;
                    },
                    .gossip_attestation => self.importDeliveredGossipAttestation(to, msg.data),
                    .req_resp_request => try self.handleReqRespRequest(msg),
                    .req_resp_response => try self.handleReqRespResponse(msg),
                }
            }
        }
    }

    fn handleReqRespRequest(self: *SimTopology, msg: sim_network.DeliveredMessage) !void {
        const to: usize = @intCast(msg.to);
        if (!self.isNodeActive(msg.to)) return;

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

    fn handleReqRespResponse(self: *SimTopology, msg: sim_network.DeliveredMessage) !void {
        const to: usize = @intCast(msg.to);
        const from: usize = @intCast(msg.from);
        if (!self.isNodeActive(msg.to)) return;

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

    fn importDeliveredGossipAttestation(self: *SimTopology, node_idx: usize, bytes: []const u8) void {
        if (!self.isNodeActive(@intCast(node_idx))) return;
        const ctx = self.attestation_import_ctx orelse return;
        const import_fn = self.attestation_import_fn orelse return;
        import_fn(ctx, node_idx, bytes);
    }

    fn findNodeIndexByPeerId(self: *const SimTopology, peer_id: []const u8) ?usize {
        for (0..self.nodes.len) |idx| {
            if (std.mem.eql(u8, self.beacon_nodes[idx].api_node_identity.peer_id, peer_id)) {
                return idx;
            }
        }
        return null;
    }

    fn isNodeActive(self: *const SimTopology, node_idx: u8) bool {
        const crashed_nodes = self.crashed_nodes orelse return true;
        return !crashed_nodes[node_idx];
    }
};
