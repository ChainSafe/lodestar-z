//! Subnet-aware peer prioritization for the heartbeat pruning cycle.
//!
//! Given the set of connected peers, validator subnet duties, and target
//! peer count, this module decides:
//! - Which peers to disconnect (pruning excess)
//! - How many new peers to discover
//! - Which subnets need more peers (for targeted discovery)
//!
//! The algorithm follows Lodestar TS's `prioritizePeers()` and Lighthouse's
//! `prune_excess_peers()`:
//! 1. Protect peers with active subnet duties
//! 2. Protect outbound peers up to the outbound ratio
//! 3. Prune peers without long-lived subnets first
//! 4. Prune low-score peers
//! 5. Prune peers that are too grouped on a single subnet
//! 6. Final fallback: prune remaining worst peers
//!
//! Reference:
//! - Lodestar: packages/beacon-node/src/network/peers/utils/prioritizePeers.ts
//! - Lighthouse: beacon_node/lighthouse_network/src/peer_manager/mod.rs

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const peer_info_mod = @import("peer_info.zig");
const AttnetsBitfield = peer_info_mod.AttnetsBitfield;
const SyncnetsBitfield = peer_info_mod.SyncnetsBitfield;
const ConnectionDirection = peer_info_mod.ConnectionDirection;
const ATTESTATION_SUBNET_COUNT = peer_info_mod.ATTESTATION_SUBNET_COUNT;
const SYNC_COMMITTEE_SUBNET_COUNT = peer_info_mod.SYNC_COMMITTEE_SUBNET_COUNT;

const subnet_service = @import("subnet_service.zig");
const SubnetId = subnet_service.SubnetId;

// ── Constants ────────────────────────────────────────────────────────────────

/// Target number of peers per attestation subnet.
pub const TARGET_SUBNET_PEERS: u32 = 6;

/// Minimum sync committee peers — don't prune below this.
pub const MIN_SYNC_COMMITTEE_PEERS: u32 = 2;

/// Score threshold for "low score" pruning.
pub const LOW_SCORE_PRUNE_THRESHOLD: f64 = -2.0;

/// Factor to overshoot discovery requests (low dial success rate ~33%).
pub const DISCOVERY_OVERSHOOT_FACTOR: u32 = 3;

/// Minimum ratio of outbound peers to maintain.
pub const OUTBOUND_PEERS_RATIO: f64 = 0.1;

/// Maximum peers to prune in a single heartbeat. Lodestar prunes up to
/// `connected - target + starvation_extra`, but typically ≤ 5 on mainnet.
pub const MAX_PRUNE_PER_HEARTBEAT: u32 = 10;

// ── Input types ──────────────────────────────────────────────────────────────

/// A read-only view of a connected peer for prioritization.
pub const ConnectedPeerView = struct {
    /// Opaque peer identifier.
    peer_id: []const u8,
    /// Connection direction (null if unknown).
    direction: ?ConnectionDirection,
    /// Attestation subnet bitfield.
    attnets: AttnetsBitfield,
    /// Sync committee subnet bitfield.
    syncnets: SyncnetsBitfield,
    /// Combined peer score.
    score: f64,
    /// Whether the peer is trusted.
    is_trusted: bool,
};

/// Configuration for prioritization.
pub const PrioritizationConfig = struct {
    target_peers: u32 = 50,
    max_peers: u32 = 55,
    target_subnet_peers: u32 = TARGET_SUBNET_PEERS,
    outbound_ratio: f64 = OUTBOUND_PEERS_RATIO,
};

// ── Output types ─────────────────────────────────────────────────────────────

/// Reason a peer was selected for disconnection.
pub const DisconnectReason = enum {
    low_score,
    no_long_lived_subnet,
    too_grouped_subnet,
    find_better_peers,
};

/// A peer selected for disconnection with the reason.
pub const PeerDisconnect = struct {
    peer_id: []const u8,
    reason: DisconnectReason,
};

/// A subnet that needs more peers.
pub const SubnetQuery = struct {
    subnet_id: SubnetId,
    kind: enum { attestation, sync_committee },
    peers_needed: u32,
};

/// Result of peer prioritization.
pub const PrioritizationResult = struct {
    /// Peers to disconnect (pruning excess).
    /// Caller does NOT own the peer_id slices — they point into the input.
    peers_to_disconnect: []PeerDisconnect,
    /// Number of additional peers to discover.
    peers_to_discover: u32,
    /// Subnets needing more peers for targeted discovery.
    subnets_needing_peers: []SubnetQuery,

    pub fn deinit(self: *PrioritizationResult, allocator: Allocator) void {
        if (self.peers_to_disconnect.len > 0) allocator.free(self.peers_to_disconnect);
        if (self.subnets_needing_peers.len > 0) allocator.free(self.subnets_needing_peers);
    }
};

// ── Core algorithm ───────────────────────────────────────────────────────────

/// Run peer prioritization. Pure function — no side effects.
///
/// The caller provides a snapshot of connected peers and active subnet
/// subscriptions. Returns actions for the peer manager to execute.
pub fn prioritizePeers(
    allocator: Allocator,
    peers: []const ConnectedPeerView,
    active_attnets: []const SubnetId,
    active_syncnets: []const SubnetId,
    config: PrioritizationConfig,
) !PrioritizationResult {
    var result = PrioritizationResult{
        .peers_to_disconnect = &.{},
        .peers_to_discover = 0,
        .subnets_needing_peers = &.{},
    };
    errdefer result.deinit(allocator);

    const connected_count: u32 = @intCast(peers.len);

    // ── Phase A: Subnet needs assessment ────────────────────────────

    var subnet_queries = std.ArrayListUnmanaged(SubnetQuery){ .items = &.{}, .capacity = 0 };
    defer subnet_queries.deinit(allocator);

    // Count peers per attestation subnet (only for active subnets).
    for (active_attnets) |subnet_id| {
        var count: u32 = 0;
        for (peers) |peer| {
            if (peer.attnets.isSet(subnet_id)) count += 1;
        }
        if (count < config.target_subnet_peers) {
            try subnet_queries.append(allocator, .{
                .subnet_id = subnet_id,
                .kind = .attestation,
                .peers_needed = config.target_subnet_peers - count,
            });
        }
    }

    // Count peers per sync committee subnet (only for active subnets).
    for (active_syncnets) |subnet_id| {
        var count: u32 = 0;
        for (peers) |peer| {
            if (peer.syncnets.isSet(subnet_id)) count += 1;
        }
        if (count < config.target_subnet_peers) {
            try subnet_queries.append(allocator, .{
                .subnet_id = subnet_id,
                .kind = .sync_committee,
                .peers_needed = config.target_subnet_peers - count,
            });
        }
    }

    result.subnets_needing_peers = try subnet_queries.toOwnedSlice(allocator);

    // ── Discovery needs ─────────────────────────────────────────────

    if (connected_count < config.target_peers) {
        const deficit = config.target_peers - connected_count;
        result.peers_to_discover = @min(
            deficit * DISCOVERY_OVERSHOOT_FACTOR,
            config.max_peers -| connected_count,
        );
    }

    // ── Phase B: Pruning when above target ──────────────────────────

    if (connected_count <= config.target_peers) {
        return result;
    }

    const prune_target = connected_count - config.target_peers;

    // Compute per-peer duty count (how many active subnets they cover).
    var duty_counts = try allocator.alloc(u32, peers.len);
    defer allocator.free(duty_counts);
    for (peers, 0..) |peer, i| {
        var duty_count: u32 = 0;
        for (active_attnets) |subnet_id| {
            if (peer.attnets.isSet(subnet_id)) duty_count += 1;
        }
        for (active_syncnets) |subnet_id| {
            if (peer.syncnets.isSet(subnet_id)) duty_count += 1;
        }
        duty_counts[i] = duty_count;
    }

    // Count outbound peers.
    var outbound_count: u32 = 0;
    for (peers) |peer| {
        if (peer.direction) |dir| {
            if (dir == .outbound) outbound_count += 1;
        }
    }
    const outbound_target: u32 = @intFromFloat(@round(config.outbound_ratio * @as(f64, @floatFromInt(connected_count))));

    // Build prune ordering: sort peers by pruning priority (most prunable first).
    var indices = try allocator.alloc(usize, peers.len);
    defer allocator.free(indices);
    for (0..peers.len) |i| indices[i] = i;

    const SortCtx = struct {
        peers: []const ConnectedPeerView,
        duties: []const u32,

        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            // Lower duty count → more prunable.
            const da = ctx.duties[a];
            const db = ctx.duties[b];
            if (da != db) return da < db;

            // Fewer long-lived subnets → more prunable.
            const la: u32 = @intCast(ctx.peers[a].attnets.count() + ctx.peers[a].syncnets.count());
            const lb: u32 = @intCast(ctx.peers[b].attnets.count() + ctx.peers[b].syncnets.count());
            if (la != lb) return la < lb;

            // Lower score → more prunable.
            return ctx.peers[a].score < ctx.peers[b].score;
        }
    };

    const sort_ctx = SortCtx{ .peers = peers, .duties = duty_counts };
    std.mem.sortUnstable(usize, indices, sort_ctx, SortCtx.lessThan);

    // Filter eligible peers (not trusted, respecting outbound ratio).
    var eligible = std.ArrayListUnmanaged(usize){ .items = &.{}, .capacity = 0 };
    defer eligible.deinit(allocator);

    var outbound_eligible: u32 = 0;
    for (indices) |idx| {
        const peer = peers[idx];

        // Never prune trusted peers.
        if (peer.is_trusted) continue;

        // Protect outbound peers up to the ratio.
        if (peer.direction) |dir| {
            if (dir == .outbound) {
                if (outbound_count - outbound_eligible <= outbound_target) {
                    continue; // Need this outbound peer.
                }
                outbound_eligible += 1;
            }
        }

        try eligible.append(allocator, idx);
    }

    // Apply pruning stages.
    var disconnects = std.ArrayListUnmanaged(PeerDisconnect){ .items = &.{}, .capacity = 0 };
    defer disconnects.deinit(allocator);

    // Track which indices we've already marked for disconnect.
    var marked = try allocator.alloc(bool, peers.len);
    defer allocator.free(marked);
    @memset(marked, false);

    // Stage 1: No long-lived subnets.
    for (eligible.items) |idx| {
        if (disconnects.items.len >= prune_target) break;
        if (marked[idx]) continue;
        const peer = peers[idx];
        const has_ll_subnet = peer.attnets.count() > 0 or peer.syncnets.count() > 0;
        if (!has_ll_subnet) {
            try disconnects.append(allocator, .{
                .peer_id = peer.peer_id,
                .reason = .no_long_lived_subnet,
            });
            marked[idx] = true;
        }
    }

    // Stage 2: Low score.
    for (eligible.items) |idx| {
        if (disconnects.items.len >= prune_target) break;
        if (marked[idx]) continue;
        if (peers[idx].score < LOW_SCORE_PRUNE_THRESHOLD) {
            try disconnects.append(allocator, .{
                .peer_id = peers[idx].peer_id,
                .reason = .low_score,
            });
            marked[idx] = true;
        }
    }

    // Stage 3: Too-grouped subnets — find subnet with most peers > target,
    // remove peers that contribute least to other subnets.
    if (disconnects.items.len < prune_target) {
        // Build per-subnet peer counts.
        var subnet_peer_counts: [ATTESTATION_SUBNET_COUNT]u32 = [_]u32{0} ** ATTESTATION_SUBNET_COUNT;
        for (peers, 0..) |peer, idx| {
            if (marked[idx]) continue;
            var s: u32 = 0;
            while (s < ATTESTATION_SUBNET_COUNT) : (s += 1) {
                if (peer.attnets.isSet(s)) subnet_peer_counts[s] += 1;
            }
        }

        // Find densest subnet.
        while (disconnects.items.len < prune_target) {
            var max_subnet: ?u32 = null;
            var max_count: u32 = 0;
            for (&subnet_peer_counts, 0..) |count, s| {
                if (count > config.target_subnet_peers and count > max_count) {
                    max_count = count;
                    max_subnet = @intCast(s);
                }
            }
            if (max_subnet == null) break; // No over-subscribed subnets.

            // Find best candidate to remove from this subnet: fewest attnets overall.
            var best_candidate: ?usize = null;
            var best_attnet_count: u32 = std.math.maxInt(u32);
            for (eligible.items) |idx| {
                if (marked[idx]) continue;
                if (!peers[idx].attnets.isSet(max_subnet.?)) continue;

                const attnet_count: u32 = @intCast(peers[idx].attnets.count());
                if (attnet_count < best_attnet_count) {
                    // Check sync committee protection.
                    var sync_safe = true;
                    var sc: u32 = 0;
                    while (sc < SYNC_COMMITTEE_SUBNET_COUNT) : (sc += 1) {
                        if (peers[idx].syncnets.isSet(sc)) {
                            var sc_count: u32 = 0;
                            for (peers, 0..) |p, pidx| {
                                if (!marked[pidx] and p.syncnets.isSet(sc)) sc_count += 1;
                            }
                            if (sc_count <= MIN_SYNC_COMMITTEE_PEERS) {
                                sync_safe = false;
                                break;
                            }
                        }
                    }
                    if (!sync_safe) continue;

                    best_attnet_count = attnet_count;
                    best_candidate = idx;
                }
            }

            if (best_candidate) |idx| {
                try disconnects.append(allocator, .{
                    .peer_id = peers[idx].peer_id,
                    .reason = .too_grouped_subnet,
                });
                marked[idx] = true;

                // Update subnet counts.
                var s: u32 = 0;
                while (s < ATTESTATION_SUBNET_COUNT) : (s += 1) {
                    if (peers[idx].attnets.isSet(s)) subnet_peer_counts[s] -|= 1;
                }
            } else {
                // Can't find a candidate for this subnet — skip it.
                subnet_peer_counts[max_subnet.?] = 0;
            }
        }
    }

    // Stage 4: Final fallback — prune remaining worst peers.
    for (eligible.items) |idx| {
        if (disconnects.items.len >= prune_target) break;
        if (marked[idx]) continue;
        try disconnects.append(allocator, .{
            .peer_id = peers[idx].peer_id,
            .reason = .find_better_peers,
        });
        marked[idx] = true;
    }

    result.peers_to_disconnect = try disconnects.toOwnedSlice(allocator);
    return result;
}

// ── Tests ────────────────────────────────────────────────────────────────────

fn makePeer(
    id: []const u8,
    dir: ?ConnectionDirection,
    score: f64,
    attnets_bits: []const u32,
    syncnets_bits: []const u32,
) ConnectedPeerView {
    var attnets = AttnetsBitfield.initEmpty();
    for (attnets_bits) |bit| attnets.set(bit);

    var syncnets = SyncnetsBitfield.initEmpty();
    for (syncnets_bits) |bit| syncnets.set(bit);

    return .{
        .peer_id = id,
        .direction = dir,
        .attnets = attnets,
        .syncnets = syncnets,
        .score = score,
        .is_trusted = false,
    };
}

test "prioritizePeers: below target → discover, no prune" {
    const peers = [_]ConnectedPeerView{
        makePeer("p1", .inbound, 0.0, &.{}, &.{}),
        makePeer("p2", .outbound, 0.0, &.{}, &.{}),
    };
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        .{ .target_peers = 10, .max_peers = 15 },
    );
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), result.peers_to_disconnect.len);
    try testing.expect(result.peers_to_discover > 0);
    // Deficit 8, overshoot 3x = 24, capped at max_peers - 2 = 13.
    try testing.expectEqual(@as(u32, 13), result.peers_to_discover);
}

test "prioritizePeers: at target → no action" {
    var peers_arr: [5]ConnectedPeerView = undefined;
    for (&peers_arr, 0..) |*p, i| {
        var buf: [8]u8 = undefined;
        const id = std.fmt.bufPrint(&buf, "peer_{d}", .{i}) catch "peer";
        p.* = makePeer(id, .outbound, 0.0, &.{}, &.{});
    }
    var result = try prioritizePeers(
        testing.allocator,
        &peers_arr,
        &.{},
        &.{},
        .{ .target_peers = 5, .max_peers = 10 },
    );
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), result.peers_to_disconnect.len);
    try testing.expectEqual(@as(u32, 0), result.peers_to_discover);
}

test "prioritizePeers: above target → prune no-subnet peers first" {
    const peers = [_]ConnectedPeerView{
        makePeer("has_subnet", .inbound, 0.0, &.{ 1, 5, 10 }, &.{}),
        makePeer("no_subnet_1", .inbound, 0.0, &.{}, &.{}),
        makePeer("no_subnet_2", .inbound, -1.0, &.{}, &.{}),
        makePeer("has_subnet_2", .outbound, 5.0, &.{ 2, 3 }, &.{}),
    };
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        .{ .target_peers = 2, .max_peers = 5 },
    );
    defer result.deinit(testing.allocator);

    // Should disconnect 2 peers (4 - 2 = 2).
    try testing.expectEqual(@as(usize, 2), result.peers_to_disconnect.len);

    // Both should be the no_subnet peers.
    for (result.peers_to_disconnect) |d| {
        try testing.expect(
            std.mem.eql(u8, d.peer_id, "no_subnet_1") or
                std.mem.eql(u8, d.peer_id, "no_subnet_2"),
        );
        try testing.expectEqual(DisconnectReason.no_long_lived_subnet, d.reason);
    }
}

test "prioritizePeers: low-score peers pruned in stage 2" {
    const peers = [_]ConnectedPeerView{
        makePeer("good_1", .outbound, 5.0, &.{1}, &.{}),
        makePeer("good_2", .inbound, 3.0, &.{2}, &.{}),
        makePeer("bad_score", .inbound, -5.0, &.{3}, &.{}),
    };
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        .{ .target_peers = 2, .max_peers = 5 },
    );
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.peers_to_disconnect.len);
    try testing.expectEqualStrings("bad_score", result.peers_to_disconnect[0].peer_id);
    try testing.expectEqual(DisconnectReason.low_score, result.peers_to_disconnect[0].reason);
}

test "prioritizePeers: trusted peers never pruned" {
    var peer_trusted = makePeer("trusted", .inbound, -100.0, &.{}, &.{});
    peer_trusted.is_trusted = true;

    const peers = [_]ConnectedPeerView{
        peer_trusted,
        makePeer("regular", .inbound, 0.0, &.{1}, &.{}),
        makePeer("regular2", .inbound, 0.0, &.{2}, &.{}),
    };
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        .{ .target_peers = 1, .max_peers = 3 },
    );
    defer result.deinit(testing.allocator);

    // Need to prune 2, but trusted can't be pruned → only 2 non-trusted available.
    for (result.peers_to_disconnect) |d| {
        try testing.expect(!std.mem.eql(u8, d.peer_id, "trusted"));
    }
}

test "prioritizePeers: subnet queries emitted for underserved subnets" {
    const peers = [_]ConnectedPeerView{
        makePeer("p1", .outbound, 0.0, &.{5}, &.{0}),
        makePeer("p2", .inbound, 0.0, &.{5}, &.{}),
    };
    // Active subnets: attestation 5 and 10, sync 0.
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &[_]SubnetId{ 5, 10 },
        &[_]SubnetId{0},
        .{ .target_peers = 10, .max_peers = 15, .target_subnet_peers = 3 },
    );
    defer result.deinit(testing.allocator);

    // Subnet 5 has 2 peers (< 3), subnet 10 has 0, sync 0 has 1.
    try testing.expectEqual(@as(usize, 3), result.subnets_needing_peers.len);

    var found_attnet_5 = false;
    var found_attnet_10 = false;
    var found_sync_0 = false;
    for (result.subnets_needing_peers) |q| {
        if (q.subnet_id == 5 and q.kind == .attestation) {
            found_attnet_5 = true;
            try testing.expectEqual(@as(u32, 1), q.peers_needed); // 3 - 2
        }
        if (q.subnet_id == 10 and q.kind == .attestation) {
            found_attnet_10 = true;
            try testing.expectEqual(@as(u32, 3), q.peers_needed); // 3 - 0
        }
        if (q.subnet_id == 0 and q.kind == .sync_committee) {
            found_sync_0 = true;
            try testing.expectEqual(@as(u32, 2), q.peers_needed); // 3 - 1
        }
    }
    try testing.expect(found_attnet_5);
    try testing.expect(found_attnet_10);
    try testing.expect(found_sync_0);
}

test "prioritizePeers: outbound ratio protection" {
    // 4 peers: 1 outbound + 3 inbound. Target 2.
    // Outbound target = 10% of 4 ≈ 0. So even the outbound peer can be pruned.
    // But if we set ratio to 0.5, the outbound peer should be protected.
    const peers = [_]ConnectedPeerView{
        makePeer("outbound_1", .outbound, -1.0, &.{}, &.{}),
        makePeer("inbound_1", .inbound, 0.0, &.{}, &.{}),
        makePeer("inbound_2", .inbound, 0.0, &.{}, &.{}),
        makePeer("inbound_3", .inbound, 0.0, &.{}, &.{}),
    };
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        .{ .target_peers = 2, .max_peers = 5, .outbound_ratio = 0.5 },
    );
    defer result.deinit(testing.allocator);

    // With 50% outbound ratio on 4 peers → need 2 outbound. We only have 1.
    // So the outbound peer should NOT be pruned.
    for (result.peers_to_disconnect) |d| {
        try testing.expect(!std.mem.eql(u8, d.peer_id, "outbound_1"));
    }
}
