const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const constants = @import("constants.zig");

const PeerIdStr = types.PeerIdStr;
const Direction = types.Direction;
const Status = types.Status;
const RequestedSubnet = types.RequestedSubnet;
const SubnetQuery = types.SubnetQuery;
const PeerDisconnect = types.PeerDisconnect;
const ExcessPeerDisconnectReason = types.ExcessPeerDisconnectReason;

const ATTESTATION_SUBNET_COUNT: u32 = 64;

// --- Public Types ---

pub const PrioritizePeersInput = struct {
    peer_id: PeerIdStr,
    direction: ?Direction,
    status: ?Status,
    attnets: ?[8]u8,
    syncnets: ?[1]u8,
    sampling_groups: ?[]const u32,
    score: f64,
};

pub const PrioritizePeersOpts = struct {
    target_peers: u32,
    max_peers: u32,
    target_group_peers: u32,
    local_status: Status,
    starved: bool,
    starvation_prune_ratio: f64,
    starvation_threshold_slots: u64,
    outbound_peers_ratio: f64 = constants.OUTBOUND_PEERS_RATIO,
    target_subnet_peers: u32 = constants.TARGET_SUBNET_PEERS,
    number_of_custody_groups: u32,
};

pub const PrioritizePeersResult = struct {
    peers_to_connect: u32,
    peers_to_disconnect: std.ArrayList(PeerDisconnect),
    attnet_queries: std.ArrayList(SubnetQuery),
    syncnet_queries: std.ArrayList(SubnetQuery),
    custody_group_queries: std.AutoHashMap(u32, u32),

    pub fn deinit(self: *PrioritizePeersResult) void {
        self.peers_to_disconnect.deinit();
        self.attnet_queries.deinit();
        self.syncnet_queries.deinit();
        self.custody_group_queries.deinit();
    }
};

// --- Internal Types ---

const StatusScore = enum(i2) {
    close_to_us = -1,
    far_ahead = 0,
};

const PeerInfo = struct {
    id: PeerIdStr,
    direction: ?Direction,
    status_score: StatusScore,
    attnets: [8]u8,
    syncnets: [1]u8,
    sampling_groups: []const u32,
    attnet_indices: std.BoundedArray(u8, 64),
    syncnet_indices: std.BoundedArray(u8, 8),
    score: f64,
};

// --- Core Algorithm ---

/// Port of prioritizePeers from prioritizePeers.ts (lines 2667-2743).
/// Determines peers to connect/disconnect and subnet queries needed.
pub fn prioritizePeers(
    allocator: Allocator,
    connected_peers: []const PrioritizePeersInput,
    active_attnets: []const RequestedSubnet,
    active_syncnets: []const RequestedSubnet,
    our_sampling_groups: ?[]const u32,
    opts: PrioritizePeersOpts,
) !PrioritizePeersResult {
    var result = PrioritizePeersResult{
        .peers_to_connect = 0,
        .peers_to_disconnect = std.ArrayList(PeerDisconnect).init(allocator),
        .attnet_queries = std.ArrayList(SubnetQuery).init(allocator),
        .syncnet_queries = std.ArrayList(SubnetQuery).init(allocator),
        .custody_group_queries = std.AutoHashMap(u32, u32).init(allocator),
    };
    errdefer result.deinit();

    // Pre-compute PeerInfo array
    const peers = try buildPeerInfoArray(
        allocator,
        connected_peers,
        opts,
    );
    defer allocator.free(peers);

    // Request subnet peers and build duties map
    var duties_by_peer = std.AutoHashMap(usize, u32).init(allocator);
    defer duties_by_peer.deinit();

    try requestAttnetPeers(
        peers,
        active_attnets,
        opts.target_subnet_peers,
        &result.attnet_queries,
        &duties_by_peer,
    );
    try requestSyncnetPeers(
        peers,
        active_syncnets,
        opts.target_subnet_peers,
        &result.syncnet_queries,
        &duties_by_peer,
    );
    try requestCustodyGroupPeers(
        peers,
        our_sampling_groups,
        opts,
        &result.custody_group_queries,
    );

    const count: u32 = @intCast(connected_peers.len);

    if (count < opts.target_peers) {
        // Overshoot connection attempts (success rate ~33%)
        const deficit = opts.target_peers - count;
        const overshoot = constants.PEERS_TO_CONNECT_OVERSHOOT_FACTOR * deficit;
        const max_connect = opts.max_peers - count;
        result.peers_to_connect = @min(overshoot, max_connect);
    } else if (count > opts.target_peers) {
        try pruneExcessPeers(
            allocator,
            peers,
            &duties_by_peer,
            active_attnets,
            &result.peers_to_disconnect,
            opts,
        );
    }

    return result;
}

// --- PeerInfo Construction ---

fn buildPeerInfoArray(
    allocator: Allocator,
    inputs: []const PrioritizePeersInput,
    opts: PrioritizePeersOpts,
) ![]PeerInfo {
    const peers = try allocator.alloc(PeerInfo, inputs.len);
    for (inputs, 0..) |input, i| {
        peers[i] = .{
            .id = input.peer_id,
            .direction = input.direction,
            .status_score = computeStatusScore(
                opts.local_status,
                input.status,
                opts,
            ),
            .attnets = input.attnets orelse std.mem.zeroes([8]u8),
            .syncnets = input.syncnets orelse std.mem.zeroes([1]u8),
            .sampling_groups = input.sampling_groups orelse &.{},
            .attnet_indices = types.getAttnetsActiveBits(
                input.attnets orelse std.mem.zeroes([8]u8),
            ),
            .syncnet_indices = types.getSyncnetsActiveBits(
                input.syncnets orelse std.mem.zeroes([1]u8),
            ),
            .score = input.score,
        };
    }
    return peers;
}

/// Port of computeStatusScore (TS lines 2604-2624).
fn computeStatusScore(
    ours: Status,
    theirs: ?Status,
    opts: PrioritizePeersOpts,
) StatusScore {
    const their_status = theirs orelse return .close_to_us;

    if (their_status.finalized_epoch > ours.finalized_epoch) {
        return .far_ahead;
    }

    if (their_status.head_slot > ours.head_slot + opts.starvation_threshold_slots) {
        return .far_ahead;
    }

    return .close_to_us;
}

// --- Subnet Peer Requests ---

/// Port of attnet portion of requestSubnetPeers (TS lines 2770-2793).
fn requestAttnetPeers(
    peers: []const PeerInfo,
    active_attnets: []const RequestedSubnet,
    target_subnet_peers: u32,
    queries: *std.ArrayList(SubnetQuery),
    duties_by_peer: *std.AutoHashMap(usize, u32),
) !void {
    if (active_attnets.len == 0) return;

    var peers_per_subnet: [ATTESTATION_SUBNET_COUNT]u32 = std.mem.zeroes([ATTESTATION_SUBNET_COUNT]u32);

    for (peers, 0..) |peer, peer_idx| {
        var duty_count: u32 = 0;
        for (active_attnets) |active| {
            if (peerHasAttnetBit(peer, @intCast(active.subnet))) {
                duty_count += 1;
                peers_per_subnet[active.subnet] += 1;
            }
        }
        if (duty_count > 0) {
            const existing = duties_by_peer.get(peer_idx) orelse 0;
            try duties_by_peer.put(peer_idx, existing + duty_count);
        }
    }

    for (active_attnets) |active| {
        const count = peers_per_subnet[active.subnet];
        if (count < target_subnet_peers) {
            try queries.append(.{
                .subnet = active.subnet,
                .to_slot = active.to_slot,
                .max_peers_to_discover = target_subnet_peers - count,
            });
        }
    }
}

/// Port of syncnet portion of requestSubnetPeers (TS lines 2796-2820).
fn requestSyncnetPeers(
    peers: []const PeerInfo,
    active_syncnets: []const RequestedSubnet,
    target_subnet_peers: u32,
    queries: *std.ArrayList(SubnetQuery),
    duties_by_peer: *std.AutoHashMap(usize, u32),
) !void {
    if (active_syncnets.len == 0) return;

    var peers_per_subnet: [8]u32 = std.mem.zeroes([8]u32);

    for (peers, 0..) |peer, peer_idx| {
        var duty_count: u32 = 0;
        for (active_syncnets) |active| {
            if (peerHasSyncnetBit(peer, @intCast(active.subnet))) {
                duty_count += 1;
                peers_per_subnet[active.subnet] += 1;
            }
        }
        if (duty_count > 0) {
            const existing = duties_by_peer.get(peer_idx) orelse 0;
            try duties_by_peer.put(peer_idx, existing + duty_count);
        }
    }

    for (active_syncnets) |active| {
        const count = peers_per_subnet[active.subnet];
        if (count < target_subnet_peers) {
            try queries.append(.{
                .subnet = active.subnet,
                .to_slot = active.to_slot,
                .max_peers_to_discover = target_subnet_peers - count,
            });
        }
    }
}

/// Port of custody group portion of requestSubnetPeers (TS lines 2822-2849).
fn requestCustodyGroupPeers(
    peers: []const PeerInfo,
    our_sampling_groups: ?[]const u32,
    opts: PrioritizePeersOpts,
    queries: *std.AutoHashMap(u32, u32),
) !void {
    const our_groups = our_sampling_groups orelse return;

    var peers_per_group = std.AutoHashMap(u32, u32).init(queries.allocator);
    defer peers_per_group.deinit();

    for (peers) |peer| {
        for (peer.sampling_groups) |group| {
            const entry = try peers_per_group.getOrPut(group);
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
        }
    }

    // Build a set of our sampling groups for fast lookup
    var our_group_set = std.AutoHashMap(u32, void).init(queries.allocator);
    defer our_group_set.deinit();
    for (our_groups) |g| {
        try our_group_set.put(g, {});
    }

    var group_idx: u32 = 0;
    while (group_idx < opts.number_of_custody_groups) : (group_idx += 1) {
        const peers_in_group = peers_per_group.get(group_idx) orelse 0;
        const target = if (our_group_set.contains(group_idx))
            opts.target_group_peers
        else
            constants.TARGET_GROUP_PEERS_PER_SUBNET;

        if (peers_in_group < target) {
            try queries.put(group_idx, target - peers_in_group);
        }
    }
}

// --- Pruning ---

/// Port of pruneExcessPeers (TS lines 2865-3031).
fn pruneExcessPeers(
    allocator: Allocator,
    peers: []const PeerInfo,
    duties_by_peer: *const std.AutoHashMap(usize, u32),
    active_attnets: []const RequestedSubnet,
    disconnects: *std.ArrayList(PeerDisconnect),
    opts: PrioritizePeersOpts,
) !void {
    const count: u32 = @intCast(peers.len);
    const outbound_target = roundU32(
        opts.outbound_peers_ratio * @as(f64, @floatFromInt(count)),
    );

    var outbound_peers: u32 = 0;
    for (peers) |peer| {
        if (peer.direction == .outbound) outbound_peers += 1;
    }

    // Sort peers for pruning order
    const sorted = try sortPeersToPrune(allocator, peers, duties_by_peer);
    defer allocator.free(sorted);

    // Filter to eligible peers
    var eligible = std.ArrayList(usize).init(allocator);
    defer eligible.deinit();
    var outbound_eligible: u32 = 0;

    try filterEligiblePeers(
        peers,
        sorted,
        duties_by_peer,
        opts,
        outbound_peers,
        outbound_target,
        &eligible,
        &outbound_eligible,
    );

    // Compute disconnect target
    const starvation_extra = if (opts.starved)
        @as(f64, @floatFromInt(opts.target_peers)) * opts.starvation_prune_ratio
    else
        0.0;
    const target_f = @as(f64, @floatFromInt(count -| opts.target_peers)) + starvation_extra;
    const disconnect_target = roundU32(target_f);

    // Track which peers are already marked for disconnect
    var already_disconnected = std.AutoHashMap(usize, ExcessPeerDisconnectReason).init(allocator);
    defer already_disconnected.deinit();
    var disconnected_count: u32 = 0;

    // Phase 1: no long-lived subnet peers
    try pruneNoSubnetPeers(
        peers,
        eligible.items,
        disconnect_target,
        disconnects,
        &already_disconnected,
        &disconnected_count,
    );

    // Phase 2: low score peers
    try pruneLowScorePeers(
        peers,
        eligible.items,
        disconnect_target,
        disconnects,
        &already_disconnected,
        &disconnected_count,
    );

    // Phase 3: too-grouped subnet peers
    try pruneTooGroupedPeers(
        allocator,
        peers,
        active_attnets,
        opts.target_subnet_peers,
        disconnect_target,
        disconnects,
        &already_disconnected,
        &disconnected_count,
    );

    // Phase 4: find better peers
    try pruneFindBetterPeers(
        peers,
        sorted,
        disconnect_target,
        disconnects,
        &already_disconnected,
        &disconnected_count,
    );
}

fn filterEligiblePeers(
    peers: []const PeerInfo,
    sorted: []const usize,
    duties_by_peer: *const std.AutoHashMap(usize, u32),
    opts: PrioritizePeersOpts,
    outbound_peers: u32,
    outbound_target: u32,
    eligible: *std.ArrayList(usize),
    outbound_eligible: *u32,
) !void {
    for (sorted) |idx| {
        const peer = peers[idx];

        // Peers with duties not eligible
        if ((duties_by_peer.get(idx) orelse 0) > 0) continue;

        // Peers far ahead when starved not eligible
        if (opts.starved and peer.status_score == .far_ahead) continue;

        // Protect outbound peers up to ratio
        if (peer.direction == .outbound) {
            if (outbound_peers - outbound_eligible.* > outbound_target) {
                outbound_eligible.* += 1;
            } else {
                continue;
            }
        }

        try eligible.append(idx);
    }
}

/// Phase 1: prune peers without long-lived subnets.
fn pruneNoSubnetPeers(
    peers: []const PeerInfo,
    eligible: []const usize,
    target: u32,
    disconnects: *std.ArrayList(PeerDisconnect),
    already: *std.AutoHashMap(usize, ExcessPeerDisconnectReason),
    count: *u32,
) !void {
    for (eligible) |idx| {
        if (count.* >= target) break;
        const peer = peers[idx];
        const has_subnet = peer.attnet_indices.len > 0 or
            peer.syncnet_indices.len > 0;
        if (!has_subnet) {
            try disconnects.append(.{
                .peer_id = peer.id,
                .reason = .no_long_lived_subnet,
            });
            try already.put(idx, .no_long_lived_subnet);
            count.* += 1;
        }
    }
}

/// Phase 2: prune low-score peers.
fn pruneLowScorePeers(
    peers: []const PeerInfo,
    eligible: []const usize,
    target: u32,
    disconnects: *std.ArrayList(PeerDisconnect),
    already: *std.AutoHashMap(usize, ExcessPeerDisconnectReason),
    count: *u32,
) !void {
    for (eligible) |idx| {
        if (count.* >= target) break;
        if (already.contains(idx)) continue;
        const peer = peers[idx];
        if (peer.score < constants.LOW_SCORE_TO_PRUNE_IF_TOO_MANY_PEERS) {
            try disconnects.append(.{
                .peer_id = peer.id,
                .reason = .low_score,
            });
            try already.put(idx, .low_score);
            count.* += 1;
        }
    }
}

/// Phase 3: prune peers that are too grouped on subnets (TS lines 2946-3005).
fn pruneTooGroupedPeers(
    allocator: Allocator,
    peers: []const PeerInfo,
    active_attnets: []const RequestedSubnet,
    target_subnet_peers: u32,
    disconnect_target: u32,
    disconnects: *std.ArrayList(PeerDisconnect),
    already: *std.AutoHashMap(usize, ExcessPeerDisconnectReason),
    count: *u32,
) !void {
    if (count.* >= disconnect_target) return;

    // Build subnet -> peer indices map
    var subnet_to_peers = std.AutoHashMap(u32, std.ArrayList(usize)).init(allocator);
    defer {
        var it = subnet_to_peers.valueIterator();
        while (it.next()) |list| list.deinit();
        subnet_to_peers.deinit();
    }

    var syncnet_peer_count = std.AutoHashMap(u32, u32).init(allocator);
    defer syncnet_peer_count.deinit();

    try buildSubnetMaps(
        peers,
        already,
        &subnet_to_peers,
        &syncnet_peer_count,
    );

    // Iteratively find most-grouped subnet and prune
    const max_iterations: u32 = @intCast(peers.len);
    var iterations: u32 = 0;
    while (count.* < disconnect_target and iterations < max_iterations) : (iterations += 1) {
        const max_subnet = findMaxPeersSubnet(
            &subnet_to_peers,
            target_subnet_peers,
        ) orelse break;

        const removed = try findPeerToRemove(
            peers,
            &subnet_to_peers,
            &syncnet_peer_count,
            max_subnet,
            target_subnet_peers,
            active_attnets,
        );

        if (removed) |idx| {
            removePeerFromSubnetToPeers(&subnet_to_peers, idx);
            decreaseSyncCommitteePeerCount(
                &syncnet_peer_count,
                peers[idx],
            );
            try disconnects.append(.{
                .peer_id = peers[idx].id,
                .reason = .too_grouped_subnet,
            });
            try already.put(idx, .too_grouped_subnet);
            count.* += 1;
        } else {
            // No removable peer on this subnet; remove subnet from map
            if (subnet_to_peers.getPtr(max_subnet)) |list| {
                list.deinit();
            }
            _ = subnet_to_peers.remove(max_subnet);
        }
    }
}

/// Phase 4: disconnect remaining peers to reach target (TS lines 3007-3029).
fn pruneFindBetterPeers(
    peers: []const PeerInfo,
    sorted: []const usize,
    target: u32,
    disconnects: *std.ArrayList(PeerDisconnect),
    already: *std.AutoHashMap(usize, ExcessPeerDisconnectReason),
    count: *u32,
) !void {
    for (sorted) |idx| {
        if (count.* >= target) break;
        if (already.contains(idx)) continue;
        try disconnects.append(.{
            .peer_id = peers[idx].id,
            .reason = .find_better_peers,
        });
        try already.put(idx, .find_better_peers);
        count.* += 1;
    }
}

fn buildSubnetMaps(
    peers: []const PeerInfo,
    already: *const std.AutoHashMap(usize, ExcessPeerDisconnectReason),
    subnet_to_peers: *std.AutoHashMap(u32, std.ArrayList(usize)),
    syncnet_peer_count: *std.AutoHashMap(u32, u32),
) !void {
    const alloc = subnet_to_peers.allocator;
    for (peers, 0..) |peer, idx| {
        if (already.contains(idx)) continue;

        for (peer.attnet_indices.constSlice()) |subnet| {
            const entry = try subnet_to_peers.getOrPut(subnet);
            if (!entry.found_existing) {
                entry.value_ptr.* = std.ArrayList(usize).init(alloc);
            }
            try entry.value_ptr.append(idx);
        }
        for (peer.syncnet_indices.constSlice()) |subnet| {
            const entry = try syncnet_peer_count.getOrPut(subnet);
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
        }
    }
}

/// Port of findMaxPeersSubnet (TS lines 3065-3077).
fn findMaxPeersSubnet(
    subnet_to_peers: *const std.AutoHashMap(u32, std.ArrayList(usize)),
    target_subnet_peers: u32,
) ?u32 {
    var max_subnet: ?u32 = null;
    var max_count: u32 = 0;

    var it = subnet_to_peers.iterator();
    while (it.next()) |entry| {
        const peer_count: u32 = @intCast(entry.value_ptr.items.len);
        if (peer_count > target_subnet_peers and peer_count > max_count) {
            max_subnet = entry.key_ptr.*;
            max_count = peer_count;
        }
    }
    return max_subnet;
}

/// Port of findPeerToRemove (TS lines 3084-3131).
fn findPeerToRemove(
    peers: []const PeerInfo,
    subnet_to_peers: *const std.AutoHashMap(u32, std.ArrayList(usize)),
    syncnet_peer_count: *const std.AutoHashMap(u32, u32),
    max_subnet: u32,
    target_subnet_peers: u32,
    active_attnets: []const RequestedSubnet,
) !?usize {
    const peer_list = subnet_to_peers.get(max_subnet) orelse return null;

    // Sort by attnet count ascending (peers with fewer attnets pruned first)
    // We iterate in order; TS does sortBy on attnetsTrueBitIndices.length
    var best: ?usize = null;
    var best_attnet_count: u32 = std.math.maxInt(u32);

    for (peer_list.items) |idx| {
        const peer = peers[idx];
        const attnet_count: u32 = @intCast(peer.attnet_indices.len);
        if (attnet_count < best_attnet_count or best == null) {
            // Check attnet constraint
            if (!canRemoveAttnetPeer(
                peer,
                subnet_to_peers,
                target_subnet_peers,
                active_attnets,
            )) continue;

            // Check syncnet constraint
            if (!canRemoveSyncnetPeer(peer, syncnet_peer_count)) continue;

            best = idx;
            best_attnet_count = attnet_count;
        }
    }
    return best;
}

fn canRemoveAttnetPeer(
    peer: PeerInfo,
    subnet_to_peers: *const std.AutoHashMap(u32, std.ArrayList(usize)),
    target_subnet_peers: u32,
    active_attnets: []const RequestedSubnet,
) bool {
    if (peer.attnet_indices.len == 0) return true;

    var min_attnet_count: u32 = ATTESTATION_SUBNET_COUNT;
    var found_overlap = false;
    for (active_attnets) |active| {
        if (!peerHasAttnetBit(peer, @intCast(active.subnet))) continue;
        const list = subnet_to_peers.get(active.subnet) orelse continue;
        const num: u32 = @intCast(list.items.len);
        if (num < min_attnet_count) {
            min_attnet_count = num;
            found_overlap = true;
        }
    }
    // If there's overlap and it would drop below target, don't remove
    if (found_overlap and min_attnet_count <= target_subnet_peers) return false;
    return true;
}

fn canRemoveSyncnetPeer(
    peer: PeerInfo,
    syncnet_peer_count: *const std.AutoHashMap(u32, u32),
) bool {
    if (peer.syncnet_indices.len == 0) return true;
    for (peer.syncnet_indices.constSlice()) |subnet| {
        const count = syncnet_peer_count.get(subnet) orelse 0;
        if (count <= constants.MIN_SYNC_COMMITTEE_PEERS) return false;
    }
    return true;
}

/// Port of removePeerFromSubnetToPeers (TS lines 3136-3143).
/// Removes all occurrences of the given peer index from every list
/// in the subnet-to-peers map.
fn removePeerFromSubnetToPeers(
    subnet_to_peers: *std.AutoHashMap(u32, std.ArrayList(usize)),
    peer_idx: usize,
) void {
    var it = subnet_to_peers.valueIterator();
    while (it.next()) |list| {
        var i: usize = 0;
        while (i < list.items.len) {
            if (list.items[i] == peer_idx) {
                _ = list.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
}

/// Port of decreaseSynccommitteePeerCount (TS lines 3148-3157).
fn decreaseSyncCommitteePeerCount(
    syncnet_peer_count: *std.AutoHashMap(u32, u32),
    peer: PeerInfo,
) void {
    for (peer.syncnet_indices.constSlice()) |subnet| {
        if (syncnet_peer_count.getPtr(subnet)) |val| {
            val.* = val.* -| 1;
        }
    }
}

// --- Sorting ---

/// Port of sortPeersToPrune (TS lines 3040-3058).
/// Returns array of peer indices sorted in pruning order (most pruneable first).
fn sortPeersToPrune(
    allocator: Allocator,
    peers: []const PeerInfo,
    duties_by_peer: *const std.AutoHashMap(usize, u32),
) ![]usize {
    const indices = try allocator.alloc(usize, peers.len);

    for (0..peers.len) |i| {
        indices[i] = i;
    }

    // Shuffle for tie-breaking (deterministic seed from peer count)
    var prng = std.Random.DefaultPrng.init(@as(u64, @intCast(peers.len)));
    var random = prng.random();
    random.shuffle(usize, indices);

    // Sort ascending: lowest values = most pruneable
    const Context = struct {
        peers: []const PeerInfo,
        duties: *const std.AutoHashMap(usize, u32),
    };
    const ctx = Context{ .peers = peers, .duties = duties_by_peer };

    std.mem.sort(usize, indices, ctx, struct {
        fn lessThan(c: Context, a: usize, b: usize) bool {
            const d1 = c.duties.get(a) orelse 0;
            const d2 = c.duties.get(b) orelse 0;
            if (d1 != d2) return d1 < d2;

            const s1 = @intFromEnum(c.peers[a].status_score);
            const s2 = @intFromEnum(c.peers[b].status_score);
            if (s1 != s2) return s1 < s2;

            const ll1 = c.peers[a].attnet_indices.len +
                c.peers[a].syncnet_indices.len;
            const ll2 = c.peers[b].attnet_indices.len +
                c.peers[b].syncnet_indices.len;
            if (ll1 != ll2) return ll1 < ll2;

            return c.peers[a].score < c.peers[b].score;
        }
    }.lessThan);

    return indices;
}

// --- Bitvector Helpers ---

fn peerHasAttnetBit(peer: PeerInfo, subnet: u8) bool {
    for (peer.attnet_indices.constSlice()) |idx| {
        if (idx == subnet) return true;
    }
    return false;
}

fn peerHasSyncnetBit(peer: PeerInfo, subnet: u8) bool {
    for (peer.syncnet_indices.constSlice()) |idx| {
        if (idx == subnet) return true;
    }
    return false;
}

fn roundU32(val: f64) u32 {
    if (val <= 0) return 0;
    return @intFromFloat(@round(val));
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

fn makeStatus() Status {
    return .{
        .fork_digest = .{ 0, 0, 0, 0 },
        .finalized_root = std.mem.zeroes([32]u8),
        .finalized_epoch = 100,
        .head_root = std.mem.zeroes([32]u8),
        .head_slot = 3200,
        .earliest_available_slot = null,
    };
}

fn makePeerInput(id: PeerIdStr, dir: ?Direction, score: f64) PrioritizePeersInput {
    return .{
        .peer_id = id,
        .direction = dir,
        .status = makeStatus(),
        .attnets = null,
        .syncnets = null,
        .sampling_groups = null,
        .score = score,
    };
}

fn makeOpts(target: u32, max: u32) PrioritizePeersOpts {
    return .{
        .target_peers = target,
        .max_peers = max,
        .target_group_peers = 6,
        .local_status = makeStatus(),
        .starved = false,
        .starvation_prune_ratio = 0.05,
        .starvation_threshold_slots = 96,
        .number_of_custody_groups = 128,
    };
}

fn generatePeerIds(comptime n: u32) [n]PrioritizePeersInput {
    var peers: [n]PrioritizePeersInput = undefined;
    for (0..n) |i| {
        peers[i] = makePeerInput(PEER_NAMES[i], .inbound, 0);
    }
    return peers;
}

// We need stable peer id strings for tests. Use a compile-time table.
const PEER_NAMES = blk: {
    var names: [200][]const u8 = undefined;
    for (0..200) |i| {
        names[i] = std.fmt.comptimePrint("peer-{d}", .{i});
    }
    break :blk names;
};

test "below target peers — returns peers_to_connect with overshoot" {
    const peers = generatePeerIds(50);
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        null,
        makeOpts(100, 110),
    );
    defer result.deinit();

    // overshoot = 3 * (100 - 50) = 150, max_connect = 110 - 50 = 60
    try testing.expectEqual(@as(u32, 60), result.peers_to_connect);
    try testing.expectEqual(@as(usize, 0), result.peers_to_disconnect.items.len);
}

test "at target peers — no connect no disconnect" {
    const peers = generatePeerIds(100);
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        null,
        makeOpts(100, 110),
    );
    defer result.deinit();

    try testing.expectEqual(@as(u32, 0), result.peers_to_connect);
    try testing.expectEqual(@as(usize, 0), result.peers_to_disconnect.items.len);
}

test "above target peers — disconnects excess" {
    const peers = generatePeerIds(120);
    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        null,
        makeOpts(100, 110),
    );
    defer result.deinit();

    try testing.expectEqual(@as(u32, 0), result.peers_to_connect);
    // Should disconnect ~20 peers
    try testing.expectEqual(@as(usize, 20), result.peers_to_disconnect.items.len);
}

test "subnet queries generated for under-covered attnets" {
    // Create 3 peers with attnet bit 5 set
    var peers: [3]PrioritizePeersInput = undefined;
    for (0..3) |i| {
        var p = makePeerInput(PEER_NAMES[i], .inbound, 0);
        var attnets = std.mem.zeroes([8]u8);
        attnets[0] = 0x20; // bit 5
        p.attnets = attnets;
        peers[i] = p;
    }

    const active = [_]RequestedSubnet{.{ .subnet = 5, .to_slot = 1000 }};

    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &active,
        &.{},
        null,
        makeOpts(100, 110),
    );
    defer result.deinit();

    // 3 peers on subnet 5, target is 6 -> query for 3 more
    try testing.expectEqual(@as(usize, 1), result.attnet_queries.items.len);
    try testing.expectEqual(@as(u32, 5), result.attnet_queries.items[0].subnet);
    try testing.expectEqual(@as(u32, 3), result.attnet_queries.items[0].max_peers_to_discover);
}

test "pruning order — no subnet peers pruned first" {
    // 12 peers: 10 have attnets, 2 don't. Target=10 so need to prune 2.
    var peers: [12]PrioritizePeersInput = undefined;
    for (0..12) |i| {
        var p = makePeerInput(PEER_NAMES[i], .inbound, 0);
        if (i < 10) {
            var attnets = std.mem.zeroes([8]u8);
            attnets[0] = 0x01; // bit 0
            p.attnets = attnets;
        }
        // peers 10 and 11 have no attnets
        peers[i] = p;
    }

    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        null,
        makeOpts(10, 15),
    );
    defer result.deinit();

    try testing.expectEqual(@as(usize, 2), result.peers_to_disconnect.items.len);
    // Both disconnected peers should be no_long_lived_subnet
    for (result.peers_to_disconnect.items) |d| {
        try testing.expectEqual(
            ExcessPeerDisconnectReason.no_long_lived_subnet,
            d.reason,
        );
    }
}

test "outbound peers protected from pruning" {
    // 120 peers: 80 outbound, 40 inbound. Target 100.
    // Outbound target = round(0.1 * 120) = 12, so at least 12 outbound protected.
    var peers: [120]PrioritizePeersInput = undefined;
    for (0..120) |i| {
        const dir: Direction = if (i < 80) .outbound else .inbound;
        peers[i] = makePeerInput(PEER_NAMES[i], dir, 0);
    }

    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        null,
        makeOpts(100, 110),
    );
    defer result.deinit();

    // Count how many outbound peers were disconnected
    var outbound_disconnected: u32 = 0;
    for (result.peers_to_disconnect.items) |d| {
        // peer-0 through peer-79 are outbound
        const id = d.peer_id;
        // Parse "peer-N" to get N
        if (std.mem.startsWith(u8, id, "peer-")) {
            const num = std.fmt.parseInt(u32, id[5..], 10) catch continue;
            if (num < 80) outbound_disconnected += 1;
        }
    }

    // At least 12 outbound peers should be protected (not disconnected)
    const outbound_remaining = 80 - outbound_disconnected;
    try testing.expect(outbound_remaining >= 12);
}

test "starvation prunes extra peers" {
    const peers = generatePeerIds(120);

    // Without starvation
    var result_normal = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        null,
        makeOpts(100, 110),
    );
    defer result_normal.deinit();

    // With starvation
    var opts = makeOpts(100, 110);
    opts.starved = true;
    opts.starvation_prune_ratio = 0.05;

    var result_starved = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        null,
        opts,
    );
    defer result_starved.deinit();

    // Starved should prune more: 20 + round(100 * 0.05) = 25
    try testing.expect(
        result_starved.peers_to_disconnect.items.len >
            result_normal.peers_to_disconnect.items.len,
    );
    try testing.expectEqual(
        @as(usize, 25),
        result_starved.peers_to_disconnect.items.len,
    );
}

test "custody group queries post-fulu" {
    const peers = generatePeerIds(50);

    // Provide our_sampling_groups so custody logic activates
    const our_groups = [_]u32{ 0, 1, 2 };

    var opts = makeOpts(100, 110);
    opts.number_of_custody_groups = 8;
    opts.target_group_peers = 6;

    var result = try prioritizePeers(
        testing.allocator,
        &peers,
        &.{},
        &.{},
        &our_groups,
        opts,
    );
    defer result.deinit();

    // No peers have sampling groups, so all 8 groups should have queries.
    // Groups 0,1,2 need target_group_peers(6), others need TARGET_GROUP_PEERS_PER_SUBNET(4).
    try testing.expectEqual(@as(u32, 8), result.custody_group_queries.count());

    // Our sampling groups should need 6 peers
    try testing.expectEqual(@as(u32, 6), result.custody_group_queries.get(0).?);
    try testing.expectEqual(@as(u32, 6), result.custody_group_queries.get(1).?);
    try testing.expectEqual(@as(u32, 6), result.custody_group_queries.get(2).?);

    // Non-sampling groups should need 4 peers
    try testing.expectEqual(@as(u32, 4), result.custody_group_queries.get(3).?);
    try testing.expectEqual(@as(u32, 4), result.custody_group_queries.get(7).?);
}
