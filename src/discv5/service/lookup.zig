const std = @import("std");
const Allocator = std.mem.Allocator;
const NodeId = @import("../enr.zig").NodeId;
const kbucket = @import("../kbucket.zig");

pub const MAX_RESULTS: usize = kbucket.K;
pub const MAX_PARALLELISM: usize = kbucket.K;
/// Bound the closest-candidate frontier while retaining contacted/in-flight
/// entries so eviction cannot erase request history and cause repeated queries.
pub const MAX_CANDIDATES: usize = MAX_RESULTS + MAX_PARALLELISM;

pub const Config = struct {
    num_results: usize,
    parallelism: usize,
    request_limit: usize,
    timeout_ms: u64,
};

pub const PeerState = enum {
    not_contacted,
    waiting,
    succeeded,
    failed,
};

pub const Peer = struct {
    node_id: NodeId,
    peers_returned: usize = 0,
    state: PeerState = .not_contacted,
};

pub const State = enum {
    iterating,
    stalled,
    finished,
};

pub const Lookup = struct {
    target: NodeId,
    started_at_ns: i64,
    state: State = .iterating,
    no_progress: usize = 0,
    num_waiting: usize = 0,
    peers: std.ArrayListUnmanaged(Peer) = .empty,

    pub fn init(alloc: Allocator, target: NodeId, seeds: []const NodeId, started_at_ns: i64, config: Config) !Lookup {
        if (config.num_results == 0 or config.num_results > MAX_RESULTS) return error.InvalidNumResults;
        if (config.parallelism == 0 or config.parallelism > MAX_PARALLELISM) return error.InvalidParallelism;
        if (seeds.len > MAX_RESULTS) return error.TooManySeeds;

        var lookup = Lookup{
            .target = target,
            .started_at_ns = started_at_ns,
        };
        errdefer lookup.deinit(alloc);
        try lookup.peers.ensureTotalCapacityPrecise(alloc, MAX_CANDIDATES);

        for (seeds) |seed| {
            _ = lookup.insertCandidate(seed);
        }
        lookup.truncateCandidates(config.num_results);
        return lookup;
    }

    pub fn deinit(self: *Lookup, alloc: Allocator) void {
        self.peers.deinit(alloc);
    }

    pub fn isTimedOut(self: *const Lookup, now_ns: i64, config: Config) bool {
        const elapsed_ns: i128 = @as(i128, now_ns) - @as(i128, self.started_at_ns);
        return elapsed_ns >= @as(i128, config.timeout_ms) * std.time.ns_per_ms;
    }

    pub fn atCapacity(self: *const Lookup, config: Config) bool {
        return switch (self.state) {
            .iterating => self.num_waiting >= config.parallelism,
            .stalled => self.num_waiting >= config.num_results,
            .finished => true,
        };
    }

    fn insertCandidate(self: *Lookup, node_id: NodeId) ?usize {
        std.debug.assert(self.peers.items.len <= MAX_CANDIDATES);
        std.debug.assert(self.peers.capacity >= MAX_CANDIDATES);

        for (self.peers.items) |peer| {
            if (std.mem.eql(u8, &peer.node_id, &node_id)) return null;
        }

        const candidate_distance = kbucket.xorDistance(&self.target, &node_id);
        var insert_at = self.peers.items.len;
        for (self.peers.items, 0..) |peer, i| {
            const peer_distance = kbucket.xorDistance(&self.target, &peer.node_id);
            if (std.mem.lessThan(u8, &candidate_distance, &peer_distance)) {
                insert_at = i;
                break;
            }
        }

        if (self.peers.items.len == MAX_CANDIDATES) {
            // Only an uncontacted candidate can be replaced. Keeping waiting,
            // succeeded, and failed peers prevents a later response from
            // reintroducing the same NodeId as fresh work.
            var evict_index = self.peers.items.len;
            while (evict_index > 0) {
                evict_index -= 1;
                if (self.peers.items[evict_index].state == .not_contacted) break;
            } else return null;

            if (insert_at > evict_index) return null;
            _ = self.peers.orderedRemove(evict_index);
        }

        self.peers.insertAssumeCapacity(insert_at, .{ .node_id = node_id });
        return insert_at;
    }

    pub fn findPeerIndex(self: *const Lookup, node_id: *const NodeId) ?usize {
        for (self.peers.items, 0..) |peer, i| {
            if (std.mem.eql(u8, &peer.node_id, node_id)) return i;
        }
        return null;
    }

    pub fn truncateCandidates(self: *Lookup, max_candidates: usize) void {
        if (self.peers.items.len <= max_candidates) return;
        self.peers.shrinkRetainingCapacity(max_candidates);
    }

    pub fn onSuccess(self: *Lookup, node_id: *const NodeId, closer_peers: []const NodeId, config: Config) void {
        if (self.state == .finished) return;

        const peer_index = self.findPeerIndex(node_id) orelse {
            self.maybeFinish(config);
            return;
        };

        const accepted_peers = closer_peers[0..@min(closer_peers.len, kbucket.K)];
        if (self.peers.items[peer_index].state == .waiting) {
            self.num_waiting -= 1;
            self.peers.items[peer_index].peers_returned += accepted_peers.len;
            self.peers.items[peer_index].state = .succeeded;
        }

        const had_few_results = self.peers.items.len < config.num_results;
        var progress = false;
        for (accepted_peers) |peer_id| {
            if (self.insertCandidate(peer_id)) |insert_index| {
                if (insert_index == 0 or had_few_results) progress = true;
            }
        }

        switch (self.state) {
            .iterating => {
                self.no_progress = if (progress) 0 else self.no_progress + 1;
                if (self.no_progress >= config.parallelism) self.state = .stalled;
            },
            .stalled => {
                if (progress) {
                    self.state = .iterating;
                    self.no_progress = 0;
                }
            },
            .finished => {},
        }

        self.maybeFinish(config);
    }

    pub fn onFailure(self: *Lookup, node_id: *const NodeId, config: Config) void {
        if (self.state == .finished) return;

        if (self.findPeerIndex(node_id)) |index| {
            if (self.peers.items[index].state == .waiting) {
                self.num_waiting -= 1;
                self.peers.items[index].state = .failed;
            }
        }

        self.maybeFinish(config);
    }

    pub fn nextPeer(self: *Lookup, config: Config) ?NodeId {
        if (self.state == .finished or self.atCapacity(config)) return null;

        for (self.peers.items) |*peer| {
            if (peer.state != .not_contacted) continue;
            peer.state = .waiting;
            self.num_waiting += 1;
            return peer.node_id;
        }

        self.maybeFinish(config);
        return null;
    }

    fn maybeFinish(self: *Lookup, config: Config) void {
        if (self.state == .finished) return;

        const limit = @min(config.num_results, self.peers.items.len);
        var blocked = false;
        var succeeded: usize = 0;
        for (self.peers.items[0..limit]) |peer| {
            switch (peer.state) {
                .succeeded => succeeded += 1,
                .waiting, .not_contacted => {
                    blocked = true;
                    break;
                },
                .failed => {},
            }
        }
        if (!blocked and succeeded == limit) {
            self.state = .finished;
            return;
        }

        if (self.num_waiting == 0) {
            for (self.peers.items) |peer| {
                if (peer.state == .not_contacted) return;
            }
            self.state = .finished;
        }
    }
};

fn appendUniqueDistance(out: []u16, len: *usize, distance: u16) void {
    for (out[0..len.*]) |existing| {
        if (existing == distance) return;
    }
    out[len.*] = distance;
    len.* += 1;
}

pub fn findNodeLogDistances(target: *const NodeId, peer_id: *const NodeId, max_distances: usize, out: []u16) usize {
    if (max_distances == 0) return 0;

    var len: usize = 0;
    var wire_distance: u16 = 1;
    if (kbucket.logDistance(target, peer_id)) |distance| {
        wire_distance = @as(u16, distance) + 1;
    }

    appendUniqueDistance(out, &len, wire_distance);

    var diff: u16 = 1;
    while (len < max_distances and diff <= 256) : (diff += 1) {
        if (wire_distance + diff <= 256) appendUniqueDistance(out, &len, wire_distance + diff);
        if (len >= max_distances) break;
        if (wire_distance > diff) appendUniqueDistance(out, &len, wire_distance - diff);
    }
    return len;
}

fn testNodeId(last_byte: u8) NodeId {
    var node_id = [_]u8{0} ** 32;
    node_id[31] = last_byte;
    return node_id;
}

fn testConfig(num_results: usize, parallelism: usize) Config {
    return .{
        .num_results = num_results,
        .parallelism = parallelism,
        .request_limit = 3,
        .timeout_ms = 60_000,
    };
}

test "discv5 lookup: initial peers are bounded to requested result count" {
    const alloc = std.testing.allocator;
    const config = testConfig(3, 2);
    const target = testNodeId(0);
    const seeds = [_]NodeId{
        testNodeId(1),
        testNodeId(2),
        testNodeId(3),
        testNodeId(4),
        testNodeId(5),
    };

    var lookup = try Lookup.init(alloc, target, &seeds, 0, config);
    defer lookup.deinit(alloc);

    try std.testing.expectEqual(config.num_results, lookup.peers.items.len);
    try std.testing.expectEqual(testNodeId(1), lookup.peers.items[0].node_id);
    try std.testing.expectEqual(testNodeId(2), lookup.peers.items[1].node_id);
    try std.testing.expectEqual(testNodeId(3), lookup.peers.items[2].node_id);
}

test "discv5 lookup: success from unknown peer does not add candidates" {
    const alloc = std.testing.allocator;
    const config = testConfig(3, 2);
    const target = testNodeId(0);
    const seeds = [_]NodeId{testNodeId(10)};
    const returned = [_]NodeId{ testNodeId(1), testNodeId(2) };

    var lookup = try Lookup.init(alloc, target, &seeds, 0, config);
    defer lookup.deinit(alloc);

    lookup.onSuccess(&testNodeId(99), &returned, config);

    try std.testing.expectEqual(@as(usize, 1), lookup.peers.items.len);
    try std.testing.expectEqual(testNodeId(10), lookup.peers.items[0].node_id);
}

test "discv5 lookup: candidate growth is bounded across responses" {
    const alloc = std.testing.allocator;
    const config = testConfig(3, 2);
    const target = testNodeId(0);
    const seeds = [_]NodeId{testNodeId(250)};
    const first_batch = [_]NodeId{
        testNodeId(33), testNodeId(34), testNodeId(35), testNodeId(36),
        testNodeId(37), testNodeId(38), testNodeId(39), testNodeId(40),
        testNodeId(41), testNodeId(42), testNodeId(43), testNodeId(44),
        testNodeId(45), testNodeId(46), testNodeId(47), testNodeId(48),
    };
    const second_batch = [_]NodeId{
        testNodeId(1),  testNodeId(2),  testNodeId(3),  testNodeId(4),
        testNodeId(5),  testNodeId(6),  testNodeId(7),  testNodeId(8),
        testNodeId(9),  testNodeId(10), testNodeId(11), testNodeId(12),
        testNodeId(13), testNodeId(14), testNodeId(15), testNodeId(16),
    };
    const third_batch = [_]NodeId{
        testNodeId(17), testNodeId(18), testNodeId(19), testNodeId(20),
        testNodeId(21), testNodeId(22), testNodeId(23), testNodeId(24),
        testNodeId(25), testNodeId(26), testNodeId(27), testNodeId(28),
        testNodeId(29), testNodeId(30), testNodeId(31), testNodeId(32),
    };

    var lookup = try Lookup.init(alloc, target, &seeds, 0, config);
    defer lookup.deinit(alloc);

    const first_peer = lookup.nextPeer(config).?;
    lookup.onSuccess(&first_peer, &first_batch, config);
    const second_peer = lookup.nextPeer(config).?;
    lookup.onSuccess(&second_peer, &second_batch, config);
    const third_peer = lookup.nextPeer(config).?;
    lookup.onSuccess(&third_peer, &third_batch, config);

    try std.testing.expectEqual(MAX_CANDIDATES, lookup.peers.items.len);
    const first_index = lookup.findPeerIndex(&first_peer) orelse return error.ContactedPeerEvicted;
    try std.testing.expectEqual(PeerState.succeeded, lookup.peers.items[first_index].state);
    for (lookup.peers.items[1..], lookup.peers.items[0 .. lookup.peers.items.len - 1]) |peer, previous| {
        const peer_distance = kbucket.xorDistance(&target, &peer.node_id);
        const previous_distance = kbucket.xorDistance(&target, &previous.node_id);
        try std.testing.expect(!std.mem.lessThan(u8, &peer_distance, &previous_distance));
    }
}

test "discv5 lookup: invalid bounds fail before allocation" {
    const alloc = std.testing.allocator;
    const target = testNodeId(0);
    const no_seeds = [_]NodeId{};

    try std.testing.expectError(error.InvalidNumResults, Lookup.init(alloc, target, &no_seeds, 0, testConfig(0, 1)));
    try std.testing.expectError(error.InvalidNumResults, Lookup.init(alloc, target, &no_seeds, 0, testConfig(MAX_RESULTS + 1, 1)));
    try std.testing.expectError(error.InvalidParallelism, Lookup.init(alloc, target, &no_seeds, 0, testConfig(1, 0)));
    try std.testing.expectError(error.InvalidParallelism, Lookup.init(alloc, target, &no_seeds, 0, testConfig(1, MAX_PARALLELISM + 1)));
}
