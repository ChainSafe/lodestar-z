const std = @import("std");
const c = @import("constants.zig");
const state_mod = @import("state.zig");
const peers_mod = @import("peers.zig");
const score_mod = @import("score.zig");
const io_mod = @import("peer_io.zig");
const protobuf = @import("protobuf.zig");
const topic_mod = @import("topic.zig");
const assert = std.debug.assert;
const Set = state_mod.PeerSet;
const Snapshot = struct { generation: u64 = 0, score: f64 = 0 };

fn logChange(context: *const Context, topic: u16, peer: u16, comptime event: []const u8, backoff_ms: u64) void {
    const row = &context.state.registry.rows[topic];
    const conn = context.state.peers[peer].conn;
    std.log.scoped(.network_mesh).debug(event ++ " connection={d}:{d} topic={s} backoff_ms={d}", .{ conn.index, conn.generation, row.string[0..row.string_len], backoff_ms });
}
pub const Context = struct {
    state: *state_mod.State,
    peers: *peers_mod.Peers,
    scores: *score_mod.PeerScore,
    now: u64,
    heartbeat_ms: u64,
    pressure_ms: u64,
    use_snapshot: bool = false,
};

pub const Mesh = struct {
    rng: std.Random.DefaultPrng,
    snapshot: [c.peers_cap]Snapshot = [_]Snapshot{.{}} ** c.peers_cap,
    pending_prunes: [c.topics_cap]Set = [_]Set{.initEmpty()} ** c.topics_cap,
    pending_count: [c.peers_cap]u16 = [_]u16{0} ** c.peers_cap,
    pending_since: [c.peers_cap]?u64 = [_]?u64{null} ** c.peers_cap,
    retire: Set = .initEmpty(),
    outbound_deficits: u64 = 0,

    pub fn init(seed: u64) Mesh {
        return .{ .rng = std.Random.DefaultPrng.init(seed) };
    }

    pub fn takeSnapshot(self: *Mesh, context: *const Context) void {
        for (context.state.peers, 0..) |*peer, index| {
            self.snapshot[index] = if (peer.active) .{
                .generation = peer.generation,
                .score = context.scores.score(peer.logical.index, context.now),
            } else .{};
        }
    }

    fn score(self: *const Mesh, context: *const Context, peer: u16) f64 {
        if (!context.use_snapshot) return context.scores.score(context.state.peers[peer].logical.index, context.now);
        if (self.snapshot[peer].generation != context.state.peerGeneration(peer)) return -score_mod.counter_max;
        return self.snapshot[peer].score;
    }

    fn eligible(self: *const Mesh, context: *const Context, topic: u16, peer: u16, threshold: f64) bool {
        const row = &context.state.peers[peer];
        if (!row.active or context.peers.rows[row.logical.index].direct or self.retire.isSet(peer)) return false;
        return context.state.registry.subscribers(topic).isSet(peer) and self.score(context, peer) >= threshold;
    }

    fn graftEligible(self: *const Mesh, context: *const Context, topic: u16, peer: u16) bool {
        if (!self.eligible(context, topic, peer, 0) or self.pending_prunes[topic].isSet(peer)) return false;
        return !context.peers.backedOff(context.state.peers[peer].logical, topic, context.state.registry.rows[topic].generation, context.now -| (c.backoff_slack_heartbeats * context.heartbeat_ms));
    }

    fn outbound(context: *const Context, peer: u16) bool {
        return context.peers.rows[context.state.peers[peer].logical.index].direction == .outbound;
    }

    fn outboundCount(context: *const Context, members: *const Set) usize {
        var count: usize = 0;
        var it = members.iterator(.{});
        while (it.next()) |peer| if (outbound(context, @intCast(peer))) {
            count += 1;
        };
        return count;
    }

    pub fn maintain(self: *Mesh, context: *const Context, topic: u16) void {
        self.flushPrunes(context, topic);
        const members = context.state.registry.mesh(topic);
        var it = members.iterator(.{});
        while (it.next()) |index| {
            const peer: u16 = @intCast(index);
            if (!self.eligible(context, topic, peer, 0)) self.prune(context, topic, peer, c.prune_backoff_ms);
        }
        if (!context.state.registry.subscribed(topic)) return;
        var candidate_peers: [c.peers_cap]u16 = undefined;
        const n = self.candidates(context, topic, &candidate_peers, true, 0);
        self.shuffle(candidate_peers[0..n]);
        var out = outboundCount(context, members);
        for (candidate_peers[0..n]) |peer| {
            if (out >= c.mesh_d_out) break;
            if (outbound(context, peer) and self.graft(context, topic, peer)) out += 1;
        }
        if (out < c.mesh_d_out) self.outbound_deficits += 1;
        if (members.count() < c.mesh_d_low) {
            for (candidate_peers[0..n]) |peer| {
                if (members.count() >= c.mesh_d) break;
                _ = self.graft(context, topic, peer);
            }
        }
        if (members.count() > c.mesh_d_high) self.trim(context, topic);
    }

    fn shuffle(self: *Mesh, members: []u16) void {
        assert(members.len <= c.peers_cap);
        for (0..members.len -| 1) |i| {
            const offset = self.rng.random().uintLessThanBiased(u64, @intCast(members.len - i));
            const chosen = i + @as(usize, @intCast(offset));
            std.mem.swap(u16, &members[i], &members[chosen]);
        }
    }

    fn candidates(self: *Mesh, context: *const Context, topic: u16, out: *[c.peers_cap]u16, graft_only: bool, threshold: f64) usize {
        var count: usize = 0;
        for (0..context.state.peers.len) |index| {
            const peer: u16 = @intCast(index);
            if (context.state.registry.mesh(topic).isSet(peer)) continue;
            if (!self.eligible(context, topic, peer, threshold)) continue;
            if (graft_only and !self.graftEligible(context, topic, peer)) continue;
            out[count] = peer;
            count += 1;
        }
        return count;
    }

    fn graft(self: *Mesh, context: *const Context, topic: u16, peer: u16) bool {
        const members = context.state.registry.mesh(topic);
        if (members.isSet(peer) or !self.graftEligible(context, topic, peer)) return false;
        if (!queue(context, topic, peer, null)) return false;
        members.set(peer);
        context.scores.graft(context.state.peers[peer].logical.index, topic, context.now);
        logChange(context, topic, peer, "mesh_graft_sent", 0);
        return true;
    }

    pub fn prune(self: *Mesh, context: *const Context, topic: u16, peer: u16, backoff_ms: u64) void {
        if (context.state.registry.mesh(topic).isSet(peer)) {
            logChange(context, topic, peer, "mesh_prune_local", backoff_ms);
            context.state.registry.mesh(topic).unset(peer);
            context.scores.prune(context.state.peers[peer].logical.index, topic, context.now);
        }
        const row = &context.state.peers[peer];
        if (!row.active) return;
        context.peers.addBackoff(row.logical, topic, context.state.registry.rows[topic].generation, context.now, backoff_ms);
        if (queue(context, topic, peer, backoff_ms / 1000)) {
            self.clearPending(topic, peer);
        } else {
            if (!self.pending_prunes[topic].isSet(peer)) self.pending_count[peer] += 1;
            self.pending_prunes[topic].set(peer);
            if (self.pending_since[peer] == null) self.pending_since[peer] = context.now;
        }
    }

    fn flushPrunes(self: *Mesh, context: *const Context, topic: u16) void {
        var it = self.pending_prunes[topic].iterator(.{});
        while (it.next()) |index| {
            const peer: u16 = @intCast(index);
            if (!context.state.peers[peer].active) {
                self.clearPending(topic, peer);
                continue;
            }
            const logical = context.state.peers[peer].logical;
            const entry = context.peers.backoff(logical, topic);
            const remaining_ms = entry.until -| context.now;
            const backoff_ms = if (remaining_ms == 0) c.prune_backoff_ms else remaining_ms;
            const seconds = backoff_ms / 1000 + @intFromBool(backoff_ms % 1000 != 0);
            if (queue(context, topic, peer, seconds)) {
                if (remaining_ms == 0) context.peers.addBackoff(logical, topic, context.state.registry.rows[topic].generation, context.now, backoff_ms);
                entry.until = @max(entry.until, context.now +| (seconds *| 1000));
                self.clearPending(topic, peer);
            } else if (context.now -| self.pending_since[peer].? >= context.pressure_ms) self.retire.set(peer);
        }
    }

    fn clearPending(self: *Mesh, topic: u16, peer: u16) void {
        if (!self.pending_prunes[topic].isSet(peer)) return;
        self.pending_prunes[topic].unset(peer);
        assert(self.pending_count[peer] > 0);
        self.pending_count[peer] -= 1;
        if (self.pending_count[peer] == 0) self.pending_since[peer] = null;
    }

    pub fn expireActions(self: *Mesh, now: u64, timeout: u64) void {
        for (self.pending_since, 0..) |since, peer| {
            if (since) |started| if (now -| started >= timeout) {
                self.retire.set(peer);
            };
        }
    }

    pub fn forget(self: *Mesh, peer: u16) void {
        self.retire.unset(peer);
        for (&self.pending_prunes) |*set| set.unset(peer);
        self.pending_since[peer] = null;
        self.pending_count[peer] = 0;
        self.snapshot[peer] = .{};
    }

    pub fn onGraft(self: *Mesh, context: *const Context, topic: u16, peer: u16) void {
        const row = &context.state.peers[peer];
        const backoff = context.peers.backoff(row.logical, topic);
        const blocked = backoff.topic_generation == context.state.registry.rows[topic].generation and context.now < backoff.until;
        if (blocked) {
            context.scores.penalize(row.logical.index, 1);
            context.scores.penalties.graft_backoff +|= 1;
            if (context.now -| backoff.pruned_at < c.graft_flood_threshold_ms) {
                context.scores.penalize(row.logical.index, 1);
                context.scores.penalties.graft_backoff +|= 1;
            }
        }
        if (self.retire.isSet(peer) or self.pending_prunes[topic].isSet(peer)) return;
        if (!context.state.registry.subscribed(topic) or context.peers.rows[row.logical.index].direct or blocked or
            context.scores.score(row.logical.index, context.now) < 0 or
            (!context.state.registry.mesh(topic).isSet(peer) and context.state.registry.mesh(topic).count() >= c.mesh_d_high and !outbound(context, peer)))
        {
            self.prune(context, topic, peer, c.prune_backoff_ms);
            return;
        }
        if (context.state.registry.mesh(topic).isSet(peer)) return;
        context.state.registry.setSubscription(topic, peer, true);
        context.state.registry.mesh(topic).set(peer);
        context.scores.graft(row.logical.index, topic, context.now);
        logChange(context, topic, peer, "mesh_graft_received", 0);
    }

    pub fn onPrune(self: *Mesh, context: *const Context, topic: u16, peer: u16, backoff_ms: u64) void {
        _ = self;
        logChange(context, topic, peer, "mesh_prune_received", backoff_ms);
        context.state.registry.mesh(topic).unset(peer);
        context.scores.prune(context.state.peers[peer].logical.index, topic, context.now);
        context.peers.addBackoff(context.state.peers[peer].logical, topic, context.state.registry.rows[topic].generation, context.now, backoff_ms);
    }

    fn trim(self: *Mesh, context: *const Context, topic: u16) void {
        var ordered: [c.peers_cap]u16 = undefined;
        var count: usize = 0;
        var it = context.state.registry.mesh(topic).iterator(.{});
        while (it.next()) |peer| {
            ordered[count] = @intCast(peer);
            count += 1;
        }
        self.sort(context, ordered[0..count]);
        self.shuffle(ordered[c.mesh_d_score..count]);
        var survivors: Set = .initEmpty();
        for (ordered[0..c.mesh_d_score]) |peer| survivors.set(peer);
        var out = outboundCount(context, &survivors);
        for (ordered[c.mesh_d_score..count]) |peer| {
            if (out >= c.mesh_d_out) break;
            if (outbound(context, peer)) {
                survivors.set(peer);
                out += 1;
            }
        }
        for (ordered[c.mesh_d_score..count]) |peer| {
            if (survivors.count() >= c.mesh_d) break;
            survivors.set(peer);
        }
        for (ordered[0..count]) |peer| if (!survivors.isSet(peer)) self.prune(context, topic, peer, c.prune_backoff_ms);
        assert(context.state.registry.mesh(topic).count() == c.mesh_d);
    }

    fn sort(self: *const Mesh, context: *const Context, members: []u16) void {
        assert(members.len <= c.peers_cap);
        for (members, 0..) |peer, i| {
            var j = i;
            for (0..i) |_| {
                if (self.score(context, members[j - 1]) >= self.score(context, peer)) break;
                members[j] = members[j - 1];
                j -= 1;
                if (j == 0) break;
            }
            members[j] = peer;
        }
    }

    pub fn opportunistic(self: *Mesh, context: *const Context, topic: u16) void {
        const members = context.state.registry.mesh(topic);
        if (members.count() < c.mesh_d) return;
        var ordered: [c.peers_cap]u16 = undefined;
        var n: usize = 0;
        var it = members.iterator(.{});
        while (it.next()) |peer| {
            ordered[n] = @intCast(peer);
            n += 1;
        }
        self.sort(context, ordered[0..n]);
        const median = self.score(context, ordered[n / 2]);
        if (median >= context.scores.params.opportunistic_graft_threshold) return;
        n = self.candidates(context, topic, &ordered, true, 0);
        self.shuffle(ordered[0..n]);
        var added: usize = 0;
        for (ordered[0..n]) |peer| {
            if (added == c.opportunistic_graft_peers) break;
            if (self.score(context, peer) > median and self.graft(context, topic, peer)) added += 1;
        }
    }

    pub fn publicationRecipients(self: *Mesh, context: *const Context, topic: u16, flood: bool) Set {
        var result: Set = .initEmpty();
        const threshold = context.scores.params.publish_threshold;
        if (flood) {
            for (0..context.state.peers.len) |index| {
                if (self.eligible(context, topic, @intCast(index), threshold)) result.set(index);
            }
        } else {
            var it = context.state.registry.mesh(topic).iterator(.{});
            while (it.next()) |index| {
                if (self.eligible(context, topic, @intCast(index), threshold)) result.set(index);
            }
            if (result.count() == 0) {
                result = self.fanout(context, topic, true).*;
            } else self.fillPublication(context, topic, &result);
        }
        for (context.state.peers, 0..) |*row, index| {
            if (row.active and !self.retire.isSet(index) and context.peers.rows[row.logical.index].direct and context.state.registry.subscribers(topic).isSet(index)) result.set(index);
        }
        return result;
    }

    fn fillPublication(self: *Mesh, context: *const Context, topic: u16, members: *Set) void {
        if (members.count() >= c.mesh_d) return;
        var candidate_peers: [c.peers_cap]u16 = undefined;
        var count: usize = 0;
        for (0..context.state.peers.len) |index| {
            const peer: u16 = @intCast(index);
            if (members.isSet(peer) or context.state.peers[peer].outStream() == null) continue;
            if (!self.eligible(context, topic, peer, context.scores.params.publish_threshold)) continue;
            candidate_peers[count] = peer;
            count += 1;
        }
        self.shuffle(candidate_peers[0..count]);
        for (candidate_peers[0..count]) |peer| {
            if (members.count() >= c.mesh_d) break;
            members.set(peer);
        }
    }

    pub fn fanout(self: *Mesh, context: *const Context, topic: u16, publishing: bool) *Set {
        const row = &context.state.registry.rows[topic];
        if (!publishing and context.now -| row.fanout_last_ms >= c.fanout_ttl_ms) {
            row.fanout = .initEmpty();
            return &row.fanout;
        }
        if (publishing) row.fanout_last_ms = context.now;
        var it = row.fanout.iterator(.{});
        while (it.next()) |peer| if (!self.eligible(context, topic, @intCast(peer), context.scores.params.publish_threshold)) {
            row.fanout.unset(peer);
        };
        self.fillPublication(context, topic, &row.fanout);
        return &row.fanout;
    }

    pub fn gossipRecipients(self: *Mesh, context: *const Context, topic: u16, factor: f64) Set {
        assert(std.math.isFinite(factor) and factor >= 0 and factor <= 1);
        var candidates_buf: [c.peers_cap]u16 = undefined;
        const count = self.candidates(context, topic, &candidates_buf, false, context.scores.params.gossip_threshold);
        var n: usize = 0;
        for (candidates_buf[0..count]) |peer| {
            if (context.state.registry.fanout(topic).isSet(peer)) continue;
            candidates_buf[n] = peer;
            n += 1;
        }
        self.shuffle(candidates_buf[0..n]);
        const wanted = @min(n, @max(c.mesh_d_lazy, @as(usize, @intFromFloat(@ceil(factor * @as(f64, @floatFromInt(n)))))));
        var result: Set = .initEmpty();
        for (candidates_buf[0..wanted]) |peer| result.set(peer);
        return result;
    }
};

fn queue(context: *const Context, topic: u16, peer: u16, prune_s: ?u64) bool {
    var bytes: [32 + topic_mod.topic_max_len]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    const name = context.state.registry.topicString(topic);
    if (prune_s) |seconds| {
        writer.varint(protobuf.pruneRpcSize(name, seconds));
        protobuf.writePruneRpc(&writer, name, seconds);
    } else {
        writer.varint(protobuf.graftRpcSize(name));
        protobuf.writeGraftRpc(&writer, name);
    }
    return context.state.peers[peer].io.appendControl(writer.written(), true, if (prune_s != null) .prune else .graft, context.now) != null;
}

const Fixture = struct {
    g: @import("gossipsub.zig").Gossipsub,
    topic: u16,

    fn init(count: usize) !Fixture {
        var g = try @import("gossipsub.zig").Gossipsub.init(std.testing.allocator, .{ .random_seed = 17 });
        errdefer g.deinit();
        const name = "/eth2/01020304/beacon_block/ssz_snappy";
        assert(g.subscribe(name));
        const topic = g.state.registry.findTopic(name).?;
        for (0..count) |index| {
            const peer = @import("test_support.zig").addPeer(&g, .{ .index = @intCast(index), .generation = 1 }, .v1_2).?;
            g.state.registry.setSubscription(topic, peer.index, true);
        }
        return .{ .g = g, .topic = topic };
    }
    fn context(self: *Fixture, now: u64) Context {
        return .{ .state = self.g.state, .peers = &self.g.peers, .scores = &self.g.scores, .now = now, .heartbeat_ms = 700, .pressure_ms = 30_000, .use_snapshot = true };
    }
};

test "gossip policy mesh trimming preserves highest scores and outbound quota" {
    var f = try Fixture.init(16);
    defer f.g.deinit();
    for (0..16) |peer| {
        f.g.state.registry.mesh(f.topic).set(peer);
        f.g.scores.graft(@intCast(peer), f.topic, 1);
        if (peer < 4) try std.testing.expect(f.g.scores.setAppScore(@intCast(peer), 100));
    }
    f.g.peers.rows[f.g.state.peers[14].logical.index].direction = .outbound;
    f.g.peers.rows[f.g.state.peers[15].logical.index].direction = .outbound;
    const context = f.context(2);
    f.g.mesh_policy.takeSnapshot(&context);
    f.g.mesh_policy.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, c.mesh_d), f.g.state.registry.mesh(f.topic).count());
    for (0..4) |peer| try std.testing.expect(f.g.state.registry.mesh(f.topic).isSet(peer));
    try std.testing.expect(f.g.state.registry.mesh(f.topic).isSet(14));
    try std.testing.expect(f.g.state.registry.mesh(f.topic).isSet(15));
}

test "gossip policy outbound repair applies inside mesh degree limits" {
    var f = try Fixture.init(10);
    defer f.g.deinit();
    for (0..8) |peer| f.g.state.registry.mesh(f.topic).set(peer);
    f.g.peers.rows[f.g.state.peers[8].logical.index].direction = .outbound;
    f.g.peers.rows[f.g.state.peers[9].logical.index].direction = .outbound;
    const context = f.context(2);
    f.g.mesh_policy.takeSnapshot(&context);
    f.g.mesh_policy.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 10), f.g.state.registry.mesh(f.topic).count());
    try std.testing.expect(f.g.state.registry.mesh(f.topic).isSet(8));
    try std.testing.expect(f.g.state.registry.mesh(f.topic).isSet(9));
}

test "gossip policy mesh queue pressure preserves required action ownership" {
    var f = try Fixture.init(1);
    defer f.g.deinit();
    const context = f.context(2);
    const bytes = try std.testing.allocator.alloc(u8, f.g.options.critical_bytes);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 0);
    try std.testing.expect(f.g.state.peers[0].io.appendControl(bytes, true, null, 1) != null);
    f.g.mesh_policy.takeSnapshot(&context);
    f.g.mesh_policy.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 0), f.g.state.registry.mesh(f.topic).count());
    f.g.state.peers[0].io.resetTx(&f.g.messages.store);
    f.g.mesh_policy.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 1), f.g.state.registry.mesh(f.topic).count());
    f.g.state.peers[0].io.resetTx(&f.g.messages.store);
    try std.testing.expect(f.g.state.peers[0].io.appendControl(bytes, true, null, 2) != null);
    try std.testing.expect(f.g.scores.setAppScore(0, -1));
    f.g.mesh_policy.takeSnapshot(&context);
    f.g.mesh_policy.maintain(&context, f.topic);
    try std.testing.expectEqual(@as(usize, 0), f.g.state.registry.mesh(f.topic).count());
    try std.testing.expect(f.g.mesh_policy.pending_prunes[f.topic].isSet(0));
    f.g.mesh_policy.expireActions(30_002, 30_000);
    try std.testing.expect(f.g.mesh_policy.retire.isSet(0));
}

test "gossip policy adaptive gossip randomizes recipients and fanout expires" {
    var f = try Fixture.init(64);
    defer f.g.deinit();
    f.g.markDirect(f.g.state.peers[0].conn);
    try std.testing.expect(f.g.scores.setAppScore(1, -10_000));
    var context = f.context(2);
    f.g.mesh_policy.takeSnapshot(&context);
    const recipients = f.g.mesh_policy.gossipRecipients(&context, f.topic, 0.5);
    try std.testing.expectEqual(@as(usize, 31), recipients.count());
    try std.testing.expect(!recipients.isSet(0) and !recipients.isSet(1));
    var high_selected = false;
    for (32..64) |peer| if (recipients.isSet(peer)) {
        high_selected = true;
    };
    try std.testing.expect(high_selected);
    f.g.state.registry.setSubscribed(f.topic, false);
    for (f.g.state.peers) |*row| if (row.active) {
        row.outbound = .{ .live = .{ .conn = row.conn, .id = 2, .slot = 0 } };
    };
    const fanout = f.g.mesh_policy.fanout(&context, f.topic, true);
    try std.testing.expectEqual(@as(usize, c.mesh_d), fanout.count());
    try std.testing.expect(!fanout.isSet(0) and !fanout.isSet(1));
    context.now += c.fanout_ttl_ms;
    _ = f.g.mesh_policy.fanout(&context, f.topic, false);
    try std.testing.expectEqual(@as(usize, 0), fanout.count());
}

test "gossip policy review I2 pending PRUNE gates resubscription GRAFT until queue recovery" {
    var f = try Fixture.init(1);
    defer f.g.deinit();
    var context = f.context(1);
    f.g.mesh_policy.onGraft(&context, f.topic, 0);
    const bytes = try std.testing.allocator.alloc(u8, f.g.options.critical_bytes);
    defer std.testing.allocator.free(bytes);
    @memset(bytes, 0);
    try std.testing.expect(f.g.state.peers[0].io.appendControl(bytes, true, null, 1) != null);
    f.g.last_now_ms = 1;
    const name = f.g.state.registry.topicString(f.topic);
    try std.testing.expect(f.g.unsubscribe(name));
    try std.testing.expect(f.g.mesh_policy.pending_prunes[f.topic].isSet(0));
    context.now = 2;
    f.g.mesh_policy.onGraft(&context, f.topic, 0);
    try std.testing.expectEqual(@as(f64, 2), f.g.scores.behaviour[f.g.state.peers[0].logical.index]);
    try std.testing.expectEqual(@as(u64, 2), f.g.scores.penalties.graft_backoff);
    context.now = 11_001;
    f.g.last_now_ms = context.now;
    try std.testing.expect(f.g.subscribe(name));
    f.g.mesh_policy.onGraft(&context, f.topic, 0);
    try std.testing.expect(!f.g.state.registry.mesh(f.topic).isSet(0));
    try std.testing.expectEqual(@as(?u64, 1), f.g.mesh_policy.pending_since[0]);
    f.g.state.peers[0].io.resetTx(&f.g.messages.store);
    f.g.mesh_policy.takeSnapshot(&context);
    f.g.mesh_policy.maintain(&context, f.topic);
    try std.testing.expect(!f.g.state.registry.mesh(f.topic).isSet(0));
    try std.testing.expect(!f.g.mesh_policy.pending_prunes[f.topic].isSet(0));
    try std.testing.expectEqual(@as(?u64, null), f.g.mesh_policy.pending_since[0]);
    var expected: [32 + topic_mod.topic_max_len]u8 = undefined;
    var writer = protobuf.Writer.init(&expected);
    writer.varint(protobuf.pruneRpcSize(name, c.prune_backoff_ms / 1000));
    protobuf.writePruneRpc(&writer, name, c.prune_backoff_ms / 1000);
    const sent = f.g.state.peers[0].io.segment(&f.g.messages.store);
    try std.testing.expectEqualSlices(u8, writer.written(), sent);
    _ = f.g.state.peers[0].io.advance(&f.g.messages.store, sent.len);
    context.now = 71_002;
    f.g.mesh_policy.onGraft(&context, f.topic, 0);
    try std.testing.expect(f.g.state.registry.mesh(f.topic).isSet(0));
    f.g.mesh_policy.expireActions(context.now, 30_000);
    try std.testing.expect(!f.g.mesh_policy.retire.isSet(0));
    f.g.state.registry.mesh(f.topic).unset(0);
    f.g.scores.prune(f.g.state.peers[0].logical.index, f.topic, context.now);
    f.g.mesh_policy.retire.set(0);
    f.g.mesh_policy.onGraft(&context, f.topic, 0);
    try std.testing.expect(!f.g.state.registry.mesh(f.topic).isSet(0));
}

test "gossip policy delayed PRUNE preserves the effective remote backoff" {
    for ([_]u64{ 501, 2_001 }) |queued_at| {
        var f = try Fixture.init(1);
        defer f.g.deinit();
        var context = f.context(1);
        const logical = f.g.state.peers[0].logical;
        const bytes = try std.testing.allocator.alloc(u8, f.g.options.critical_bytes);
        defer std.testing.allocator.free(bytes);
        @memset(bytes, 0);
        try std.testing.expect(f.g.state.peers[0].io.appendControl(bytes, true, null, 1) != null);
        f.g.mesh_policy.prune(&context, f.topic, 0, 1_000);
        context.now = queued_at;
        f.g.mesh_policy.takeSnapshot(&context);
        f.g.mesh_policy.maintain(&context, f.topic);
        try std.testing.expect(f.g.mesh_policy.pending_prunes[f.topic].isSet(0));
        try std.testing.expectEqual(@as(u64, 1_001), f.g.peers.backoff(logical, f.topic).until);
        f.g.state.peers[0].io.resetTx(&f.g.messages.store);
        f.g.mesh_policy.maintain(&context, f.topic);
        try std.testing.expect(!f.g.mesh_policy.pending_prunes[f.topic].isSet(0));
        const expired = queued_at >= 1_001;
        const seconds: u64 = if (expired) c.prune_backoff_ms / 1000 else 1;
        const local_until = queued_at + seconds * 1000;
        try std.testing.expectEqual(local_until, f.g.peers.backoff(logical, f.topic).until);
        var expected: [32 + topic_mod.topic_max_len]u8 = undefined;
        var writer = protobuf.Writer.init(&expected);
        const name = f.g.state.registry.topicString(f.topic);
        writer.varint(protobuf.pruneRpcSize(name, seconds));
        protobuf.writePruneRpc(&writer, name, seconds);
        const sent = f.g.state.peers[0].io.segment(&f.g.messages.store);
        try std.testing.expectEqualSlices(u8, writer.written(), sent);
        _ = f.g.state.peers[0].io.advance(&f.g.messages.store, sent.len);
        context.now = queued_at + seconds * 1000 - 1;
        f.g.mesh_policy.maintain(&context, f.topic);
        try std.testing.expect(!f.g.state.registry.mesh(f.topic).isSet(0));
        context.now = local_until + c.backoff_slack_heartbeats * context.heartbeat_ms;
        f.g.mesh_policy.maintain(&context, f.topic);
        try std.testing.expect(f.g.state.registry.mesh(f.topic).isSet(0));
    }
}

test "gossip policy review I3 bounded shuffle consumes one draw per swap" {
    var f = try Fixture.init(3);
    defer f.g.deinit();
    const context = f.context(1);
    f.g.mesh_policy.takeSnapshot(&context);
    f.g.mesh_policy.rng = .{ .s = .{ 0, 1, 0, 0 } };
    var expected = f.g.mesh_policy.rng;
    for (0..2) |_| _ = expected.next();
    const recipients = f.g.mesh_policy.gossipRecipients(&context, f.topic, 1);
    try std.testing.expectEqual(@as(usize, 3), recipients.count());
    try std.testing.expectEqualSlices(u64, &expected.s, &f.g.mesh_policy.rng.s);
}

test "gossip policy review I3 shuffle budget holds at empty singleton and capacity" {
    var members: [c.peers_cap]u16 = undefined;
    for ([_]usize{ 0, 1, 3, c.peers_cap }) |len| {
        var mesh = Mesh.init(17);
        var expected = mesh.rng;
        for (0..len -| 1) |_| _ = expected.next();
        for (members[0..len], 0..) |*peer, i| peer.* = @intCast(i);
        mesh.shuffle(members[0..len]);
        try std.testing.expectEqualSlices(u64, &expected.s, &mesh.rng.s);
        var seen: Set = .initEmpty();
        for (members[0..len]) |peer| {
            try std.testing.expect(peer < len and !seen.isSet(peer));
            seen.set(peer);
        }
    }
    var mesh = Mesh.init(17);
    var ordered = [_]u16{ 0, 1, 2, 3, 4, 5, 6, 7 };
    mesh.shuffle(&ordered);
    try std.testing.expectEqualSlices(u16, &.{ 6, 7, 2, 0, 5, 1, 3, 4 }, &ordered);
}

fn maintainFastHeartbeat(g: *@import("gossipsub.zig").Gossipsub, topic: u16, now: u64) void {
    g.mesh_policy.maintain(&.{ .state = g.state, .peers = &g.peers, .scores = &g.scores, .now = now, .heartbeat_ms = 1, .pressure_ms = g.options.pressure_timeout_ms }, topic);
}

test "gossip policy final review positive remainder respects rounded remote PRUNE deadline" {
    var g = try @import("gossipsub.zig").Gossipsub.init(std.testing.allocator, .{ .random_seed = 17, .heartbeat_interval_ms = 1 });
    defer g.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    const topic = g.state.registry.findTopic(name).?;
    const peer = g.addPeer(.{ .index = 0, .generation = 1 }, .v1_2, &.{ .identity = .{ .bytes = [_]u8{1} ** 39 }, .address = .unspecified, .direction = .inbound }, .{ .mono_ms = 1, .unix_s = 0 }).admitted.index;
    g.state.registry.setSubscription(topic, peer, true);
    const logical = g.state.peers[peer].logical;
    const full = try std.testing.allocator.alloc(u8, g.options.critical_bytes);
    defer std.testing.allocator.free(full);
    @memset(full, 0);
    try std.testing.expect(g.state.peers[peer].io.appendControl(full, true, null, 1) != null);
    g.mesh_policy.prune(&.{ .state = g.state, .peers = &g.peers, .scores = &g.scores, .now = 1, .heartbeat_ms = 1, .pressure_ms = g.options.pressure_timeout_ms }, topic, peer, 1000);
    maintainFastHeartbeat(&g, topic, 1000);
    try std.testing.expect(g.mesh_policy.pending_prunes[topic].isSet(peer));
    try std.testing.expectEqual(@as(u64, 1001), g.peers.backoff(logical, topic).until);
    try std.testing.expectEqual(@as(?u64, 1), g.mesh_policy.pending_since[peer]);
    try std.testing.expectEqual(@as(u64, 1), g.peers.backoff(logical, topic).pruned_at);
    g.state.peers[peer].io.resetTx(&g.messages.store);
    maintainFastHeartbeat(&g, topic, 1000);
    try std.testing.expect(!g.mesh_policy.pending_prunes[topic].isSet(peer));
    var expected: [128]u8 = undefined;
    var writer = protobuf.Writer.init(&expected);
    writer.varint(protobuf.pruneRpcSize(name, 1));
    protobuf.writePruneRpc(&writer, name, 1);
    const sent = g.state.peers[peer].io.segment(&g.messages.store);
    try std.testing.expectEqualSlices(u8, writer.written(), sent);
    _ = g.state.peers[peer].io.advance(&g.messages.store, sent.len);
    maintainFastHeartbeat(&g, topic, 1003);
    try std.testing.expect(!g.state.registry.mesh(topic).isSet(peer));
    try std.testing.expectEqual(@as(u64, 2000), g.peers.backoff(logical, topic).until);
    try std.testing.expectEqual(@as(u64, 1), g.peers.backoff(logical, topic).pruned_at);
    maintainFastHeartbeat(&g, topic, 2001);
    try std.testing.expect(!g.state.registry.mesh(topic).isSet(peer));
    maintainFastHeartbeat(&g, topic, 2002);
    try std.testing.expect(g.state.registry.mesh(topic).isSet(peer));
}
