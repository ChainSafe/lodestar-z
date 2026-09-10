const std = @import("std");
const c = @import("constants.zig");
const score = @import("score.zig");
const topic = @import("topic.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const Gossipsub = @import("gossipsub.zig").Gossipsub;
pub const peers_per_page = 8;

pub const Topic = struct {
    index: u16,
    name: [topic.topic_max_len]u8,
    len: u8,
    subscribed: bool,
    weight: f64,
    mesh_activation_ms: u64,
};
pub const TopicScore = struct {
    index: u16,
    counters: score.TopicCounters,
    weights: score.TopicWeights,
    mesh_member: bool,
};
pub const Peer = struct {
    identity: PeerId,
    connected: bool,
    outbound_ready: bool,
    address: [16]u8,
    retain_until: u64,
    score: f64,
    app_score: f64,
    behaviour: f64,
    weights: score.GlobalWeights,
    topics: [c.topics_cap]TopicScore = undefined,
    topic_count: u16 = 0,
};
pub const Page = struct {
    mono_ms: u64 = 0,
    unix_s: i64 = 0,
    next: ?u16 = null,
    peers: [peers_per_page]Peer = undefined,
    peer_count: u8 = 0,
    topics: [c.topics_cap]Topic = undefined,
    topic_count: u16 = 0,
};

pub fn capture(g: *const Gossipsub, cursor: u16, now: @import("../types.zig").Now, out: *Page) error{InvalidDiagnosticsCursor}!void {
    if (cursor > g.peers.rows.len) return error.InvalidDiagnosticsCursor;
    out.mono_ms = now.mono_ms;
    out.unix_s = now.unix_s;
    out.next = null;
    out.peer_count = 0;
    out.topic_count = 0;
    for (&g.overlay.rows, 0..) |*row, i| {
        if (!row.active) continue;
        const params = &g.scores.topic_params[i];
        const target = &out.topics[out.topic_count];
        target.* = .{ .index = @intCast(i), .name = undefined, .len = row.string_len, .subscribed = row.subscribed, .weight = params.weight, .mesh_activation_ms = params.mesh_delivery_activation_ms };
        @memcpy(target.name[0..target.len], row.string[0..row.string_len]);
        out.topic_count += 1;
    }
    var position: usize = cursor;
    for (0..g.peers.rows.len - cursor) |_| {
        if (out.peer_count == peers_per_page) break;
        const index = position;
        position += 1;
        const row = &g.peers.rows[index];
        if (!row.occupied) continue;
        const session = if (row.connection) |conn| g.state.findPeer(conn) else null;
        var weights: score.Breakdown = undefined;
        const total = g.scores.snapshotWeights(@intCast(index), now.mono_ms, &weights);
        const peer = &out.peers[out.peer_count];
        peer.* = .{ .identity = row.identity, .connected = row.connection != null, .outbound_ready = if (session) |i| g.state.peers[i].outStream() != null else false, .address = row.address, .retain_until = row.retain_until, .score = total, .app_score = g.scores.app_score[index], .behaviour = g.scores.behaviour[index], .weights = weights.global };
        for (out.topics[0..out.topic_count]) |*known| {
            const counters = &g.scores.topics[index * c.topics_cap + known.index];
            const member = if (session) |i| g.overlay.rows[known.index].mesh.isSet(i) else false;
            if (!member and !counters.in_mesh and counters.first_deliveries == 0 and counters.mesh_deliveries == 0 and counters.mesh_failures == 0 and counters.invalid == 0) continue;
            peer.topics[peer.topic_count] = .{ .index = known.index, .counters = counters.*, .weights = weights.topics[known.index], .mesh_member = member };
            peer.topic_count += 1;
        }
        out.peer_count += 1;
    }
    if (position < g.peers.rows.len) out.next = @intCast(position);
}

test "gossip diagnostic pages bound peers preserve scores and include empty meshes" {
    const a = std.testing.allocator;
    var g = try Gossipsub.init(a, .{ .random_seed = 1, .connected_capacity = 10, .retained_capacity = 16, .retained_outbound_reserve = 1 });
    defer g.deinit();
    const name = "/eth2/01020304/beacon_block/ssz_snappy";
    try std.testing.expect(g.subscribe(name));
    const t = g.overlay.findTopic(name).?;
    for (0..10) |i| {
        const peer = @import("test_support.zig").addPeer(&g, .{ .index = @intCast(i), .generation = 1 }, .v1_2).?;
        g.scores.invalid(g.state.peers[peer.index].logical.index, t);
    }
    const page = try a.create(Page);
    defer a.destroy(page);
    const calls = g.scores.calls;
    const revision = g.scores.revision;
    const dirty = g.scores.dirty;
    try capture(&g, 0, .{ .mono_ms = 200, .unix_s = 1000 }, page);
    try std.testing.expectEqual(@as(u8, 8), page.peer_count);
    try std.testing.expectEqual(@as(?u16, 8), page.next);
    try std.testing.expectEqual(@as(u16, 1), page.topic_count);
    try std.testing.expect(page.topics[0].subscribed);
    try std.testing.expect(!page.peers[0].topics[0].mesh_member);
    try std.testing.expectEqual(@as(f64, 1), page.peers[0].topics[0].counters.invalid);
    try std.testing.expectEqual(g.scores.snapshot(0, 200), page.peers[0].score);
    try capture(&g, page.next.?, .{ .mono_ms = 200, .unix_s = 1000 }, page);
    try std.testing.expectEqual(@as(u8, 2), page.peer_count);
    try std.testing.expectEqual(@as(?u16, null), page.next);
    try std.testing.expectEqual(calls, g.scores.calls);
    try std.testing.expectEqual(revision, g.scores.revision);
    try std.testing.expectEqualSlices(bool, &dirty, &g.scores.dirty);
    try std.testing.expectError(error.InvalidDiagnosticsCursor, capture(&g, 17, .{ .mono_ms = 200, .unix_s = 1000 }, page));
}
