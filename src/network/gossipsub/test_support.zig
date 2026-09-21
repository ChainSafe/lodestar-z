const std = @import("std");
const gossip = @import("gossipsub.zig");
const sessions_mod = @import("sessions.zig");
const engine = @import("../quic/engine.zig");
const peers = @import("peer_book.zig");
const local_intent = @import("local_intent.zig");
const topic_policy = @import("topic_policy.zig");
const topic_fixture = @import("topic_fixture.zig");

pub fn init(allocator: std.mem.Allocator, options: gossip.Options) !gossip.Gossipsub {
    var configured = options;
    configured.topic_policy = options.topic_policy orelse &.{topic_fixture.bytes(.{ 1, 2, 3, 4 })};
    return gossip.Gossipsub.init(allocator, configured);
}

pub fn subscriptionUpdate(g: *const gossip.Gossipsub, name: ?[]const u8, subscribed: bool, out: *[topic_policy.boundary_max]local_intent.Boundary) ![]const local_intent.Boundary {
    var names: [@import("constants.zig").topics_cap][]const u8 = undefined;
    var count: usize = 0;
    for (&g.overlay.rows, 0..) |*row, index| {
        if (!row.active or !row.subscribed) continue;
        const current = g.overlay.topicString(@intCast(index));
        if (name) |changed| if (std.mem.eql(u8, current, changed)) continue;
        names[count] = current;
        count += 1;
    }
    if (name) |changed| if (subscribed) {
        if (count == names.len) return error.TopicCapacity;
        names[count] = changed;
        count += 1;
    };
    return topic_fixture.subscriptionsInto(names[0..count], out);
}

pub fn intern(g: *gossip.Gossipsub, name: []const u8) ?u16 {
    return g.overlay.internTopic(&g.overlayContext(g.last_now_ms), &g.messages.topicPins(), name);
}

pub fn subscribe(g: *gossip.Gossipsub, name: []const u8) !void {
    try setSubscription(g, name, true);
}

pub fn unsubscribe(g: *gossip.Gossipsub, name: []const u8) !void {
    try setSubscription(g, name, false);
}

fn setSubscription(g: *gossip.Gossipsub, name: []const u8, subscribed: bool) !void {
    var boundaries: [topic_policy.boundary_max]local_intent.Boundary = undefined;
    var workspace: local_intent.Workspace = .{};
    _ = try g.prepareSubscriptions(try subscriptionUpdate(g, name, subscribed, &boundaries), &workspace, .{ .mono_ms = g.last_now_ms, .unix_s = 0 }, g.overlay.slot);
    g.commitSubscriptions(&workspace);
}

pub fn addPeer(g: *gossip.Gossipsub, conn: engine.Handle, version: sessions_mod.Version) ?sessions_mod.SessionRef {
    var metadata: peers.Metadata = .{
        .identity = .{ .bytes = [_]u8{0} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    std.mem.writeInt(u64, metadata.identity.bytes[0..8], conn.generation, .little);
    std.mem.writeInt(u16, metadata.identity.bytes[8..10], conn.index, .little);
    const peer = switch (g.addPeer(conn, &metadata, .{ .mono_ms = g.last_now_ms, .unix_s = 0 })) {
        .admitted => |peer| peer,
        else => return null,
    };
    g.sessions.setOutbound(peer.index, .{ .live = .{ .stream = .{ .conn = conn, .id = 2, .slot = 0 }, .version = version } });
    g.sendSubscriptions(peer.index);
    return peer;
}

pub fn penalize(g: *gossip.Gossipsub, conn: engine.Handle, count: f64) void {
    const index = g.sessions.findPeer(conn).?;
    g.peers.penalize(g.sessions.rows[index].logical, count);
}

pub fn pump(g: *gossip.Gossipsub, transport: *engine.Engine, now: @import("../types.zig").Now, events: []gossip.Event) usize {
    return pumpTurn(g, transport, now, events).count;
}

pub fn pumpTurn(g: *gossip.Gossipsub, transport: *engine.Engine, now: @import("../types.zig").Now, events: []gossip.Event) @import("turn.zig").Turn {
    var router = @import("../router.zig").Router.init(std.testing.allocator, .{ .negotiations_max = 1, .reqresp = false }) catch @panic("test router allocation failed");
    defer router.deinit();
    var turn = @import("session_io.zig").beginPump(g, now, events);
    @import("session_io.zig").runTurn(g, &router, transport, &turn);
    return turn;
}

pub fn processRpc(g: *gossip.Gossipsub, index: u16, now: @import("../types.zig").Now, events: []gossip.Event, count: *usize, items: *usize) !bool {
    var turn = @import("turn.zig").Turn.init(&g.options, now, events, g.decompressed, g.msg_scratch);
    turn.count = count.*;
    var peer = @import("turn.zig").Credits.peer(&g.options);
    peer.items = items.*;
    const result = try @import("session_io.zig").processRpc(g, index, &turn, &peer);
    count.* = turn.count;
    items.* = peer.items;
    return result == .done;
}

pub fn ageHistory(g: *gossip.Gossipsub) void {
    std.debug.assert(!g.cycle.isActive());
    g.cycle.epoch += 1;
    g.messages.history.age(&g.messages.store, g.cycle.epoch);
}

pub fn sessions(a: std.mem.Allocator, capacity: u16) !sessions_mod.Sessions {
    const options: @import("options.zig").Options = .{ .connected_capacity = capacity };
    return sessions_mod.Sessions.init(a, &options, &@import("layout.zig").Layout.init(&options));
}

const Gossipsub = gossip.Gossipsub;
const Event = gossip.Event;
const Now = @import("../types.zig").Now;
const protobuf = @import("protobuf.zig");
const Turn = @import("turn.zig").Turn;
const Credits = @import("turn.zig").Credits;
const snappy = @import("snappy");
pub fn receiveMessage(g: *Gossipsub, index: u16, msg: protobuf.Message, now: Now, events: []Event, start: usize) ?usize {
    var turn = Turn.init(&g.options, now, events, g.decompressed, g.msg_scratch);
    turn.count = start;
    if (events.len == 0) turn.used = turn.arena.len;
    var peer = Credits.peer(&g.options);
    const result = g.receiveItem(g.sessions.ref(index), .{ .message = msg }, &turn, &peer);
    switch (result) {
        .events => g.pressure(index, .events, now.mono_ms),
        .done, .credits => {},
    }
    return if (result == .done) turn.count else null;
}

pub fn message(g: *Gossipsub, peer: u16, text: []const u8, now_ms: u64, events: []Event) !?usize {
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    var compressed: [256]u8 = undefined;
    const n = try snappy.raw.compress(text, &compressed);
    return receiveMessage(g, peer, .{ .data = compressed[0..n], .topic = topic }, .{ .mono_ms = now_ms, .unix_s = 1 }, events, 0);
}

pub fn control(g: *Gossipsub, index: u16, item: protobuf.Item, now: Now) void {
    var turn = Turn.init(&g.options, now, &.{}, g.decompressed, g.msg_scratch);
    var peer = Credits.peer(&g.options);
    std.debug.assert(g.receiveItem(g.sessions.ref(index), item, &turn, &peer) == .done);
}

pub fn heartbeat(g: *Gossipsub, now: Now) void {
    std.debug.assert(now.mono_ms > 0);
    g.heartbeat_at = now.mono_ms;
    g.tick(now);
}
