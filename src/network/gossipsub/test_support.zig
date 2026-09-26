const std = @import("std");
const gossip = @import("gossipsub.zig");
const sessions_mod = @import("sessions.zig");
const engine = @import("../quic/engine.zig");
const peers = @import("peer_book.zig");
const local_intent = @import("local_intent.zig");
const topic_policy = @import("topic_policy.zig");
const topic_fixture = @import("topic_fixture.zig");

/// A MessageSink that admits as the gossip processor does: it commits each feasible
/// candidate and copies the message, which stays readable until `clear`.
pub const Inbox = struct {
    pub const capacity = 64;
    sink: gossip.MessageSink = undefined,
    events: [capacity]@import("messages.zig").MessageEvent = undefined,
    count: usize = 0,
    /// Report no capacity, as a full processor does.
    full: bool = false,

    /// The inbox must not move while the owner holds the sink.
    pub fn attach(self: *Inbox, g: *gossip.Gossipsub) void {
        self.sink = .{ .context = self, .has_capacity = hasCapacity, .admit = admit };
        g.message_sink = &self.sink;
    }

    pub fn messages(self: *const Inbox) []const @import("messages.zig").MessageEvent {
        return self.events[0..self.count];
    }

    pub fn last(self: *const Inbox) @import("messages.zig").MessageEvent {
        std.debug.assert(self.count > 0);
        return self.events[self.count - 1];
    }

    pub fn clear(self: *Inbox) void {
        for (self.events[0..self.count]) |event| {
            std.testing.allocator.free(event.topic);
            std.testing.allocator.free(event.bytes);
        }
        self.count = 0;
    }

    pub fn deinit(self: *Inbox) void {
        self.clear();
    }

    fn hasCapacity(context: *anyopaque, _: @import("topic.zig").Kind, _: usize) bool {
        const self: *Inbox = @ptrCast(@alignCast(context));
        return !self.full and self.count < capacity;
    }

    fn admit(context: *anyopaque, candidate: *gossip.Admission) bool {
        const self: *Inbox = @ptrCast(@alignCast(context));
        if (self.full or self.count == capacity or !candidate.feasible(&.{})) return false;
        const topic = std.testing.allocator.dupe(u8, candidate.event.topic) catch return false;
        const bytes = std.testing.allocator.dupe(u8, candidate.event.bytes) catch {
            std.testing.allocator.free(topic);
            return false;
        };
        candidate.commit();
        self.events[self.count] = candidate.event;
        self.events[self.count].topic = topic;
        self.events[self.count].bytes = bytes;
        self.count += 1;
        return true;
    }
};

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

/// Invalid deliveries the score counters hold across peers and topics.
pub fn invalidDeliveries(g: *const gossip.Gossipsub) f64 {
    var total: f64 = 0;
    for (g.peers.scores.topics) |counters| total += counters.invalid;
    return total;
}

pub fn penalize(g: *gossip.Gossipsub, conn: engine.Handle, count: f64) void {
    const index = g.sessions.find(conn).?;
    g.peers.penalize(g.sessions.rows[index].logical, count);
}

/// Returns the messages delivered to the attached sink, as validations they left pending.
pub fn pump(g: *gossip.Gossipsub, transport: *engine.Engine, now: @import("../types.zig").Now) usize {
    const pending = g.messages.pendingValidations();
    _ = pumpTurn(g, transport, now);
    return g.messages.pendingValidations() - pending;
}

pub fn pumpTurn(g: *gossip.Gossipsub, transport: *engine.Engine, now: @import("../types.zig").Now) @import("turn.zig").Turn {
    var router = @import("../router.zig").Router.init(std.testing.allocator, .{ .negotiations_max = 1 }) catch @panic("test router allocation failed");
    defer router.deinit();
    var turn = @import("session_io.zig").beginPump(g, now);
    @import("session_io.zig").runTurn(g, &router, transport, &turn);
    return turn;
}

/// Now while a session is ready, else the earliest session deadline; heartbeat and
/// maintenance deadlines are left out.
pub fn sessionWakeup(g: *const gossip.Gossipsub, now: @import("../types.zig").Now) u64 {
    if (g.sessions.ready.len > 0) return now.mono_ms;
    const top = g.sessions.deadlines.peek() orelse return std.math.maxInt(u64);
    return @max(now.mono_ms, top.deadline);
}

pub fn processRpc(g: *gossip.Gossipsub, index: u16, now: @import("../types.zig").Now, count: *usize, items: *usize) !bool {
    var turn = @import("turn.zig").Turn.init(&g.options, now, g.msg_scratch);
    turn.sink = g.message_sink;
    var peer = @import("turn.zig").Credits.peer(&g.options);
    peer.items = items.*;
    const pending = g.messages.pendingValidations();
    const result = try @import("session_io.zig").processRpc(g, index, &turn, &peer);
    count.* += g.messages.pendingValidations() - pending;
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
const Now = @import("../types.zig").Now;
const protobuf = @import("protobuf.zig");
const Turn = @import("turn.zig").Turn;
const Credits = @import("turn.zig").Credits;
const snappy = @import("snappy");
/// Returns the messages delivered to the attached sink, as validations they left pending, or null
/// when the item needs more credits.
pub fn receiveMessage(g: *Gossipsub, index: u16, msg: protobuf.Message, now: Now) ?usize {
    var turn = Turn.init(&g.options, now, g.msg_scratch);
    turn.sink = g.message_sink;
    var peer = Credits.peer(&g.options);
    const pending = g.messages.pendingValidations();
    const result = g.receiveItem(g.sessions.ref(index), .{ .message = msg }, &turn, &peer);
    return if (result == .done) g.messages.pendingValidations() - pending else null;
}

pub fn message(g: *Gossipsub, peer: u16, text: []const u8, now_ms: u64) !?usize {
    const topic = "/eth2/01020304/beacon_block/ssz_snappy";
    var compressed: [256]u8 = undefined;
    const n = try snappy.raw.compress(text, &compressed);
    return receiveMessage(g, peer, .{ .data = compressed[0..n], .topic = topic }, .{ .mono_ms = now_ms, .unix_s = 1 });
}

pub fn control(g: *Gossipsub, index: u16, item: protobuf.Item, now: Now) void {
    var turn = Turn.init(&g.options, now, g.msg_scratch);
    var peer = Credits.peer(&g.options);
    std.debug.assert(g.receiveItem(g.sessions.ref(index), item, &turn, &peer) == .done);
}

pub fn heartbeat(g: *Gossipsub, now: Now) void {
    std.debug.assert(now.mono_ms > 0);
    g.heartbeat_at = now.mono_ms;
    g.tick(now);
}
