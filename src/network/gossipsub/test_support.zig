const std = @import("std");
const gossip = @import("gossipsub.zig");
const sessions = @import("sessions.zig");
const engine = @import("../quic/engine.zig");
const peers = @import("peer_book.zig");

pub fn addPeer(g: *gossip.Gossipsub, conn: engine.Handle, version: sessions.Version) ?sessions.SessionRef {
    var metadata: peers.Metadata = .{
        .identity = .{ .bytes = [_]u8{0} ** @import("../wire/peer_id.zig").length },
        .address = .unspecified,
        .direction = .inbound,
    };
    std.mem.writeInt(u64, metadata.identity.bytes[0..8], conn.generation, .little);
    std.mem.writeInt(u16, metadata.identity.bytes[8..10], conn.index, .little);
    const peer = switch (g.addPeer(conn, version, &metadata, .{ .mono_ms = g.last_now_ms, .unix_s = 0 })) {
        .admitted => |peer| peer,
        else => return null,
    };
    g.sessions.setOutbound(peer.index, .{ .live = .{ .conn = conn, .id = 2, .slot = 0 } });
    g.sendSubscriptions(peer.index);
    return peer;
}

pub fn driver(g: *gossip.Gossipsub) @import("session_driver.zig").Driver {
    return .{ .inner = g };
}

pub fn pump(g: *gossip.Gossipsub, transport: *engine.Engine, now: @import("../types.zig").Now, events: []gossip.Event) usize {
    return pumpTurn(g, transport, now, events).count;
}

pub fn pumpTurn(g: *gossip.Gossipsub, transport: *engine.Engine, now: @import("../types.zig").Now, events: []gossip.Event) @import("turn.zig").Turn {
    var router = @import("../router.zig").Router.init(std.testing.allocator, .{ .negotiations_max = 1, .reqresp = false }) catch @panic("test router allocation failed");
    defer router.deinit();
    const io = driver(g);
    var turn = g.beginPump(now, events);
    io.runTurn(&router, transport, &turn);
    return turn;
}

pub fn processRpc(g: *gossip.Gossipsub, index: u16, now: @import("../types.zig").Now, events: []gossip.Event, count: *usize, items: *usize) !bool {
    var turn = @import("turn.zig").Turn.init(&g.options, now, events, g.decompressed, g.msg_scratch);
    turn.count = count.*;
    var peer = @import("turn.zig").Credits.peer(&g.options);
    peer.items = items.*;
    const result = try driver(g).processRpc(index, &turn, &peer);
    count.* = turn.count;
    items.* = peer.items;
    return result == .done;
}

pub fn ageHistory(g: *gossip.Gossipsub) void {
    std.debug.assert(!g.cycle.isActive());
    g.cycle.epoch += 1;
    g.messages.history.age(&g.messages.store, g.cycle.epoch);
}
