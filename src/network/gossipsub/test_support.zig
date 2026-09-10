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
    return switch (g.addPeer(conn, version, &metadata, .{ .mono_ms = g.last_now_ms, .unix_s = 0 })) {
        .admitted => |peer| peer,
        else => null,
    };
}

pub fn driver(g: *gossip.Gossipsub) @import("session_driver.zig").Driver {
    return .{ .inner = g };
}

pub fn pump(g: *gossip.Gossipsub, transport: *engine.Engine, now: @import("../types.zig").Now, events: []gossip.Event) usize {
    var router = @import("../router.zig").Router.init(std.testing.allocator, .{ .negotiations_max = 1, .reqresp = false }) catch @panic("test router allocation failed");
    defer router.deinit();
    const io = driver(g);
    return io.pumpReady(&router, transport, now, events);
}
