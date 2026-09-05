const std = @import("std");
const gossip = @import("gossipsub.zig");
const state = @import("state.zig");
const engine = @import("../quic/engine.zig");
const peers = @import("peers.zig");

pub fn addPeer(g: *gossip.Gossipsub, conn: engine.Handle, version: state.Version) ?state.PeerHandle {
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
