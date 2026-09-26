const std = @import("std");
const network = @import("../network_core.zig");
const peers = @import("peers.zig");
const client = @import("../peers/client.zig");

/// Borrowed only on the network owner while it is not advancing protocol state.
pub const Context = struct {
    owner: *const network.NetworkCore,
    now: @import("../types.zig").Now,
    running: bool,
    expired_executing: usize = 0,
    oldest_expired_execution_age_ms: u64 = 0,
    /// The host's bridge measurements, copied under its runtime mutex. Null renders zeros.
    bridge: ?*const @import("bridge.zig").Snapshot = null,
    population: peers.Distribution = .{},
    peer_count: usize = 0,
    relevant: usize = 0,
    /// Kernel drop totals per family of the QUIC and discovery UDP sockets. Reading them extends
    /// each socket's 32-bit kernel count, so `init` takes the owner mutably.
    socket_drops: [2][2]?u64 = @splat(@splat(null)),

    pub fn init(owner: *network.NetworkCore, now: @import("../types.zig").Now, running: bool) Context {
        var result: Context = .{ .owner = owner, .now = now, .running = running };
        result.socket_drops[0] = owner.transport.udp.sockets.drops();
        if (owner.discovery) |discovery| result.socket_drops[1] = discovery.transport.sockets.drops();
        if (!running) return result;
        for (owner.peer_manager.catalog.rows) |*row| {
            if (row.connection == null) continue;
            result.peer_count += 1;
            result.relevant += @intFromBool(row.status != null);
            result.population.observe(row, client.fromIdentify(&row.identify), now.mono_ms);
        }
        return result;
    }

    pub fn live(self: *const Context, value: anytype) @TypeOf(value) {
        return if (self.running) value else std.mem.zeroes(@TypeOf(value));
    }
};
