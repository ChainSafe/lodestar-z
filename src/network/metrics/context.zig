const std = @import("std");
const network = @import("../network_core.zig");
const Population = @import("../peers/population.zig").Population;

/// Borrowed only on the network owner while it is not advancing protocol state.
pub const Context = struct {
    owner: *const network.NetworkCore,
    now: @import("../types.zig").Now,
    running: bool,
    expired_executing: usize = 0,
    /// The host's bridge measurements, copied under its runtime mutex. Null renders zeros.
    bridge: ?*const @import("bridge.zig").Snapshot = null,
    population: Population = .{},
    /// Kernel drop totals per family of the QUIC and discovery UDP sockets. Reading them extends
    /// each socket's 32-bit kernel count, so `init` takes the owner mutably.
    socket_drops: [2][2]?u64 = @splat(@splat(null)),

    pub fn init(owner: *network.NetworkCore, now: @import("../types.zig").Now, running: bool) Context {
        var result: Context = .{ .owner = owner, .now = now, .running = running };
        result.socket_drops[0] = owner.transport.sockets.drops();
        if (owner.discovery) |discovery| result.socket_drops[1] = discovery.transport.sockets.drops();
        if (!running) return result;
        result.population = .collect(&owner.peer_manager.catalog, now.mono_ms);
        return result;
    }

    pub fn live(self: *const Context, value: anytype) @TypeOf(value) {
        return if (self.running) value else std.mem.zeroes(@TypeOf(value));
    }
};
