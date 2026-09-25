const std = @import("std");
const network = @import("../network_core.zig");
const gossip = @import("../gossipsub/root.zig");
const peers = @import("peers.zig");
const scores = @import("scores.zig");
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
    scores: scores.Distribution = .{},
    mesh_clients: [std.meta.fields(client.Client).len]usize = @splat(0),
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
        var clients: peers.ConnectionClients = .{};
        for (owner.peer_manager.catalog.rows) |*row| {
            const conn = row.connection orelse continue;
            result.peer_count += 1;
            result.relevant += @intFromBool(row.status != null);
            const kind = client.fromIdentify(&row.identify);
            clients.put(conn, kind);
            result.population.observe(row, kind, now.mono_ms);
        }
        const g = owner.service.gossipsub;
        var mesh_peers = gossip.sessions.PeerSet.initEmpty();
        var meshes: [scores.kind_count]gossip.sessions.PeerSet = @splat(.initEmpty());
        var kinds: scores.TopicKinds = @splat(null);
        for (&g.overlay.rows, 0..) |*row, index| {
            if (!row.active) continue;
            mesh_peers.setUnion(row.mesh);
            const parsed = gossip.topic.parse(row.string[0..row.string_len]) orelse continue;
            const known = gossip.topic.Name.parse(parsed.name);
            const kind: u8 = if (known) |value| @intFromEnum(value.kind) else gossip.topic_policy.kind_count;
            kinds[index] = kind;
            meshes[kind].setUnion(row.mesh);
        }
        for (g.sessions.rows, 0..) |*row, index| {
            if (!row.active) continue;
            var details: gossip.score.Breakdown = undefined;
            const value = g.peers.snapshotWeights(row.logical, now.mono_ms, &details);
            result.scores.observe(value, &g.peers.scores.params);
            result.scores.observeWeights(&details, &kinds);
            for (&meshes, &result.scores.mesh_scores) |*mesh, *range| {
                if (mesh.isSet(index)) range.observe(value);
            }
            const kind = clients.get(row.conn);
            result.population.gossip_scores[@intFromEnum(kind)].observe(value);
            if (mesh_peers.isSet(index)) result.mesh_clients[@intFromEnum(kind)] += 1;
        }
        return result;
    }

    pub fn live(self: *const Context, value: anytype) @TypeOf(value) {
        return if (self.running) value else std.mem.zeroes(@TypeOf(value));
    }
};
