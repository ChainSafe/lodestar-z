const std = @import("std");
const gossip = @import("gossipsub.zig");
const Service = @import("service.zig").Service;
const engine = @import("../quic/engine.zig");
const support = @import("../test_support.zig");
const name = "/eth2/01020304/beacon_block/ssz_snappy";

const Simulation = struct {
    pair: support.Pair = .{},
    nodes: [2]Service = undefined,
    connections: [2]engine.Handle = undefined,
    rng: std.Random.DefaultPrng,
    received: [8]bool = @splat(false),
    pending: [8]?struct { handle: gossip.ValidationHandle, due: u64 } = @splat(null),
    host_ready: bool = true,
    polls: usize = 0,
    sleeps: usize = 0,

    fn init(self: *Simulation, seed: u64) !void {
        self.rng = .init(seed);
        try self.pair.init(.{}, .{});
        errdefer self.pair.deinit();
        var initialized: usize = 0;
        errdefer for (self.nodes[0..initialized]) |*node| node.deinit();
        for (&self.nodes, 0..) |*node, i| {
            node.* = try Service.init(std.testing.allocator, .{ .negotiations_max = 4, .gossipsub = .{
                .random_seed = seed + i,
                .connected_capacity = 2,
                .retained_capacity = 4,
                .retained_outbound_reserve = 1,
                .mcache_capacity = 16,
                .seen_capacity = 64,
                .validation_capacity = 8,
                .heartbeat_interval_ms = 100,
                .output_per_peer = 1 + self.rng.random().uintLessThan(usize, 17),
                .calls_per_peer = 3,
                .body_buffer_bytes = 64,
            } });
            initialized += 1;
            try std.testing.expect(node.handler.subscribe(name));
        }
        const connected = try support.connectPair(&self.pair);
        self.connections = .{ connected.client, connected.server };
        for (&self.nodes, 0..) |*node, i| {
            try std.testing.expectEqual(.admitted, node.handler.peerConnected(self.transport(i), self.connections[i], self.pair.now));
        }
    }

    fn deinit(self: *Simulation) void {
        for (&self.nodes, 0..) |*node, i| {
            node.handler.shutdown(&node.router, self.transport(i));
            node.deinit();
        }
        self.pair.deinit();
    }

    fn transport(self: *Simulation, i: usize) *engine.Engine {
        return if (i == 0) &self.pair.client else &self.pair.server;
    }

    fn capacity(self: *const Simulation, i: usize) usize {
        return if (i == 0 or self.host_ready) 16 else 0;
    }

    fn poll(self: *Simulation) !bool {
        try self.pair.pump();
        const now = self.pair.now;
        var work = false;
        for (&self.pending) |*entry| if (entry.*) |pending| {
            if (pending.due <= now.mono_ms) {
                try std.testing.expectEqualDeep(gossip.ReportOutcome{ .applied = .accept }, self.nodes[1].handler.report(pending.handle, .accept, now));
                entry.* = null;
                work = true;
            }
        };
        for (&self.nodes, 0..) |*node, i| {
            const quic = self.transport(i);
            var events: [16]engine.Event = undefined;
            var activity: [128]engine.Handle = undefined;
            const active = quic.driverView().takeActivity(&activity);
            const incoming = self.pair.events(quic, &events);
            const due = node.nextWakeup(now, self.capacity(i)) orelse std.math.maxInt(u64);
            if (active == 0 and incoming.len == 0 and due > now.mono_ms) continue;
            self.polls += 1;
            work = true;
            var output: [16]gossip.Event = undefined;
            const count = node.process(quic, incoming, activity[0..active], now, output[0..self.capacity(i)]);
            for (output[0..count]) |event| switch (event) {
                .subscription_change => {},
                .message => |message| {
                    try std.testing.expectEqual(@as(usize, 1), i);
                    try std.testing.expectEqual(@as(usize, 1), message.bytes.len);
                    const id = message.bytes[0];
                    try std.testing.expect(id < self.received.len and !self.received[id]);
                    self.received[id] = true;
                    self.pending[id] = .{ .handle = message.handle, .due = now.mono_ms + 100 + self.rng.random().uintLessThan(u64, 100) };
                },
            };
        }
        return work;
    }

    fn until(self: *Simulation, end: u64) !void {
        for (0..8192) |_| {
            if (try self.poll()) continue;
            if (self.pair.now.mono_ms == end) return;
            var next = end;
            for (&self.nodes, 0..) |*node, i| {
                if (node.nextWakeup(self.pair.now, self.capacity(i))) |due| next = @min(next, due);
                if (self.transport(i).driverView().nextTimeoutMs(self.pair.now)) |delay| next = @min(next, self.pair.now.mono_ms + delay);
            }
            for (self.pending) |entry| if (entry) |pending| {
                next = @min(next, pending.due);
            };
            try std.testing.expect(next > self.pair.now.mono_ms);
            self.pair.advance(next - self.pair.now.mono_ms);
            self.sleeps += 1;
        }
        return error.SchedulerDidNotQuiesce;
    }
};

test "gossip scheduler converges through pressure loss stream replacement and session reuse" {
    for ([_]u64{ 1, 7, 91, 800 }) |seed| {
        var sim: Simulation = .{ .rng = undefined };
        try sim.init(seed);
        defer sim.deinit();
        const start = sim.pair.now.mono_ms;
        try sim.until(start + 400);
        sim.host_ready = false;
        for (0..4) |id| {
            const published = try sim.nodes[0].handler.publish(name, &.{@intCast(id)}, sim.pair.now);
            try std.testing.expectEqual(@as(u16, 1), published.queued);
        }
        try sim.until(start + 600);
        for (sim.received) |received| try std.testing.expect(!received);
        sim.host_ready = true;
        sim.pair.drop_to_server = true;
        try sim.until(start + 800);
        const receiver = sim.nodes[1].handler.inner.sessions;
        const index = receiver.findPeer(sim.connections[1]).?;
        const old_stream = receiver.rows[index].in_stream.?;
        sim.pair.server.closeStream(old_stream, 0);
        try sim.until(start + 1000);
        sim.pair.drop_to_server = false;
        try std.testing.expect(sim.nodes[1].handler.unsubscribe(name));
        try sim.until(start + 1100);
        try std.testing.expect(sim.nodes[1].handler.subscribe(name));
        try sim.until(start + 2400);
        try std.testing.expect(!std.meta.eql(old_stream, receiver.rows[index].in_stream.?));
        for (sim.received[0..4]) |received| try std.testing.expect(received);

        const core = sim.nodes[0].handler.inner;
        const prior = core.sessions.ref(core.sessions.findPeer(sim.connections[0]).?);
        sim.nodes[0].handler.shutdown(&sim.nodes[0].router, &sim.pair.client);
        try std.testing.expectEqual(@as(usize, 0), core.resourceSnapshot().held_tx_retains);
        try std.testing.expectEqual(@as(usize, 0), core.resourceSnapshot().promises);
        try std.testing.expectEqual(.admitted, sim.nodes[0].handler.peerConnected(&sim.pair.client, sim.connections[0], sim.pair.now));
        try std.testing.expect(!core.sessions.matches(prior));
        const sent = core.rpc_metrics.sent_frames;
        core.writeCompleted(prior, .{ .control = .{ .token = 1, .kind = .iwant } }, sim.pair.now.mono_ms);
        try std.testing.expectEqual(sent, core.rpc_metrics.sent_frames);
        try sim.until(start + 3600);
        for (4..8) |id| {
            const published = try sim.nodes[0].handler.publish(name, &.{@intCast(id)}, sim.pair.now);
            try std.testing.expectEqual(@as(u16, 1), published.queued);
        }
        try sim.until(start + 4200);
        for (sim.received, sim.pending) |received, pending| {
            try std.testing.expect(received);
            try std.testing.expect(pending == null);
        }
        try std.testing.expect(sim.sleeps > 10 and sim.polls < 8192);
        try std.testing.expectEqual(@as(usize, 0), core.resourceSnapshot().held_tx_retains);
    }
}
