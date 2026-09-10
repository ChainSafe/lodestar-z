const std = @import("std");
const gossip = @import("gossipsub.zig");
const Driver = @import("session_driver.zig").Driver;
const SessionRef = @import("sessions.zig").SessionRef;
const Now = @import("../types.zig").Now;
const name = "/eth2/01020304/beacon_block/ssz_snappy";

const Node = struct {
    core: gossip.Gossipsub,
    session: SessionRef,
    received: [8]bool = @splat(false),
    pending: [8]?struct { handle: gossip.ValidationHandle, due: u64 } = @splat(null),

    fn init(identity: u8, seed: u64) !Node {
        var core = try gossip.Gossipsub.init(std.testing.allocator, .{
            .random_seed = seed,
            .connected_capacity = 2,
            .retained_capacity = 4,
            .retained_outbound_reserve = 1,
            .mcache_capacity = 16,
            .seen_capacity = 64,
            .validation_capacity = 8,
            .heartbeat_interval_ms = 100,
        });
        errdefer core.deinit();
        try std.testing.expect(core.subscribe(name));
        const session = core.addPeer(.{ .index = 0, .generation = 1 }, .v1_2, &.{
            .identity = .{ .bytes = @splat(identity) },
            .address = .unspecified,
            .direction = .outbound,
        }, .{ .mono_ms = 0, .unix_s = 0 }).admitted;
        core.sessions.setStreams(session.index, .{ .conn = .{ .index = 0, .generation = 1 }, .id = 0, .slot = 0 }, .{ .conn = .{ .index = 0, .generation = 1 }, .id = 1, .slot = 1 });
        return .{ .core = core, .session = session };
    }

    fn begin(self: *Node, now: Now) !void {
        for (&self.pending) |*pending| if (pending.*) |validation| {
            if (now.mono_ms >= validation.due) {
                try std.testing.expectEqualDeep(gossip.ReportOutcome{ .applied = .accept }, self.core.report(validation.handle, .accept, now));
                pending.* = null;
            }
        };
        self.core.beginPump(now);
        self.core.tick(now);
        self.core.sessions.rows[self.session.index].io.decompressed_pump = 0;
        self.core.sessions.rows[self.session.index].io.fields_pump = 0;
    }

    fn receive(self: *Node, now: Now, host_available: bool) !void {
        const io = &self.core.sessions.rows[self.session.index].io;
        if (io.rpc == null) return;
        var events: [16]gossip.Event = undefined;
        var count: usize = 0;
        var items: usize = self.core.options.items_per_peer;
        const driver: Driver = .{ .inner = &self.core };
        const done = try driver.processRpc(self.session.index, now, events[0..if (host_available) events.len else 0], &count, &items);
        for (events[0..count]) |event| switch (event) {
            .message => |message| {
                try std.testing.expectEqual(@as(usize, 1), message.bytes.len);
                const id = message.bytes[0];
                try std.testing.expect(id < self.received.len and !self.received[id]);
                self.received[id] = true;
                self.pending[id] = .{ .handle = message.handle, .due = now.mono_ms + 100 };
            },
            .subscription_change => {},
        };
        if (done) {
            io.rpc = null;
            io.frame_since = null;
            io.pressure_since = null;
            if (self.core.sessions.releaseFrame(io)) self.core.wakeStorage();
        }
    }

    fn transfer(source: *Node, target: *Node, now: Now, bytes: usize) !void {
        const tx = &source.core.sessions.rows[source.session.index].io;
        const rx = &target.core.sessions.rows[target.session.index].io;
        if (rx.rpc != null) return;
        source.core.queueSubscriptions(tx);
        const segment = tx.segment(&source.core.messages.store);
        if (segment.len == 0) return;
        const take = @min(bytes, segment.len, rx.unread.len);
        @memcpy(rx.unread[0..take], segment[0..take]);
        rx.unread_start = 0;
        rx.unread_end = take;
        const body = target.core.sessions.frameBody(rx) orelse return error.TestUnexpectedResult;
        const result = try rx.feedUnread(body, take, now.mono_ms);
        try std.testing.expectEqual(take, result.consumed);
        if (tx.advance(&source.core.messages.store, take)) |completion| source.core.writeCompleted(source.session, completion, now.mono_ms);
        rx.unread_start = 0;
        rx.unread_end = 0;
    }
};

test "gossip simulation converges after partial writes and host validation pressure" {
    for ([_]u64{ 1, 7, 91, 800 }) |seed| {
        var a = try Node.init(2, seed);
        defer a.core.deinit();
        var b = try Node.init(1, seed + 1);
        defer b.core.deinit();
        var rng = std.Random.DefaultPrng.init(seed);
        for (0..1024) |step| {
            const now: Now = .{ .mono_ms = step * 5, .unix_s = 0 };
            try a.begin(now);
            try b.begin(now);
            if (step == 128) {
                try std.testing.expectEqual(@as(usize, 1), a.core.overlay.mesh(a.core.overlay.findTopic(name).?).count());
                try std.testing.expectEqual(@as(usize, 1), b.core.overlay.mesh(b.core.overlay.findTopic(name).?).count());
                for (0..8) |id| {
                    const outcome = try a.core.publish(name, &.{@intCast(id)}, now);
                    try std.testing.expectEqual(@as(u16, 1), outcome.queued);
                }
            }
            try a.receive(now, true);
            try b.receive(now, step < 128 or step >= 256);
            if (step % 7 != 0) try Node.transfer(&a, &b, now, 1 + rng.random().uintLessThan(usize, 17));
            if (step % 11 != 0) try Node.transfer(&b, &a, now, 1 + rng.random().uintLessThan(usize, 13));
            a.core.finishPump(now);
            b.core.finishPump(now);
            if (step == 255) {
                for (b.received) |received| try std.testing.expect(!received);
                try std.testing.expect(a.core.resourceSnapshot().held_tx_retains > 0);
            }
        }
        for (b.received, b.pending) |received, pending| {
            try std.testing.expect(received);
            try std.testing.expect(pending == null);
        }
        try std.testing.expectEqual(@as(usize, 0), a.core.resourceSnapshot().held_tx_retains);
        try std.testing.expectEqual(@as(usize, 0), b.core.resourceSnapshot().pending_validations);
        try std.testing.expectEqual(@as(u64, 8), a.core.rpc_metrics.sent_items[@intFromEnum(@as(std.meta.Tag(@import("protobuf.zig").Item), .message))]);
    }
}

test "gossip simulation ignores decoded items and write receipts from a retired session" {
    var node = try Node.init(2, 1);
    defer node.core.deinit();
    const old = node.session;
    node.core.connectionClosed(node.core.sessions.rows[old.index].conn);
    node.session = node.core.addPeer(.{ .index = 0, .generation = 2 }, .v1_2, &.{ .identity = .{ .bytes = @splat(2) }, .address = .unspecified, .direction = .outbound }, .{ .mono_ms = 1, .unix_s = 0 }).admitted;
    try std.testing.expect(old.generation != node.session.generation);
    var count: usize = 0;
    const now: Now = .{ .mono_ms = 2, .unix_s = 0 };
    try node.begin(now);
    try std.testing.expect(node.core.receiveItem(old, .{ .subscription = .{ .topic = name, .subscribe = true } }, now, &.{}, &count));
    node.core.writeCompleted(old, .{ .control = .{ .token = 1, .kind = .iwant } }, now.mono_ms);
    try std.testing.expectEqual(@as(usize, 0), node.core.resourceSnapshot().remote_subscriptions);
    try std.testing.expectEqual(@as(u64, 0), node.core.rpc_metrics.sent_frames);
}
