const std = @import("std");
const Now = @import("../types.zig").Now;
const t = std.testing;
const messages = @import("messages.zig");
const Gossipsub = @import("Gossipsub.zig");
const support = @import("test_support.zig");
const topic = @import("topic.zig");
const constants = @import("constants.zig");
const topic_policy = @import("topic_policy.zig");
const snappy = @import("snappy");
const validation = @import("validation.zig");
const turn_mod = @import("turn.zig");

test "message admission retains canonical topic bounds" {
    const Sink = struct {
        canonical: ?topic.Canonical = null,
        maximum: usize = 0,
        source_maximum: usize = 0,
        handle: Gossipsub.ValidationHandle = undefined,
        id: Gossipsub.MessageId = undefined,

        fn hasCapacity(_: *anyopaque, _: topic.Kind, _: usize) bool {
            return true;
        }

        fn admit(context: *anyopaque, candidate: *Gossipsub.MessageAdmission) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.canonical = candidate.canonical;
            self.maximum = candidate.maximum_compressed;
            self.source_maximum = candidate.sourceUsage().maximum_bytes;
            if (!candidate.feasible(&candidate.usage(&.{}))) return false;
            candidate.commit();
            self.handle = candidate.event.handle;
            self.id = candidate.event.id;
            return true;
        }
    };
    {
        const name = "/eth2/01020304/beacon_block/ssz_snappy";
        var boundary: topic_policy.Boundary = .{ .digest = .{ 1, 2, 3, 4 } };
        boundary.rules[0] = .{ .count = 1, .ssz_min = 4, .ssz_max = 6000 };
        var options: Gossipsub.Options = .{ .random_seed = 1, .connected_capacity = 2, .retained_capacity = 4, .retained_outbound_reserve = 1, .seen_capacity = 16, .mcache_capacity = 16, .validation_capacity = 8 };
        options.topic_policy = &.{boundary};
        var g = try Gossipsub.init(t.allocator, options);
        defer g.deinit();
        const peer = support.addPeer(&g, .{ .index = 0, .generation = 1 }, .v1_2).?;
        const index = support.activate(&g, name).?;
        g.overlay.rows[index].subscribed = true;
        const context: messages.Context = .{ .overlay = g.overlay, .peers = &g.peers, .options = &g.options, .epoch = g.cycle.epoch };
        const source: messages.Source = .{ .peer = g.sessions.rows[peer.index].logical, .session = peer, .connection = g.sessions.rows[peer.index].conn };
        var sink: Sink = .{};
        const callback: messages.MessageSink = .{ .context = &sink, .has_capacity = Sink.hasCapacity, .admit = Sink.admit };
        var turn = Gossipsub.beginPump(&g, Now.fromMilliseconds(.{ .mono_ms = 1, .unix_s = 0 }));
        turn.sink = &callback;
        var credits = turn_mod.Credits.peer(&g.options);
        const workspace = turn.workspace(&credits);
        var compressed: [64]u8 = undefined;
        const len = try snappy.raw.compress("data", &compressed);
        const received = g.messages.receive(&context, &workspace, &source, .{ .topic = name, .data = compressed[0..len] }, 1);
        try t.expect(received == .admitted);
        try t.expectEqual(index, received.admitted.topic_index);
        try t.expectEqual(sink.id, received.admitted.id);
        try t.expectEqual(true, sink.canonical != null);
        if (sink.canonical) |canonical| try t.expectEqual(topic.Kind.beacon_block, canonical.name.kind);
        const maximum = constants.maxCompressedLen(6000);
        try t.expectEqual(maximum, sink.maximum);
        try t.expectEqual(validation.Validation.chargedBytes(maximum), sink.source_maximum);
        try t.expectEqual(Gossipsub.ReportOutcome{ .applied = .ignore }, g.report(sink.handle, .ignore, Now.fromMilliseconds(.{ .mono_ms = 2, .unix_s = 0 })));
    }
}
