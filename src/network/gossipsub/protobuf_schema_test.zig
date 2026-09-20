const std = @import("std");
const schema = @import("protobuf_schema.zig");
const pb = @import("protobuf.zig");
const wire = @import("../wire/protobuf.zig");
const constants = @import("constants.zig");
const receive = @import("receive_pool.zig");
const topic = @import("topic.zig");

test "gossip protobuf schema rejects ambiguous unsupported and malformed fields" {
    const Case = struct { shape: schema.Shape, bytes: []const u8, err: schema.Error };
    const cases = [_]Case{
        .{ .shape = .rpc, .bytes = &.{ 0, 0 }, .err = error.InvalidField },
        .{ .shape = .rpc, .bytes = &.{ 0x0b, 0x0c }, .err = error.BadWireType },
        .{ .shape = .rpc, .bytes = &.{ 0x20, 0 }, .err = error.UnsupportedField },
        .{ .shape = .rpc, .bytes = &.{ 0x08, 0 }, .err = error.BadWireType },
        .{ .shape = .rpc, .bytes = &.{ 0x1a, 0, 0x1a, 0 }, .err = error.DuplicateField },
        .{ .shape = .rpc, .bytes = &.{ 0x9a, 0, 0 }, .err = error.NonCanonical },
        .{ .shape = .rpc, .bytes = &.{ 0x1a, 0x80, 0 }, .err = error.NonCanonical },
        .{ .shape = .rpc, .bytes = &.{ 0x1a, 2, 0x32, 0 }, .err = error.UnsupportedField },
        .{ .shape = .subscription, .bytes = &.{ 8, 2, 18, 1, 't' }, .err = error.InvalidBoolean },
        .{ .shape = .subscription, .bytes = &.{ 8, 1, 8, 0, 18, 1, 't' }, .err = error.DuplicateField },
        .{ .shape = .subscription, .bytes = &.{ 18, 1, 't', 18, 1, 'u' }, .err = error.DuplicateField },
        .{ .shape = .subscription, .bytes = &.{ 18, 1, 0xff }, .err = error.InvalidUtf8 },
        .{ .shape = .subscription, .bytes = &.{ 18, 0 }, .err = error.LengthLimit },
        .{ .shape = .subscription, .bytes = &.{8}, .err = error.Truncated },
        .{ .shape = .subscription, .bytes = &.{ 8, 1 }, .err = error.MissingField },
        .{ .shape = .message, .bytes = &.{ 18, 0, 34, 1, 't', 18, 0 }, .err = error.DuplicateField },
        .{ .shape = .message, .bytes = &.{ 10, 0 }, .err = error.UnsupportedField },
        .{ .shape = .message, .bytes = &.{ 26, 0 }, .err = error.UnsupportedField },
        .{ .shape = .message, .bytes = &.{ 42, 0 }, .err = error.UnsupportedField },
        .{ .shape = .message, .bytes = &.{ 50, 0 }, .err = error.UnsupportedField },
        .{ .shape = .message, .bytes = &.{ 34, 1, 't' }, .err = error.MissingField },
        .{ .shape = .ihave, .bytes = &.{ 10, 1, 't', 18, 0 }, .err = error.LengthLimit },
        .{ .shape = .iwant, .bytes = &.{ 10, 21 }, .err = error.LengthLimit },
        .{ .shape = .idontwant, .bytes = &.{ 8, 1 }, .err = error.BadWireType },
        .{ .shape = .graft, .bytes = &.{ 10, 1, 't', 8, 1 }, .err = error.BadWireType },
        .{ .shape = .prune, .bytes = &.{ 10, 1, 't', 18, 0 }, .err = error.UnsupportedField },
        .{ .shape = .prune, .bytes = &.{ 10, 1, 't', 24, 1, 24, 2 }, .err = error.DuplicateField },
    };
    for (cases) |case| {
        try std.testing.expectError(case.err, schema.validate(case.shape, case.bytes));
        try paged(case.shape, case.bytes, case.err);
    }
}

test "gossip protobuf schema preserves field order optional defaults and unsigned backoff" {
    try schema.validate(.rpc, &.{});
    try schema.validate(.rpc, &.{ 0x1a, 0 });
    try schema.validate(.subscription, &.{ 18, 1, 't' });
    try schema.validate(.subscription, &.{ 18, 1, 't', 8, 0 });
    try schema.validate(.message, &.{ 34, 1, 't', 18, 0 });
    var bytes: [32]u8 = undefined;
    var writer = wire.Writer.init(&bytes);
    writer.varintField(3, std.math.maxInt(u64));
    writer.bytesField(1, "t");
    try paged(.prune, writer.written(), null);
}

test "gossip protobuf schema bounds declarations before copying or reading their bodies" {
    var bytes: [16]u8 = undefined;
    var writer = wire.Writer.init(&bytes);
    writer.tag(2, wire.wire_len);
    writer.varint(constants.maxCompressedLen(constants.MAX_PAYLOAD_SIZE) + 1);
    try std.testing.expectError(error.LengthLimit, schema.validate(.message, writer.written()));
    writer = wire.Writer.init(&bytes);
    writer.tag(2, wire.wire_len);
    writer.varint(topic.topic_max_len + 1);
    try std.testing.expectError(error.LengthLimit, schema.validate(.subscription, writer.written()));
    writer = wire.Writer.init(&bytes);
    writer.tag(2, wire.wire_len);
    writer.varint(10);
    try std.testing.expectError(error.Truncated, schema.validate(.message, writer.written()));
}

test "gossip protobuf schema enforces complete RPC cardinality before exposing items" {
    inline for (.{ .subscription, .message, .graft }) |kind| {
        const count = switch (kind) {
            .subscription => constants.max_subscriptions_per_rpc,
            .message => constants.max_publish_per_rpc,
            .graft => constants.max_control_per_rpc,
            else => unreachable,
        };
        var item: [256]u8 = undefined;
        var writer = pb.Writer.init(&item);
        switch (kind) {
            .subscription => pb.writeSubscription(&writer, true, "t"),
            .message => pb.writeMessage(&writer, "d", "t"),
            .graft => {
                writer.tag(3, wire.wire_len);
                writer.varint(3);
                writer.bytesField(1, "t");
            },
            else => unreachable,
        }
        const bytes = try std.testing.allocator.alloc(u8, (count + 1) * writer.len + 8);
        defer std.testing.allocator.free(bytes);
        for ([_]usize{ count, count + 1 }) |n| {
            var rpc_writer = pb.Writer.init(bytes);
            if (kind == .graft) {
                rpc_writer.tag(3, wire.wire_len);
                rpc_writer.varint(n * writer.len);
            }
            for (0..n) |_| rpc_writer.bytes(writer.written());
            var rpc = pb.RpcReader.init(rpc_writer.written());
            if (n == count) {
                try schema.validate(.rpc, rpc_writer.written());
                try std.testing.expect((try rpc.next()) != null);
            } else {
                try std.testing.expectError(error.OccurrenceLimit, rpc.next());
                try std.testing.expectEqual(@as(usize, 0), rpc.top.cursor.pos);
            }
        }
    }
}

test "gossip protobuf schema bounds individual and aggregate ID lists" {
    const count = constants.max_iwant_ids_per_rpc;
    const list = try std.testing.allocator.alloc(u8, (count + 1) * wire.bytesFieldSize(1, constants.message_id_length));
    defer std.testing.allocator.free(list);
    var writer = pb.Writer.init(list);
    for (0..count) |_| writer.bytesField(1, &([_]u8{7} ** constants.message_id_length));
    try schema.validate(.iwant, writer.written());
    try paged(.iwant, writer.written(), null);
    writer.bytesField(1, &([_]u8{7} ** constants.message_id_length));
    try std.testing.expectError(error.LengthLimit, schema.validate(.iwant, writer.written()));
    const list_bytes = list[0 .. list.len - 22];
    const rpc = try std.testing.allocator.alloc(u8, list_bytes.len * 4 + 64);
    defer std.testing.allocator.free(rpc);
    for ([_]usize{ 3, 4 }) |lists| {
        writer = pb.Writer.init(rpc);
        writer.tag(3, wire.wire_len);
        writer.varint(lists * wire.bytesFieldSize(2, list_bytes.len));
        for (0..lists) |_| writer.bytesField(2, list_bytes);
        if (lists == 3) try schema.validate(.rpc, writer.written()) else try std.testing.expectError(error.OccurrenceLimit, schema.validate(.rpc, writer.written()));
    }
}

test "gossip protobuf prevalidation resumes without exposing a valid prefix of an invalid frame" {
    var bytes: [256]u8 = undefined;
    var writer = pb.Writer.init(&bytes);
    pb.writeSubscription(&writer, true, "topic");
    writer.bytes(&.{ 0x1a, 0, 0x1a, 0 });
    var rpc = pb.RpcReader.init(writer.written());
    var budget: usize = 1;
    try std.testing.expectEqual(pb.RpcReader.Step.deferred, try rpc.step(&budget));
    try std.testing.expectEqual(@as(usize, 0), rpc.top.cursor.pos);
    budget = 1000;
    try std.testing.expectError(error.DuplicateField, rpc.step(&budget));
    try std.testing.expectEqual(@as(usize, 0), rpc.top.cursor.pos);
    try paged(.rpc, writer.written(), error.DuplicateField);
}

fn paged(shape: schema.Shape, bytes: []const u8, expected: ?schema.Error) !void {
    var pool = try receive.ReceivePool.init(std.testing.allocator, std.mem.alignForward(usize, @max(bytes.len, 1), receive.page_bytes));
    defer pool.deinit(std.testing.allocator);
    for ([_]usize{ 0, 1, 2, 3, 4095 }) |split| {
        const prefix = @min(bytes.len, split);
        var chain: receive.Chain = .{};
        defer pool.release(&chain);
        var copied = prefix;
        for (0..pool.next.len) |_| {
            if (copied == bytes.len) break;
            const target = pool.writable(&chain).?;
            const count = @min(target.len, bytes.len - copied);
            @memcpy(target[0..count], bytes[copied..][0..count]);
            copied += count;
            chain.len += count;
        }
        var view: receive.View = .{ .prefix = bytes[0..prefix], .pool = &pool, .first = chain.first, .len = bytes.len };
        var validator = schema.Validator.init(shape, &view);
        var terminal = false;
        for (0..schema.fields_per_rpc + 1) |_| {
            var budget: usize = 128;
            const complete = validator.advance(&view, &budget) catch |err| {
                try std.testing.expectEqual(expected.?, err);
                terminal = true;
                break;
            };
            if (complete) {
                try std.testing.expect(expected == null);
                terminal = true;
                break;
            }
        }
        try std.testing.expect(terminal);
    }
}
