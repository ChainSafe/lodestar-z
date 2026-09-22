const TimeoutReason = @import("peer_io.zig").TimeoutReason;
const frame = @import("frame.zig");
const protobuf = @import("protobuf.zig");
const std = @import("std");

test "gossip deadlines track pressure and progress through partial frame reset" {
    var pool = try @import("test_support.zig").sessions(std.testing.allocator, 1);
    defer pool.deinit(std.testing.allocator);
    const io = &pool.rows[0].io;
    const options: @import("options.zig").Options = .{ .pressure_timeout_ms = 100, .large_frame_timeout_ms = 50, .tx_timeout_ms = 100 };
    io.frame_since = 0;
    io.progress_ms = 20;
    try std.testing.expectEqual(@as(?u64, 70), io.deadlines(&options).next());
    io.pressure_since = 30;
    try std.testing.expect(io.deadlines(&options).expired(70) == null);
    try std.testing.expectEqual(@as(?u64, 100), io.deadlines(&options).next());
    try std.testing.expectEqual(TimeoutReason.receive_frame, io.deadlines(&options).expired(100).?);
    try std.testing.expect(!pool.resetRx(0));
    try std.testing.expect(io.deadlines(&options).next() == null);
    _ = io.tx.injectFrame("abc", false, .iwant, 0).?;
    io.tx.progress_ms = 20;
    try std.testing.expectEqual(TimeoutReason.send_progress, io.deadlines(&options).expired(70).?);
    io.tx.progress_ms = 50;
    try std.testing.expectEqual(@as(?u64, 100), io.deadlines(&options).next());
    try std.testing.expectEqual(TimeoutReason.send_queue, io.deadlines(&options).expired(100).?);
}

test "gossip active RPC completion discard and reset clear frame borrows and limits" {
    var sessions = try @import("test_support.zig").sessions(std.testing.allocator, 1);
    defer sessions.deinit(std.testing.allocator);
    const io = &sessions.rows[0].io;
    var bytes: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&bytes);
    protobuf.writeSubscription(&writer, true, "topic");
    var framed: [65]u8 = undefined;
    const wire = frame.writeFrame(&framed, writer.written());

    const Finish = enum { complete, discard, reset };
    for ([_]Finish{ .complete, .discard, .reset }) |finish| {
        @memcpy(io.unread[0..wire.len], wire);
        io.unread_start = 0;
        io.unread_end = wire.len;
        try std.testing.expect((try io.feedUnread(&sessions.receive_pool, wire.len, 1)).complete);
        const rpc = &io.rpc.?;
        try std.testing.expect(rpc.item == null and !rpc.had_control);
        var fields: usize = 65536;
        rpc.item = (try rpc.reader.step(&fields)).item;
        try std.testing.expectEqualStrings("topic", (try rpc.reader.decode(rpc.item.?, &.{})).subscription.topic);
        if (finish == .complete) {
            rpc.consumeItem();
            try std.testing.expect(rpc.item == null);
            try std.testing.expect(try rpc.reader.next() == null);
        }
        rpc.had_control = true;
        io.pressure_since = 1;
        io.blocked = .events;
        try std.testing.expect(!if (finish == .reset) sessions.resetRx(0) else sessions.finishFrame(io));
        try std.testing.expect(io.rpc == null and io.reader.declaredLen() == null);
        try std.testing.expect(io.frame_since == null and io.pressure_since == null);
        try std.testing.expectEqual(.none, io.blocked);
        const unread = if (finish == .reset) 0 else wire.len;
        try std.testing.expectEqual(unread, io.unread_start);
        try std.testing.expectEqual(unread, io.unread_end);
    }
}

test "gossip local discard releases pages preserves the next frame and keeps the original deadline" {
    const receive = @import("receive_pool.zig");
    var sessions = try @import("test_support.zig").sessions(std.testing.allocator, 1);
    defer sessions.deinit(std.testing.allocator);
    const io = &sessions.rows[0].io;
    const options: @import("options.zig").Options = .{ .large_frame_timeout_ms = 200, .pressure_timeout_ms = 300 };
    _ = sessions.receive_pool.writable(&io.overflow).?;
    io.overflow.len = receive.page_bytes;
    io.reader.declared = io.body.len + receive.page_bytes + 5;
    io.reader.filled = io.body.len + receive.page_bytes;
    io.frame_since = 100;
    io.progress_ms = 110;
    var body: [64]u8 = undefined;
    var writer = protobuf.Writer.init(&body);
    protobuf.writeSubscription(&writer, true, "next");
    @memset(io.unread[0..5], 0xff);
    const following = frame.writeFrame(io.unread[5..], writer.written());
    io.unread_end = 5 + following.len;
    sessions.discardFrame(io);
    try std.testing.expectEqual(sessions.receive_pool.next.len, sessions.receive_pool.free_pages);
    try std.testing.expectEqual(@as(?u64, 300), io.deadlines(&options).next());
    try std.testing.expect(!(try io.feedUnread(&sessions.receive_pool, 3, 120)).complete);
    try std.testing.expectEqual(@as(usize, 3), io.unread_start);
    try std.testing.expect((try io.feedUnread(&sessions.receive_pool, io.unread_end - io.unread_start, 125)).complete);
    try std.testing.expect(io.rpc == null and io.discarding);
    try std.testing.expectEqual(@as(usize, 5), io.unread_start);
    try std.testing.expectEqual(@as(?u64, 300), io.deadlines(&options).next());
    _ = sessions.finishFrame(io);
    try std.testing.expect((try io.feedUnread(&sessions.receive_pool, following.len, 126)).complete);
    try std.testing.expectEqualStrings("next", (try io.rpc.?.reader.next()).?.subscription.topic);
    _ = sessions.finishFrame(io);
}
