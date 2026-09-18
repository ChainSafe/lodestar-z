const Record = @import("logging.zig").Record;
const Sink = @import("logging.zig").Sink;
const bind = @import("logging.zig").bind;
const capacity = @import("logging.zig").capacity;
const drain_max = @import("logging.zig").drain_max;
const logFn = @import("logging.zig").logFn;
const message_capacity = @import("logging.zig").message_capacity;
const std = @import("std");

test "native logging bounds records, sanitizes text and isolates sinks" {
    var first: Sink = .{};
    var second: Sink = .{};
    first.configure(.debug);
    first.write(.debug, .network_reqresp, 10, 20, "event value={s}", .{"a\n\r\x1bb"});
    var records: [drain_max]Record = undefined;
    const batch = first.peek(&records);
    try std.testing.expectEqual(@as(usize, 1), batch.count);
    try std.testing.expectEqualStrings("event value=a???b", records[0].message[0..records[0].len]);
    try std.testing.expectEqual(@as(u16, 0), second.snapshot().queued);
    try std.testing.expectEqual(@as(usize, 1), first.peek(&records).count);
    first.commit(1);
    first.write(.info, .network_core, 10, 20, "{s}", .{&([_]u8{'x'} ** (message_capacity + 1))});
    _ = first.peek(&records);
    try std.testing.expect(records[0].truncated);
    try std.testing.expectEqual(@as(u16, message_capacity), records[0].len);
    first.configure(null);
    first.write(.err, .network_runtime, 10, 20, "disabled", .{});
    try std.testing.expectEqual(@as(u16, 1), first.snapshot().queued);
}

test "native logging rate limits independently and reserves capacity for severe records" {
    var sink: Sink = .{};
    sink.configure(.debug);
    for (0..100) |_| sink.write(.debug, .network_gossip, 1, 1, "busy", .{});
    try std.testing.expectEqual(@as(u64, 92), sink.snapshot().total("suppressed"));
    for (1..20) |i| for (0..8) |_| sink.write(.debug, .network_gossip, i * 1000, i * 1000, "busy", .{});
    try std.testing.expectEqual(@as(u16, capacity - 32), sink.snapshot().queued);
    sink.write(.info, .network_runtime, 20000, 20000, "lifecycle", .{});
    sink.write(.err, .network_runtime, 20000, 20000, "failure", .{});
    try std.testing.expectEqual(@as(u16, capacity - 30), sink.snapshot().queued);
    try std.testing.expect(sink.snapshot().total("dropped") > 0);
}

test "native logging restores nested bindings and isolates owner threads" {
    var main_sink: Sink = .{};
    var child_sink: Sink = .{};
    const previous = bind(&main_sink);
    defer _ = bind(previous);
    const Child = struct {
        fn run(sink: *Sink) void {
            const old = bind(sink);
            std.debug.assert(old == null);
            defer _ = bind(old);
            logFn(.info, .network_runtime, "child_owner", .{});
        }
    };
    const thread = try std.Thread.spawn(.{}, Child.run, .{&child_sink});
    thread.join();
    const nested = bind(&child_sink);
    std.debug.assert(nested == &main_sink);
    _ = bind(nested);
    logFn(.info, .network_runtime, "main_owner", .{});
    var records: [drain_max]Record = undefined;
    try std.testing.expectEqual(@as(usize, 1), main_sink.peek(&records).count);
    try std.testing.expectEqualStrings("main_owner", records[0].message[0..records[0].len]);
    try std.testing.expectEqual(@as(usize, 1), child_sink.peek(&records).count);
    try std.testing.expectEqualStrings("child_owner", records[0].message[0..records[0].len]);
}

test "native logging preserves copied records and ordering across queue wrap and loss" {
    var sink: Sink = .{};
    for (0..120) |i| sink.write(.info, .network_runtime, i * 1000, i * 1000, "event index={d}", .{i});
    var records: [drain_max]Record = undefined;
    _ = sink.peek(&records);
    records[0].message[0] = '?';
    _ = sink.peek(&records);
    try std.testing.expectEqualStrings("event index=0", records[0].message[0..records[0].len]);
    sink.commit(drain_max);
    for (0..32) |i| sink.write(.err, .network_runtime, 200000 + i * 1000, 200000, "critical index={d}", .{i});
    var sequence: u64 = drain_max;
    for (0..4) |_| {
        const batch = sink.peek(&records);
        for (records[0..batch.count]) |*record| {
            try std.testing.expect(record.sequence > sequence);
            sequence = record.sequence;
        }
        sink.commit(batch.count);
        if (!batch.more) break;
    }
    try std.testing.expectEqual(@as(u16, 0), sink.snapshot().queued);
    try std.testing.expectEqual(@as(u64, 8), sink.snapshot().total("dropped"));
    try std.testing.expectEqual(@as(u64, 152), sequence);
}
