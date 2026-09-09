const std = @import("std");
const prom = @import("metrics_prometheus.zig");

pub const Scope = enum { network_runtime, network_core, network_quic, network_peers, network_reqresp, network_reqresp_errors, network_gossip, network_mesh, network_discovery, network_bridge, network_gossip_errors };
pub const capacity = 128;
pub const message_capacity = 768;
pub const drain_max = 32;
const scope_count = @typeInfo(Scope).@"enum".fields.len;
const level_count = @typeInfo(std.log.Level).@"enum".fields.len;
pub const scope_levels: []const std.log.ScopeLevel = &.{
    .{ .scope = .network_runtime, .level = .debug },
    .{ .scope = .network_core, .level = .debug },
    .{ .scope = .network_quic, .level = .debug },
    .{ .scope = .network_peers, .level = .debug },
    .{ .scope = .network_reqresp, .level = .debug },
    .{ .scope = .network_reqresp_errors, .level = .debug },
    .{ .scope = .network_gossip, .level = .debug },
    .{ .scope = .network_mesh, .level = .debug },
    .{ .scope = .network_discovery, .level = .debug },
    .{ .scope = .network_bridge, .level = .debug },
    .{ .scope = .network_gossip_errors, .level = .debug },
};

pub const Record = struct {
    sequence: u64,
    timestamp_ms: u64,
    monotonic_ms: u64,
    scope: Scope,
    level: std.log.Level,
    truncated: bool,
    len: u16,
    message: [message_capacity]u8,
};
pub const Counts = struct { emitted: u64 = 0, dropped: u64 = 0, suppressed: u64 = 0, truncated: u64 = 0 };
pub const Stats = struct {
    queued: u16 = 0,
    high_water: u16 = 0,
    counts: [scope_count][level_count]Counts = @splat(@splat(.{})),

    pub fn total(self: *const Stats, comptime field: []const u8) u64 {
        var result: u64 = 0;
        for (self.counts) |levels| for (levels) |entry| {
            result +|= @field(entry, field);
        };
        return result;
    }

    pub fn write(self: *const Stats, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try prom.scalar(writer, "lodestar_native_logs_queued", .gauge, "Native log records awaiting host delivery", self.queued);
        try prom.scalar(writer, "lodestar_native_logs_capacity", .gauge, "Native log queue capacity", capacity);
        try prom.scalar(writer, "lodestar_native_logs_high_water", .gauge, "Maximum native log queue occupancy", self.high_water);
        inline for (.{ "emitted", "dropped", "suppressed", "truncated" }) |kind| {
            try prom.family(writer, "lodestar_native_logs_" ++ kind ++ "_total", .counter, "Native log records " ++ kind ++ " by scope and level");
            inline for (@typeInfo(Scope).@"enum".fields) |scope| {
                inline for (@typeInfo(std.log.Level).@"enum".fields) |level| {
                    try writer.print("lodestar_native_logs_" ++ kind ++ "_total{{scope=\"" ++ scope.name ++ "\",level=\"{s}\"}} {d}\n", .{ levelName(@enumFromInt(level.value)), @field(self.counts[scope.value][level.value], kind) });
                }
            }
        }
    }
};

pub const Sink = struct {
    mutex: std.Io.Mutex = .init,
    level: ?std.log.Level = .info,
    records: [capacity]Record = undefined,
    head: u16 = 0,
    len: u16 = 0,
    sequence: u64 = 0,
    stats: Stats = .{},
    window_start: ?u64 = null,
    window_levels: [level_count]u16 = @splat(0),
    window_scopes: [scope_count][level_count]u8 = @splat(@splat(0)),

    pub fn configure(self: *Sink, level: ?std.log.Level) void {
        self.lock();
        defer self.unlock();
        self.level = level;
    }

    pub fn write(self: *Sink, comptime level: std.log.Level, comptime scope: Scope, monotonic_ms: u64, timestamp_ms: u64, comptime format: []const u8, args: anytype) void {
        self.lock();
        defer self.unlock();
        const selected = self.level orelse return;
        if (@intFromEnum(level) > @intFromEnum(selected)) return;
        const s = @intFromEnum(scope);
        const l = @intFromEnum(level);
        const counts = &self.stats.counts[s][l];
        if (self.sequence == std.math.maxInt(u64)) {
            counts.dropped +|= 1;
            return;
        }
        self.sequence += 1;
        if (self.window_start == null or monotonic_ms -| self.window_start.? >= 1000) {
            self.window_start = monotonic_ms;
            self.window_levels = @splat(0);
            self.window_scopes = @splat(@splat(0));
        }
        const per_level = [_]u16{ 8, 16, 16, 64 };
        if (self.window_levels[l] == per_level[l] or self.window_scopes[s][l] == 8) {
            counts.suppressed +|= 1;
            return;
        }
        self.window_levels[l] += 1;
        self.window_scopes[s][l] += 1;
        const reserve: u16 = switch (level) {
            .debug => 32,
            .info => 16,
            .warn, .err => 0,
        };
        if (self.len >= capacity - reserve) {
            counts.dropped +|= 1;
            return;
        }
        const record = &self.records[(@as(usize, self.head) + self.len) % capacity];
        var writer: std.Io.Writer = .fixed(&record.message);
        var truncated = false;
        writer.print(format, args) catch {
            truncated = true;
        };
        const message = writer.buffered();
        // Keep records single-line and valid UTF-8 even after byte truncation or hostile text.
        for (message) |*byte| if (byte.* < 32 or byte.* > 126) {
            byte.* = '?';
        };
        record.sequence = self.sequence;
        record.timestamp_ms = timestamp_ms;
        record.monotonic_ms = monotonic_ms;
        record.scope = scope;
        record.level = level;
        record.truncated = truncated;
        record.len = @intCast(message.len);
        counts.emitted +|= 1;
        counts.truncated +|= @intFromBool(truncated);
        self.len += 1;
        self.stats.high_water = @max(self.stats.high_water, self.len);
    }

    pub fn peek(self: *Sink, out: []Record) struct { count: usize, stats: Stats, more: bool } {
        std.debug.assert(out.len > 0 and out.len <= drain_max);
        self.lock();
        defer self.unlock();
        const count = @min(out.len, self.len);
        for (0..count) |i| out[i] = self.records[(@as(usize, self.head) + i) % capacity];
        var stats = self.stats;
        stats.queued = self.len;
        return .{ .count = count, .stats = stats, .more = self.len > count };
    }

    /// Commit only after the host has copied the entire batch. Producers never evict queued records.
    pub fn commit(self: *Sink, count: usize) void {
        self.lock();
        defer self.unlock();
        std.debug.assert(count <= self.len and count <= drain_max);
        self.head = @intCast((@as(usize, self.head) + count) % capacity);
        self.len -= @intCast(count);
    }

    pub fn snapshot(self: *Sink) Stats {
        self.lock();
        defer self.unlock();
        var result = self.stats;
        result.queued = self.len;
        return result;
    }
    fn lock(self: *Sink) void {
        std.Io.Threaded.mutexLock(&self.mutex);
    }
    fn unlock(self: *Sink) void {
        std.Io.Threaded.mutexUnlock(&self.mutex);
    }
};

threadlocal var current: ?*Sink = null;

/// Bind only for a synchronous native call or the lifetime of its owner thread, before releasing the sink.
pub fn bind(sink: ?*Sink) ?*Sink {
    const previous = current;
    current = sink;
    return previous;
}

pub fn logFn(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    if (comptime std.meta.stringToEnum(Scope, @tagName(scope))) |known| {
        if (current) |sink| {
            const io = std.Options.debug_io;
            const mono: u64 = @intCast(@max(0, std.Io.Timestamp.now(io, .awake).toMilliseconds()));
            const timestamp: u64 = @intCast(@max(0, std.Io.Timestamp.now(io, .real).toMilliseconds()));
            sink.write(level, known, mono, timestamp, format, args);
            return;
        }
    }
    std.log.defaultLog(level, scope, format, args);
}

pub fn levelName(level: std.log.Level) []const u8 {
    return switch (level) {
        .err => "error",
        .warn => "warn",
        .info => "info",
        .debug => "debug",
    };
}

pub fn peer(value: *const @import("wire/peer_id.zig").PeerId) PeerFormatter {
    return .{ .value = value };
}
const PeerFormatter = struct {
    value: *const @import("wire/peer_id.zig").PeerId,
    pub fn format(self: PeerFormatter, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var buffer: [@import("wire/peer_id.zig").text_length_max]u8 = undefined;
        try writer.writeAll(self.value.toText(&buffer));
    }
};

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
