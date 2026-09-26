const std = @import("std");
const prom = @import("metrics/registry.zig");

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
pub const Counts = struct { dropped: u64 = 0, suppressed: u64 = 0, truncated: u64 = 0 };
pub const Stats = struct {
    counts: [scope_count][level_count]Counts = @splat(@splat(.{})),

    pub fn total(self: *const Stats, comptime field: []const u8) u64 {
        var result: u64 = 0;
        for (self.counts) |levels| for (levels) |entry| {
            result +|= @field(entry, field);
        };
        return result;
    }

    pub fn write(self: *const Stats, writer: *prom.Encoder) prom.Error!void {
        const records = try writer.family(.{
            .name = "lodestar_native_logs_dropped_total",
            .kind = .counter,
            .help = "Native log records dropped by scope and level",
            .labels = &.{ "scope", "level" },
        });
        inline for (@typeInfo(Scope).@"enum".fields) |scope| {
            inline for (@typeInfo(std.log.Level).@"enum".fields) |level| {
                try records.sample(.{ scope.name, levelName(@enumFromInt(level.value)) }, self.counts[scope.value][level.value].dropped);
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
        counts.truncated +|= @intFromBool(truncated);
        self.len += 1;
    }

    pub fn peek(self: *Sink, out: []Record) struct { count: usize, stats: Stats, more: bool } {
        std.debug.assert(out.len > 0 and out.len <= drain_max);
        self.lock();
        defer self.unlock();
        const count = @min(out.len, self.len);
        for (0..count) |i| out[i] = self.records[(@as(usize, self.head) + i) % capacity];
        return .{ .count = count, .stats = self.stats, .more = self.len > count };
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
        return self.stats;
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

test {
    _ = @import("logging_test.zig");
}
