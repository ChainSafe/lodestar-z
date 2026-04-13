//! Runtime backend for Zig's scoped `std.log` frontend.
//!
//! Application code should use `std.log` or `std.log.scoped(.scope)`.
//! This module only owns formatting, runtime level filtering, and optional
//! file output through `std.options.logFn`.

const std = @import("std");

pub const Level = enum(u2) {
    err = 0,
    warn = 1,
    info = 2,
    debug = 3,

    pub fn asText(self: Level) []const u8 {
        return switch (self) {
            .err => "error",
            .warn => "warn ",
            .info => "info ",
            .debug => "debug",
        };
    }

    pub fn asJsonText(self: Level) []const u8 {
        return switch (self) {
            .err => "error",
            .warn => "warn",
            .info => "info",
            .debug => "debug",
        };
    }

    pub fn parse(s: []const u8) ?Level {
        const eql = std.ascii.eqlIgnoreCase;
        if (eql(s, "error")) return .err;
        if (eql(s, "warn")) return .warn;
        if (eql(s, "info")) return .info;
        if (eql(s, "verbose")) return .debug;
        if (eql(s, "debug")) return .debug;
        if (eql(s, "trace")) return .debug;
        return null;
    }

    pub fn fromStd(std_level: std.log.Level) Level {
        return switch (std_level) {
            .err => .err,
            .warn => .warn,
            .info => .info,
            .debug => .debug,
        };
    }
};

pub const Format = enum {
    human,
    json,
};

pub const Backend = struct {
    level: Level,
    format: Format,
    file_transport: ?*FileTransport = null,

    pub fn init(level: Level, format: Format) Backend {
        return .{
            .level = level,
            .format = format,
        };
    }

    pub inline fn enabled(self: *const Backend, level: Level) bool {
        return @intFromEnum(level) <= @intFromEnum(self.level);
    }

    pub fn setLevel(self: *Backend, level: Level) void {
        self.level = level;
    }

    pub fn setFileTransport(self: *Backend, transport: *FileTransport) !void {
        try transport.start();
        self.file_transport = transport;
    }

    pub fn writeStdLog(
        self: *Backend,
        level: Level,
        comptime scope: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        {
            var buffer: [8192]u8 = undefined;
            const stderr = std.debug.lockStderr(&buffer);
            defer std.debug.unlockStderr();
            const w = stderr.terminal().writer;

            switch (self.format) {
                .human => renderHumanStdLogLine(w, level, scope, fmt, args),
                .json => renderJsonStdLogLine(w, level, scope, fmt, args),
            }
        }

        if (self.file_transport) |ft| {
            if (@intFromEnum(level) <= @intFromEnum(ft.level)) {
                ft.writeStdLogLine(level, scope, fmt, args);
            }
        }
    }
};

pub fn stdLogFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime fmt: []const u8,
    args: anytype,
) void {
    const log_root = @import("root.zig");
    const backend_level = Level.fromStd(level);
    if (!shouldEmitStdLog(&log_root.global, backend_level, @tagName(scope), fmt)) return;

    log_root.global.writeStdLog(backend_level, @tagName(scope), fmt, args);
}

fn shouldEmitStdLog(
    backend: *const Backend,
    level: Level,
    comptime scope: []const u8,
    comptime fmt: []const u8,
) bool {
    if (!backend.enabled(level)) return false;

    // Dependency scopes that are currently too chatty at info level. Keep them
    // available when the operator explicitly opts into debug logging.
    if (backend.level != .debug) {
        if (scopeOverrideLevel(scope)) |scope_level| {
            if (@intFromEnum(level) > @intFromEnum(scope_level)) return false;
        }
        if (shouldSuppressKnownDependencyNoise(level, scope, fmt)) return false;
    }

    return true;
}

fn scopeOverrideLevel(comptime scope: []const u8) ?Level {
    if (std.mem.eql(u8, scope, "switch")) return .warn;
    if (std.mem.eql(u8, scope, "quic_engine")) return .warn;
    if (std.mem.eql(u8, scope, "gossipsub")) return .warn;
    if (std.mem.eql(u8, scope, "gossipsub_service")) return .warn;
    if (std.mem.eql(u8, scope, "identify")) return .warn;
    return null;
}

fn shouldSuppressKnownDependencyNoise(
    level: Level,
    comptime scope: []const u8,
    comptime fmt: []const u8,
) bool {
    if (std.mem.eql(u8, scope, "quic_engine") and level == .warn) {
        if (std.mem.startsWith(u8, fmt, "CONNECTION_CLOSE received:")) return true;
        if (std.mem.startsWith(u8, fmt, "onConnClosed: status=")) return true;
        if (std.mem.startsWith(u8, fmt, "read: stream closed, no leftover data")) return true;
    }
    return false;
}

fn renderHumanStdLogLine(
    w: anytype,
    level: Level,
    comptime scope: []const u8,
    comptime fmt: []const u8,
    args: anytype,
) void {
    writeTimestampTo(w);
    w.print(" [{s}] [{s: <18}] ", .{ level.asText(), scope }) catch {};
    w.print(fmt, args) catch {};
    w.writeAll("\n") catch {};
}

fn renderJsonStdLogLine(
    w: anytype,
    level: Level,
    comptime scope: []const u8,
    comptime fmt: []const u8,
    args: anytype,
) void {
    w.writeAll("{") catch {};
    writeTimestampJsonTo(w);
    w.print(",\"level\":\"{s}\",\"scope\":\"{s}\",\"msg\":\"", .{
        level.asJsonText(),
        scope,
    }) catch {};
    var msg_buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, fmt, args) catch fmt;
    writeJsonEscapedTo(w, msg);
    w.writeAll("\"}\n") catch {};
}

fn writeTimestampTo(w: anytype) void {
    const ts = getRealtimeSeconds();
    const epoch = std.time.epoch.EpochSeconds{ .secs = ts.secs };
    const day = epoch.getDaySeconds();
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const month_names = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    const month_idx = @intFromEnum(month_day.month) - 1;

    w.print("{s}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        month_names[month_idx],
        month_day.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    }) catch {};
}

fn writeTimestampJsonTo(w: anytype) void {
    const ts = getRealtimeSeconds();
    const epoch = std.time.epoch.EpochSeconds{ .secs = ts.secs };
    const day = epoch.getDaySeconds();
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    w.print("\"ts\":\"{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z\"", .{
        year_day.year,
        @intFromEnum(month_day.month),
        month_day.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    }) catch {};
}

fn writeJsonEscapedTo(w: anytype, s: []const u8) void {
    for (s) |c| switch (c) {
        '"' => w.writeAll("\\\"") catch {},
        '\\' => w.writeAll("\\\\") catch {},
        '\n' => w.writeAll("\\n") catch {},
        '\r' => w.writeAll("\\r") catch {},
        '\t' => w.writeAll("\\t") catch {},
        else => if (c < 0x20)
            w.print("\\u{x:0>4}", .{c}) catch {}
        else
            w.writeByte(c) catch {},
    };
}

/// Stack-allocated buffer writer for formatting file log lines without heap allocation.
const BufWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeAll(self: *BufWriter, bytes: []const u8) error{}!void {
        const end = @min(self.pos + bytes.len, self.buf.len);
        const n = end - self.pos;
        @memcpy(self.buf[self.pos..end], bytes[0..n]);
        self.pos = end;
    }

    fn print(self: *BufWriter, comptime fmt: []const u8, args: anytype) error{}!void {
        const remaining = self.buf[self.pos..];
        const result = std.fmt.bufPrint(remaining, fmt, args) catch {
            self.pos = self.buf.len;
            return;
        };
        self.pos += result.len;
    }

    fn getWritten(self: *const BufWriter) []const u8 {
        return self.buf[0..self.pos];
    }
};

const file_queue_capacity = 1024;
const max_file_line_bytes = 8192;

const QueueSlot = struct {
    sequence: std.atomic.Value(usize),
    len: usize = 0,
    bytes: [max_file_line_bytes]u8 = undefined,
};

const DequeuedSlot = struct {
    slot: *QueueSlot,
    position: usize,
};

const AsyncLineQueue = struct {
    slots: [file_queue_capacity]QueueSlot,
    enqueue_pos: std.atomic.Value(usize),
    dequeue_pos: usize,

    fn init() AsyncLineQueue {
        var queue: AsyncLineQueue = .{
            .slots = undefined,
            .enqueue_pos = .init(0),
            .dequeue_pos = 0,
        };
        for (&queue.slots, 0..) |*slot, i| {
            slot.* = .{ .sequence = .init(i) };
        }
        return queue;
    }

    fn push(self: *AsyncLineQueue, line: []const u8) bool {
        var pos = self.enqueue_pos.load(.monotonic);
        while (true) {
            const slot = &self.slots[pos % file_queue_capacity];
            const seq = slot.sequence.load(.acquire);
            const diff = signedDistance(seq, pos);

            if (diff == 0) {
                if (self.enqueue_pos.cmpxchgWeak(pos, pos + 1, .acq_rel, .monotonic) == null) {
                    const len = @min(line.len, max_file_line_bytes);
                    @memcpy(slot.bytes[0..len], line[0..len]);
                    if (len == max_file_line_bytes and slot.bytes[len - 1] != '\n') {
                        slot.bytes[len - 1] = '\n';
                    }
                    slot.len = len;
                    slot.sequence.store(pos + 1, .release);
                    return true;
                }
                pos = self.enqueue_pos.load(.monotonic);
                continue;
            }

            if (diff < 0) return false;
            pos = self.enqueue_pos.load(.monotonic);
        }
    }

    fn pop(self: *AsyncLineQueue) ?DequeuedSlot {
        const pos = self.dequeue_pos;
        const slot = &self.slots[pos % file_queue_capacity];
        const seq = slot.sequence.load(.acquire);
        if (signedDistance(seq, pos + 1) != 0) return null;

        self.dequeue_pos = pos + 1;
        return .{ .slot = slot, .position = pos };
    }

    fn release(_: *AsyncLineQueue, dequeued: DequeuedSlot) void {
        dequeued.slot.sequence.store(dequeued.position + file_queue_capacity, .release);
    }
};

fn signedDistance(lhs: usize, rhs: usize) isize {
    return @as(isize, @intCast(lhs)) - @as(isize, @intCast(rhs));
}

/// File transport for writing log lines to a file with optional rotation.
/// Producers enqueue formatted lines into a bounded MPSC queue.
/// A single background thread owns the file handle and rotation state.
pub const FileTransport = struct {
    io: std.Io,
    path: []const u8,
    level: Level,
    rotation: RotationConfig,
    file: ?std.Io.File = null,
    bytes_written: u64 = 0,
    current_date: Date = .{ .year = 1970, .month = 1, .day = 1 },
    worker: ?std.Thread = null,
    lifecycle_mutex: std.Io.Mutex = .init,
    wake_mutex: std.Io.Mutex = .init,
    wake_cond: std.Io.Condition = .init,
    drain_cond: std.Io.Condition = .init,
    queue: AsyncLineQueue = undefined,
    pending_count: std.atomic.Value(usize) = .init(0),
    submitted_count: std.atomic.Value(u64) = .init(0),
    completed_count: std.atomic.Value(u64) = .init(0),
    dropped_count: std.atomic.Value(u64) = .init(0),
    shutdown_requested: std.atomic.Value(bool) = .init(false),
    started: bool = false,

    pub const Date = struct {
        year: u32,
        month: u8,
        day: u8,

        pub fn eql(a: Date, b: Date) bool {
            return a.year == b.year and a.month == b.month and a.day == b.day;
        }
    };

    pub fn init(io: std.Io, path: []const u8, level: Level, rotation: RotationConfig) FileTransport {
        return .{
            .io = io,
            .path = path,
            .level = level,
            .rotation = rotation,
            .queue = AsyncLineQueue.init(),
        };
    }

    pub fn start(self: *FileTransport) !void {
        self.lifecycle_mutex.lockUncancelable(self.io);
        defer self.lifecycle_mutex.unlock(self.io);

        if (self.started) return;

        self.queue = AsyncLineQueue.init();
        const file = try openLogFile(self.io, self.path);
        errdefer file.close(self.io);
        const bytes_written = (try file.stat(self.io)).size;
        self.current_date = getCurrentDate();
        self.shutdown_requested.store(false, .release);
        self.completed_count.store(0, .release);
        self.submitted_count.store(0, .release);
        self.pending_count.store(0, .release);
        self.dropped_count.store(0, .release);
        self.file = file;
        errdefer self.file = null;
        self.bytes_written = bytes_written;

        self.worker = try std.Thread.spawn(.{}, fileWorkerMain, .{self});
        self.started = true;
    }

    pub fn writeStdLogLine(
        self: *FileTransport,
        level: Level,
        comptime scope: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        if (!self.started) return;
        var buf: [max_file_line_bytes]u8 = undefined;
        var w = BufWriter{ .buf = &buf };
        renderHumanStdLogLine(&w, level, scope, fmt, args);
        self.enqueue(w.getWritten());
    }

    pub fn flush(self: *FileTransport) void {
        if (!self.started) return;

        const target = self.submitted_count.load(.acquire);
        self.wake_mutex.lockUncancelable(self.io);
        defer self.wake_mutex.unlock(self.io);

        while (self.completed_count.load(.acquire) < target or self.dropped_count.load(.acquire) != 0) {
            self.drain_cond.waitUncancelable(self.io, &self.wake_mutex);
        }
    }

    pub fn close(self: *FileTransport) void {
        self.lifecycle_mutex.lockUncancelable(self.io);
        if (!self.started) {
            self.lifecycle_mutex.unlock(self.io);
            return;
        }

        self.shutdown_requested.store(true, .release);
        const worker = self.worker.?;
        self.lifecycle_mutex.unlock(self.io);

        self.wake_cond.signal(self.io);
        worker.join();

        self.lifecycle_mutex.lockUncancelable(self.io);
        self.worker = null;
        self.started = false;
        self.lifecycle_mutex.unlock(self.io);
    }

    fn enqueue(self: *FileTransport, line: []const u8) void {
        if (!self.queue.push(line)) {
            _ = self.dropped_count.fetchAdd(1, .monotonic);
            return;
        }

        _ = self.submitted_count.fetchAdd(1, .release);
        _ = self.pending_count.fetchAdd(1, .release);
        self.wake_cond.signal(self.io);
    }

    fn fileWorkerMain(self: *FileTransport) void {
        while (true) {
            if (self.processOneQueuedLine()) continue;
            self.writeDroppedSummary();

            self.wake_mutex.lockUncancelable(self.io);
            while (self.pending_count.load(.acquire) == 0 and !self.shutdown_requested.load(.acquire)) {
                self.wake_cond.waitUncancelable(self.io, &self.wake_mutex);
            }
            const should_exit = self.pending_count.load(.acquire) == 0 and self.shutdown_requested.load(.acquire);
            self.wake_mutex.unlock(self.io);

            if (should_exit) break;
        }

        self.writeDroppedSummary();
        if (self.file) |*file| {
            file.close(self.io);
            self.file = null;
        }
    }

    fn processOneQueuedLine(self: *FileTransport) bool {
        const dequeued = self.queue.pop() orelse return false;
        defer self.queue.release(dequeued);

        self.writeDroppedSummary();
        self.maybeRotate();

        const line = dequeued.slot.bytes[0..dequeued.slot.len];
        if (self.file) |*file| {
            file.writePositionalAll(self.io, line, self.bytes_written) catch {};
            self.bytes_written += line.len;
        }

        _ = self.pending_count.fetchSub(1, .acq_rel);
        _ = self.completed_count.fetchAdd(1, .release);
        self.drain_cond.signal(self.io);
        return true;
    }

    fn writeDroppedSummary(self: *FileTransport) void {
        const dropped = self.dropped_count.swap(0, .acq_rel);
        if (dropped == 0) return;

        var buf: [256]u8 = undefined;
        var w = BufWriter{ .buf = &buf };
        renderHumanStdLogLine(&w, .warn, "log", "file logger dropped {d} lines", .{dropped});
        const line = w.getWritten();
        self.maybeRotate();
        if (self.file) |*file| {
            file.writePositionalAll(self.io, line, self.bytes_written) catch {};
            self.bytes_written += line.len;
        }
        self.drain_cond.signal(self.io);
    }

    fn maybeRotate(self: *FileTransport) void {
        const now = getCurrentDate();

        if (self.rotation.daily and !Date.eql(now, self.current_date)) {
            self.performRotation(now);
            return;
        }

        if (self.bytes_written >= self.rotation.max_size_bytes) {
            self.performRotation(now);
        }
    }

    fn performRotation(self: *FileTransport, now: Date) void {
        if (self.file == null) return;

        var rotated_buf: [640]u8 = undefined;
        const rotated_path = self.nextRotatedPath(&rotated_buf) catch return;

        self.file.?.close(self.io);
        self.file = null;

        std.Io.Dir.rename(std.Io.Dir.cwd(), self.path, std.Io.Dir.cwd(), rotated_path, self.io) catch {
            self.file = openLogFile(self.io, self.path) catch null;
            if (self.file) |file| {
                self.bytes_written = (file.stat(self.io) catch return).size;
            }
            return;
        };

        self.cleanOldFiles();

        self.file = openLogFile(self.io, self.path) catch null;
        self.bytes_written = 0;
        self.current_date = now;
    }

    fn nextRotatedPath(self: *FileTransport, buf: []u8) ![]const u8 {
        var index: u32 = 0;
        while (true) : (index += 1) {
            const candidate = if (index == 0)
                try std.fmt.bufPrint(buf, "{s}.{d}-{d:0>2}-{d:0>2}", .{
                    self.path,
                    self.current_date.year,
                    self.current_date.month,
                    self.current_date.day,
                })
            else
                try std.fmt.bufPrint(buf, "{s}.{d}-{d:0>2}-{d:0>2}.{d:0>3}", .{
                    self.path,
                    self.current_date.year,
                    self.current_date.month,
                    self.current_date.day,
                    index,
                });

            if (!pathExists(self.io, candidate)) return candidate;
        }
    }

    fn cleanOldFiles(self: *FileTransport) void {
        const dir_path = std.fs.path.dirname(self.path) orelse ".";
        const base_name = std.fs.path.basename(self.path);

        var dir = std.Io.Dir.cwd().openDir(self.io, dir_path, .{ .iterate = true }) catch return;
        defer dir.close(self.io);

        var names: [256][256]u8 = undefined;
        var name_lens: [256]usize = undefined;
        var name_count: usize = 0;

        var iter = dir.iterate();
        while (iter.next(self.io) catch null) |entry| {
            if (!isRotatedFileName(base_name, entry.name)) continue;
            if (name_count >= names.len) break;

            const copy_len = @min(entry.name.len, names[name_count].len);
            @memcpy(names[name_count][0..copy_len], entry.name[0..copy_len]);
            name_lens[name_count] = copy_len;
            name_count += 1;
        }

        if (name_count <= self.rotation.max_files) return;

        for (1..name_count) |i| {
            const key_name = names[i];
            const key_len = name_lens[i];
            var j = i;
            while (j > 0) : (j -= 1) {
                const order = std.mem.order(u8, names[j - 1][0..name_lens[j - 1]], key_name[0..key_len]);
                if (order != .gt) break;
                names[j] = names[j - 1];
                name_lens[j] = name_lens[j - 1];
            }
            names[j] = key_name;
            name_lens[j] = key_len;
        }

        const to_delete = name_count - self.rotation.max_files;
        for (0..to_delete) |i| {
            dir.deleteFile(self.io, names[i][0..name_lens[i]]) catch {};
        }
    }
};

pub const RotationConfig = struct {
    max_size_bytes: u64 = 100 * 1024 * 1024,
    max_files: u32 = 7,
    daily: bool = true,
};

fn openLogFile(io: std.Io, path: []const u8) !std.Io.File {
    return std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = false,
    });
}

fn pathExists(io: std.Io, path: []const u8) bool {
    var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return true,
    };
    file.close(io);
    return true;
}

fn isRotatedFileName(base_name: []const u8, entry_name: []const u8) bool {
    if (!std.mem.startsWith(u8, entry_name, base_name)) return false;
    if (entry_name.len <= base_name.len + 1 or entry_name[base_name.len] != '.') return false;

    const suffix = entry_name[base_name.len + 1 ..];
    if (suffix.len < 10) return false;
    if (suffix[4] != '-' or suffix[7] != '-') return false;
    if (suffix.len == 10) return true;
    if (suffix[10] != '.') return false;
    if (suffix.len == 11) return false;
    for (suffix[11..]) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn getRealtimeSeconds() struct { secs: u64 } {
    var ts: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => return .{ .secs = if (ts.sec >= 0) @intCast(ts.sec) else 0 },
        else => return .{ .secs = 0 },
    }
}

fn getCurrentDate() FileTransport.Date {
    const ts = getRealtimeSeconds();
    const epoch = std.time.epoch.EpochSeconds{ .secs = ts.secs };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return .{
        .year = year_day.year,
        .month = @intFromEnum(month_day.month),
        .day = month_day.day_index + 1,
    };
}

fn tmpLogPath(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir, filename: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, filename });
}

test "Level parse maps std.log-compatible levels" {
    const testing = std.testing;
    try testing.expectEqual(Level.err, Level.parse("error").?);
    try testing.expectEqual(Level.warn, Level.parse("warn").?);
    try testing.expectEqual(Level.info, Level.parse("INFO").?);
    try testing.expectEqual(Level.debug, Level.parse("debug").?);
    try testing.expectEqual(Level.debug, Level.parse("verbose").?);
    try testing.expectEqual(Level.debug, Level.parse("trace").?);
    try testing.expectEqual(@as(?Level, null), Level.parse("unknown"));
}

test "Backend level filtering" {
    const testing = std.testing;
    var backend = Backend.init(.info, .human);
    try testing.expect(backend.enabled(.err));
    try testing.expect(backend.enabled(.warn));
    try testing.expect(backend.enabled(.info));
    try testing.expect(!backend.enabled(.debug));

    backend.setLevel(.debug);
    try testing.expect(backend.enabled(.debug));
}

test "noisy dependency scopes are filtered below debug" {
    const testing = std.testing;
    const info_backend = Backend.init(.info, .human);
    try testing.expect(!shouldEmitStdLog(&info_backend, .info, "switch", "opened peer stream"));
    try testing.expect(!shouldEmitStdLog(&info_backend, .info, "gossipsub", "heartbeat"));
    try testing.expect(!shouldEmitStdLog(&info_backend, .info, "identify", "identify: sent {d} byte response"));
    try testing.expect(!shouldEmitStdLog(&info_backend, .warn, "quic_engine", "CONNECTION_CLOSE received: app_error={d}, code=0x{x}, reason=\"{s}\""));
    try testing.expect(!shouldEmitStdLog(&info_backend, .warn, "quic_engine", "onConnClosed: status={d}, errmsg={s}, lc={any}"));
    try testing.expect(!shouldEmitStdLog(&info_backend, .warn, "quic_engine", "read: stream closed, no leftover data (has_received={}, lsquic={?*anyopaque})"));
    try testing.expect(shouldEmitStdLog(&info_backend, .warn, "switch", "peer limit reached"));
    try testing.expect(shouldEmitStdLog(&info_backend, .warn, "quic_engine", "unexpected transport failure: {}"));
    try testing.expect(shouldEmitStdLog(&info_backend, .info, "node", "ready"));

    const debug_backend = Backend.init(.debug, .human);
    try testing.expect(shouldEmitStdLog(&debug_backend, .info, "switch", "opened peer stream"));
    try testing.expect(shouldEmitStdLog(&debug_backend, .warn, "quic_engine", "CONNECTION_CLOSE received: app_error={d}, code=0x{x}, reason=\"{s}\""));
    try testing.expect(shouldEmitStdLog(&debug_backend, .warn, "quic_engine", "read: stream closed, no leftover data (has_received={}, lsquic={?*anyopaque})"));
}

test "human std.log line includes scope and formatted message" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    var w = BufWriter{ .buf = &buf };

    renderHumanStdLogLine(&w, .info, "chain", "slot={d}", .{@as(u64, 42)});
    const line = w.getWritten();

    try testing.expect(std.mem.indexOf(u8, line, "[info ] [chain") != null);
    try testing.expect(std.mem.indexOf(u8, line, "slot=42") != null);
}

test "FileTransport writes expected contents" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const log_path = try tmpLogPath(testing.allocator, &tmp, "app.log");
    defer testing.allocator.free(log_path);

    var ft = FileTransport.init(std.testing.io, log_path, .debug, .{
        .max_size_bytes = 1024 * 1024,
        .max_files = 2,
        .daily = false,
    });
    try ft.start();
    defer ft.close();

    ft.writeStdLogLine(.info, "chain", "hello {d}", .{@as(u32, 7)});
    ft.flush();

    var buf: [512]u8 = undefined;
    const data = try tmp.dir.readFile(std.testing.io, "app.log", &buf);
    try testing.expect(std.mem.indexOf(u8, data, "[info ] [chain") != null);
    try testing.expect(std.mem.indexOf(u8, data, "hello 7") != null);
}
