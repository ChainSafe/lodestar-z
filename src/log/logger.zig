//! Structured logger for lodestar-z.
//!
//! Provides per-module, level-filtered logging with human-readable and JSON
//! output formats. Designed for zero overhead when a log level is disabled:
//! the level check is a single integer comparison, and format strings are
//! comptime — no work is done if the message won't be emitted.
//!
//! Integrates with `std.log` via a custom `logFn` — all existing `std.log.*`
//! calls are routed through the same output path, formatting, and level control.
//!
//! Uses the Zig 0.16 std.Io interface for thread-safe stderr output.
//!
//! ## Intended Logging Solution (C-logger)
//!
//! This module is the CANONICAL logging solution for lodestar-z. Use it instead
//! of `std.log.*` directly.
//!
//! Usage:
//!   const log_mod = @import("log");
//!   const logger = log_mod.logger(.chain);
//!   logger.info("block imported", .{ .slot = slot, .root = root });
//!
//! Available modules: chain, sync, network, api, execution, db, validator,
//!   bls, node, backfill, rest, metrics, default.
//!
//! ## Migration Plan (std.log → custom logger)
//!
//! Status (2026-03-28): ~357 `std.log.*` calls vs ~4 custom logger calls.
//! The custom logger routes through `logFn` so `std.log` calls already use
//! the same output path — this is a cosmetic + structured-logging migration.
//!
//! Priority order for migration:
//!   1. beacon_node.zig — high-visibility node lifecycle events
//!   2. chain/chain.zig — block import, finality, head update hot path
//!   3. fork_choice/fork_choice.zig — fork choice ops
//!   4. validator/ — signing and duty submission events
//!   5. Remaining files: replace `std.log.X(fmt, .{...})` with
//!      `log_mod.logger(.MODULE).X(fmt, .{...})` as they are touched.
//!
//! Why migrate?
//!   - Per-module log-level control (e.g. silence .db, verbose .chain)
//!   - Structured JSON output for log aggregation
//!   - Caller context (module tag) in every log line
//!   - `verbose` and `trace` levels not available in std.log

const std = @import("std");

/// Log severity levels, ordered from most to least severe.
/// Numeric values enable single-comparison filtering:
///   `if (@intFromEnum(msg_level) > @intFromEnum(configured_level)) return;`
///
/// Extends `std.log.Level` with `verbose` and `trace` for beacon node needs.
pub const Level = enum(u3) {
    err = 0,
    warn = 1,
    info = 2,
    verbose = 3,
    debug = 4,
    trace = 5,

    pub fn asText(self: Level) []const u8 {
        return switch (self) {
            .err => "error",
            .warn => "warn ",
            .info => "info ",
            .verbose => "verbo",
            .debug => "debug",
            .trace => "trace",
        };
    }

    /// Compact text for JSON (no padding).
    pub fn asJsonText(self: Level) []const u8 {
        return switch (self) {
            .err => "error",
            .warn => "warn",
            .info => "info",
            .verbose => "verbose",
            .debug => "debug",
            .trace => "trace",
        };
    }

    /// Parse a log level string (case-insensitive).
    pub fn parse(s: []const u8) ?Level {
        const eql = std.ascii.eqlIgnoreCase;
        if (eql(s, "error")) return .err;
        if (eql(s, "warn")) return .warn;
        if (eql(s, "info")) return .info;
        if (eql(s, "verbose")) return .verbose;
        if (eql(s, "debug")) return .debug;
        if (eql(s, "trace")) return .trace;
        return null;
    }

    /// Convert from std.log.Level to our extended Level.
    pub fn fromStd(std_level: std.log.Level) Level {
        return switch (std_level) {
            .err => .err,
            .warn => .warn,
            .info => .info,
            .debug => .debug,
        };
    }
};

/// Subsystem modules — each gets its own configurable log level.
pub const Module = enum(u5) {
    chain = 0,
    sync = 1,
    network = 2,
    api = 3,
    execution = 4,
    db = 5,
    validator = 6,
    bls = 7,
    node = 8,
    backfill = 9,
    rest = 10,
    metrics = 11,
    /// Catch-all for std.log calls without a recognized scope.
    default = 12,

    pub const count = @typeInfo(Module).@"enum".fields.len;

    pub fn asText(self: Module) []const u8 {
        return @tagName(self);
    }
};

/// Explicitly render a byte slice as text in structured context.
pub const Text = struct {
    bytes: []const u8,
};

/// Explicitly render a byte slice as truncated hexadecimal in structured context.
pub const Hex = struct {
    bytes: []const u8,
};

pub inline fn text(bytes: []const u8) Text {
    return .{ .bytes = bytes };
}

pub inline fn hex(bytes: []const u8) Hex {
    return .{ .bytes = bytes };
}

/// A module-scoped logger. Cheap to copy (two words).
///
/// Obtained via `GlobalLogger.logger(.chain)`. All log methods are
/// inlined so the level check happens at the call site.
pub const Logger = struct {
    module: Module,
    global: *GlobalLogger,

    pub inline fn err(self: Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }

    pub inline fn warn(self: Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, fmt, args);
    }

    pub inline fn info(self: Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }

    pub inline fn verbose(self: Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.verbose, fmt, args);
    }

    pub inline fn debug(self: Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }

    pub inline fn trace(self: Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.trace, fmt, args);
    }

    inline fn log(self: Logger, comptime level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) > @intFromEnum(self.global.getLevel(self.module))) return;
        self.global.writeLog(level, self.module, fmt, args);
    }
};

/// Global logger state. One instance per process, shared by all `Logger`s.
///
/// Holds per-module levels and output format. Uses `std.debug.lockStderr`
/// for thread-safe output following the Zig 0.16 I/O model.
pub const GlobalLogger = struct {
    /// Per-module log levels. Index by `@intFromEnum(module)`.
    module_levels: [Module.count]Level,
    /// Output format selector.
    format: Format,
    /// File transport (optional). When set, log lines are also written to file.
    file_transport: ?*FileTransport = null,

    pub const Format = enum {
        human,
        json,
    };

    /// Initialize with a default level for all modules.
    pub fn init(default_level: Level, format: Format) GlobalLogger {
        var gl: GlobalLogger = .{
            .module_levels = undefined,
            .format = format,
        };
        for (&gl.module_levels) |*l| l.* = default_level;
        return gl;
    }

    /// Get the effective log level for a module.
    pub inline fn getLevel(self: *const GlobalLogger, module: Module) Level {
        return self.module_levels[@intFromEnum(module)];
    }

    /// Set the log level for a specific module.
    pub fn setModuleLevel(self: *GlobalLogger, module: Module, level: Level) void {
        self.module_levels[@intFromEnum(module)] = level;
    }

    /// Set the log level for all modules.
    pub fn setLevel(self: *GlobalLogger, level: Level) void {
        for (&self.module_levels) |*l| l.* = level;
    }

    /// Get a scoped logger for a module.
    pub fn logger(self: *GlobalLogger, module: Module) Logger {
        return .{ .module = module, .global = self };
    }

    /// Attach a file transport for dual output (stderr + file).
    pub fn setFileTransport(self: *GlobalLogger, transport: *FileTransport) !void {
        try transport.start();
        self.file_transport = transport;
    }

    /// Write a formatted log line. Called by Logger after the level check passes.
    /// Uses std.debug.lockStderr for thread-safe output (Zig 0.16 I/O model).
    pub fn writeLog(self: *GlobalLogger, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        // Write to stderr (always)
        {
            var buffer: [8192]u8 = undefined;
            const stderr = std.debug.lockStderr(&buffer);
            defer std.debug.unlockStderr();
            const w = stderr.terminal().writer;

            switch (self.format) {
                .human => writeHuman(w, level, module, fmt, args),
                .json => writeJson(w, level, module, fmt, args),
            }
        }

        // Write to file transport if configured
        if (self.file_transport) |ft| {
            if (@intFromEnum(level) <= @intFromEnum(ft.level)) {
                ft.writeLogLine(level, module, fmt, args);
            }
        }
    }

    /// Write a formatted log line from std.log (unstructured format string + args).
    /// This is the bridge from std.log's format to our output.
    pub fn writeStdLog(self: *GlobalLogger, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        // Write to stderr
        {
            var buffer: [8192]u8 = undefined;
            const stderr = std.debug.lockStderr(&buffer);
            defer std.debug.unlockStderr();
            const w = stderr.terminal().writer;

            switch (self.format) {
                .human => writeHumanStdLog(w, level, module, fmt, args),
                .json => writeJsonStdLog(w, level, module, fmt, args),
            }
        }

        // Write to file transport if configured
        if (self.file_transport) |ft| {
            if (@intFromEnum(level) <= @intFromEnum(ft.level)) {
                ft.writeStdLogLine(level, module, fmt, args);
            }
        }
    }

    /// Write a human-readable log line (structured context).
    fn writeHuman(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        renderHumanLine(w, level, module, fmt, args);
    }

    /// Write a human-readable log line (std.log format — fmt + args is the message).
    fn writeHumanStdLog(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        renderHumanStdLogLine(w, level, module, fmt, args);
    }

    /// Write a JSON log line (structured context).
    fn writeJson(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        renderJsonLine(w, level, module, fmt, args);
    }

    /// Write a JSON log line (std.log format).
    fn writeJsonStdLog(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        renderJsonStdLogLine(w, level, module, fmt, args);
    }
};

fn renderHumanLine(w: anytype, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
    writeTimestampTo(w);
    w.print(" [{s}] [{s: <9}] {s}", .{ level.asText(), module.asText(), fmt }) catch {};
    writeContextHumanTo(w, args);
    w.writeAll("\n") catch {};
}

fn renderHumanStdLogLine(w: anytype, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
    writeTimestampTo(w);
    w.print(" [{s}] [{s: <9}] ", .{ level.asText(), module.asText() }) catch {};
    w.print(fmt, args) catch {};
    w.writeAll("\n") catch {};
}

fn renderJsonLine(w: anytype, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
    w.writeAll("{") catch {};
    writeTimestampJsonTo(w);
    w.print(",\"level\":\"{s}\",\"module\":\"{s}\",\"msg\":\"", .{
        level.asJsonText(),
        module.asText(),
    }) catch {};
    writeJsonEscapedTo(w, fmt);
    w.writeAll("\"") catch {};
    writeContextJsonTo(w, args);
    w.writeAll("}\n") catch {};
}

fn renderJsonStdLogLine(w: anytype, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
    w.writeAll("{") catch {};
    writeTimestampJsonTo(w);
    w.print(",\"level\":\"{s}\",\"module\":\"{s}\",\"msg\":\"", .{
        level.asJsonText(),
        module.asText(),
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

fn writeContextHumanTo(w: anytype, args: anytype) void {
    const ArgsType = @TypeOf(args);
    const args_info = @typeInfo(ArgsType);

    if (args_info != .@"struct") return;

    const fields = args_info.@"struct".fields;
    if (fields.len == 0) return;

    w.writeAll("  ") catch {};
    inline for (fields, 0..) |field, i| {
        if (i > 0) w.writeAll(", ") catch {};
        w.writeAll(field.name) catch {};
        w.writeAll("=") catch {};
        writeFieldHumanTo(w, @field(args, field.name));
    }
}

fn writeContextJsonTo(w: anytype, args: anytype) void {
    const ArgsType = @TypeOf(args);
    const args_info = @typeInfo(ArgsType);

    if (args_info != .@"struct") return;

    const fields = args_info.@"struct".fields;
    inline for (fields) |field| {
        w.print(",\"{s}\":", .{field.name}) catch {};
        writeFieldJsonTo(w, @field(args, field.name));
    }
}

fn writeFieldHumanTo(w: anytype, value: anytype) void {
    const T = @TypeOf(value);

    if (T == Text) {
        w.writeAll(value.bytes) catch {};
        return;
    }
    if (T == Hex) {
        writeHexTruncatedTo(w, value.bytes);
        return;
    }

    switch (@typeInfo(T)) {
        .int, .comptime_int => w.print("{d}", .{value}) catch {},
        .float, .comptime_float => w.print("{d:.3}", .{value}) catch {},
        .bool => w.writeAll(if (value) "true" else "false") catch {},
        .optional => {
            if (value) |v| {
                writeFieldHumanTo(w, v);
            } else {
                w.writeAll("null") catch {};
            }
        },
        .@"enum" => w.writeAll(@tagName(value)) catch {},
        .pointer => if (byteSlice(value)) |bytes| {
            writeBytesHumanTo(w, bytes);
        } else {
            w.print("{any}", .{value}) catch {};
        },
        .array => |arr| {
            if (arr.child == u8) {
                writeBytesHumanTo(w, &value);
            } else {
                w.print("[{d} items]", .{arr.len}) catch {};
            }
        },
        else => w.print("{any}", .{value}) catch {},
    }
}

fn writeFieldJsonTo(w: anytype, value: anytype) void {
    const T = @TypeOf(value);

    if (T == Text) {
        writeJsonStringTo(w, value.bytes);
        return;
    }
    if (T == Hex) {
        w.writeAll("\"") catch {};
        writeHexTruncatedTo(w, value.bytes);
        w.writeAll("\"") catch {};
        return;
    }

    switch (@typeInfo(T)) {
        .int, .comptime_int => w.print("{d}", .{value}) catch {},
        .float, .comptime_float => w.print("{d:.3}", .{value}) catch {},
        .bool => w.writeAll(if (value) "true" else "false") catch {},
        .optional => {
            if (value) |v| {
                writeFieldJsonTo(w, v);
            } else {
                w.writeAll("null") catch {};
            }
        },
        .@"enum" => writeJsonStringTo(w, @tagName(value)),
        .pointer => if (byteSlice(value)) |bytes| {
            writeBytesJsonTo(w, bytes);
        } else {
            writeJsonAnyStringTo(w, value);
        },
        .array => |arr| {
            if (arr.child == u8) {
                writeBytesJsonTo(w, &value);
            } else {
                writeJsonAnyStringTo(w, value);
            }
        },
        else => writeJsonAnyStringTo(w, value),
    }
}

fn writeBytesHumanTo(w: anytype, bytes: []const u8) void {
    if (isTextBytes(bytes)) {
        w.writeAll(bytes) catch {};
    } else {
        writeHexTruncatedTo(w, bytes);
    }
}

fn writeBytesJsonTo(w: anytype, bytes: []const u8) void {
    if (isTextBytes(bytes)) {
        writeJsonStringTo(w, bytes);
    } else {
        w.writeAll("\"") catch {};
        writeHexTruncatedTo(w, bytes);
        w.writeAll("\"") catch {};
    }
}

fn writeJsonAnyStringTo(w: anytype, value: anytype) void {
    var buf: [256]u8 = undefined;
    const rendered = std.fmt.bufPrint(&buf, "{any}", .{value}) catch "<fmt-overflow>";
    writeJsonStringTo(w, rendered);
}

fn writeJsonStringTo(w: anytype, s: []const u8) void {
    w.writeAll("\"") catch {};
    writeJsonEscapedTo(w, s);
    w.writeAll("\"") catch {};
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

fn writeHexTruncatedTo(w: anytype, bytes: []const u8) void {
    w.writeAll("0x") catch {};
    const display_len = @min(bytes.len, 4);
    for (bytes[0..display_len]) |b| {
        w.print("{x:0>2}", .{b}) catch {};
    }
    if (bytes.len > 4) {
        w.writeAll("..") catch {};
    }
}

fn isTextBytes(bytes: []const u8) bool {
    for (bytes) |b| switch (b) {
        '\t', ' '...'~' => {},
        else => return false,
    };
    return true;
}

fn byteSlice(value: anytype) ?[]const u8 {
    const T = @TypeOf(value);
    return switch (@typeInfo(T)) {
        .pointer => |ptr| blk: {
            if (ptr.size == .slice and ptr.child == u8) break :blk value;
            if (ptr.size == .one) {
                switch (@typeInfo(ptr.child)) {
                    .array => |arr| if (arr.child == u8) break :blk value[0..],
                    else => {},
                }
            }
            break :blk null;
        },
        else => null,
    };
}

/// Stack-allocated buffer writer for formatting log lines without heap allocation.
/// Replaces std.io.fixedBufferStream which was removed in Zig 0.16.
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

    /// Write a structured log line to the file.
    pub fn writeLogLine(self: *FileTransport, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        if (!self.started) return;
        var buf: [max_file_line_bytes]u8 = undefined;
        var w = BufWriter{ .buf = &buf };
        renderHumanLine(&w, level, module, fmt, args);
        self.enqueue(w.getWritten());
    }

    /// Write a std.log-style line to the file.
    pub fn writeStdLogLine(self: *FileTransport, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        if (!self.started) return;
        var buf: [max_file_line_bytes]u8 = undefined;
        var w = BufWriter{ .buf = &buf };
        renderHumanStdLogLine(&w, level, module, fmt, args);
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
        renderHumanStdLogLine(&w, .warn, .default, "file logger dropped {d} lines", .{dropped});
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
    max_size_bytes: u64 = 100 * 1024 * 1024, // 100MB
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

/// Custom std.log handler that routes all std.log.* calls through our GlobalLogger.
/// This bridges existing std.log calls (271 in the codebase) into our unified
/// logging output with timestamps, module tags, and format support.
pub fn stdLogFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    const log_root = @import("root.zig");
    const our_level = Level.fromStd(level);
    const module = mapScopeToModule(scope);

    if (@intFromEnum(our_level) > @intFromEnum(log_root.global.getLevel(module))) return;

    log_root.global.writeStdLog(our_level, module, format, args);
}

/// Map std.log scope enum literals to our Module enum.
/// Known scopes from the codebase are mapped to their corresponding modules.
/// Unknown scopes fall back to .default.
fn mapScopeToModule(comptime scope: @EnumLiteral()) Module {
    const scope_name = @tagName(scope);

    // Direct matches
    if (comptime std.mem.eql(u8, scope_name, "chain")) return .chain;
    if (comptime std.mem.eql(u8, scope_name, "sync")) return .sync;
    if (comptime std.mem.eql(u8, scope_name, "network")) return .network;
    if (comptime std.mem.eql(u8, scope_name, "api")) return .api;
    if (comptime std.mem.eql(u8, scope_name, "execution")) return .execution;
    if (comptime std.mem.eql(u8, scope_name, "db")) return .db;
    if (comptime std.mem.eql(u8, scope_name, "validator")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "bls")) return .bls;
    if (comptime std.mem.eql(u8, scope_name, "node")) return .node;
    if (comptime std.mem.eql(u8, scope_name, "backfill")) return .backfill;
    if (comptime std.mem.eql(u8, scope_name, "rest")) return .rest;
    if (comptime std.mem.eql(u8, scope_name, "metrics")) return .metrics;

    // Validator subsystem scopes → .validator
    if (comptime std.mem.eql(u8, scope_name, "validator_client")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "validator_store")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "attestation_service")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "block_service")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "sync_committee_service")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "doppelganger")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "prepare_beacon_proposer")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "interchange")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "keystore")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "chain_header_tracker")) return .validator;
    if (comptime std.mem.eql(u8, scope_name, "vc_api")) return .api;
    if (comptime std.mem.eql(u8, scope_name, "vc_clock")) return .validator;

    // API subsystem scopes
    if (comptime std.mem.eql(u8, scope_name, "http_server")) return .api;

    // Default scope or unknown
    return .default;
}


// ── Tests ────────────────────────────────────────────────────────────────

fn tmpLogPath(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir, filename: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, filename });
}

fn readTmpFile(tmp: *std.testing.TmpDir, filename: []const u8, buf: []u8) ![]u8 {
    return tmp.dir.readFile(std.testing.io, filename, buf);
}

test "Level.parse" {
    const testing = std.testing;
    try testing.expectEqual(Level.err, Level.parse("error").?);
    try testing.expectEqual(Level.warn, Level.parse("warn").?);
    try testing.expectEqual(Level.info, Level.parse("INFO").?);
    try testing.expectEqual(Level.verbose, Level.parse("Verbose").?);
    try testing.expectEqual(Level.debug, Level.parse("debug").?);
    try testing.expectEqual(Level.trace, Level.parse("TRACE").?);
    try testing.expectEqual(@as(?Level, null), Level.parse("unknown"));
}

test "Level ordering" {
    const testing = std.testing;
    try testing.expect(@intFromEnum(Level.err) < @intFromEnum(Level.warn));
    try testing.expect(@intFromEnum(Level.warn) < @intFromEnum(Level.info));
    try testing.expect(@intFromEnum(Level.info) < @intFromEnum(Level.verbose));
    try testing.expect(@intFromEnum(Level.verbose) < @intFromEnum(Level.debug));
    try testing.expect(@intFromEnum(Level.debug) < @intFromEnum(Level.trace));
}

test "Level.fromStd" {
    const testing = std.testing;
    try testing.expectEqual(Level.err, Level.fromStd(.err));
    try testing.expectEqual(Level.warn, Level.fromStd(.warn));
    try testing.expectEqual(Level.info, Level.fromStd(.info));
    try testing.expectEqual(Level.debug, Level.fromStd(.debug));
}

test "Module.count" {
    try std.testing.expectEqual(@as(usize, 13), Module.count);
}

test "GlobalLogger init and level control" {
    var gl = GlobalLogger.init(.info, .human);

    try std.testing.expectEqual(Level.info, gl.getLevel(.chain));
    try std.testing.expectEqual(Level.info, gl.getLevel(.bls));

    gl.setModuleLevel(.bls, .trace);
    try std.testing.expectEqual(Level.trace, gl.getLevel(.bls));
    try std.testing.expectEqual(Level.info, gl.getLevel(.chain));

    gl.setLevel(.warn);
    try std.testing.expectEqual(Level.warn, gl.getLevel(.bls));
    try std.testing.expectEqual(Level.warn, gl.getLevel(.chain));
}

test "Logger level filtering" {
    var gl = GlobalLogger.init(.info, .human);
    const log = gl.logger(.chain);

    log.info("hello", .{});
    log.err("error msg", .{});
    log.warn("warn msg", .{});
    log.debug("should not appear", .{});
}

test "Logger structured context" {
    var gl = GlobalLogger.init(.trace, .human);
    const log = gl.logger(.chain);
    log.info("block imported", .{
        .slot = @as(u64, 12345),
        .proposer = @as(u32, 42),
        .finalized = true,
    });
}

test "Logger JSON output" {
    var gl = GlobalLogger.init(.trace, .json);
    const log = gl.logger(.sync);
    log.warn("sync stalled", .{
        .slot = @as(u64, 9999),
        .peers = @as(u32, 3),
    });
}

test "Per-module level control with logging" {
    var gl = GlobalLogger.init(.info, .human);
    gl.setModuleLevel(.bls, .trace);

    const bls_log = gl.logger(.bls);
    const chain_log = gl.logger(.chain);

    bls_log.trace("verify timing", .{ .ms = @as(u32, 5) });
    chain_log.trace("should not appear", .{});
}

test "Logger hex truncation" {
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    const root = [_]u8{ 0xab, 0x12, 0xcd, 0x34, 0xef, 0x56, 0x78, 0x9a } ** 4;
    GlobalLogger.writeHuman(&writer, .info, .chain, "block", .{ .root = root });
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "root=0xab12cd34..") != null);
}

test "Logger empty context" {
    var gl = GlobalLogger.init(.trace, .human);
    const log = gl.logger(.node);
    log.info("started", .{});
}

test "mapScopeToModule" {
    // Direct module matches
    try std.testing.expectEqual(Module.chain, mapScopeToModule(.chain));
    try std.testing.expectEqual(Module.sync, mapScopeToModule(.sync));
    try std.testing.expectEqual(Module.validator, mapScopeToModule(.validator));

    // Validator subsystem scopes
    try std.testing.expectEqual(Module.validator, mapScopeToModule(.validator_client));
    try std.testing.expectEqual(Module.validator, mapScopeToModule(.block_service));
    try std.testing.expectEqual(Module.api, mapScopeToModule(.http_server));

    // Unknown scope → default
    try std.testing.expectEqual(Module.default, mapScopeToModule(.unknown_scope));
    try std.testing.expectEqual(Module.default, mapScopeToModule(.default));
}

test "writeHuman renders module level and structured context" {
    var buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);

    GlobalLogger.writeHuman(&writer, .info, .chain, "block imported", .{
        .slot = @as(u64, 12345),
        .finalized = true,
        .root = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee },
    });

    const out = writer.buffered();
    try std.testing.expect(out.len > 0);
    try std.testing.expect(out[out.len - 1] == '\n');
    try std.testing.expect(std.mem.indexOf(u8, out, " [info ] [chain    ] block imported  slot=12345, finalized=true, root=0xaabbccdd..") != null);
}

test "writeJson escapes message and emits JSON fields" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    GlobalLogger.writeJson(&aw.writer, .warn, .sync, "quote\" slash\\ newline\n", .{
        .slot = @as(u64, 7),
        .missing = @as(?u64, null),
    });

    const out = aw.written();
    try std.testing.expect(std.mem.startsWith(u8, out, "{\"ts\":\""));
    try std.testing.expect(std.mem.indexOf(u8, out, "\"level\":\"warn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"module\":\"sync\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"msg\":\"quote\\\" slash\\\\ newline\\n\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"slot\":7") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"missing\":null") != null);
    try std.testing.expect(out[out.len - 1] == '\n');
}

test "structured bytes render text by default and wrappers keep explicit hex" {
    var buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);

    GlobalLogger.writeHuman(&writer, .info, .node, "started", .{
        .path = "/tmp/lodestar",
        .root = hex(&[_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01 }),
    });

    const out = writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "path=/tmp/lodestar") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "root=0xdeadbeef..") != null);
}

test "FileTransport writes expected contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const log_path = try tmpLogPath(std.testing.allocator, &tmp, "test.log");
    defer std.testing.allocator.free(log_path);

    var ft = FileTransport.init(std.testing.io, log_path, .debug, .{
        .max_size_bytes = 1024 * 1024,
        .max_files = 3,
        .daily = false,
    });
    try ft.start();
    defer ft.close();

    ft.writeLogLine(.info, .chain, "block imported", .{
        .slot = @as(u64, 12345),
        .root = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01 },
    });
    ft.writeStdLogLine(.warn, .sync, "sync stalled peers={d}", .{@as(u32, 3)});
    ft.flush();

    var read_buf: [4096]u8 = undefined;
    const contents = try readTmpFile(&tmp, "test.log", &read_buf);

    try std.testing.expect(ft.bytes_written > 0);
    try std.testing.expect(std.mem.indexOf(u8, contents, " [info ] [chain    ] block imported  slot=12345, root=0xdeadbeef..") != null);
    try std.testing.expect(std.mem.indexOf(u8, contents, " [warn ] [sync     ] sync stalled peers=3") != null);
}

test "FileTransport handles concurrent producers" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const log_path = try tmpLogPath(std.testing.allocator, &tmp, "concurrent.log");
    defer std.testing.allocator.free(log_path);

    var ft = FileTransport.init(std.testing.io, log_path, .trace, .{
        .max_size_bytes = 1024 * 1024,
        .max_files = 2,
        .daily = false,
    });
    try ft.start();
    defer ft.close();

    const worker_count = 4;
    const lines_per_worker = 32;

    const Ctx = struct {
        ft: *FileTransport,
        offset: usize,

        fn run(ctx: @This()) void {
            for (0..lines_per_worker) |i| {
                ctx.ft.writeStdLogLine(.info, .chain, "worker={d} line={d}", .{ ctx.offset, i });
            }
        }
    };

    var threads: [worker_count]std.Thread = undefined;
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, Ctx.run, .{Ctx{ .ft = &ft, .offset = i }});
    }
    for (threads) |thread| thread.join();

    ft.flush();

    var read_buf: [16384]u8 = undefined;
    const contents = try readTmpFile(&tmp, "concurrent.log", &read_buf);

    var count: usize = 0;
    for (contents) |c| {
        if (c == '\n') count += 1;
    }

    try std.testing.expectEqual(@as(usize, worker_count * lines_per_worker), count);
    try std.testing.expect(std.mem.indexOf(u8, contents, "dropped") == null);
}

test "GlobalLogger file transport honors file level threshold" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const log_path = try tmpLogPath(std.testing.allocator, &tmp, "threshold.log");
    defer std.testing.allocator.free(log_path);

    var ft = FileTransport.init(std.testing.io, log_path, .warn, .{
        .max_size_bytes = 1024 * 1024,
        .max_files = 2,
        .daily = false,
    });
    defer ft.close();

    var gl = GlobalLogger.init(.trace, .human);
    try gl.setFileTransport(&ft);

    const log = gl.logger(.chain);
    log.info("suppressed info", .{});
    log.warn("captured warn", .{ .peers = @as(u32, 4) });
    ft.flush();

    var read_buf: [2048]u8 = undefined;
    const contents = try readTmpFile(&tmp, "threshold.log", &read_buf);

    try std.testing.expect(std.mem.indexOf(u8, contents, "suppressed info") == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, "captured warn  peers=4") != null);
}

test "FileTransport rotates and preserves old contents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const log_path = try tmpLogPath(std.testing.allocator, &tmp, "rotate.log");
    defer std.testing.allocator.free(log_path);

    var ft = FileTransport.init(std.testing.io, log_path, .trace, .{
        .max_size_bytes = 1,
        .max_files = 2,
        .daily = false,
    });
    try ft.start();
    defer ft.close();

    ft.current_date = .{ .year = 2024, .month = 1, .day = 2 };

    ft.writeLogLine(.info, .chain, "first", .{ .slot = @as(u64, 1) });
    ft.writeLogLine(.info, .chain, "second", .{ .slot = @as(u64, 2) });
    ft.flush();

    var current_buf: [2048]u8 = undefined;
    const current = try readTmpFile(&tmp, "rotate.log", &current_buf);
    var rotated_buf: [2048]u8 = undefined;
    const rotated = try readTmpFile(&tmp, "rotate.log.2024-01-02", &rotated_buf);

    try std.testing.expect(std.mem.indexOf(u8, rotated, "first  slot=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, current, "second  slot=2") != null);
}

test "FileTransport cleanOldFiles keeps newest rotated files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const log_path = try tmpLogPath(std.testing.allocator, &tmp, "app.log");
    defer std.testing.allocator.free(log_path);

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "app.log.2024-01-01", .data = "a" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "app.log.2024-01-02", .data = "b" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "app.log.2024-01-03", .data = "c" });

    var ft = FileTransport.init(std.testing.io, log_path, .trace, .{
        .max_size_bytes = 1024,
        .max_files = 2,
        .daily = false,
    });
    try ft.start();
    defer ft.close();

    ft.cleanOldFiles();

    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "app.log.2024-01-01", .{}));

    {
        var f = try tmp.dir.openFile(std.testing.io, "app.log.2024-01-02", .{});
        f.close(std.testing.io);
    }
    {
        var f = try tmp.dir.openFile(std.testing.io, "app.log.2024-01-03", .{});
        f.close(std.testing.io);
    }
}

/// Get current wall-clock time as epoch seconds.
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
