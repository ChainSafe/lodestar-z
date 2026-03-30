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
    pub fn setFileTransport(self: *GlobalLogger, transport: *FileTransport) void {
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
        writeTimestamp(w);
        w.print(" [{s}] [{s: <9}] {s}", .{ level.asText(), module.asText(), fmt }) catch {};
        writeContextHuman(w, args);
        w.writeAll("\n") catch {};
    }

    /// Write a human-readable log line (std.log format — fmt + args is the message).
    fn writeHumanStdLog(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        writeTimestamp(w);
        w.print(" [{s}] [{s: <9}] ", .{ level.asText(), module.asText() }) catch {};
        w.print(fmt, args) catch {};
        w.writeAll("\n") catch {};
    }

    /// Write a JSON log line (structured context).
    fn writeJson(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        w.writeAll("{") catch {};
        writeTimestampJson(w);
        w.print(",\"level\":\"{s}\",\"module\":\"{s}\",\"msg\":\"", .{
            level.asJsonText(),
            module.asText(),
        }) catch {};
        // fmt is comptime but may contain backslashes/quotes; escape for valid JSON
        writeJsonEscaped(w, fmt);
        w.writeAll("\"") catch {};
        writeContextJson(w, args);
        w.writeAll("}\n") catch {};
    }

    /// Write a JSON log line (std.log format).
    fn writeJsonStdLog(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        w.writeAll("{") catch {};
        writeTimestampJson(w);
        w.print(",\"level\":\"{s}\",\"module\":\"{s}\",\"msg\":\"", .{
            level.asJsonText(),
            module.asText(),
        }) catch {};
        // Format msg into temporary buffer, then escape for valid JSON
        var msg_buf: [4096]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, fmt, args) catch fmt;
        writeJsonEscaped(w, msg);
        w.writeAll("\"}\n") catch {};
    }

    /// Format timestamp as "Mar-27 20:30:00"
    fn writeTimestamp(w: *std.Io.Writer) void {
        const ts = getRealtimeSeconds();
        const epoch_secs = ts.secs;
        const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
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

    /// Format timestamp as ISO 8601 for JSON.
    fn writeTimestampJson(w: *std.Io.Writer) void {
        const ts = getRealtimeSeconds();
        const epoch_secs = ts.secs;
        const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
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

    /// Write context struct fields as `  key=value, key2=value2` (human format).
    fn writeContextHuman(w: *std.Io.Writer, args: anytype) void {
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
            writeFieldHuman(w, @field(args, field.name));
        }
    }

    /// Write context struct fields as JSON key-value pairs.
    fn writeContextJson(w: *std.Io.Writer, args: anytype) void {
        const ArgsType = @TypeOf(args);
        const args_info = @typeInfo(ArgsType);

        if (args_info != .@"struct") return;

        const fields = args_info.@"struct".fields;
        inline for (fields) |field| {
            w.print(",\"{s}\":", .{field.name}) catch {};
            writeFieldJson(w, @field(args, field.name));
        }
    }

    /// Format a single context field value for human output.
    fn writeFieldHuman(w: *std.Io.Writer, value: anytype) void {
        const T = @TypeOf(value);
        const info = @typeInfo(T);

        switch (info) {
            .int, .comptime_int => w.print("{d}", .{value}) catch {},
            .float, .comptime_float => w.print("{d:.3}", .{value}) catch {},
            .bool => w.writeAll(if (value) "true" else "false") catch {},
            .optional => {
                if (value) |v| {
                    writeFieldHuman(w, v);
                } else {
                    w.writeAll("null") catch {};
                }
            },
            .@"enum" => w.writeAll(@tagName(value)) catch {},
            .pointer => |ptr| {
                if (ptr.size == .slice) {
                    if (ptr.child == u8) {
                        writeHexTruncated(w, value);
                    } else {
                        w.print("[{d} items]", .{value.len}) catch {};
                    }
                } else {
                    w.print("{any}", .{value}) catch {};
                }
            },
            .array => |arr| {
                if (arr.child == u8) {
                    writeHexTruncated(w, &value);
                } else {
                    w.print("[{d} items]", .{arr.len}) catch {};
                }
            },
            else => w.print("{any}", .{value}) catch {},
        }
    }

    /// Format a single context field value for JSON output.
    fn writeFieldJson(w: *std.Io.Writer, value: anytype) void {
        const T = @TypeOf(value);
        const info = @typeInfo(T);

        switch (info) {
            .int, .comptime_int => w.print("{d}", .{value}) catch {},
            .float, .comptime_float => w.print("{d:.3}", .{value}) catch {},
            .bool => w.writeAll(if (value) "true" else "false") catch {},
            .optional => {
                if (value) |v| {
                    writeFieldJson(w, v);
                } else {
                    w.writeAll("null") catch {};
                }
            },
            .@"enum" => w.print("\"{s}\"", .{@tagName(value)}) catch {},
            .pointer => |ptr| {
                if (ptr.size == .slice and ptr.child == u8) {
                    w.writeAll("\"") catch {};
                    writeHexTruncated(w, value);
                    w.writeAll("\"") catch {};
                } else {
                    w.print("\"{any}\"", .{value}) catch {};
                }
            },
            .array => |arr| {
                if (arr.child == u8) {
                    w.writeAll("\"") catch {};
                    writeHexTruncated(w, &value);
                    w.writeAll("\"") catch {};
                } else {
                    w.print("\"{any}\"", .{value}) catch {};
                }
            },
            else => w.print("\"{any}\"", .{value}) catch {},
        }
    }

    /// Write a string with JSON escaping for special characters.
    fn writeJsonEscaped(w: *std.Io.Writer, s: []const u8) void {
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

    /// Write a byte slice as 0x-prefixed hex, truncated to first 4 bytes (8 hex chars).
    fn writeHexTruncated(w: *std.Io.Writer, bytes: []const u8) void {
        w.writeAll("0x") catch {};
        const display_len = @min(bytes.len, 4);
        for (bytes[0..display_len]) |b| {
            w.print("{x:0>2}", .{b}) catch {};
        }
        if (bytes.len > 4) {
            w.writeAll("..") catch {};
        }
    }
};

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

/// Simple spinlock that doesn't require std.Io.
/// Used by FileTransport for thread-safe file writes.
const SpinLock = struct {
    state: std.atomic.Value(u32),

    const init: SpinLock = .{ .state = .init(0) };

    fn lock(self: *SpinLock) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *SpinLock) void {
        self.state.store(0, .release);
    }
};

/// File transport for writing log lines to a file with optional rotation.
/// Thread-safe: uses a spinlock for file writes.
/// Uses raw Linux syscalls for I/O to avoid dependency on std.Io instance.
pub const FileTransport = struct {
    io: std.Io,
    file: std.Io.File,
    path: []const u8,
    level: Level,
    rotation: RotationConfig,
    bytes_written: u64,
    current_date: Date,
    mutex: SpinLock,

    pub const Date = struct {
        year: u32,
        month: u8,
        day: u8,

        pub fn eql(a: Date, b: Date) bool {
            return a.year == b.year and a.month == b.month and a.day == b.day;
        }
    };

    pub fn init(io: std.Io, path: []const u8, level: Level, rotation: RotationConfig) !FileTransport {
        const file = try openLogFile(io, path);
        const bytes_written = (try file.stat(io)).size;

        return .{
            .io = io,
            .file = file,
            .path = path,
            .level = level,
            .rotation = rotation,
            .bytes_written = bytes_written,
            .current_date = getCurrentDate(),
            .mutex = .init,
        };
    }

    /// Write a structured log line to the file.
    pub fn writeLogLine(self: *FileTransport, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.maybeRotate();

        var buf: [8192]u8 = undefined;
        var w = BufWriter{ .buf = &buf };

        writeTimestampBuf(&w);
        w.print(" [{s}] [{s: <9}] {s}", .{ level.asText(), module.asText(), fmt }) catch {};
        writeContextHumanBuf(&w, args);
        w.writeAll("\n") catch {};

        const written = w.getWritten();
        self.file.writePositionalAll(self.io, written, self.bytes_written) catch return;
        self.bytes_written += written.len;
    }

    /// Write a std.log-style line to the file.
    pub fn writeStdLogLine(self: *FileTransport, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.maybeRotate();

        var buf: [8192]u8 = undefined;
        var w = BufWriter{ .buf = &buf };

        writeTimestampBuf(&w);
        w.print(" [{s}] [{s: <9}] ", .{ level.asText(), module.asText() }) catch {};
        w.print(fmt, args) catch {};
        w.writeAll("\n") catch {};

        const written = w.getWritten();
        self.file.writePositionalAll(self.io, written, self.bytes_written) catch return;
        self.bytes_written += written.len;
    }

    /// Check if rotation is needed and perform it.
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
        self.file.close(self.io);

        // Build dated name: path.YYYY-MM-DD
        var dated_buf: [512]u8 = undefined;
        const dated_name = std.fmt.bufPrint(&dated_buf, "{s}.{d}-{d:0>2}-{d:0>2}", .{
            self.path,
            self.current_date.year,
            self.current_date.month,
            self.current_date.day,
        }) catch self.path;

        // Rename current → dated
        std.Io.Dir.rename(std.Io.Dir.cwd(), self.path, std.Io.Dir.cwd(), dated_name, self.io) catch {};

        // Clean up old rotated files
        self.cleanOldFiles();

        // Open new file
        self.file = openLogFile(self.io, self.path) catch return;
        self.bytes_written = 0;
        self.current_date = now;
    }

    fn cleanOldFiles(self: *FileTransport) void {
        const dir_path = std.fs.path.dirname(self.path) orelse ".";
        const base_name = std.fs.path.basename(self.path);

        var dir = std.Io.Dir.cwd().openDir(self.io, dir_path, .{ .iterate = true }) catch return;
        defer dir.close(self.io);

        // Collect matching rotated log filenames
        var names: [256][256]u8 = undefined;
        var name_lens: [256]usize = undefined;
        var name_count: usize = 0;

        var iter = dir.iterate();
        while (iter.next(self.io) catch null) |entry| {
            const entry_name = entry.name;
            if (!std.mem.startsWith(u8, entry_name, base_name)) continue;
            if (entry_name.len <= base_name.len + 1) continue;
            if (entry_name[base_name.len] != '.') continue;
            const suffix = entry_name[base_name.len + 1 ..];
            if (suffix.len == 10 and suffix[4] == '-' and suffix[7] == '-') {
                if (name_count < 256) {
                    const copy_len = @min(entry_name.len, 256);
                    @memcpy(names[name_count][0..copy_len], entry_name[0..copy_len]);
                    name_lens[name_count] = copy_len;
                    name_count += 1;
                }
            }
        }

        if (name_count <= self.rotation.max_files) return;

        // Sort ascending (oldest first by date suffix)
        for (1..name_count) |i| {
            const key_name = names[i];
            const key_len = name_lens[i];
            var j: usize = i;
            while (j > 0) {
                const order = std.mem.order(u8, names[j - 1][0..name_lens[j - 1]], key_name[0..key_len]);
                if (order != .gt) break;
                names[j] = names[j - 1];
                name_lens[j] = name_lens[j - 1];
                j -= 1;
            }
            names[j] = key_name;
            name_lens[j] = key_len;
        }

        // Delete oldest files exceeding max_files
        const to_delete = name_count - self.rotation.max_files;
        for (0..to_delete) |i| {
            const fname = names[i][0..name_lens[i]];
            dir.deleteFile(self.io, fname) catch {};
        }
    }

    pub fn close(self: *FileTransport) void {
        self.file.close(self.io);
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





/// Helpers for writing timestamps to a std.io.FixedBufferStream writer
/// (used by FileTransport which can't use std.Io.Writer).
fn writeTimestampBuf(w: anytype) void {
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

fn writeContextHumanBuf(w: anytype, args: anytype) void {
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
        writeFieldHumanBuf(w, @field(args, field.name));
    }
}

fn writeFieldHumanBuf(w: anytype, value: anytype) void {
    const T = @TypeOf(value);
    const info = @typeInfo(T);

    switch (info) {
        .int, .comptime_int => w.print("{d}", .{value}) catch {},
        .float, .comptime_float => w.print("{d:.3}", .{value}) catch {},
        .bool => w.writeAll(if (value) "true" else "false") catch {},
        .optional => {
            if (value) |v| {
                writeFieldHumanBuf(w, v);
            } else {
                w.writeAll("null") catch {};
            }
        },
        .@"enum" => w.writeAll(@tagName(value)) catch {},
        .pointer => |ptr| {
            if (ptr.size == .slice and ptr.child == u8) {
                w.writeAll("0x") catch {};
                const display_len = @min(value.len, 4);
                for (value[0..display_len]) |b| {
                    w.print("{x:0>2}", .{b}) catch {};
                }
                if (value.len > 4) w.writeAll("..") catch {};
            } else {
                w.print("{any}", .{value}) catch {};
            }
        },
        .array => |arr| {
            if (arr.child == u8) {
                w.writeAll("0x") catch {};
                const display_len = @min(value.len, 4);
                for (value[0..display_len]) |b| {
                    w.print("{x:0>2}", .{b}) catch {};
                }
                if (value.len > 4) w.writeAll("..") catch {};
            } else {
                w.print("[{d} items]", .{arr.len}) catch {};
            }
        },
        else => w.print("{any}", .{value}) catch {},
    }
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
    var gl = GlobalLogger.init(.trace, .human);
    const log = gl.logger(.chain);
    const root = [_]u8{ 0xab, 0x12, 0xcd, 0x34, 0xef, 0x56, 0x78, 0x9a } ** 4;
    log.info("block", .{ .root = root });
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

test "FileTransport basic write" {
    const tmp_path = "/tmp/lodestar-z-test-log.log";
    var ft = try FileTransport.init(tmp_path, .debug, .{
        .max_size_bytes = 1024 * 1024,
        .max_files = 3,
        .daily = false,
    });
    defer ft.close();
    defer {
        // Clean up using debug_io
        const io = std.Options.debug_io;
        std.Io.Dir.cwd().deleteFile(io, tmp_path) catch {};
    }

    ft.writeLogLine(.info, .chain, "block imported", .{
        .slot = @as(u64, 12345),
    });

    ft.writeStdLogLine(.warn, .sync, "sync stalled peers={d}", .{@as(u32, 3)});

    // Verify bytes were written
    try std.testing.expect(ft.bytes_written > 0);
}

test "FileTransport size-based rotation" {
    const tmp_dir = "/tmp/lodestar-z-test-rotation";
    // Create dir (ignore error if already exists)
    std.fs.makeDirAbsolute(tmp_dir) catch {};

    const log_path = tmp_dir ++ "/test.log";

    // Use a tiny max size to trigger rotation
    var ft = try FileTransport.init(log_path, .trace, .{
        .max_size_bytes = 100, // 100 bytes — will trigger quickly
        .max_files = 2,
        .daily = false,
    });

    // Write enough to exceed max size
    for (0..10) |i| {
        ft.writeLogLine(.info, .chain, "message number", .{ .i = i });
    }

    ft.close();

    // Count files using std.fs
    var file_count: u32 = 0;
    {
        var dir = try std.fs.openDirAbsolute(tmp_dir, .{ .iterate = true });
        defer dir.close();
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;
            file_count += 1;
        }
    }
    // Should have current file + at least 1 rotated file
    try std.testing.expect(file_count >= 1);
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
