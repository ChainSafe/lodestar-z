//! Structured logger for lodestar-z.
//!
//! Provides per-module, level-filtered logging with human-readable and JSON
//! output formats. Designed for zero overhead when a log level is disabled:
//! the level check is a single integer comparison, and format strings are
//! comptime — no work is done if the message won't be emitted.
//!
//! Uses the Zig 0.16 std.Io interface for thread-safe stderr output.
//!
//! Usage:
//!   const log_mod = @import("log");
//!   const logger = log_mod.logger(.chain);
//!   logger.info("block imported", .{ .slot = slot, .root = root });

const std = @import("std");

/// Log severity levels, ordered from most to least severe.
/// Numeric values enable single-comparison filtering:
///   `if (@intFromEnum(msg_level) > @intFromEnum(configured_level)) return;`
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
};

/// Subsystem modules — each gets its own configurable log level.
pub const Module = enum(u4) {
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

    /// Write a formatted log line. Called by Logger after the level check passes.
    /// Uses std.debug.lockStderr for thread-safe output (Zig 0.16 I/O model).
    pub fn writeLog(self: *GlobalLogger, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        var buffer: [8192]u8 = undefined;
        const stderr = std.debug.lockStderr(&buffer);
        defer std.debug.unlockStderr();
        const w = stderr.terminal().writer;

        switch (self.format) {
            .human => writeHuman(w, level, module, fmt, args),
            .json => writeJson(w, level, module, fmt, args),
        }
    }

    /// Write a human-readable log line.
    fn writeHuman(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        // Timestamp
        writeTimestamp(w);
        // Level + module (padded)
        w.print(" [{s}] [{s: <9}] {s}", .{ level.asText(), module.asText(), fmt }) catch {};
        // Context fields
        writeContextHuman(w, args);
        w.writeAll("\n") catch {};
    }

    /// Write a JSON log line.
    fn writeJson(w: *std.Io.Writer, level: Level, module: Module, comptime fmt: []const u8, args: anytype) void {
        w.writeAll("{") catch {};
        writeTimestampJson(w);
        w.print(",\"level\":\"{s}\",\"module\":\"{s}\",\"msg\":\"{s}\"", .{
            level.asJsonText(),
            module.asText(),
            fmt,
        }) catch {};
        writeContextJson(w, args);
        w.writeAll("}\n") catch {};
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

test "Module.count" {
    try std.testing.expectEqual(@as(usize, 12), Module.count);
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

/// Get current wall-clock time as epoch seconds.
/// Uses CLOCK_REALTIME on Linux, fallback for other platforms.
fn getRealtimeSeconds() struct { secs: u64 } {
    if (@hasDecl(std.os, "linux")) {
        var ts: std.os.linux.timespec = undefined;
        const rc = std.os.linux.clock_gettime(std.os.linux.CLOCK.REALTIME, &ts);
        if (rc == 0) {
            return .{ .secs = @intCast(ts.sec) };
        }
    }
    return .{ .secs = 0 };
}
