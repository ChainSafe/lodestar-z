const std = @import("std");
const time = @import("time");

fn defaultIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub const LogLevel = enum {
    err,
    warn,
    info,
    verbose,
    debug,
    trace,

    fn enabled(self: LogLevel, level: LogLevel) bool {
        return @intFromEnum(self) <= @intFromEnum(level);
    }

    fn asText(self: LogLevel) []const u8 {
        return switch (self) {
            .err => "error",
            .warn => "warn",
            .info => "info",
            .verbose => "verbose",
            .debug => "debug",
            .trace => "trace",
        };
    }

    fn color(self: LogLevel) []const u8 {
        return switch (self) {
            .err => Colors.red,
            .warn => Colors.yellow,
            .info => Colors.green,
            .verbose => Colors.gray,
            .debug => Colors.cyan,
            .trace => Colors.white,
        };
    }
};

const Colors = struct {
    const reset = "\x1b[0m";

    const red = "\x1b[31m";
    const yellow = "\x1b[33m";
    const green = "\x1b[32m";
    const cyan = "\x1b[36m";
    const white = "\x1b[37m";
    const gray = "\x1b[90m";
};

fn formatLine(buf: []u8, module: ?[]const u8, secs: f64, level: LogLevel, comptime fmt: []const u8, args: anytype) []const u8 {
    const marker = Colors.reset ++ "…[trunc]\n";
    var w = std.Io.Writer.fixed(buf[0 .. buf.len - marker.len]);
    const padding_between_info = 30;
    const m = module orelse "";
    const used = m.len + level.asText().len;
    const padding_length: usize = if (used >= padding_between_info) 0 else padding_between_info - used;
    var padding_storage: [padding_between_info]u8 = undefined;
    const padding = padding_storage[0..padding_length];
    @memset(padding, ' ');

    w.print("[{d:.3}s] [{s}] {s}{s}{s}:{s} " ++ fmt ++ "\n", .{ secs, m, padding, level.color(), level.asText(), Colors.reset } ++ args) catch |err| {
        std.debug.assert(err == error.WriteFailed);
        @memcpy(buf[w.end..][0..marker.len], marker);
        return buf[0 .. w.end + marker.len];
    };
    return buf[0..w.end];
}

fn writeStderr(bytes: []const u8) void {
    var buf: [4096]u8 = undefined;
    const stderr = std.debug.lockStderr(&buf);
    defer std.debug.unlockStderr();
    nosuspend stderr.file_writer.interface.writeAll(bytes) catch {};
}

pub const LoggerConfig = struct {
    active_level: LogLevel,
    start: std.Io.Timestamp,

    pub fn init(active_level: LogLevel) LoggerConfig {
        return .{
            .active_level = active_level,
            .start = time.start(defaultIo()),
        };
    }

    fn log(self: *const LoggerConfig, module: ?[]const u8, level: LogLevel, comptime fmt: []const u8, args: anytype) void {
        if (!level.enabled(self.active_level)) return;
        var buf: [4096]u8 = undefined;
        const secs = time.durationSeconds(time.since(defaultIo(), self.start));
        const line = formatLine(&buf, module, secs, level, fmt, args);
        writeStderr(line);
    }

    pub fn logger(self: *const LoggerConfig, module: ?[]const u8) ModuleLogger {
        return .{
            .config = self,
            .module = module,
        };
    }
};

pub const ModuleLogger = struct {
    config: *const LoggerConfig,
    module: ?[]const u8,

    pub fn err(self: *const ModuleLogger, comptime fmt: []const u8, args: anytype) void {
        self.config.log(self.module, .err, fmt, args);
    }

    pub fn warn(self: *const ModuleLogger, comptime fmt: []const u8, args: anytype) void {
        self.config.log(self.module, .warn, fmt, args);
    }

    pub fn info(self: *const ModuleLogger, comptime fmt: []const u8, args: anytype) void {
        self.config.log(self.module, .info, fmt, args);
    }

    pub fn verbose(self: *const ModuleLogger, comptime fmt: []const u8, args: anytype) void {
        self.config.log(self.module, .verbose, fmt, args);
    }

    pub fn debug(self: *const ModuleLogger, comptime fmt: []const u8, args: anytype) void {
        self.config.log(self.module, .debug, fmt, args);
    }

    pub fn trace(self: *const ModuleLogger, comptime fmt: []const u8, args: anytype) void {
        self.config.log(self.module, .trace, fmt, args);
    }
};

test "enabled" {
    try std.testing.expectEqual(true, LogLevel.err.enabled(.info));
    try std.testing.expectEqual(true, LogLevel.info.enabled(.info));
    try std.testing.expectEqual(false, LogLevel.debug.enabled(.info));
}

test "asText" {
    try std.testing.expectEqualStrings("error", LogLevel.err.asText());
    try std.testing.expectEqualStrings("verbose", LogLevel.verbose.asText());
}

test "formatLine" {
    var buf: [256]u8 = undefined;
    const secs = 2.347;
    const line = formatLine(&buf, "test-module", secs, .info, "hello {s} {d}", .{ "world", 42 });
    try std.testing.expectEqualStrings("[2.347s] [test-module] " ++ (" " ** 15) ++ Colors.green ++ "info:" ++ Colors.reset ++ " hello world 42\n", line);
    const line_no_module = formatLine(&buf, null, secs, .info, "hello {s} {d}", .{ "world", 42 });
    try std.testing.expectEqualStrings("[2.347s] [] " ++ (" " ** 26) ++ Colors.green ++ "info:" ++ Colors.reset ++ " hello world 42\n", line_no_module);
}

test "formatLine truncates" {
    var buf: [64]u8 = undefined;
    const line = formatLine(&buf, null, 2.347, .info, "{s}", .{"x" ** 200});
    try std.testing.expect(std.mem.endsWith(u8, line, Colors.reset ++ "…[trunc]\n"));
    try std.testing.expect(line.len <= buf.len);
}

test "log smoke" {
    var cfg = LoggerConfig.init(.info);
    const logger = cfg.logger("test-module");
    logger.info("visible {d}", .{1}); // should print
    logger.debug("hidden {d}", .{2}); // should NOT print
}
