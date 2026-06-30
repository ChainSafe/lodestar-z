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

fn formatLine(buf: []u8, module: ?[]const u8, secs: f64, level: LogLevel, comptime fmt: []const u8, args: anytype) ![]const u8 {
    if (module) |m| {
        return std.fmt.bufPrint(buf, "[{d:.3}s] [{s}] {s}[{s}]{s} " ++ fmt ++ "\n", .{ secs, m, level.color(), level.asText(), Colors.reset } ++ args);
    } else {
        return std.fmt.bufPrint(buf, "[{d:.3}s] {s}[{s}]{s} " ++ fmt ++ "\n", .{ secs, level.color(), level.asText(), Colors.reset } ++ args);
    }
}

fn writeStderr(bytes: []const u8) void {
    const io = defaultIo();
    _ = std.debug.lockStderr(&.{});
    defer std.debug.unlockStderr();
    const stdErr = std.Io.File.stderr();

    var stdErrWriteBuffer: [4096]u8 = undefined;
    var stdErrWriter = stdErr.writer(io, &stdErrWriteBuffer);
    nosuspend stdErrWriter.interface.writeAll(bytes) catch return;
    nosuspend stdErrWriter.interface.flush() catch return;
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
        const line = formatLine(&buf, module, secs, level, fmt, args) catch return;
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
    const line = try formatLine(&buf, "test-module", secs, .info, "hello {s} {d}", .{ "world", 42 });
    try std.testing.expectEqualStrings("[2.347s] [test-module] " ++ Colors.green ++ "[info]" ++ Colors.reset ++ " hello world 42\n", line);
    const lineNoModule = try formatLine(&buf, null, secs, .info, "hello {s} {d}", .{ "world", 42 });
    try std.testing.expectEqualStrings("[2.347s] " ++ Colors.green ++ "[info]" ++ Colors.reset ++ " hello world 42\n", lineNoModule);
}

test "log smoke" {
    var cfg = LoggerConfig.init(.info);
    const logger = cfg.logger("test-module");
    logger.info("visible {d}", .{1}); // should print
    logger.debug("hidden {d}", .{2}); // should NOT print
}
