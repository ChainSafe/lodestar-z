//! JS binding for the `logger` module: runtime log-level control over the
//! addon's `std.log` output (see src/logger.zig and #413).

const std = @import("std");
const js = @import("zapi:zapi").js;
const logger = @import("logger");

/// Set the runtime log level from a Lodestar level string
/// ("error"/"warn"/"info"/"verbose"/"debug"/"trace").
/// `verbose` and `trace` map to `std.log`'s `debug`.
pub fn setLogLevel(level: js.String) !void {
    var buf: [16]u8 = undefined;
    const level_str = level.toSlice(&buf) catch return error.InvalidLogLevel;
    const parsed = logger.levelFromString(level_str) orelse return error.InvalidLogLevel;
    logger.setLevel(parsed);
}

/// Current runtime log level as a `std.log` level name.
pub fn getLogLevel() !js.String {
    return js.String.from(@tagName(logger.getLevel()));
}
