//! Pluggable time source abstraction.
//!
//! Allows injecting fake clocks for deterministic testing while using
//! `std.Io.Clock.real` in production via `fromIo`.

const std = @import("std");
const slot_math = @import("slot_math.zig");

pub const TimeSource = struct {
    ctx: ?*anyopaque = null,
    now_ms_fn: *const fn (ctx: ?*anyopaque) slot_math.UnixMs,

    pub fn nowMs(self: TimeSource) slot_math.UnixMs {
        return self.now_ms_fn(self.ctx);
    }

    /// Construct a TimeSource backed by std.Io.Clock.real.
    /// The caller must ensure the pointed-to std.Io outlives this TimeSource.
    pub fn fromIo(io: *std.Io) TimeSource {
        return .{
            .ctx = @ptrCast(io),
            .now_ms_fn = struct {
                fn nowMs(ctx: ?*anyopaque) slot_math.UnixMs {
                    const p: *std.Io = @ptrCast(@alignCast(ctx.?));
                    const ms = std.Io.Clock.real.now(p.*).toMilliseconds();
                    std.debug.assert(ms >= 0);
                    return @intCast(ms);
                }
            }.nowMs,
        };
    }
};
