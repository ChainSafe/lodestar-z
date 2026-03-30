//! Graceful shutdown handler for the beacon node.
//!
//! Installs POSIX signal handlers for SIGINT (Ctrl-C) and SIGTERM that set an
//! atomic flag.  The main loop polls the flag and exits cleanly when set.
//!
//! Signal handlers must be async-signal-safe: no allocations, no locks, no
//! syscalls beyond what the kernel guarantees safe.  Setting an atomic bool is.

const std = @import("std");
const posix = std.posix;

/// Global atomic flag.  The signal handler writes here; the main loop reads.
/// Must be module-level so the signal handler (a plain C function pointer)
/// can reach it without a closure.
var g_should_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Async-signal-safe handler: just set the flag.
fn handleSignal(sig: posix.SIG) callconv(.c) void {
    _ = sig;
    g_should_stop.store(true, .release);
}

pub const ShutdownHandler = struct {
    /// Install signal handlers for SIGINT and SIGTERM.
    ///
    /// Call once at startup before entering any service loop.
    pub fn installSignalHandlers() void {
        const act = posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.INT, &act, null);
        posix.sigaction(posix.SIG.TERM, &act, null);
    }

    /// Returns true when a shutdown signal has been received.
    pub fn shouldStop() bool {
        return g_should_stop.load(.acquire);
    }
};
