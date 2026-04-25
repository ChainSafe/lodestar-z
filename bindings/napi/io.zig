const std = @import("std");

/// Process-wide `Io` for NAPI callbacks, mirroring the `init.io` that a Zig
/// binary receives from `std.process.Init` (see `std.start.zig`'s
/// `std.Io.Threaded.init(gpa, .{})`).
///
/// Why not `init_single_threaded`?
///
///   Today the only Io operations we invoke inside NAPI callbacks are
///   `Clock.Timestamp.now`, `Io.Mutex` lock/unlock, and `io.random` — all
///   backed by direct OS syscalls that don't touch the Threaded executor's
///   allocator / worker pool, so `init_single_threaded` would technically
///   suffice. But that instance pins `allocator = .failing` and
///   `async_limit = .nothing`, so the moment any code path starts calling
///   `io.async(...)` / `io.concurrent(...)` / group scheduling, it panics.
///   Matching the `init.io` defaults keeps us future-proof at essentially
///   zero cost — the worker pool is lazy: threads are only spawned on the
///   first async/concurrent call, up to `async_limit` (cpu_count - 1).
///
/// Initialized once on the first `register()` call (env_refcount 0→1) and
/// torn down when the last NAPI env closes (env_refcount 1→0). Safe to share
/// across Node.js worker threads — `std.Io.Threaded` protects its own
/// internal state with mutexes.
var instance: std.Io.Threaded = undefined;
var initialized: bool = false;

const gpa: std.mem.Allocator = std.heap.page_allocator;

/// Initialize the shared `Threaded`. Idempotent.
pub fn init() !void {
    if (initialized) return;
    instance = std.Io.Threaded.init(gpa, .{});
    initialized = true;
}

/// Get the shared `Io`. Caller must ensure `init()` has been invoked
/// (guaranteed by the `register()` flow in `root.zig`).
pub fn get() std.Io {
    std.debug.assert(initialized);
    return instance.io();
}

/// Tear down the shared `Threaded`. Idempotent.
pub fn deinit() void {
    if (!initialized) return;
    instance.deinit();
    initialized = false;
}
