//! Lifecycle for the blst verification `ThreadPool`.

const std = @import("std");
const bls = @import("bls");
const napi_io = @import("./io.zig");

const ThreadPool = bls.ThreadPool;

/// Cached thread pool reference.
///
/// Initialized once via `init`, torn down via `deinit`.
var thread_pool: ?*ThreadPool = null;

pub fn init(n_workers: u16) !void {
    if (thread_pool != null) return error.PoolExists;
    thread_pool = try ThreadPool.init(std.heap.page_allocator, napi_io.get(), .{ .n_workers = n_workers });
}

/// Closes the `ThreadPool` used for blst operations.
///
/// NOTE: this can invalidate any inflight verification requests. Consumer is
/// responsible for the lifecycle of their program and should only call this when
/// all work is done. For lodestar's long-lived process this is typically never
/// called.
pub fn deinit() void {
    if (thread_pool) |p| {
        p.deinit(napi_io.get());
        thread_pool = null;
    }
}

/// Current pool, or null if not yet initialized.
pub fn get() ?*ThreadPool {
    return thread_pool;
}
