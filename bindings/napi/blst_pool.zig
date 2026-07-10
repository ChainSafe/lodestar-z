//! Lifecycle for the blst verification `ThreadPool`.
//!
//! These functions live here — not in `blst.zig` — on purpose. `blst.zig` is
//! exported to JS via zapi's `exportModule`, which turns every `pub fn` of an
//! exported module into a JS callback and rejects any whose parameters aren't
//! zapi DSL types. `initThreadPool(n_workers: u16)` takes a plain `u16`, so it
//! can't live in an exported module. This module is imported privately (as a
//! plain `const`, never `pub`) by both `blst.zig` and `root.zig`, so zapi never
//! sees it while Zig code on both sides can still call it.
const std = @import("std");
const bls = @import("bls");
const napi_io = @import("./io.zig");

const ThreadPool = bls.ThreadPool;

/// Cached thread pool reference for parallel verification.
/// Initialized once via `init`, torn down via `deinit`.
var thread_pool: ?*ThreadPool = null;

pub fn init(n_workers: u16) !void {
    if (thread_pool != null) return error.PoolExists;
    thread_pool = try ThreadPool.init(std.heap.page_allocator, napi_io.get(), .{ .n_workers = n_workers });
}

/// Closes the `ThreadPool` used for blst operations.
///
/// Note: this can invalidate any inflight verification requests. Consumer is
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
