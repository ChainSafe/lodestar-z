//! Interim generic async-task plumbing for napi bindings.
//!
//! zapi has no async DSL — `js.Promise` requires dropping to the low-level
//! `napi.AsyncWork`/`Deferred` layer for worker-thread resolution — so this
//! module confines that raw plumbing to one place. It is an upstream
//! candidate for a zapi `js.AsyncTask`; `transferOwnedSlice` is superseded
//! by zapi#68 `OwnedTypedArray` once zapi 4.0 ships.
//!
//! A Task is any struct providing:
//!  - `compute(self: *Task) !void` — libuv worker thread; MUST NOT call napi APIs
//!  - `resolve(self: *Task, env: napi.Env) !napi.Value` — JS thread; builds the
//!    fulfillment value
//!  - `errorMessage(err: anyerror) [:0]const u8` — maps errors to rejection
//!    messages
//!  - `deinit(self: *Task) void` — frees task-owned memory; must be safe after
//!    a successful transfer in `resolve`
//!
//! Ownership: on `spawn` error the task is NOT consumed — the caller's
//! errdefers must free its resources. After `spawn` returns successfully the
//! helper owns the task and calls `deinit` in the complete callback.

const std = @import("std");
const builtin = @import("builtin");
const js = @import("zapi:zapi").js;
const napi = @import("zapi:zapi").napi;

var gpa: std.heap.DebugAllocator(.{}) = .init;
/// Allocator for task contexts and for any buffer handed to JS through
/// `transferOwnedSlice` — the ArrayBuffer finalizer cannot carry an arbitrary
/// allocator, so transferable buffers must come from this one.
pub const allocator = if (builtin.mode == .Debug) gpa.allocator() else std.heap.c_allocator;

/// Runs `task.compute` on the libuv worker pool and returns a JS Promise that
/// settles on the JS thread: rejected with `Task.errorMessage(err)` if
/// `compute` failed, otherwise resolved with `task.resolve(env)`.
pub fn spawn(comptime Task: type, task: Task, comptime resource_name: []const u8) !js.Value {
    const Context = struct {
        task: Task,
        err: ?anyerror,
        deferred: napi.Deferred,
        work: napi.c.napi_async_work,

        const Self = @This();

        /// Worker thread. MUST NOT call any napi APIs.
        fn execute(_: napi.Env, ctx: *Self) void {
            ctx.task.compute() catch |err| {
                ctx.err = err;
            };
        }

        /// JS thread, after the worker finished. Always settles the promise;
        /// if settling itself fails we fall back to a bare reject so callers
        /// never see a dangling Promise.
        fn complete(env: napi.Env, status: napi.status.Status, ctx: *Self) void {
            defer {
                napi.status.check(napi.c.napi_delete_async_work(env.env, ctx.work)) catch {};
                ctx.task.deinit();
                allocator.destroy(ctx);
            }

            settle(env, status, ctx) catch {
                rejectWithMessage(env, ctx.deferred, "InternalError") catch {};
            };
        }

        fn settle(env: napi.Env, status: napi.status.Status, ctx: *Self) !void {
            if (status != .ok) {
                // libuv's async work itself failed (e.g. cancelled), not compute.
                return rejectWithMessage(env, ctx.deferred, @tagName(status));
            }
            if (ctx.err) |err| {
                return rejectWithMessage(env, ctx.deferred, Task.errorMessage(err));
            }
            try ctx.deferred.resolve(try ctx.task.resolve(env));
        }
    };

    const env = js.env();

    const ctx = try allocator.create(Context);
    errdefer allocator.destroy(ctx);

    ctx.task = task;
    ctx.err = null;
    ctx.deferred = undefined;
    ctx.work = undefined;

    const deferred_cleanup_value = try env.getUndefined();
    const resource = try env.createStringUtf8(resource_name);

    // Until queue succeeds, this function owns the unqueued work handle.
    const work = try env.createAsyncWork(Context, null, resource, Context.execute, Context.complete, ctx);
    errdefer work.delete() catch |err| {
        std.log.err("failed to delete unqueued async work ({s}): {s}", .{ resource_name, @errorName(err) });
    };

    ctx.work = work.work;

    // Settle the unreturned Promise so Node can release its deferred handle.
    ctx.deferred = try env.createPromise();
    errdefer ctx.deferred.resolve(deferred_cleanup_value) catch |err| {
        std.log.err("failed to settle unreturned async promise ({s}): {s}", .{ resource_name, @errorName(err) });
    };

    try work.queue();

    return .{ .val = ctx.deferred.getPromise() };
}

/// Transfers an `allocator`-owned slice to a JS TypedArray without copying;
/// V8 frees the buffer via a finalizer when the array is collected. On
/// success `data.*` becomes empty so a later unconditional `free` is a no-op
/// (mirrors zapi#68's transactional `OwnedTypedArray` contract). Empty input
/// resolves to a regular zero-length typed array.
pub fn transferOwnedSlice(
    comptime Element: type,
    comptime array_type: napi.value_types.TypedarrayType,
    env: napi.Env,
    data: *[]Element,
) !napi.Value {
    if (data.len == 0) {
        const arraybuffer = try env.createArrayBuffer(0, null);
        return env.createTypedarray(array_type, 0, arraybuffer, 0);
    }

    const byte_len = data.len * @sizeOf(Element);
    const finalize_cb = comptime napi.wrapSliceFinalizeCallback(Element, Finalizer(Element).cb);
    const len_hint: ?*anyopaque = @ptrFromInt(data.len);
    const arraybuffer = try env.createExternalArrayBuffer(std.mem.sliceAsBytes(data.*), finalize_cb, len_hint);
    const len = data.len;
    // Ownership transferred: the ArrayBuffer finalizer frees the buffer from
    // here on, even if createTypedarray below fails.
    data.* = &.{};
    _ = env.adjustExternalMemory(@intCast(byte_len)) catch {};

    return env.createTypedarray(array_type, len, arraybuffer, 0);
}

/// Frees a buffer handed to `transferOwnedSlice` and reverses the matching
/// `adjustExternalMemory` accounting.
fn Finalizer(comptime Element: type) type {
    return struct {
        fn cb(env: napi.Env, data: []Element) void {
            const byte_len = data.len * @sizeOf(Element);
            allocator.free(data);
            _ = env.adjustExternalMemory(-@as(i64, @intCast(byte_len))) catch {};
        }
    };
}

/// Reject `deferred` with `new Error(message)` so JS callers can match on
/// `err.message`.
fn rejectWithMessage(env: napi.Env, deferred: napi.Deferred, message: []const u8) !void {
    const msg_val = try env.createStringUtf8(message);
    const err_val = try env.createError(napi.Value{ .env = env.env, .value = null }, msg_val);
    try deferred.reject(err_val);
}
