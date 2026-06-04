//! Bounded TSFN-backed worker pool for production async native work.
//!
//! Workers are OS threads that pull jobs off a native FIFO queue, run compute
//! without touching N-API, then hand completed jobs back to the owning JS event
//! loop through a single, reused N-API `ThreadSafeFunction`.
//!
//! BLS-agnostic: a caller embeds a `Task` in its own job struct, sets `run_fn`
//! (worker thread, no napi calls) and `complete_fn` (loop thread, settles the
//! Promise), and `submit`s the task. Recover the outer struct in callbacks with
//! `@fieldParentPtr("task", task)`.
const std = @import("std");
const zapi = @import("zapi:zapi");
const napi = zapi.napi;

pub const Task = struct {
    /// Runs on a worker thread. MUST NOT call any napi API.
    run_fn: *const fn (*Task) void,
    /// Runs on the JS loop thread (via the TSFN). Settles the Promise / returns
    /// the slot. Receives the env so it can build resolution/rejection values.
    complete_fn: *const fn (napi.Env, *Task) void,
    /// Intrusive FIFO link; owned by the pool while queued.
    next: ?*Task = null,
};

pub const AsyncWorkerPool = struct {
    pub const MAX_WORKERS = 64;

    const Tsfn = napi.ThreadSafeFunction(@This(), Task);

    io: std.Io = undefined,
    threads: [MAX_WORKERS]std.Thread = undefined,
    n_workers: u32 = 0,
    owner_env: ?napi.c.napi_env = null,

    mutex: std.Io.Mutex = std.Io.Mutex.init,
    cond: std.Io.Condition = std.Io.Condition.init,
    queue: Queue = .{},
    shutdown: bool = false,

    tsfn: Tsfn = undefined,
    initialized: bool = false,
    active_count: usize = 0,

    const Queue = struct {
        head: ?*Task = null,
        tail: ?*Task = null,

        fn push(self: *Queue, task: *Task) void {
            task.next = null;
            if (self.tail) |tail| {
                tail.next = task;
            } else {
                self.head = task;
            }
            self.tail = task;
        }

        fn pop(self: *Queue) ?*Task {
            const task = self.head orelse return null;
            self.head = task.next;
            if (self.head == null) self.tail = null;
            task.next = null;
            return task;
        }

        fn isEmpty(self: *const Queue) bool {
            return self.head == null;
        }
    };

    /// Spawn `n_workers` threads and create the completion TSFN.
    /// `max_queue_size` should be >= the caller's max in-flight job count so a
    /// completion `call` never finds the TSFN queue full.
    pub fn init(self: *AsyncWorkerPool, env: napi.Env, io: std.Io, n_workers: u32, max_queue_size: usize) !void {
        if (self.initialized) {
            if (!self.isOwnerEnv(env)) return error.MultipleNapiEnvsUnsupported;
            return;
        }
        std.debug.assert(n_workers >= 1);
        std.debug.assert(n_workers <= MAX_WORKERS);
        if (max_queue_size == 0) return error.InvalidMaxJobs;

        self.io = io;
        self.owner_env = env.env;
        self.mutex = std.Io.Mutex.init;
        self.cond = std.Io.Condition.init;
        self.queue = .{};
        self.shutdown = false;
        self.active_count = 0;

        const name = try env.createStringUtf8("blsBatchWorkerPool");
        self.tsfn = try Tsfn.create(
            env,
            null, // no JS function — complete_fn settles natively
            null, // no async resource
            name,
            max_queue_size,
            1, // initial_thread_count: the main thread owns the single ref
            self, // context
            null, // no finalize callback
            callJs,
        );
        errdefer self.tsfn.release(.abort) catch {};
        // Don't let an idle pool keep the event loop (process) alive.
        try self.tsfn.unref(env);

        self.n_workers = n_workers;
        var spawned: usize = 0;
        errdefer {
            self.mutex.lockUncancelable(self.io);
            self.shutdown = true;
            self.mutex.unlock(self.io);
            self.cond.broadcast(self.io);
            for (self.threads[0..spawned]) |t| t.join();
        }
        while (spawned < n_workers) : (spawned += 1) {
            self.threads[spawned] = try std.Thread.spawn(.{}, workerLoop, .{self});
        }

        self.initialized = true;
    }

    /// Enqueue a task for a worker. Called on the loop thread.
    pub fn submit(self: *AsyncWorkerPool, env: napi.Env, task: *Task) !void {
        try self.ensureReady(env);

        self.mutex.lockUncancelable(self.io);
        errdefer self.mutex.unlock(self.io);

        if (self.shutdown) return error.PoolShuttingDown;

        if (self.active_count == 0) {
            // The TSFN is unref'd while idle so an initialized but unused pool
            // does not keep Node alive. Active work should behave like
            // napi_async_work and keep the process alive until completion.
            try self.tsfn.ref(env);
        }
        self.active_count += 1;
        self.queue.push(task);
        self.mutex.unlock(self.io);
        self.cond.signal(self.io);
    }

    pub fn ensureReady(self: *AsyncWorkerPool, env: napi.Env) !void {
        if (!self.initialized) return error.PoolNotInitialized;
        if (!self.isOwnerEnv(env)) return error.MultipleNapiEnvsUnsupported;
    }

    pub fn isReadyForEnv(self: *AsyncWorkerPool, env: napi.Env) bool {
        if (!self.initialized or !self.isOwnerEnv(env)) return false;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return !self.shutdown;
    }

    fn isOwnerEnv(self: *const AsyncWorkerPool, env: napi.Env) bool {
        const owner = self.owner_env orelse return false;
        return owner == env.env;
    }

    fn workerLoop(self: *AsyncWorkerPool) void {
        const io = self.io;
        while (true) {
            self.mutex.lockUncancelable(io);
            while (self.queue.isEmpty() and !self.shutdown) {
                self.cond.waitUncancelable(io, &self.mutex);
            }
            if (self.shutdown) {
                self.mutex.unlock(io);
                return;
            }
            const task = self.queue.pop().?;
            self.mutex.unlock(io);

            task.run_fn(task);
            self.tsfn.call(task, .non_blocking) catch {
                // Only expected while the env is closing. The owner pool is
                // deinitialized immediately after workers join, so there is no
                // live JS caller to hand this slot back to.
                self.finishTaskFromWorker();
            };
        }
    }

    fn callJs(env: napi.Env, _: napi.Value, self: *AsyncWorkerPool, task: *Task) void {
        task.complete_fn(env, task);
        self.finishTaskOnLoop(env);
    }

    fn finishTaskOnLoop(self: *AsyncWorkerPool, env: napi.Env) void {
        var should_unref = false;
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(self.active_count > 0);
        self.active_count -= 1;
        should_unref = self.active_count == 0 and !self.shutdown;
        self.mutex.unlock(self.io);

        if (should_unref) {
            self.tsfn.unref(env) catch {};
        }
    }

    fn finishTaskFromWorker(self: *AsyncWorkerPool) void {
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(self.active_count > 0);
        self.active_count -= 1;
        self.mutex.unlock(self.io);
    }

    /// Tear down safely: workers already running a task finish before slots are
    /// freed, but queued tasks are abandoned because completions cannot be
    /// delivered while the owner env is closing.
    pub fn deinit(self: *AsyncWorkerPool) void {
        if (!self.initialized) return;
        self.mutex.lockUncancelable(self.io);
        self.shutdown = true;
        self.mutex.unlock(self.io);
        self.cond.broadcast(self.io);
        for (self.threads[0..self.n_workers]) |t| t.join();
        self.tsfn.release(.abort) catch {};
        self.* = .{};
    }
};
