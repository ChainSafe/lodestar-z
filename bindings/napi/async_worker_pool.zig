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
    /// Monotonic (CLOCK_MONOTONIC) timestamp captured at `submit`; used to measure
    /// queue residency. Always set before the task is popped.
    enqueue: std.Io.Clock.Timestamp = undefined,
    /// Queue residency (submit → worker pickup) in nanoseconds, set by the pool at
    /// pop and read by the owner's completion callback for metrics. Computed off the
    /// hot path (outside any lock); 0 means unmeasured.
    queue_wait_ns: u64 = 0,
    /// Worker compute time (`run_fn` duration) in nanoseconds, set by the pool right
    /// around run_fn (worker thread, lock-free). Read by the completion callback.
    run_ns: u64 = 0,
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
    /// Jobs submitted but not yet completed (queued + running + awaiting TSFN
    /// completion). Drives the TSFN ref/unref idle gate.
    active_count: usize = 0,
    /// Observability counters (read by `stats()` for metrics). `queued_count` is
    /// jobs admitted but not yet picked up by a worker; `running_count` is workers
    /// currently inside `run_fn`. Both are mutated only under `mutex`.
    queued_count: usize = 0,
    running_count: usize = 0,
    /// The admission/queue capacity this pool was sized for (== max_queue_size).
    max_inflight: usize = 0,

    /// Point-in-time pool occupancy snapshot for metrics. Every field is a real
    /// measured count — no derived or fabricated values.
    pub const Stats = struct {
        workers: u32,
        max_inflight: usize,
        active: usize,
        queued: usize,
        running: usize,
    };

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
        self.max_inflight = max_queue_size;
        self.mutex = std.Io.Mutex.init;
        self.cond = std.Io.Condition.init;
        self.queue = .{};
        self.shutdown = false;
        self.active_count = 0;
        self.queued_count = 0;
        self.running_count = 0;

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

        // Stamp enqueue time before taking the lock (the task is caller-owned until
        // pushed) so queue-wait timing adds nothing to the critical section.
        task.enqueue = std.Io.Clock.Timestamp.now(self.io, .awake);
        task.queue_wait_ns = 0;

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
        self.queued_count += 1;
        self.mutex.unlock(self.io);
        self.cond.signal(self.io);
    }

    /// Real-time pool occupancy for metrics. Safe from any thread (reads under the
    /// mutex); intended to be polled by the owner env's metrics collector.
    pub fn stats(self: *AsyncWorkerPool) Stats {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return .{
            .workers = self.n_workers,
            .max_inflight = self.max_inflight,
            .active = self.active_count,
            .queued = self.queued_count,
            .running = self.running_count,
        };
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
            self.queued_count -= 1;
            self.running_count += 1;
            self.mutex.unlock(io);

            // Measure queue residency off the lock (the task is now worker-owned).
            const pickup = std.Io.Clock.Timestamp.now(io, .awake);
            const wait_ns = task.enqueue.durationTo(pickup).raw.nanoseconds;
            task.queue_wait_ns = if (wait_ns > 0) @intCast(wait_ns) else 0;

            const run_start = std.Io.Clock.Timestamp.now(io, .awake);
            task.run_fn(task);
            const run_ns = run_start.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds;
            task.run_ns = if (run_ns > 0) @intCast(run_ns) else 0;
            self.finishRun();
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

    /// Mark the just-finished `run_fn` as no longer occupying a worker. Runs on a
    /// worker thread right after `run_fn` returns, before the completion is queued.
    fn finishRun(self: *AsyncWorkerPool) void {
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(self.running_count > 0);
        self.running_count -= 1;
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
