//! Thread pool for parallel BLS operations.
//!
//! Provides multi-threaded versions of aggregation and verification functions
//! using a persistent pool of worker threads to avoid thread creation overhead.
//!
//! Multiple callers can dispatch work concurrently. Each job owns its own
//! pairing buffers. Workers pull work items from a shared queue and use atomic
//! counters within each job to grab individual signature sets to process,
//! similar to how the Rust `blst` crate's `verify_multiple_aggregate_signatures`
//! works with `threadpool::ThreadPool`.
const ThreadPool = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @import("root.zig").c;
const Pairing = @import("Pairing.zig");
const blst = @import("root.zig");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const SigningRoot = blst.SigningRoot;
const AggregatePublicKey = blst.AggregatePublicKey;
const AggregateSignature = blst.AggregateSignature;
const BlstError = @import("error.zig").BlstError;
const fast_verify = @import("fast_verify.zig");
const BatchVerifyItem = fast_verify.BatchVerifyItem;
const SecretKey = @import("SecretKey.zig");
const pippenger = @import("pippenger.zig");

pub const PoolError = error{
    /// Pool is currently shutting down.
    ShuttingDown,
    /// The bounded asynchronous root-job admission limit has been reached.
    QueueFull,
};

/// This is pretty arbitrary
pub const MAX_WORKERS: usize = 16;
pub const MAX_ASYNC_ROOTS: usize = 512;

pub const Priority = enum(u8) {
    normal,
    critical,
};

const WorkKind = enum(u8) {
    child,
    root,
};

/// Number of random bits used for verification.
const RAND_BITS = 64;

const PairingBuf = struct {
    data: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined,
};

pub const Opts = struct {
    n_workers: u16 = 1,
};

allocator: Allocator,
n_workers: usize,
threads: [MAX_WORKERS]std.Thread = undefined,
/// Signals workers to exit after draining the queue. Checked by `workerLoop`
/// only when the queue is empty, so all pending items are processed first.
shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
queue: JobQueue,

threadlocal var current_pool: ?*ThreadPool = null;
threadlocal var current_root_priority: ?Priority = null;

const QueueList = struct {
    head: ?*WorkItem = null,
    tail: ?*WorkItem = null,

    fn push(self: *QueueList, item: *WorkItem) void {
        item.next = null;
        if (self.tail) |tail| {
            tail.next = item;
        } else {
            self.head = item;
        }
        self.tail = item;
    }

    fn pop(self: *QueueList) ?*WorkItem {
        const item = self.head orelse return null;
        self.head = item.next;
        if (self.head == null) self.tail = null;
        item.next = null;
        return item;
    }
};

/// Thread-safe priority work queue. Root jobs and their forked child work are
/// kept separate so a worker helping a root never recursively starts an
/// equal-priority root.
const JobQueue = struct {
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    cond: std.Io.Condition = std.Io.Condition.init,
    roots: [2]QueueList = .{ .{}, .{} },
    children: [2]QueueList = .{ .{}, .{} },
    accepting_roots: bool = true,
    active_roots: usize = 0,
    /// Count of workers currently blocked in `cond.wait`. Guarded by `mutex`
    /// (read in `pushBatch`, maintained in `workerLoop`), so it is exact at
    /// signal time. Lets `pushBatch` wake only as many workers as there is new
    /// work for, instead of broadcasting to all of them.
    sleeping_workers: usize = 0,

    /// Pushes a batch of `WorkItem`s to the `JobQueue`.
    ///
    /// Returns false only after workers have been told to stop. During graceful
    /// shutdown accepted roots may continue to submit child work.
    fn pushBatch(self: *JobQueue, io: std.Io, pool: *ThreadPool, items: []*WorkItem) std.Io.Cancelable!bool {
        try self.mutex.lock(io);
        defer self.mutex.unlock(io);

        if (pool.shutdown.load(.acquire)) return false;

        for (items) |item| {
            std.debug.assert(item.kind == .child);
            self.children[@intFromEnum(item.priority)].push(item);
        }
        // Wake at most one sleeping worker per submitted item, and never more than
        // are actually asleep. Running workers loop back to `pop()` after each item,
        // so signals are only needed to bring sleeping workers back into the queue;
        // extra signals only create scheduler churn.
        for (0..@min(items.len, self.sleeping_workers)) |_| {
            self.cond.signal(io);
        }
        return true;
    }

    fn pushRoot(self: *JobQueue, io: std.Io, pool: *ThreadPool, item: *WorkItem) PoolError!void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        if (!self.accepting_roots or pool.shutdown.load(.acquire)) return PoolError.ShuttingDown;
        if (self.active_roots >= MAX_ASYNC_ROOTS) return PoolError.QueueFull;

        std.debug.assert(item.kind == .root);
        self.active_roots += 1;
        self.roots[@intFromEnum(item.priority)].push(item);
        self.cond.signal(io);
    }

    fn popWorker(self: *JobQueue) ?*WorkItem {
        return self.roots[@intFromEnum(Priority.critical)].pop() orelse
            self.children[@intFromEnum(Priority.critical)].pop() orelse
            self.roots[@intFromEnum(Priority.normal)].pop() orelse
            self.children[@intFromEnum(Priority.normal)].pop();
    }

    fn popHelper(self: *JobQueue, priority: Priority) ?*WorkItem {
        if (priority == .normal) {
            if (self.roots[@intFromEnum(Priority.critical)].pop()) |item| return item;
        }
        return self.children[@intFromEnum(Priority.critical)].pop() orelse
            if (priority == .normal) self.children[@intFromEnum(Priority.normal)].pop() else null;
    }
};

/// A work item submitted to the queue. Each worker that picks one up
/// executes the work function, then signals `done`.
pub const WorkItem = struct {
    exec_fn: *const fn (*WorkItem) void,
    finish_fn: ?*const fn (*WorkItem) void = null,
    done: std.Io.Event = .unset,
    next: ?*WorkItem = null,
    priority: Priority = .normal,
    kind: WorkKind = .child,
};

/// Creates a thread pool with the specified number of workers.
/// The caller owns the returned pool and must call `deinit` when done.
pub fn init(allocator_: Allocator, io: std.Io, opts: Opts) (Allocator.Error || std.Thread.SpawnError)!*ThreadPool {
    std.debug.assert(opts.n_workers >= 1);
    std.debug.assert(opts.n_workers <= MAX_WORKERS);

    const pool = try allocator_.create(ThreadPool);
    errdefer pool.deinit(io);

    pool.* = .{
        .allocator = allocator_,
        .n_workers = 0,
        .queue = .{},
    };

    for (0..opts.n_workers) |i| {
        pool.threads[i] = try std.Thread.spawn(.{}, workerLoop, .{ pool, io });
        pool.n_workers += 1;
    }
    std.debug.assert(pool.n_workers == opts.n_workers);

    return pool;
}

/// Shuts down the thread pool and frees resources.
///
/// Cleanup first closes root admission, then lets accepted roots finish all
/// forked work before stopping worker threads.
///
/// The pool pointer is invalid after this call.
pub fn deinit(pool: *ThreadPool, io: std.Io) void {
    pool.queue.mutex.lockUncancelable(io);
    pool.queue.accepting_roots = false;
    while (pool.queue.active_roots > 0) {
        pool.queue.cond.waitUncancelable(io, &pool.queue.mutex);
    }

    pool.shutdown.store(true, .release);
    pool.queue.cond.broadcast(io);
    pool.queue.mutex.unlock(io);

    for (pool.threads[0..pool.n_workers]) |t| t.join();
    pool.allocator.destroy(pool);
}

/// Main loop for worker threads.
///
/// Pops work first before checking for `shutdown` signal, allowing
/// workers to finish their work before closing.
///
fn workerLoop(pool: *ThreadPool, io: std.Io) void {
    while (true) {
        const item: *WorkItem = blk: {
            pool.queue.mutex.lockUncancelable(io);
            defer pool.queue.mutex.unlock(io);

            while (true) {
                if (pool.queue.popWorker()) |wi| break :blk wi;
                if (pool.shutdown.load(.acquire)) return;
                pool.queue.sleeping_workers += 1;
                pool.queue.cond.waitUncancelable(io, &pool.queue.mutex);
                pool.queue.sleeping_workers -= 1;
            }
        };

        executeWorkItem(pool, io, item);
    }
}

fn executeWorkItem(pool: *ThreadPool, io: std.Io, item: *WorkItem) void {
    const is_root = item.kind == .root;
    const finish_fn = item.finish_fn;
    std.debug.assert(finish_fn == null or is_root);
    const previous_pool = current_pool;
    const previous_root_priority = current_root_priority;
    current_pool = pool;
    if (is_root) current_root_priority = item.priority;

    item.exec_fn(item);

    current_pool = previous_pool;
    current_root_priority = previous_root_priority;

    if (is_root) {
        pool.queue.mutex.lockUncancelable(io);
        std.debug.assert(pool.queue.active_roots > 0);
        pool.queue.active_roots -= 1;
        if (pool.queue.active_roots == 0) pool.queue.cond.broadcast(io);
        pool.queue.mutex.unlock(io);
    }

    // Ordinary callers may release stack-owned child work as soon as `done`
    // is set, so do not read the work item after this point. Async roots remain
    // owned through their explicit finish callback.
    item.done.set(io);
    if (finish_fn) |finish| finish(item);
}

/// Submit a native-owned asynchronous root job. Its memory must remain valid
/// through `finish_fn`, which runs after the root and all child work complete.
pub fn submitRoot(pool: *ThreadPool, io: std.Io, item: *WorkItem, priority: Priority) PoolError!void {
    item.kind = .root;
    item.priority = priority;
    try pool.queue.pushRoot(io, pool, item);
}

pub fn workerCount(pool: *const ThreadPool) usize {
    return pool.n_workers;
}

/// Submit work items to the pool and wait for all to complete.
pub fn submitAndWait(pool: *ThreadPool, io: std.Io, items: []*WorkItem) (PoolError || std.Io.Cancelable)!void {
    if (current_pool == pool) {
        const inherited_priority = current_root_priority orelse .normal;
        for (items) |item| {
            std.debug.assert(item.kind == .child);
            if (@intFromEnum(item.priority) < @intFromEnum(inherited_priority)) {
                item.priority = inherited_priority;
            }
        }
    }

    if (!try pool.queue.pushBatch(io, pool, items)) return PoolError.ShuttingDown;

    if (current_pool == pool) {
        const priority = current_root_priority orelse .normal;
        while (true) {
            var incomplete: ?*WorkItem = null;
            for (items) |item| {
                if (!item.done.isSet()) {
                    incomplete = item;
                    break;
                }
            }
            const wait_item = incomplete orelse return;

            pool.queue.mutex.lockUncancelable(io);
            const help_item = pool.queue.popHelper(priority);
            pool.queue.mutex.unlock(io);

            if (help_item) |item| {
                executeWorkItem(pool, io, item);
            } else {
                wait_item.done.waitUncancelable(io);
            }
        }
    }

    // Work items live on the caller's stack, so cancellation must not let the
    // caller return while workers still reference them.
    for (items) |item| {
        item.done.waitUncancelable(io);
    }
}

const VerifyMultiJob = struct {
    items: []const BatchVerifyItem,
    dst: []const u8,
    pks_validate: bool,
    sigs_groupcheck: bool,
    counter: std.atomic.Value(usize),
    err_flag: std.atomic.Value(bool),
    /// Workers write committed pairing results here, indexed by work item id.
    result_bufs: *[MAX_WORKERS]PairingBuf,
};

const VerifyMultiWorkItem = struct {
    base: WorkItem,
    job: *VerifyMultiJob,
    worker_id: usize,

    fn exec(base_item: *WorkItem) void {
        const self: *VerifyMultiWorkItem = @fieldParentPtr("base", base_item);
        const job = self.job;

        var pairing = Pairing.init(&job.result_bufs[self.worker_id].data, true, job.dst);
        const n_elems = job.items.len;

        while (true) {
            const i = job.counter.fetchAdd(1, .monotonic);
            if (i >= n_elems) break;
            if (job.err_flag.load(.monotonic)) break;

            const item = &job.items[i];
            pairing.mulAndAggregate(
                item.public_key,
                job.pks_validate,
                item.signature,
                job.sigs_groupcheck,
                &item.randomness,
                RAND_BITS,
                item.message,
            ) catch {
                job.err_flag.store(true, .release);
                break;
            };
        }

        if (!job.err_flag.load(.monotonic)) pairing.commit();
    }
};

/// Verifies multiple aggregate signatures in parallel using the thread pool.
///
/// This is the multi-threaded version of the same function in `fast_verify.zig`.
/// Multiple callers may invoke this concurrently — each call owns its own
/// pairing buffers and job state, workers pull from a shared queue.
/// Invalid cryptographic inputs return false; pool lifecycle errors propagate.
pub fn verifyMultipleAggregateSignatures(
    pool: *ThreadPool,
    io: std.Io,
    items: []const BatchVerifyItem,
    dst: []const u8,
    pks_validate: bool,
    sigs_groupcheck: bool,
) (PoolError || std.Io.Cancelable)!bool {
    const n_elems = items.len;
    if (n_elems == 0) return false;

    if (n_elems <= 2 or pool.n_workers <= 1) {
        var pairing_buf: PairingBuf = .{};
        return fast_verify.verifyMultipleAggregateSignatures(
            &pairing_buf.data,
            items,
            dst,
            pks_validate,
            sigs_groupcheck,
        ) catch false;
    }

    const n_active = @min(pool.n_workers, n_elems);

    var result_bufs: [MAX_WORKERS]PairingBuf = undefined;

    var job = VerifyMultiJob{
        .items = items,
        .dst = dst,
        .pks_validate = pks_validate,
        .sigs_groupcheck = sigs_groupcheck,
        .counter = std.atomic.Value(usize).init(0),
        .err_flag = std.atomic.Value(bool).init(false),
        .result_bufs = &result_bufs,
    };

    // Create work items on the stack — one per active worker
    var work_items: [MAX_WORKERS]VerifyMultiWorkItem = undefined;
    var item_ptrs: [MAX_WORKERS]*WorkItem = undefined;
    for (0..n_active) |i| {
        work_items[i] = .{
            .base = .{ .exec_fn = VerifyMultiWorkItem.exec },
            .job = &job,
            .worker_id = i,
        };
        item_ptrs[i] = &work_items[i].base;
    }

    try pool.submitAndWait(io, item_ptrs[0..n_active]);

    if (job.err_flag.load(.acquire)) return false;

    return mergeAndVerify(&result_bufs, n_active, null) catch false;
}

const AggVerifyJob = struct {
    pks: []const *PublicKey,
    msgs: []const SigningRoot,
    dst: []const u8,
    pks_validate: bool,
    n_elems: usize,
    counter: std.atomic.Value(usize),
    err_flag: std.atomic.Value(bool),
    result_bufs: *[MAX_WORKERS]PairingBuf,
};

const AggVerifyWorkItem = struct {
    base: WorkItem,
    job: *AggVerifyJob,
    worker_id: usize,

    fn exec(base_item: *WorkItem) void {
        const self: *AggVerifyWorkItem = @fieldParentPtr("base", base_item);
        const job = self.job;

        var pairing = Pairing.init(&job.result_bufs[self.worker_id].data, true, job.dst);

        var did_work = false;

        while (true) {
            const i = job.counter.fetchAdd(1, .monotonic);
            if (i >= job.n_elems) break;
            if (job.err_flag.load(.monotonic)) break;

            did_work = true;

            pairing.aggregate(
                job.pks[i],
                job.pks_validate,
                null,
                false,
                &job.msgs[i],
                null,
            ) catch {
                job.err_flag.store(true, .release);
                break;
            };
        }

        if (!job.err_flag.load(.monotonic)) pairing.commit();
    }
};

/// Verifies an aggregated signature against multiple messages and public keys
/// in parallel using the thread pool.
///
/// This is the multi-threaded version of `Signature.aggregateVerify`.
pub fn aggregateVerify(
    pool: *ThreadPool,
    io: std.Io,
    sig: *const Signature,
    sig_groupcheck: bool,
    msgs: []const SigningRoot,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
) (BlstError || PoolError || std.Io.Cancelable)!bool {
    const n_elems = pks.len;
    if (n_elems == 0 or msgs.len != n_elems) return BlstError.VerifyFail;

    // Single-threaded fallback
    if (n_elems <= 2 or pool.n_workers <= 1) {
        var buf: PairingBuf = .{};
        var pairing = Pairing.init(&buf.data, true, dst);
        try pairing.aggregate(pks[0], pks_validate, sig, sig_groupcheck, &msgs[0], null);
        for (1..n_elems) |i| {
            try pairing.aggregate(pks[i], pks_validate, null, false, &msgs[i], null);
        }
        pairing.commit();
        var gtsig = c.blst_fp12{};
        Pairing.aggregated(&gtsig, sig);
        return pairing.finalVerify(&gtsig);
    }

    const n_active = @min(pool.n_workers, n_elems);

    if (sig_groupcheck) sig.validate(false) catch return false;

    var result_bufs: [MAX_WORKERS]PairingBuf = undefined;

    var job = AggVerifyJob{
        .pks = pks[0..n_elems],
        .msgs = msgs[0..n_elems],
        .dst = dst,
        .pks_validate = pks_validate,
        .n_elems = n_elems,
        .counter = std.atomic.Value(usize).init(0),
        .err_flag = std.atomic.Value(bool).init(false),
        .result_bufs = &result_bufs,
    };

    var work_items: [MAX_WORKERS]AggVerifyWorkItem = undefined;
    var item_ptrs: [MAX_WORKERS]*WorkItem = undefined;
    for (0..n_active) |i| {
        work_items[i] = .{
            .base = .{ .exec_fn = AggVerifyWorkItem.exec },
            .job = &job,
            .worker_id = i,
        };
        item_ptrs[i] = &work_items[i].base;
    }

    try pool.submitAndWait(io, item_ptrs[0..n_active]);

    if (job.err_flag.load(.acquire)) return false;

    var gtsig = c.blst_fp12{};
    Pairing.aggregated(&gtsig, sig);

    return mergeAndVerify(&result_bufs, n_active, &gtsig);
}

/// Merges the first `n_results` pairing buffers and executes `finalVerify`.
fn mergeAndVerify(
    result_bufs: *[MAX_WORKERS]PairingBuf,
    n_results: usize,
    gtsig: ?*const c.blst_fp12,
) BlstError!bool {
    if (n_results == 0) return BlstError.MergeError;

    var acc = Pairing{ .ctx = @ptrCast(&result_bufs[0].data) };

    for (1..n_results) |i| {
        const other = Pairing{ .ctx = @ptrCast(&result_bufs[i].data) };
        try acc.merge(&other);
    }

    return acc.finalVerify(gtsig);
}

/// Aggregates `pks` and `sigs` with multi-scalar multiplication using `randomness`.
/// Each MSM (PK then Sig) is fully fanned out across the pool via tile Pippenger
/// (see `pippenger.zig`).
///
///
/// ## Invariants:
/// - `pks` and `sigs` are paired by index.
/// - `randomness` must contain at least `pks.len * 32` bytes;
/// - only the first 8 bytes per 32-byte slot are read by
///   the underlying 64-bit Pippenger, but the 32-byte stride matches the existing
///   `AggregatePublicKey.aggregateWithRandomness` layout.
pub fn aggregateWithRandomness(
    pool: *ThreadPool,
    io: std.Io,
    pks: []*const PublicKey,
    sigs: []*const Signature,
    randomness: []const u8,
    pks_validate: bool,
    sigs_groupcheck: bool,
    pk_out: *PublicKey,
    sig_out: *Signature,
) (BlstError || PoolError || std.Io.Cancelable || std.mem.Allocator.Error)!void {
    if (pks.len == 0 or pks.len != sigs.len) return BlstError.AggrTypeMismatch;
    if (pks.len > blst.MAX_AGGREGATE_PER_JOB) return BlstError.AggrTypeMismatch;
    if (randomness.len < pks.len * 32) return BlstError.AggrTypeMismatch;

    if (pks_validate) for (pks) |pk| try pk.validate();
    if (sigs_groupcheck) for (sigs) |sig| try sig.validate(true);

    var scalars_refs: [blst.MAX_AGGREGATE_PER_JOB]*const u8 = undefined;
    for (0..pks.len) |i| scalars_refs[i] = &randomness[i * 32];

    var pk_proj: c.blst_p1 = undefined;
    try pippenger.parallelMSMG1(pool, io, pks, scalars_refs[0..pks.len], 64, &pk_proj);

    var sig_proj: c.blst_p2 = undefined;
    try pippenger.parallelMSMG2(pool, io, sigs, scalars_refs[0..sigs.len], 64, &sig_proj);

    c.blst_p1_to_affine(&pk_out.point, &pk_proj);
    c.blst_p2_to_affine(&sig_out.point, &sig_proj);
}

test "verifyMultipleAggregateSignatures multi-threaded" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 4 });
    defer pool.deinit(std.testing.io);

    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const num_sigs = 16;

    var msgs: [num_sigs]SigningRoot = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]Signature = undefined;
    var items: [num_sigs]blst.BatchVerifyItem = undefined;

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.testing.io.random(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const rand = prng.random();

    for (0..num_sigs) |i| {
        std.Random.bytes(rand, &msgs[i]);
        var ikm_i = ikm;
        ikm_i[0] = @intCast(i & 0xff);
        const sk = try SecretKey.keyGen(&ikm_i, null);
        pks[i] = sk.toPublicKey();
        sigs[i] = sk.sign(&msgs[i], blst.DST, null);
        items[i] = .{
            .message = &msgs[i],
            .public_key = &pks[i],
            .signature = &sigs[i],
            .randomness = undefined,
        };
        std.Random.bytes(rand, &items[i].randomness);
    }

    const result = try pool.verifyMultipleAggregateSignatures(
        std.testing.io,
        &items,
        blst.DST,
        true,
        true,
    );

    try std.testing.expect(result);
}

test "aggregateVerify multi-threaded" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 4 });
    defer pool.deinit(std.testing.io);

    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const num_sigs = 16;

    var msgs: [num_sigs][32]u8 = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]Signature = undefined;
    var pk_ptrs: [num_sigs]*PublicKey = undefined;

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.testing.io.random(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const rand = prng.random();

    for (0..num_sigs) |i| {
        std.Random.bytes(rand, &msgs[i]);
        var ikm_i = ikm;
        ikm_i[0] = @intCast(i & 0xff);
        const sk = try SecretKey.keyGen(&ikm_i, null);
        pks[i] = sk.toPublicKey();
        sigs[i] = sk.sign(&msgs[i], blst.DST, null);
        pk_ptrs[i] = &pks[i];
    }

    const agg_sig = blst.AggregateSignature.aggregate(&sigs, false) catch return error.AggregationFailed;
    const final_sig = agg_sig.toSignature();

    try std.testing.expect(try pool.aggregateVerify(
        std.testing.io,
        &final_sig,
        false,
        &msgs,
        blst.DST,
        &pk_ptrs,
        true,
    ));
}

test "aggregateWithRandomness multi-threaded" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 4 });
    defer pool.deinit(std.testing.io);

    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const num_sigs = blst.MAX_AGGREGATE_PER_JOB;

    var msg: [32]u8 = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]Signature = undefined;
    var pk_ptrs: [num_sigs]*const PublicKey = undefined;
    var sig_ptrs: [num_sigs]*const Signature = undefined;

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.testing.io.random(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const rand = prng.random();
    std.Random.bytes(rand, &msg);

    for (0..num_sigs) |i| {
        var ikm_i = ikm;
        ikm_i[0] = @intCast(i & 0xff);
        const sk = try SecretKey.keyGen(&ikm_i, null);
        pks[i] = sk.toPublicKey();
        sigs[i] = sk.sign(&msg, blst.DST, null);
        pk_ptrs[i] = &pks[i];
        sig_ptrs[i] = &sigs[i];
    }

    var randomness: [32 * num_sigs]u8 = undefined;
    std.Random.bytes(rand, &randomness);

    var agg_pk: PublicKey = .{};
    var agg_sig: Signature = .{};

    try pool.aggregateWithRandomness(
        std.testing.io,
        &pk_ptrs,
        &sig_ptrs,
        &randomness,
        true,
        true,
        &agg_pk,
        &agg_sig,
    );

    try agg_sig.verify(true, &msg, blst.DST, null, &agg_pk, true);
}

test "asynchronous roots cooperatively execute child work" {
    const Child = struct {
        base: WorkItem,
        completed: *std.atomic.Value(u32),

        fn exec(base: *WorkItem) void {
            const self: *@This() = @fieldParentPtr("base", base);
            _ = self.completed.fetchAdd(1, .monotonic);
        }
    };

    const Root = struct {
        base: WorkItem,
        pool: *ThreadPool,
        completed: *std.atomic.Value(u32),

        fn exec(base: *WorkItem) void {
            const self: *@This() = @fieldParentPtr("base", base);
            var child = Child{
                .base = .{ .exec_fn = Child.exec },
                .completed = self.completed,
            };
            var children = [_]*WorkItem{&child.base};
            self.pool.submitAndWait(std.testing.io, &children) catch unreachable;
        }
    };

    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 2 });
    defer pool.deinit(std.testing.io);

    var completed = std.atomic.Value(u32).init(0);
    var roots: [4]Root = undefined;
    for (&roots) |*root| {
        root.* = .{
            .base = .{ .exec_fn = Root.exec },
            .pool = pool,
            .completed = &completed,
        };
        try pool.submitRoot(std.testing.io, &root.base, .normal);
    }

    for (&roots) |*root| root.base.done.waitUncancelable(std.testing.io);
    try std.testing.expectEqual(roots.len, completed.load(.acquire));
}

test "critical asynchronous roots run before queued normal roots" {
    const Root = struct {
        base: WorkItem,
        started: ?*std.Io.Event = null,
        release: ?*std.Io.Event = null,
        sequence: ?*std.atomic.Value(u32) = null,
        order: ?*u32 = null,

        fn exec(base: *WorkItem) void {
            const self: *@This() = @fieldParentPtr("base", base);
            if (self.started) |started| started.set(std.testing.io);
            if (self.release) |release| release.waitUncancelable(std.testing.io);
            if (self.sequence) |sequence| {
                self.order.?.* = sequence.fetchAdd(1, .monotonic);
            }
        }
    };

    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 1 });
    defer pool.deinit(std.testing.io);

    var blocker_started: std.Io.Event = .unset;
    var blocker_release: std.Io.Event = .unset;
    var blocker = Root{
        .base = .{ .exec_fn = Root.exec },
        .started = &blocker_started,
        .release = &blocker_release,
    };
    try pool.submitRoot(std.testing.io, &blocker.base, .normal);
    blocker_started.waitUncancelable(std.testing.io);

    var sequence = std.atomic.Value(u32).init(0);
    var normal_order: u32 = undefined;
    var critical_order: u32 = undefined;
    var normal = Root{
        .base = .{ .exec_fn = Root.exec },
        .sequence = &sequence,
        .order = &normal_order,
    };
    var critical = Root{
        .base = .{ .exec_fn = Root.exec },
        .sequence = &sequence,
        .order = &critical_order,
    };
    try pool.submitRoot(std.testing.io, &normal.base, .normal);
    try pool.submitRoot(std.testing.io, &critical.base, .critical);
    blocker_release.set(std.testing.io);

    critical.base.done.waitUncancelable(std.testing.io);
    normal.base.done.waitUncancelable(std.testing.io);
    try std.testing.expectEqual(0, critical_order);
    try std.testing.expectEqual(1, normal_order);
}

test "normal roots cooperatively yield to critical roots between child items" {
    const Child = struct {
        base: WorkItem,
        started: ?*std.Io.Event = null,
        release: ?*std.Io.Event = null,
        sequence: *std.atomic.Value(u32),
        order: *u32,

        fn exec(base: *WorkItem) void {
            const self: *@This() = @fieldParentPtr("base", base);
            if (self.started) |started| started.set(std.testing.io);
            if (self.release) |release| release.waitUncancelable(std.testing.io);
            self.order.* = self.sequence.fetchAdd(1, .monotonic);
        }
    };

    const NormalRoot = struct {
        base: WorkItem,
        pool: *ThreadPool,
        child_started: *std.Io.Event,
        child_release: *std.Io.Event,
        sequence: *std.atomic.Value(u32),
        child_orders: *[2]u32,

        fn exec(base: *WorkItem) void {
            const self: *@This() = @fieldParentPtr("base", base);
            var children = [_]Child{
                .{
                    .base = .{ .exec_fn = Child.exec },
                    .started = self.child_started,
                    .release = self.child_release,
                    .sequence = self.sequence,
                    .order = &self.child_orders[0],
                },
                .{
                    .base = .{ .exec_fn = Child.exec },
                    .sequence = self.sequence,
                    .order = &self.child_orders[1],
                },
            };
            var child_ptrs = [_]*WorkItem{ &children[0].base, &children[1].base };
            self.pool.submitAndWait(std.testing.io, &child_ptrs) catch unreachable;
        }
    };

    const CriticalRoot = struct {
        base: WorkItem,
        sequence: *std.atomic.Value(u32),
        order: *u32,

        fn exec(base: *WorkItem) void {
            const self: *@This() = @fieldParentPtr("base", base);
            self.order.* = self.sequence.fetchAdd(1, .monotonic);
        }
    };

    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 1 });
    defer pool.deinit(std.testing.io);

    var child_started: std.Io.Event = .unset;
    var child_release: std.Io.Event = .unset;
    var sequence = std.atomic.Value(u32).init(0);
    var child_orders: [2]u32 = undefined;
    var critical_order: u32 = undefined;
    var normal = NormalRoot{
        .base = .{ .exec_fn = NormalRoot.exec },
        .pool = pool,
        .child_started = &child_started,
        .child_release = &child_release,
        .sequence = &sequence,
        .child_orders = &child_orders,
    };
    var critical = CriticalRoot{
        .base = .{ .exec_fn = CriticalRoot.exec },
        .sequence = &sequence,
        .order = &critical_order,
    };

    try pool.submitRoot(std.testing.io, &normal.base, .normal);
    child_started.waitUncancelable(std.testing.io);
    try pool.submitRoot(std.testing.io, &critical.base, .critical);
    child_release.set(std.testing.io);

    normal.base.done.waitUncancelable(std.testing.io);
    critical.base.done.waitUncancelable(std.testing.io);
    try std.testing.expectEqualSlices(u32, &.{ 0, 2 }, &child_orders);
    try std.testing.expectEqual(1, critical_order);
}
