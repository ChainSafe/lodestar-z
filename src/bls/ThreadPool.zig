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
const AggregatePublicKey = blst.AggregatePublicKey;
const AggregateSignature = blst.AggregateSignature;
const BlstError = @import("error.zig").BlstError;
const SecretKey = @import("SecretKey.zig");
const pippenger = @import("pippenger.zig");

pub const PoolError = error{
    /// Pool is currently shutting down.
    ShuttingDown,
};

/// This is pretty arbitrary
pub const MAX_WORKERS: usize = 16;

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
/// Signals `pushBatch` to reject new work. Set before `shutdown` so no new
/// items enter the queue while workers are draining it.
shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
queue: JobQueue,

/// Thread-safe FIFO work queue. Workers wait on `cond` for new items
/// and pop them in submission order.
const JobQueue = struct {
    mutex: std.Io.Mutex = std.Io.Mutex.init,
    cond: std.Io.Condition = std.Io.Condition.init,
    head: ?*WorkItem = null,
    tail: ?*WorkItem = null,
    /// Count of workers currently blocked in `cond.wait`. Guarded by `mutex`
    /// (read in `pushBatch`, maintained in `workerLoop`), so it is exact at
    /// signal time. Lets `pushBatch` wake only as many workers as there is new
    /// work for, instead of broadcasting to all of them.
    sleeping_workers: usize = 0,

    /// Pushes a batch of `WorkItem`s to the `JobQueue`.
    ///
    /// Returns false if the pool has signalled that it is shutting down and does
    /// not push any work.
    fn pushBatch(self: *JobQueue, io: std.Io, pool: *ThreadPool, items: []*WorkItem) std.Io.Cancelable!bool {
        try self.mutex.lock(io);
        defer self.mutex.unlock(io);

        if (pool.shutting_down.load(.acquire)) return false;

        for (items) |item| {
            item.next = null;
            if (self.tail) |tail| {
                tail.next = item;
            } else {
                self.head = item;
            }
            self.tail = item;
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

    fn pop(self: *JobQueue) ?*WorkItem {
        const item = self.head orelse return null;
        self.head = item.next;
        if (self.head == null) {
            self.tail = null;
        }
        item.next = null;
        return item;
    }
};

/// A work item submitted to the queue. Each worker that picks one up
/// executes the work function, then signals `done`.
pub const WorkItem = struct {
    exec_fn: *const fn (*WorkItem) void,
    done: std.Io.Event = .unset,
    next: ?*WorkItem = null,
};

/// Creates a thread pool with the specified number of workers.
/// The caller owns the returned pool and must call `deinit` when done.
pub fn init(allocator_: Allocator, io: std.Io, opts: Opts) (Allocator.Error || std.Thread.SpawnError)!*ThreadPool {
    std.debug.assert(opts.n_workers >= 1);
    std.debug.assert(opts.n_workers <= MAX_WORKERS);

    const pool = try allocator_.create(ThreadPool);
    pool.* = .{
        .allocator = allocator_,
        .n_workers = opts.n_workers,
        .queue = .{},
    };
    for (0..pool.n_workers) |i| {
        pool.threads[i] = try std.Thread.spawn(.{}, workerLoop, .{ pool, io });
    }
    return pool;
}

/// Shuts down the thread pool and frees resources.
///
/// Cleanup happens in 3 phases:
///   1) stop accepting new work,
///   2) tell workers to drain queue then exist,
///   3) wait for workers to finish draining then cleanup
///
/// The pool pointer is invalid after this call.
pub fn deinit(pool: *ThreadPool, io: std.Io) void {
    // Phase 1: stop accepting new work
    pool.queue.mutex.lockUncancelable(io);
    pool.shutting_down.store(true, .release);

    // Phase 2: tell workers to drain queue then exit
    pool.shutdown.store(true, .release);
    pool.queue.cond.broadcast(io);
    pool.queue.mutex.unlock(io);

    // Phase 3: wait for workers to finish draining and cleanup
    for (pool.threads[0..pool.n_workers]) |t| t.join();
    pool.allocator.destroy(pool);
}

/// Main loop for worker threads.
///
/// Pops work first before checking for `shutdown` signal, allowing
/// workers to finish their work before closing.
///
/// Safety: it is safe to pop work first since we stop accepting work
/// in `pushBatch` by checking for the `shutting_down` signal; no new
/// work can be accepted at the point of entry into this loop.
fn workerLoop(pool: *ThreadPool, io: std.Io) void {
    while (true) {
        const item: *WorkItem = blk: {
            pool.queue.mutex.lockUncancelable(io);
            defer pool.queue.mutex.unlock(io);

            while (true) {
                if (pool.queue.pop()) |wi| break :blk wi;
                if (pool.shutdown.load(.acquire)) return;
                pool.queue.sleeping_workers += 1;
                pool.queue.cond.waitUncancelable(io, &pool.queue.mutex);
                pool.queue.sleeping_workers -= 1;
            }
        };

        item.exec_fn(item);
        item.done.set(io);
    }
}

/// Submit work items to the pool and wait for all to complete.
pub fn submitAndWait(pool: *ThreadPool, io: std.Io, items: []*WorkItem) (PoolError || std.Io.Cancelable)!void {
    if (!try pool.queue.pushBatch(io, pool, items)) return PoolError.ShuttingDown;
    // NOTE: must be uncancelable — work items live on the caller's stack, so a
    // cancel here would let workers write into freed frames.
    for (items) |item| {
        item.done.waitUncancelable(io);
    }
}

const VerifyMultiJob = struct {
    pks: []const *PublicKey,
    sigs: []const *Signature,
    msgs: []const [32]u8,
    rands: []const [32]u8,
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
        const n_elems = job.pks.len;

        while (true) {
            const i = job.counter.fetchAdd(1, .monotonic);
            if (i >= n_elems) break;
            if (job.err_flag.load(.monotonic)) break;

            pairing.mulAndAggregate(
                job.pks[i],
                job.pks_validate,
                job.sigs[i],
                job.sigs_groupcheck,
                &job.rands[i],
                RAND_BITS,
                &job.msgs[i],
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
pub fn verifyMultipleAggregateSignatures(
    pool: *ThreadPool,
    io: std.Io,
    n_elems: usize,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
    sigs: []const *Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
) (BlstError || PoolError || std.Io.Cancelable)!bool {
    if (n_elems == 0 or
        pks.len != n_elems or
        sigs.len != n_elems or
        msgs.len != n_elems or
        rands.len != n_elems)
        return BlstError.VerifyFail;

    const n_active = @min(pool.n_workers, n_elems);

    var result_bufs: [MAX_WORKERS]PairingBuf = undefined;

    var job = VerifyMultiJob{
        .pks = pks[0..n_elems],
        .sigs = sigs[0..n_elems],
        .msgs = msgs[0..n_elems],
        .rands = rands[0..n_elems],
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

    if (job.err_flag.load(.acquire)) return BlstError.VerifyFail;

    return mergeAndVerify(&result_bufs, n_active, null);
}

const AggVerifyJob = struct {
    pks: []const *PublicKey,
    msgs: []const [32]u8,
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
    msgs: []const [32]u8,
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
    c.blst_p1_to_affine(&pk_out.point, &pk_proj);

    var sig_proj: c.blst_p2 = undefined;
    try pippenger.parallelMSMG2(pool, io, sigs, scalars_refs[0..sigs.len], 64, &sig_proj);
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

    var msgs: [num_sigs][32]u8 = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]Signature = undefined;
    var pk_ptrs: [num_sigs]*PublicKey = undefined;
    var sig_ptrs: [num_sigs]*Signature = undefined;

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
        sig_ptrs[i] = &sigs[i];
    }

    var rands: [num_sigs][32]u8 = undefined;
    for (&rands) |*r| std.Random.bytes(rand, r);

    const result = try pool.verifyMultipleAggregateSignatures(
        std.testing.io,
        num_sigs,
        &msgs,
        blst.DST,
        &pk_ptrs,
        true,
        &sig_ptrs,
        true,
        &rands,
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
