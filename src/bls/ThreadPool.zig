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
const c = @cImport({
    @cInclude("blst.h");
});
const Pairing = @import("Pairing.zig");
const blst = @import("root.zig");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const BlstError = @import("error.zig").BlstError;
const SecretKey = @import("SecretKey.zig");

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
shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
queue: JobQueue,

const JobQueue = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    head: ?*WorkItem = null,

    fn pushBatch(self: *JobQueue, items: []*WorkItem) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (items) |item| {
            item.next = self.head;
            self.head = item;
        }
        self.cond.broadcast();
    }

    fn pop(self: *JobQueue) ?*WorkItem {
        // Called with mutex held
        const item = self.head orelse return null;
        self.head = item.next;
        item.next = null;
        return item;
    }
};

/// A work item submitted to the queue. Each worker that picks one up
/// executes the work function, then signals `done`.
const WorkItem = struct {
    exec_fn: *const fn (*WorkItem) void,
    done: std.Thread.ResetEvent = .{},
    next: ?*WorkItem = null,
};

/// Creates a thread pool with the specified number of workers.
/// The caller owns the returned pool and must call `deinit` when done.
pub fn init(allocator_: Allocator, opts: Opts) (Allocator.Error || std.Thread.SpawnError)!*ThreadPool {
    std.debug.assert(opts.n_workers >= 1 and opts.n_workers <= MAX_WORKERS);
    const pool = try allocator_.create(ThreadPool);
    pool.* = .{
        .allocator = allocator_,
        .n_workers = opts.n_workers,
        .queue = .{},
    };
    for (0..pool.n_workers) |i| {
        pool.threads[i] = try std.Thread.spawn(.{}, workerLoop, .{pool});
    }
    return pool;
}

/// Shuts down the thread pool and frees resources.
/// The pool pointer is invalid after this call.
pub fn deinit(pool: *ThreadPool) void {
    pool.shutdown.store(true, .release);
    {
        pool.queue.mutex.lock();
        defer pool.queue.mutex.unlock();
        pool.queue.cond.broadcast();
    }
    for (pool.threads[0..pool.n_workers]) |t| {
        t.join();
    }
    pool.allocator.destroy(pool);
}

fn workerLoop(pool: *ThreadPool) void {
    while (true) {
        const item: *WorkItem = blk: {
            pool.queue.mutex.lock();
            defer pool.queue.mutex.unlock();

            while (true) {
                if (pool.shutdown.load(.acquire)) return;
                if (pool.queue.pop()) |wi| {
                    break :blk wi;
                }
                pool.queue.cond.wait(&pool.queue.mutex);
            }
        };

        item.exec_fn(item);
        item.done.set();
    }
}

/// Submit work items to the pool and wait for all to complete.
fn submitAndWait(pool: *ThreadPool, items: []*WorkItem) void {
    pool.queue.pushBatch(items);
    for (items) |item| {
        item.done.wait();
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
    /// Workers write committed pairing results here. Indexed by result_count.
    result_bufs: []PairingBuf,
    result_count: std.atomic.Value(usize),
};

const VerifyMultiWorkItem = struct {
    base: WorkItem,
    job: *VerifyMultiJob,

    fn exec(base_item: *WorkItem) void {
        const self: *VerifyMultiWorkItem = @fieldParentPtr("base", base_item);
        const job = self.job;

        // Each worker gets its own pairing buffer on the stack
        var buf: PairingBuf = .{};
        var pairing = Pairing.init(&buf.data, true, job.dst);

        var did_work = false;
        const n_elems = job.pks.len;

        while (true) {
            const i = job.counter.fetchAdd(1, .monotonic);
            if (i >= n_elems) break;
            if (job.err_flag.load(.acquire)) break;

            did_work = true;

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

        if (did_work) {
            pairing.commit();
            const slot = job.result_count.fetchAdd(1, .acq_rel);
            job.result_bufs[slot] = buf;
        }
    }
};

/// Verifies multiple aggregate signatures in parallel using the thread pool.
///
/// This is the multi-threaded version of the same function in `fast_verify.zig`.
/// Multiple callers may invoke this concurrently — each call owns its own
/// pairing buffers and job state, workers pull from a shared queue.
pub fn verifyMultipleAggregateSignatures(
    pool: *ThreadPool,
    n_elems: usize,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
    sigs: []const *Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
) BlstError!bool {
    if (n_elems == 0 or
        pks.len != n_elems or
        sigs.len != n_elems or
        msgs.len != n_elems or
        rands.len != n_elems)
        return BlstError.VerifyFail;

    // Single-threaded fallback for small inputs or single worker
    if (n_elems <= 2 or pool.n_workers <= 1) {
        var buf: PairingBuf = .{};
        const fast_verify = @import("fast_verify.zig");
        return fast_verify.verifyMultipleAggregateSignatures(
            &buf.data,
            n_elems,
            msgs,
            dst,
            pks,
            pks_validate,
            sigs,
            sigs_groupcheck,
            rands,
        );
    }

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
        .result_count = std.atomic.Value(usize).init(0),
    };

    // Create work items on the stack — one per active worker
    var work_items: [MAX_WORKERS]VerifyMultiWorkItem = undefined;
    var item_ptrs: [MAX_WORKERS]*WorkItem = undefined;
    for (0..n_active) |i| {
        work_items[i] = .{
            .base = .{ .exec_fn = VerifyMultiWorkItem.exec },
            .job = &job,
        };
        item_ptrs[i] = &work_items[i].base;
    }

    pool.submitAndWait(item_ptrs[0..n_active]);

    if (job.err_flag.load(.acquire)) return BlstError.VerifyFail;

    const n_results = job.result_count.load(.acquire);
    if (n_results == 0) return BlstError.VerifyFail;

    return mergeAndVerify(&result_bufs, n_results, null);
}

const AggVerifyJob = struct {
    pks: []const *PublicKey,
    msgs: []const [32]u8,
    dst: []const u8,
    pks_validate: bool,
    n_elems: usize,
    counter: std.atomic.Value(usize),
    err_flag: std.atomic.Value(bool),
    result_bufs: []PairingBuf,
    result_count: std.atomic.Value(usize),
};

const AggVerifyWorkItem = struct {
    base: WorkItem,
    job: *AggVerifyJob,

    fn exec(base_item: *WorkItem) void {
        const self: *AggVerifyWorkItem = @fieldParentPtr("base", base_item);
        const job = self.job;

        var buf: PairingBuf = .{};
        var pairing = Pairing.init(&buf.data, true, job.dst);

        var did_work = false;

        while (true) {
            const i = job.counter.fetchAdd(1, .monotonic);
            if (i >= job.n_elems) break;
            if (job.err_flag.load(.acquire)) break;

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

        if (did_work) {
            pairing.commit();
            const slot = job.result_count.fetchAdd(1, .acq_rel);
            job.result_bufs[slot] = buf;
        }
    }
};

/// Verifies an aggregated signature against multiple messages and public keys
/// in parallel using the thread pool.
///
/// This is the multi-threaded version of `Signature.aggregateVerify`.
pub fn aggregateVerify(
    pool: *ThreadPool,
    sig: *const Signature,
    sig_groupcheck: bool,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
) BlstError!bool {
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
        .result_count = std.atomic.Value(usize).init(0),
    };

    var work_items: [MAX_WORKERS]AggVerifyWorkItem = undefined;
    var item_ptrs: [MAX_WORKERS]*WorkItem = undefined;
    for (0..n_active) |i| {
        work_items[i] = .{
            .base = .{ .exec_fn = AggVerifyWorkItem.exec },
            .job = &job,
        };
        item_ptrs[i] = &work_items[i].base;
    }

    pool.submitAndWait(item_ptrs[0..n_active]);

    if (job.err_flag.load(.acquire)) return false;

    const n_results = job.result_count.load(.acquire);
    if (n_results == 0) return false;

    var gtsig = c.blst_fp12{};
    Pairing.aggregated(&gtsig, sig);

    return mergeAndVerify(&result_bufs, n_results, &gtsig);
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

test "verifyMultipleAggregateSignatures multi-threaded" {
    const pool = try ThreadPool.init(std.testing.allocator, .{ .n_workers = 4 });
    defer pool.deinit();

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
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
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
    const pool = try ThreadPool.init(std.testing.allocator, .{ .n_workers = 4 });
    defer pool.deinit();

    const AggregateSignature = blst.AggregateSignature;

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
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
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

    const agg_sig = AggregateSignature.aggregate(&sigs, false) catch return error.AggregationFailed;
    const final_sig = agg_sig.toSignature();

    try std.testing.expect(try pool.aggregateVerify(
        &final_sig,
        false,
        &msgs,
        blst.DST,
        &pk_ptrs,
        true,
    ));
}
