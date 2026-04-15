//! Thread pool for parallel BLS operations.
//!
//! Provides multi-threaded versions of aggregation and verification functions
//! using a persistent pool of worker threads to avoid thread creation overhead.
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

const WorkItem = union(enum) {
    verify_multi: *VerifyMultiJob,
    aggregate_verify: *AggVerifyJob,
};

pub const Opts = struct {
    n_workers: u16 = 1,
};

allocator: Allocator,
n_workers: usize,
threads: [MAX_WORKERS - 1]std.Thread = undefined,
work_ready: [MAX_WORKERS]std.Thread.ResetEvent = [_]std.Thread.ResetEvent{.{}} ** MAX_WORKERS,
work_done: [MAX_WORKERS]std.Thread.ResetEvent = [_]std.Thread.ResetEvent{.{}} ** MAX_WORKERS,
work_items: [MAX_WORKERS]?WorkItem = [_]?WorkItem{null} ** MAX_WORKERS,
shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
pairing_bufs: [MAX_WORKERS]PairingBuf = [_]PairingBuf{.{}} ** MAX_WORKERS,
partial_p1: [MAX_WORKERS]c.blst_p1 = undefined,
partial_p2: [MAX_WORKERS]c.blst_p2 = undefined,
has_work: [MAX_WORKERS]bool = [_]bool{false} ** MAX_WORKERS,
/// Mutex for dispatching multi-threaded verification work.
dispatch_mutex: std.Thread.Mutex = .{},

/// Creates a thread pool with the specified number of workers.
/// The caller owns the returned pool and must call `deinit` when done.
pub fn init(allocator: Allocator, opts: Opts) (Allocator.Error || std.Thread.SpawnError)!*ThreadPool {
    std.debug.assert(opts.n_workers >= 1 and opts.n_workers <= MAX_WORKERS);
    const pool = try allocator.create(ThreadPool);
    pool.* = .{ .allocator = allocator, .n_workers = opts.n_workers };
    // Workers start from index 1; index 0 is reserved for the calling thread
    // which executes as worker 0 inside dispatch() to avoid wasting a core.
    for (1..pool.n_workers) |i| {
        pool.threads[i - 1] = try std.Thread.spawn(.{}, workerLoop, .{ pool, i });
    }
    return pool;
}

/// Shuts down the thread pool and frees resources.
/// The pool pointer is invalid after this call.
pub fn deinit(pool: *ThreadPool) void {
    pool.shutdown.store(true, .release);
    const n_workers = pool.n_workers;
    for (1..n_workers) |i| {
        pool.work_ready[i].set();
    }
    for (pool.threads[0 .. n_workers - 1]) |t| {
        t.join();
    }
    pool.allocator.destroy(pool);
}

/// Handles a `WorkItem`.
///
/// Currently supports `aggregateVerify` and `verifyMultipleAggregateSignatures`.
fn workerLoop(pool: *ThreadPool, worker_index: usize) void {
    while (true) {
        pool.work_ready[worker_index].wait();
        pool.work_ready[worker_index].reset();

        if (pool.shutdown.load(.acquire)) return;

        const item = pool.work_items[worker_index] orelse {
            pool.work_done[worker_index].set();
            continue;
        };

        switch (item) {
            .verify_multi => |job| execVerifyMulti(pool, job, worker_index),
            .aggregate_verify => |job| execAggVerify(pool, job, worker_index),
        }

        pool.work_items[worker_index] = null;
        pool.work_done[worker_index].set();
    }
}

fn dispatch(pool: *ThreadPool, item: WorkItem, n_active: usize) void {
    std.debug.assert(n_active <= pool.n_workers);

    // Signal background workers before main thread starts
    for (1..n_active) |i| {
        pool.work_items[i] = item;
        pool.work_ready[i].set();
    }

    // Main thread executes as worker 0
    pool.work_items[0] = item;
    switch (item) {
        .verify_multi => |job| execVerifyMulti(pool, job, 0),
        .aggregate_verify => |job| execAggVerify(pool, job, 0),
    }
    pool.work_items[0] = null;

    // Wait for all background workers
    for (1..n_active) |i| {
        pool.work_done[i].wait();
        pool.work_done[i].reset();
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
};

fn execVerifyMulti(pool: *ThreadPool, job: *VerifyMultiJob, worker_index: usize) void {
    var pairing = Pairing.init(
        &pool.pairing_bufs[worker_index].data,
        true,
        job.dst,
    );

    var did_work = false;
    const n_elems = job.pks.len;

    while (true) {
        const i = job.counter.fetchAdd(1, .monotonic);
        if (i >= n_elems) break;
        if (job.err_flag.load(.monotonic)) break;

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

    if (did_work) pairing.commit();
    pool.has_work[worker_index] = did_work;
}

/// Verifies multiple aggregate signatures in parallel using the thread pool.
///
/// This is the multi-threaded version of the same function in `fast_verify.zig`.
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

    pool.dispatch_mutex.lock();
    defer pool.dispatch_mutex.unlock();

    // Single-threaded fallback for small inputs or single worker
    if (n_elems <= 2 or pool.n_workers <= 1) {
        const fast_verify = @import("fast_verify.zig");
        return fast_verify.verifyMultipleAggregateSignatures(
            &pool.pairing_bufs[0].data,
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
    };

    @memset(pool.has_work[0..n_active], false);
    pool.dispatch(.{ .verify_multi = &job }, n_active);

    if (job.err_flag.load(.acquire)) return BlstError.VerifyFail;

    return mergeAndVerify(pool, n_active, null);
}

const AggVerifyJob = struct {
    pks: []const *PublicKey,
    msgs: []const [32]u8,
    dst: []const u8,
    pks_validate: bool,
    n_elems: usize,
    counter: std.atomic.Value(usize),
    err_flag: std.atomic.Value(bool),
};

fn execAggVerify(pool: *ThreadPool, job: *AggVerifyJob, worker_index: usize) void {
    var pairing = Pairing.init(
        &pool.pairing_bufs[worker_index].data,
        true,
        job.dst,
    );

    var did_work = false;

    while (true) {
        const i = job.counter.fetchAdd(1, .monotonic);
        if (i >= job.n_elems) break;
        if (job.err_flag.load(.monotonic)) break;

        did_work = true;

        // Workers only aggregate pk+msg pairs; the signature is handled
        // separately on the main thread after dispatch.
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

    if (did_work) pairing.commit();
    pool.has_work[worker_index] = did_work;
}

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

    pool.dispatch_mutex.lock();
    defer pool.dispatch_mutex.unlock();

    // Single-threaded fallback
    if (n_elems <= 2 or pool.n_workers <= 1) {
        var pairing = Pairing.init(&pool.pairing_bufs[0].data, true, dst);
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

    // Validate `sig` on the main thread (runs concurrently with merge below)
    if (sig_groupcheck) sig.validate(false) catch return false;
    var job = AggVerifyJob{
        .pks = pks[0..n_elems],
        .msgs = msgs[0..n_elems],
        .dst = dst,
        .pks_validate = pks_validate,
        .n_elems = n_elems,
        .counter = std.atomic.Value(usize).init(0),
        .err_flag = std.atomic.Value(bool).init(false),
    };

    @memset(pool.has_work[0..n_active], false);
    pool.dispatch(.{ .aggregate_verify = &job }, n_active);

    if (job.err_flag.load(.acquire)) return false;

    var gtsig = c.blst_fp12{};
    Pairing.aggregated(&gtsig, sig);

    return mergeAndVerify(pool, n_active, &gtsig);
}

/// Merges all of `pool`'s `pairing_bufs` and execute `finalVerify` on the accumulated `acc`.
///
/// Perform final verification of `gtsig`, returning `false` if verification fails.
fn mergeAndVerify(pool: *ThreadPool, n_active: usize, gtsig: ?*const c.blst_fp12) BlstError!bool {
    var acc_idx: ?usize = null;
    for (0..n_active) |i| {
        if (pool.has_work[i]) {
            acc_idx = i;
            break;
        }
    }

    const first = acc_idx orelse return BlstError.MergeError;
    var acc = Pairing{ .ctx = @ptrCast(&pool.pairing_bufs[first].data) };

    for (first + 1..n_active) |i| {
        if (pool.has_work[i]) {
            const other = Pairing{ .ctx = @ptrCast(&pool.pairing_bufs[i].data) };
            try acc.merge(&other);
        }
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
