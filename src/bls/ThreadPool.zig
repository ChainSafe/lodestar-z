//! Thread pool for parallel BLS operations.
//!
//! Provides multi-threaded versions of aggregation and verification functions
//! using a persistent pool of worker threads to avoid thread creation overhead.
const ThreadPool = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @import("blst");
const Pairing = @import("Pairing.zig");
const blst = @import("root.zig");
const fast_verify = @import("fast_verify.zig");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const SignatureSet = blst.SignatureSet;
const BlstError = @import("error.zig").BlstError;
const SecretKey = @import("SecretKey.zig");

/// This is pretty arbitrary
pub const MAX_WORKERS: usize = 16;
pub const MAX_ASYNC_VERIFY_SETS_JOBS: usize = 16;

/// Number of random bits used for verification.
const RAND_BITS = 64;

const PairingBuf = struct {
    data: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined,
};

const WorkItem = union(enum) {
    verify_multi: *VerifyMultiJob,
    verify_sets: *VerifySetsJob,
    verify_same_message_sets: *VerifySameMessageSetsJob,
    aggregate_verify: *AggVerifyJob,
};

pub const Opts = struct {
    n_workers: u16 = 1,
    use_caller_thread: bool = true,
    max_async_verify_sets_jobs: u16 = 4,
};

allocator: Allocator,
io: std.Io,
n_workers: usize,
use_caller_thread: bool,
spawned_threads: usize = 0,
threads: [MAX_WORKERS]std.Thread = undefined,
work_ready: [MAX_WORKERS]std.Io.Event = [_]std.Io.Event{.unset} ** MAX_WORKERS,
work_done: [MAX_WORKERS]std.Io.Event = [_]std.Io.Event{.unset} ** MAX_WORKERS,
work_items: [MAX_WORKERS]?WorkItem = [_]?WorkItem{null} ** MAX_WORKERS,
shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
pairing_bufs: [MAX_WORKERS]PairingBuf = [_]PairingBuf{.{}} ** MAX_WORKERS,
partial_p1: [MAX_WORKERS]c.blst_p1 = undefined,
partial_p2: [MAX_WORKERS]c.blst_p2 = undefined,
has_work: [MAX_WORKERS]bool = [_]bool{false} ** MAX_WORKERS,
/// Mutex for dispatching multi-threaded verification work.
dispatch_mutex: std.Io.Mutex = .init,
async_verify_sets_mutex: std.Io.Mutex = .init,
max_async_verify_sets_jobs: usize,
active_verify_sets: ?*VerifySetsFuture = null,
queued_verify_sets_len: usize = 0,
queued_verify_sets: [MAX_ASYNC_VERIFY_SETS_JOBS]?*VerifySetsFuture = [_]?*VerifySetsFuture{null} ** MAX_ASYNC_VERIFY_SETS_JOBS,

/// Creates a thread pool with the specified number of workers.
/// The caller owns the returned pool and must call `deinit` when done.
pub fn init(allocator: Allocator, io: std.Io, opts: Opts) (Allocator.Error || std.Thread.SpawnError)!*ThreadPool {
    std.debug.assert(opts.n_workers >= 1 and opts.n_workers <= MAX_WORKERS);
    std.debug.assert(opts.max_async_verify_sets_jobs >= 1 and opts.max_async_verify_sets_jobs <= MAX_ASYNC_VERIFY_SETS_JOBS);
    const pool = try allocator.create(ThreadPool);
    pool.* = .{
        .allocator = allocator,
        .io = io,
        .n_workers = opts.n_workers,
        .use_caller_thread = opts.use_caller_thread,
        .max_async_verify_sets_jobs = opts.max_async_verify_sets_jobs,
    };

    const start_index: usize = if (pool.use_caller_thread) 1 else 0;
    for (start_index..pool.n_workers) |i| {
        pool.threads[pool.spawned_threads] = try std.Thread.spawn(.{}, workerLoop, .{ pool, i });
        pool.spawned_threads += 1;
    }
    return pool;
}

/// Shuts down the thread pool and frees resources.
/// The pool pointer is invalid after this call.
pub fn deinit(pool: *ThreadPool) void {
    pool.shutdown.store(true, .release);
    const n_workers = pool.n_workers;
    const start_index: usize = if (pool.use_caller_thread) 1 else 0;
    for (start_index..n_workers) |i| {
        pool.work_ready[i].set(pool.io);
    }
    for (pool.threads[0..pool.spawned_threads]) |t| {
        t.join();
    }
    pool.allocator.destroy(pool);
}

/// Handles a `WorkItem`.
///
/// Currently supports `aggregateVerify` and `verifyMultipleAggregateSignatures`.
fn workerLoop(pool: *ThreadPool, worker_index: usize) void {
    while (true) {
        pool.work_ready[worker_index].wait(pool.io) catch unreachable;
        pool.work_ready[worker_index].reset();

        if (pool.shutdown.load(.acquire)) return;

        const item = pool.work_items[worker_index] orelse {
            pool.work_done[worker_index].set(pool.io);
            continue;
        };

        switch (item) {
            .verify_multi => |job| execVerifyMulti(pool, job, worker_index),
            .verify_sets => |job| execVerifySets(pool, job, worker_index),
            .verify_same_message_sets => |job| execVerifySameMessageSets(pool, job, worker_index),
            .aggregate_verify => |job| execAggVerify(pool, job, worker_index),
        }

        pool.work_items[worker_index] = null;
        pool.work_done[worker_index].set(pool.io);
    }
}

fn dispatch(pool: *ThreadPool, item: WorkItem, n_active: usize) void {
    std.debug.assert(n_active <= pool.n_workers);

    if (pool.use_caller_thread) {
        // Signal background workers before main thread starts.
        for (1..n_active) |i| {
            pool.work_items[i] = item;
            pool.work_ready[i].set(pool.io);
        }

        // Main thread executes as worker 0.
        pool.work_items[0] = item;
        switch (item) {
            .verify_multi => |job| execVerifyMulti(pool, job, 0),
            .verify_sets => |job| execVerifySets(pool, job, 0),
            .verify_same_message_sets => |job| execVerifySameMessageSets(pool, job, 0),
            .aggregate_verify => |job| execAggVerify(pool, job, 0),
        }
        pool.work_items[0] = null;

        // Wait for all background workers.
        for (1..n_active) |i| {
            pool.work_done[i].wait(pool.io) catch unreachable;
            pool.work_done[i].reset();
        }
    } else {
        for (0..n_active) |i| {
            pool.work_items[i] = item;
            pool.work_ready[i].set(pool.io);
        }
        for (0..n_active) |i| {
            pool.work_done[i].wait(pool.io) catch unreachable;
            pool.work_done[i].reset();
        }
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

    if (did_work) pairing.commit();
    pool.has_work[worker_index] = did_work;
}

const VerifySetsJob = struct {
    sets: []const SignatureSet,
    rands: []const [32]u8,
    dst: []const u8,
    counter: std.atomic.Value(usize),
    err_flag: std.atomic.Value(bool),
};

pub const StartVerifySetsError = Allocator.Error || BlstError || error{
    ThreadPoolBusy,
    AsyncDispatchRequiresBackgroundWorkers,
};

pub const VerifySetsPriority = enum(u8) {
    normal,
    high,
};

pub const StartVerifySetsOpts = struct {
    priority: VerifySetsPriority = .normal,
};

pub const VerifySetsFuture = struct {
    pub const Mode = enum {
        generic,
        same_message,
    };

    pool: *ThreadPool,
    allocator: Allocator,
    sets: []SignatureSet,
    rands: [][32]u8,
    dst: []u8,
    mode: Mode,
    job: VerifySetsJob,
    same_message_job: VerifySameMessageSetsJob,
    n_active: usize,
    priority: VerifySetsPriority,
    partial_aggregates: [MAX_WORKERS]fast_verify.SameMessageAggregate = undefined,
    started: std.Io.Event = .unset,

    pub fn isReady(self: *const VerifySetsFuture) bool {
        if (!self.started.isSet()) return false;
        for (0..self.n_active) |i| {
            if (!self.pool.work_done[i].isSet()) return false;
        }
        return true;
    }

    fn waitAll(self: *VerifySetsFuture) void {
        for (0..self.n_active) |i| {
            self.pool.work_done[i].wait(self.pool.io) catch unreachable;
        }
    }

    pub fn finish(self: *VerifySetsFuture) BlstError!bool {
        if (!self.started.isSet()) {
            self.started.wait(self.pool.io) catch unreachable;
        }

        self.waitAll();
        const result: BlstError!bool = switch (self.mode) {
            .generic => if (self.job.err_flag.load(.acquire))
                BlstError.VerifyFail
            else
                mergeAndVerify(self.pool, self.n_active, null),
            .same_message => if (self.same_message_job.err_flag.load(.acquire))
                BlstError.VerifyFail
            else
                self.finishSameMessage(),
        };

        const pool = self.pool;
        pool.async_verify_sets_mutex.lockUncancelable(pool.io);
        defer pool.async_verify_sets_mutex.unlock(pool.io);
        self.cleanupLocked();

        return result;
    }

    fn finishSameMessage(self: *VerifySetsFuture) BlstError!bool {
        var first_idx: ?usize = null;
        for (0..self.n_active) |i| {
            if (self.pool.has_work[i]) {
                first_idx = i;
                break;
            }
        }

        const first = first_idx orelse return BlstError.VerifyFail;
        var aggregate = self.partial_aggregates[first];
        for (first + 1..self.n_active) |i| {
            if (!self.pool.has_work[i]) continue;
            c.blst_p1_add_or_double(
                @ptrCast(&aggregate.public_key.point),
                @ptrCast(&aggregate.public_key.point),
                @ptrCast(&self.partial_aggregates[i].public_key.point),
            );
            c.blst_p2_add_or_double(
                @ptrCast(&aggregate.signature.point),
                @ptrCast(&aggregate.signature.point),
                @ptrCast(&self.partial_aggregates[i].signature.point),
            );
        }

        const sig = aggregate.signature.toSignature();
        const pk = aggregate.public_key.toPublicKey();
        var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
        return sig.fastAggregateVerifyPreAggregated(
            true,
            &pairing_buf,
            &self.same_message_job.message,
            self.same_message_job.dst,
            &pk,
        );
    }

    fn cleanupLocked(self: *VerifySetsFuture) void {
        std.debug.assert(self.pool.active_verify_sets == self);
        for (0..self.n_active) |i| {
            if (self.pool.work_done[i].isSet()) {
                self.pool.work_done[i].reset();
            }
            self.pool.work_items[i] = null;
        }

        self.pool.active_verify_sets = null;
        if (self.pool.queued_verify_sets_len > 0) {
            const next = self.pool.dequeueVerifySetsFutureLocked();
            self.pool.startVerifySetsFutureLocked(next);
        } else {
            self.pool.dispatch_mutex.unlock(self.pool.io);
        }

        self.allocator.free(self.dst);
        self.allocator.free(self.rands);
        self.allocator.free(self.sets);
        self.allocator.destroy(self);
    }
};

fn execVerifySets(pool: *ThreadPool, job: *VerifySetsJob, worker_index: usize) void {
    var pairing = Pairing.init(
        &pool.pairing_bufs[worker_index].data,
        true,
        job.dst,
    );

    var did_work = false;
    const n_elems = job.sets.len;

    while (true) {
        const i = job.counter.fetchAdd(1, .monotonic);
        if (i >= n_elems) break;
        if (job.err_flag.load(.acquire)) break;

        did_work = true;

        const pk = job.sets[i].resolvePublicKey() catch {
            job.err_flag.store(true, .release);
            break;
        };
        const sig = job.sets[i].decompressSignature() catch {
            job.err_flag.store(true, .release);
            break;
        };

        pairing.mulAndAggregate(
            &pk,
            false,
            &sig,
            true,
            &job.rands[i],
            RAND_BITS,
            &job.sets[i].signing_root,
        ) catch {
            job.err_flag.store(true, .release);
            break;
        };
    }

    if (did_work) pairing.commit();
    pool.has_work[worker_index] = did_work;
}

const VerifySameMessageSetsJob = struct {
    sets: []const SignatureSet,
    rands: []const [32]u8,
    dst: []const u8,
    message: [32]u8,
    n_active: usize,
    partial_aggregates: *[MAX_WORKERS]fast_verify.SameMessageAggregate,
    err_flag: std.atomic.Value(bool),
};

fn execVerifySameMessageSets(pool: *ThreadPool, job: *VerifySameMessageSetsJob, worker_index: usize) void {
    const start = @divFloor(worker_index * job.sets.len, job.n_active);
    const end = @divFloor((worker_index + 1) * job.sets.len, job.n_active);

    if (start >= end) {
        pool.has_work[worker_index] = false;
        return;
    }

    job.partial_aggregates[worker_index] = fast_verify.aggregateSignatureSetsSameMessage(
        job.sets[start..end],
        &job.message,
        job.rands[start..end],
    ) catch {
        job.err_flag.store(true, .release);
        pool.has_work[worker_index] = false;
        return;
    };

    pool.has_work[worker_index] = true;
}

pub fn canAcceptWork(pool: *ThreadPool) bool {
    pool.async_verify_sets_mutex.lockUncancelable(pool.io);
    defer pool.async_verify_sets_mutex.unlock(pool.io);
    return pool.asyncVerifySetsJobCountLocked() < pool.max_async_verify_sets_jobs;
}

pub fn startVerifySignatureSets(
    pool: *ThreadPool,
    allocator: Allocator,
    sets: []const SignatureSet,
    dst: []const u8,
    opts: StartVerifySetsOpts,
) StartVerifySetsError!*VerifySetsFuture {
    if (pool.use_caller_thread) return error.AsyncDispatchRequiresBackgroundWorkers;
    if (sets.len == 0) return BlstError.VerifyFail;

    const future = try allocator.create(VerifySetsFuture);
    errdefer allocator.destroy(future);

    const owned_sets = try allocator.dupe(SignatureSet, sets);
    errdefer allocator.free(owned_sets);

    const owned_rands = try allocator.alloc([32]u8, sets.len);
    errdefer allocator.free(owned_rands);
    fillRandomScalars(owned_rands);

    const owned_dst = try allocator.dupe(u8, dst);
    errdefer allocator.free(owned_dst);

    const n_active = @min(pool.n_workers, sets.len);
    future.* = .{
        .pool = pool,
        .allocator = allocator,
        .sets = owned_sets,
        .rands = owned_rands,
        .dst = owned_dst,
        .mode = .generic,
        .job = .{
            .sets = owned_sets,
            .rands = owned_rands,
            .dst = owned_dst,
            .counter = std.atomic.Value(usize).init(0),
            .err_flag = std.atomic.Value(bool).init(false),
        },
        .same_message_job = undefined,
        .n_active = n_active,
        .priority = opts.priority,
    };

    pool.async_verify_sets_mutex.lockUncancelable(pool.io);
    defer pool.async_verify_sets_mutex.unlock(pool.io);

    if (pool.asyncVerifySetsJobCountLocked() >= pool.max_async_verify_sets_jobs) {
        return error.ThreadPoolBusy;
    }

    if (pool.active_verify_sets == null) {
        pool.dispatch_mutex.lockUncancelable(pool.io);
        pool.startVerifySetsFutureLocked(future);
    } else {
        pool.enqueueVerifySetsFutureLocked(future);
    }

    return future;
}

pub fn startVerifySignatureSetsSameMessage(
    pool: *ThreadPool,
    allocator: Allocator,
    sets: []const SignatureSet,
    dst: []const u8,
    opts: StartVerifySetsOpts,
) StartVerifySetsError!*VerifySetsFuture {
    if (pool.use_caller_thread) return error.AsyncDispatchRequiresBackgroundWorkers;
    if (sets.len == 0) return BlstError.VerifyFail;

    const future = try allocator.create(VerifySetsFuture);
    errdefer allocator.destroy(future);

    const owned_sets = try allocator.dupe(SignatureSet, sets);
    errdefer allocator.free(owned_sets);

    const owned_rands = try allocator.alloc([32]u8, sets.len);
    errdefer allocator.free(owned_rands);
    fillRandomScalars(owned_rands);

    const owned_dst = try allocator.dupe(u8, dst);
    errdefer allocator.free(owned_dst);

    const n_active = @min(pool.n_workers, sets.len);
    future.* = .{
        .pool = pool,
        .allocator = allocator,
        .sets = owned_sets,
        .rands = owned_rands,
        .dst = owned_dst,
        .mode = .same_message,
        .job = undefined,
        .same_message_job = .{
            .sets = owned_sets,
            .rands = owned_rands,
            .dst = owned_dst,
            .message = owned_sets[0].signing_root,
            .n_active = n_active,
            .partial_aggregates = &future.partial_aggregates,
            .err_flag = std.atomic.Value(bool).init(false),
        },
        .n_active = n_active,
        .priority = opts.priority,
    };

    pool.async_verify_sets_mutex.lockUncancelable(pool.io);
    defer pool.async_verify_sets_mutex.unlock(pool.io);

    if (pool.asyncVerifySetsJobCountLocked() >= pool.max_async_verify_sets_jobs) {
        return error.ThreadPoolBusy;
    }

    if (pool.active_verify_sets == null) {
        pool.dispatch_mutex.lockUncancelable(pool.io);
        pool.startVerifySetsFutureLocked(future);
    } else {
        pool.enqueueVerifySetsFutureLocked(future);
    }

    return future;
}

fn asyncVerifySetsJobCountLocked(pool: *const ThreadPool) usize {
    return @intFromBool(pool.active_verify_sets != null) + pool.queued_verify_sets_len;
}

fn enqueueVerifySetsFutureLocked(pool: *ThreadPool, future: *VerifySetsFuture) void {
    std.debug.assert(pool.queued_verify_sets_len < pool.max_async_verify_sets_jobs);
    std.debug.assert(pool.queued_verify_sets_len < MAX_ASYNC_VERIFY_SETS_JOBS);

    var insert_at = pool.queued_verify_sets_len;
    if (future.priority == .high) {
        insert_at = 0;
        while (insert_at < pool.queued_verify_sets_len) : (insert_at += 1) {
            const existing = pool.queued_verify_sets[insert_at].?;
            if (existing.priority != .high) break;
        }
    }

    var i = pool.queued_verify_sets_len;
    while (i > insert_at) : (i -= 1) {
        pool.queued_verify_sets[i] = pool.queued_verify_sets[i - 1];
    }
    pool.queued_verify_sets[insert_at] = future;
    pool.queued_verify_sets_len += 1;
}

fn dequeueVerifySetsFutureLocked(pool: *ThreadPool) *VerifySetsFuture {
    std.debug.assert(pool.queued_verify_sets_len > 0);
    const future = pool.queued_verify_sets[0].?;
    var i: usize = 1;
    while (i < pool.queued_verify_sets_len) : (i += 1) {
        pool.queued_verify_sets[i - 1] = pool.queued_verify_sets[i];
    }
    pool.queued_verify_sets[pool.queued_verify_sets_len - 1] = null;
    pool.queued_verify_sets_len -= 1;
    return future;
}

fn startVerifySetsFutureLocked(pool: *ThreadPool, future: *VerifySetsFuture) void {
    std.debug.assert(pool.active_verify_sets == null);

    pool.active_verify_sets = future;
    @memset(pool.has_work[0..future.n_active], false);
    for (0..future.n_active) |i| {
        pool.work_items[i] = switch (future.mode) {
            .generic => .{ .verify_sets = &future.job },
            .same_message => .{ .verify_same_message_sets = &future.same_message_job },
        };
        pool.work_ready[i].set(pool.io);
    }
    future.started.set(pool.io);
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

    // Acquire dispatch lock — serializes concurrent verification requests.
    pool.dispatch_mutex.lockUncancelable(pool.io);
    defer pool.dispatch_mutex.unlock(pool.io);

    // Single-threaded fallback for small inputs or single worker
    if (n_elems <= 2 or pool.n_workers <= 1) {
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

/// Verifies a batch of signature sets in parallel using the thread pool.
///
/// Aggregate-pubkey resolution and signature decompression happen on worker
/// threads rather than on the caller thread.
pub fn verifySignatureSets(
    pool: *ThreadPool,
    sets: []const SignatureSet,
    dst: []const u8,
    rands: []const [32]u8,
) BlstError!bool {
    if (sets.len == 0 or rands.len != sets.len) return BlstError.VerifyFail;

    pool.dispatch_mutex.lockUncancelable(pool.io);
    defer pool.dispatch_mutex.unlock(pool.io);

    if (sets.len <= 2 or pool.n_workers <= 1) {
        return fast_verify.verifySignatureSets(
            &pool.pairing_bufs[0].data,
            sets,
            dst,
            rands,
        );
    }

    const n_active = @min(pool.n_workers, sets.len);

    var job = VerifySetsJob{
        .sets = sets,
        .rands = rands,
        .dst = dst,
        .counter = std.atomic.Value(usize).init(0),
        .err_flag = std.atomic.Value(bool).init(false),
    };

    @memset(pool.has_work[0..n_active], false);
    pool.dispatch(.{ .verify_sets = &job }, n_active);

    if (job.err_flag.load(.acquire)) return BlstError.VerifyFail;

    return mergeAndVerify(pool, n_active, null);
}

fn fillRandomScalars(rands: [][32]u8) void {
    const bytes = std.mem.sliceAsBytes(rands);
    std.Options.debug_io.randomSecure(bytes) catch std.Options.debug_io.random(bytes);
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
        if (job.err_flag.load(.acquire)) break;

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

    // Acquire dispatch lock (see comment in verifyMultipleAggregateSignatures).
    pool.dispatch_mutex.lockUncancelable(pool.io);
    defer pool.dispatch_mutex.unlock(pool.io);

    // Single-threaded fallback
    if (n_elems <= 2 or pool.n_workers <= 1) {
        var pairing = Pairing.init(&pool.pairing_bufs[0].data, true, dst);
        try pairing.aggregate(pks[0], pks_validate, sig, sig_groupcheck, &msgs[0], null);
        for (1..n_elems) |i| {
            try pairing.aggregate(pks[i], pks_validate, null, false, &msgs[i], null);
        }
        pairing.commit();
        var gtsig = c.blst_fp12{};
        Pairing.aggregated(@ptrCast(&gtsig), sig);
        return pairing.finalVerify(@ptrCast(&gtsig));
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
    Pairing.aggregated(@ptrCast(&gtsig), sig);

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

    return acc.finalVerify(@ptrCast(gtsig));
}

test "verifyMultipleAggregateSignatures multi-threaded" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 4 });
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
        break :blk 0xDEADBEEF_CAFEBABE;
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
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{ .n_workers = 4 });
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
        break :blk 0xDEADBEEF_CAFEBABE;
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

test "verifySignatureSets multi-threaded without caller worker" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{
        .n_workers = 2,
        .use_caller_thread = false,
    });
    defer pool.deinit();

    const ikm_a: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const ikm_b: [32]u8 = .{
        0x94, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const msg_a = [_]u8{0xAA} ** 32;
    const msg_b = [_]u8{0xBB} ** 32;

    const sk_a = try SecretKey.keyGen(&ikm_a, null);
    const sk_b = try SecretKey.keyGen(&ikm_b, null);
    const pk_a = sk_a.toPublicKey();
    const pk_b = sk_b.toPublicKey();
    const sig_a = sk_a.sign(&msg_a, blst.DST, null);
    const sig_b = sk_b.sign(&msg_b, blst.DST, null);

    const sets = [_]SignatureSet{
        SignatureSet.initSingle(pk_a, msg_a, sig_a.compress()),
        SignatureSet.initSingle(pk_b, msg_b, sig_b.compress()),
    };

    var prng = std.Random.DefaultPrng.init(0x1234_5678_9ABC_DEF0);
    const rand = prng.random();
    var rands: [2][32]u8 = undefined;
    for (&rands) |*r| std.Random.bytes(rand, r);

    try std.testing.expect(try pool.verifySignatureSets(&sets, blst.DST, &rands));
}

test "startVerifySignatureSets dispatches asynchronously on background-only pool" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{
        .n_workers = 2,
        .use_caller_thread = false,
        .max_async_verify_sets_jobs = 1,
    });
    defer pool.deinit();

    const ikm_a: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const ikm_b: [32]u8 = .{
        0x94, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const msg_a = [_]u8{0xAA} ** 32;
    const msg_b = [_]u8{0xBB} ** 32;

    const sk_a = try SecretKey.keyGen(&ikm_a, null);
    const sk_b = try SecretKey.keyGen(&ikm_b, null);
    const pk_a = sk_a.toPublicKey();
    const pk_b = sk_b.toPublicKey();
    const sig_a = sk_a.sign(&msg_a, blst.DST, null);
    const sig_b = sk_b.sign(&msg_b, blst.DST, null);

    const sets = [_]SignatureSet{
        SignatureSet.initSingle(pk_a, msg_a, sig_a.compress()),
        SignatureSet.initSingle(pk_b, msg_b, sig_b.compress()),
    };

    const future = try pool.startVerifySignatureSets(std.testing.allocator, &sets, blst.DST, .{});
    try std.testing.expect(!pool.canAcceptWork());
    try std.testing.expect(try future.finish());
    try std.testing.expect(pool.canAcceptWork());
}

test "startVerifySignatureSets queues high priority work ahead of normal work" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{
        .n_workers = 2,
        .use_caller_thread = false,
        .max_async_verify_sets_jobs = 3,
    });
    defer pool.deinit();

    const ikm_a: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    var msgs: [3][32]u8 = .{
        [_]u8{0xAA} ** 32,
        [_]u8{0xBB} ** 32,
        [_]u8{0xCC} ** 32,
    };
    var sets_storage: [3]SignatureSet = undefined;

    for (0..3) |i| {
        var ikm = ikm_a;
        ikm[0] +%= @intCast(i);
        const sk = try SecretKey.keyGen(&ikm, null);
        const pk = sk.toPublicKey();
        const sig = sk.sign(&msgs[i], blst.DST, null);
        sets_storage[i] = SignatureSet.initSingle(pk, msgs[i], sig.compress());
    }

    const future_a = try pool.startVerifySignatureSets(std.testing.allocator, sets_storage[0..1], blst.DST, .{ .priority = .normal });
    const future_b = try pool.startVerifySignatureSets(std.testing.allocator, sets_storage[1..2], blst.DST, .{ .priority = .normal });
    const future_c = try pool.startVerifySignatureSets(std.testing.allocator, sets_storage[2..3], blst.DST, .{ .priority = .high });

    try std.testing.expect(try future_a.finish());
    try std.testing.expect(!future_b.started.isSet());
    try std.testing.expect(future_c.started.isSet());
    try std.testing.expect(try future_c.finish());
    try std.testing.expect(try future_b.finish());
}

test "startVerifySignatureSetsSameMessage dispatches asynchronously on background-only pool" {
    const pool = try ThreadPool.init(std.testing.allocator, std.testing.io, .{
        .n_workers = 2,
        .use_caller_thread = false,
        .max_async_verify_sets_jobs = 1,
    });
    defer pool.deinit();

    const base_ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const msg = [_]u8{0xAA} ** 32;
    var sets: [3]SignatureSet = undefined;
    for (0..sets.len) |i| {
        var ikm = base_ikm;
        ikm[0] +%= @intCast(i);
        const sk = try SecretKey.keyGen(&ikm, null);
        sets[i] = SignatureSet.initSingle(sk.toPublicKey(), msg, sk.sign(&msg, blst.DST, null).compress());
    }

    const future = try pool.startVerifySignatureSetsSameMessage(
        std.testing.allocator,
        &sets,
        blst.DST,
        .{ .priority = .high },
    );

    try std.testing.expect(!pool.canAcceptWork());
    try std.testing.expect(try future.finish());
    try std.testing.expect(pool.canAcceptWork());
}
