//! blsBatch — high-level BLS batch verification that resolves pubkeys by
//! validator index from the shared pubkey cache and dispatches heavy crypto
//! to the libuv thread-pool.
//!
//! All NAPI parsing, pubkey resolution, and signature deserialization happen
//! on the main thread.  Async jobs pass fully-resolved (msgs, pks, sigs) to
//! a worker thread that only does the expensive pairing math.
//!
//! Memory strategy
//! ───────────────
//! Sync path: threadlocal arena, reset with retain_capacity after each call.
//!
//! Async path: a fixed pool of reusable buffer triples (msgs, pks, sigs),
//! all pre-allocated at init time.  On dispatch, pop a buffer from the pool;
//! on completion, push it back.  The hot path does zero allocator calls.
//! The JS-side manager gates dispatching via canAcceptWork() to ensure a
//! free slot is available before dispatching.
//!
//! Worker threads use a threadlocal arena for per-job temporaries (random
//! scalars, Pippenger scratch).  The arena is reset after each job.
const std = @import("std");
const napi = @import("zapi:napi");
const blst = @import("blst");
const builtin = @import("builtin");
const pubkeys = @import("./pubkeys.zig");

const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const Pairing = blst.Pairing;
const AggregatePublicKey = blst.AggregatePublicKey;
const AggregateSignature = blst.AggregateSignature;
const DST = blst.DST;

/// Maximum number of verification sets per async job.  This is comptime because
/// the same-message Pippenger path needs stack-allocated pointer arrays of this
/// size (heap-allocated arrays crash in blst assembly under optimized builds).
/// All pool buffer slots are allocated to this capacity.
const MAX_SETS_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

/// Per-thread arena for batch verification scratch space.
/// Retains capacity across calls via reset(.retain_capacity).
threadlocal var batch_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);

// ---------------------------------------------------------------------------
// Buffer pool — fixed set of reusable (msgs, pks, sigs) triples for async jobs
// ---------------------------------------------------------------------------

/// Fixed-size pool of reusable buffer triples, all pre-allocated at init
/// time.  All operations are main-thread only (dispatch and completion
/// callbacks both run on the main thread), so no synchronization is needed.
const SigSetsPool = struct {
    /// stack[0..free_count] holds the currently-free buffer triples.
    stack: []Buffers = &.{},
    free_count: usize = 0,

    /// A reusable triple of pre-allocated buffers.  Each job uses a prefix
    /// `[0..n]` where n <= MAX_SETS_PER_JOB.
    pub const Buffers = struct {
        msgs: [][32]u8 = &.{},
        pks: []PublicKey = &.{},
        sigs: []Signature = &.{},
    };

    /// Allocate `max_jobs` buffer triples, each sized to MAX_SETS_PER_JOB.
    fn init(self: *SigSetsPool, max_jobs: usize) !void {
        self.stack = try allocator.alloc(Buffers, max_jobs);
        errdefer allocator.free(self.stack);

        var initialized: usize = 0;
        errdefer for (self.stack[0..initialized]) |*slot| {
            allocator.free(slot.msgs);
            allocator.free(slot.pks);
            allocator.free(slot.sigs);
        };

        for (self.stack) |*slot| {
            slot.msgs = try allocator.alloc([32]u8, MAX_SETS_PER_JOB);
            errdefer allocator.free(slot.msgs);
            slot.pks = try allocator.alloc(PublicKey, MAX_SETS_PER_JOB);
            errdefer allocator.free(slot.pks);
            slot.sigs = try allocator.alloc(Signature, MAX_SETS_PER_JOB);
            initialized += 1;
        }
        self.free_count = max_jobs;
    }

    fn pop(self: *SigSetsPool) ?Buffers {
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        return self.stack[self.free_count];
    }

    fn push(self: *SigSetsPool, bufs: Buffers) void {
        self.stack[self.free_count] = bufs;
        self.free_count += 1;
    }

    fn canAcceptWork(self: *SigSetsPool) bool {
        return self.free_count > 0;
    }

    fn deinit(self: *SigSetsPool) void {
        for (self.stack) |*slot| {
            allocator.free(slot.msgs);
            allocator.free(slot.pks);
            allocator.free(slot.sigs);
        }
        if (self.stack.len > 0) allocator.free(self.stack);
        self.* = .{};
    }
};

var pool: SigSetsPool = .{};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up a PublicKey from the shared cache by validator index.
/// Called only from the main thread.
fn getPubkey(index: u32) !*const PublicKey {
    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
    if (index >= pubkeys.state.index2pubkey.items.len) return error.PubkeyIndexOutOfRange;
    return &pubkeys.state.index2pubkey.items[index];
}

/// Deserialize + group-check a signature from a Uint8Array NAPI value.
fn deserializeSig(sig_value: napi.Value) !Signature {
    const info = try sig_value.getTypedarrayInfo();
    var sig = Signature.deserialize(info.data[0..]) catch return error.DeserializationFailed;
    sig.validate(true) catch return error.InvalidSignature;
    return sig;
}

/// Deserialize + group-check a public key from a Uint8Array NAPI value.
fn deserializePubkey(pk_value: napi.Value) !PublicKey {
    const info = try pk_value.getTypedarrayInfo();
    const pk = PublicKey.deserialize(info.data[0..]) catch return error.DeserializationFailed;
    pk.validate() catch return error.InvalidPublicKey;
    return pk;
}

const RAND_BYTES = 8;
const RAND_BITS = 8 * RAND_BYTES;

/// Batch-verify using Pairing.mulAndAggregate.
/// `arena_alloc` is used for temporary allocations (random scalars).
/// Returns false for empty slices or verification failure.
fn batchVerify(
    arena_alloc: std.mem.Allocator,
    msgs: [][32]u8,
    pks: []PublicKey,
    sigs: []Signature,
) error{OutOfMemory}!bool {
    const n = msgs.len;
    std.debug.assert(pks.len == n and sigs.len == n);
    if (n == 0) return false;

    const rands = try arena_alloc.alloc([RAND_BYTES]u8, n);
    for (0..n) |i| std.crypto.random.bytes(&rands[i]);

    var pairing_buf: [Pairing.sizeOf()]u8 = undefined;
    var pairing = Pairing.init(&pairing_buf, true, DST);

    for (0..n) |i| {
        pairing.mulAndAggregate(
            &pks[i],
            false,
            &sigs[i],
            false,
            &rands[i],
            RAND_BITS,
            &msgs[i],
        ) catch return false;
    }

    pairing.commit();
    return pairing.finalVerify(null);
}

// ---------------------------------------------------------------------------
// Shared NAPI set parsing (used by both sync and async paths)
// ---------------------------------------------------------------------------

/// Parse sets of {index, message, signature} into pre-allocated slices.
fn parseIndexedSets(sets: napi.Value, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));

        const msg_val = try set.getNamedProperty("message");
        const msg_info = try msg_val.getTypedarrayInfo();
        if (msg_info.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_info.data[0..32]);

        const idx_val = try set.getNamedProperty("index");
        const idx = try idx_val.getValueUint32();
        pks[i] = (try getPubkey(idx)).*;

        const sig_val = try set.getNamedProperty("signature");
        sigs[i] = try deserializeSig(sig_val);
    }
}

/// Parse sets of {indices, message, signature} into pre-allocated slices,
/// aggregating pubkeys when multiple indices are provided.
/// `alloc` is used for temporary pubkey aggregation buffers.
fn parseAggregateSets(alloc: std.mem.Allocator, sets: napi.Value, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));

        const msg_val = try set.getNamedProperty("message");
        const msg_info = try msg_val.getTypedarrayInfo();
        if (msg_info.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_info.data[0..32]);

        const indices_val = try set.getNamedProperty("indices");
        const indices_len = try indices_val.getArrayLength();
        if (indices_len == 0) return error.EmptyIndicesArray;

        if (indices_len == 1) {
            const idx_elem = try indices_val.getElement(0);
            const idx = try idx_elem.getValueUint32();
            pks[i] = (try getPubkey(idx)).*;
        } else {
            const tmp_pks = try alloc.alloc(PublicKey, indices_len);
            defer alloc.free(tmp_pks);
            for (0..indices_len) |j| {
                const idx_elem = try indices_val.getElement(@intCast(j));
                const idx = try idx_elem.getValueUint32();
                tmp_pks[j] = (try getPubkey(idx)).*;
            }
            const agg_pk = AggregatePublicKey.aggregate(tmp_pks, false) catch
                return error.AggregationFailed;
            pks[i] = agg_pk.toPublicKey();
        }

        const sig_val = try set.getNamedProperty("signature");
        sigs[i] = try deserializeSig(sig_val);
    }
}

/// Parse sets of {publicKey, message, signature} into pre-allocated slices.
fn parseSingleSets(sets: napi.Value, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));

        const msg_val = try set.getNamedProperty("message");
        const msg_info = try msg_val.getTypedarrayInfo();
        if (msg_info.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_info.data[0..32]);

        const pk_val = try set.getNamedProperty("publicKey");
        pks[i] = try deserializePubkey(pk_val);

        const sig_val = try set.getNamedProperty("signature");
        sigs[i] = try deserializeSig(sig_val);
    }
}

// ---------------------------------------------------------------------------
// 1. verifyIndexed(sets: {index, message, signature}[])  — sync
// ---------------------------------------------------------------------------

pub fn blsBatch_verifyIndexed(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try env.getBoolean(false);

    const arena_alloc = batch_arena.allocator();
    defer _ = batch_arena.reset(.retain_capacity);

    const msgs = try arena_alloc.alloc([32]u8, n);
    const pks = try arena_alloc.alloc(PublicKey, n);
    const sigs = try arena_alloc.alloc(Signature, n);

    try parseIndexedSets(sets, n, msgs, pks, sigs);

    return try env.getBoolean(try batchVerify(arena_alloc, msgs, pks, sigs));
}

// ---------------------------------------------------------------------------
// 2. verifyAggregate(sets: {indices, message, signature}[])  — sync
// ---------------------------------------------------------------------------

pub fn blsBatch_verifyAggregate(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try env.getBoolean(false);

    const arena_alloc = batch_arena.allocator();
    defer _ = batch_arena.reset(.retain_capacity);

    const msgs = try arena_alloc.alloc([32]u8, n);
    const pks = try arena_alloc.alloc(PublicKey, n);
    const sigs = try arena_alloc.alloc(Signature, n);

    try parseAggregateSets(arena_alloc, sets, n, msgs, pks, sigs);

    return try env.getBoolean(try batchVerify(arena_alloc, msgs, pks, sigs));
}

// ---------------------------------------------------------------------------
// 3. verifySingle(sets: {publicKey, message, signature}[])  — sync
// ---------------------------------------------------------------------------

pub fn blsBatch_verifySingle(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try env.getBoolean(false);

    const arena_alloc = batch_arena.allocator();
    defer _ = batch_arena.reset(.retain_capacity);

    const msgs = try arena_alloc.alloc([32]u8, n);
    const pks = try arena_alloc.alloc(PublicKey, n);
    const sigs = try arena_alloc.alloc(Signature, n);

    try parseSingleSets(sets, n, msgs, pks, sigs);

    return try env.getBoolean(try batchVerify(arena_alloc, msgs, pks, sigs));
}

// ---------------------------------------------------------------------------
// Async batch infrastructure
// ---------------------------------------------------------------------------

/// Create a Promise that is immediately resolved with false.
fn resolveWithFalse(env: napi.Env) !napi.Value {
    const deferred = try napi.Deferred.create(env.env);
    try deferred.resolve(try env.getBoolean(false));
    return deferred.getPromise();
}

const AsyncBatchJobData = struct {
    bufs: SigSetsPool.Buffers,
    n: usize,

    result: bool = false,
    err: bool = false,

    deferred: napi.Deferred,
    work: napi.AsyncWork(AsyncBatchJobData) = undefined,
};

fn asyncBatchExecute(_: napi.Env, data: *AsyncBatchJobData) void {
    const arena_alloc = batch_arena.allocator();
    defer _ = batch_arena.reset(.retain_capacity);

    data.result = batchVerify(
        arena_alloc,
        data.bufs.msgs[0..data.n],
        data.bufs.pks[0..data.n],
        data.bufs.sigs[0..data.n],
    ) catch {
        data.err = true;
        return;
    };
}

fn asyncBatchComplete(env: napi.Env, _: napi.status.Status, data: *AsyncBatchJobData) void {
    defer {
        data.work.delete() catch {};
        pool.push(data.bufs);
        allocator.destroy(data);
    }

    if (data.err) {
        if (env.createStringUtf8("BLST_ERROR: Batch verification failed")) |msg| {
            data.deferred.reject(msg) catch {};
        } else |_| {}
        return;
    }

    const result = env.getBoolean(data.result) catch return;
    data.deferred.resolve(result) catch return;
}

fn queueBatchJob(
    env: napi.Env,
    bufs: SigSetsPool.Buffers,
    n: usize,
    resource_name_str: [:0]const u8,
) !napi.Value {
    const deferred = try napi.Deferred.create(env.env);
    errdefer {
        if (env.getBoolean(false)) |val| {
            deferred.resolve(val) catch {};
        } else |_| {}
    }

    const data = try allocator.create(AsyncBatchJobData);
    errdefer allocator.destroy(data);

    data.* = .{
        .bufs = bufs,
        .n = n,
        .deferred = deferred,
    };

    const resource_name = try env.createStringUtf8(resource_name_str);
    data.work = try napi.AsyncWork(AsyncBatchJobData).create(
        env,
        null,
        resource_name,
        asyncBatchExecute,
        asyncBatchComplete,
        data,
    );
    errdefer data.work.delete() catch {};
    try data.work.queue();

    return deferred.getPromise();
}

// ---------------------------------------------------------------------------
// 4. asyncVerifyIndexed(sets)
// ---------------------------------------------------------------------------

pub fn blsBatch_asyncVerifyIndexed(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;

    const bufs = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(bufs);

    try parseIndexedSets(sets, n, bufs.msgs[0..n], bufs.pks[0..n], bufs.sigs[0..n]);

    return try queueBatchJob(env, bufs, n, "asyncVerifyIndexed");
}

// ---------------------------------------------------------------------------
// 5. asyncVerifyAggregate(sets)
// ---------------------------------------------------------------------------

pub fn blsBatch_asyncVerifyAggregate(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;

    const bufs = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(bufs);

    // Use the main-thread arena for tmp_pks inside parseAggregateSets.
    // Results are written into pool buffers; the arena is reset after.
    const arena_alloc = batch_arena.allocator();
    defer _ = batch_arena.reset(.retain_capacity);
    try parseAggregateSets(arena_alloc, sets, n, bufs.msgs[0..n], bufs.pks[0..n], bufs.sigs[0..n]);

    return try queueBatchJob(env, bufs, n, "asyncVerifyAggregate");
}

// ---------------------------------------------------------------------------
// 6. asyncVerifySingle(sets)
// ---------------------------------------------------------------------------

pub fn blsBatch_asyncVerifySingle(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;

    const bufs = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(bufs);

    try parseSingleSets(sets, n, bufs.msgs[0..n], bufs.pks[0..n], bufs.sigs[0..n]);

    return try queueBatchJob(env, bufs, n, "asyncVerifySingle");
}

// ---------------------------------------------------------------------------
// 7. asyncVerifySameMessage(sets, message)
// ---------------------------------------------------------------------------

const AsyncVerifySameMessageData = struct {
    bufs: SigSetsPool.Buffers,
    n: usize,
    msg: [32]u8,

    result: bool = false,
    err: bool = false,

    deferred: napi.Deferred,
    work: napi.AsyncWork(AsyncVerifySameMessageData) = undefined,
};

fn asyncVerifySameMessageExecute(_: napi.Env, data: *AsyncVerifySameMessageData) void {
    const n = data.n;

    const arena_alloc = batch_arena.allocator();
    defer _ = batch_arena.reset(.retain_capacity);

    // Generate randomness
    const rands = arena_alloc.alloc(u8, n * 32) catch {
        data.err = true;
        return;
    };
    std.crypto.random.bytes(rands);

    // Build pointer arrays on stack — blst Pippenger assembly crashes
    // with heap-allocated pointer arrays under optimized builds.
    var pk_refs: [MAX_SETS_PER_JOB]*const PublicKey = undefined;
    var sig_refs: [MAX_SETS_PER_JOB]*const Signature = undefined;
    for (0..n) |i| {
        pk_refs[i] = &data.bufs.pks[i];
        sig_refs[i] = &data.bufs.sigs[i];
    }

    const p1_scratch_size = blst.c.blst_p1s_mult_pippenger_scratch_sizeof(n);
    const p2_scratch_size = blst.c.blst_p2s_mult_pippenger_scratch_sizeof(n);
    const scratch_size = @max(p1_scratch_size, p2_scratch_size);
    const scratch = arena_alloc.alloc(u64, scratch_size) catch {
        data.err = true;
        return;
    };

    // Aggregate pubkeys with randomness (Pippenger)
    const agg_pk = AggregatePublicKey.aggregateWithRandomness(
        pk_refs[0..n],
        rands[0 .. n * 32],
        false,
        scratch,
    ) catch {
        data.err = true;
        return;
    };

    // Aggregate signatures with randomness (Pippenger)
    const agg_sig = AggregateSignature.aggregateWithRandomness(
        sig_refs[0..n],
        rands[0 .. n * 32],
        false,
        scratch,
    ) catch {
        data.err = true;
        return;
    };

    const pk = agg_pk.toPublicKey();
    const sig = agg_sig.toSignature();

    // Single pairing verify
    var pairing_buf: [Pairing.sizeOf()]u8 = undefined;
    data.result = sig.fastAggregateVerifyPreAggregated(false, &pairing_buf, &data.msg, DST, &pk) catch {
        data.err = true;
        return;
    };
}

fn asyncVerifySameMessageComplete(env: napi.Env, _: napi.status.Status, data: *AsyncVerifySameMessageData) void {
    defer {
        data.work.delete() catch {};
        pool.push(data.bufs);
        allocator.destroy(data);
    }

    if (data.err) {
        if (env.createStringUtf8("BLST_ERROR: Verification failed")) |msg| {
            data.deferred.reject(msg) catch {};
        } else |_| {}
        return;
    }

    const result = env.getBoolean(data.result) catch return;
    data.deferred.resolve(result) catch return;
}

pub fn blsBatch_asyncVerifySameMessage(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;

    const msg_info = try cb.arg(1).getTypedarrayInfo();
    if (msg_info.data.len != 32) return error.InvalidMessageLength;

    const bufs = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(bufs);

    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));

        const idx_val = try set.getNamedProperty("index");
        const idx = try idx_val.getValueUint32();
        bufs.pks[i] = (try getPubkey(idx)).*;

        const sig_val = try set.getNamedProperty("signature");
        bufs.sigs[i] = try deserializeSig(sig_val);
    }

    const deferred = try napi.Deferred.create(env.env);
    errdefer {
        if (env.getBoolean(false)) |val| {
            deferred.resolve(val) catch {};
        } else |_| {}
    }

    const data = try allocator.create(AsyncVerifySameMessageData);
    errdefer allocator.destroy(data);

    data.* = .{
        .bufs = bufs,
        .n = n,
        .msg = msg_info.data[0..32].*,
        .deferred = deferred,
    };

    const resource_name = try env.createStringUtf8("asyncVerifySameMessage");
    data.work = try napi.AsyncWork(AsyncVerifySameMessageData).create(
        env,
        null,
        resource_name,
        asyncVerifySameMessageExecute,
        asyncVerifySameMessageComplete,
        data,
    );
    errdefer data.work.delete() catch {};
    try data.work.queue();

    return deferred.getPromise();
}

// ---------------------------------------------------------------------------
// Init & backpressure
// ---------------------------------------------------------------------------

/// Pre-allocate the buffer pool.  Call once at startup before dispatching work.
///   maxJobs — maximum number of concurrent async jobs (= number of buffer slots)
/// Each slot is sized to MAX_SETS_PER_JOB (128) verification sets.
pub fn blsBatch_init(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    try pool.init(try cb.arg(0).getValueUint32());
    return try env.getUndefined();
}

/// Returns true if the pool has a free buffer slot for another async job.
/// The JS-side manager can call this before dispatching async work or do its own tracking of in-flight jobs.
pub fn blsBatch_canAcceptWork(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    return try env.getBoolean(pool.canAcceptWork());
}

pub fn deinit() void {
    pool.deinit();
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const obj = try env.createObject();

    // Sync
    try obj.setNamedProperty("verifyIndexed", try env.createFunction("verifyIndexed", 1, blsBatch_verifyIndexed, null));
    try obj.setNamedProperty("verifyAggregate", try env.createFunction("verifyAggregate", 1, blsBatch_verifyAggregate, null));
    try obj.setNamedProperty("verifySingle", try env.createFunction("verifySingle", 1, blsBatch_verifySingle, null));

    // Async
    try obj.setNamedProperty("asyncVerifyIndexed", try env.createFunction("asyncVerifyIndexed", 1, blsBatch_asyncVerifyIndexed, null));
    try obj.setNamedProperty("asyncVerifyAggregate", try env.createFunction("asyncVerifyAggregate", 1, blsBatch_asyncVerifyAggregate, null));
    try obj.setNamedProperty("asyncVerifySingle", try env.createFunction("asyncVerifySingle", 1, blsBatch_asyncVerifySingle, null));
    try obj.setNamedProperty("asyncVerifySameMessage", try env.createFunction("asyncVerifySameMessage", 2, blsBatch_asyncVerifySameMessage, null));

    // Pool management
    try obj.setNamedProperty("init", try env.createFunction("init", 1, blsBatch_init, null));
    try obj.setNamedProperty("canAcceptWork", try env.createFunction("canAcceptWork", 0, blsBatch_canAcceptWork, null));

    try exports.setNamedProperty("blsBatch", obj);
}
