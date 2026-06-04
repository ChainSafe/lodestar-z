//! blsBatch — high-level BLS batch verification that resolves pubkeys by
//! validator index from the shared pubkey cache and dispatches heavy crypto to
//! a bounded, dedicated TSFN-backed BLS worker pool.
//!
//! All NAPI parsing, pubkey resolution, and signature deserialization happen
//! on the main thread.  Async jobs pass fully-resolved (msgs, pks, sigs) to
//! a worker thread that only does the expensive pairing math.
//!
//! Threading model
//! ───────────────
//! This module is single-threaded with respect to its JobPool: `verify`,
//! `asyncVerify`, `asyncVerifySameMessage`, `init` and the async completion
//! callback all run on one N-API environment's main (event-loop) thread, so
//! normal slot checkout/return is not contended. The JobPool owns the hard slot
//! admission counter; the worker pool owns only FIFO dispatch and TSFN
//! completion. Only the pairing/Pippenger math runs on dedicated BLS worker
//! threads, and it touches only its own job slot.
//!
//! Memory strategy
//! ───────────────
//! Sync path: all buffers (msgs, pks, sigs, rands) are stack-allocated.
//!
//! Async path: msgs, pks, and sigs are pre-allocated in the job pool.
//! Rands, Pippenger scratch, and pointer arrays are stack-allocated on
//! the worker thread.  Zero allocator calls on the hot path.
//!
//! Entry points
//! ────────────
//! verify(kind, sets)                    — sync batch verify (main thread)
//! asyncVerify(kind, sets)               — async batch verify (worker thread)
//! asyncVerifySameMessage(sets, message) — async Pippenger same-message verify
//!
//! Kind constants (exported to JS):
//!   indexed (0)   — sets have {index, message, signature}
//!   aggregate (1) — sets have {indices, message, signature}
//!   single (2)    — sets have {publicKey, message, signature}
const std = @import("std");
const builtin = @import("builtin");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const blst = @import("bls");
const pubkeys = @import("./pubkeys.zig");
const napi_io = @import("./io.zig");
const options = @import("bls_options");
const AsyncWorkerPool = @import("./async_worker_pool.zig").AsyncWorkerPool;
const Task = @import("./async_worker_pool.zig").Task;

const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const Pairing = blst.Pairing;
const AggregatePublicKey = blst.AggregatePublicKey;
const AggregateSignature = blst.AggregateSignature;
const DST = blst.DST;

/// Maximum number of verification sets per job.
const MAX_SETS_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;

/// Stack scratch buffer size (u64 count) for Pippenger.  Derived from
/// MAX_SETS_PER_JOB; verified against the actual blst requirement at pool init.
const MAX_SCRATCH_SIZE = 128 * MAX_SETS_PER_JOB;

/// Per-set random multiplier width: 8 bytes / 64 bits. Both the pairing
/// (`mulAndAggregate`) and Pippenger (`aggregateWithRandomness`, which strides
/// 32 bytes per set but only reads `nbits = 64`) consume the first 8 bytes.
const RAND_BYTES = 8;
const RAND_BITS = 8 * RAND_BYTES;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

const SetKind = enum(u32) {
    indexed = 0,
    aggregate = 1,
    single = 2,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reads a `Uint8Array`'s bytes from a generic property value, rejecting any
/// other typed-array element type (mirrors blst.zig's helper).
fn uint8SliceFromValue(value: js.Value) ![]u8 {
    const raw = value.toValue();
    if (!(try raw.isTypedarray())) return error.TypeMismatch;
    const info = try raw.getTypedarrayInfo();
    if (info.array_type != .uint8) return error.TypeMismatch;
    return info.data;
}

fn getPubkey(index: u32) !*const PublicKey {
    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
    if (index >= pubkeys.state.index2pubkey.items.len) return error.PubkeyIndexOutOfRange;
    return &pubkeys.state.index2pubkey.items[index];
}

fn deserializeSig(sig_value: napi.Value) !Signature {
    const bytes = try uint8SliceFromValue(.{ .val = sig_value });
    // On-curve check only (preserves DeserializationFailed). The G2 subgroup check is
    // relocated to the worker via the groupcheck flags in batchVerify/sameMessageExecute.
    return Signature.deserialize(bytes) catch return error.DeserializationFailed;
}

fn deserializePubkey(pk_value: napi.Value) !PublicKey {
    const bytes = try uint8SliceFromValue(.{ .val = pk_value });
    // On-curve check only; the G1 subgroup check is relocated to the worker
    // (mulAndAggregate pk_validate=true for the untrusted single-set pubkey).
    return PublicKey.deserialize(bytes) catch return error.DeserializationFailed;
}

/// Fill `rands` with cryptographically-seeded multipliers, guaranteeing the
/// 8-byte scalar of each set is non-zero. A zero multiplier would drop that set
/// from the batch equation, so an invalid signature there would go undetected
/// (same guard as blst.zig:468-471 / 608-610).
fn fillNonZeroRands(rands: [][RAND_BYTES]u8) void {
    var seed_bytes: [8]u8 = undefined;
    napi_io.get().random(&seed_bytes);
    var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed_bytes, .little));
    const rand = prng.random();

    for (rands) |*r| {
        rand.bytes(r);
        while (std.mem.allEqual(u8, r, 0)) rand.bytes(r);
    }
}

/// Batch-verify using Pairing.mulAndAggregate.
/// Caller provides pre-allocated `rands` slice (len >= n).
fn batchVerify(
    msgs: [][32]u8,
    pks: []PublicKey,
    sigs: []Signature,
    rands: [][RAND_BYTES]u8,
    pk_validate: bool,
) !bool {
    const n = msgs.len;
    std.debug.assert(pks.len == n and sigs.len == n and rands.len >= n);
    if (n == 0) return false;

    fillNonZeroRands(rands[0..n]);

    var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
    var pairing = Pairing.init(&pairing_buf, true, DST);

    for (0..n) |i| {
        try pairing.mulAndAggregate(
            &pks[i],
            pk_validate,
            &sigs[i],
            true,
            &rands[i],
            RAND_BITS,
            &msgs[i],
        );
    }

    pairing.commit();
    return pairing.finalVerify(null);
}

// ---------------------------------------------------------------------------
// Set parsing (one function per kind)
// ---------------------------------------------------------------------------

/// Parse {index, message, signature} sets.
fn parseIndexedSets(sets: js.Array, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = (try sets.get(@intCast(i))).toValue();

        const msg_bytes = try uint8SliceFromValue(.{ .val = try set.getNamedProperty("message") });
        if (msg_bytes.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_bytes[0..32]);

        const idx = try (try set.getNamedProperty("index")).getValueUint32();
        pks[i] = (try getPubkey(idx)).*;

        sigs[i] = try deserializeSig(try set.getNamedProperty("signature"));
    }
}

/// Parse {indices, message, signature} sets, aggregating pubkeys per set.
fn parseAggregateSets(sets: js.Array, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = (try sets.get(@intCast(i))).toValue();

        const msg_bytes = try uint8SliceFromValue(.{ .val = try set.getNamedProperty("message") });
        if (msg_bytes.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_bytes[0..32]);

        const indices_val = try set.getNamedProperty("indices");
        const indices_len = try indices_val.getArrayLength();
        if (indices_len == 0) return error.EmptyIndicesArray;

        const first_idx = try (try indices_val.getElement(0)).getValueUint32();
        if (indices_len == 1) {
            pks[i] = (try getPubkey(first_idx)).*;
        } else {
            // Incremental aggregation: accumulate in projective coords
            // one pubkey at a time from the cache — no temp buffer needed.
            // TODO add this to upstream blst-z?
            var agg: blst.c.blst_p1 = undefined;
            blst.c.blst_p1_from_affine(&agg, &(try getPubkey(first_idx)).point);
            for (1..indices_len) |j| {
                const idx = try (try indices_val.getElement(@intCast(j))).getValueUint32();
                blst.c.blst_p1_add_or_double_affine(&agg, &agg, &(try getPubkey(idx)).point);
            }
            blst.c.blst_p1_to_affine(&pks[i].point, &agg);
        }

        sigs[i] = try deserializeSig(try set.getNamedProperty("signature"));
    }
}

/// Parse {publicKey, message, signature} sets.
fn parseSingleSets(sets: js.Array, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = (try sets.get(@intCast(i))).toValue();

        const msg_bytes = try uint8SliceFromValue(.{ .val = try set.getNamedProperty("message") });
        if (msg_bytes.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_bytes[0..32]);

        pks[i] = try deserializePubkey(try set.getNamedProperty("publicKey"));

        sigs[i] = try deserializeSig(try set.getNamedProperty("signature"));
    }
}

/// Parse {index, signature} sets (same-message path, no per-set message).
fn parseSameMessageSets(sets: js.Array, n: usize, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = (try sets.get(@intCast(i))).toValue();
        const idx = try (try set.getNamedProperty("index")).getValueUint32();
        pks[i] = (try getPubkey(idx)).*;
        sigs[i] = try deserializeSig(try set.getNamedProperty("signature"));
    }
}

/// Dispatch to the correct parser based on kind.
fn parseSets(kind: SetKind, sets: js.Array, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    switch (kind) {
        .indexed => try parseIndexedSets(sets, n, msgs, pks, sigs),
        .aggregate => try parseAggregateSets(sets, n, msgs, pks, sigs),
        .single => try parseSingleSets(sets, n, msgs, pks, sigs),
    }
}

// ---------------------------------------------------------------------------
// Sync entry point: verify(kind, sets)
// ---------------------------------------------------------------------------

/// JS: blsBatch.verify(kind, sets) → boolean
pub fn verify(kind_num: js.Number, sets: js.Array) !js.Boolean {
    const kind = std.enums.fromInt(SetKind, try kind_num.toU32()) orelse return error.InvalidSetKind;

    const n = try sets.length();
    if (n == 0) return js.Boolean.from(false);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;

    var msgs: [MAX_SETS_PER_JOB][32]u8 = undefined;
    var pks: [MAX_SETS_PER_JOB]PublicKey = undefined;
    var sigs: [MAX_SETS_PER_JOB]Signature = undefined;
    var rands: [MAX_SETS_PER_JOB][RAND_BYTES]u8 = undefined;

    try parseSets(kind, sets, n, msgs[0..n], pks[0..n], sigs[0..n]);

    return js.Boolean.from(try batchVerify(msgs[0..n], pks[0..n], sigs[0..n], rands[0..n], kind == .single));
}

// ---------------------------------------------------------------------------
// Async job infrastructure
// ---------------------------------------------------------------------------

const JobKind = enum { batch, same_message };

const AsyncJobData = struct {
    task: Task = .{ .run_fn = runJob, .complete_fn = completeJob },

    msgs: [][32]u8 = &.{},
    pks: []PublicKey = &.{},
    sigs: []Signature = &.{},

    n: usize = 0,
    kind: JobKind = .batch,
    msg: [32]u8 = undefined,
    pk_validate: bool = false,

    result: bool = false,
    err: ?anyerror = null,

    deferred: napi.Deferred = undefined,
};

// ---------------------------------------------------------------------------
// Job pool
//
// Single-threaded: every pop/push happens on one env's main thread (the async
// entry points and the completion callback). The BLS worker only touches the
// slot it was handed, never the pool bookkeeping, so no lock is needed.
// ---------------------------------------------------------------------------

const JobPool = struct {
    slots: []AsyncJobData = &.{},
    stack: []*AsyncJobData = &.{},
    free_count: usize = 0,
    initialized: bool = false,

    fn init(self: *JobPool, max_jobs: usize) !void {
        // Idempotent: a second blsBatch.init() is a no-op rather than leaking
        // the existing pool (mirrors io.init / pubkeys.State.init / blst.initThreadPool).
        if (self.initialized) return;

        // Verify stack scratch buffer is large enough for Pippenger at MAX_SETS_PER_JOB.
        const max_scratch = @max(
            blst.c.blst_p1s_mult_pippenger_scratch_sizeof(MAX_SETS_PER_JOB),
            blst.c.blst_p2s_mult_pippenger_scratch_sizeof(MAX_SETS_PER_JOB),
        );
        std.debug.assert(max_scratch <= MAX_SCRATCH_SIZE);

        self.slots = try allocator.alloc(AsyncJobData, max_jobs);
        errdefer allocator.free(self.slots);

        self.stack = try allocator.alloc(*AsyncJobData, max_jobs);
        errdefer allocator.free(self.stack);

        var init_count: usize = 0;
        errdefer for (self.slots[0..init_count]) |*slot| {
            allocator.free(slot.msgs);
            allocator.free(slot.pks);
            allocator.free(slot.sigs);
        };

        for (self.slots, 0..) |*slot, i| {
            slot.* = .{};
            slot.msgs = try allocator.alloc([32]u8, MAX_SETS_PER_JOB);
            errdefer allocator.free(slot.msgs);
            slot.pks = try allocator.alloc(PublicKey, MAX_SETS_PER_JOB);
            errdefer allocator.free(slot.pks);
            slot.sigs = try allocator.alloc(Signature, MAX_SETS_PER_JOB);
            self.stack[i] = slot;
            init_count += 1;
        }
        self.free_count = max_jobs;
        self.initialized = true;
    }

    fn pop(self: *JobPool) ?*AsyncJobData {
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        return self.stack[self.free_count];
    }

    fn push(self: *JobPool, job: *AsyncJobData) void {
        self.stack[self.free_count] = job;
        self.free_count += 1;
    }

    fn canAcceptWork(self: *JobPool) bool {
        return self.free_count > 0;
    }

    fn deinit(self: *JobPool) void {
        if (!self.initialized) return;
        for (self.slots) |*slot| {
            allocator.free(slot.msgs);
            allocator.free(slot.pks);
            allocator.free(slot.sigs);
        }
        allocator.free(self.slots);
        allocator.free(self.stack);
        self.* = .{};
    }
};

var pool: JobPool = .{};
var worker_pool: AsyncWorkerPool = .{};
var cleanup_hook_registered: bool = false;

pub const EnvShutdown = struct {};

fn envCleanup(_: ?*anyopaque) callconv(.c) void {
    deinit(.{});
}

fn registerEnvCleanupHook(env: napi.Env) !void {
    if (cleanup_hook_registered) return;
    // Worker-thread envs come and go in real deployments. Tie the TSFN owner to
    // that env's lifetime so a dead owner never blocks the next live importer.
    try napi.status.check(napi.c.napi_add_env_cleanup_hook(env.env, envCleanup, null));
    cleanup_hook_registered = true;
}

// ---------------------------------------------------------------------------
// Async execute / complete
// ---------------------------------------------------------------------------

/// Runs on a worker thread (via AsyncWorkerPool). MUST NOT call any napi APIs.
fn runJob(task: *Task) void {
    const data: *AsyncJobData = @fieldParentPtr("task", task);
    switch (data.kind) {
        .batch => {
            var rands: [MAX_SETS_PER_JOB][RAND_BYTES]u8 = undefined;
            data.result = batchVerify(
                data.msgs[0..data.n],
                data.pks[0..data.n],
                data.sigs[0..data.n],
                rands[0..data.n],
                data.pk_validate,
            ) catch |err| {
                data.err = err;
                return;
            };
        },
        .same_message => sameMessageExecute(data),
    }
}

fn sameMessageExecute(data: *AsyncJobData) void {
    const n = data.n;

    var rands: [MAX_SETS_PER_JOB][32]u8 = undefined;
    fillNonZeroSameMessageRands(rands[0..n]);

    var pk_refs: [MAX_SETS_PER_JOB]*const PublicKey = undefined;
    var sig_refs: [MAX_SETS_PER_JOB]*const Signature = undefined;
    for (0..n) |i| {
        pk_refs[i] = &data.pks[i];
        sig_refs[i] = &data.sigs[i];
    }

    var scratch: [MAX_SCRATCH_SIZE]u64 = undefined;

    const agg_pk = AggregatePublicKey.aggregateWithRandomness(
        pk_refs[0..n],
        std.mem.sliceAsBytes(rands[0..n]),
        false,
        &scratch,
    ) catch |err| {
        data.err = err;
        return;
    };

    const agg_sig = AggregateSignature.aggregateWithRandomness(
        sig_refs[0..n],
        std.mem.sliceAsBytes(rands[0..n]),
        true,
        &scratch,
    ) catch |err| {
        data.err = err;
        return;
    };

    const pk = agg_pk.toPublicKey();
    const sig = agg_sig.toSignature();

    var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
    data.result = sig.fastAggregateVerifyPreAggregated(false, &pairing_buf, &data.msg, DST, &pk) catch |err| {
        data.err = err;
        return;
    };
}

/// Fill the Pippenger randomness blob (32-byte stride per set), guaranteeing the
/// first `RAND_BYTES` of each stride — the only bytes read at `nbits = 64` — are
/// non-zero, so no set is silently dropped from the aggregation.
fn fillNonZeroSameMessageRands(rands: [][32]u8) void {
    var seed_bytes: [8]u8 = undefined;
    napi_io.get().random(&seed_bytes);
    var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed_bytes, .little));
    const rand = prng.random();

    for (rands) |*r| {
        rand.bytes(r);
        while (std.mem.allEqual(u8, r[0..RAND_BYTES], 0)) rand.bytes(r[0..RAND_BYTES]);
    }
}

/// Runs on the loop thread (via the worker pool's TSFN). Settles the Promise
/// and returns the slot to the pool.
fn completeJob(env: napi.Env, task: *Task) void {
    const data: *AsyncJobData = @fieldParentPtr("task", task);
    defer pool.push(data);
    settle(env, data) catch {
        rejectWithError(env, data.deferred, "blsBatch", "InternalError") catch {};
    };
}

/// Resolve with the boolean result, or reject with the captured error. Both
/// async kinds use the same contract: a verification outcome resolves a
/// boolean; any crypto-library error rejects.
fn settle(env: napi.Env, data: *AsyncJobData) !void {
    if (data.err) |err| {
        return rejectWithError(env, data.deferred, "blsBatch", @errorName(err));
    }
    try data.deferred.resolve(try env.getBoolean(data.result));
}

/// Build a JS `Error` with `.code = code` and `.message = "<where>: <code>"`
/// and reject `deferred` with it, so JS callers can branch on `err.code`.
fn rejectWithError(env: napi.Env, deferred: napi.Deferred, where: []const u8, code: []const u8) !void {
    var msg_buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, "{s}: {s}", .{ where, code }) catch code;

    const code_val = try env.createStringUtf8(code);
    const msg_val = try env.createStringUtf8(msg);
    const err_val = try env.createError(code_val, msg_val);
    try deferred.reject(err_val);
}

fn resolveWithFalse(env: napi.Env) !js.Value {
    const deferred = try env.createPromise();
    try deferred.resolve(try env.getBoolean(false));
    return .{ .val = deferred.getPromise() };
}

fn queueJob(env: napi.Env, data: *AsyncJobData) !js.Value {
    data.result = false;
    data.err = null;
    data.deferred = try env.createPromise();
    try worker_pool.submit(env, &data.task);
    return .{ .val = data.deferred.getPromise() };
}

// ---------------------------------------------------------------------------
// Async entry points
// ---------------------------------------------------------------------------

/// JS: blsBatch.asyncVerify(kind, sets) → Promise<boolean>
pub fn asyncVerify(kind_num: js.Number, sets: js.Array) !js.Value {
    const kind = std.enums.fromInt(SetKind, try kind_num.toU32()) orelse return error.InvalidSetKind;

    const n = try sets.length();
    const env = js.env();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;
    try ensureAsyncReady(env);

    const data = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(data);

    data.kind = .batch;
    data.n = n;
    data.pk_validate = kind == .single;
    try parseSets(kind, sets, n, data.msgs[0..n], data.pks[0..n], data.sigs[0..n]);

    return try queueJob(env, data);
}

/// JS: blsBatch.asyncVerifySameMessage(sets, message) → Promise<boolean>
pub fn asyncVerifySameMessage(sets: js.Array, message: js.Uint8Array) !js.Value {
    const n = try sets.length();
    const env = js.env();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;
    try ensureAsyncReady(env);

    const msg_slice = try message.toSlice();
    if (msg_slice.len != 32) return error.InvalidMessageLength;

    const data = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(data);

    data.kind = .same_message;
    data.n = n;
    data.msg = msg_slice[0..32].*;
    try parseSameMessageSets(sets, n, data.pks[0..n], data.sigs[0..n]);

    return try queueJob(env, data);
}

// ---------------------------------------------------------------------------
// Pool management & lifecycle
// ---------------------------------------------------------------------------

/// JS: blsBatch.init(maxJobs) — allocate the async job pool + worker pool. Idempotent.
pub fn init(max_jobs: js.Number) !void {
    const env = js.env();
    const n = try max_jobs.toU32();
    if (n == 0) return error.InvalidMaxJobs;

    const pool_was_initialized = pool.initialized;
    try pool.init(n);
    errdefer if (!pool_was_initialized) pool.deinit();

    const n_workers = try configuredBlsWorkerCount(n);
    const worker_pool_was_initialized = worker_pool.initialized;
    try worker_pool.init(env, napi_io.get(), n_workers, n);
    errdefer if (!worker_pool_was_initialized) worker_pool.deinit();
    try registerEnvCleanupHook(env);
}

/// JS: blsBatch.canAcceptWork() → boolean — async backpressure signal.
pub fn canAcceptWork() !js.Boolean {
    const env = js.env();
    return js.Boolean.from(pool.initialized and pool.canAcceptWork() and worker_pool.isReadyForEnv(env));
}

fn configuredBlsWorkerCount(max_jobs: u32) !u32 {
    var configured_workers: usize = @intCast(options.thread_count);
    if (configured_workers == 0) {
        configured_workers = @max((try std.Thread.getCpuCount()) -| 1, 1);
    }

    configured_workers = @min(configured_workers, blst.ThreadPool.MAX_WORKERS);
    configured_workers = @min(configured_workers, AsyncWorkerPool.MAX_WORKERS);
    configured_workers = @min(configured_workers, @as(usize, @intCast(max_jobs)));
    return @intCast(configured_workers);
}

fn ensureAsyncReady(env: napi.Env) !void {
    if (!pool.initialized) return error.PoolNotInitialized;
    try worker_pool.ensureReady(env);
}

/// Tear down the worker pool then the job pool. Called from root.zig env cleanup.
/// Order matters: workers must be joined and the TSFN released (AsyncWorkerPool.deinit)
/// BEFORE the slots they read are freed, or a worker mid-runJob hits freed memory.
pub fn deinit(_: EnvShutdown) void {
    worker_pool.deinit();
    pool.deinit();
    cleanup_hook_registered = false;
}

/// Exports the integer kind constants and `maxSetsPerJob` onto the auto-created
/// `blsBatch` namespace. The DSL has no mechanism for exporting plain `pub const`
/// values, so this runs via root.zig's `.register` hook, keeping the Zig
/// `SetKind` enum and `MAX_SETS_PER_JOB` as the single source of truth. JS callers
/// must chunk to `maxSetsPerJob` before calling verify/asyncVerify (larger jobs
/// are rejected with `TooManySets`).
pub fn registerConstants(env: napi.Env, exports: napi.Value) !void {
    const obj = try exports.getNamedProperty("blsBatch");
    try obj.setNamedProperty("indexed", try env.createUint32(@intFromEnum(SetKind.indexed)));
    try obj.setNamedProperty("aggregate", try env.createUint32(@intFromEnum(SetKind.aggregate)));
    try obj.setNamedProperty("single", try env.createUint32(@intFromEnum(SetKind.single)));
    try obj.setNamedProperty("maxSetsPerJob", try env.createUint32(@intCast(MAX_SETS_PER_JOB)));
}
