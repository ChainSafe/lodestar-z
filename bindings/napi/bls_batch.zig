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

/// Maximum number of verification sets per job.
const MAX_SETS_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;

/// Maximum number of validator indices that can be aggregated in a single set.
const MAX_INDICES_PER_SET = 2048;

/// Stack scratch buffer size (u64 count) for Pippenger.  Derived from
/// MAX_SETS_PER_JOB; verified against the actual blst requirement at pool init.
const MAX_SCRATCH_SIZE = 128 * MAX_SETS_PER_JOB;

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

fn getPubkey(index: u32) !*const PublicKey {
    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
    if (index >= pubkeys.state.index2pubkey.items.len) return error.PubkeyIndexOutOfRange;
    return &pubkeys.state.index2pubkey.items[index];
}

fn deserializeSig(sig_value: napi.Value) !Signature {
    const info = try sig_value.getTypedarrayInfo();
    var sig = Signature.deserialize(info.data[0..]) catch return error.DeserializationFailed;
    sig.validate(true) catch return error.InvalidSignature;
    return sig;
}

fn deserializePubkey(pk_value: napi.Value) !PublicKey {
    const info = try pk_value.getTypedarrayInfo();
    const pk = PublicKey.deserialize(info.data[0..]) catch return error.DeserializationFailed;
    pk.validate() catch return error.InvalidPublicKey;
    return pk;
}

const RAND_BYTES = 8;
const RAND_BITS = 8 * RAND_BYTES;

/// Batch-verify using Pairing.mulAndAggregate.
/// Caller provides pre-allocated `rands` slice (len >= n).
fn batchVerify(
    msgs: [][32]u8,
    pks: []PublicKey,
    sigs: []Signature,
    rands: [][RAND_BYTES]u8,
) bool {
    const n = msgs.len;
    std.debug.assert(pks.len == n and sigs.len == n and rands.len >= n);
    if (n == 0) return false;

    for (0..n) |i| std.crypto.random.bytes(&rands[i]);

    var pairing_buf: [Pairing.sizeOf()]u8 align(32) = undefined;
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
// NAPI set parsing (one function per kind)
// ---------------------------------------------------------------------------

/// Parse {index, message, signature} sets.
fn parseIndexedSets(sets: napi.Value, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));

        const msg_info = try (try set.getNamedProperty("message")).getTypedarrayInfo();
        if (msg_info.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_info.data[0..32]);

        const idx = try (try set.getNamedProperty("index")).getValueUint32();
        pks[i] = (try getPubkey(idx)).*;

        sigs[i] = try deserializeSig(try set.getNamedProperty("signature"));
    }
}

/// Parse {indices, message, signature} sets, aggregating pubkeys per set.
fn parseAggregateSets(sets: napi.Value, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));

        const msg_info = try (try set.getNamedProperty("message")).getTypedarrayInfo();
        if (msg_info.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_info.data[0..32]);

        const indices_val = try set.getNamedProperty("indices");
        const indices_len = try indices_val.getArrayLength();
        if (indices_len == 0) return error.EmptyIndicesArray;

        if (indices_len == 1) {
            const idx = try (try indices_val.getElement(0)).getValueUint32();
            pks[i] = (try getPubkey(idx)).*;
        } else {
            if (indices_len > MAX_INDICES_PER_SET) return error.TooManyIndices;
            var tmp_pks: [MAX_INDICES_PER_SET]PublicKey = undefined;
            for (0..indices_len) |j| {
                const idx = try (try indices_val.getElement(@intCast(j))).getValueUint32();
                tmp_pks[j] = (try getPubkey(idx)).*;
            }
            const agg_pk = AggregatePublicKey.aggregate(tmp_pks[0..indices_len], false) catch
                return error.AggregationFailed;
            pks[i] = agg_pk.toPublicKey();
        }

        sigs[i] = try deserializeSig(try set.getNamedProperty("signature"));
    }
}

/// Parse {publicKey, message, signature} sets.
fn parseSingleSets(sets: napi.Value, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));

        const msg_info = try (try set.getNamedProperty("message")).getTypedarrayInfo();
        if (msg_info.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_info.data[0..32]);

        pks[i] = try deserializePubkey(try set.getNamedProperty("publicKey"));

        sigs[i] = try deserializeSig(try set.getNamedProperty("signature"));
    }
}

/// Parse {index, signature} sets (same-message path, no per-set message).
fn parseSameMessageSets(sets: napi.Value, n: usize, pks: []PublicKey, sigs: []Signature) !void {
    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));
        const idx = try (try set.getNamedProperty("index")).getValueUint32();
        pks[i] = (try getPubkey(idx)).*;
        sigs[i] = try deserializeSig(try set.getNamedProperty("signature"));
    }
}

/// Dispatch to the correct parser based on kind.
fn parseSets(kind: SetKind, sets: napi.Value, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
    switch (kind) {
        .indexed => try parseIndexedSets(sets, n, msgs, pks, sigs),
        .aggregate => try parseAggregateSets(sets, n, msgs, pks, sigs),
        .single => try parseSingleSets(sets, n, msgs, pks, sigs),
    }
}

// ---------------------------------------------------------------------------
// Sync entry point: verify(kind, sets)
// ---------------------------------------------------------------------------

pub fn blsBatch_verify(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const kind = std.meta.intToEnum(SetKind, try cb.arg(0).getValueUint32()) catch
        return error.InvalidSetKind;

    const sets = cb.arg(1);
    const n = try sets.getArrayLength();
    if (n == 0) return try env.getBoolean(false);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;

    var msgs: [MAX_SETS_PER_JOB][32]u8 = undefined;
    var pks: [MAX_SETS_PER_JOB]PublicKey = undefined;
    var sigs: [MAX_SETS_PER_JOB]Signature = undefined;
    var rands: [MAX_SETS_PER_JOB][RAND_BYTES]u8 = undefined;

    try parseSets(kind, sets, n, msgs[0..n], pks[0..n], sigs[0..n]);

    return try env.getBoolean(batchVerify(msgs[0..n], pks[0..n], sigs[0..n], rands[0..n]));
}

// ---------------------------------------------------------------------------
// Async job infrastructure
// ---------------------------------------------------------------------------

const JobKind = enum { batch, same_message };

const AsyncJobData = struct {
    msgs: [][32]u8 = &.{},
    pks: []PublicKey = &.{},
    sigs: []Signature = &.{},

    n: usize = 0,
    kind: JobKind = .batch,
    msg: [32]u8 = undefined,

    result: bool = false,
    err: ?blst.BlstError = null,

    deferred: napi.Deferred = undefined,
    work: napi.AsyncWork(AsyncJobData) = undefined,
};

// ---------------------------------------------------------------------------
// Job pool
// ---------------------------------------------------------------------------

const JobPool = struct {
    slots: []AsyncJobData = &.{},
    stack: []*AsyncJobData = &.{},
    free_count: usize = 0,

    fn init(self: *JobPool, max_jobs: usize) !void {
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

        var initialized: usize = 0;
        errdefer for (self.slots[0..initialized]) |*slot| {
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
            initialized += 1;
        }
        self.free_count = max_jobs;
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
        for (self.slots) |*slot| {
            allocator.free(slot.msgs);
            allocator.free(slot.pks);
            allocator.free(slot.sigs);
        }
        if (self.slots.len > 0) {
            allocator.free(self.slots);
            allocator.free(self.stack);
        }
        self.* = .{};
    }
};

var pool: JobPool = .{};

// ---------------------------------------------------------------------------
// Async execute / complete
// ---------------------------------------------------------------------------

fn asyncExecute(_: napi.Env, data: *AsyncJobData) void {
    switch (data.kind) {
        .batch => {
            var rands: [MAX_SETS_PER_JOB][RAND_BYTES]u8 = undefined;
            data.result = batchVerify(
                data.msgs[0..data.n],
                data.pks[0..data.n],
                data.sigs[0..data.n],
                rands[0..data.n],
            );
        },
        .same_message => sameMessageExecute(data),
    }
}

fn sameMessageExecute(data: *AsyncJobData) void {
    const n = data.n;

    var rands: [MAX_SETS_PER_JOB][32]u8 = undefined;
    std.crypto.random.bytes(std.mem.sliceAsBytes(rands[0..n]));

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
        false,
        &scratch,
    ) catch |err| {
        data.err = err;
        return;
    };

    const pk = agg_pk.toPublicKey();
    const sig = agg_sig.toSignature();

    var pairing_buf: [Pairing.sizeOf()]u8 align(32) = undefined;
    data.result = sig.fastAggregateVerifyPreAggregated(false, &pairing_buf, &data.msg, DST, &pk) catch |err| {
        data.err = err;
        return;
    };
}

fn asyncComplete(env: napi.Env, status: napi.status.Status, data: *AsyncJobData) void {
    defer {
        data.work.delete() catch {};
        // Don't push back to pool during shutdown — pool may already be deinitialized.
        if (status != .cancelled) pool.push(data);
    }

    if (data.err) |err| {
        const code = env.createStringUtf8(@errorName(err)) catch {
            data.deferred.reject(env.getUndefined() catch return) catch {};
            return;
        };
        const msg = env.createStringUtf8("Batch verification failed") catch {
            data.deferred.reject(code) catch {};
            return;
        };
        const err_obj = env.createError(code, msg) catch {
            data.deferred.reject(code) catch {};
            return;
        };
        data.deferred.reject(err_obj) catch {};
        return;
    }

    const result = env.getBoolean(data.result) catch {
        // Ensure the promise always settles even if env is shutting down.
        data.deferred.reject(env.getUndefined() catch return) catch {};
        return;
    };
    data.deferred.resolve(result) catch {};
}

fn resolveWithFalse(env: napi.Env) !napi.Value {
    const deferred = try napi.Deferred.create(env.env);
    try deferred.resolve(try env.getBoolean(false));
    return deferred.getPromise();
}

fn queueJob(env: napi.Env, data: *AsyncJobData, comptime execute: *const fn (napi.Env, *AsyncJobData) void) !napi.Value {
    data.result = false;
    data.err = null;
    data.deferred = try napi.Deferred.create(env.env);
    errdefer {
        if (env.getBoolean(false)) |val| {
            data.deferred.resolve(val) catch {};
        } else |_| {}
    }

    const resource_name = try env.createStringUtf8("asyncVerify");
    data.work = try napi.AsyncWork(AsyncJobData).create(
        env,
        null,
        resource_name,
        execute,
        asyncComplete,
        data,
    );
    errdefer data.work.delete() catch {};
    try data.work.queue();

    return data.deferred.getPromise();
}

// ---------------------------------------------------------------------------
// Async entry points
// ---------------------------------------------------------------------------

/// asyncVerify(kind, sets) — batch verify on a worker thread.
pub fn blsBatch_asyncVerify(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const kind = std.meta.intToEnum(SetKind, try cb.arg(0).getValueUint32()) catch
        return error.InvalidSetKind;

    const sets = cb.arg(1);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;

    const data = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(data);

    data.kind = .batch;
    data.n = n;
    try parseSets(kind, sets, n, data.msgs[0..n], data.pks[0..n], data.sigs[0..n]);

    return try queueJob(env, data, asyncExecute);
}

/// asyncVerifySameMessage(sets, message) — Pippenger same-message verify on a worker thread.
pub fn blsBatch_asyncVerifySameMessage(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_SETS_PER_JOB) return error.TooManySets;

    const msg_info = try cb.arg(1).getTypedarrayInfo();
    if (msg_info.data.len != 32) return error.InvalidMessageLength;

    const data = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(data);

    data.kind = .same_message;
    data.n = n;
    data.msg = msg_info.data[0..32].*;
    try parseSameMessageSets(sets, n, data.pks[0..n], data.sigs[0..n]);

    return try queueJob(env, data, asyncExecute);
}

// ---------------------------------------------------------------------------
// Init & backpressure
// ---------------------------------------------------------------------------

pub fn blsBatch_init(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    try pool.init(try cb.arg(0).getValueUint32());
    return try env.getUndefined();
}

pub fn blsBatch_canAcceptWork(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    return try env.getBoolean(pool.canAcceptWork());
}

pub fn deinit() void {
    pool.deinit();
}

// ---------------------------------------------------------------------------
// Test helper
// ---------------------------------------------------------------------------

/// Worker that unconditionally sets an error — used to exercise the
/// Error-object rejection path in asyncComplete from tests.
fn testAsyncRejectExecute(_: napi.Env, data: *AsyncJobData) void {
    data.err = error.VerifyFail;
}

/// Test-only: queue an async job whose worker always fails, returning a
/// promise that rejects with a proper Error object.  Allows JS tests to
/// assert on the shape of the rejection (instanceof Error, .code, .message).
pub fn blsBatch__testAsyncReject(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    const data = pool.pop() orelse return error.PoolExhausted;
    errdefer pool.push(data);
    data.kind = .batch;
    data.n = 0;
    return try queueJob(env, data, testAsyncRejectExecute);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const obj = try env.createObject();

    try obj.setNamedProperty("verify", try env.createFunction("verify", 2, blsBatch_verify, null));
    try obj.setNamedProperty("asyncVerify", try env.createFunction("asyncVerify", 2, blsBatch_asyncVerify, null));
    try obj.setNamedProperty("asyncVerifySameMessage", try env.createFunction("asyncVerifySameMessage", 2, blsBatch_asyncVerifySameMessage, null));

    // Kind constants
    try obj.setNamedProperty("indexed", try env.createUint32(0));
    try obj.setNamedProperty("aggregate", try env.createUint32(1));
    try obj.setNamedProperty("single", try env.createUint32(2));

    // Pool management
    try obj.setNamedProperty("init", try env.createFunction("init", 1, blsBatch_init, null));
    try obj.setNamedProperty("canAcceptWork", try env.createFunction("canAcceptWork", 0, blsBatch_canAcceptWork, null));

    // Test helpers
    try obj.setNamedProperty("__testAsyncReject", try env.createFunction("__testAsyncReject", 0, blsBatch__testAsyncReject, null));

    try exports.setNamedProperty("blsBatch", obj);
}
