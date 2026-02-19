//! blsBatch — high-level BLS batch verification that resolves pubkeys by
//! validator index from the shared pubkey cache and dispatches heavy crypto
//! to the libuv thread-pool.
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
const MAX_AGGREGATE_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up a PublicKey from the shared cache by validator index.
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

/// Batch-verify using Pairing.mulAndAggregate directly on value slices.
/// Returns false for empty slices or verification failure.
fn batchVerify(
    msgs: [][32]u8,
    pks: []PublicKey,
    sigs: []Signature,
) error{OutOfMemory}!bool {
    const n = msgs.len;
    std.debug.assert(pks.len == n and sigs.len == n);
    if (n == 0) return false;

    const rands = try allocator.alloc([RAND_BYTES]u8, n);
    defer allocator.free(rands);

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
// Shared NAPI set parsing
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
fn parseAggregateSets(sets: napi.Value, n: usize, msgs: [][32]u8, pks: []PublicKey, sigs: []Signature) !void {
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
            const tmp_pks = try allocator.alloc(PublicKey, indices_len);
            defer allocator.free(tmp_pks);
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
// 1. verifyIndexed(sets: {index, message, signature}[])
// ---------------------------------------------------------------------------

/// Batch-verify sets where each set resolves its pubkey by validator index.
///
/// Arguments:
/// 1) sets: Array<{ index: number, message: Uint8Array, signature: Uint8Array }>
///
/// Returns: boolean
pub fn blsBatch_verifyIndexed(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try env.getBoolean(false);

    const msgs = try allocator.alloc([32]u8, n);
    defer allocator.free(msgs);
    const pks = try allocator.alloc(PublicKey, n);
    defer allocator.free(pks);
    const sigs = try allocator.alloc(Signature, n);
    defer allocator.free(sigs);

    try parseIndexedSets(sets, n, msgs, pks, sigs);

    return try env.getBoolean(try batchVerify(msgs, pks, sigs));
}

// ---------------------------------------------------------------------------
// 2. verifyAggregate(sets: {indices, message, signature}[])
// ---------------------------------------------------------------------------

/// Batch-verify sets where each set aggregates pubkeys from multiple indices.
///
/// Arguments:
/// 1) sets: Array<{ indices: number[], message: Uint8Array, signature: Uint8Array }>
///
/// Returns: boolean
pub fn blsBatch_verifyAggregate(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try env.getBoolean(false);

    const msgs = try allocator.alloc([32]u8, n);
    defer allocator.free(msgs);
    const pks = try allocator.alloc(PublicKey, n);
    defer allocator.free(pks);
    const sigs = try allocator.alloc(Signature, n);
    defer allocator.free(sigs);

    try parseAggregateSets(sets, n, msgs, pks, sigs);

    return try env.getBoolean(try batchVerify(msgs, pks, sigs));
}

// ---------------------------------------------------------------------------
// 3. verifySingle(sets: {publicKey, message, signature}[])
// ---------------------------------------------------------------------------

/// Batch-verify sets where each set provides an explicit pubkey as bytes.
///
/// Arguments:
/// 1) sets: Array<{ publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array }>
///
/// Returns: boolean
pub fn blsBatch_verifySingle(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try env.getBoolean(false);

    const msgs = try allocator.alloc([32]u8, n);
    defer allocator.free(msgs);
    const pks = try allocator.alloc(PublicKey, n);
    defer allocator.free(pks);
    const sigs = try allocator.alloc(Signature, n);
    defer allocator.free(sigs);

    try parseSingleSets(sets, n, msgs, pks, sigs);

    return try env.getBoolean(try batchVerify(msgs, pks, sigs));
}

// ---------------------------------------------------------------------------
// Shared async batch-verify infrastructure
// ---------------------------------------------------------------------------

const AsyncBatchVerifyData = struct {
    msgs: [][32]u8,
    pks: []PublicKey,
    sigs: []Signature,

    result: bool = false,
    err: bool = false,

    deferred: napi.Deferred,
    work: napi.AsyncWork(AsyncBatchVerifyData) = undefined,
};

fn asyncBatchExecute(_: napi.Env, data: *AsyncBatchVerifyData) void {
    data.result = batchVerify(data.msgs, data.pks, data.sigs) catch {
        data.err = true;
        return;
    };
}

fn asyncBatchComplete(env: napi.Env, _: napi.status.Status, data: *AsyncBatchVerifyData) void {
    defer {
        data.work.delete() catch {};
        allocator.free(data.msgs);
        allocator.free(data.pks);
        allocator.free(data.sigs);
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

fn queueBatchVerify(
    env: napi.Env,
    msgs: [][32]u8,
    pks: []PublicKey,
    sigs: []Signature,
    resource_name_str: [:0]const u8,
) !napi.Value {
    const deferred = try napi.Deferred.create(env.env);
    errdefer {
        if (env.getBoolean(false)) |val| {
            deferred.resolve(val) catch {};
        } else |_| {}
    }

    const data = try allocator.create(AsyncBatchVerifyData);
    errdefer allocator.destroy(data);

    data.* = .{
        .msgs = msgs,
        .pks = pks,
        .sigs = sigs,
        .deferred = deferred,
    };

    const resource_name = try env.createStringUtf8(resource_name_str);
    data.work = try napi.AsyncWork(AsyncBatchVerifyData).create(
        env,
        null,
        resource_name,
        asyncBatchExecute,
        asyncBatchComplete,
        data,
    );
    try data.work.queue();

    return deferred.getPromise();
}

/// Create a Promise that is immediately resolved with false.
fn resolveWithFalse(env: napi.Env) !napi.Value {
    const deferred = try napi.Deferred.create(env.env);
    try deferred.resolve(try env.getBoolean(false));
    return deferred.getPromise();
}

// ---------------------------------------------------------------------------
// 4. asyncVerifyIndexed(sets)
// ---------------------------------------------------------------------------

/// Async version of verifyIndexed — dispatched to libuv threadpool.
///
/// Returns: Promise<boolean>
pub fn blsBatch_asyncVerifyIndexed(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);

    const msgs = try allocator.alloc([32]u8, n);
    errdefer allocator.free(msgs);
    const pks = try allocator.alloc(PublicKey, n);
    errdefer allocator.free(pks);
    const sigs = try allocator.alloc(Signature, n);
    errdefer allocator.free(sigs);

    try parseIndexedSets(sets, n, msgs, pks, sigs);

    return try queueBatchVerify(env, msgs, pks, sigs, "asyncVerifyIndexed");
}

// ---------------------------------------------------------------------------
// 5. asyncVerifyAggregate(sets)
// ---------------------------------------------------------------------------

/// Async version of verifyAggregate — dispatched to libuv threadpool.
///
/// Returns: Promise<boolean>
pub fn blsBatch_asyncVerifyAggregate(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);

    const msgs = try allocator.alloc([32]u8, n);
    errdefer allocator.free(msgs);
    const pks = try allocator.alloc(PublicKey, n);
    errdefer allocator.free(pks);
    const sigs = try allocator.alloc(Signature, n);
    errdefer allocator.free(sigs);

    try parseAggregateSets(sets, n, msgs, pks, sigs);

    return try queueBatchVerify(env, msgs, pks, sigs, "asyncVerifyAggregate");
}

// ---------------------------------------------------------------------------
// 6. asyncVerifySingle(sets)
// ---------------------------------------------------------------------------

/// Async version of verifySingle — dispatched to libuv threadpool.
///
/// Returns: Promise<boolean>
pub fn blsBatch_asyncVerifySingle(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);

    const msgs = try allocator.alloc([32]u8, n);
    errdefer allocator.free(msgs);
    const pks = try allocator.alloc(PublicKey, n);
    errdefer allocator.free(pks);
    const sigs = try allocator.alloc(Signature, n);
    errdefer allocator.free(sigs);

    try parseSingleSets(sets, n, msgs, pks, sigs);

    return try queueBatchVerify(env, msgs, pks, sigs, "asyncVerifySingle");
}

// ---------------------------------------------------------------------------
// 7. asyncVerifySameMessage(sets, message)
// ---------------------------------------------------------------------------

const AsyncVerifySameMessageData = struct {
    msg: [32]u8,
    pks: []PublicKey,
    sigs: []Signature,

    result: bool = false,
    err: bool = false,

    deferred: napi.Deferred,
    work: napi.AsyncWork(AsyncVerifySameMessageData) = undefined,
};

fn asyncVerifySameMessageExecute(_: napi.Env, data: *AsyncVerifySameMessageData) void {
    const n = data.pks.len;

    // Generate randomness
    var rands: [32 * MAX_AGGREGATE_PER_JOB]u8 = undefined;
    std.crypto.random.bytes(rands[0 .. n * 32]);

    // Build pointer arrays on stack
    var pk_refs: [MAX_AGGREGATE_PER_JOB]*const PublicKey = undefined;
    var sig_refs: [MAX_AGGREGATE_PER_JOB]*const Signature = undefined;
    for (0..n) |i| {
        pk_refs[i] = &data.pks[i];
        sig_refs[i] = &data.sigs[i];
    }

    // Scratch space for Pippenger
    const p1_scratch_size = blst.c.blst_p1s_mult_pippenger_scratch_sizeof(n);
    const p2_scratch_size = blst.c.blst_p2s_mult_pippenger_scratch_sizeof(n);
    const scratch_size = @max(p1_scratch_size, p2_scratch_size);
    const scratch = allocator.alloc(u64, scratch_size) catch {
        data.err = true;
        return;
    };
    defer allocator.free(scratch);

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
        allocator.free(data.pks);
        allocator.free(data.sigs);
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

/// Async same-message optimization: aggregateWithRandomness over all sets,
/// then a single pairing verify on a libuv worker thread.
///
/// Arguments:
/// 1) sets: Array<{ index: number, signature: Uint8Array }>
/// 2) message: Uint8Array (32 bytes)
///
/// Returns: Promise<boolean>
pub fn blsBatch_asyncVerifySameMessage(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();
    if (n == 0) return try resolveWithFalse(env);
    if (n > MAX_AGGREGATE_PER_JOB) return error.TooManySets;

    const msg_info = try cb.arg(1).getTypedarrayInfo();
    if (msg_info.data.len != 32) return error.InvalidMessageLength;

    const pks = try allocator.alloc(PublicKey, n);
    errdefer allocator.free(pks);
    const sigs = try allocator.alloc(Signature, n);
    errdefer allocator.free(sigs);

    for (0..n) |i| {
        const set = try sets.getElement(@intCast(i));

        const idx_val = try set.getNamedProperty("index");
        const idx = try idx_val.getValueUint32();
        pks[i] = (try getPubkey(idx)).*;

        const sig_val = try set.getNamedProperty("signature");
        sigs[i] = try deserializeSig(sig_val);
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
        .msg = msg_info.data[0..32].*,
        .pks = pks,
        .sigs = sigs,
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
    try data.work.queue();

    return deferred.getPromise();
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

    try exports.setNamedProperty("blsBatch", obj);
}
