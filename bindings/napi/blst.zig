//! NAPI bindings for BLS (blst) cryptographic operations used by lodestar.
//!
//! This module uses a **Zig ThreadPool** (`thread_pool`) — a fixed-size pool of OS threads
//! initialized once via `initThreadPool`. Used by synchronous NAPI functions (`aggregateVerify`,
//! `verifyMultipleAggregateSignatures`) to fan out pairing checks across worker threads. The
//! call still blocks the JS thread while it waits for the pool to finish, but the crypto work
//! itself is parallelized.
//!
//! `aggregateWithRandomness` runs synchronously on the calling thread and does not
//! rely on the native `thread_pool`. In lodestar, this is called from a Node.js
//! worker thread (BLS thread pool), not the main thread.
const std = @import("std");
const builtin = @import("builtin");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const bls = @import("bls");
const napi_io = @import("./io.zig");

const NativePublicKey = bls.PublicKey;
const NativeSignature = bls.Signature;
const NativeSecretKey = bls.SecretKey;
const Pairing = bls.Pairing;
const AggregatePublicKey = bls.AggregatePublicKey;
const AggregateSignature = bls.AggregateSignature;
const ThreadPool = bls.ThreadPool;
const DST = bls.DST;
const MAX_AGGREGATE_PER_JOB = bls.MAX_AGGREGATE_PER_JOB;

/// Cached thread pool reference for parallel verification.
/// Initialized lazily on first use, torn down via `deinitThreadPool`.
var thread_pool: ?*ThreadPool = null;

pub fn initThreadPool(n_workers: u16) !void {
    if (thread_pool != null) return error.PoolExists;
    thread_pool = try ThreadPool.init(std.heap.page_allocator, napi_io.get(), .{ .n_workers = n_workers });
}

/// Closes the `ThreadPool` used for blst operations.
///
/// Note: this can invalidate any inflight verification requests. Consumer is responsible
/// for the lifecycle of their program and should only call this when all work is done.
///
/// This note is however application dependent. For the use case of lodestar,
/// it's likely that this would not be called at all.
/// Same goes for any other long-lived processes.
pub fn deinitThreadPool() void {
    if (thread_pool) |p| {
        p.deinit(napi_io.get());
        thread_pool = null;
    }
}

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

fn boolOrDefault(value: ?js.Boolean, default: bool) bool {
    return if (value) |v| v.assertBool() else default;
}

fn hexFromString(hex_string: js.String, buf: []u8) ![]const u8 {
    const full = try hex_string.toSlice(buf);
    return if (full.len >= 2 and full[0] == '0' and full[1] == 'x') full[2..] else full;
}

fn formatHex(bytes: []const u8) !js.String {
    const hex = try std.fmt.allocPrint(allocator, "0x{x}", .{bytes});
    defer allocator.free(hex);
    return js.String.from(hex);
}

fn unwrapClass(comptime T: type, value: js.Value) !*T {
    return js.env().unwrap(T, value.toValue());
}

/// Reads a Uint8Array slice from a generic `js.Value`.
///
/// Workaround: `js.Value.asUint8Array` is currently broken in zapi 2.0.0
/// (it calls a non-existent `expectType` method). Instead we narrow via
/// the underlying `napi.Value` directly.
fn uint8SliceFromValue(value: js.Value) ![]u8 {
    const raw = value.toValue();
    if (!(try raw.isTypedarray())) return error.TypeMismatch;
    const info = try raw.getTypedarrayInfo();
    if (info.array_type != .uint8) return error.TypeMismatch;
    return info.data;
}

pub const PublicKey = struct {
    pub const js_meta = js.class(.{});

    raw: NativePublicKey = .{},

    pub fn init() PublicKey {
        return .{};
    }

    /// Converts given array of bytes to a `PublicKey`.
    /// 1) bytes: Uint8Array
    /// 2) pk_validate: ?bool
    pub fn fromBytes(bytes: js.Uint8Array, pk_validate: ?js.Boolean) !PublicKey {
        const slice = try bytes.toSlice();
        var pk = try NativePublicKey.deserialize(slice);
        if (boolOrDefault(pk_validate, false)) {
            try pk.validate();
        }
        return .{ .raw = pk };
    }

    /// Converts given hex string to a `PublicKey`.
    /// 1) bytes: string
    /// 2) pk_validate: ?bool
    pub fn fromHex(hex_string: js.String, pk_validate: ?js.Boolean) !PublicKey {
        var hex_buf: [NativePublicKey.SERIALIZE_SIZE * 2 + 2]u8 = undefined;
        const hex = try hexFromString(hex_string, &hex_buf);

        var bytes_buf: [NativePublicKey.SERIALIZE_SIZE]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&bytes_buf, hex);

        var pk = try NativePublicKey.deserialize(bytes);
        if (boolOrDefault(pk_validate, false)) {
            try pk.validate();
        }
        return .{ .raw = pk };
    }

    /// Validates this public key.
    pub fn validate(self: *const PublicKey) !void {
        try self.raw.validate();
    }

    /// Serializes this public key to bytes.
    pub fn toBytes(self: *const PublicKey, compress: ?js.Boolean) js.Uint8Array {
        if (boolOrDefault(compress, true)) {
            const bytes = self.raw.compress();
            return js.Uint8Array.from(bytes[0..]);
        }
        const bytes = self.raw.serialize();
        return js.Uint8Array.from(bytes[0..]);
    }

    pub fn toHex(self: *const PublicKey, compress: ?js.Boolean) !js.String {
        if (boolOrDefault(compress, true)) {
            const bytes = self.raw.compress();
            return formatHex(bytes[0..]);
        }
        const bytes = self.raw.serialize();
        return formatHex(bytes[0..]);
    }
};

pub const Signature = struct {
    pub const js_meta = js.class(.{});

    raw: NativeSignature = .{},

    pub fn init() Signature {
        return .{};
    }

    /// Converts given array of bytes to a `Signature`.
    pub fn fromBytes(bytes: js.Uint8Array, sig_validate: ?js.Boolean, sig_infcheck: ?js.Boolean) !Signature {
        const slice = try bytes.toSlice();
        var sig = NativeSignature.deserialize(slice) catch return error.DeserializationFailed;
        if (boolOrDefault(sig_validate, false)) {
            try sig.validate(boolOrDefault(sig_infcheck, false));
        }
        return .{ .raw = sig };
    }

    /// Converts given hex string to a `Signature`.
    ///
    /// If `sig_validate` is `true`, the signature will be infinity and group checked.
    /// If `sig_infcheck` is `false`, the infinity check will be skipped.
    pub fn fromHex(hex_string: js.String, sig_validate: ?js.Boolean, sig_infcheck: ?js.Boolean) !Signature {
        var hex_buf: [NativeSignature.SERIALIZE_SIZE * 2 + 2]u8 = undefined;
        const hex = try hexFromString(hex_string, &hex_buf);

        var bytes_buf: [NativeSignature.SERIALIZE_SIZE]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&bytes_buf, hex);

        var sig = NativeSignature.deserialize(bytes) catch return error.DeserializationFailed;
        if (boolOrDefault(sig_validate, false)) {
            try sig.validate(boolOrDefault(sig_infcheck, false));
        }
        return .{ .raw = sig };
    }

    /// Aggregates multiple Signature objects into one.
    /// 1) sigs_array: Signature[]
    /// 2) sigs_groupcheck: ?bool
    pub fn aggregate(signatures: js.Array, sigs_groupcheck: ?js.Boolean) !Signature {
        const signatures_len = try signatures.length();
        if (signatures_len == 0) return error.EmptySignatureArray;

        const sigs = try allocator.alloc(NativeSignature, signatures_len);
        defer allocator.free(sigs);

        for (0..signatures_len) |i| {
            const wrapped = try unwrapClass(Signature, try signatures.get(@intCast(i)));
            sigs[i] = wrapped.raw;
        }

        const agg_sig = AggregateSignature.aggregate(sigs, boolOrDefault(sigs_groupcheck, false)) catch
            return error.AggregationFailed;

        return .{ .raw = agg_sig.toSignature() };
    }

    /// Serializes this signature to bytes.
    pub fn toBytes(self: *const Signature, compress: ?js.Boolean) js.Uint8Array {
        if (boolOrDefault(compress, true)) {
            const bytes = self.raw.compress();
            return js.Uint8Array.from(bytes[0..]);
        }
        const bytes = self.raw.serialize();
        return js.Uint8Array.from(bytes[0..]);
    }

    pub fn toHex(self: *const Signature, compress: ?js.Boolean) !js.String {
        if (boolOrDefault(compress, true)) {
            const bytes = self.raw.compress();
            return formatHex(bytes[0..]);
        }
        const bytes = self.raw.serialize();
        return formatHex(bytes[0..]);
    }

    /// Validates the signature.
    /// Throws an error if the signature is invalid.
    pub fn validate(self: *const Signature, sig_infcheck: js.Boolean) !void {
        self.raw.validate(sig_infcheck.assertBool()) catch return error.InvalidSignature;
    }
};

pub const SecretKey = struct {
    pub const js_meta = js.class(.{});

    raw: NativeSecretKey = .{},

    pub fn init() SecretKey {
        return .{};
    }

    /// Creates a `SecretKey` from raw bytes.
    pub fn fromBytes(bytes: js.Uint8Array) !SecretKey {
        const slice = try bytes.toSlice();
        if (slice.len != NativeSecretKey.serialize_size) {
            return error.InvalidSecretKeyLength;
        }
        const sk = NativeSecretKey.deserialize(slice[0..NativeSecretKey.serialize_size]) catch
            return error.DeserializationFailed;
        return .{ .raw = sk };
    }

    /// Creates a `SecretKey` from a hex string.
    pub fn fromHex(hex_string: js.String) !SecretKey {
        var hex_buf: [NativeSecretKey.serialize_size * 2 + 3]u8 = undefined;
        const hex = try hexFromString(hex_string, &hex_buf);

        var bytes_buf: [NativeSecretKey.serialize_size]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&bytes_buf, hex);
        const sk = NativeSecretKey.deserialize(bytes[0..NativeSecretKey.serialize_size]) catch
            return error.DeserializationFailed;
        return .{ .raw = sk };
    }

    /// Generates a `SecretKey` from a seed (IKM) using key derivation.
    /// Seed must be at least 32 bytes.
    pub fn fromKeygen(seed: js.Uint8Array, key_info: ?js.Value) !SecretKey {
        const seed_slice = try seed.toSlice();
        if (seed_slice.len < 32) return error.InvalidSeedLength;

        const key_info_slice: ?[]const u8 = if (key_info) |value| blk: {
            if (value.isUndefined() or value.isNull()) break :blk null;
            break :blk try uint8SliceFromValue(value);
        } else null;

        const sk = NativeSecretKey.keyGen(seed_slice, key_info_slice) catch return error.KeyGenFailed;
        return .{ .raw = sk };
    }

    /// Signs a message with this `SecretKey`, returns a `Signature`.
    pub fn sign(self: *const SecretKey, msg: js.Uint8Array) !Signature {
        const slice = try msg.toSlice();
        return .{ .raw = self.raw.sign(slice, DST, null) };
    }

    /// Derives the PublicKey from this SecretKey.
    pub fn toPublicKey(self: *const SecretKey) !PublicKey {
        return .{ .raw = self.raw.toPublicKey() };
    }

    /// Serializes the SecretKey to bytes (32 bytes).
    pub fn toBytes(self: *const SecretKey) js.Uint8Array {
        const bytes = self.raw.serialize();
        return js.Uint8Array.from(bytes[0..]);
    }

    pub fn toHex(self: *const SecretKey) !js.String {
        const bytes = self.raw.serialize();
        return formatHex(bytes[0..]);
    }
};

/// Verifies a given `msg` against a `Signature` and a `PublicKey`.
///
/// Returns `true` if signature is valid, `false` otherwise.
///
/// Arguments:
/// 1) msg: Uint8Array
/// 2) pk: PublicKey
/// 3) sig: Signature
/// 4) pk_validate: ?bool
/// 5) sig_groupcheck: ?bool
pub fn verify(msg: js.Uint8Array, pk: PublicKey, sig: Signature, pk_validate: ?js.Boolean, sig_groupcheck: ?js.Boolean) !js.Boolean {
    const msg_slice = try msg.toSlice();

    sig.raw.verify(
        boolOrDefault(sig_groupcheck, false),
        msg_slice,
        DST,
        null,
        &pk.raw,
        boolOrDefault(pk_validate, false),
    ) catch return js.Boolean.from(false);

    return js.Boolean.from(true);
}

/// Verify an aggregated signature against multiple messages and multiple public keys.
/// 1) msgs: Uint8Array[]
/// 2) pks: PublicKey[]
/// 3) sig: Signature
/// 4) pks_validate: ?bool
/// 5) sig_groupcheck: ?bool
pub fn aggregateVerify(msgs: js.Array, pks: js.Array, sig: Signature, pks_validate: ?js.Boolean, sig_groupcheck: ?js.Boolean) !js.Boolean {
    const msgs_len = try msgs.length();
    const pks_len = try pks.length();
    if (msgs_len == 0 or pks_len == 0 or msgs_len != pks_len) {
        return error.InvalidAggregateVerifyInput;
    }

    const msg_bufs = try allocator.alloc([32]u8, msgs_len);
    defer allocator.free(msg_bufs);

    const pk_ptrs = try allocator.alloc(*NativePublicKey, pks_len);
    defer allocator.free(pk_ptrs);

    for (0..msgs_len) |i| {
        const msg_value = try msgs.get(@intCast(i));
        const msg_bytes = try uint8SliceFromValue(msg_value);
        if (msg_bytes.len != 32) return error.InvalidMessageLength;
        @memcpy(&msg_bufs[i], msg_bytes[0..32]);

        const wrapped_pk = try unwrapClass(PublicKey, try pks.get(@intCast(i)));
        pk_ptrs[i] = &wrapped_pk.raw;
    }

    const pool = thread_pool orelse @panic("ThreadPool not initialized; call initThreadPool first");
    const result = pool.aggregateVerify(
        napi_io.get(),
        &sig.raw,
        boolOrDefault(sig_groupcheck, false),
        msg_bufs,
        DST,
        pk_ptrs,
        boolOrDefault(pks_validate, false),
    ) catch return js.Boolean.from(false);

    return js.Boolean.from(result);
}

/// Aggregate and verify an array of `PublicKey`s. Returns `false` if pks array is empty
/// or if signature is invalid.
///
/// `msg` (signing root) must be exactly 32 bytes.
///
/// Arguments:
/// 1) msg: Uint8Array
/// 2) pks: PublicKey[]
/// 3) sig: Signature
/// 4) sigs_groupcheck: ?bool
pub fn fastAggregateVerify(msg: js.Uint8Array, pks: js.Array, sig: Signature, sigs_groupcheck: ?js.Boolean) !js.Boolean {
    const msg_slice = try msg.toSlice();
    if (msg_slice.len != 32) return error.InvalidMessageLength;

    const pks_len = try pks.length();
    if (pks_len == 0) return js.Boolean.from(false);

    const native_pks = try allocator.alloc(NativePublicKey, pks_len);
    defer allocator.free(native_pks);

    for (0..pks_len) |i| {
        const wrapped_pk = try unwrapClass(PublicKey, try pks.get(@intCast(i)));
        native_pks[i] = wrapped_pk.raw;
    }

    var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
    // `pks_validate` is always false here since we assume proof of possession for public keys.
    const result = sig.raw.fastAggregateVerify(
        boolOrDefault(sigs_groupcheck, false),
        &pairing_buf,
        msg_slice[0..32],
        DST,
        native_pks,
        false,
    ) catch return js.Boolean.from(false);

    return js.Boolean.from(result);
}

/// Batch verify multiple signature sets.
/// Returns `false` if verification fails.
///
/// Arguments:
/// 1) sets: Array of { msg: Uint8Array, pk: PublicKey, sig: Signature }
/// 2) pks_validate: ?bool
/// 3) sigs_groupcheck: ?bool
pub fn verifyMultipleAggregateSignatures(sets: js.Array, pks_validate: ?js.Boolean, sigs_groupcheck: ?js.Boolean) !js.Boolean {
    const n_elems = try sets.length();
    if (n_elems == 0) return js.Boolean.from(false);

    const msgs = try allocator.alloc([32]u8, n_elems);
    defer allocator.free(msgs);

    const pks = try allocator.alloc(*NativePublicKey, n_elems);
    defer allocator.free(pks);

    const sigs = try allocator.alloc(*NativeSignature, n_elems);
    defer allocator.free(sigs);

    const rands = try allocator.alloc([32]u8, n_elems);
    defer allocator.free(rands);

    var seed_bytes: [8]u8 = undefined;
    const io = napi_io.get();
    io.random(&seed_bytes);
    var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed_bytes, .little));
    const rand = prng.random();

    const e = js.env();
    for (0..n_elems) |i| {
        const set = (try sets.get(@intCast(i))).toValue();

        const msg_napi = try set.getNamedProperty("msg");
        const msg_bytes = try uint8SliceFromValue(.{ .val = msg_napi });
        if (msg_bytes.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_bytes[0..32]);

        const pk_napi = try set.getNamedProperty("pk");
        const wrapped_pk = try e.unwrap(PublicKey, pk_napi);
        pks[i] = &wrapped_pk.raw;

        const sig_napi = try set.getNamedProperty("sig");
        const wrapped_sig = try e.unwrap(Signature, sig_napi);
        sigs[i] = &wrapped_sig.raw;

        rand.bytes(&rands[i]);
        // Ensure first 8 bytes (RAND_BITS=64) are non-zero
        while (std.mem.allEqual(u8, rands[i][0..8], 0)) {
            rand.bytes(rands[i][0..8]);
        }
    }

    const pool = thread_pool orelse @panic("ThreadPool not initialized; call initThreadPool first");
    const result = pool.verifyMultipleAggregateSignatures(
        napi_io.get(),
        n_elems,
        msgs,
        DST,
        pks,
        boolOrDefault(pks_validate, false),
        sigs,
        boolOrDefault(sigs_groupcheck, false),
        rands,
    ) catch return js.Boolean.from(false);

    return js.Boolean.from(result);
}

/// Aggregate multiple Signature objects into one.
/// Validates each signature if `sigs_groupcheck` is true.
///
/// Arguments:
/// 1) signatures: Signature[]
/// 2) sigs_groupcheck: ?bool
pub fn aggregateSignatures(signatures: js.Array, sigs_groupcheck: ?js.Boolean) !Signature {
    const signatures_len = try signatures.length();
    if (signatures_len == 0) return error.EmptySignatureArray;

    const sigs = try allocator.alloc(NativeSignature, signatures_len);
    defer allocator.free(sigs);

    for (0..signatures_len) |i| {
        const wrapped = try unwrapClass(Signature, try signatures.get(@intCast(i)));
        sigs[i] = wrapped.raw;
    }

    const agg_sig = AggregateSignature.aggregate(sigs, boolOrDefault(sigs_groupcheck, false)) catch
        return error.AggregationFailed;

    return .{ .raw = agg_sig.toSignature() };
}

/// Aggregate multiple `PublicKey` objects into one.
///
/// Arguments:
/// 1) pks: PublicKey[]
/// 2) pks_validate: ?bool
pub fn aggregatePublicKeys(pks: js.Array, pks_validate: ?js.Boolean) !PublicKey {
    const pks_len = try pks.length();
    if (pks_len == 0) return error.EmptyPublicKeyArray;

    const native_pks = try allocator.alloc(NativePublicKey, pks_len);
    defer allocator.free(native_pks);

    for (0..pks_len) |i| {
        const wrapped = try unwrapClass(PublicKey, try pks.get(@intCast(i)));
        native_pks[i] = wrapped.raw;
    }

    const agg_pk = AggregatePublicKey.aggregate(native_pks, boolOrDefault(pks_validate, false)) catch
        return error.AggregationFailed;

    return .{ .raw = agg_pk.toPublicKey() };
}

/// Aggregate public keys from serialized bytes.
///
/// Arguments:
/// 1) serializedPublicKeys: Uint8Array[] - array of serialized (96-bytes each) `PublicKey`s.
/// 2) pks_validate: ?bool
pub fn aggregateSerializedPublicKeys(serialized_public_keys: js.Array, pks_validate: ?js.Boolean) !PublicKey {
    const pks_len = try serialized_public_keys.length();
    if (pks_len == 0) return error.EmptyPublicKeyArray;

    const native_pks = try allocator.alloc(NativePublicKey, pks_len);
    defer allocator.free(native_pks);

    for (0..pks_len) |i| {
        const bytes = try uint8SliceFromValue(try serialized_public_keys.get(@intCast(i)));
        native_pks[i] = NativePublicKey.deserialize(bytes) catch return error.DeserializationFailed;
    }

    const agg_pk = AggregatePublicKey.aggregate(native_pks, boolOrDefault(pks_validate, false)) catch
        return error.AggregationFailed;

    return .{ .raw = agg_pk.toPublicKey() };
}

/// Synchronously aggregates public keys and signatures with randomness using
/// Pippenger multi-scalar multiplication. Runs on the calling thread.
///
/// Arguments:
/// 1) sets: Array of {pk: PublicKey, sig: Uint8Array}
///
/// Returns: {pk: PublicKey, sig: Signature}
///
/// TODO(zapi#23): once the DSL supports returning a struct of class instances,
/// change the return type to `!struct { pk: PublicKey, sig: Signature }` and
/// drop the manual `createObject` + `convertReturn` + `setNamedProperty` plumbing
/// at the bottom of this function.
/// See https://github.com/ChainSafe/zapi/issues/23
pub fn aggregateWithRandomness(sets: js.Array) !js.Value {
    const n = try sets.length();
    if (n == 0) return error.EmptyArray;
    if (n > MAX_AGGREGATE_PER_JOB) return error.TooManySets;

    const nbits: usize = 64;
    const nbytes: usize = 8;

    var pk_ptrs: [MAX_AGGREGATE_PER_JOB]*const NativePublicKey = undefined;
    var sigs: [MAX_AGGREGATE_PER_JOB]NativeSignature = undefined;
    var sig_ptrs: [MAX_AGGREGATE_PER_JOB]*const NativeSignature = undefined;

    var seed_bytes: [8]u8 = undefined;
    const io = napi_io.get();
    io.random(&seed_bytes);
    var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed_bytes, .little));
    const rand = prng.random();
    var scalars: [8 * MAX_AGGREGATE_PER_JOB]u8 = undefined;
    var sca_ptrs: [MAX_AGGREGATE_PER_JOB]*const u8 = undefined;
    rand.bytes(scalars[0 .. n * nbytes]);

    const env = js.env();
    for (0..n) |i| {
        const set = (try sets.get(@intCast(i))).toValue();

        const pk_napi = try set.getNamedProperty("pk");
        const wrapped_pk = try env.unwrap(PublicKey, pk_napi);
        pk_ptrs[i] = &wrapped_pk.raw;

        const sig_napi = try set.getNamedProperty("sig");
        const sig_bytes = try uint8SliceFromValue(.{ .val = sig_napi });
        sigs[i] = NativeSignature.deserialize(sig_bytes[0..]) catch return error.DeserializationFailed;
        sigs[i].validate(true) catch return error.InvalidSignature;
        sig_ptrs[i] = &sigs[i];

        while (std.mem.allEqual(u8, scalars[i * nbytes ..][0..nbytes], 0)) {
            rand.bytes(scalars[i * nbytes ..][0..nbytes]);
        }
        sca_ptrs[i] = &scalars[i * nbytes];
    }

    const scratch_size = @max(
        bls.c.blst_p1s_mult_pippenger_scratch_sizeof(n),
        bls.c.blst_p2s_mult_pippenger_scratch_sizeof(n),
    );
    const scratch = try allocator.alloc(u64, scratch_size);
    defer allocator.free(scratch);

    // Pippenger multi-scalar multiplication on G1 (pubkeys)
    var p1_ret: bls.c.blst_p1 = std.mem.zeroes(bls.c.blst_p1);
    bls.c.blst_p1s_mult_pippenger(
        &p1_ret,
        @ptrCast(&pk_ptrs),
        n,
        @ptrCast(&sca_ptrs),
        nbits,
        scratch.ptr,
    );
    var result_pk: NativePublicKey = .{};
    bls.c.blst_p1_to_affine(&result_pk.point, &p1_ret);

    // Pippenger multi-scalar multiplication on G2 (signatures)
    var p2_ret: bls.c.blst_p2 = std.mem.zeroes(bls.c.blst_p2);
    bls.c.blst_p2s_mult_pippenger(
        &p2_ret,
        @ptrCast(&sig_ptrs),
        n,
        @ptrCast(&sca_ptrs),
        nbits,
        scratch.ptr,
    );
    var result_sig: NativeSignature = .{};
    bls.c.blst_p2_to_affine(&result_sig.point, &p2_ret);

    const pk_value = napi.Value{ .env = env.env, .value = js.convertReturn(PublicKey, .{ .raw = result_pk }, env.env) };
    const sig_value = napi.Value{ .env = env.env, .value = js.convertReturn(Signature, .{ .raw = result_sig }, env.env) };

    const result = try env.createObject();
    try result.setNamedProperty("pk", pk_value);
    try result.setNamedProperty("sig", sig_value);
    return .{ .val = result };
}
