//! Contains the necessary bindings for blst operations in lodestar-ts.
const std = @import("std");
const napi = @import("zapi:napi");
const blst = @import("blst");
const builtin = @import("builtin");
const getter = @import("napi_property_descriptor.zig").getter;
const method = @import("napi_property_descriptor.zig").method;

const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const SecretKey = blst.SecretKey;
const Pairing = blst.Pairing;
const AggregatePublicKey = blst.AggregatePublicKey;
const AggregateSignature = blst.AggregateSignature;
const DST = blst.DST;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

pub fn PublicKey_finalize(_: napi.Env, pk: *PublicKey, _: ?*anyopaque) void {
    allocator.destroy(pk);
}

pub fn PublicKey_ctor(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const pk = try allocator.create(PublicKey);
    errdefer allocator.destroy(pk);
    _ = try env.wrap(cb.this(), PublicKey, pk, PublicKey_finalize, null);
    return cb.this();
}

/// Converts given array of bytes to a `PublicKey`.
pub fn PublicKey_fromBytes(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const ctor = cb.this();
    const bytes_info = try cb.arg(0).getTypedarrayInfo();

    const pk_value = try env.newInstance(ctor, .{});
    const pk = try env.unwrap(PublicKey, pk_value);

    pk.* = try PublicKey.deserialize(bytes_info.data[0..PublicKey.SERIALIZE_SIZE]);

    return pk_value;
}

/// Serializes and compresses this public key to bytes.
pub fn PublicKey_toBytesCompress(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const pk = try env.unwrap(PublicKey, cb.this());
    const bytes = pk.compress();

    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(PublicKey.COMPRESS_SIZE, &arraybuffer_bytes);
    @memcpy(arraybuffer_bytes[0..PublicKey.COMPRESS_SIZE], &bytes);
    return try env.createTypedarray(.uint8, PublicKey.COMPRESS_SIZE, arraybuffer, 0);
}

/// Serializes this public key to bytes.
pub fn PublicKey_toBytes(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const pk = try env.unwrap(PublicKey, cb.this());
    const bytes = pk.serialize();

    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(PublicKey.SERIALIZE_SIZE, &arraybuffer_bytes);
    @memcpy(arraybuffer_bytes[0..PublicKey.SERIALIZE_SIZE], &bytes);
    return try env.createTypedarray(.uint8, PublicKey.SERIALIZE_SIZE, arraybuffer, 0);
}

pub fn Signature_finalize(_: napi.Env, sig: *Signature, _: ?*anyopaque) void {
    allocator.destroy(sig);
}

pub fn Signature_ctor(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const sig = try allocator.create(Signature);
    errdefer allocator.destroy(sig);
    _ = try env.wrap(cb.this(), Signature, sig, Signature_finalize, null);
    return cb.this();
}

/// Converts given array of bytes to a `Signature`.
pub fn Signature_fromBytes(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const ctor = cb.this();
    const bytes_info = try cb.arg(0).getTypedarrayInfo();

    const sig_value = try env.newInstance(ctor, .{});
    const sig = try env.unwrap(Signature, sig_value);

    sig.* = Signature.deserialize(bytes_info.data[0..Signature.SERIALIZE_SIZE]) catch return error.DeserializationFailed;

    return sig_value;
}

/// Serializes this signature to bytes.
pub fn Signature_toBytes(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const sig = try env.unwrap(Signature, cb.this());
    const bytes = sig.serialize();

    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(Signature.SERIALIZE_SIZE, &arraybuffer_bytes);
    @memcpy(arraybuffer_bytes[0..Signature.SERIALIZE_SIZE], &bytes);
    return try env.createTypedarray(.uint8, Signature.SERIALIZE_SIZE, arraybuffer, 0);
}

/// Serializes and compresses this signature to bytes.
pub fn Signature_toBytesCompress(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const sig = try env.unwrap(Signature, cb.this());
    const bytes = sig.compress();

    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(Signature.COMPRESS_SIZE, &arraybuffer_bytes);
    @memcpy(arraybuffer_bytes[0..Signature.COMPRESS_SIZE], &bytes);
    return try env.createTypedarray(.uint8, Signature.COMPRESS_SIZE, arraybuffer, 0);
}

/// Verifies a given `msg` against a `Signature` and a `PublicKey`.
///
/// Returns `true` if signature is valid, `false` otherwise.
///
/// Arguments:
/// 1) msg: Uint8Array
/// 2) pk: PublicKey
/// 3) sig: Signature
/// 4) pk_validate: bool
/// 5) sig_groupcheck: bool
pub fn blst_verify(env: napi.Env, cb: napi.CallbackInfo(5)) !napi.Value {
    const msg_info = try cb.arg(0).getTypedarrayInfo();
    const pk = try env.unwrap(PublicKey, cb.arg(1));
    const sig = try env.unwrap(Signature, cb.arg(2));
    const pk_validate = try cb.arg(3).getValueBool();
    const sig_groupcheck = try cb.arg(4).getValueBool();

    sig.verify(sig_groupcheck, msg_info.data, DST, null, pk, pk_validate) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(true);
}

pub fn SecretKey_finalize(_: napi.Env, sk: *SecretKey, _: ?*anyopaque) void {
    allocator.destroy(sk);
}

pub fn SecretKey_ctor(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const sk = try allocator.create(SecretKey);
    errdefer allocator.destroy(sk);
    _ = try env.wrap(cb.this(), SecretKey, sk, SecretKey_finalize, null);
    return cb.this();
}

/// Creates a `SecretKey` from raw bytes.
pub fn SecretKey_fromBytes(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const ctor = cb.this();
    const bytes_info = try cb.arg(0).getTypedarrayInfo();

    if (bytes_info.data.len != SecretKey.serialize_size) {
        return error.InvalidSecretKeyLength;
    }

    const sk_value = try env.newInstance(ctor, .{});
    const sk = try env.unwrap(SecretKey, sk_value);
    sk.* = SecretKey.deserialize(bytes_info.data[0..SecretKey.serialize_size]) catch return error.DeserializationFailed;

    return sk_value;
}

/// Generates a `SecretKey` from a seed (IKM) using key derivation.
///
/// Seed must be at least 32 bytes.
pub fn SecretKey_fromKeygen(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const ctor = cb.this();
    const bytes_info = try cb.arg(0).getTypedarrayInfo();

    if (bytes_info.data.len < 32) return error.InvalidSeedLength;

    const sk_value = try env.newInstance(ctor, .{});
    const sk = try env.unwrap(SecretKey, sk_value);
    sk.* = SecretKey.keyGen(bytes_info.data, null) catch return error.KeyGenFailed;

    return sk_value;
}

/// Signs a message with this `SecretKey`, returns a `Signature`.
pub fn SecretKey_sign(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sk = try env.unwrap(SecretKey, cb.this());
    const msg = try cb.arg(0).getTypedarrayInfo();

    const global = try env.getGlobal();
    const blst_obj = try global.getNamedProperty("blst");
    const sig_ctor = try blst_obj.getNamedProperty("Signature");

    const sig_value = try env.newInstance(sig_ctor, .{});
    const sig = try env.unwrap(Signature, sig_value);
    sig.* = sk.sign(msg.data, DST, null);

    return sig_value;
}

/// Derives the PublicKey from this SecretKey.
pub fn SecretKey_toPublicKey(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const sk = try env.unwrap(SecretKey, cb.this());

    const global = try env.getGlobal();
    const blst_obj = try global.getNamedProperty("blst");
    const pk_ctor = try blst_obj.getNamedProperty("PublicKey");

    const pk_value = try env.newInstance(pk_ctor, .{});
    const pk = try env.unwrap(PublicKey, pk_value);
    pk.* = sk.toPublicKey();

    return pk_value;
}

/// Serializes the SecretKey to bytes (32 bytes).
pub fn SecretKey_toBytes(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const sk = try env.unwrap(SecretKey, cb.this());
    const bytes = sk.serialize();

    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(SecretKey.serialize_size, &arraybuffer_bytes);
    @memcpy(arraybuffer_bytes[0..SecretKey.serialize_size], &bytes);
    return try env.createTypedarray(.uint8, SecretKey.serialize_size, arraybuffer, 0);
}

/// Aggregates multiple Signature objects into one.
///
/// 1) sigs_array: []Signature
/// 2) sigs_groupcheck: bool
pub fn Signature_aggregate(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const ctor = cb.this();
    const sigs_array = cb.arg(0);
    const sigs_groupcheck = try cb.arg(1).getValueBool();

    const sigs_len = try sigs_array.getArrayLength();
    if (sigs_len == 0) return error.EmptySignatureArray;

    const sigs = try allocator.alloc(Signature, sigs_len);
    defer allocator.free(sigs);

    for (0..sigs_len) |i| {
        const sig_value = try sigs_array.getElement(@intCast(i));
        const sig = try env.unwrap(Signature, sig_value);
        sigs[i] = sig.*;
    }

    const agg_sig = AggregateSignature.aggregate(sigs, sigs_groupcheck) catch return error.AggregationFailed;

    const sig_value = try env.newInstance(ctor, .{});
    const sig = try env.unwrap(Signature, sig_value);
    sig.* = agg_sig.toSignature();

    return sig_value;
}

/// Validates the signature.
/// Throws an error if the signature is invalid.
pub fn Signature_sigValidate(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sig = try env.unwrap(Signature, cb.this());
    const sig_infcheck = try cb.arg(0).getValueBool();

    sig.validate(sig_infcheck) catch return error.InvalidSignature;

    return try env.getUndefined();
}

/// Aggregate and verify an array of `PublicKey`s. Returns `false` if pks array is empty or if signature is invalid.
///
/// `msg` (signing root) must be exactly 32 bytes.
///
/// Arguments:
/// 1) msg: Uint8Array
/// 2) pks: PublicKey[]
/// 3) sig: Signature
/// 4) sig_groupcheck: bool
/// 5) pks_validate: bool
pub fn blst_fastAggregateVerify(env: napi.Env, cb: napi.CallbackInfo(3)) !napi.Value {
    const msg_info = try cb.arg(0).getTypedarrayInfo();
    if (msg_info.data.len != 32) return error.InvalidMessageLength;

    const pks_array = cb.arg(1);
    const sig = try env.unwrap(Signature, cb.arg(2));
    const pks_validate = try cb.arg(3).getValueBool();
    const sig_groupcheck = try cb.arg(4).getValueBool();

    const pks_len = try pks_array.getArrayLength();
    if (pks_len == 0) {
        return try env.getBoolean(false);
    }

    const pks = try allocator.alloc(PublicKey, pks_len);
    defer allocator.free(pks);

    for (0..pks_len) |i| {
        const pk_value = try pks_array.getElement(@intCast(i));
        const pk = try env.unwrap(PublicKey, pk_value);
        pks[i] = pk.*;
    }

    var pairing_buf: [Pairing.sizeOf()]u8 = undefined;
    const result = sig.fastAggregateVerify(sig_groupcheck, &pairing_buf, msg_info.data[0..32], DST, pks, pks_validate) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(result);
}

/// Batch verify multiple signature sets.
/// Returns `false` if verification fails.
///
/// Arguments:
/// 1) sets: Array of { msg: Uint8Array, pk: PublicKey, sig: Signature }
/// 2) sigs_groupcheck: bool
/// 3) pks_validate: bool
pub fn blst_verifyMultipleAggregateSignatures(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n_elems = try sets.getArrayLength();

    const sigs_groupcheck = try cb.arg(1).getValueBool();
    const pks_validate = try cb.arg(2).getValueBool();

    if (n_elems == 0) {
        return try env.getBoolean(false);
    }

    //TODO: don't allocate msgs, pks, sigs
    const msgs = try allocator.alloc([32]u8, n_elems);
    defer allocator.free(msgs);

    const pks = try allocator.alloc(*PublicKey, n_elems);
    defer allocator.free(pks);

    const sigs = try allocator.alloc(*Signature, n_elems);
    defer allocator.free(sigs);

    const rands = try allocator.alloc([32]u8, n_elems);
    defer allocator.free(rands);

    const pk_storage = try allocator.alloc(PublicKey, n_elems);
    defer allocator.free(pk_storage);

    const sig_storage = try allocator.alloc(Signature, n_elems);
    defer allocator.free(sig_storage);

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch {
            seed = @intCast(std.time.milliTimestamp());
        };
        break :blk seed;
    });
    const rand = prng.random();

    for (0..n_elems) |i| {
        const set_value = try sets.getElement(@intCast(i));

        const msg_value = try set_value.getNamedProperty("msg");
        const msg = try msg_value.getTypedarrayInfo();
        if (msg.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg.data[0..32]);

        const pk_value = try set_value.getNamedProperty("pk");
        const pk = try env.unwrap(PublicKey, pk_value);
        pk_storage[i] = pk.*;
        pks[i] = &pk_storage[i];

        const sig_value = try set_value.getNamedProperty("sig");
        const sig = try env.unwrap(Signature, sig_value);
        sig_storage[i] = sig.*;
        sigs[i] = &sig_storage[i];

        rand.bytes(&rands[i]);
    }

    var pairing_buf: [Pairing.sizeOf()]u8 = undefined;
    const result = blst.verifyMultipleAggregateSignatures(
        &pairing_buf,
        n_elems,
        msgs,
        DST,
        pks,
        pks_validate,
        sigs,
        sigs_groupcheck,
        rands,
    ) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(result);
}

/// Aggregate multiple Signature objects into one.
/// Validates each signature if `sigs_groupcheck` is true.
///
/// Arguments:
/// 1) signatures: Signature[]
/// 2) sigs_groupcheck: bool
pub fn blst_aggregateSignatures(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const sigs_array = cb.arg(0);
    const sigs_groupcheck = try cb.arg(1).getValueBool();

    const sigs_len = try sigs_array.getArrayLength();

    if (sigs_len == 0) return error.EmptySignatureArray;

    const sigs = try allocator.alloc(Signature, sigs_len);
    defer allocator.free(sigs);

    for (0..sigs_len) |i| {
        const sig_value = try sigs_array.getElement(@intCast(i));
        const sig = try env.unwrap(Signature, sig_value);
        sigs[i] = sig.*;
    }

    const agg_sig = AggregateSignature.aggregate(sigs, sigs_groupcheck) catch return error.AggregationFailed;
    const result_sig = agg_sig.toSignature();

    const global = try env.getGlobal();
    const blst_obj = try global.getNamedProperty("blst");
    const sig_ctor = try blst_obj.getNamedProperty("Signature");

    const sig_value = try env.newInstance(sig_ctor, .{});
    const sig = try env.unwrap(Signature, sig_value);
    sig.* = result_sig;

    return sig_value;
}

/// Aggregate multiple `PublicKey` objects into one.
///
/// Arguments:
/// 1) pks: PublicKey[]
/// 2) pks_validate: bool
pub fn blst_aggregatePublicKeys(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const pks_array = cb.arg(0);
    const pks_len = try pks_array.getArrayLength();
    const pks_validate = try cb.arg(1).getValueBool();

    if (pks_len == 0) {
        return error.EmptyPublicKeyArray;
    }

    const pks = try allocator.alloc(PublicKey, pks_len);
    defer allocator.free(pks);

    for (0..pks_len) |i| {
        const pk_value = try pks_array.getElement(@intCast(i));
        const pk = try env.unwrap(PublicKey, pk_value);
        pks[i] = pk.*;
    }

    const agg_pk = AggregatePublicKey.aggregate(pks, pks_validate) catch return error.AggregationFailed;
    const result_pk = agg_pk.toPublicKey();

    const global = try env.getGlobal();
    const blst_obj = try global.getNamedProperty("blst");
    const pk_ctor = try blst_obj.getNamedProperty("PublicKey");

    const pk_value = try env.newInstance(pk_ctor, .{});
    const pk = try env.unwrap(PublicKey, pk_value);
    pk.* = result_pk;

    return pk_value;
}

/// Aggregate public keys from serialized bytes.
///
/// Arguments:
/// 1) serializedPublicKeys: Uint8Array[] - array of serialized (96-bytes each) `PublicKey`s.
pub fn blst_aggregateSerializedPublicKeys(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const pks_array = cb.arg(0);
    const pks_len = try pks_array.getArrayLength();
    const pks_validate = try cb.arg(1).getValueBool();

    if (pks_len == 0) return error.EmptyPublicKeyArray;

    const pks = try allocator.alloc(PublicKey, pks_len);
    defer allocator.free(pks);

    for (0..pks_len) |i| {
        const pk_bytes_value = try pks_array.getElement(@intCast(i));
        const bytes_info = try pk_bytes_value.getTypedarrayInfo();

        pks[i] = PublicKey.deserialize(bytes_info.data[0..PublicKey.SERIALIZE_SIZE]) catch
            return error.DeserializationFailed;
    }

    const agg_pk = AggregatePublicKey.aggregate(pks, pks_validate) catch return error.AggregationFailed;
    const result_pk = agg_pk.toPublicKey();

    const global = try env.getGlobal();
    const blst_obj = try global.getNamedProperty("blst");
    const pk_ctor = try blst_obj.getNamedProperty("PublicKey");

    const pk_value = try env.newInstance(pk_ctor, .{});
    const pk = try env.unwrap(PublicKey, pk_value);
    pk.* = result_pk;

    return pk_value;
}

//TODO: implement
pub fn blst_asyncAggregateWithRandomness(_: napi.Env, _: napi.CallbackInfo(1)) !napi.Value {
    unreachable;
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const blst_obj = try env.createObject();

    const sk_ctor = try env.defineClass(
        "SecretKey",
        0,
        SecretKey_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            method(1, SecretKey_sign),
            method(0, SecretKey_toPublicKey),
            method(0, SecretKey_toBytes),
        },
    );
    try sk_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{
        method(1, SecretKey_fromBytes),
        method(1, SecretKey_fromKeygen),
    });

    const pk_ctor = try env.defineClass(
        "PublicKey",
        0,
        PublicKey_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            method(0, PublicKey_toBytes),
            method(0, PublicKey_toBytesCompress),
        },
    );
    try pk_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{
        method(1, PublicKey_fromBytes),
    });

    const sig_ctor = try env.defineClass(
        "Signature",
        0,
        Signature_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            method(0, Signature_toBytes),
            method(0, Signature_toBytesCompress),
            .{ .utf8name = "sigValidate", .method = napi.wrapCallback(1, Signature_sigValidate) },
        },
    );
    try sig_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{
        .{ .utf8name = "fromBytes", .method = napi.wrapCallback(1, Signature_fromBytes) },
        .{ .utf8name = "aggregate", .method = napi.wrapCallback(1, Signature_aggregate) },
    });

    try blst_obj.setNamedProperty("SecretKey", sk_ctor);
    try blst_obj.setNamedProperty("PublicKey", pk_ctor);
    try blst_obj.setNamedProperty("Signature", sig_ctor);

    try blst_obj.setNamedProperty("verify", try env.createFunction("verify", 5, blst_verify, null));
    try blst_obj.setNamedProperty("fastAggregateVerify", try env.createFunction("fastAggregateVerify", 3, blst_fastAggregateVerify, null));
    try blst_obj.setNamedProperty("verifyMultipleAggregateSignatures", try env.createFunction("verifyMultipleAggregateSignatures", 1, blst_verifyMultipleAggregateSignatures, null));
    try blst_obj.setNamedProperty("aggregateSignatures", try env.createFunction("aggregateSignatures", 2, blst_aggregateSignatures, null));
    try blst_obj.setNamedProperty("aggregatePublicKeys", try env.createFunction("aggregatePublicKeys", 1, blst_aggregatePublicKeys, null));
    try blst_obj.setNamedProperty("aggregateSerializedPublicKeys", try env.createFunction("aggregateSerializedPublicKeys", 1, blst_aggregateSerializedPublicKeys, null));

    try blst_obj.setNamedProperty("SIGNATURE_LENGTH_UNCOMPRESSED", try env.createUint32(Signature.SERIALIZE_SIZE));

    try exports.setNamedProperty("blst", blst_obj);

    const global = try env.getGlobal();
    try global.setNamedProperty("blst", blst_obj);
}
