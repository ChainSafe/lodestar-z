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

// Holds references to the constructors for PublicKey and Signature classes.
var public_key_ctor_ref: ?napi.c.napi_ref = null;
var signature_ctor_ref: ?napi.c.napi_ref = null;

fn setRef(env: napi.Env, ctor: napi.Value, slot: *?napi.c.napi_ref) !void {
    if (slot.*) |ref| {
        try napi.status.check(napi.c.napi_delete_reference(env.env, ref));
    }

    var ref: napi.c.napi_ref = undefined;
    try napi.status.check(napi.c.napi_create_reference(env.env, ctor.value, 1, &ref));
    slot.* = ref;
}

fn getFromRef(env: napi.Env, slot: ?napi.c.napi_ref) !napi.Value {
    const ref_ = slot orelse return error.RefNotInitialized;

    var value: napi.c.napi_value = undefined;
    try napi.status.check(napi.c.napi_get_reference_value(env.env, ref_, &value));
    return .{
        .env = env.env,
        .value = value,
    };
}

pub fn newPublicKeyInstance(env: napi.Env) !napi.Value {
    const ctor = try getFromRef(env, public_key_ctor_ref);
    return try env.newInstance(ctor, .{});
}

pub fn newSignatureInstance(env: napi.Env) !napi.Value {
    const ctor = try getFromRef(env, signature_ctor_ref);
    return try env.newInstance(ctor, .{});
}

fn coerceToBool(boolish: napi.Value) napi.status.NapiError!bool {
    const b = try boolish.coerceToBool();
    return b.getValueBool();
}

pub fn deinit() void {
    if (public_key_ctor_ref) |ref| {
        napi.status.check(napi.c.napi_delete_reference(null, ref)) catch {};
        public_key_ctor_ref = null;
    }
    if (signature_ctor_ref) |ref| {
        napi.status.check(napi.c.napi_delete_reference(null, ref)) catch {};
        signature_ctor_ref = null;
    }
}

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

    pk.* = try PublicKey.deserialize(bytes_info.data[0..]);

    return pk_value;
}

/// Converts given array of bytes to a `PublicKey`.
pub fn PublicKey_validate(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const pk = try env.unwrap(PublicKey, cb.this());
    try pk.validate();

    return try env.getUndefined();
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
pub fn Signature_fromBytes(env: napi.Env, cb: napi.CallbackInfo(3)) !napi.Value {
    const ctor = cb.this();
    const bytes_info = try cb.arg(0).getTypedarrayInfo();
    const sig_validate: bool = if (cb.getArg(1)) |sgc|
        try coerceToBool(sgc)
    else
        false;
    const sig_infcheck: bool = if (cb.getArg(2)) |v|
        try coerceToBool(v)
    else
        false;

    const sig_value = try env.newInstance(ctor, .{});
    const sig = try env.unwrap(Signature, sig_value);

    sig.* = Signature.deserialize(bytes_info.data[0..], sig_validate, sig_infcheck) catch return error.DeserializationFailed;

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
/// 4) pk_validate: ?bool
/// 5) sig_groupcheck: ?bool
pub fn blst_verify(env: napi.Env, cb: napi.CallbackInfo(5)) !napi.Value {
    const msg_info = try cb.arg(0).getTypedarrayInfo();
    const pk = try env.unwrap(PublicKey, cb.arg(1));
    const sig = try env.unwrap(Signature, cb.arg(2));
    const sig_groupcheck: bool = if (cb.getArg(3)) |sgc|
        try coerceToBool(sgc)
    else
        false;
    const pk_validate: bool = if (cb.getArg(4)) |v|
        try coerceToBool(v)
    else
        false;

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
pub fn SecretKey_fromKeygen(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const ctor = cb.this();
    const bytes_info = try cb.arg(0).getTypedarrayInfo();

    const key_info_data: ?[]const u8 = if (cb.getArg(1)) |ki| blk: {
        const typeof = try ki.typeof();
        if (typeof == .undefined or typeof == .null) break :blk null;
        const info = try ki.getTypedarrayInfo();
        if (info.array_type != .uint8) return error.InvalidArgument;
        break :blk info.data;
    } else null;

    if (bytes_info.data.len < 32) return error.InvalidSeedLength;

    const sk_value = try env.newInstance(ctor, .{});
    const sk = try env.unwrap(SecretKey, sk_value);
    sk.* = SecretKey.keyGen(bytes_info.data, key_info_data) catch return error.KeyGenFailed;

    return sk_value;
}

/// Signs a message with this `SecretKey`, returns a `Signature`.
pub fn SecretKey_sign(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sk = try env.unwrap(SecretKey, cb.this());
    const msg = try cb.arg(0).getTypedarrayInfo();

    const sig_value = try newSignatureInstance(env);
    const sig = try env.unwrap(Signature, sig_value);
    sig.* = sk.sign(msg.data, DST, null);

    return sig_value;
}

/// Derives the PublicKey from this SecretKey.
pub fn SecretKey_toPublicKey(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const sk = try env.unwrap(SecretKey, cb.this());

    const pk_value = try newPublicKeyInstance(env);
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
    const sigs_groupcheck = try coerceToBool(cb.arg(1));

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
pub fn Signature_validate(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sig = try env.unwrap(Signature, cb.this());
    const sig_infcheck = try coerceToBool(cb.arg(0));

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
pub fn blst_fastAggregateVerify(env: napi.Env, cb: napi.CallbackInfo(4)) !napi.Value {
    const msg_info = try cb.arg(0).getTypedarrayInfo();
    if (msg_info.data.len != 32) return error.InvalidMessageLength;

    const pks_array = cb.arg(1);
    const sig = try env.unwrap(Signature, cb.arg(2));
    const sig_groupcheck = try coerceToBool(cb.arg(3));

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
    // `pks_validate` is always false here since we assume proof of possession for public keys.
    const result = sig.fastAggregateVerify(sig_groupcheck, &pairing_buf, msg_info.data[0..32], DST, pks, false) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(result);
}

/// Batch verify multiple signature sets.
/// Returns `false` if verification fails.
///
/// Arguments:
/// 1) sets: Array of { msg: Uint8Array, pk: PublicKey, sig: Signature }
/// 2) sigs_groupcheck: ?bool
/// 3) pks_validate: ?bool
pub fn blst_verifyMultipleAggregateSignatures(env: napi.Env, cb: napi.CallbackInfo(3)) !napi.Value {
    const sets = cb.arg(0);
    const n_elems = try sets.getArrayLength();

    const sigs_groupcheck: bool = if (cb.getArg(1)) |sgc|
        try coerceToBool(sgc)
    else
        false;
    const pks_validate: bool = if (cb.getArg(2)) |v|
        try coerceToBool(v)
    else
        false;

    if (n_elems == 0) {
        return try env.getBoolean(false);
    }

    const msgs = try allocator.alloc([32]u8, n_elems);
    defer allocator.free(msgs);

    const pks = try allocator.alloc(*PublicKey, n_elems);
    defer allocator.free(pks);

    const sigs = try allocator.alloc(*Signature, n_elems);
    defer allocator.free(sigs);

    const rands = try allocator.alloc([32]u8, n_elems);
    defer allocator.free(rands);

    var prng = std.Random.DefaultPrng.init(std.crypto.random.int(u64));
    const rand = prng.random();

    for (0..n_elems) |i| {
        const set_value = try sets.getElement(@intCast(i));

        const msg_value = try set_value.getNamedProperty("msg");
        const msg = try msg_value.getTypedarrayInfo();
        if (msg.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg.data[0..32]);

        // Use unwrapped pointers directly - no copy needed
        const pk_value = try set_value.getNamedProperty("pk");
        pks[i] = try env.unwrap(PublicKey, pk_value);

        const sig_value = try set_value.getNamedProperty("sig");
        sigs[i] = try env.unwrap(Signature, sig_value);

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
/// 2) sigs_groupcheck: ?bool
pub fn blst_aggregateSignatures(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const sigs_array = cb.arg(0);

    const sigs_groupcheck: bool = if (cb.getArg(1)) |sgc|
        try coerceToBool(sgc)
    else
        false;

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

    const sig_value = try newSignatureInstance(env);
    const sig = try env.unwrap(Signature, sig_value);
    sig.* = result_sig;

    return sig_value;
}

/// Aggregate multiple `PublicKey` objects into one.
///
/// Arguments:
/// 1) pks: PublicKey[]
/// 2) pks_validate: ?bool
pub fn blst_aggregatePublicKeys(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const pks_array = cb.arg(0);
    const pks_len = try pks_array.getArrayLength();

    const pks_validate: bool = if (cb.getArg(1)) |v|
        try coerceToBool(v)
    else
        false;

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

    const pk_value = try newPublicKeyInstance(env);
    const pk = try env.unwrap(PublicKey, pk_value);
    pk.* = result_pk;

    return pk_value;
}

/// Aggregate public keys from serialized bytes.
///
/// Arguments:
/// 1) serializedPublicKeys: Uint8Array[] - array of serialized (96-bytes each) `PublicKey`s.
pub fn blst_aggregateSerializedPublicKeys(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const pks_array = cb.arg(0);
    const pks_len = try pks_array.getArrayLength();
    const pks_validate = try coerceToBool(cb.arg(1));

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

    const pk_value = try newPublicKeyInstance(env);
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
        method(2, SecretKey_fromKeygen),
    });

    const pk_ctor = try env.defineClass(
        "PublicKey",
        0,
        PublicKey_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            method(0, PublicKey_toBytes),
            method(0, PublicKey_toBytesCompress),
            method(0, PublicKey_validate),
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
            method(1, Signature_validate),
        },
    );
    try sig_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{
        method(1, Signature_fromBytes),
        method(1, Signature_aggregate),
    });

    try setRef(env, pk_ctor, &public_key_ctor_ref);
    try setRef(env, sig_ctor, &signature_ctor_ref);

    try blst_obj.setNamedProperty("SecretKey", sk_ctor);
    try blst_obj.setNamedProperty("PublicKey", pk_ctor);
    try blst_obj.setNamedProperty("Signature", sig_ctor);

    try blst_obj.setNamedProperty("verify", try env.createFunction("verify", 5, blst_verify, null));
    try blst_obj.setNamedProperty("fastAggregateVerify", try env.createFunction("fastAggregateVerify", 4, blst_fastAggregateVerify, null));
    try blst_obj.setNamedProperty("verifyMultipleAggregateSignatures", try env.createFunction("verifyMultipleAggregateSignatures", 3, blst_verifyMultipleAggregateSignatures, null));
    try blst_obj.setNamedProperty("aggregateSignatures", try env.createFunction("aggregateSignatures", 2, blst_aggregateSignatures, null));
    try blst_obj.setNamedProperty("aggregatePublicKeys", try env.createFunction("aggregatePublicKeys", 2, blst_aggregatePublicKeys, null));
    try blst_obj.setNamedProperty("aggregateSerializedPublicKeys", try env.createFunction("aggregateSerializedPublicKeys", 2, blst_aggregateSerializedPublicKeys, null));

    try exports.setNamedProperty("blst", blst_obj);
}
