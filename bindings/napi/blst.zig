//! Contains the necessary bindings for blst operations in lodestar-ts.
//!
//! Note that this set of bindings is not feature complete; it only implements what
//! lodestar-ts uses in production. `blst.SecretKey` for example has no bindings.
const std = @import("std");
const napi = @import("zapi:napi");
const blst = @import("blst");
const builtin = @import("builtin");

const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const Pairing = blst.Pairing;
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

    if (bytes_info.data.len == PublicKey.COMPRESS_SIZE) {
        pk.* = try PublicKey.uncompress(bytes_info.data[0..PublicKey.COMPRESS_SIZE]);
    } else if (bytes_info.data.len == PublicKey.SERIALIZE_SIZE) {
        pk.* = try PublicKey.deserialize(bytes_info.data[0..PublicKey.SERIALIZE_SIZE]);
    } else {
        return error.InvalidPublicKeyLength;
    }

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

    if (bytes_info.data.len == Signature.COMPRESS_SIZE) {
        sig.* = Signature.uncompress(bytes_info.data[0..Signature.COMPRESS_SIZE]) catch return error.DeserializationFailed;
    } else if (bytes_info.data.len == Signature.SERIALIZE_SIZE) {
        sig.* = Signature.deserialize(bytes_info.data[0..Signature.SERIALIZE_SIZE]) catch return error.DeserializationFailed;
    } else {
        return error.InvalidSignatureLength;
    }

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

/// Arguments:
/// 1) msg: Uint8Array
/// 2) pk: PublicKey
/// 3) sig: Signature
///
/// Returns `true` if signature is valid, `false` otherwise.
pub fn blst_verify(env: napi.Env, cb: napi.CallbackInfo(3)) !napi.Value {
    const msg_info = try cb.arg(0).getTypedarrayInfo();
    const pk = try env.unwrap(PublicKey, cb.arg(1));
    const sig = try env.unwrap(Signature, cb.arg(2));

    sig.verify(false, msg_info.data, DST, null, pk, false) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(true);
}

/// Arguments:
/// 1) msg: Uint8Array
/// 2) pks: PublicKey[]
/// 3) sig: Signature
///
/// `msg` (signing root) must be exactly 32 bytes.
///
/// Returns `false` if pks array is empty or if signature is invalid.
pub fn blst_fastAggregateVerify(env: napi.Env, cb: napi.CallbackInfo(3)) !napi.Value {
    const msg_info = try cb.arg(0).getTypedarrayInfo();
    if (msg_info.data.len != 32) return error.InvalidMessageLength;

    const pks_array = cb.arg(1);
    const sig = try env.unwrap(Signature, cb.arg(2));

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
    const result = sig.fastAggregateVerify(false, &pairing_buf, msg_info.data[0..32], DST, pks, false) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(result);
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const blst_obj = try env.createObject();

    const pk_ctor = try env.defineClass(
        "PublicKey",
        0,
        PublicKey_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            .{ .utf8name = "toBytes", .method = napi.wrapCallback(0, PublicKey_toBytes) },
            .{ .utf8name = "toBytesCompress", .method = napi.wrapCallback(0, PublicKey_toBytesCompress) },
        },
    );
    try pk_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{.{
        .utf8name = "fromBytes",
        .method = napi.wrapCallback(1, PublicKey_fromBytes),
    }});

    const sig_ctor = try env.defineClass(
        "Signature",
        0,
        Signature_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            .{ .utf8name = "toBytes", .method = napi.wrapCallback(0, Signature_toBytes) },
            .{ .utf8name = "toBytesCompress", .method = napi.wrapCallback(0, Signature_toBytesCompress) },
        },
    );
    try sig_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{.{
        .utf8name = "fromBytes",
        .method = napi.wrapCallback(1, Signature_fromBytes),
    }});

    try blst_obj.setNamedProperty("PublicKey", pk_ctor);
    try blst_obj.setNamedProperty("Signature", sig_ctor);
    try blst_obj.setNamedProperty("verify", try env.createFunction("verify", 3, blst_verify, null));
    try blst_obj.setNamedProperty("fastAggregateVerify", try env.createFunction("fastAggregateVerify", 3, blst_fastAggregateVerify, null));

    try exports.setNamedProperty("blst", blst_obj);

    const global = try env.getGlobal();
    try global.setNamedProperty("blst", blst_obj);
}
