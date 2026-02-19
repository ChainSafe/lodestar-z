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

/// Per-context (per-thread) instance data for constructor references
const InstanceData = struct {
    public_key_ctor_ref: ?napi.c.napi_ref = null,
    signature_ctor_ref: ?napi.c.napi_ref = null,

    fn init(env: napi.Env) !*InstanceData {
        const self = try allocator.create(InstanceData);
        errdefer allocator.destroy(self);

        self.* = .{};
        try napi.status.check(napi.c.napi_set_instance_data(
            env.env,
            @ptrCast(self),
            InstanceData.finalize,
            null,
        ));
        return self;
    }

    fn finalize(env: napi.c.napi_env, data: ?*anyopaque, _: ?*anyopaque) callconv(.C) void {
        const self: *InstanceData = @ptrCast(@alignCast(data orelse return));
        self.clearRefs(env);
        allocator.destroy(self);
    }

    fn get(env: napi.Env) !*InstanceData {
        var raw: ?*anyopaque = null;
        try napi.status.check(napi.c.napi_get_instance_data(env.env, &raw));
        return @ptrCast(@alignCast(raw orelse return error.InstanceDataNotInitialized));
    }

    fn clearRefs(self: *InstanceData, env: napi.c.napi_env) void {
        if (self.public_key_ctor_ref) |ref| {
            napi.status.check(napi.c.napi_delete_reference(env, ref)) catch {};
            self.public_key_ctor_ref = null;
        }
        if (self.signature_ctor_ref) |ref| {
            napi.status.check(napi.c.napi_delete_reference(env, ref)) catch {};
            self.signature_ctor_ref = null;
        }
    }
};

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
    const state = try InstanceData.get(env);
    const ctor = try getFromRef(env, state.public_key_ctor_ref);
    return try env.newInstance(ctor, .{});
}

pub fn newSignatureInstance(env: napi.Env) !napi.Value {
    const state = try InstanceData.get(env);
    const ctor = try getFromRef(env, state.signature_ctor_ref);
    return try env.newInstance(ctor, .{});
}

fn coerceToBool(boolish: napi.Value) napi.status.NapiError!bool {
    const b = try boolish.coerceToBool();
    return b.getValueBool();
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
/// 1) bytes: Uint8Array
/// 2) pk_validate: ?bool
pub fn PublicKey_fromBytes(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const ctor = cb.this();
    const bytes_info = try cb.arg(0).getTypedarrayInfo();
    const pk_validate: bool = if (cb.getArg(1)) |sgc|
        try coerceToBool(sgc)
    else
        false;

    const pk_value = try env.newInstance(ctor, .{});
    const pk = try env.unwrap(PublicKey, pk_value);

    pk.* = try PublicKey.deserialize(bytes_info.data[0..]);

    if (pk_validate) {
        try pk.validate();
    }

    return pk_value;
}

/// Converts given array of bytes to a `PublicKey`.
pub fn PublicKey_validate(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const pk = try env.unwrap(PublicKey, cb.this());
    try pk.validate();

    return try env.getUndefined();
}

/// Serializes this public key to bytes.
pub fn PublicKey_toBytes(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const pk = try env.unwrap(PublicKey, cb.this());
    const compress = try if (cb.getArg(0)) |c| coerceToBool(c) else true;

    if (compress) {
        const bytes = pk.compress();

        var arraybuffer_bytes: [*]u8 = undefined;
        const arraybuffer = try env.createArrayBuffer(PublicKey.COMPRESS_SIZE, &arraybuffer_bytes);
        @memcpy(arraybuffer_bytes[0..PublicKey.COMPRESS_SIZE], &bytes);
        return try env.createTypedarray(.uint8, PublicKey.COMPRESS_SIZE, arraybuffer, 0);
    } else {
        const bytes = pk.serialize();

        var arraybuffer_bytes: [*]u8 = undefined;
        const arraybuffer = try env.createArrayBuffer(PublicKey.SERIALIZE_SIZE, &arraybuffer_bytes);
        @memcpy(arraybuffer_bytes[0..PublicKey.SERIALIZE_SIZE], &bytes);
        return try env.createTypedarray(.uint8, PublicKey.SERIALIZE_SIZE, arraybuffer, 0);
    }
}

pub fn PublicKey_toHex(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const pk = try env.unwrap(PublicKey, cb.this());
    const compress = try if (cb.getArg(0)) |c| coerceToBool(c) else true;

    if (compress) {
        const bytes = pk.compress();

        const hex = try std.fmt.allocPrint(allocator, "0x{x}", .{std.fmt.fmtSliceHexLower(&bytes)});
        defer allocator.free(hex);

        return try env.createStringUtf8(hex);
    } else {
        const bytes = pk.serialize();

        const hex = try std.fmt.allocPrint(allocator, "0x{x}", .{std.fmt.fmtSliceHexLower(&bytes)});
        defer allocator.free(hex);

        return try env.createStringUtf8(hex);
    }
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

    sig.* = Signature.deserialize(bytes_info.data[0..]) catch return error.DeserializationFailed;

    if (sig_validate) {
        try sig.validate(sig_infcheck);
    }

    return sig_value;
}

/// Serializes this signature to bytes.
pub fn Signature_toBytes(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sig = try env.unwrap(Signature, cb.this());
    const compress = try if (cb.getArg(0)) |c| coerceToBool(c) else true;

    if (compress) {
        const bytes = sig.compress();

        var arraybuffer_bytes: [*]u8 = undefined;
        const arraybuffer = try env.createArrayBuffer(Signature.COMPRESS_SIZE, &arraybuffer_bytes);
        @memcpy(arraybuffer_bytes[0..Signature.COMPRESS_SIZE], &bytes);
        return try env.createTypedarray(.uint8, Signature.COMPRESS_SIZE, arraybuffer, 0);
    } else {
        const bytes = sig.serialize();

        var arraybuffer_bytes: [*]u8 = undefined;
        const arraybuffer = try env.createArrayBuffer(Signature.SERIALIZE_SIZE, &arraybuffer_bytes);
        @memcpy(arraybuffer_bytes[0..Signature.SERIALIZE_SIZE], &bytes);
        return try env.createTypedarray(.uint8, Signature.SERIALIZE_SIZE, arraybuffer, 0);
    }
}

pub fn Signature_toHex(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sig = try env.unwrap(Signature, cb.this());
    const compress = try if (cb.getArg(0)) |c| coerceToBool(c) else true;

    if (compress) {
        const bytes = sig.compress();

        const hex = try std.fmt.allocPrint(allocator, "0x{x}", .{std.fmt.fmtSliceHexLower(&bytes)});
        defer allocator.free(hex);

        return try env.createStringUtf8(hex);
    } else {
        const bytes = sig.serialize();

        const hex = try std.fmt.allocPrint(allocator, "0x{x}", .{std.fmt.fmtSliceHexLower(&bytes)});
        defer allocator.free(hex);

        return try env.createStringUtf8(hex);
    }
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

pub fn SecretKey_toHex(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const sk = try env.unwrap(SecretKey, cb.this());
    const bytes = sk.serialize();

    const hex = try std.fmt.allocPrint(allocator, "0x{x}", .{std.fmt.fmtSliceHexLower(&bytes)});
    defer allocator.free(hex);

    return try env.createStringUtf8(hex);
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
    const pk_validate: bool = if (cb.getArg(3)) |sgc|
        try coerceToBool(sgc)
    else
        false;
    const sig_groupcheck: bool = if (cb.getArg(4)) |v|
        try coerceToBool(v)
    else
        false;

    sig.verify(sig_groupcheck, msg_info.data, DST, null, pk, pk_validate) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(true);
}

/// Verify an aggregated signature against multiple messages and multiple public keys.
/// 1) msgs: Uint8Array[]
/// 2) pks: PublicKey[]
/// 3) sig: Signature
/// 4) pks_validate: ?bool
/// 5) sig_groupcheck: ?bool
pub fn blst_aggregateVerify(
    env: napi.Env,
    cb: napi.CallbackInfo(5),
) !napi.Value {
    const msgs_array = cb.arg(0);
    const pks_array = cb.arg(1);
    const sig = try env.unwrap(Signature, cb.arg(2));
    const pks_validate: bool = if (cb.getArg(3)) |sgc|
        try coerceToBool(sgc)
    else
        false;
    const sig_groupcheck: bool = if (cb.getArg(4)) |v|
        try coerceToBool(v)
    else
        false;

    const msgs_len = try msgs_array.getArrayLength();
    const pks_len = try pks_array.getArrayLength();
    if (msgs_len == 0 or pks_len == 0 or msgs_len != pks_len) {
        return error.InvalidAggregateVerifyInput;
    }

    const msgs = try allocator.alloc([32]u8, msgs_len);
    defer allocator.free(msgs);
    const pks = try allocator.alloc(PublicKey, pks_len);
    defer allocator.free(pks);

    for (0..msgs_len) |i| {
        const msg_value = try msgs_array.getElement(@intCast(i));
        const msg_info = try msg_value.getTypedarrayInfo();
        if (msg_info.data.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_info.data[0..32]);

        const pk_value = try pks_array.getElement(@intCast(i));
        const pk = try env.unwrap(PublicKey, pk_value);
        pks[i] = pk.*;
    }

    var pairing_buf: [Pairing.sizeOf()]u8 = undefined;

    const result = sig.aggregateVerify(
        sig_groupcheck,
        &pairing_buf,
        msgs,
        DST,
        pks,
        pks_validate,
    ) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(result);
}

/// Aggregate and verify an array of `PublicKey`s. Returns `false` if pks array is empty or if signature is invalid.
///
/// `msg` (signing root) must be exactly 32 bytes.
///
/// Arguments:
/// 1) msg: Uint8Array
/// 2) pks: PublicKey[]
/// 3) sig: Signature
/// 4) sigs_groupcheck: ?bool
pub fn blst_fastAggregateVerify(env: napi.Env, cb: napi.CallbackInfo(4)) !napi.Value {
    const msg_info = try cb.arg(0).getTypedarrayInfo();
    if (msg_info.data.len != 32) return error.InvalidMessageLength;

    const pks_array = cb.arg(1);
    const sig = try env.unwrap(Signature, cb.arg(2));
    const sigs_groupcheck = if (cb.getArg(3)) |sgc|
        try coerceToBool(sgc)
    else
        false;

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
    const result = sig.fastAggregateVerify(sigs_groupcheck, &pairing_buf, msg_info.data[0..32], DST, pks, false) catch {
        return try env.getBoolean(false);
    };

    return try env.getBoolean(result);
}

/// Batch verify multiple signature sets.
/// Returns `false` if verification fails.
///
/// Arguments:
/// 1) sets: Array of { msg: Uint8Array, pk: PublicKey, sig: Signature }
/// 2) pks_validate: ?bool
/// 3) sigs_groupcheck: ?bool
pub fn blst_verifyMultipleAggregateSignatures(env: napi.Env, cb: napi.CallbackInfo(3)) !napi.Value {
    const sets = cb.arg(0);
    const n_elems = try sets.getArrayLength();

    const pks_validate: bool = if (cb.getArg(1)) |v|
        try coerceToBool(v)
    else
        false;
    const sigs_groupcheck: bool = if (cb.getArg(2)) |sgc|
        try coerceToBool(sgc)
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
    const pks_validate: bool = if (cb.getArg(1)) |v|
        try coerceToBool(v)
    else
        false;

    if (pks_len == 0) return error.EmptyPublicKeyArray;

    const pks = try allocator.alloc(PublicKey, pks_len);
    defer allocator.free(pks);

    for (0..pks_len) |i| {
        const pk_bytes_value = try pks_array.getElement(@intCast(i));
        const bytes_info = try pk_bytes_value.getTypedarrayInfo();

        pks[i] = PublicKey.deserialize(bytes_info.data) catch
            return error.DeserializationFailed;
    }

    const agg_pk = AggregatePublicKey.aggregate(pks, pks_validate) catch return error.AggregationFailed;
    const result_pk = agg_pk.toPublicKey();

    const pk_value = try newPublicKeyInstance(env);
    const pk = try env.unwrap(PublicKey, pk_value);
    pk.* = result_pk;

    return pk_value;
}

const MAX_AGGREGATE_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;

const AsyncAggregateData = struct {
    // Inputs (copied on main thread, freed in complete)
    pks: []PublicKey,
    sigs: []Signature,
    n: usize,

    // Outputs (set in execute)
    result_pk: PublicKey = .{},
    result_sig: Signature = .{},
    err: bool = false,

    // NAPI handles
    deferred: napi.Deferred,
    work: napi.AsyncWork(AsyncAggregateData) = undefined,
};

fn asyncAggregateExecute(_: napi.Env, data: *AsyncAggregateData) void {
    const n = data.n;

    // Generate 32 bytes of randomness per element, 64 meaningful bits (nbits=64)
    var rands: [32 * MAX_AGGREGATE_PER_JOB]u8 = undefined;
    std.crypto.random.bytes(rands[0 .. n * 32]);

    // Build pointer arrays (stack-allocated, MAX_AGGREGATE_PER_JOB is 128)
    var pk_refs: [MAX_AGGREGATE_PER_JOB]*const PublicKey = undefined;
    var sig_refs: [MAX_AGGREGATE_PER_JOB]*const Signature = undefined;
    for (0..n) |i| {
        pk_refs[i] = &data.pks[i];
        sig_refs[i] = &data.sigs[i];
    }

    // Per-call scratch allocation (safe for worker threads)
    const p1_scratch_size = blst.c.blst_p1s_mult_pippenger_scratch_sizeof(n);
    const p2_scratch_size = blst.c.blst_p2s_mult_pippenger_scratch_sizeof(n);
    const scratch_size = @max(p1_scratch_size, p2_scratch_size);
    const scratch = allocator.alloc(u64, scratch_size) catch {
        data.err = true;
        return;
    };
    defer allocator.free(scratch);

    // Pippenger multi-scalar multiplication on G1 (pubkeys)
    const agg_pk = AggregatePublicKey.aggregateWithRandomness(
        pk_refs[0..n],
        rands[0 .. n * 32],
        false, // already validated
        scratch,
    ) catch {
        data.err = true;
        return;
    };

    // Pippenger multi-scalar multiplication on G2 (signatures)
    const agg_sig = AggregateSignature.aggregateWithRandomness(
        sig_refs[0..n],
        rands[0 .. n * 32],
        false, // already validated during deserialization
        scratch,
    ) catch {
        data.err = true;
        return;
    };

    data.result_pk = agg_pk.toPublicKey();
    data.result_sig = agg_sig.toSignature();
}

fn asyncAggregateComplete(env: napi.Env, _: napi.status.Status, data: *AsyncAggregateData) void {
    defer {
        data.work.delete() catch {};
        allocator.free(data.pks);
        allocator.free(data.sigs);
        allocator.destroy(data);
    }

    if (data.err) {
        const msg = env.createStringUtf8("BLST_ERROR: Aggregation failed") catch return;
        data.deferred.reject(msg) catch return;
        return;
    }

    // Wrap results as NAPI PublicKey/Signature instances
    const pk_value = newPublicKeyInstance(env) catch return;
    const pk = env.unwrap(PublicKey, pk_value) catch return;
    pk.* = data.result_pk;

    const sig_value = newSignatureInstance(env) catch return;
    const sig = env.unwrap(Signature, sig_value) catch return;
    sig.* = data.result_sig;

    // Create {pk, sig} JS object and resolve promise
    const result = env.createObject() catch return;
    result.setNamedProperty("pk", pk_value) catch return;
    result.setNamedProperty("sig", sig_value) catch return;

    data.deferred.resolve(result) catch return;
}

/// Asynchronously aggregates public keys and signatures with randomness using
/// Pippenger multi-scalar multiplication. Heavy math runs on the libuv thread pool.
///
/// Arguments:
/// 1) sets: Array of {pk: PublicKey, sig: Uint8Array}
///
/// Returns: Promise<{pk: PublicKey, sig: Signature}>
pub fn blst_asyncAggregateWithRandomness(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const sets = cb.arg(0);
    const n = try sets.getArrayLength();

    if (n == 0) return error.EmptyArray;
    // Max set size enforced at MAX_AGGREGATE_PER_JOB (128) to match blst-z internal limits
    if (n > MAX_AGGREGATE_PER_JOB) return error.TooManySets;

    const pks = try allocator.alloc(PublicKey, n);
    errdefer allocator.free(pks);

    const sigs = try allocator.alloc(Signature, n);
    errdefer allocator.free(sigs);

    for (0..n) |i| {
        const set_value = try sets.getElement(@intCast(i));

        // Unwrap PublicKey (already validated when created via fromBytes)
        const pk_value = try set_value.getNamedProperty("pk");
        const unwrapped_pk = try env.unwrap(PublicKey, pk_value);
        pks[i] = unwrapped_pk.*;

        // Deserialize signature from Uint8Array with validation (infinity + group check),
        // matching blst-ts Rust behavior
        const sig_value = try set_value.getNamedProperty("sig");
        const sig_bytes = try sig_value.getTypedarrayInfo();
        sigs[i] = Signature.deserialize(sig_bytes.data[0..]) catch return error.DeserializationFailed;
        sigs[i].validate(true) catch return error.InvalidSignature;
    }

    const data = try allocator.create(AsyncAggregateData);
    errdefer allocator.destroy(data);

    data.* = .{
        .pks = pks,
        .sigs = sigs,
        .n = n,
        .deferred = try napi.Deferred.create(env.env),
    };

    const resource_name = try env.createStringUtf8("asyncAggregateWithRandomness");
    data.work = try napi.AsyncWork(AsyncAggregateData).create(
        env,
        null,
        resource_name,
        asyncAggregateExecute,
        asyncAggregateComplete,
        data,
    );
    try data.work.queue();

    return data.deferred.getPromise();
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
            method(0, SecretKey_toHex),
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
            method(1, PublicKey_toBytes),
            method(1, PublicKey_toHex),
            method(0, PublicKey_validate),
        },
    );
    try pk_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{
        method(2, PublicKey_fromBytes),
    });

    const sig_ctor = try env.defineClass(
        "Signature",
        0,
        Signature_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            method(1, Signature_toBytes),
            method(1, Signature_toHex),
            method(1, Signature_validate),
        },
    );
    try sig_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{
        method(3, Signature_fromBytes),
        method(1, Signature_aggregate),
    });

    const state = try InstanceData.init(env);
    try setRef(env, pk_ctor, &state.public_key_ctor_ref);
    try setRef(env, sig_ctor, &state.signature_ctor_ref);

    try blst_obj.setNamedProperty("SecretKey", sk_ctor);
    try blst_obj.setNamedProperty("PublicKey", pk_ctor);
    try blst_obj.setNamedProperty("Signature", sig_ctor);

    try blst_obj.setNamedProperty("verify", try env.createFunction("verify", 5, blst_verify, null));
    try blst_obj.setNamedProperty("aggregateVerify", try env.createFunction("aggregateVerify", 5, blst_aggregateVerify, null));
    try blst_obj.setNamedProperty("fastAggregateVerify", try env.createFunction("fastAggregateVerify", 4, blst_fastAggregateVerify, null));
    try blst_obj.setNamedProperty("verifyMultipleAggregateSignatures", try env.createFunction("verifyMultipleAggregateSignatures", 3, blst_verifyMultipleAggregateSignatures, null));
    try blst_obj.setNamedProperty("aggregateSignatures", try env.createFunction("aggregateSignatures", 2, blst_aggregateSignatures, null));
    try blst_obj.setNamedProperty("aggregatePublicKeys", try env.createFunction("aggregatePublicKeys", 2, blst_aggregatePublicKeys, null));
    try blst_obj.setNamedProperty("aggregateSerializedPublicKeys", try env.createFunction("aggregateSerializedPublicKeys", 2, blst_aggregateSerializedPublicKeys, null));
    try blst_obj.setNamedProperty("asyncAggregateWithRandomness", try env.createFunction("asyncAggregateWithRandomness", 1, blst_asyncAggregateWithRandomness, null));

    try exports.setNamedProperty("blst", blst_obj);
}
