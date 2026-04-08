//! Contains the necessary bindings for blst operations in lodestar-ts.
const std = @import("std");
const zapi = @import("zapi");
const js = zapi.js;
const napi = zapi.napi;
const bls = @import("bls");
const builtin = @import("builtin");

const NativePublicKey = bls.PublicKey;
const NativeSignature = bls.Signature;
const NativeSecretKey = bls.SecretKey;
const Pairing = bls.Pairing;
const AggregatePublicKey = bls.AggregatePublicKey;
const AggregateSignature = bls.AggregateSignature;
const DST = bls.DST;

const VerifySet = struct {
    msg: js.Value,
    pk: js.Value,
    sig: js.Value,
};

const AsyncAggregateSet = struct {
    pk: js.Value,
    sig: js.Value,
};

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

fn formatHex(bytes: []const u8, buf: []u8) !js.String {
    const written = try std.fmt.bufPrint(buf, "0x{x}", .{std.fmt.fmtSliceHexLower(bytes)});
    return js.String.from(written);
}

fn unwrapClass(comptime T: type, value: js.Value) !*T {
    return js.env().unwrap(T, value.toValue());
}

pub const PublicKey = struct {
    pub const js_meta = js.class(.{});

    raw: NativePublicKey = .{},

    pub fn init() PublicKey {
        return .{};
    }

    pub fn fromBytes(bytes: js.Uint8Array, pk_validate: ?js.Boolean) !PublicKey {
        const slice = try bytes.toSlice();
        var pk = try NativePublicKey.deserialize(slice);
        if (boolOrDefault(pk_validate, false)) {
            try pk.validate();
        }
        return .{ .raw = pk };
    }

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

    pub fn validate(self: *const PublicKey) !void {
        try self.raw.validate();
    }

    pub fn toBytes(self: *const PublicKey, compress: ?js.Boolean) js.Uint8Array {
        if (boolOrDefault(compress, true)) {
            const bytes = self.raw.compress();
            return js.Uint8Array.from(bytes[0..]);
        }

        const bytes = self.raw.serialize();
        return js.Uint8Array.from(bytes[0..]);
    }

    pub fn toHex(self: *const PublicKey, compress: ?js.Boolean) !js.String {
        var hex_buf: [NativePublicKey.SERIALIZE_SIZE * 2 + 2]u8 = undefined;
        if (boolOrDefault(compress, true)) {
            const bytes = self.raw.compress();
            return formatHex(bytes[0..], &hex_buf);
        }

        const bytes = self.raw.serialize();
        return formatHex(bytes[0..], &hex_buf);
    }
};

pub const Signature = struct {
    pub const js_meta = js.class(.{});

    raw: NativeSignature = .{},

    pub fn init() Signature {
        return .{};
    }

    pub fn fromBytes(bytes: js.Uint8Array, sig_validate: ?js.Boolean, sig_infcheck: ?js.Boolean) !Signature {
        const slice = try bytes.toSlice();
        var sig = NativeSignature.deserialize(slice) catch return error.DeserializationFailed;

        if (boolOrDefault(sig_validate, false)) {
            try sig.validate(boolOrDefault(sig_infcheck, false));
        }

        return .{ .raw = sig };
    }

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

    pub fn aggregate(signatures: js.Array, sigs_groupcheck: ?js.Boolean) !Signature {
        const signatures_len = try signatures.length();
        if (signatures_len == 0) return error.EmptySignatureArray;

        const sigs = try allocator.alloc(NativeSignature, signatures_len);
        defer allocator.free(sigs);

        for (0..signatures_len) |i| {
            const wrapped = try unwrapClass(Signature, try signatures.get(@intCast(i)));
            sigs[i] = wrapped.raw;
        }

        const agg_sig = AggregateSignature.aggregate(sigs, boolOrDefault(sigs_groupcheck, false)) catch {
            return error.AggregationFailed;
        };
        return .{ .raw = agg_sig.toSignature() };
    }

    pub fn toBytes(self: *const Signature, compress: ?js.Boolean) js.Uint8Array {
        if (boolOrDefault(compress, true)) {
            const bytes = self.raw.compress();
            return js.Uint8Array.from(bytes[0..]);
        }

        const bytes = self.raw.serialize();
        return js.Uint8Array.from(bytes[0..]);
    }

    pub fn toHex(self: *const Signature, compress: ?js.Boolean) !js.String {
        var hex_buf: [NativeSignature.SERIALIZE_SIZE * 2 + 2]u8 = undefined;
        if (boolOrDefault(compress, true)) {
            const bytes = self.raw.compress();
            return formatHex(bytes[0..], &hex_buf);
        }

        const bytes = self.raw.serialize();
        return formatHex(bytes[0..], &hex_buf);
    }

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

    pub fn fromBytes(bytes: js.Uint8Array) !SecretKey {
        const slice = try bytes.toSlice();
        if (slice.len != NativeSecretKey.serialize_size) {
            return error.InvalidSecretKeyLength;
        }

        const sk = NativeSecretKey.deserialize(slice[0..NativeSecretKey.serialize_size]) catch {
            return error.DeserializationFailed;
        };
        return .{ .raw = sk };
    }

    pub fn fromHex(hex_string: js.String) !SecretKey {
        var hex_buf: [NativeSecretKey.serialize_size * 2 + 3]u8 = undefined;
        const hex = try hexFromString(hex_string, &hex_buf);

        var bytes_buf: [NativeSecretKey.serialize_size]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&bytes_buf, hex);
        const sk = NativeSecretKey.deserialize(bytes[0..NativeSecretKey.serialize_size]) catch {
            return error.DeserializationFailed;
        };
        return .{ .raw = sk };
    }

    pub fn fromKeygen(seed: js.Uint8Array, key_info: ?js.Value) !SecretKey {
        const seed_slice = try seed.toSlice();
        if (seed_slice.len < 32) return error.InvalidSeedLength;

        const key_info_slice: ?[]const u8 = if (key_info) |value| blk: {
            if (value.isUndefined() or value.isNull()) break :blk null;
            const typed = try value.asUint8Array();
            break :blk try typed.toSlice();
        } else null;

        const sk = NativeSecretKey.keyGen(seed_slice, key_info_slice) catch return error.KeyGenFailed;
        return .{ .raw = sk };
    }

    pub fn sign(self: *const SecretKey, msg: js.Uint8Array) !Signature {
        const slice = try msg.toSlice();
        return .{ .raw = self.raw.sign(slice, DST, null) };
    }

    pub fn toPublicKey(self: *const SecretKey) !PublicKey {
        return .{ .raw = self.raw.toPublicKey() };
    }

    pub fn toBytes(self: *const SecretKey) js.Uint8Array {
        const bytes = self.raw.serialize();
        return js.Uint8Array.from(bytes[0..]);
    }

    pub fn toHex(self: *const SecretKey) !js.String {
        const bytes = self.raw.serialize();
        var hex_buf: [NativeSecretKey.serialize_size * 2 + 2]u8 = undefined;
        return formatHex(bytes[0..], &hex_buf);
    }
};

/// Verifies a given `msg` against a `Signature` and a `PublicKey`.
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

/// Verifies an aggregated signature against multiple messages and public keys.
pub fn aggregateVerify(msgs: js.Array, pks: js.Array, sig: Signature, pks_validate: ?js.Boolean, sig_groupcheck: ?js.Boolean) !js.Boolean {
    const msgs_len = try msgs.length();
    const pks_len = try pks.length();
    if (msgs_len == 0 or pks_len == 0 or msgs_len != pks_len) {
        return error.InvalidAggregateVerifyInput;
    }

    const msg_bufs = try allocator.alloc([32]u8, msgs_len);
    defer allocator.free(msg_bufs);

    const native_pks = try allocator.alloc(NativePublicKey, pks_len);
    defer allocator.free(native_pks);

    for (0..msgs_len) |i| {
        const msg_value = try msgs.get(@intCast(i));
        const msg_bytes = try (try msg_value.asUint8Array()).toSlice();
        if (msg_bytes.len != 32) return error.InvalidMessageLength;
        @memcpy(&msg_bufs[i], msg_bytes[0..32]);

        const wrapped_pk = try unwrapClass(PublicKey, try pks.get(@intCast(i)));
        native_pks[i] = wrapped_pk.raw;
    }

    var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
    const result = sig.raw.aggregateVerify(
        boolOrDefault(sig_groupcheck, false),
        &pairing_buf,
        msg_bufs,
        DST,
        native_pks,
        boolOrDefault(pks_validate, false),
    ) catch return js.Boolean.from(false);

    return js.Boolean.from(result);
}

/// Aggregates and verifies multiple public keys against one 32-byte message.
pub fn fastAggregateVerify(msg: js.Uint8Array, pks: js.Array, sig: Signature, sigs_groupcheck: ?js.Boolean) !js.Boolean {
    const msg_slice = try msg.toSlice();
    if (msg_slice.len != 32) return error.InvalidMessageLength;

    const pks_len = try pks.length();
    if (pks_len == 0) {
        return js.Boolean.from(false);
    }

    const native_pks = try allocator.alloc(NativePublicKey, pks_len);
    defer allocator.free(native_pks);

    for (0..pks_len) |i| {
        const wrapped_pk = try unwrapClass(PublicKey, try pks.get(@intCast(i)));
        native_pks[i] = wrapped_pk.raw;
    }

    var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
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

/// Batch verify multiple aggregate signature sets.
pub fn verifyMultipleAggregateSignatures(sets: js.Array, pks_validate: ?js.Boolean, sigs_groupcheck: ?js.Boolean) !js.Boolean {
    const n_elems = try sets.length();
    if (n_elems == 0) {
        return js.Boolean.from(false);
    }

    const msgs = try allocator.alloc([32]u8, n_elems);
    defer allocator.free(msgs);

    const pks = try allocator.alloc(*NativePublicKey, n_elems);
    defer allocator.free(pks);

    const sigs = try allocator.alloc(*NativeSignature, n_elems);
    defer allocator.free(sigs);

    const rands = try allocator.alloc([32]u8, n_elems);
    defer allocator.free(rands);

    var prng = std.Random.DefaultPrng.init(std.crypto.random.int(u64));
    const rand = prng.random();

    for (0..n_elems) |i| {
        const set_obj = try (try sets.get(@intCast(i))).asObject(VerifySet);
        const set = try set_obj.get();

        const msg_bytes = try (try set.msg.asUint8Array()).toSlice();
        if (msg_bytes.len != 32) return error.InvalidMessageLength;
        @memcpy(&msgs[i], msg_bytes[0..32]);

        const wrapped_pk = try unwrapClass(PublicKey, set.pk);
        pks[i] = &wrapped_pk.raw;

        const wrapped_sig = try unwrapClass(Signature, set.sig);
        sigs[i] = &wrapped_sig.raw;

        rand.bytes(&rands[i]);
    }

    var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
    const result = bls.verifyMultipleAggregateSignatures(
        &pairing_buf,
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

/// Aggregates multiple `Signature` objects into one.
pub fn aggregateSignatures(signatures: js.Array, sigs_groupcheck: ?js.Boolean) !Signature {
    const signatures_len = try signatures.length();
    if (signatures_len == 0) return error.EmptySignatureArray;

    const sigs = try allocator.alloc(NativeSignature, signatures_len);
    defer allocator.free(sigs);

    for (0..signatures_len) |i| {
        const wrapped = try unwrapClass(Signature, try signatures.get(@intCast(i)));
        sigs[i] = wrapped.raw;
    }

    const agg_sig = AggregateSignature.aggregate(sigs, boolOrDefault(sigs_groupcheck, false)) catch {
        return error.AggregationFailed;
    };

    return .{ .raw = agg_sig.toSignature() };
}

/// Aggregates multiple `PublicKey` objects into one.
pub fn aggregatePublicKeys(pks: js.Array, pks_validate: ?js.Boolean) !PublicKey {
    const pks_len = try pks.length();
    if (pks_len == 0) return error.EmptyPublicKeyArray;

    const native_pks = try allocator.alloc(NativePublicKey, pks_len);
    defer allocator.free(native_pks);

    for (0..pks_len) |i| {
        const wrapped = try unwrapClass(PublicKey, try pks.get(@intCast(i)));
        native_pks[i] = wrapped.raw;
    }

    const agg_pk = AggregatePublicKey.aggregate(native_pks, boolOrDefault(pks_validate, false)) catch {
        return error.AggregationFailed;
    };

    return .{ .raw = agg_pk.toPublicKey() };
}

/// Aggregates public keys from serialized bytes.
pub fn aggregateSerializedPublicKeys(serialized_public_keys: js.Array, pks_validate: ?js.Boolean) !PublicKey {
    const pks_len = try serialized_public_keys.length();
    if (pks_len == 0) return error.EmptyPublicKeyArray;

    const native_pks = try allocator.alloc(NativePublicKey, pks_len);
    defer allocator.free(native_pks);

    for (0..pks_len) |i| {
        const bytes = try (try (try serialized_public_keys.get(@intCast(i))).asUint8Array()).toSlice();
        native_pks[i] = NativePublicKey.deserialize(bytes) catch return error.DeserializationFailed;
    }

    const agg_pk = AggregatePublicKey.aggregate(native_pks, boolOrDefault(pks_validate, false)) catch {
        return error.AggregationFailed;
    };

    return .{ .raw = agg_pk.toPublicKey() };
}

/// Asynchronously aggregates public keys and signatures with randomness.
pub fn asyncAggregateWithRandomness(sets: js.Array) !js.Promise(js.Value) {
    const n = try sets.length();
    if (n == 0) return error.EmptyArray;
    if (n > MAX_AGGREGATE_PER_JOB) return error.TooManySets;

    const pks = try allocator.alloc(NativePublicKey, n);
    errdefer allocator.free(pks);

    const sigs = try allocator.alloc(NativeSignature, n);
    errdefer allocator.free(sigs);

    for (0..n) |i| {
        const set_obj = try (try sets.get(@intCast(i))).asObject(AsyncAggregateSet);
        const set = try set_obj.get();

        const wrapped_pk = try unwrapClass(PublicKey, set.pk);
        pks[i] = wrapped_pk.raw;

        const sig_bytes = try (try set.sig.asUint8Array()).toSlice();
        sigs[i] = NativeSignature.deserialize(sig_bytes[0..]) catch return error.DeserializationFailed;
        sigs[i].validate(true) catch return error.InvalidSignature;
    }

    const promise = try js.createPromise(js.Value);
    const data = try allocator.create(AsyncAggregateData);
    errdefer allocator.destroy(data);

    data.* = .{
        .pks = pks,
        .sigs = sigs,
        .n = n,
        .deferred = promise.deferred,
    };

    const resource_name = try js.env().createStringUtf8("asyncAggregateWithRandomness");
    data.work = try napi.AsyncWork(AsyncAggregateData).create(
        js.env(),
        null,
        resource_name,
        asyncAggregateExecute,
        asyncAggregateComplete,
        data,
    );
    try data.work.queue();

    return promise;
}

const MAX_AGGREGATE_PER_JOB = bls.MAX_AGGREGATE_PER_JOB;

const AsyncAggregateData = struct {
    pks: []NativePublicKey,
    sigs: []NativeSignature,
    n: usize,

    result_pk: NativePublicKey = .{},
    result_sig: NativeSignature = .{},
    err: bool = false,

    deferred: napi.Deferred,
    work: napi.AsyncWork(AsyncAggregateData) = undefined,
};

fn asyncAggregateExecute(_: napi.Env, data: *AsyncAggregateData) void {
    const n = data.n;

    var rands: [32 * MAX_AGGREGATE_PER_JOB]u8 = undefined;
    std.crypto.random.bytes(rands[0 .. n * 32]);

    var pk_refs: [MAX_AGGREGATE_PER_JOB]*const NativePublicKey = undefined;
    var sig_refs: [MAX_AGGREGATE_PER_JOB]*const NativeSignature = undefined;
    for (0..n) |i| {
        pk_refs[i] = &data.pks[i];
        sig_refs[i] = &data.sigs[i];
    }

    const p1_scratch_size = bls.c.blst_p1s_mult_pippenger_scratch_sizeof(n);
    const p2_scratch_size = bls.c.blst_p2s_mult_pippenger_scratch_sizeof(n);
    const scratch_size = @max(p1_scratch_size, p2_scratch_size);
    const scratch = allocator.alloc(u64, scratch_size) catch {
        data.err = true;
        return;
    };
    defer allocator.free(scratch);

    const agg_pk = AggregatePublicKey.aggregateWithRandomness(
        pk_refs[0..n],
        rands[0 .. n * 32],
        false,
        scratch,
    ) catch {
        data.err = true;
        return;
    };

    const agg_sig = AggregateSignature.aggregateWithRandomness(
        sig_refs[0..n],
        rands[0 .. n * 32],
        false,
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

    const pk_value = napi.Value{ .env = env.env, .value = js.convertReturn(PublicKey, .{ .raw = data.result_pk }, env.env) };
    const sig_value = napi.Value{ .env = env.env, .value = js.convertReturn(Signature, .{ .raw = data.result_sig }, env.env) };

    const result = env.createObject() catch return;
    result.setNamedProperty("pk", pk_value) catch return;
    result.setNamedProperty("sig", sig_value) catch return;

    data.deferred.resolve(result) catch return;
}
