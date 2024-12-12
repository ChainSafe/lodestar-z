/// this is equivalent of Rust binding in blst/bindings/rust/src/lib.rs
const std = @import("std");
const testing = std.testing;

const c = @cImport({
    @cInclude("blst.h");
});

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

/// TODO: the size of SecretKey is only 32 bytes so go with stack allocation
/// consider adding heap allocation with allocator in the future
const SecretKey = struct {
    value: c.blst_scalar,

    pub fn default() SecretKey {
        return .{
            .value = util.default_blst_scalar(),
        };
    }

    pub fn keyGen(ikm: []const u8, key_info: ?[]const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        const key_info_ptr = if (key_info != null) &key_info.?[0] else null;
        const key_info_len = if (key_info != null) key_info.?.len else 0;

        c.blst_keygen(&sk.value, &ikm[0], ikm.len, key_info_ptr, key_info_len);
        return sk;
    }

    pub fn keyGenV3(ikm: []const u8, key_info: ?[]const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        const key_info_ptr = if (key_info != null) &key_info.?[0] else null;
        const key_info_len = if (key_info != null) key_info.?.len else 0;

        c.blst_keygen_v3(&sk.value, &ikm[0], ikm.len, key_info_ptr, key_info_len);
        return sk;
    }

    pub fn keyGenV45(ikm: []const u8, salt: []const u8, info: ?[]const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        const info_ptr = if (info != null and info.?.len > 0) &info.?[0] else null;
        const info_len = if (info != null) info.?.len else 0;

        c.blst_keygen_v4_5(&sk.value, &ikm[0], ikm.len, &salt[0], salt.len, info_ptr, info_len);
        return sk;
    }

    pub fn keyGenV5(ikm: []const u8, salt: []const u8, info: ?[]const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        const info_ptr = if (info != null and info.?.len > 0) &info.?[0] else null;
        const info_len = if (info != null) info.?.len else 0;

        c.blst_keygen_v5(&sk.value, &ikm[0], ikm.len, &salt[0], salt.len, info_ptr, info_len);
        return sk;
    }

    pub fn deriveMasterEip2333(ikm: []const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        c.blst_derive_master_eip2333(&sk.value, &ikm[0], ikm.len);
        return sk;
    }

    pub fn deriveChildEip2333(self: *const SecretKey, child_index: u32) BLST_ERROR!SecretKey {
        var sk = SecretKey.default();
        c.blst_derive_child_eip2333(&sk.value, &self.value, child_index);
        return sk;
    }

    pub fn skToPk(self: *const SecretKey) PublicKey {
        var pk_aff = PublicKey.default();
        c.blst_sk_to_pk2_in_g1(null, &pk_aff.point, &self.value);
        return pk_aff;
    }

    // Sign
    pub fn sign(self: *const SecretKey, msg: []const u8, dst: []const u8, aug: ?[]const u8) Signature {
        // TODO - would the user like the serialized/compressed sig as well?
        var q = util.default_blst_p2();
        var sig_aff = Signature.default();
        const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
        const aug_len = if (aug != null) aug.?.len else 0;
        c.blst_hash_to_g2(&q, &msg[0], msg.len, &dst[0], dst.len, aug_ptr, aug_len);
        c.blst_sign_pk2_in_g1(null, &sig_aff.point, &q, &self.value);
        return sig_aff;
    }

    // TODO - formally speaking application is entitled to have
    // ultimate control over secret key storage, which means that
    // corresponding serialization/deserialization subroutines
    // should accept reference to where to store the result, as
    // opposite to returning one.

    // serialize
    pub fn serialize(self: *const SecretKey) [32]u8 {
        var sk_out = [_]u8{0} ** 32;
        c.blst_bendian_from_scalar(&sk_out[0], &self.value);
        return sk_out;
    }

    // deserialize
    pub fn deserialize(sk_in: []const u8) BLST_ERROR!SecretKey {
        var sk = SecretKey.default();
        if (sk_in.len != 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        c.blst_scalar_from_bendian(&sk.value, &sk_in[0]);
        if (!c.blst_sk_check(&sk.value)) {
            return BLST_ERROR.BAD_ENCODING;
        }

        return sk;
    }

    pub fn toBytes(self: *const SecretKey) [32]u8 {
        return self.serialize();
    }

    pub fn fromBytes(sk_in: []const u8) BLST_ERROR!SecretKey {
        return SecretKey.deserialize(sk_in);
    }
};

// TODO: implement Clone, Copy, Equal
const PublicKey = struct {
    point: c.blst_p1_affine,

    pub fn default() PublicKey {
        return .{
            .point = util.default_blst_p1_affline(),
        };
    }

    // Core operations

    // key_validate
    pub fn validate(self: *const PublicKey) BLST_ERROR!void {
        if (c.blst_p1_affine_is_inf(&self.point)) {
            return BLST_ERROR.PK_IS_INFINITY;
        }

        if (c.blst_p1_affine_in_g1(&self.point) == false) {
            return BLST_ERROR.POINT_NOT_IN_GROUP;
        }
    }

    pub fn key_validate(key: []const u8) BLST_ERROR!void {
        const pk = try PublicKey.fromBytes(key);
        try pk.validate();
    }

    pub fn fromAggregate(agg_pk: *const AggregatePublicKey) PublicKey {
        var pk_aff = PublicKey.default();
        c.blst_p1_to_affine(&pk_aff.point, &agg_pk.point);
        return pk_aff;
    }

    // Serdes

    pub fn compress(self: *const PublicKey) [48]u8 {
        var pk_comp = [_]u8{0} ** 48;
        c.blst_p1_affine_compress(&pk_comp[0], &self.point);
        return pk_comp;
    }

    pub fn serialize(self: *const PublicKey) [96]u8 {
        var pk_out = [_]u8{0} ** 96;
        c.blst_p1_affine_serialize(&pk_out[0], &self.point);
        return pk_out;
    }

    pub fn uncompress(pk_comp: []const u8) BLST_ERROR!PublicKey {
        if (pk_comp.len == 48 and (pk_comp[0] & 0x80) != 0) {
            var pk = PublicKey.default();
            const res = c.blst_p1_uncompress(&pk.point, &pk_comp[0]);
            const err = toBlstError(res);
            if (err != null) {
                return err.?;
            }
            return pk;
        }

        return BLST_ERROR.BAD_ENCODING;
    }

    pub fn deserialize(pk_in: []const u8) BLST_ERROR!PublicKey {
        if ((pk_in.len == 96 and (pk_in[0] & 0x80) == 0) or
            (pk_in.len == 48 and (pk_in[0] & 0x80) != 0))
        {
            var pk = PublicKey.default();
            const res = c.blst_p1_deserialize(&pk.point, &pk_in[0]);
            const err = toBlstError(res);
            if (err != null) {
                return err.?;
            }
            return pk;
        }

        return BLST_ERROR.BAD_ENCODING;
    }

    pub fn fromBytes(pk_in: []const u8) BLST_ERROR!PublicKey {
        return PublicKey.deserialize(pk_in);
    }

    pub fn toBytes(self: *const PublicKey) [48]u8 {
        return self.compress();
    }

    // TODO: Eq, PartialEq, Serialize, Deserialize?
};

// TODO: implement Debug, Clone, Copy?
const AggregatePublicKey = struct {
    point: c.blst_p1,

    pub fn default() AggregatePublicKey {
        return .{
            .point = util.default_blst_p1(),
        };
    }

    pub fn fromPublicKey(pk: *const PublicKey) AggregatePublicKey {
        var agg_pk = AggregatePublicKey.default();
        c.blst_p1_from_affine(&agg_pk.point, &pk.point);

        return agg_pk;
    }

    pub fn toPublicKey(self: *const AggregatePublicKey) PublicKey {
        var pk = PublicKey.default();
        c.blst_p1_to_affine(&pk.point, &self.point);
    }

    // Aggregate
    pub fn aggregate(pks: []*const PublicKey, pks_validate: bool) BLST_ERROR!AggregatePublicKey {
        if (pks.len == 0) {
            return BLST_ERROR.AGGR_TYPE_MISMATCH;
        }
        if (pks.validate) {
            try pks[0].validate();
        }

        var agg_pk = AggregatePublicKey.fromPublicKey(pks[0]);
        for (pks[1..]) |pk| {
            if (pks_validate) {
                try pk.validate();
            }

            c.blst_p1_add_or_double_affine(&agg_pk.point, &agg_pk.point, &pk.point);
        }

        return agg_pk;
    }

    pub fn aggregateSerialized(pks: [][]const u8, pks_validate: bool) BLST_ERROR!AggregatePublicKey {
        // TODO - threading
        if (pks.len == 0) {
            return BLST_ERROR.AGGR_TYPE_MISMATCH;
        }
        var pk = if (pks_validate) PublicKey.key_validate(pks[0]) else PublicKey.fromBytes(pks[0]);
        var agg_pk = AggregatePublicKey.fromPublicKey(&pk);
        for (pks[1..]) |s| {
            pk = if (pks_validate) PublicKey.key_validate(s) else PublicKey.fromBytes(s);
            c.blst_p1_add_or_double_affine(&agg_pk.point, &agg_pk.point, &pk.point);
        }

        return agg_pk;
    }

    pub fn addAggregate(self: *AggregatePublicKey, agg_pk: *const AggregatePublicKey) BLST_ERROR!void {
        c.blst_p1_add_or_double_affine(&self.point, &self.point, &agg_pk.point);
    }

    pub fn addPublicKey(self: *AggregatePublicKey, pk: *const PublicKey, pk_validate: bool) BLST_ERROR!void {
        if (pk_validate) {
            try pk.validate();
        }

        c.blst_p1_add_or_double_affine(&self.point, &self.point, &pk.point);
    }
};

const Signature = struct {
    point: c.blst_p2_affine,

    pub fn default() Signature {
        return .{
            .point = util.default_blst_p2_affine(),
        };
    }

    // sig_infcheck, check for infinity, is a way to avoid going
    // into resource-consuming verification. Passing 'false' is
    // always cryptographically safe, but application might want
    // to guard against obviously bogus individual[!] signatures.
    pub fn validate(self: *const Signature, sig_infcheck: bool) BLST_ERROR!void {
        if (sig_infcheck and c.blst_p2_affine_is_inf(&self.point)) {
            return BLST_ERROR.PK_IS_INFINITY;
        }

        if (!c.blst_p2_affine_in_g2(&self.point)) {
            return BLST_ERROR.POINT_NOT_IN_GROUP;
        }
    }

    pub fn sigValidate(sig_in: []const u8, sig_infcheck: bool) BLST_ERROR!Signature {
        var sig = Signature.fromBytes(sig_in);
        sig.validate(sig_infcheck);
        return sig;
    }

    pub fn verify(self: *const Signature, sig_groupcheck: bool, msg: []const u8, dst: []const u8, aug: ?[]const u8, pk: *const PublicKey, pk_validate: bool) BLST_ERROR!void {
        if (sig_groupcheck) {
            try self.validate(false);
        }

        if (pk_validate) {
            try pk.validate();
        }
        const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
        const aug_len = if (aug != null) aug.?.len else 0;

        const res = c.blst_core_verify_pk_in_g1(&pk.point, &self.point, true, &msg[0], msg.len, &dst[0], dst.len, aug_ptr, aug_len);
        const err = toBlstError(res);
        if (err != null) {
            return err.?;
        }
    }

    // TODO: need thread pool
    // verify
    // aggregate_verify
    // fast_aggregate_verify
    // verify_multiple_aggregate_signatures

    pub fn fromAggregate(agg_sig: *const AggregateSignature) Signature {
        var sig_aff = Signature.default();
        c.blst_p2_to_affine(&sig_aff.point, &agg_sig.point);
        return sig_aff;
    }

    pub fn compress(self: *const Signature) [96]u8 {
        var sig_comp = [_]u8{0} ** 96;
        c.blst_p2_affine_compress(&sig_comp[0], &self.point);
        return sig_comp;
    }

    pub fn serialize(self: *const Signature) [192]u8 {
        var sig_out = [_]u8{0} ** 192;
        c.blst_p2_affine_serialize(&sig_out[0], &self.point);
        return sig_out;
    }

    pub fn uncompress(sig_comp: []const u8) BLST_ERROR!Signature {
        if (sig_comp.len == 96 and (sig_comp[0] & 0x80) != 0) {
            var sig = Signature.default();
            const res = c.blst_p2_uncompress(&sig.point, &sig_comp[0]);
            if (res != null) {
                return res;
            }
            return sig;
        }

        return BLST_ERROR.BAD_ENCODING;
    }

    pub fn deserialize(sig_in: []const u8) BLST_ERROR!Signature {
        if ((sig_in.len == 192 and (sig_in[0] & 0x80) == 0) or (sig_in.len == 96 and sig_in[0] & 0x80) != 0) {
            var sig = Signature.default();
            const res = c.blst_p2_deserialize(&sig.point, &sig_in[0]);
            const err = toBlstError(res);
            if (err != null) {
                return err.?;
            }
            return sig;
        }

        return BLST_ERROR.BAD_ENCODING;
    }

    pub fn fromBytes(sig_in: []const u8) BLST_ERROR!Signature {
        return Signature.deserialize(sig_in);
    }

    pub fn toBytes(self: *const Signature) [96]u8 {
        return self.compress();
    }

    pub fn subgroupCheck(self: *const Signature) bool {
        return c.blst_p2_affine_in_g2(&self.point);
    }

    // TODO: Eq PartialEq, Serialize, Deserialize?
};

const AggregateSignature = struct {
    point: c.blst_p2,

    pub fn default() AggregateSignature {
        return .{
            .point = util.default_blst_p2(),
        };
    }

    pub fn validate(self: *const AggregateSignature) BLST_ERROR!void {
        const res = c.blst_p2_in_g2(&self.point);
        const err = toBlstError(res);
        if (err != null) {
            return err.?;
        }
    }

    pub fn fromSignature(sig: *const Signature) AggregateSignature {
        var agg_sig = AggregateSignature.default();
        c.blst_p2_from_affine(&agg_sig.point, &sig.point);
        return agg_sig;
    }

    pub fn toSignature(self: *const AggregateSignature) Signature {
        var sig = Signature.default();
        c.blst_p2_to_affine(&sig.point, &self.point);
        return sig;
    }

    // Aggregate
    pub fn aggregate(sigs: []*const Signature, sigs_groupcheck: bool) BLST_ERROR!AggregateSignature {
        if (sigs.len == 0) {
            return BLST_ERROR.AGGR_TYPE_MISMATCH;
        }
        if (sigs_groupcheck) {
            // We can't actually judge if input is individual or
            // aggregated signature, so we can't enforce infinity
            // check.
            try sigs[0].validate(false);
        }

        var agg_sig = AggregateSignature.fromSignature(sigs[0]);
        for (sigs[1..]) |s| {
            if (sigs_groupcheck) {
                try s.validate(false);
            }
            c.blst_p2_add_or_double_affine(&agg_sig.point, &agg_sig.point, &s.point);
        }

        return agg_sig;
    }

    pub fn aggregateSerialized(sigs: [][]const u8, sigs_groupcheck: bool) BLST_ERROR!AggregateSignature {
        // TODO - threading
        if (sigs.len() == 0) {
            return BLST_ERROR.AGGR_TYPE_MISMATCH;
        }

        var sig = if (sigs_groupcheck) Signature.sigValidate(sigs[0], false) else Signature.fromBytes(sigs[0]);

        var agg_sig = AggregateSignature.fromSignature(&sig);
        for (sigs[1..]) |s| {
            sig = if (sigs_groupcheck) Signature.sigValidate(s, false) else Signature.fromBytes(s);
            c.blst_p2_add_or_double_affine(&agg_sig.point, &agg_sig.point, &sig.point);
        }
        return agg_sig;
    }

    pub fn addAggregate(self: *AggregateSignature, agg_sig: *const AggregateSignature) void {
        c.blst_p2_add_or_double(&self.point, &self.point, &agg_sig.point);
    }

    pub fn addSignature(self: *AggregateSignature, sig: *const Signature, sig_groupcheck: bool) BLST_ERROR!void {
        if (sig_groupcheck) {
            try sig.validate(false);
        }
        c.blst_p2_add_or_double_affine(&self.point, &self.point, &sig.point);
    }

    pub fn subgroupCheck(self: *const AggregateSignature) bool {
        return c.blst_p2_in_g2(&self.point);
    }
};

// TODO: implement MultiPoint

test "SecretKey" {
    std.debug.print("size of SecretKey: {}, align is {}\n", .{ @sizeOf(SecretKey), @alignOf(SecretKey) });
    const zero_bytes = [_]u8{0} ** 32;
    const info = zero_bytes[0..32];
    _ = try SecretKey.keyGen(info, info);
    _ = try SecretKey.keyGenV3(info, info);
    _ = try SecretKey.keyGenV45(info, info, info);
    _ = try SecretKey.keyGenV5(info, info, info);
    const sk = try SecretKey.deriveMasterEip2333(info);
    _ = try sk.deriveChildEip2333(0);
}

/// this is a simulation of get_random_key() in Rust without having to use chacha20 random
/// this is not nice but good enough to start with
/// TODO: use zig equivalent way, could produce different data
/// equivalent Rust code
/// ```rust
/// let seed = [0u8; 32];
///  let mut rng = ChaCha20Rng::from_seed(seed);
/// let num_msgs = 10;
/// (0..num_msgs).for_each(|i| {
///   let mut msg = [0u8; 32];
///   rng.fill_bytes(&mut msg);
/// });
///
/// let mut msgs: Vec<Vec<u8>> = vec![vec![]; num_msgs];
/// (0..num_msgs).for_each(|i| {
///   let msg_len = (rng.next_u64() & 0x3F) + 1;
///   msgs[i] = vec![0u8; msg_len as usize];
///   rng.fill_bytes(&mut msgs[i]);
/// })
const RandomKeyFn = *const fn () SecretKey;
fn getChacha20Rng() RandomKeyFn {
    const T = struct {
        threadlocal var i: u8 = 0;
        fn getRandomKey() SecretKey {
            const value: [32]u8 = switch (i) {
                0 => [_]u8{ 118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199 },
                1 => [_]u8{ 218, 65, 89, 124, 81, 87, 72, 141, 119, 36, 224, 63, 184, 216, 74, 55, 106, 67, 184, 244, 21, 24, 161, 28, 195, 135, 182, 105, 178, 238, 101, 134 },
                2 => [_]u8{ 159, 7, 231, 190, 85, 81, 56, 122, 152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227, 101, 105, 18, 198, 83, 62, 50, 238, 122, 237 },
                3 => [_]u8{ 41, 183, 33, 118, 156, 230, 78, 67, 213, 113, 51, 176, 116, 216, 57, 213, 49, 237, 31, 40, 81, 10, 251, 69, 172, 225, 10, 31, 75, 121, 77, 111 },
                4 => [_]u8{ 45, 9, 160, 230, 99, 38, 108, 225, 174, 126, 209, 8, 25, 104, 160, 117, 142, 113, 142, 153, 123, 211, 98, 198, 176, 195, 70, 52, 169, 160, 179, 93 },
                5 => [_]u8{ 1, 39, 55, 104, 31, 123, 93, 15, 40, 30, 58, 253, 228, 88, 188, 30, 115, 210, 211, 19, 201, 207, 148, 192, 95, 243, 113, 98, 64, 162, 72, 242 },
                6 => [_]u8{ 19, 32, 160, 88, 215, 179, 86, 107, 213, 32, 218, 170, 62, 210, 191, 10, 197, 184, 177, 32, 251, 133, 39, 115, 195, 99, 151, 52, 180, 92, 145, 164 },
                7 => [_]u8{ 45, 212, 203, 131, 248, 132, 13, 46, 237, 177, 88, 19, 16, 98, 172, 63, 31, 44, 248, 255, 109, 205, 24, 86, 232, 106, 30, 108, 49, 103, 22, 126 },
                8 => [_]u8{ 229, 166, 136, 116, 43, 71, 197, 173, 251, 89, 212, 223, 118, 253, 29, 177, 229, 30, 224, 59, 28, 169, 248, 42, 202, 23, 62, 219, 139, 114, 147, 71 },
                9 => [_]u8{ 78, 190, 152, 15, 144, 77, 16, 201, 22, 68, 43, 71, 131, 160, 233, 132, 134, 12, 182, 201, 87, 179, 156, 56, 237, 143, 81, 207, 250, 166, 138, 77 },
                else => @panic("getRadomKey() is not implemented for big number"),
            };
            i += 1;
            const sk = SecretKey.keyGen(value[0..], null) catch {
                @panic("SecretKey.keyGen() failed\n");
            };
            return sk;
        }
    };

    return T.getRandomKey;
}

test "test_sign_n_verify" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(ikm[0..], null);
    const pk = sk.skToPk();

    const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    const msg = "hello foo";
    // aug is null
    const sig = sk.sign(msg[0..], dst[0..], null);

    // aug is null
    try sig.verify(true, msg[0..], dst[0..], null, &pk, true);
}

test "test_aggregate" {
    const num_msgs = 10;
    const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    const getRandomKey = getChacha20Rng();
    var sks = [_]SecretKey{SecretKey.default()} ** num_msgs;
    for (0..num_msgs) |i| {
        sks[i] = getRandomKey();
    }

    var pks: [num_msgs]PublicKey = undefined;
    const pksSlice = pks[0..];
    for (0..num_msgs) |i| {
        pksSlice[i] = sks[i].skToPk();
    }

    var pks_ptr: [num_msgs]*PublicKey = undefined;
    var pks_ptr_rev: [num_msgs]*PublicKey = undefined;
    for (pksSlice, 0..num_msgs) |*pk_ptr, i| {
        pks_ptr[i] = pk_ptr;
        pks_ptr_rev[num_msgs - i - 1] = pk_ptr;
    }

    const pk_comp = pksSlice[0].compress();
    _ = try PublicKey.uncompress(pk_comp[0..]);

    var msgs: [num_msgs][]u8 = undefined;
    const msg_lens: [num_msgs]u64 = comptime .{ 33, 34, 39, 22, 43, 1, 24, 60, 2, 41 };

    inline for (0..num_msgs) |i| {
        var msg = [_]u8{0} ** msg_lens[i];
        msgs[i] = msg[0..];
        std.crypto.random.bytes(msgs[i]);
    }

    var sigs: [num_msgs]Signature = undefined;
    for (0..num_msgs) |i| {
        sigs[i] = sks[i].sign(msgs[i], dst, null);
    }

    for (0..num_msgs) |i| {
        try sigs[i].verify(true, msgs[i], dst, null, pks_ptr[i], true);
    }

    // Swap message/public key pairs to create bad signature
    for (0..num_msgs) |i| {
        if (sigs[i].verify(true, msgs[num_msgs - i - 1], dst, null, pks_ptr_rev[i], true)) {
            try std.testing.expect(false);
        } else |err| {
            try std.testing.expectEqual(err, BLST_ERROR.VERIFY_FAIL);
        }
    }

    var sig_ptrs: [num_msgs]*Signature = undefined;
    for (sigs[0..], 0..num_msgs) |*sig_ptr, i| {
        sig_ptrs[i] = sig_ptr;
    }
    const agg = try AggregateSignature.aggregate(sig_ptrs[0..], true);
    _ = agg.toSignature();
    // TODO aggregate_verify
    // let mut result = agg_sig
    //   .aggregate_verify(false, &msgs_refs, dst, &pks_refs, false);
    // assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
    // // Swap message/public key pairs to create bad signature
    // result = agg_sig
    //     .aggregate_verify(false, &msgs_refs, dst, &pks_rev, false);
    // assert_ne!(result, BLST_ERROR::BLST_SUCCESS);
}
