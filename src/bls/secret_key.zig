const c = @cImport({
    @cInclude("blst.h");
});
const PublicKey = @import("./public_key.zig").PublicKey;
const Signature = @import("./signature.zig").Signature;

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

/// TODO: the size of SecretKey is only 32 bytes so go with stack allocation
/// consider adding heap allocation with allocator in the future
pub const SecretKey = struct {
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
