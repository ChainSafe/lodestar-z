const PublicKey = @import("./public_key.zig").PublicKey;
const c = @cImport({
    @cInclude("blst.h");
});

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

pub const Signature = struct {
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

pub const AggregateSignature = struct {
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
