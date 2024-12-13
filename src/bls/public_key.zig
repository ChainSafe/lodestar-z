const c = @cImport({
    @cInclude("blst.h");
});

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

// TODO: implement Clone, Copy, Equal
pub const PublicKey = struct {
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
pub const AggregatePublicKey = struct {
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
