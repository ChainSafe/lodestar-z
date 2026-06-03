const types = @import("consensus_types");
pub const bls = @import("bls");
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;
const Root = types.primitive.Root.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const fastAggregateVerify = @import("bls").fastAggregateVerify;

pub const SignatureSetType = enum { single, aggregate };

pub const SingleSignatureSet = struct {
    // fromBytes api return PublicKey so it's more convenient to model this as value
    pubkey: PublicKey,
    signing_root: Root,
    signature: BLSSignature,
};

pub const AggregatedSignatureSet = struct {
    // fastAggregateVerify also requires []*const PublicKey
    pubkeys: []const PublicKey,
    signing_root: Root,
    signature: BLSSignature,
};

pub fn verifySingleSignatureSet(set: *const SingleSignatureSet) !bool {
    // All signatures are not trusted and must be group checked (p2.subgroup_check)
    //msg: []const u8, pk: *const PublicKey, sig: *const Signature, in_pk_validate: ?bool, in_sig_groupcheck: ?bool
    const signature = try Signature.uncompress(&set.signature);
    if (signature.verify(
        false,
        &set.signing_root,
        bls.DST,
        null,
        &set.pubkey,
        false,
    )) {
        return true;
    } else |_| {
        return false;
    }
}

pub fn verifyAggregatedSignatureSet(set: *const AggregatedSignatureSet) !bool {
    // All signatures are not trusted and must be group checked (p2.subgroup_check)
    const signature = try Signature.uncompress(&set.signature);
    var buf: [bls.Pairing.sizeOf()]u8 align(bls.Pairing.buf_align) = undefined;
    var pk_ptrs: []*const bls.PublicKey = undefined;
    for (set.pubkeys, 0..) |pk, i| {
        pk_ptrs[i] = &pk;
    }
    return signature.fastAggregateVerify(false, &buf, &set.signing_root, bls.DST, pk_ptrs[0..], false);
}

pub fn createSingleSignatureSetFromComponents(pubkey: *const PublicKey, signing_root: Root, signature: BLSSignature) SingleSignatureSet {
    return .{
        .pubkey = pubkey,
        .signing_root = signing_root,
        .signature = signature,
    };
}

pub fn createAggregateSignatureSetFromComponents(pubkeys: []const PublicKey, signing_root: Root, signature: BLSSignature) AggregatedSignatureSet {
    return .{
        .pubkeys = pubkeys,
        .signing_root = signing_root,
        .signature = signature,
    };
}

// TODO: unit tests
