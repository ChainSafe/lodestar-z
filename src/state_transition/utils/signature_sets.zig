const types = @import("consensus_types");
pub const blst = @import("blst");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const Root = types.primitive.Root.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const verify = @import("./bls.zig").verify;
const fastAggregateVerify = @import("./bls.zig").fastAggregateVerify;

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
    const signature = try Signature.uncompress(&set.signature);
    if (verify(&set.signing_root, &set.pubkey, &signature, null, null)) {
        return true;
    } else |_| {
        return false;
    }
}

pub fn verifyAggregatedSignatureSet(set: *const AggregatedSignatureSet) !bool {
    // All signatures are not trusted and must be group checked (p2.subgroup_check)
    const signature = try Signature.uncompress(&set.signature);
    return fastAggregateVerify(&set.signing_root, set.pubkeys, &signature, null, null);
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
