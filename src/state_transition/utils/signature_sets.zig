const std = @import("std");
const types = @import("consensus_types");
pub const bls = @import("bls");
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;
const SecretKey = bls.SecretKey;
const Root = types.primitive.Root.Type;
const BLSSignature = types.primitive.BLSSignature.Type;
const sign = @import("./bls.zig").sign;
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
        .pubkey = pubkey.*,
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

// Deterministic IKMs for tests only (not production secrets).
const input_key_material_a: [32]u8 = [_]u8{
    0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
    0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
    0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
    0x48, 0x99,
};
const input_key_material_b: [32]u8 = [_]u8{
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10,
};

test "verifySingleSignatureSet returns expected result for each scenario" {
    const secret_key_a = try SecretKey.keyGen(input_key_material_a[0..], null);
    const secret_key_b = try SecretKey.keyGen(input_key_material_b[0..], null);
    const valid_signing_root = [_]u8{1} ** 32;
    var mismatched_signing_root = valid_signing_root;
    mismatched_signing_root[0] ^= 1;
    const signature = sign(secret_key_a, &valid_signing_root);
    const signer_public_key = secret_key_a.toPublicKey();

    const cases = [_]struct {
        set: SingleSignatureSet,
        expected: bool,
    }{
        .{
            .set = .{
                .pubkey = signer_public_key,
                .signing_root = valid_signing_root,
                .signature = signature.compress(),
            },
            .expected = true,
        },
        .{
            .set = .{
                .pubkey = signer_public_key,
                .signing_root = mismatched_signing_root,
                .signature = signature.compress(),
            },
            .expected = false,
        },
        .{
            .set = .{
                .pubkey = secret_key_b.toPublicKey(),
                .signing_root = valid_signing_root,
                .signature = signature.compress(),
            },
            .expected = false,
        },
    };

    for (cases) |case| {
        const actual = try verifySingleSignatureSet(&case.set);
        try std.testing.expectEqual(case.expected, actual);
    }
}

test "verifySingleSignatureSet returns error when signature bytes are not valid compressed G2" {
    const secret_key = try SecretKey.keyGen(input_key_material_a[0..], null);
    const signing_root = [_]u8{1} ** 32;
    const set = SingleSignatureSet{
        .pubkey = secret_key.toPublicKey(),
        .signing_root = signing_root,
        .signature = [_]u8{0} ** 96,
    };
    try std.testing.expectError(bls.BlstError.BadEncoding, verifySingleSignatureSet(&set));
}

test "verifyAggregatedSignatureSet accepts valid single-key aggregate" {
    const secret_key = try SecretKey.keyGen(input_key_material_a[0..], null);
    const signing_root = [_]u8{1} ** 32;
    const signature = sign(secret_key, &signing_root);
    const public_key = secret_key.toPublicKey();
    var pubkeys = [_]PublicKey{public_key};
    const set = createAggregateSignatureSetFromComponents(pubkeys[0..], signing_root, signature.compress());
    try std.testing.expect(try verifyAggregatedSignatureSet(&set));
}

test "verifyAggregatedSignatureSet returns false when signing root does not match" {
    const secret_key = try SecretKey.keyGen(input_key_material_a[0..], null);
    var signing_root = [_]u8{1} ** 32;
    const signature = sign(secret_key, &signing_root);
    const public_key = secret_key.toPublicKey();
    signing_root[31] ^= 0xff;
    var pubkeys = [_]PublicKey{public_key};
    const set = createAggregateSignatureSetFromComponents(pubkeys[0..], signing_root, signature.compress());
    try std.testing.expectEqual(false, try verifyAggregatedSignatureSet(&set));
}

test "verifyAggregatedSignatureSet returns false when pubkeys are not the signers" {
    const secret_key_a = try SecretKey.keyGen(input_key_material_a[0..], null);
    const secret_key_b = try SecretKey.keyGen(input_key_material_b[0..], null);
    const signing_root = [_]u8{1} ** 32;
    const signature = sign(secret_key_a, &signing_root);
    var pubkeys = [_]PublicKey{secret_key_b.toPublicKey()};
    const set = createAggregateSignatureSetFromComponents(pubkeys[0..], signing_root, signature.compress());
    try std.testing.expectEqual(false, try verifyAggregatedSignatureSet(&set));
}

test "createSingleSignatureSetFromComponents matches equivalent struct literal" {
    const secret_key = try SecretKey.keyGen(input_key_material_a[0..], null);
    var signing_root: Root = undefined;
    @memset(signing_root[0..], 0x77);
    const signature = sign(secret_key, signing_root[0..]);
    const public_key = secret_key.toPublicKey();
    const compressed = signature.compress();
    const from_fn = createSingleSignatureSetFromComponents(&public_key, signing_root, compressed);
    const literal = SingleSignatureSet{
        .pubkey = public_key,
        .signing_root = signing_root,
        .signature = compressed,
    };
    try std.testing.expect(try verifySingleSignatureSet(&from_fn));
    try std.testing.expect(try verifySingleSignatureSet(&literal));
}
