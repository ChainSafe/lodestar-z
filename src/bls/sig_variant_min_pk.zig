const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Xoshiro256 = std.rand.Xoshiro256;
const Pairing = @import("./pairing.zig").Pairing;
const spawnTask = @import("./thread_pool.zig").spawnTask;
const initializeThreadPool = @import("./thread_pool.zig").initializeThreadPool;
const deinitializeThreadPool = @import("./thread_pool.zig").deinitializeThreadPool;
const c = @cImport({
    @cInclude("blst.h");
});
const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

const createSigVariant = @import("./sig_variant.zig").createSigVariant;
const MAX_SIGNATURE_SETS = @import("./sig_variant.zig").MAX_SIGNATURE_SETS;
const randBytes = @import("./sig_variant.zig").randBytes;

/// See https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const SigVariant = createSigVariant(
    util.default_blst_p1_affline,
    util.default_blst_p1,
    util.default_blst_p2_affine,
    util.default_blst_p2,
    c.blst_p1,
    c.blst_p1_affine,
    c.blst_p2,
    c.blst_p2_affine,
    c.blst_sk_to_pk2_in_g1,
    true,
    c.blst_hash_to_g2,
    c.blst_sign_pk2_in_g1,
    c.blst_p1_affine_is_equal,
    c.blst_p2_affine_is_equal,
    // 2 new zig specific eq functions
    c.blst_p1_is_equal,
    c.blst_p2_is_equal,
    c.blst_core_verify_pk_in_g1,
    c.blst_p1_affine_in_g1,
    c.blst_p1_to_affine,
    c.blst_p1_from_affine,
    c.blst_p1_affine_serialize,
    c.blst_p1_affine_compress,
    c.blst_p1_deserialize,
    c.blst_p1_uncompress,
    48,
    96,
    c.blst_p2_affine_in_g2,
    c.blst_p2_to_affine,
    c.blst_p2_from_affine,
    c.blst_p2_affine_serialize,
    c.blst_p2_affine_compress,
    c.blst_p2_deserialize,
    c.blst_p2_uncompress,
    96,
    192,
    c.blst_p1_add_or_double,
    c.blst_p1_add_or_double_affine,
    c.blst_p2_add_or_double,
    c.blst_p2_add_or_double_affine,
    c.blst_p1_affine_is_inf,
    c.blst_p2_affine_is_inf,
    c.blst_p2_in_g2,
    // multi_point
    c.blst_p1s_add,
    c.blst_p1s_mult_pippenger,
    c.blst_p1s_mult_pippenger_scratch_sizeof,
    c.blst_p1_mult,
    c.blst_p1_generator,
    c.blst_p1s_to_affine,
    c.blst_p2s_add,
    c.blst_p2s_mult_pippenger,
    c.blst_p2s_mult_pippenger_scratch_sizeof,
    c.blst_p2_mult,
    c.blst_p2_generator,
    c.blst_p2s_to_affine,
);

pub const PublicKey = SigVariant.createPublicKey();
pub const AggregatePublicKey = SigVariant.createAggregatePublicKey();
pub const Signature = SigVariant.createSignature();
pub const AggregateSignature = SigVariant.createAggregateSignature();
pub const SecretKey = SigVariant.createSecretKey();

/// exported C-ABI functions need to be declared at top level, and they only work with extern struct
const PublicKeyType = SigVariant.getPublicKeyType();
const AggregatePublicKeyType = SigVariant.getAggregatePublicKeyType();
const SignatureType = SigVariant.getSignatureType();
const AggregateSignatureType = SigVariant.getAggregateSignatureType();
const SecretKeyType = SigVariant.getSecretKeyType();
const SignatureSetType = SigVariant.getSignatureSetType();
const PkAndSerializedSigType = SigVariant.getPkAndSerializedSigType();
const CallBackFn = SigVariant.getCallBackFn();
const MemoryPool = SigVariant.getMemoryPoolType();

/// PublicKey functions
export fn defaultPublicKey() PublicKeyType {
    return PublicKey.defaultPublicKey();
}

export fn validatePublicKey(pk: *const PublicKeyType) c_uint {
    return PublicKey.validatePublicKey(pk);
}

export fn publicKeyBytesValidate(key: [*c]const u8, len: usize) c_uint {
    return PublicKey.publicKeyBytesValidate(key, len);
}

export fn publicKeyFromAggregate(out: *PublicKeyType, agg_pk: *const AggregatePublicKeyType) void {
    return PublicKey.publicKeyFromAggregate(out, agg_pk);
}

export fn compressPublicKey(out: *u8, point: *const PublicKeyType) void {
    return PublicKey.compressPublicKey(out, point);
}

export fn serializePublicKey(out: *u8, point: *const PublicKeyType) void {
    return PublicKey.serializePublicKey(out, point);
}

export fn uncompressPublicKey(out: *PublicKeyType, pk_comp: [*c]const u8, len: usize) c_uint {
    return PublicKey.uncompressPublicKey(out, pk_comp, len);
}

export fn deserializePublicKey(out: *PublicKeyType, pk_in: [*c]const u8, len: usize) c_uint {
    return PublicKey.deserializePublicKey(out, pk_in, len);
}

export fn publicKeyFromBytes(point: *PublicKeyType, pk_in: [*c]const u8, len: usize) c_uint {
    return PublicKey.publicKeyFromBytes(point, pk_in, len);
}

export fn toPublicKeyBytes(out: *u8, point: *PublicKeyType) void {
    return PublicKey.toPublicKeyBytes(out, point);
}

export fn isPublicKeyEqual(point: *PublicKeyType, other: *PublicKeyType) bool {
    return PublicKey.isPublicKeyEqual(point, other);
}

/// AggregatePublicKeyType functions
export fn defaultAggregatePublicKey() AggregatePublicKeyType {
    return AggregatePublicKey.defaultAggregatePublicKey();
}

export fn aggregateFromPublicKey(out: *AggregatePublicKeyType, pk: *const PublicKeyType) void {
    return AggregatePublicKey.aggregateFromPublicKey(out, pk);
}

export fn aggregateToPublicKey(out: *PublicKeyType, agg_pk: *const AggregatePublicKeyType) void {
    return AggregatePublicKey.aggregateToPublicKey(out, agg_pk);
}

export fn aggregatePublicKeys(out: *PublicKeyType, pks: [*c]*const PublicKeyType, len: usize, pks_validate: bool) c_uint {
    var aggregate_pk = defaultAggregatePublicKey();
    const res = AggregatePublicKey.aggregatePublicKeys(&aggregate_pk, pks, len, pks_validate);
    aggregateToPublicKey(out, &aggregate_pk);
    return res;
}

export fn aggregateSerializedPublicKeys(out: *PublicKeyType, pks: [*c][*c]const u8, pks_len: usize, pk_len: usize, pks_validate: bool) c_uint {
    var aggregate_pk = defaultAggregatePublicKey();
    const res = AggregatePublicKey.aggregateSerializedPublicKeys(&aggregate_pk, pks, pks_len, pk_len, pks_validate);
    aggregateToPublicKey(out, &aggregate_pk);
    return res;
}

export fn addAggregatePublicKey(out: *AggregatePublicKeyType, agg_pk: *const AggregatePublicKeyType) void {
    return AggregatePublicKey.addAggregatePublicKey(out, agg_pk);
}

export fn addPublicKeyToAggregate(out: *AggregatePublicKeyType, pk: *const PublicKeyType, pk_validate: bool) c_uint {
    return AggregatePublicKey.addPublicKeyToAggregate(out, pk, pk_validate);
}

export fn isAggregatePublicKeyEqual(agg_pk: *const AggregatePublicKeyType, other: *const AggregatePublicKeyType) bool {
    return AggregatePublicKey.isAggregatePublicKeyEqual(agg_pk, other);
}

/// Signature functions
export fn defaultSignature() SignatureType {
    return Signature.defaultSignature();
}

export fn validateSignature(sig: *const SignatureType, sig_infcheck: bool) c_uint {
    return Signature.validateSignature(sig, sig_infcheck);
}

export fn sigValidate(out: *SignatureType, sig: [*c]const u8, sig_len: usize, sig_infcheck: bool) c_uint {
    return Signature.sigValidateC(out, sig, sig_len, sig_infcheck);
}

export fn verifySignature(sig: *const SignatureType, sig_groupcheck: bool, msg: [*c]const u8, msg_len: usize, pk: *const PublicKeyType, pk_validate: bool) c_uint {
    // aug_ptr is null, aug_len is 0
    return Signature.verifySignature(sig, sig_groupcheck, msg, msg_len, &DST[0], DST.len, null, 0, pk, pk_validate);
}

export fn aggregateVerify(sig: *const SignatureType, sig_groupcheck: bool, msgs: [*c][*c]const u8, msgs_len: usize, msg_len: usize, pks: [*c]const *PublicKeyType, pks_len: usize, pks_validate: bool, pairing_buffer: [*c]u8, pairing_buffer_len: usize) c_uint {
    return Signature.aggregateVerifyC(sig, sig_groupcheck, msgs, msgs_len, msg_len, &DST[0], DST.len, pks, pks_len, pks_validate, pairing_buffer, pairing_buffer_len);
}

export fn fastAggregateVerify(sig: *const SignatureType, sig_groupcheck: bool, msg: [*c]const u8, msg_len: usize, pks: [*c]*const PublicKeyType, pks_len: usize, pairing_buffer: [*c]u8, pairing_buffer_len: usize) c_uint {
    return Signature.fastAggregateVerifyC(sig, sig_groupcheck, msg, msg_len, &DST[0], DST.len, pks, pks_len, pairing_buffer, pairing_buffer_len);
}

export fn fastAggregateVerifyPreAggregated(sig: *const SignatureType, sig_groupcheck: bool, msg: [*c]const u8, msg_len: usize, pk: *PublicKeyType, pairing_buffer: [*c]u8, pairing_buffer_len: usize) c_uint {
    return Signature.fastAggregateVerifyPreAggregatedC(sig, sig_groupcheck, msg, msg_len, &DST[0], DST.len, pk, pairing_buffer, pairing_buffer_len);
}

const RAND_BYTES = 8;
const RAND_BITS = 8 * RAND_BYTES;
var rands: [RAND_BYTES * MAX_SIGNATURE_SETS]u8 = [_]u8{0} ** (RAND_BYTES * MAX_SIGNATURE_SETS);
var rand_refs: [MAX_SIGNATURE_SETS][*c]u8 = undefined;
// Flag to track rand_refs initialization
var rand_refs_initialized: bool = false;

fn initRandRefs() void {
    for (0..MAX_SIGNATURE_SETS) |i| {
        rand_refs[i] = &rands[i * 8];
    }
}

/// this is single thread version so it can reuse some params:
/// - pairing_buffer: reuse at consumer side
/// - random bytes: do stack allocation and reuse
export fn verifyMultipleAggregateSignatures(sets: [*c]*const SignatureSetType, sets_len: usize, msg_len: usize, pks_validate: bool, sigs_groupcheck: bool) c_uint {
    return doVerifyMultipleAggregateSignatures(null, sets, sets_len, msg_len, pks_validate, sigs_groupcheck);
}

/// a zig application should pass the allocator to this function
/// for Bun binding, allocator is null
pub fn doVerifyMultipleAggregateSignatures(allocator: ?Allocator, sets: [*c]*const SignatureSetType, sets_len: usize, msg_len: usize, pks_validate: bool, sigs_groupcheck: bool) c_uint {
    if (rand_refs_initialized == false) {
        initRandRefs();
    }
    rand_refs_initialized = true;

    if (sets_len > MAX_SIGNATURE_SETS) {
        return c.BLST_BAD_ENCODING;
    }
    randBytes(rands[0..(sets_len * 8)]);
    const pool = getMemoryPool(allocator) catch return c.BLST_BAD_ENCODING;
    return Signature.verifyMultipleAggregateSignaturesC(sets, sets_len, msg_len, &DST[0], DST.len, pks_validate, sigs_groupcheck, &rand_refs[0], sets_len, RAND_BITS, pool);
}

export fn signatureFromAggregate(out: *SignatureType, agg_sig: *const AggregateSignatureType) void {
    Signature.signatureFromAggregate(out, agg_sig);
}

export fn compressSignature(out: *u8, point: *const SignatureType) void {
    Signature.compressSignature(out, point);
}

export fn serializeSignature(out: *u8, point: *const SignatureType) void {
    Signature.serializeSignature(out, point);
}

export fn uncompressSignature(out: *SignatureType, sig_comp: [*c]const u8, len: usize) c_uint {
    return Signature.uncompressSignature(out, sig_comp, len);
}

export fn deserializeSignature(out: *SignatureType, sig_in: [*c]const u8, len: usize) c_uint {
    return Signature.deserializeSignature(out, sig_in, len);
}

export fn signatureFromBytes(out: *SignatureType, sig_in: [*c]const u8, len: usize) c_uint {
    return Signature.signatureFromBytes(out, sig_in, len);
}

export fn signatureToBytes(out: *u8, point: *SignatureType) void {
    return Signature.signatureToBytes(out, point);
}

export fn signatureSubgroupCheck(point: *SignatureType) bool {
    return Signature.signatureSubgroupCheck(point);
}

export fn isSignatureEqual(point: *const SignatureType, other: *const SignatureType) bool {
    return Signature.isSignatureEqual(point, other);
}

/// AggregateSignatureType functions
export fn defaultAggregateSignature() AggregateSignatureType {
    return AggregateSignature.defaultAggregateSignature();
}

export fn validateAggregateSignature(point: *const AggregateSignatureType) c_uint {
    return AggregateSignature.validateAggregateSignature(point);
}

export fn aggregateFromSignature(out: *AggregateSignatureType, sig: *const SignatureType) void {
    return AggregateSignature.aggregateFromSignature(out, sig);
}

export fn aggregateToSignature(out: *SignatureType, agg_sig: *const AggregateSignatureType) void {
    return AggregateSignature.aggregateToSignature(out, agg_sig);
}

export fn aggregateSignatures(out: *SignatureType, sigs: [*c]*const SignatureType, len: usize, sigs_groupcheck: bool) c_uint {
    var aggregate_sig = defaultAggregateSignature();
    const res = AggregateSignature.aggregateSignatures(&aggregate_sig, sigs, len, sigs_groupcheck);
    aggregateToSignature(out, &aggregate_sig);
    return res;
}

export fn aggregateSerializedSignatures(out: *SignatureType, sigs: [*c][*c]const u8, sigs_len: usize, sig_len: usize, sigs_groupcheck: bool) c_uint {
    var aggregate_sig = defaultAggregateSignature();
    const res = AggregateSignature.aggregateSerializedC(&aggregate_sig, sigs, sigs_len, sig_len, sigs_groupcheck);
    aggregateToSignature(out, &aggregate_sig);
    return res;
}

export fn addAggregate(out: *AggregateSignatureType, agg_sig: *const AggregateSignatureType) void {
    return AggregateSignature.addAggregateC(out, agg_sig);
}

export fn addSignatureToAggregate(out: *AggregateSignatureType, sig: *const SignatureType, sig_groupcheck: bool) c_uint {
    return AggregateSignature.addSignatureToAggregate(out, sig, sig_groupcheck);
}

export fn subgroupCheckC(agg_sig: *const AggregateSignatureType) bool {
    return AggregateSignature.subgroupCheckC(agg_sig);
}

export fn isAggregateSignatureEqual(point: *const AggregateSignatureType, other: *const AggregateSignatureType) bool {
    return AggregateSignature.isAggregateSignatureEqual(point, other);
}

// SecretKeyType functions
export fn defaultSecretKey() SecretKeyType {
    return SecretKey.defaultSecretKey();
}

export fn secretKeyGen(out: *SecretKeyType, ikm: [*c]const u8, ikm_len: usize, key_info: [*c]const u8, key_info_len: usize) c_uint {
    return SecretKey.secretKeyGen(out, ikm, ikm_len, key_info, key_info_len);
}

export fn secretKeyGenV3(out: *SecretKeyType, ikm: [*c]const u8, ikm_len: usize, key_info: [*c]const u8, key_info_len: usize) c_uint {
    return SecretKey.secretKeyGenV3(out, ikm, ikm_len, key_info, key_info_len);
}

export fn secretKeyGenV45(out: *SecretKeyType, ikm: [*c]const u8, ikm_len: usize, salt: [*c]const u8, salt_len: usize, info: [*c]const u8, info_len: usize) c_uint {
    return SecretKey.secretKeyGenV45(out, ikm, ikm_len, salt, salt_len, info, info_len);
}

export fn secretKeyGenV5(out: *SecretKeyType, ikm: [*c]const u8, ikm_len: usize, salt: [*c]const u8, salt_len: usize, info: [*c]const u8, info_len: usize) c_uint {
    return SecretKey.secretKeyGenV5(out, ikm, ikm_len, salt, salt_len, info, info_len);
}

export fn secretKeyDeriveMasterEip2333(out: *SecretKeyType, ikm: [*c]const u8, ikm_len: usize) c_uint {
    return SecretKey.secretKeyDeriveMasterEip2333(out, ikm, ikm_len);
}

export fn secretKeyDeriveChildEip2333(out: *SecretKeyType, sk: *const SecretKeyType, child_index: u32) void {
    SecretKey.secretKeyDeriveChildEip2333(out, sk, child_index);
}

export fn secretKeyToPublicKey(out: *PublicKeyType, sk: *const SecretKeyType) void {
    return SecretKey.secretKeyToPublicKey(out, sk);
}

export fn sign(out: *SignatureType, sk: *const SecretKeyType, msg: [*c]const u8, msg_len: usize) void {
    return SecretKey.signC(out, sk, msg, msg_len, &DST[0], DST.len, null, 0);
}

export fn serializeSecretKey(out: *u8, sk: *const SecretKeyType) void {
    return SecretKey.serializeSecretKey(out, sk);
}

export fn deserializeSecretKey(out: *SecretKeyType, sk_in: [*c]const u8, len: usize) c_uint {
    return SecretKey.deserializeSecretKey(out, sk_in, len);
}

export fn secretKeyToBytes(out: *u8, sk: *const SecretKeyType) void {
    return SecretKey.secretKeyToBytes(out, sk);
}

export fn secretKeyFromBytes(out: *SecretKeyType, sk_in: [*c]const u8, len: usize) c_uint {
    return SecretKey.secretKeyFromBytes(out, sk_in, len);
}

// MultiPoints functions
export fn addPublicKeys(out: *AggregatePublicKeyType, pks: [*c]*const PublicKeyType, pks_len: usize) void {
    return SigVariant.addPublicKeysC(out, pks, pks_len);
}

export fn multPublicKeys(out: *AggregatePublicKeyType, pks: [*c]*const PublicKeyType, pks_len: usize, scalars: [*c]*const u8, n_bits: usize, scratch: [*c]u64) void {
    return SigVariant.multPublicKeysC(out, pks, pks_len, scalars, n_bits, scratch);
}

export fn addSignatures(out: *AggregateSignatureType, sigs: [*c]*const SignatureType, sigs_len: usize) void {
    return SigVariant.addSignaturesC(out, sigs, sigs_len);
}

export fn multSignatures(out: *AggregateSignatureType, sigs: [*c]*const SignatureType, sigs_len: usize, scalars: [*c]*const u8, n_bits: usize, scratch: [*c]u64) void {
    return SigVariant.multSignaturesC(out, sigs, sigs_len, scalars, n_bits, scratch);
}

export fn sizeOfPairing() c_uint {
    return @intCast(Pairing.sizeOf());
}

threadlocal var memory_pool: ?*MemoryPool = null;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

/// this is supposed to be called from the main thread so we dont need mutex here
fn getMemoryPool(in_allocator: ?Allocator) !*MemoryPool {
    if (memory_pool) |pool| {
        return pool;
    }
    const allocator = in_allocator orelse gpa.allocator();
    var mem_pool = try allocator.create(MemoryPool);
    try mem_pool.init(allocator);
    memory_pool = mem_pool;
    return mem_pool;
}

export fn aggregateWithRandomness(sets: [*c]*const PkAndSerializedSigType, sets_len: c_uint, pk_out: *PublicKeyType, sig_out: *SignatureType) c_uint {
    return doAggregateWithRandomness(null, sets, sets_len, pk_out, sig_out);
}

/// a zig application should pass the allocator to this function
/// for Bun binding, allocator is null
pub fn doAggregateWithRandomness(allocator: ?Allocator, sets: [*c]*const PkAndSerializedSigType, sets_len: c_uint, pk_out: *PublicKeyType, sig_out: *SignatureType) c_uint {
    const pool = getMemoryPool(allocator) catch return c.BLST_BAD_ENCODING;
    const res = SigVariant.aggregateWithRandomnessC(sets, sets_len, pool, pk_out, sig_out, null);
    return res;
}

export fn asyncAggregateWithRandomness(sets: [*c]*const PkAndSerializedSigType, sets_len: c_uint, pk_out: *PublicKeyType, sig_out: *SignatureType, callback: CallBackFn) c_uint {
    return doAsyncAggregateWithRandomness(null, sets, sets_len, pk_out, sig_out, callback);
}

/// a zig application should pass the allocator to this function
/// for Bun binding, allocator is null
pub fn doAsyncAggregateWithRandomness(allocator: ?Allocator, sets: [*c]*const PkAndSerializedSigType, sets_len: c_uint, pk_out: *PublicKeyType, sig_out: *SignatureType, callback: CallBackFn) c_uint {
    const pool = getMemoryPool(allocator) catch return c.BLST_BAD_ENCODING;
    return SigVariant.asyncAggregateWithRandomness(sets, sets_len, pool, pk_out, sig_out, callback);
}

/// a Bun application should call this before using any of the exported functions
export fn init() c_uint {
    initializeThreadPool(null) catch return c.BLST_BAD_ENCODING;
    // this is optional to do, we may lazy init it
    _ = getMemoryPool(null) catch return c.BLST_BAD_ENCODING;
    return c.BLST_SUCCESS;
}

/// a Bun application should call this after using any of the exported functions
export fn deinit() void {
    deinitializeThreadPool();
    if (memory_pool) |pool| {
        const allocator = pool.allocator;
        pool.deinit();
        allocator.destroy(pool);
    }
}

test "test_sign_n_verify" {
    try SigVariant.testSignNVerify();
}

test "test_aggregate" {
    try SigVariant.testAggregate(true);
}

test "test_aggregate with aggregateVerifyC" {
    try SigVariant.testAggregate(false);
}

test "test_multiple_agg_sigs" {
    try SigVariant.testMultipleAggSigs(true);
}

test "test_verify_multiple_aggregate_signatures" {
    try SigVariant.testMultipleAggSigs(false);
}

test "test_serialization" {
    try SigVariant.testSerialization();
}

test "test_serde" {
    try SigVariant.testSerde();
}

// prerequisite for test_multi_point
test "multi_point_test_type_alignment" {
    try SigVariant.testTypeAlignment();
}

test "multi_point_test_add_pubkey" {
    try SigVariant.testAddPubkey();
}

test "multi_point_test_mult_pubkey" {
    try SigVariant.testMultPubkey();
}

test "multi_point_test_add_signature" {
    try SigVariant.testAddSig();
}

test "multi_point_test_mult_signature" {
    try SigVariant.testMultSig();
}

test "test_multi_point" {
    try SigVariant.testMultiPoint();
}

test "test_aggregate_with_randomness" {
    try SigVariant.testAggregateWithRandomness();
}

test "verify_multipleaggregatesignatures" {
    // sanity test for verifyMultipleAggregateSignatures, we already test verifyMultipleAggregateSignaturesC inside sig_variant
    const msg0 = [_]u8{0} ** 32;
    var sk0 = defaultSecretKey();
    var ikm = [_]u8{0} ** 32;
    var res = secretKeyGen(&sk0, &ikm[0], ikm.len, null, 0);
    try std.testing.expect(res == 0);

    var pk0 = defaultPublicKey();
    secretKeyToPublicKey(&pk0, &sk0);

    var sig0 = defaultSignature();
    sign(&sig0, &sk0, &msg0[0], msg0.len);

    const set: SignatureSetType = .{
        .msg = &msg0[0],
        .pk = &pk0,
        .sig = &sig0,
    };
    var sets = [_]*const SignatureSetType{&set};

    try initializeThreadPool(null);
    defer deinitializeThreadPool();
    res = verifyMultipleAggregateSignatures(&sets[0], 1, msg0.len, false, false);
    try std.testing.expect(res == 0);
}
