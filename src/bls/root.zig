/// this is equivalent of Rust binding in blst/bindings/rust/src/lib.rs
const std = @import("std");
const testing = std.testing;
const SecretKey = @import("./secret_key.zig").SecretKey;
const PublicKey = @import("./public_key.zig").PublicKey;
const Signature = @import("./signature.zig").Signature;
const AggregateSignature = @import("./signature.zig").AggregateSignature;

const c = @cImport({
    @cInclude("blst.h");
});

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

// TODO: implement MultiPoint

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
