const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const Body = @import("../types/block.zig").Body;
const Bytes32 = types.primitive.Bytes32.Type;
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;
const verifyRandaoSignature = @import("../signature_sets/randao.zig").verifyRandaoSignature;
const digest = @import("../utils/sha256.zig").digest;

pub fn processRandao(
    cached_state: *CachedBeaconState,
    body: Body,
    proposer_idx: u64,
    verify_signature: bool,
) !void {
    const state = cached_state.state;
    const epoch_cache = cached_state.getEpochCache();
    const epoch = epoch_cache.epoch;
    const randao_reveal = body.randaoReveal();

    // verify RANDAO reveal
    if (verify_signature) {
        if (!try verifyRandaoSignature(cached_state, body, try cached_state.state.slot(), proposer_idx)) {
            return error.InvalidRandaoSignature;
        }
    }

    // mix in RANDAO reveal
    var randao_reveal_digest: [32]u8 = undefined;
    digest(&randao_reveal, &randao_reveal_digest);

    var randao_mix: [32]u8 = undefined;
    const current_mix = try getRandaoMix(state, epoch);
    xor(current_mix, &randao_reveal_digest, &randao_mix);
    try state.setRandaoMix(epoch, &randao_mix);
}

fn xor(a: *const [32]u8, b: *const [32]u8, out: *[32]u8) void {
    inline for (a, b, out) |a_i, b_i, *out_i| {
        out_i.* = a_i ^ b_i;
    }
}
