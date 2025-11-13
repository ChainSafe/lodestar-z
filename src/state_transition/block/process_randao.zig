const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const Body = @import("../types/signed_block.zig").Body;
const Bytes32 = types.primitive.Bytes32.Type;
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;
const verifyRandaoSignature = @import("../signature_sets/randao.zig").verifyRandaoSignature;
const digest = @import("../utils/sha256.zig").digest;

pub fn processRandao(
    cached_state: *const CachedBeaconStateAllForks,
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
        if (!try verifyRandaoSignature(cached_state, body, cached_state.state.slot(), proposer_idx)) {
            return error.InvalidRandaoSignature;
        }
    }

    // mix in RANDAO reveal
    var randao_reveal_digest: [32]u8 = undefined;
    digest(&randao_reveal, &randao_reveal_digest);
    const randao_mix = xor(getRandaoMix(state, epoch), randao_reveal_digest);
    const state_randao_mixes = state.randaoMixes();
    state_randao_mixes[epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR] = randao_mix;
}

fn xor(a: Bytes32, b: Bytes32) Bytes32 {
    var result: Bytes32 = undefined;
    for (0..types.primitive.Bytes32.length) |i| {
        result[i] = a[i] ^ b[i];
    }
    return result;
}
