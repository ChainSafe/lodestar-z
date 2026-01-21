const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const BlockType = @import("fork_types").BlockType;
const ForkBeaconBlockBody = @import("fork_types").ForkBeaconBlockBody;
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;
const verifyRandaoSignature = @import("../signature_sets/randao.zig").verifyRandaoSignature;
const digest = @import("../utils/sha256.zig").digest;

pub fn processRandao(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    comptime block_type: BlockType,
    body: ForkBeaconBlockBody(fork, block_type),
    proposer_idx: u64,
    verify_signature: bool,
) !void {
    const epoch = epoch_cache.epoch;
    const randao_reveal = body.inner.randao_reveal;

    // verify RANDAO reveal
    if (verify_signature) {
        if (!try verifyRandaoSignature(fork, config, epoch_cache, state, block_type, body, try state.slot(), proposer_idx)) {
            return error.InvalidRandaoSignature;
        }
    }

    // mix in RANDAO reveal
    var randao_reveal_digest: [32]u8 = undefined;
    digest(&randao_reveal, &randao_reveal_digest);

    var randao_mix: [32]u8 = undefined;
    const current_mix = try getRandaoMix(fork, state, epoch);
    xor(current_mix, &randao_reveal_digest, &randao_mix);
    try state.setRandaoMix(epoch, &randao_mix);
}

fn xor(a: *const [32]u8, b: *const [32]u8, out: *[32]u8) void {
    inline for (a, b, out) |a_i, b_i, *out_i| {
        out_i.* = a_i ^ b_i;
    }
}
