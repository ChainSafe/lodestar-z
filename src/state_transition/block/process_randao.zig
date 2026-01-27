const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const config = @import("config");
const ForkSeq = config.ForkSeq;
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const Body = @import("../types/block.zig").Body;
const Bytes32 = types.primitive.Bytes32.Type;
const getRandaoMix = @import("../utils/seed.zig").getRandaoMix;
const verifyRandaoSignature = @import("../signature_sets/randao.zig").verifyRandaoSignature;
const Sha256 = std.crypto.hash.sha2.Sha256;

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
    Sha256.hash(&randao_reveal, &randao_reveal_digest, .{});

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

const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Block = @import("../types/block.zig").Block;
const Node = @import("persistent_merkle_tree").Node;

test "process randao - sanity" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    const slot = config.mainnet.chain_config.ELECTRA_FORK_EPOCH * preset.SLOTS_PER_EPOCH + 2025 * preset.SLOTS_PER_EPOCH - 1;
    defer test_state.deinit();

    const proposers = test_state.cached_state.getEpochCache().proposers;

    var message: types.electra.BeaconBlock.Type = types.electra.BeaconBlock.default_value;
    const proposer_index = proposers[slot % preset.SLOTS_PER_EPOCH];
    var header = try test_state.cached_state.state.latestBlockHeader();
    const header_parent_root = try header.hashTreeRoot();

    message.slot = slot;
    message.proposer_index = proposer_index;
    message.parent_root = header_parent_root.*;

    const beacon_block = BeaconBlock{ .electra = &message };
    const block = Block{ .regular = beacon_block };
    try processRandao(test_state.cached_state, block.beaconBlockBody(), block.proposerIndex(), false);
}
