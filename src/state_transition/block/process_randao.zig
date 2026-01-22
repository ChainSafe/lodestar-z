const std = @import("std");
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
    beacon_config: *const BeaconConfig,
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
        if (!try verifyRandaoSignature(fork, beacon_config, epoch_cache, state, block_type, body, try state.slot(), proposer_idx)) {
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

const types = @import("consensus_types");
const preset = @import("preset").preset;
const config = @import("config");
const BeaconBlock = @import("../types/beacon_block.zig").BeaconBlock;
const Block = @import("../types/block.zig").Block;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
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

    const fork_state = switch (test_state.cached_state.state.*) {
        .electra => |*state_view| @as(*ForkBeaconState(.electra), @ptrCast(state_view)),
        else => return error.UnexpectedForkSeq,
    };
    const fork_body = ForkBeaconBlockBody(.electra, .full){ .inner = message.body };

    try processRandao(
        .electra,
        test_state.cached_state.config,
        test_state.cached_state.getEpochCache(),
        fork_state,
        .full,
        fork_body,
        block.proposerIndex(),
        false,
    );
}
