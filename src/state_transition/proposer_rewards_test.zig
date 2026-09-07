const std = @import("std");
const types = @import("consensus_types");
const preset = @import("preset").preset;
const constants = @import("constants");
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("test_utils/root.zig").TestCachedBeaconState;
const generateElectraBlock = @import("test_utils/root.zig").generateElectraBlock;
const processAttestations = @import("block/process_attestations.zig").processAttestations;
const processSyncAggregate = @import("block/process_sync_committee.zig").processSyncAggregate;
const slashValidator = @import("block/slash_validator.zig").slashValidator;
const ProposerRewards = @import("cache/state_cache.zig").ProposerRewards;

test "proposer rewards should report only new attestation participation and reset on clone" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 180_000 });
    defer pool.deinit();

    var fixture = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer fixture.deinit();
    const cached = fixture.cached_state;
    const state = cached.state.castToFork(.electra);
    var participation = try state.currentEpochParticipation();
    for (0..256) |index| try participation.set(index, 0);

    var block = types.electra.SignedBeaconBlock.default_value;
    defer types.electra.SignedBeaconBlock.deinit(allocator, &block);
    try generateElectraBlock(allocator, cached, &block);

    const proposer = try cached.getBeaconProposer(try state.slot());
    var balances = try state.balances();
    const balance_before = try balances.get(proposer);
    try processAttestations(.electra, allocator, std.testing.io, cached.config, cached.epoch_cache, state, &cached.proposer_rewards, &cached.slashings_cache, block.message.body.attestations.items, false);
    const rewards = cached.getProposerRewards();
    try std.testing.expect(rewards.attestations > 0);
    try std.testing.expectEqual(rewards.attestations, try balances.get(proposer) - balance_before);

    const root = (try cached.state.hashTreeRoot()).*;
    const cloned = try cached.clone(allocator, .{});
    defer {
        cloned.deinit();
        allocator.destroy(cloned);
    }
    try std.testing.expectEqualDeep(ProposerRewards{}, cloned.getProposerRewards());
    try std.testing.expectEqualDeep(rewards, cached.getProposerRewards());
    try std.testing.expectEqualDeep(root, (try cloned.state.hashTreeRoot()).*);

    try processAttestations(.electra, allocator, std.testing.io, cached.config, cached.epoch_cache, state, &cached.proposer_rewards, &cached.slashings_cache, block.message.body.attestations.items, false);
    try std.testing.expectEqual(@as(u64, 0), cached.getProposerRewards().attestations);
    try std.testing.expectEqual(balance_before + rewards.attestations, try balances.get(proposer));
}

test "proposer rewards should count sync positions without participant rewards" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 180_000 });
    defer pool.deinit();

    var fixture = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer fixture.deinit();
    const cached = fixture.cached_state;
    const state = cached.state.castToFork(.electra);
    const epoch_cache = cached.epoch_cache;
    const proposer = try cached.getBeaconProposer(try state.slot());
    const indices = epoch_cache.current_sync_committee_indexed.get().getValidatorIndices();
    var proposer_positions: u64 = 0;
    var aggregate = types.electra.SyncAggregate.default_value;
    for (0..preset.SYNC_COMMITTEE_SIZE) |index| {
        try aggregate.sync_committee_bits.set(index, true);
        if (indices[index] == proposer) proposer_positions += 1;
    }
    var balances = try state.balances();
    const before = try balances.get(proposer);
    try processSyncAggregate(.electra, allocator, std.testing.io, cached.config, epoch_cache, state, &cached.proposer_rewards, &aggregate, false);
    const expected = preset.SYNC_COMMITTEE_SIZE * epoch_cache.sync_proposer_reward;
    try std.testing.expect(expected > 0);
    try std.testing.expectEqual(expected, cached.getProposerRewards().sync_aggregate);
    try std.testing.expectEqual(expected + proposer_positions * epoch_cache.sync_participant_reward, try balances.get(proposer) - before);
}

test "proposer rewards should accumulate slashing rewards with and without a whistleblower" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 180_000 });
    defer pool.deinit();

    var fixture = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer fixture.deinit();
    const cached = fixture.cached_state;
    const state = cached.state.castToFork(.electra);
    const proposer = try cached.getBeaconProposer(try state.slot());
    const slashed = (proposer + 1) % 256;
    const second_slashed = (proposer + 2) % 256;
    const whistleblower = (proposer + 3) % 256;
    const reward = 32_000_000_000 / preset.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
    const proposer_share = reward * constants.PROPOSER_WEIGHT / constants.WEIGHT_DENOMINATOR;
    var balances = try state.balances();
    const before = try balances.get(proposer);
    const whistleblower_before = try balances.get(whistleblower);

    try @import("cache/slashings_cache.zig").buildFromStateIfNeeded(allocator, state, &cached.slashings_cache);
    try slashValidator(.electra, cached.config, cached.epoch_cache, state, &cached.proposer_rewards, &cached.slashings_cache, slashed, null);
    try std.testing.expectEqual(@as(u64, reward), cached.getProposerRewards().slashing);
    try slashValidator(.electra, cached.config, cached.epoch_cache, state, &cached.proposer_rewards, &cached.slashings_cache, second_slashed, whistleblower);
    try std.testing.expectEqual(@as(u64, reward + proposer_share), cached.getProposerRewards().slashing);
    try std.testing.expectEqual(@as(u64, reward + proposer_share), try balances.get(proposer) - before);
    try std.testing.expectEqual(@as(u64, reward - proposer_share), try balances.get(whistleblower) - whistleblower_before);
}
