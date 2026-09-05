const std = @import("std");
const config = @import("config");
const ct = @import("consensus_types");
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const active_preset = @import("preset").active_preset;
const preset = @import("preset").preset;
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("test_utils/root.zig").TestCachedBeaconState;
const getConfig = @import("test_utils/generate_state.zig").getConfig;
const EpochCache = @import("cache/epoch_cache.zig").EpochCache;
const EpochShuffling = @import("utils/epoch_shuffling.zig").EpochShuffling;
const PubkeyCache = @import("cache/pubkey_cache.zig").PubkeyCache;
const deserializeContainerOverrideFieldsWithRanges =
    @import("ssz_container.zig").deserializeContainerOverrideFieldsWithRanges;
const processRewardsAndPenalties =
    @import("epoch/process_rewards_and_penalties.zig").processRewardsAndPenalties;
const upgradeStateToCapella = @import("slot/upgrade_state_to_capella.zig").upgradeStateToCapella;
const upgradeStateToDeneb = @import("slot/upgrade_state_to_deneb.zig").upgradeStateToDeneb;

test "EpochShuffling.init should free completed committees when a later slot allocation fails" {
    const allocator = std.testing.allocator;
    const active_indices = try allocator.alloc(ct.primitive.ValidatorIndex.Type, 256);
    defer allocator.free(active_indices);
    for (active_indices, 0..) |*index, i| {
        index.* = @intCast(i);
    }

    // The shuffling and first slot allocations succeed; the second slot allocation fails.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 2 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        EpochShuffling.init(
            failing.allocator(),
            [_]u8{0} ** 32,
            0,
            active_indices,
        ),
    );
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "EpochShuffling.init should free committees when the final allocation fails" {
    const allocator = std.testing.allocator;
    const active_indices = try allocator.alloc(ct.primitive.ValidatorIndex.Type, 256);
    defer allocator.free(active_indices);
    for (active_indices, 0..) |*index, i| {
        index.* = @intCast(i);
    }

    // One shuffling allocation and one allocation per slot precede the final struct allocation.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 + preset.SLOTS_PER_EPOCH },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        EpochShuffling.init(
            failing.allocator(),
            [_]u8{0} ** 32,
            0,
            active_indices,
        ),
    );
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "upgradeStateToCapella and upgradeStateToDeneb should release temporary payload headers" {
    const allocator = std.testing.allocator;
    const chain_config = if (active_preset == .mainnet)
        config.mainnet.chain_config
    else
        config.minimal.chain_config;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 345_000 });
    defer pool.deinit();

    var bellatrix_value = ct.bellatrix.BeaconState.default_value;
    defer ct.bellatrix.BeaconState.deinit(allocator, &bellatrix_value);
    bellatrix_value.fork = .{
        .previous_version = chain_config.ALTAIR_FORK_VERSION,
        .current_version = chain_config.BELLATRIX_FORK_VERSION,
        .epoch = 0,
    };
    try bellatrix_value.latest_execution_payload_header.extra_data.append(allocator, 0xaa);

    var state = try AnyBeaconState.fromValue(allocator, &pool, .bellatrix, &bellatrix_value);
    defer state.deinit();

    var pubkey_cache = PubkeyCache.init(allocator, std.testing.io);
    defer pubkey_cache.deinit();

    const beacon_config = config.BeaconConfig.init(
        getConfig(chain_config, .bellatrix, 0),
        (try state.genesisValidatorsRoot()).*,
    );
    const epoch_cache = try EpochCache.createFromState(
        allocator,
        std.testing.io,
        &state,
        .{
            .config = &beacon_config,
            .pubkey_cache = &pubkey_cache,
        },
        .{
            .skip_sync_committee_cache = true,
            .skip_sync_pubkeys = true,
        },
    );
    defer epoch_cache.deinit();

    // std.testing.allocator makes the test fail without an explicit expect if either upgrade
    // leaks its temporary payload header.
    const capella_state = try upgradeStateToCapella(
        allocator,
        &beacon_config,
        epoch_cache,
        state.castToFork(.bellatrix),
    );
    state = .{ .capella = capella_state.inner };

    const deneb_state = try upgradeStateToDeneb(
        allocator,
        &beacon_config,
        epoch_cache,
        state.castToFork(.capella),
    );
    state = .{ .deneb = deneb_state.inner };
}

test "deserializeContainerOverrideFields... cleans up pool nodes on error" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 64 });
    defer pool.deinit();

    const U64 = ssz.UintType(64);
    const U64List = ssz.FixedListType(U64, 4, .{});
    const Fields = struct {
        a: U64,
        b: U64List,
    };
    const ContainerST = ssz.VariableContainerType(Fields);

    // Valid offsets for `b`, but `b` payload length is 1 which is not divisible by 8.
    var bytes: [13]u8 = undefined;
    @memset(&bytes, 0);
    std.mem.writeInt(u32, bytes[8..12], 12, .little);

    const baseline_in_use = pool.getNodesInUse();
    const ranges = try ContainerST.readFieldRanges(bytes[0..]);
    try std.testing.expectError(
        error.UnexpectedRemainder,
        deserializeContainerOverrideFieldsWithRanges(
            allocator,
            &pool,
            ContainerST,
            bytes[0..],
            &ranges,
            .{},
        ),
    );
    try std.testing.expectEqual(baseline_in_use, pool.getNodesInUse());
}

test "processRewardsAndPenalties - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 200_000;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 10_000);
    defer test_state.deinit();

    try processRewardsAndPenalties(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        null,
    );

    // Verify replacing the old cached balances does not leak.
    try processRewardsAndPenalties(
        .electra,
        allocator,
        test_state.cached_state.config,
        test_state.cached_state.epoch_cache,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
        null,
    );
}

test "EpochCache.clone does not retain shared references when allocation fails" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 200_000,
    });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 256);
    defer test_state.deinit();

    var failing_allocator = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    // Leaked refs prevent test_state teardown from releasing the last shared owners.
    try std.testing.expectError(
        error.OutOfMemory,
        test_state.cached_state.epoch_cache.clone(failing_allocator.allocator()),
    );
}
