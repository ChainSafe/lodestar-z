const std = @import("std");
const config = @import("config");
const ct = @import("consensus_types");
const AnyBeaconState = @import("fork_types").AnyBeaconState;
const active_preset = @import("preset").active_preset;
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("test_utils/root.zig").TestCachedBeaconState;
const getConfig = @import("test_utils/generate_state.zig").getConfig;
const generateElectraState = @import("test_utils/generate_state.zig").generateElectraState;
const EpochCache = @import("cache/epoch_cache.zig").EpochCache;
const PubkeyCache = @import("cache/pubkey_cache.zig").PubkeyCache;
const deserializeContainerOverrideFieldsWithRanges =
    @import("ssz_container.zig").deserializeContainerOverrideFieldsWithRanges;
const processRewardsAndPenalties =
    @import("epoch/process_rewards_and_penalties.zig").processRewardsAndPenalties;
const processHistoricalRootsUpdate =
    @import("epoch/process_historical_roots_update.zig").processHistoricalRootsUpdate;
const processHistoricalSummariesUpdate =
    @import("epoch/process_historical_summaries_update.zig").processHistoricalSummariesUpdate;
const processSlot = @import("slot/process_slot.zig").processSlot;
const upgradeStateToCapella = @import("slot/upgrade_state_to_capella.zig").upgradeStateToCapella;
const upgradeStateToDeneb = @import("slot/upgrade_state_to_deneb.zig").upgradeStateToDeneb;
const preset = @import("preset").preset;
const Root = ct.primitive.Root.Type;

// Extends the pool length only to its allocated capacity, so storage does not move yet.
// Occupies every free slot, then reopens exactly `free_slot_count` slots.
// The caller owns the returned filler nodes and must unref them and deinit the list.
fn occupyPoolLeavingFreeSlots(
    allocator: std.mem.Allocator,
    pool: *Node.Pool,
    free_slot_count: usize,
) !std.ArrayList(Node.Id) {
    try pool.preheat(@intCast(pool.nodes.capacity - pool.nodes.len));

    var filler_nodes = try std.ArrayList(Node.Id).initCapacity(allocator, pool.nodes.len);
    errdefer filler_nodes.deinit(allocator);
    errdefer for (filler_nodes.items) |node| pool.unref(node);

    for (0..pool.nodes.len) |_| {
        if (@intFromEnum(pool.next_free_node) == pool.nodes.len) break;
        filler_nodes.appendAssumeCapacity(try pool.createLeafFromUint(0));
    }
    try std.testing.expectEqual(pool.nodes.len, @intFromEnum(pool.next_free_node));
    try std.testing.expect(filler_nodes.items.len >= free_slot_count);

    // The block-roots commit consumes the reopened slots, forcing the state-roots commit to grow
    // the pool.
    for (0..free_slot_count) |_| pool.unref(filler_nodes.pop().?);

    return filler_nodes;
}

test "upgradeStateToCapella and upgradeStateToDeneb should release temporary payload headers" {
    const allocator = std.testing.allocator;
    const chain_config = if (active_preset == .mainnet)
        config.mainnet.chain_config
    else
        config.minimal.chain_config;

    var pool = try Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 10_000,
    });
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
    const pool_size = 10_000 * 5;
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

test "historical summaries should preserve block root across pool growth" {
    const allocator = std.testing.allocator;
    const chain_config = if (active_preset == .mainnet)
        config.mainnet.chain_config
    else
        config.minimal.chain_config;

    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator });
    defer pool.deinit();

    const electra_chain_config = chain_config.merge(.{ .ELECTRA_FORK_EPOCH = 0 });
    const state = try generateElectraState(allocator, &pool, electra_chain_config, 8);
    var state_owned = true;
    defer if (state_owned) {
        state.deinit();
        allocator.destroy(state);
    };

    // This slot makes next_epoch enter the historical accumulator branch.
    const historical_slot = preset.SLOTS_PER_HISTORICAL_ROOT - 1;
    try state.setSlot(historical_slot);
    try state.commit();

    var fork_view = try state.fork();
    const fork_epoch = try fork_view.get("epoch");
    var test_state = try TestCachedBeaconState.initFromState(
        allocator,
        &pool,
        state,
        .electra,
        fork_epoch,
    );
    state_owned = false;
    defer test_state.deinit();

    // processSlot leaves block_roots and state_roots cached and dirty.
    try processSlot(test_state.cached_state.state);

    // Leave enough slots for block_roots to commit, forcing state_roots to grow the pool.
    var pool_filler_nodes = try occupyPoolLeavingFreeSlots(
        allocator,
        &pool,
        ct.phase0.HistoricalBlockRoots.chunk_depth,
    );
    defer {
        for (pool_filler_nodes.items) |node| pool.unref(node);
        pool_filler_nodes.deinit(allocator);
    }

    // Integer address and capacity checks prove movement without dereferencing the old pointer.
    const root_column_address_before = @intFromPtr(pool.nodes.items(.root).ptr);
    const pool_capacity_before = pool.nodes.capacity;
    try processHistoricalSummariesUpdate(
        .electra,
        test_state.cached_state.state.castToFork(.electra),
        test_state.epoch_transition_cache,
    );
    try std.testing.expect(pool.nodes.capacity > pool_capacity_before);
    try std.testing.expect(root_column_address_before != @intFromPtr(pool.nodes.items(.root).ptr));

    // Reread both roots from current storage before checking the appended summary.
    const expected_block_summary_root = (try test_state.cached_state.state.blockRootsRoot()).*;
    const expected_state_summary_root = (try test_state.cached_state.state.stateRootsRoot()).*;
    var historical_summaries = try test_state.cached_state.state.historicalSummaries();
    try std.testing.expectEqual(@as(usize, 1), try historical_summaries.length());

    var actual_summary: ct.capella.HistoricalSummary.Type = undefined;
    try historical_summaries.getValue(allocator, 0, &actual_summary);
    try std.testing.expectEqual(expected_block_summary_root, actual_summary.block_summary_root);
    try std.testing.expectEqual(expected_state_summary_root, actual_summary.state_summary_root);
}

test "historical roots should preserve block root across pool growth" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator });
    defer pool.deinit();

    const state = try allocator.create(AnyBeaconState);
    state.* = AnyBeaconState.fromValue(
        allocator,
        &pool,
        .phase0,
        &ct.phase0.BeaconState.default_value,
    ) catch |err| {
        allocator.destroy(state);
        return err;
    };
    var state_owned = true;
    defer if (state_owned) {
        state.deinit();
        allocator.destroy(state);
    };

    // This slot makes next_epoch enter the historical accumulator branch.
    const historical_slot = preset.SLOTS_PER_HISTORICAL_ROOT - 1;
    try state.setSlot(historical_slot);
    try state.commit();

    var test_state = try TestCachedBeaconState.initFromState(
        allocator,
        &pool,
        state,
        .phase0,
        0,
    );
    state_owned = false;
    defer test_state.deinit();

    // processSlot leaves block_roots and state_roots cached and dirty.
    try processSlot(test_state.cached_state.state);

    // Leave enough slots for block_roots to commit, forcing state_roots to grow the pool.
    var pool_filler_nodes = try occupyPoolLeavingFreeSlots(
        allocator,
        &pool,
        ct.phase0.HistoricalBlockRoots.chunk_depth,
    );
    defer {
        for (pool_filler_nodes.items) |node| pool.unref(node);
        pool_filler_nodes.deinit(allocator);
    }

    // Integer address and capacity checks prove movement without dereferencing the old pointer.
    const root_column_address_before = @intFromPtr(pool.nodes.items(.root).ptr);
    const pool_capacity_before = pool.nodes.capacity;
    try processHistoricalRootsUpdate(
        .phase0,
        test_state.cached_state.state.castToFork(.phase0),
        test_state.epoch_transition_cache,
    );
    try std.testing.expect(pool.nodes.capacity > pool_capacity_before);
    try std.testing.expect(root_column_address_before != @intFromPtr(pool.nodes.items(.root).ptr));

    // Reread both roots from current storage before checking the appended historical root.
    const expected_block_roots = (try test_state.cached_state.state.blockRootsRoot()).*;
    const expected_state_roots = (try test_state.cached_state.state.stateRootsRoot()).*;
    var expected_historical_root: Root = undefined;
    try ct.phase0.HistoricalBatchRoots.hashTreeRoot(&.{
        .block_roots = expected_block_roots,
        .state_roots = expected_state_roots,
    }, &expected_historical_root);

    var historical_roots = try test_state.cached_state.state.historicalRoots();
    try std.testing.expectEqual(@as(usize, 1), try historical_roots.length());
    var actual_historical_root: Root = undefined;
    try historical_roots.getValue(allocator, 0, &actual_historical_root);
    try std.testing.expectEqual(expected_historical_root, actual_historical_root);
}
