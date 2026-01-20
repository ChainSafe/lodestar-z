const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const BeaconState = @import("../types/beacon_state.zig").BeaconState;
const EpochCacheImmutableData = @import("../cache/epoch_cache.zig").EpochCacheImmutableData;
const types = @import("consensus_types");
const Epoch = types.primitive.Epoch.Type;
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const ForkTypes = @import("fork_types").ForkTypes;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const processAttestationPhase0 = @import("./process_attestation_phase0.zig").processAttestationPhase0;
const processAttestationsAltair = @import("./process_attestation_altair.zig").processAttestationsAltair;

pub fn processAttestations(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *ForkBeaconState(fork),
    attestations: []const ForkTypes(fork).Attestation.Type,
    verify_signatures: bool,
) !void {
    if (comptime fork == .phase0) {
        for (attestations) |attestation| {
            try processAttestationPhase0(allocator, config, epoch_cache, state, &attestation, verify_signatures);
        }
    } else {
        try processAttestationsAltair(fork, allocator, config, epoch_cache, state, attestations, verify_signatures);
    }
}

test "process attestations - sanity" {
    const allocator = std.testing.allocator;

    const Node = @import("persistent_merkle_tree").Node;

    // TODO re-enable when TestCachedBeaconState supports phase0
    // {
    //     var pool = try Node.Pool.init(allocator, 500_000);
    //     defer pool.deinit();
    //     var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    //     defer test_state.deinit();
    //     var phase0: std.ArrayListUnmanaged(types.phase0.Attestation.Type) = .empty;
    //     const attestation = types.phase0.Attestation.default_value;
    //     try phase0.append(allocator, attestation);
    //     const attestations = Attestations{ .phase0 = &phase0 };
    //     try std.testing.expectError(error.EpochShufflingNotFound, processAttestations(allocator, test_state.cached_state, attestations, true));
    //     phase0.deinit(allocator);
    // }
    {
        var pool = try Node.Pool.init(allocator, 500_000);
        defer pool.deinit();
        var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
        defer test_state.deinit();
        var electra: std.ArrayListUnmanaged(types.electra.Attestation.Type) = .empty;
        const attestation = types.electra.Attestation.default_value;
        try electra.append(allocator, attestation);
        try std.testing.expectError(
            error.EpochShufflingNotFound,
            processAttestations(allocator, test_state.cached_state, electra.items, true),
        );
        electra.deinit(allocator);
    }
}
