const std = @import("std");
const Allocator = std.mem.Allocator;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const types = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const ForkTypes = @import("fork_types").ForkTypes;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const SlashingsCache = @import("../cache/slashings_cache.zig").SlashingsCache;
const processAttestationPhase0 = @import("./process_attestation_phase0.zig").processAttestationPhase0;
const processAttestationsAltair = @import("./process_attestation_altair.zig").processAttestationsAltair;
const Node = @import("persistent_merkle_tree").Node;

pub fn processAttestations(
    comptime fork: ForkSeq,
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    slashings_cache: *const SlashingsCache,
    attestations: []const ForkTypes(fork).Attestation.Type,
    verify_signatures: bool,
) !void {
    if (comptime fork == .phase0) {
        for (attestations) |attestation| {
            try processAttestationPhase0(
                allocator,
                config,
                epoch_cache,
                state,
                &attestation,
                verify_signatures,
            );
        }
    } else {
        try processAttestationsAltair(
            fork,
            allocator,
            config,
            epoch_cache,
            state,
            slashings_cache,
            attestations,
            verify_signatures,
        );
    }
}

test "process attestations - sanity" {
    const allocator = std.testing.allocator;
    const pool_size = 16 * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var electra: std.ArrayListUnmanaged(types.electra.Attestation.Type) = .empty;
    const attestation = types.electra.Attestation.default_value;
    try electra.append(allocator, attestation);
    try std.testing.expectError(
        error.EpochShufflingNotFound,
        processAttestations(
            .electra,
            allocator,
            test_state.cached_state.config,
            test_state.cached_state.getEpochCache(),
            test_state.cached_state.state.castToFork(.electra),
            &test_state.cached_state.slashings_cache,
            electra.items,
            true,
        ),
    );
    electra.deinit(allocator);
}
