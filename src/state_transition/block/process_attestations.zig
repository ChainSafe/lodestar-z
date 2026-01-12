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
const Attestations = @import("../types/attestation.zig").Attestations;
const processAttestationPhase0 = @import("./process_attestation_phase0.zig").processAttestationPhase0;
const processAttestationsAltair = @import("./process_attestation_altair.zig").processAttestationsAltair;

pub fn processAttestations(allocator: Allocator, cached_state: *CachedBeaconState, attestations: Attestations, verify_signatures: bool) !void {
    const state = &cached_state.state;
    switch (attestations) {
        .phase0 => |attestations_phase0| {
            if (state.forkSeq().gte(.altair)) {
                // altair to deneb
                try processAttestationsAltair(allocator, cached_state, types.phase0.Attestation.Type, attestations_phase0.items, verify_signatures);
            } else {
                // phase0
                for (attestations_phase0.items) |attestation| {
                    try processAttestationPhase0(allocator, cached_state, &attestation, verify_signatures);
                }
            }
        },
        .electra => |attestations_electra| {
            try processAttestationsAltair(allocator, cached_state, types.electra.Attestation.Type, attestations_electra.items, verify_signatures);
        },
    }
}

test "process attestations - sanity" {
    const allocator = std.testing.allocator;

    const Node = @import("persistent_merkle_tree").Node;

    {
        var pool = try Node.Pool.init(allocator, 500_000);
        defer pool.deinit();
        var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
        defer test_state.deinit();
        var phase0: std.ArrayListUnmanaged(types.phase0.Attestation.Type) = .empty;
        const attestation = types.phase0.Attestation.default_value;
        try phase0.append(allocator, attestation);
        const attestations = Attestations{ .phase0 = &phase0 };
        try std.testing.expectError(error.EpochShufflingNotFound, processAttestations(allocator, test_state.cached_state, attestations, true));
        phase0.deinit(allocator);
    }
    {
        var pool = try Node.Pool.init(allocator, 500_000);
        defer pool.deinit();
        var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
        defer test_state.deinit();
        var electra: std.ArrayListUnmanaged(types.electra.Attestation.Type) = .empty;
        const attestation = types.electra.Attestation.default_value;
        try electra.append(allocator, attestation);
        const attestations = Attestations{ .electra = &electra };
        try std.testing.expectError(error.EpochShufflingNotFound, processAttestations(allocator, test_state.cached_state, attestations, true));
        electra.deinit(allocator);
    }
}
