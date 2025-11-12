const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const TestCachedBeaconStateAllForks = @import("../test_utils/root.zig").TestCachedBeaconStateAllForks;
const BeaconStateAllForks = @import("../types/beacon_state.zig").BeaconStateAllForks;
const EpochCacheImmutableData = @import("../cache/epoch_cache.zig").EpochCacheImmutableData;
const ct = @import("consensus_types");
const Epoch = ct.primitive.Epoch.Type;
const preset = @import("preset").preset;
const ForkSeq = @import("config").ForkSeq;
const Attestations = @import("../types/attestation.zig").Attestations;
const processAttestationPhase0 = @import("./process_attestation_phase0.zig").processAttestationPhase0;
const processAttestationsAltair = @import("./process_attestation_altair.zig").processAttestationsAltair;

pub fn processAttestations(allocator: Allocator, cached_state: *CachedBeaconStateAllForks, attestations: Attestations, verify_signatures: bool) !void {
    const state = cached_state.state;
    switch (attestations) {
        .phase0 => |attestations_phase0| {
            if (state.isPostAltair()) {
                // altair to deneb
                try processAttestationsAltair(allocator, cached_state, ct.phase0.Attestation.Type, attestations_phase0.items, verify_signatures);
            } else {
                // phase0
                for (attestations_phase0.items) |attestation| {
                    try processAttestationPhase0(allocator, cached_state, &attestation, verify_signatures);
                }
            }
        },
        .electra => |attestations_electra| {
            try processAttestationsAltair(allocator, cached_state, ct.electra.Attestation.Type, attestations_electra.items, verify_signatures);
        },
    }
}

test "process attestations - sanity" {
    const allocator = std.testing.allocator;

    {
        var test_state = try TestCachedBeaconStateAllForks.init(allocator, 16);
        defer test_state.deinit();
        var phase0: std.ArrayListUnmanaged(ct.phase0.Attestation.Type) = .empty;
        const attestation = ct.phase0.Attestation.default_value;
        try phase0.append(allocator, attestation);
        const attestations = Attestations{ .phase0 = &phase0 };
        try std.testing.expectError(error.EpochShufflingNotFound, processAttestations(allocator, test_state.cached_state, attestations, true));
        phase0.deinit(allocator);
    }
    {
        var test_state = try TestCachedBeaconStateAllForks.init(allocator, 16);
        defer test_state.deinit();
        var electra: std.ArrayListUnmanaged(ct.electra.Attestation.Type) = .empty;
        const attestation = ct.electra.Attestation.default_value;
        try electra.append(allocator, attestation);
        const attestations = Attestations{ .electra = &electra };
        try std.testing.expectError(error.EpochShufflingNotFound, processAttestations(allocator, test_state.cached_state, attestations, true));
        electra.deinit(allocator);
    }
}
