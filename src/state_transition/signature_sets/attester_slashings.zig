const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const AggregatedSignatureSet = @import("../utils/signature_sets.zig").AggregatedSignatureSet;
const getIndexedAttestationSignatureSet = @import("./indexed_attestation.zig").getIndexedAttestationSignatureSet;
const AnyAttesterSlashingItems = @import("fork_types").AnyAttesterSlashingItems;

pub fn attesterSlashingsSignatureSets(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    attester_slashings: AnyAttesterSlashingItems,
    out: *std.ArrayList(AggregatedSignatureSet),
) !void {
    switch (attester_slashings) {
        .phase0 => |slashings| {
            for (slashings) |*slashing| {
                const set_1 = try getIndexedAttestationSignatureSet(.phase0, allocator, config, epoch_cache, &slashing.attestation_1);
                try out.append(allocator, set_1);
                const set_2 = try getIndexedAttestationSignatureSet(.phase0, allocator, config, epoch_cache, &slashing.attestation_2);
                try out.append(allocator, set_2);
            }
        },
        .electra => |slashings| {
            for (slashings) |*slashing| {
                const set_1 = try getIndexedAttestationSignatureSet(.electra, allocator, config, epoch_cache, &slashing.attestation_1);
                try out.append(allocator, set_1);
                const set_2 = try getIndexedAttestationSignatureSet(.electra, allocator, config, epoch_cache, &slashing.attestation_2);
                try out.append(allocator, set_2);
            }
        },
    }
}
