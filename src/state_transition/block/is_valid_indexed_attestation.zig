const std = @import("std");
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const ForkTypes = @import("fork_types").ForkTypes;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const verifyAggregatedSignatureSet = @import("../utils/signature_sets.zig").verifyAggregatedSignatureSet;
const getIndexedAttestationSignatureSet = @import("../signature_sets/indexed_attestation.zig").getIndexedAttestationSignatureSet;

pub fn isValidIndexedAttestation(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    validators_count: usize,
    indexed_attestation: *const ForkTypes(fork).IndexedAttestation.Type,
    verify_signature: bool,
) !bool {
    if (!(try isValidIndexedAttestationIndices(fork, validators_count, indexed_attestation.attesting_indices.items))) {
        return false;
    }

    if (verify_signature) {
        const signature_set = try getIndexedAttestationSignatureSet(
            fork,
            allocator,
            config,
            epoch_cache,
            indexed_attestation,
        );
        defer allocator.free(signature_set.pubkeys);
        return try verifyAggregatedSignatureSet(&signature_set);
    } else {
        return true;
    }
}

pub fn isValidIndexedAttestationIndices(
    comptime fork: ForkSeq,
    validators_count: usize,
    indices: []const ValidatorIndex,
) !bool {
    // verify max number of indices
    const max_indices: usize = if (fork.gte(.electra))
        preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT
    else
        preset.MAX_VALIDATORS_PER_COMMITTEE;

    if (!(indices.len > 0 and indices.len <= max_indices)) {
        return false;
    }

    // verify indices are sorted and unique.
    // Just check if they are monotonically increasing,
    // instead of creating a set and sorting it. Should be (O(n)) instead of O(n log(n))
    var prev: ValidatorIndex = 0;
    for (indices, 0..) |index, i| {
        if (i >= 1 and index <= prev) {
            return false;
        }
        prev = index;
    }

    // check if indices are out of bounds, by checking the highest index (since it is sorted).
    // After the uniqueness loop above, prev already holds the last (highest) index.
    // indices.len > 0 is guaranteed by the first check.
    if (prev >= validators_count) {
        return false;
    }

    return true;
}

test "isValidIndexedAttestationIndices - valid sorted unique indices" {
    const indices = [_]ValidatorIndex{ 0, 1, 5, 10, 100 };
    const result = try isValidIndexedAttestationIndices(.phase0, 200, &indices);
    try std.testing.expect(result);
}

test "isValidIndexedAttestationIndices - empty indices returns false" {
    const indices = [_]ValidatorIndex{};
    const result = try isValidIndexedAttestationIndices(.phase0, 200, &indices);
    try std.testing.expect(!result);
}

test "isValidIndexedAttestationIndices - single index valid" {
    const indices = [_]ValidatorIndex{42};
    const result = try isValidIndexedAttestationIndices(.phase0, 100, &indices);
    try std.testing.expect(result);
}

test "isValidIndexedAttestationIndices - duplicate indices returns false" {
    const indices = [_]ValidatorIndex{ 1, 1 };
    const result = try isValidIndexedAttestationIndices(.phase0, 200, &indices);
    try std.testing.expect(!result);
}

test "isValidIndexedAttestationIndices - unsorted indices returns false" {
    const indices = [_]ValidatorIndex{ 5, 3, 10 };
    const result = try isValidIndexedAttestationIndices(.phase0, 200, &indices);
    try std.testing.expect(!result);
}

test "isValidIndexedAttestationIndices - index out of bounds returns false" {
    const indices = [_]ValidatorIndex{ 0, 1, 200 };
    const result = try isValidIndexedAttestationIndices(.phase0, 200, &indices);
    try std.testing.expect(!result);
}

test "isValidIndexedAttestationIndices - index at boundary valid" {
    const indices = [_]ValidatorIndex{199};
    const result = try isValidIndexedAttestationIndices(.phase0, 200, &indices);
    try std.testing.expect(result);
}

test "isValidIndexedAttestationIndices - index at validators_count returns false" {
    const indices = [_]ValidatorIndex{200};
    const result = try isValidIndexedAttestationIndices(.phase0, 200, &indices);
    try std.testing.expect(!result);
}

test "isValidIndexedAttestationIndices - electra allows more indices" {
    // Phase0 max = MAX_VALIDATORS_PER_COMMITTEE (2048)
    // Electra max = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT
    var indices: [2049]ValidatorIndex = undefined;
    for (&indices, 0..) |*v, i| v.* = @intCast(i);

    const result_phase0 = try isValidIndexedAttestationIndices(.phase0, 10000, &indices);
    try std.testing.expect(!result_phase0);

    const result_electra = try isValidIndexedAttestationIndices(.electra, 10000, &indices);
    try std.testing.expect(result_electra);
}
