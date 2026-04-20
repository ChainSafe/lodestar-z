const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const AttestationData = types.phase0.AttestationData.Type;
const AttesterSlashing = types.phase0.AttesterSlashing.Type;

const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Slot = types.primitive.Slot.Type;

pub fn isSlashableAttestationData(data1: *const AttestationData, data2: *const AttestationData) bool {
    // Double vote
    if (!types.phase0.AttestationData.equals(data1, data2) and data1.target.epoch == data2.target.epoch) {
        return true;
    }
    // Surround vote
    if (data1.source.epoch < data2.source.epoch and data2.target.epoch < data1.target.epoch) {
        return true;
    }
    return false;
}

/// Two-pointer sorted merge membership check for attesting indices to slash without auxiliary allocations.
///
/// Pre-requisite: isValidIndexedAttestation already checks for attesting indices to be sorted and unique.
/// Without that check, this would be incorrect.
pub fn findAttesterSlashableIndices(attester_slashing: *const AttesterSlashing, indices: *std.ArrayList(ValidatorIndex)) !void {
    const a = attester_slashing.attestation_1.attesting_indices.items;
    const b = attester_slashing.attestation_2.attesting_indices.items;
    var i: usize = 0;
    var j: usize = 0;
    while (i < a.len and j < b.len) {
        if (a[i] == b[j]) {
            try indices.append(a[i]);
            i += 1;
            j += 1;
        } else if (a[i] < b[j]) {
            i += 1;
        } else {
            j += 1;
        }
    }
    // we must reach the end of one of the indices
    std.debug.assert(i == a.len or j == b.len);
}

test "isSlashableAttestationData - double vote" {
    // Same target epoch, different data = double vote
    const data1 = AttestationData{
        .slot = 10,
        .index = 0,
        .beacon_block_root = [_]u8{0xaa} ** 32,
        .source = .{ .epoch = 1, .root = [_]u8{0} ** 32 },
        .target = .{ .epoch = 5, .root = [_]u8{0x11} ** 32 },
    };
    const data2 = AttestationData{
        .slot = 10,
        .index = 0,
        .beacon_block_root = [_]u8{0xbb} ** 32, // different block root
        .source = .{ .epoch = 1, .root = [_]u8{0} ** 32 },
        .target = .{ .epoch = 5, .root = [_]u8{0x22} ** 32 }, // same epoch, different root
    };
    try std.testing.expect(isSlashableAttestationData(&data1, &data2));
}

test "isSlashableAttestationData - surround vote" {
    // data1 surrounds data2: source1 < source2 AND target2 < target1
    const data1 = AttestationData{
        .slot = 10,
        .index = 0,
        .beacon_block_root = [_]u8{0} ** 32,
        .source = .{ .epoch = 1, .root = [_]u8{0} ** 32 },
        .target = .{ .epoch = 10, .root = [_]u8{0} ** 32 },
    };
    const data2 = AttestationData{
        .slot = 10,
        .index = 0,
        .beacon_block_root = [_]u8{0} ** 32,
        .source = .{ .epoch = 3, .root = [_]u8{0} ** 32 },
        .target = .{ .epoch = 7, .root = [_]u8{0} ** 32 },
    };
    try std.testing.expect(isSlashableAttestationData(&data1, &data2));
}

test "isSlashableAttestationData - identical data is not slashable" {
    const data = AttestationData{
        .slot = 10,
        .index = 0,
        .beacon_block_root = [_]u8{0} ** 32,
        .source = .{ .epoch = 1, .root = [_]u8{0} ** 32 },
        .target = .{ .epoch = 5, .root = [_]u8{0} ** 32 },
    };
    // Identical data — not a double vote (same attestation, not slashable)
    try std.testing.expect(!isSlashableAttestationData(&data, &data));
}

test "isSlashableAttestationData - different epochs not surrounding" {
    const data1 = AttestationData{
        .slot = 10,
        .index = 0,
        .beacon_block_root = [_]u8{0} ** 32,
        .source = .{ .epoch = 1, .root = [_]u8{0} ** 32 },
        .target = .{ .epoch = 5, .root = [_]u8{0} ** 32 },
    };
    const data2 = AttestationData{
        .slot = 20,
        .index = 0,
        .beacon_block_root = [_]u8{0} ** 32,
        .source = .{ .epoch = 3, .root = [_]u8{0} ** 32 },
        .target = .{ .epoch = 8, .root = [_]u8{0} ** 32 },
    };
    // Different target epochs and no surround = not slashable
    try std.testing.expect(!isSlashableAttestationData(&data1, &data2));
}

test "findAttesterSlashableIndices - common indices" {
    const allocator = std.testing.allocator;

    // Simulate an AttesterSlashing with overlapping attesting indices
    // attestation_1 indices: [1, 3, 5, 7]
    // attestation_2 indices: [2, 3, 6, 7]
    // expected intersection: [3, 7]
    var att1_indices = try std.ArrayList(ValidatorIndex).initCapacity(allocator, 4);
    defer att1_indices.deinit();
    try att1_indices.appendSlice(&.{ 1, 3, 5, 7 });

    var att2_indices = try std.ArrayList(ValidatorIndex).initCapacity(allocator, 4);
    defer att2_indices.deinit();
    try att2_indices.appendSlice(&.{ 2, 3, 6, 7 });

    var slashing = AttesterSlashing{
        .attestation_1 = .{
            .attesting_indices = .{ .items = att1_indices.items, .capacity = att1_indices.capacity },
            .data = .{
                .slot = 0,
                .index = 0,
                .beacon_block_root = [_]u8{0} ** 32,
                .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
                .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            },
            .signature = [_]u8{0} ** 96,
        },
        .attestation_2 = .{
            .attesting_indices = .{ .items = att2_indices.items, .capacity = att2_indices.capacity },
            .data = .{
                .slot = 0,
                .index = 0,
                .beacon_block_root = [_]u8{0} ** 32,
                .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
                .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            },
            .signature = [_]u8{0} ** 96,
        },
    };

    var result = std.ArrayList(ValidatorIndex).init(allocator);
    defer result.deinit();
    try findAttesterSlashableIndices(&slashing, &result);

    try std.testing.expectEqual(@as(usize, 2), result.items.len);
    try std.testing.expectEqual(@as(ValidatorIndex, 3), result.items[0]);
    try std.testing.expectEqual(@as(ValidatorIndex, 7), result.items[1]);
}

test "findAttesterSlashableIndices - no overlap" {
    const allocator = std.testing.allocator;

    var att1_indices = try std.ArrayList(ValidatorIndex).initCapacity(allocator, 3);
    defer att1_indices.deinit();
    try att1_indices.appendSlice(&.{ 1, 3, 5 });

    var att2_indices = try std.ArrayList(ValidatorIndex).initCapacity(allocator, 3);
    defer att2_indices.deinit();
    try att2_indices.appendSlice(&.{ 2, 4, 6 });

    var slashing = AttesterSlashing{
        .attestation_1 = .{
            .attesting_indices = .{ .items = att1_indices.items, .capacity = att1_indices.capacity },
            .data = .{
                .slot = 0,
                .index = 0,
                .beacon_block_root = [_]u8{0} ** 32,
                .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
                .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            },
            .signature = [_]u8{0} ** 96,
        },
        .attestation_2 = .{
            .attesting_indices = .{ .items = att2_indices.items, .capacity = att2_indices.capacity },
            .data = .{
                .slot = 0,
                .index = 0,
                .beacon_block_root = [_]u8{0} ** 32,
                .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
                .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            },
            .signature = [_]u8{0} ** 96,
        },
    };

    var result = std.ArrayList(ValidatorIndex).init(allocator);
    defer result.deinit();
    try findAttesterSlashableIndices(&slashing, &result);

    try std.testing.expectEqual(@as(usize, 0), result.items.len);
}
