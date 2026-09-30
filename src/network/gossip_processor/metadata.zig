const std = @import("std");
const Kind = @import("../gossip_limits.zig").Kind;

pub const Metadata = struct {
    slot: ?u64 = null,
    root: ?[32]u8 = null,
    group: ?[128]u8 = null,
};

pub fn extract(kind: Kind, electra: bool, data: []const u8) Metadata {
    const offset: usize = switch (kind) {
        .beacon_block => 100,
        .beacon_attestation => if (electra) 16 else 4,
        .beacon_aggregate_and_proof => 212,
        .blob_sidecar => 8 + 131072 + 96,
        .data_column_sidecar => 20,
        else => return .{},
    };
    if (data.len < offset + 8) return .{};
    const slot = std.mem.readInt(u64, data[offset..][0..8], .little);
    var result: Metadata = .{ .slot = slot };
    if ((kind == .beacon_attestation or kind == .beacon_aggregate_and_proof) and data.len >= offset + 48) result.root = data[offset + 16 ..][0..32].*;
    if (kind == .beacon_attestation and data.len >= offset + 128) result.group = data[offset..][0..128].*;
    return result;
}

pub fn eligible(metadata: *const Metadata, kind: Kind, deneb: bool, slot: u64) bool {
    const message_slot = metadata.slot orelse return true;
    const slots = @import("preset").preset.SLOTS_PER_EPOCH;
    const attestation = kind == .beacon_attestation or kind == .beacon_aggregate_and_proof;
    // Slot-only admission retains the previous-slot clock-disparity allowance. The host
    // applies the exact time bound before accepting either form of attestation.
    const earliest_current = if (attestation) slot -| 1 else slot;
    const earliest = if (deneb and attestation) (earliest_current / slots -| 1) * slots else earliest_current -| 32;
    return message_slot >= earliest and message_slot <= slot +| 1;
}

test {
    _ = @import("metadata_test.zig");
}
