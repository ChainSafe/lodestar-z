const std = @import("std");
const Kind = @import("limits.zig").Kind;

pub const Metadata = struct {
    slot: ?u64 = null,
    root: ?[32]u8 = null,
    group: ?[128]u8 = null,
    await_block: bool = false,
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
    if (kind == .beacon_block or kind == .beacon_attestation or kind == .beacon_aggregate_and_proof) {
        if (data.len >= offset + 48) result.root = data[offset + 16 ..][0..32].*;
        result.await_block = kind != .beacon_block;
    }
    if (kind == .beacon_attestation and data.len >= offset + 128) result.group = data[offset..][0..128].*;
    return result;
}

pub fn eligible(metadata: *const Metadata, kind: Kind, deneb: bool, slot: u64) bool {
    const message_slot = metadata.slot orelse return true;
    const slots = @import("preset").preset.SLOTS_PER_EPOCH;
    const earliest = if (deneb and kind == .beacon_attestation) (slot / slots -| 1) * slots else slot -| 32;
    return message_slot >= earliest and message_slot <= slot +| 1;
}

test "gossip metadata bounds offsets and rejects far future retention" {
    const t = std.testing;
    var data: [240]u8 = @splat(0);
    std.mem.writeInt(u64, data[16..24], 9999999, .little);
    const meta = extract(.beacon_attestation, true, &data);
    try t.expect(!eligible(&meta, .beacon_attestation, true, 100));
    try t.expect(extract(.beacon_block, false, data[0..100]).slot == null);
    try t.expect(meta.group != null and meta.root != null and meta.await_block);
}
