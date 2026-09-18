const ItemKind = std.meta.Tag(Item);
const Rpc = @import("metrics.zig").Rpc;
const Topics = @import("metrics.zig").Topics;
const policy = @import("topic_policy.zig");
const std = @import("std");
const topic = @import("topic.zig");
const Item = @import("protobuf.zig").Item;

test "metric topic labels have a fixed vocabulary and canonical subnet bounds" {
    try std.testing.expectEqual(@as(u16, 63), topic.Name.parse("beacon_attestation_63").?.subnet);
    try std.testing.expectEqual(@as(u16, 127), topic.Name.parse("data_column_sidecar_127").?.subnet);
    for ([_][]const u8{ "beacon_attestation_64", "sync_committee_4", "data_column_sidecar_128", "blob_sidecar_000", "beacon_attestation_+1", "beacon_block\"\n" }) |invalid| {
        try std.testing.expectEqual(null, topic.Name.parse(invalid));
    }
    var counters: Topics = .{};
    counters.get("/eth2/00000000/unknown/ssz_snappy").admitted += 1;
    try std.testing.expectEqual(@as(u64, 1), counters.counts[policy.kind_count].admitted);
}

test "RPC metrics count multiple control items as one control frame" {
    var rpc: Rpc = .{};
    var had_control = false;
    rpc.observeItem(.{ .message = .{ .data = "payload", .topic = "unknown" } }, &had_control);
    try std.testing.expectEqual(@as(u64, 0), rpc.control_frames_received);
    rpc.observeItem(.{ .graft = "unknown" }, &had_control);
    rpc.observeItem(.{ .prune = .{} }, &had_control);
    try std.testing.expectEqual(@as(u64, 1), rpc.control_frames_received);
    had_control = false;
    rpc.observeItem(.{ .graft = "unknown" }, &had_control);
    try std.testing.expectEqual(@as(u64, 2), rpc.control_frames_received);
    try std.testing.expectEqual(@as(u64, 2), rpc.items[@intFromEnum(ItemKind.graft)]);
    try std.testing.expectEqual(@as(u64, 1), rpc.items[@intFromEnum(ItemKind.prune)]);
}
