const Topics = @import("metrics.zig").Topics;
const policy = @import("topic_policy.zig");
const std = @import("std");
const topic = @import("topic.zig");

test "metric topic labels have a fixed vocabulary and canonical subnet bounds" {
    try std.testing.expectEqual(@as(u16, 63), topic.Name.parse("beacon_attestation_63").?.subnet);
    try std.testing.expectEqual(@as(u16, 127), topic.Name.parse("data_column_sidecar_127").?.subnet);
    for ([_][]const u8{ "beacon_attestation_64", "sync_committee_4", "data_column_sidecar_128", "blob_sidecar_000", "beacon_attestation_+1", "beacon_block\"\n" }) |invalid| {
        try std.testing.expectEqual(null, topic.Name.parse(invalid));
    }
    var counters: Topics = .{};
    counters.get("/eth2/00000000/unknown/ssz_snappy").accepted += 1;
    try std.testing.expectEqual(@as(u64, 1), counters.counts[policy.kind_count].accepted);
}
