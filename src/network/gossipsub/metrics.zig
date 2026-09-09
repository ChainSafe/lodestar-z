const std = @import("std");
const policy = @import("topic_policy.zig");
const topic = @import("topic.zig");

pub const Topic = struct {
    kind: policy.Kind,
    subnet: u16 = 0,

    pub fn parse(name: []const u8) ?Topic {
        if (name.len > topic.name_max_len) return null;
        inline for (@typeInfo(policy.Kind).@"enum".fields) |field| {
            const kind: policy.Kind = @enumFromInt(field.value);
            if (comptime kind.countMax() == 1) {
                if (std.mem.eql(u8, name, field.name)) return .{ .kind = kind };
            } else if (std.mem.startsWith(u8, name, field.name ++ "_")) {
                const suffix = name[field.name.len + 1 ..];
                if (suffix.len == 0 or suffix.len > 3 or (suffix.len > 1 and suffix[0] == '0')) return null;
                for (suffix) |char| if (!std.ascii.isDigit(char)) return null;
                const subnet = std.fmt.parseInt(u16, suffix, 10) catch return null;
                if (subnet >= kind.countMax()) return null;
                return .{ .kind = kind, .subnet = subnet };
            }
        }
        return null;
    }
};

pub const ValidationTime = @import("../metrics_histogram.zig").Histogram(&.{ 10, 30, 100, 300, 1000, 3000, 10000 });

pub const Counters = struct {
    accepted: u64 = 0,
    rejected: u64 = 0,
    ignored: u64 = 0,
    published: u64 = 0,
    published_peers: u64 = 0,
    forwarded: u64 = 0,
    forwarded_peers: u64 = 0,
    admitted: u64 = 0,
    duplicates: u64 = 0,
};

pub const Topics = struct {
    counts: [policy.kind_count + 1]Counters = @splat(.{}),

    pub fn get(self: *Topics, wire: []const u8) *Counters {
        const parsed = topic.parse(wire) orelse return &self.counts[policy.kind_count];
        const known = Topic.parse(parsed.name) orelse return &self.counts[policy.kind_count];
        return &self.counts[@intFromEnum(known.kind)];
    }
};

test "metric topic labels have a fixed vocabulary and canonical subnet bounds" {
    try std.testing.expectEqual(@as(u16, 63), Topic.parse("beacon_attestation_63").?.subnet);
    try std.testing.expectEqual(@as(u16, 127), Topic.parse("data_column_sidecar_127").?.subnet);
    for ([_][]const u8{ "beacon_attestation_64", "sync_committee_4", "data_column_sidecar_128", "blob_sidecar_000", "beacon_attestation_+1", "beacon_block\"\n" }) |invalid| {
        try std.testing.expectEqual(null, Topic.parse(invalid));
    }
    var counters: Topics = .{};
    counters.get("/eth2/00000000/unknown/ssz_snappy").admitted += 1;
    try std.testing.expectEqual(@as(u64, 1), counters.counts[policy.kind_count].admitted);
}
