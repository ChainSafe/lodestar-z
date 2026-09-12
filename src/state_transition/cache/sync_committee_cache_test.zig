//! Tests for `sync_committee_cache.zig`.

const std = @import("std");
const ValidatorIndex = @import("consensus_types").primitive.ValidatorIndex.Type;
const SyncCommitteeCache = @import("sync_committee_cache.zig").SyncCommitteeCache;

test "memory_safety: initValidatorIndices should release cloned indices on init failure" {
    const indices = [_]ValidatorIndex{ 0, 1, 2 };
    var saw_oom = false;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, input: []const ValidatorIndex, failed: *bool) !void {
            errdefer failed.* = true;
            var cache = try SyncCommitteeCache.initValidatorIndices(allocator, input);
            defer cache.deinit();
            try std.testing.expectEqualSlices(ValidatorIndex, input, cache.getValidatorIndices());
        }
    }.run, .{ &indices, &saw_oom });
    try std.testing.expect(saw_oom);
}
