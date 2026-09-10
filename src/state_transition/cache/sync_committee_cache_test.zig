//! Tests for `sync_committee_cache.zig`.

const std = @import("std");
const ValidatorIndex = @import("consensus_types").primitive.ValidatorIndex.Type;
const SyncCommitteeCache = @import("sync_committee_cache.zig").SyncCommitteeCache;

test "memory_safety: initValidatorIndices should release cloned indices on init failure" {
    const indices = [_]ValidatorIndex{ 0, 1, 2 };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });

    try std.testing.expectError(
        error.OutOfMemory,
        SyncCommitteeCache.initValidatorIndices(failing.allocator(), &indices),
    );
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}
