const std = @import("std");
const Stores = @import("network_storage.zig").Stores;

test "application typed store allocation prefixes release all requested bytes" {
    for ([_]usize{ 64, 512 }) |capacity| {
        for ([_]usize{ 1, 615, 1082 }) |topics| {
            var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            const stores = try Stores.createForTopics(measured.allocator(), capacity, topics);
            try std.testing.expectEqual(Stores.bytesForTopics(capacity, topics), measured.allocated_bytes);
            for (&stores.gossip_diagnostics) |*page| {
                try std.testing.expectEqual(topics, page.topics.len);
                for (page.peers) |peer| try std.testing.expectEqual(topics, peer.topics.len);
            }
            stores.destroy();
            try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
            for (0..measured.alloc_index) |prefix| {
                var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = prefix });
                try std.testing.expectError(error.OutOfMemory, Stores.createForTopics(failing.allocator(), capacity, topics));
                try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            }
        }
    }
}
