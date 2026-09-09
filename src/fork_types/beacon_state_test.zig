const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const ct = @import("consensus_types");
const BeaconState = @import("beacon_state.zig").BeaconState;

const pool_size = 500_000;
const participation = [_]u8{ 1, 2, 4 };

fn initParticipationState(allocator: std.mem.Allocator, pool: *Node.Pool) !BeaconState(.altair) {
    var state: BeaconState(.altair) = .{
        .inner = try ct.altair.BeaconState.TreeView.fromValue(allocator, pool, &ct.altair.BeaconState.default_value),
    };
    errdefer state.deinit();

    const current = try state.currentEpochParticipation();
    for (participation) |flags| try current.push(flags);
    try state.commit();
    return state;
}

fn expectPreviousParticipation(state: *BeaconState(.altair)) !void {
    const previous = try state.previousEpochParticipation();
    try std.testing.expectEqual(participation.len, try previous.length());
    for (participation, 0..) |flags, index| {
        try std.testing.expectEqual(flags, try previous.get(index));
    }
}

test "rotateEpochParticipation preserves transferred view after pool exhaustion" {
    const allocator = std.testing.allocator;
    for (0..2) |remaining_slots| {
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
        defer pool.deinit();
        const initial_nodes = pool.getNodesInUse();

        {
            var state = try initParticipationState(allocator, &pool);
            defer state.deinit();

            const filler = try allocator.alloc(Node.Id, pool_size);
            defer allocator.free(filler);
            var filler_count: usize = 0;
            defer pool.free(filler[0..filler_count]);
            while (filler_count < filler.len) : (filler_count += 1) {
                filler[filler_count] = pool.createLeafFromUint(0) catch |err| switch (err) {
                    error.PoolExhausted => break,
                };
            }
            try std.testing.expectEqual(pool.nodes.len, @as(usize, @intFromEnum(pool.next_free_node)));
            for (0..remaining_slots) |_| {
                filler_count -= 1;
                pool.unref(filler[filler_count]);
            }
            const nodes_before = pool.getNodesInUse();

            try std.testing.expectError(error.PoolExhausted, state.rotateEpochParticipation());
            try std.testing.expectEqual(nodes_before, pool.getNodesInUse());
            try expectPreviousParticipation(&state);
        }

        try std.testing.expectEqual(initial_nodes, pool.getNodesInUse());
    }
}

test "rotateEpochParticipation preserves transferred view after replacement allocation failure" {
    const allocator = std.testing.allocator;
    for (1..3) |successful_allocations| {
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
        defer pool.deinit();
        const initial_nodes = pool.getNodesInUse();
        var failing = std.testing.FailingAllocator.init(allocator, .{});

        {
            var state = try initParticipationState(failing.allocator(), &pool);
            defer state.deinit();
            const nodes_before = pool.getNodesInUse();

            failing.fail_index = failing.alloc_index + successful_allocations;
            try std.testing.expectError(error.OutOfMemory, state.rotateEpochParticipation());
            failing.fail_index = std.math.maxInt(usize);

            try std.testing.expectEqual(nodes_before, pool.getNodesInUse());
            try expectPreviousParticipation(&state);
        }

        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        try std.testing.expectEqual(initial_nodes, pool.getNodesInUse());
    }
}

test "rotateEpochParticipation moves flags and resets current participation" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = pool_size });
    defer pool.deinit();

    var state = try initParticipationState(allocator, &pool);
    defer state.deinit();

    try state.rotateEpochParticipation();
    try state.commit();
    try expectPreviousParticipation(&state);

    const current = try state.currentEpochParticipation();
    try std.testing.expectEqual(participation.len, try current.length());
    for (0..participation.len) |index| {
        try std.testing.expectEqual(@as(u8, 0), try current.get(index));
    }
}
