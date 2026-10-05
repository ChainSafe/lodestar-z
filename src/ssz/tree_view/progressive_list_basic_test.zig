const std = @import("std");
const Node = @import("persistent_merkle_tree").Node;
const ssz = @import("../type/root.zig");
const List = ssz.FixedProgressiveListType(ssz.UintType(64));
const allocator = std.testing.allocator;
const Allocator = std.mem.Allocator;
const zero_nodes = @import("hashing").max_depth;

fn expectRoot(comptime ST: type, view: *ST.TreeView, value: *const ST.Type) !void {
    var expected: [32]u8 = undefined;
    try ST.hashTreeRoot(allocator, value, &expected);
    try std.testing.expectEqualSlices(u8, &expected, try view.hashTreeRoot());
}

test "progressive basic view packed types and subtree boundaries" {
    inline for (.{ ssz.BoolType(), ssz.UintType(8), ssz.UintType(16), ssz.UintType(32), ssz.UintType(64), ssz.UintType(128), ssz.UintType(256) }) |Element| {
        const ST = ssz.FixedProgressiveListType(Element);
        var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 2048 });
        defer pool.deinit();
        {
            var value: ST.Type = .empty;
            defer value.deinit(allocator);
            const view = try ST.TreeView.fromValue(allocator, &pool, &value);
            defer view.deinit();
            const count = 86 * (32 / Element.fixed_size) + 1;
            for (0..count) |i| {
                const item: Element.Type = if (Element.Type == bool) i % 3 != 0 else @intCast(i % 251);
                try view.push(item);
                try value.append(allocator, item);
                if (i % (32 / Element.fixed_size) == 0) {
                    try std.testing.expectEqual(item, try view.get(i));
                }
            }
            const output = try allocator.alloc(Element.Type, count);
            defer allocator.free(output);
            _ = try view.getAllInto(output);
            try std.testing.expectEqualSlices(Element.Type, value.items, output);
            try expectRoot(ST, view, &value);
            var iterator = view.iteratorReadonly(3);
            for (value.items[3..]) |item| try std.testing.expectEqual(item, try iterator.next());
            try std.testing.expectError(error.InvalidLength, iterator.next());
            try std.testing.expectError(error.IndexOutOfBounds, view.get(count));
            try std.testing.expectError(error.IndexOutOfBounds, view.set(count, Element.default_value));
            try std.testing.expectError(error.InvalidLength, view.growTo(count - 1));
            try std.testing.expectError(error.LengthOverLimit, view.growTo(ST.TreeView.max_length + 1));
        }
        try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
    }
}

test "progressive basic view grows zero subtrees and slices shared prefixes" {
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();
    {
        var value: List.Type = .empty;
        defer value.deinit(allocator);
        const view = try List.TreeView.fromValue(allocator, &pool, &value);
        defer view.deinit();
        try view.growTo(345);
        try value.resize(allocator, 345);
        @memset(value.items, 0);
        for ([_]usize{ 0, 3, 4, 19, 20, 83, 84, 339, 340, 344 }) |i| {
            try view.set(i, i + 1);
            value.items[i] = i + 1;
        }
        var actual: [345]u64 = undefined;
        _ = try view.getAllInto(&actual);
        try std.testing.expectEqualSlices(u64, value.items, &actual);
        try expectRoot(List, view, &value);
        for ([_]usize{ 0, 2, 3, 4, 18, 19, 20, 82, 83, 84, 338, 339, 340, 344 }) |cut| {
            const sliced = try view.sliceTo(cut);
            defer sliced.deinit();
            var expected: List.Type = .empty;
            defer expected.deinit(allocator);
            try expected.appendSlice(allocator, value.items[0 .. cut + 1]);
            try expectRoot(List, sliced, &expected);
            try sliced.growTo(345);
            try expected.resize(allocator, 345);
            @memset(expected.items[cut + 1 ..], 0);
            try expectRoot(List, sliced, &expected);
        }
        try expectRoot(List, view, &value);
        try view.growTo(List.TreeView.max_length);
        try view.commit();
        try std.testing.expectEqual(@as(u64, 0), try view.get(List.TreeView.max_length - 1));
        try std.testing.expectError(error.LengthOverLimit, view.push(1));
        _ = try view.hashTreeRoot();
    }
    try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
}

test "progressive basic view clone transfer drops writes and retains root consistency" {
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    {
        var value: List.Type = .empty;
        defer value.deinit(allocator);
        try value.appendSlice(allocator, &.{ 1, 2, 3, 4, 5 });
        const view = try List.TreeView.fromValue(allocator, &pool, &value);
        defer view.deinit();
        try view.set(0, 10);
        try view.push(6);
        const copy = try view.clone(.{ .transfer_cache = false });
        defer copy.deinit();
        try std.testing.expectEqual(@as(u64, 1), try copy.get(0));
        try std.testing.expectEqual(@as(u64, 10), try view.get(0));
        try view.commit();
        try view.set(0, 20);
        const transferred = try view.clone(.{ .transfer_cache = true });
        defer transferred.deinit();
        try std.testing.expectEqual(@as(u64, 10), try transferred.get(0));
        try std.testing.expectEqual(@as(u64, 10), try view.get(0));
        try view.push(7);
        view.clearCache();
        try std.testing.expectEqual(@as(usize, 6), try view.length());
        try std.testing.expectEqual(@as(usize, 5), try copy.length());
        var bytes: [48]u8 = undefined;
        _ = try transferred.serializeIntoBytes(&bytes);
        const restored = try List.TreeView.deserialize(allocator, &pool, &bytes);
        defer restored.deinit();
        try std.testing.expectEqualSlices(u8, try transferred.hashTreeRoot(), try restored.hashTreeRoot());
        var out: List.Type = .empty;
        defer out.deinit(allocator);
        try restored.toValue(allocator, &out);
        try std.testing.expectEqual(@as(u64, 10), out.items[0]);
        try expectRoot(List, copy, &value);
    }
    try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
}

test "progressive basic view integrates as an ordinary container field" {
    const Container = ssz.VariableContainerType(struct { values: List });
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 1024 });
    defer pool.deinit();
    {
        const parent = try Container.TreeView.fromValue(allocator, &pool, &Container.default_value);
        defer parent.deinit();
        const child = try parent.get("values");
        try child.push(11);
        try parent.commit();
        try child.set(0, 22);
        const copy = try parent.clone(.{ .transfer_cache = false });
        defer copy.deinit();
        try std.testing.expectEqual(@as(u64, 11), try (try copy.get("values")).get(0));
        var bytes: [12]u8 = undefined;
        _ = try copy.serializeIntoBytes(&bytes);
        try std.testing.expectEqual(@as(u64, 11), std.mem.readInt(u64, bytes[4..12], .little));
        try std.testing.expectEqual(@as(u64, 22), try child.get(0));
    }
    try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
}

test "memory_safety: progressive basic commit retains writes on pool exhaustion" {
    var failures: usize = 0;
    var successes: usize = 0;
    for ([_]usize{ 4, 20 }) |new_length| {
        for (0..28) |available| {
            var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 128 });
            defer pool.deinit();
            {
                const view = try List.TreeView.fromValue(allocator, &pool, &List.default_value);
                defer view.deinit();
                try view.growTo(new_length);
                try view.set(0, 12);
                try view.set(new_length - 1, 34);
                const original = view.getRoot();
                var fillers: [128]Node.Id = undefined;
                var count: usize = 0;
                defer for (fillers[0..count]) |node| pool.unref(node);
                while (pool.nodes.len - pool.getNodesInUse() > available) {
                    fillers[count] = try pool.createLeafFromUint(0);
                    count += 1;
                }
                view.commit() catch |err| {
                    failures += 1;
                    try std.testing.expectEqual(error.PoolExhausted, err);
                    try std.testing.expectEqual(original, view.getRoot());
                    try std.testing.expectEqual(@as(u64, 12), try view.get(0));
                    try std.testing.expectEqual(@as(u64, 34), try view.get(new_length - 1));
                    for (fillers[0..count]) |node| pool.unref(node);
                    count = 0;
                    try view.commit();
                };
                successes += 1;
                var expected: List.Type = .empty;
                defer expected.deinit(allocator);
                try expected.resize(allocator, new_length);
                @memset(expected.items, 0);
                expected.items[0] = 12;
                expected.items[new_length - 1] = 34;
                try expectRoot(List, view, &expected);
            }
            try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
        }
    }
    try std.testing.expect(failures > 0);
    try std.testing.expect(successes > failures);
}

fn allocationFailures(failing: Allocator) !void {
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 2048 });
    defer pool.deinit();
    defer std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse()) catch @panic("leaked pool nodes");
    {
        const view = try List.TreeView.fromValue(failing, &pool, &List.default_value);
        defer view.deinit();
        try view.growTo(96);
        try view.set(0, 11);
        try view.set(95, 22);
        try view.commit();
        const copy = try view.clone(.{ .transfer_cache = true });
        defer copy.deinit();
        const sliced = try copy.sliceTo(7);
        defer sliced.deinit();
        var values: List.Type = .empty;
        defer values.deinit(failing);
        try copy.toValue(failing, &values);
        try std.testing.expectEqual(@as(u64, 22), values.items[95]);
    }
    try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
}

test "memory_safety: progressive basic view allocation failure cleanup" {
    try std.testing.checkAllAllocationFailures(allocator, allocationFailures, .{});
}

test "progressive basic deserialization propagates original errors" {
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 128 });
    defer pool.deinit();
    const Booleans = ssz.FixedProgressiveListType(ssz.BoolType());
    try std.testing.expectError(error.invalidBoolean, Booleans.TreeView.deserialize(allocator, &pool, &.{2}));
    try std.testing.expectError(error.InvalidSSZ, List.TreeView.deserialize(allocator, &pool, &.{0}));
    try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
}

test "memory_safety: progressive basic commit OOM preserves ordinary and growing roots" {
    for ([_]usize{ 4, 96 }) |len| {
        var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 2048 });
        defer pool.deinit();
        {
            var failing = std.testing.FailingAllocator.init(allocator, .{});
            const view = try List.TreeView.fromValue(failing.allocator(), &pool, &List.default_value);
            defer view.deinit();
            try view.push(1);
            try view.commit();
            const original = view.getRoot();
            try view.growTo(len);
            try view.set(len - 1, 2);
            failing.fail_index = failing.alloc_index;
            try std.testing.expectError(error.OutOfMemory, view.commit());
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(original, view.getRoot());
            try std.testing.expectEqual(@as(u64, 2), try view.get(len - 1));
            failing.fail_index = std.math.maxInt(usize);
            try view.commit();
            try std.testing.expectEqual(@as(u64, 2), try view.get(len - 1));
        }
        try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
    }
}

test "progressive basic repeated packed writes reuse one pending leaf" {
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 128 });
    defer pool.deinit();
    {
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        const view = try List.TreeView.fromValue(failing.allocator(), &pool, &List.default_value);
        defer view.deinit();
        try view.growTo(4);
        try view.set(0, 1);
        const nodes = pool.getNodesInUse();
        failing.fail_index = failing.alloc_index;
        for (0..32) |i| try view.set(i % 4, i);
        try std.testing.expectEqual(nodes, pool.getNodesInUse());
        try std.testing.expect(!failing.has_induced_failure);
        failing.fail_index = std.math.maxInt(usize);
        try view.commit();
        for (0..4) |i| try std.testing.expectEqual(@as(u64, 28 + i), try view.get(i));
    }
    try std.testing.expectEqual(@as(usize, zero_nodes), pool.getNodesInUse());
}

test "progressive basic roots match TS SSZ reference fixtures" {
    const counts = [_]usize{ 0, 1, 4, 5, 20, 21, 84, 85, 340, 341 };
    const roots = [_][]const u8{
        "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "e832d263aaa8f9417d9f45a702834f6961ee7b15ad4d3d27f2b0f4fe79d33031",
        "fb119bdda96d8ebf59b511db66fc19a40f4f1543a5aa87d8d9b4519655a8eda9",
        "b52da986d8c44ac58d43d54d5a6f27363363ad09e1249d211c38c21c5221e5f4",
        "1957d11b2bce3ef0c72872fca6fa4cffacc27e601c91b88ab8e6b28eebc6525c",
        "86a8ce9749021379ba7af31ac5d6f3b33e0e0791a5c9bb2e00580fe8d6aeb117",
        "765cd3f85263382f72bcf782dd80038ec9184206fdde9e0872f5ec4025ed992f",
        "44149f84b9899187d206378ab59b88e7e59ebd3ed84fd95b4b2ba58b08f98024",
        "3083accc9e7cff9414433f3012d5b356e592e23df63c125f238f1a7efdc92ef2",
        "124e759295d6379ae9fba4499aa45580f940cab8214b34260e36977bd0e6e9fa",
    };
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 2048 });
    defer pool.deinit();
    for (counts, roots) |count, root_hex| {
        const view = try List.TreeView.fromValue(allocator, &pool, &List.default_value);
        defer view.deinit();
        for (0..count) |i| try view.push(i % 251);
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, root_hex);
        try std.testing.expectEqualSlices(u8, &expected, try view.hashTreeRoot());
    }
}
