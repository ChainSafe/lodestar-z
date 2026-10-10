const std = @import("std");
const progressive = @import("progressive.zig");
const Node = @import("persistent_merkle_tree").Node;

test "progressive chunk indexes differ from subtree counts at interior positions" {
    for (0..31) |index| {
        const expected: u64 = if (index == 0) 2 else if (index < 5) 24 + index - 1 else if (index < 21) 224 + index - 5 else 1920 + index - 21;
        try std.testing.expectEqual(expected, @intFromEnum(progressive.chunkGindex(index)));
    }
    try std.testing.expectEqual(0, progressive.subtreeCount(0));
    try std.testing.expectEqual(1, progressive.subtreeCount(1));
    try std.testing.expectEqual(1, progressive.subtreeIndex(2));
    try std.testing.expectEqual(2, progressive.subtreeCount(2));
    try std.testing.expectEqual(2, progressive.subtreeIndex(20));
    try std.testing.expectEqual(3, progressive.subtreeCount(21));
    const Gindex = @import("persistent_merkle_tree").Gindex;
    // Gloas finalized_checkpoint.root: left contents, active position20, right field.
    try std.testing.expectEqual(735, @intFromEnum(Gindex.concat(&.{ @enumFromInt(2), progressive.chunkGindex(20), @enumFromInt(3) })));
}

test "progressive builder needs no subtree offset allocation" {
    const allocator = std.testing.allocator;
    inline for (.{ 0, 1, 2, 5, 6, 21, 22, 85, 86, 341, 342 }) |count| {
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = failing.allocator(), .pool_size = 2048 });
        defer pool.deinit();
        const baseline = pool.getNodesInUse();
        var nodes: [count]Node.Id = undefined;
        var chunks: [count][32]u8 = undefined;
        for (&chunks, &nodes, 0..) |*chunk, *node, i| {
            chunk.* = @splat(@truncate(i));
            node.* = try pool.createLeaf(chunk);
        }
        const tree = try progressive.fillWithContents(failing.allocator(), &pool, &nodes);
        var expected: [32]u8 = undefined;
        try progressive.merkleizeChunks(allocator, &chunks, &expected);
        try std.testing.expectEqualSlices(u8, &expected, tree.getRoot(&pool));
        pool.unref(tree);
        try std.testing.expectEqual(baseline, pool.getNodesInUse());
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "progressive Merkleization matches tree roots without scratch allocation" {
    const allocator = std.testing.allocator;
    inline for (.{ 0, 1, 2, 5, 6, 21, 22, 85, 86, 341, 342, 1365, 1366 }) |count| {
        var chunks: [count][32]u8 = undefined;
        var nodes: [count]Node.Id = undefined;
        var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 8192 });
        defer pool.deinit();
        for (&chunks, &nodes, 0..) |*chunk, *node, i| {
            chunk.* = @splat(@truncate(i));
            node.* = try pool.createLeaf(chunk);
        }
        const tree = try progressive.fillWithContents(allocator, &pool, &nodes);
        defer pool.unref(tree);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        var root: [32]u8 = undefined;
        try progressive.merkleizeChunks(failing.allocator(), &chunks, &root);
        try std.testing.expectEqualSlices(u8, tree.getRoot(&pool), &root);
        try progressive.merkleizeChunksComptime(count, &chunks, &root);
        try std.testing.expectEqualSlices(u8, tree.getRoot(&pool), &root);
        for (chunks, 0..) |chunk, i| try std.testing.expectEqual([_]u8{@truncate(i)} ** 32, chunk);
    }
}

test "progressive accumulator enforces length and finish state" {
    var accumulator = try progressive.MerkleAccumulator.init(2);
    var root: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidLength, accumulator.finish(&root));
    try accumulator.append(&@as([32]u8, @splat(1)));
    try accumulator.append(&@as([32]u8, @splat(2)));
    try std.testing.expectError(error.InputTooLong, accumulator.append(&root));
    try accumulator.finish(&root);
    try std.testing.expectError(error.InvalidState, accumulator.finish(&root));
    try std.testing.expectError(error.InvalidState, accumulator.append(&root));
    try std.testing.expectError(error.InputTooLong, progressive.MerkleAccumulator.init(std.math.maxInt(usize)));
}

// Zig 0.16 has no std.testing.fuzz entry point. Keep a deterministic, bounded
// mutation corpus in the ordinary SSZ suite so decoder properties run in CI.
const ssz = @import("root.zig");
const fuzz_input_bound = 1100;

fn encodingAccepted(result: anyerror!void) !bool {
    if (result) |_| return true else |err| switch (err) {
        // A resource failure is never evidence that an encoding is invalid.
        error.OutOfMemory, error.PoolExhausted, error.RefCountOverflow => return err,
        else => return false,
    }
}

fn checkDecoderAgreement(comptime ST: type, pool: *Node.Pool, data: []const u8) !bool {
    const allocator = std.testing.allocator;
    const baseline = pool.getNodesInUse();
    const valid = try encodingAccepted(ST.serialized.validate(data));
    var value = ssz.initValue(ST);
    defer if (comptime !ssz.isFixedType(ST)) ST.deinit(allocator, &value);
    const decoded = try encodingAccepted(if (comptime ssz.isFixedType(ST))
        ST.deserializeFromBytes(data, &value)
    else
        ST.deserializeFromBytes(allocator, data, &value));
    try std.testing.expectEqual(valid, decoded);

    const tree: ?Node.Id = ST.tree.deserializeFromBytes(pool, data) catch |err| blk: {
        _ = try encodingAccepted(@as(anyerror!void, err));
        break :blk null;
    };
    if (tree) |root| {
        defer pool.unref(root);
        try std.testing.expect(valid);
        var bytes: [fuzz_input_bound]u8 = undefined;
        try std.testing.expectEqual(data.len, ST.serializedSize(&value));
        const value_size = ST.serializeIntoBytes(&value, &bytes);
        try std.testing.expectEqualSlices(u8, data, bytes[0..value_size]);
        try std.testing.expectEqual(data.len, try ST.tree.serializedSize(root, pool));
        const tree_size = try ST.tree.serializeIntoBytes(root, pool, &bytes);
        try std.testing.expectEqualSlices(u8, data, bytes[0..tree_size]);
        var value_root: [32]u8 = undefined;
        if (comptime ssz.isFixedType(ST)) try ST.hashTreeRoot(&value, &value_root) else try ST.hashTreeRoot(allocator, &value, &value_root);
        try std.testing.expectEqualSlices(u8, &value_root, root.getRoot(pool));
        var serialized_root: [32]u8 = undefined;
        if (comptime ssz.isFixedType(ST)) try ST.serialized.hashTreeRoot(data, &serialized_root) else try ST.serialized.hashTreeRoot(allocator, data, &serialized_root);
        try std.testing.expectEqualSlices(u8, &value_root, &serialized_root);
    } else try std.testing.expect(!valid);
    try std.testing.expectEqual(baseline, pool.getNodesInUse());
    return valid;
}

fn mutateDecoderCorpus(comptime ST: type, pool: *Node.Pool, seeds: []const []const u8) !void {
    var random_state = std.Random.DefaultPrng.init(0x67_6c_6f_61_73);
    const random = random_state.random();
    var accepted: usize = 0;
    var rejected: usize = 0;
    // Include every boundary seed verbatim before mutations can shorten it.
    for (seeds) |seed| {
        if (try checkDecoderAgreement(ST, pool, seed)) accepted += 1 else rejected += 1;
    }
    for (0..1024) |iteration| {
        const seed = seeds[random.uintLessThan(usize, seeds.len)];
        var bytes: [fuzz_input_bound]u8 = undefined;
        @memcpy(bytes[0..seed.len], seed);
        var length = seed.len;
        switch (iteration % 6) {
            0 => {
                length = random.intRangeAtMost(usize, 0, bytes.len);
                random.bytes(bytes[0..length]);
            },
            1 => length = random.intRangeAtMost(usize, 0, length),
            2 => {
                const extra = random.intRangeAtMost(usize, 0, @min(16, bytes.len - length));
                random.bytes(bytes[length..][0..extra]);
                length += extra;
            },
            3 => if (length > 0) {
                bytes[random.uintLessThan(usize, length)] ^= @as(u8, 1) << random.int(u3);
            },
            4 => if (length >= 4) {
                const offset = random.intRangeAtMost(usize, 0, length - 4);
                @memset(bytes[offset..][0..4], 255);
            },
            else => {},
        }
        if (try checkDecoderAgreement(ST, pool, bytes[0..length])) accepted += 1 else rejected += 1;
    }
    try std.testing.expect(accepted > 0);
    try std.testing.expect(rejected > 0);
}

test "bounded_fuzz: progressive decoders agree on seeded and mutated canonical encodings" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .allocator = allocator, .page_allocator = allocator, .pool_size = 4096 });
    defer pool.deinit();
    const zeroes = [_]u8{0} ** fuzz_input_bound;
    const list_seeds = [_][]const u8{
        &.{},           &.{1},          &.{2},          zeroes[0..8],   zeroes[0..31],   zeroes[0..32], zeroes[0..33],
        zeroes[0..160], zeroes[0..671], zeroes[0..672], zeroes[0..673], zeroes[0..1024], &zeroes,
    };
    inline for (.{ false, true }) |chunked| {
        try mutateDecoderCorpus(ssz.FixedProgressiveListTypeWithOptions(ssz.UintType(64), .{ .limit = 128, .chunked_leaf = chunked }), &pool, &list_seeds);
        try mutateDecoderCorpus(ssz.FixedProgressiveListTypeWithOptions(ssz.BoolType(), .{ .limit = 1024, .chunked_leaf = chunked }), &pool, &list_seeds);
    }
    const Bytes = ssz.ProgressiveByteListTypeWithOptions(.{ .limit = 1024, .chunked_leaf = true });
    const Bits = ssz.ProgressiveBitListTypeWithOptions(.{ .limit = 4096 });
    try mutateDecoderCorpus(Bytes, &pool, &list_seeds);
    try mutateDecoderCorpus(Bits, &pool, &.{ &.{}, &.{0}, &.{1}, &.{128}, &.{255}, &.{ 0, 1 }, zeroes[0..512], &zeroes });

    const ByteLists = ssz.VariableProgressiveListTypeWithOptions(Bytes, .{ .limit = 16 });
    try mutateDecoderCorpus(ByteLists, &pool, &.{ &.{}, &.{ 4, 0, 0, 0 }, &.{ 4, 0, 0, 0, 255 }, &.{ 8, 0, 0, 0, 9, 0, 0, 0, 1, 2 }, &.{ 255, 255, 255, 255 }, &zeroes });
    const Fixed = ssz.FixedProgressiveContainerType(struct { flag: ssz.BoolType(), count: ssz.UintType(64) }, &.{ 0, 1, 0, 0, 1 });
    try mutateDecoderCorpus(Fixed, &pool, &.{ &.{}, zeroes[0..8], zeroes[0..9], &.{ 1, 255, 255, 255, 255, 255, 255, 255, 255 }, &.{ 2, 0, 0, 0, 0, 0, 0, 0, 0 } });
    const Variable = ssz.VariableProgressiveContainerType(struct { flag: ssz.BoolType(), bytes: Bytes, bits: Bits }, &.{ 1, 0, 1, 0, 0, 1 });
    const Ordinary = ssz.VariableContainerType(struct { flag: ssz.BoolType(), bytes: ssz.ByteListType(1024), bits: ssz.BitListType(4096) });
    inline for (.{ Variable, Ordinary }) |ST| {
        try mutateDecoderCorpus(ST, &pool, &.{ &.{}, &.{ 1, 9, 0, 0, 0, 9, 0, 0, 0, 1 }, &.{ 0, 9, 0, 0, 0, 11, 0, 0, 0, 255, 17, 128 }, &.{ 0, 9, 0, 0, 0, 8, 0, 0, 0, 1 }, &zeroes });
    }
    const Union = ssz.CompatibleUnionType(.{ .{ 1, Bytes }, .{ 7, Bytes }, .{ 19, Bytes } });
    try mutateDecoderCorpus(Union, &pool, &.{ &.{}, &.{0}, &.{ 1, 0, 0, 0, 0, 0, 0, 0, 0 }, &.{7}, &.{ 7, 255, 128 }, &.{ 19, 1 }, &.{ 19, 0 }, &.{255} });
    const Unions = ssz.VariableProgressiveListTypeWithOptions(Union, .{ .limit = 16 });
    try mutateDecoderCorpus(Unions, &pool, &.{ &.{}, &.{ 4, 0, 0, 0, 7 }, &.{ 4, 0, 0, 0, 19, 1 }, &.{ 8, 0, 0, 0, 9, 0, 0, 0, 7, 19, 1 }, &.{ 4, 0, 0, 0, 255 } });
}
