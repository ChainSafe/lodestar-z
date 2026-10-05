//! zig build run:bench_progressive_list_basic -Doptimize=ReleaseFast
//! Two warmups and nine samples. Tree construction and initial hashing are outside the timer.
//! Mutation samples include view initialization, reads/writes, commit, hashing, and teardown.
const std = @import("std");
const ssz = @import("ssz");
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const Gindex = pmt.Gindex;
const allocator = std.heap.c_allocator;
const item_count = 1 << 20;
const probe_count = 4096;
const sample_count = 9;
const Work = enum { sparse, clustered, dense, cold_read, warm_read, bulk_read, append, slice };

pub fn main(init: std.process.Init) !void {
    var pool = try Node.Pool.init(.{ .allocator = allocator, .pool_size = 3_000_000 });
    defer pool.deinit();
    std.debug.print("1M items, 2 warmups, 9 samples; median and min/max in ms\n", .{});
    inline for (.{ ssz.UintType(8), ssz.UintType(64) }) |Element| {
        const Progressive = ssz.FixedProgressiveListType(Element);
        const Plain = ssz.FixedListType(Element, 1 << 22, .{});
        const Chunked = ssz.FixedListType(Element, 1 << 22, .{ .chunked_leaf = true });
        var value: Progressive.Type = .empty;
        defer value.deinit(allocator);
        try value.resize(allocator, item_count);
        for (value.items, 0..) |*item, i| item.* = @intCast(i % 127);
        const output = try allocator.alloc(Element.Type, item_count);
        defer allocator.free(output);
        inline for (.{ Progressive, Plain, Chunked }) |ST| {
            const name = if (ST == Progressive) "progressive" else if (ST == Plain) "fixed plain" else "fixed chunked";
            const base = try ST.TreeView.fromValue(allocator, &pool, &value);
            defer base.deinit();
            _ = try base.hashTreeRoot();
            inline for (comptime std.meta.tags(Work)) |work| {
                var expected: ST.Type = .empty;
                defer expected.deinit(allocator);
                try expected.appendSlice(allocator, value.items);
                if (work == .sparse or work == .clustered or work == .dense) {
                    const count: usize = if (work == .sparse) 512 else if (work == .clustered) 4096 else item_count;
                    for (0..count) |i| {
                        const index = if (work == .sparse) scatterIndex(i) else if (work == .clustered) i % 128 else i;
                        expected.items[index] +%= 1;
                    }
                } else if (work == .append) {
                    try expected.appendNTimes(allocator, 1, 512);
                } else if (work == .slice) {
                    @memset(expected.items[item_count / 2 + 2 ..], 0);
                }
                var expected_root: [32]u8 = undefined;
                try ST.hashTreeRoot(allocator, &expected, &expected_root);
                var readings: [sample_count]i64 = undefined;
                for (0..sample_count + 2) |sample| {
                    var start = std.Io.Timestamp.now(init.io, .awake);
                    const view = try base.clone(.{ .transfer_cache = false });
                    // Warm reads measure the second probe pass, with its cache populated outside timing.
                    if (work == .warm_read) {
                        try readProbes(ST, view);
                        start = std.Io.Timestamp.now(init.io, .awake);
                    }
                    const actual = try runWork(ST, view, work, output);
                    view.deinit();
                    const elapsed: i64 = @intCast(start.untilNow(init.io, .awake).nanoseconds);
                    if (!std.mem.eql(u8, &expected_root, &actual)) return error.BenchmarkRootMismatch;
                    if (work == .bulk_read) {
                        if (!std.mem.eql(Element.Type, expected.items, output)) {
                            return error.BenchmarkValueMismatch;
                        }
                    }
                    if (sample >= 2) readings[sample - 2] = elapsed;
                }
                std.mem.sort(i64, &readings, {}, std.sort.asc(i64));
                std.debug.print("u{d} {s: <13} {s: <10} {d:.3} [{d:.3}, {d:.3}]\n", .{
                    @bitSizeOf(Element.Type),                 name,                      @tagName(work),
                    milliseconds(readings[sample_count / 2]), milliseconds(readings[0]), milliseconds(readings[sample_count - 1]),
                });
            }
            if (ST == Progressive) {
                var expected: Progressive.Type = .empty;
                defer expected.deinit(allocator);
                try expected.appendSlice(allocator, value.items);
                for (0..512) |i| expected.items[scatterIndex(i)] +%= 1;
                var expected_root: [32]u8 = undefined;
                try Progressive.hashTreeRoot(allocator, &expected, &expected_root);
                var readings: [sample_count]i64 = undefined;
                for (0..sample_count + 2) |sample| {
                    const start = std.Io.Timestamp.now(init.io, .awake);
                    const actual = try immediateSparse(Progressive, &pool, base.getRoot());
                    const elapsed: i64 = @intCast(start.untilNow(init.io, .awake).nanoseconds);
                    if (!std.mem.eql(u8, &expected_root, &actual)) return error.BenchmarkRootMismatch;
                    if (sample >= 2) readings[sample - 2] = elapsed;
                }
                std.mem.sort(i64, &readings, {}, std.sort.asc(i64));
                std.debug.print("u{d} immediate progressive sparse {d:.3} [{d:.3}, {d:.3}]\n", .{
                    @bitSizeOf(Element.Type),  milliseconds(readings[sample_count / 2]),
                    milliseconds(readings[0]), milliseconds(readings[sample_count - 1]),
                });
            }
        }
    }
}

fn runWork(comptime ST: type, view: *ST.TreeView, comptime work: Work, output: []ST.Element.Type) ![32]u8 {
    switch (work) {
        .sparse, .clustered, .dense => {
            const count: usize = if (work == .sparse) 512 else if (work == .clustered) 4096 else item_count;
            for (0..count) |i| {
                const index = if (work == .sparse) scatterIndex(i) else if (work == .clustered) i % 128 else i;
                try view.set(index, (try view.get(index)) +% 1);
            }
        },
        .cold_read, .warm_read => try readProbes(ST, view),
        .bulk_read => {
            _ = try view.getAllInto(output);
            std.mem.doNotOptimizeAway(output);
        },
        .append => for (0..512) |_| try view.push(1),
        .slice => {
            const sliced = try view.sliceTo(item_count / 2 + 1);
            defer sliced.deinit();
            try sliced.growTo(item_count);
            return (try sliced.hashTreeRoot()).*;
        },
    }
    const root = (try view.hashTreeRoot()).*;
    std.mem.doNotOptimizeAway(root);
    return root;
}

fn readProbes(comptime ST: type, view: *ST.TreeView) !void {
    var sum: u64 = 0;
    for (0..probe_count) |i| sum +%= @intCast(try view.get(scatterIndex(i)));
    std.mem.doNotOptimizeAway(sum);
}

fn scatterIndex(i: usize) usize {
    return (i * 104729 + 17) % item_count;
}

fn milliseconds(ns: i64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_ms;
}

// Baseline follows the original TS deferred view's per-write path rebuild, then hashes once.
fn immediateSparse(comptime ST: type, pool: *Node.Pool, base: Node.Id) ![32]u8 {
    var root = base;
    try pool.ref(root);
    defer pool.unref(root);
    for (0..512) |i| {
        const index = scatterIndex(i);
        const chunk_index = index / (32 / ST.Element.fixed_size);
        const subtree = std.math.log2_int(usize, 3 * chunk_index + 1) / 2;
        const start = ((@as(usize, 1) << @intCast(2 * subtree)) - 1) / 3;
        const gindex: Gindex = @enumFromInt((((@as(Gindex.Uint, 3) << @intCast(subtree)) - 1) << @intCast(2 * subtree + 1)) + chunk_index - start);
        const old = try root.getNode(pool, gindex);
        var value: ST.Element.Type = undefined;
        try ST.Element.tree.toValuePacked(old, pool, index % (32 / ST.Element.fixed_size), &value);
        value +%= 1;
        const leaf = try ST.Element.tree.fromValuePacked(old, pool, index % (32 / ST.Element.fixed_size), &value);
        try pool.ref(leaf);
        defer pool.unref(leaf);

        const updated = try root.setNode(pool, gindex, leaf);
        try pool.ref(updated);
        pool.unref(root);
        root = updated;
    }
    const result = root.getRoot(pool).*;
    std.mem.doNotOptimizeAway(result);
    return result;
}
