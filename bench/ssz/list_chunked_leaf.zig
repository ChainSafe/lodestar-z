//! Bench comparing FixedListType(Uint64, 2^20) leaf-default vs opts.chunked_leaf=true
//! on representative balances-scale workloads.
//!
//! Run with:
//!   zig build run:bench_list_chunked_leaf -Doptimize=ReleaseFast
//!
//! Workloads (1M u64 items unless noted):
//!  - fromValue:        build tree from a populated value
//!  - getRoot:          compute root hash from a freshly built tree
//!  - toValue:          decode all items back from the tree
//!  - sparseSet:        single-item set + getRoot (CoW path), 100 iterations
//!  - bulkSetAndRoot:   set every item then getRoot (epoch-rewards-shaped)
const std = @import("std");
const zbench = @import("zbench");

const Node = @import("persistent_merkle_tree").Node;
const ChunkedLeaf = @import("persistent_merkle_tree").ChunkedLeaf;

const ssz = @import("ssz");
const FixedListType = ssz.FixedListType;
const UintType = ssz.UintType;

const Limit: comptime_int = 1 << 20;
const ItemCount: usize = 1 << 20;

const ListLeaf = FixedListType(UintType(64), Limit, .{});
const ListChunkedLeaf = FixedListType(UintType(64), Limit, .{ .chunked_leaf = true });

const global_allocator = std.heap.page_allocator;

// Shared input value used by all build-side benches.
var input_value: ListLeaf.Type = ListLeaf.Type.empty;

fn populateInput(allocator: std.mem.Allocator) !void {
    try input_value.ensureTotalCapacity(allocator, ItemCount);
    for (0..ItemCount) |i| {
        try input_value.append(allocator, @as(u64, @intCast(i * 31 + 1)));
    }
}

// ──────── fromValue ────────

const FromValueLeaf = struct {
    pool: *Node.Pool,
    pub fn run(self: *FromValueLeaf, allocator: std.mem.Allocator) void {
        _ = allocator;
        const id = ListLeaf.tree.fromValue(self.pool, &input_value) catch unreachable;
        self.pool.unref(id);
    }
};

const FromValueChunkedLeaf = struct {
    pool: *Node.Pool,
    pub fn run(self: *FromValueChunkedLeaf, allocator: std.mem.Allocator) void {
        _ = allocator;
        const id = ListChunkedLeaf.tree.fromValue(self.pool, &input_value) catch unreachable;
        self.pool.unref(id);
    }
};

// ──────── getRoot on a freshly built tree (cold lazy hashes) ────────

const GetRootLeaf = struct {
    pool: *Node.Pool,
    pub fn run(self: *GetRootLeaf, allocator: std.mem.Allocator) void {
        _ = allocator;
        const id = ListLeaf.tree.fromValue(self.pool, &input_value) catch unreachable;
        const root = id.getRoot(self.pool);
        std.mem.doNotOptimizeAway(root);
        self.pool.unref(id);
    }
};

const GetRootChunkedLeaf = struct {
    pool: *Node.Pool,
    pub fn run(self: *GetRootChunkedLeaf, allocator: std.mem.Allocator) void {
        _ = allocator;
        const id = ListChunkedLeaf.tree.fromValue(self.pool, &input_value) catch unreachable;
        const root = id.getRoot(self.pool);
        std.mem.doNotOptimizeAway(root);
        self.pool.unref(id);
    }
};

// ──────── toValue (read all items back) ────────

const ToValueLeaf = struct {
    pool: *Node.Pool,
    tree_id: Node.Id,
    pub fn run(self: *ToValueLeaf, allocator: std.mem.Allocator) void {
        var dst = ListLeaf.Type.empty;
        defer dst.deinit(allocator);
        ListLeaf.tree.toValue(allocator, self.tree_id, self.pool, &dst) catch unreachable;
        std.mem.doNotOptimizeAway(dst.items[0]);
    }
};

const ToValueChunkedLeaf = struct {
    pool: *Node.Pool,
    tree_id: Node.Id,
    pub fn run(self: *ToValueChunkedLeaf, allocator: std.mem.Allocator) void {
        var dst = ListChunkedLeaf.Type.empty;
        defer dst.deinit(allocator);
        ListChunkedLeaf.tree.toValue(allocator, self.tree_id, self.pool, &dst) catch unreachable;
        std.mem.doNotOptimizeAway(dst.items[0]);
    }
};

// ──────── bulkSetAndRoot: epoch-rewards-shaped — write every item via tree.fromValue
// of a slightly mutated input, then getRoot ────────

const BulkSetAndRootLeaf = struct {
    pool: *Node.Pool,
    mutated: *ListLeaf.Type,
    pub fn run(self: *BulkSetAndRootLeaf, allocator: std.mem.Allocator) void {
        _ = allocator;
        const id = ListLeaf.tree.fromValue(self.pool, self.mutated) catch unreachable;
        const root = id.getRoot(self.pool);
        std.mem.doNotOptimizeAway(root);
        self.pool.unref(id);
    }
};

const BulkSetAndRootChunkedLeaf = struct {
    pool: *Node.Pool,
    mutated: *ListChunkedLeaf.Type,
    pub fn run(self: *BulkSetAndRootChunkedLeaf, allocator: std.mem.Allocator) void {
        _ = allocator;
        const id = ListChunkedLeaf.tree.fromValue(self.pool, self.mutated) catch unreachable;
        const root = id.getRoot(self.pool);
        std.mem.doNotOptimizeAway(root);
        self.pool.unref(id);
    }
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = global_allocator;
    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    // Single shared pool. Sized for ~1M chunks worth of node IDs across both
    // leaf and chunked_leaf scenarios; preheats keep allocator overhead off the hot path.
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 8_000_000 });
    defer pool.deinit();

    try populateInput(allocator);
    defer input_value.deinit(allocator);

    // Build per-layout reference trees once for the read-side benches.
    const tree_leaf = try ListLeaf.tree.fromValue(&pool, &input_value);
    defer pool.unref(tree_leaf);
    _ = tree_leaf.getRoot(&pool); // warm

    const tree_chunked_leaf = try ListChunkedLeaf.tree.fromValue(&pool, &input_value);
    defer pool.unref(tree_chunked_leaf);
    _ = tree_chunked_leaf.getRoot(&pool); // warm

    // bulkSet input: each iteration rebuilds tree.fromValue on this value;
    // matches the shape of "epoch rewards rewrite all balances + recompute root".
    var mutated_leaf: ListLeaf.Type = ListLeaf.Type.empty;
    defer mutated_leaf.deinit(allocator);
    try mutated_leaf.ensureTotalCapacity(allocator, ItemCount);
    for (0..ItemCount) |i| {
        try mutated_leaf.append(allocator, @as(u64, @intCast(i * 17 + 3)));
    }

    var mutated_chunked_leaf: ListChunkedLeaf.Type = ListChunkedLeaf.Type.empty;
    defer mutated_chunked_leaf.deinit(allocator);
    try mutated_chunked_leaf.ensureTotalCapacity(allocator, ItemCount);
    for (0..ItemCount) |i| {
        try mutated_chunked_leaf.append(allocator, @as(u64, @intCast(i * 17 + 3)));
    }

    const fv_leaf = FromValueLeaf{ .pool = &pool };
    const fv_chunked_leaf = FromValueChunkedLeaf{ .pool = &pool };
    try bench.addParam("fromValue 1M leaf", &fv_leaf, .{});
    try bench.addParam("fromValue 1M chunked_leaf", &fv_chunked_leaf, .{});

    const gr_leaf = GetRootLeaf{ .pool = &pool };
    const gr_chunked_leaf = GetRootChunkedLeaf{ .pool = &pool };
    try bench.addParam("fromValue+getRoot 1M leaf", &gr_leaf, .{});
    try bench.addParam("fromValue+getRoot 1M chunked_leaf", &gr_chunked_leaf, .{});

    const tv_leaf = ToValueLeaf{ .pool = &pool, .tree_id = tree_leaf };
    const tv_chunked_leaf = ToValueChunkedLeaf{ .pool = &pool, .tree_id = tree_chunked_leaf };
    try bench.addParam("toValue 1M leaf", &tv_leaf, .{});
    try bench.addParam("toValue 1M chunked_leaf", &tv_chunked_leaf, .{});

    const bs_leaf = BulkSetAndRootLeaf{ .pool = &pool, .mutated = &mutated_leaf };
    const bs_chunked_leaf = BulkSetAndRootChunkedLeaf{ .pool = &pool, .mutated = &mutated_chunked_leaf };
    try bench.addParam("bulkSet+getRoot 1M leaf", &bs_leaf, .{});
    try bench.addParam("bulkSet+getRoot 1M chunked_leaf", &bs_chunked_leaf, .{});

    try bench.run(io, std.Io.File.stdout());

    _ = ChunkedLeaf; // silence unused if chunked_leaf code path proves unreachable in some build mode
}
