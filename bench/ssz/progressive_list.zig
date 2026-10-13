//! Bench comparing progressive list tree layouts on registry-scale workloads.
//!
//! Run with:
//!   zig build run:bench_progressive_list -Doptimize=ReleaseFast
//!
//! Every workload is registered as a pair, so each pair of output lines is a direct A/B comparison
//! of two layouts holding the same value under the same root:
//!  - `leaf` vs `chunked_leaf`: 1M uint64 items, one chunk per node vs `ChunkedLeaf.K` per node
//!  - `container` vs `container_struct`: 100K validator-shaped items, a field subtree vs one node
//!
//! Workloads:
//!  - fromValue:         build a tree from a populated value
//!  - fromValue+getRoot: build a tree and hash it
//!  - toValue:           decode every item back from the tree
//!  - serialize:         write the tree's SSZ bytes
//!  - deserialize:       build a tree from SSZ bytes
const std = @import("std");
const zbench = @import("zbench");

const Node = @import("persistent_merkle_tree").Node;

const ssz = @import("ssz");

const number_count: usize = 1 << 20;
const record_count: usize = 100_000;

const Numbers = ssz.FixedProgressiveListType(ssz.UintType(64), .{});
const NumbersChunked = ssz.FixedProgressiveListType(
    ssz.UintType(64),
    .{ .chunked_leaf = true },
);

const record_fields = struct {
    pubkey: ssz.ByteVectorType(48),
    withdrawal_credentials: ssz.ByteVectorType(32),
    effective_balance: ssz.UintType(64),
    slashed: ssz.BoolType(),
    activation_eligibility_epoch: ssz.UintType(64),
    activation_epoch: ssz.UintType(64),
    exit_epoch: ssz.UintType(64),
    withdrawable_epoch: ssz.UintType(64),
};
const Records = ssz.FixedProgressiveListType(ssz.FixedContainerType(record_fields), .{});
const RecordsStruct = ssz.FixedProgressiveListType(ssz.StructContainerType(record_fields), .{});

fn FromValue(comptime List: type) type {
    return struct {
        pool: *Node.Pool,
        value: *const List.Type,

        pub fn run(self: *@This(), _: std.mem.Allocator) void {
            const root = List.tree.fromValue(self.pool, self.value) catch unreachable;
            self.pool.unref(root);
        }
    };
}

fn FromValueGetRoot(comptime List: type) type {
    return struct {
        pool: *Node.Pool,
        value: *const List.Type,

        pub fn run(self: *@This(), _: std.mem.Allocator) void {
            const root = List.tree.fromValue(self.pool, self.value) catch unreachable;
            std.mem.doNotOptimizeAway(root.getRoot(self.pool));
            self.pool.unref(root);
        }
    };
}

fn ToValue(comptime List: type) type {
    return struct {
        pool: *Node.Pool,
        root: Node.Id,

        pub fn run(self: *@This(), allocator: std.mem.Allocator) void {
            var out: List.Type = .empty;
            defer List.deinit(allocator, &out);
            List.tree.toValue(allocator, self.root, self.pool, &out) catch unreachable;
            std.mem.doNotOptimizeAway(out.items.ptr);
        }
    };
}

fn Serialize(comptime List: type) type {
    return struct {
        pool: *Node.Pool,
        root: Node.Id,
        out: []u8,

        pub fn run(self: *@This(), _: std.mem.Allocator) void {
            const size = List.tree.serializeIntoBytes(self.root, self.pool, self.out);
            std.mem.doNotOptimizeAway(size catch unreachable);
        }
    };
}

fn Deserialize(comptime List: type) type {
    return struct {
        pool: *Node.Pool,
        bytes: []const u8,

        pub fn run(self: *@This(), _: std.mem.Allocator) void {
            const root = List.tree.deserializeFromBytes(self.pool, self.bytes) catch unreachable;
            self.pool.unref(root);
        }
    };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = std.heap.page_allocator;
    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    // Node payloads come from c_allocator, like the production bindings.
    var pool = try Node.Pool.init(.{ .allocator = std.heap.c_allocator, .pool_size = 8_000_000 });
    defer pool.deinit();

    var numbers: Numbers.Type = .empty;
    defer numbers.deinit(allocator);
    try numbers.resize(allocator, number_count);
    for (numbers.items, 0..) |*number, i| number.* = i * 31 + 1;

    const numbers_bytes = try allocator.alloc(u8, Numbers.serializedSize(&numbers));
    defer allocator.free(numbers_bytes);
    _ = Numbers.serializeIntoBytes(&numbers, numbers_bytes);
    const numbers_out = try allocator.alloc(u8, numbers_bytes.len);
    defer allocator.free(numbers_out);

    const numbers_leaf = try Numbers.tree.fromValue(&pool, &numbers);
    defer pool.unref(numbers_leaf);
    const numbers_chunked = try NumbersChunked.tree.fromValue(&pool, &numbers);
    defer pool.unref(numbers_chunked);

    var records: Records.Type = .empty;
    defer records.deinit(allocator);
    try records.resize(allocator, record_count);
    for (records.items, 0..) |*record, i| {
        record.* = Records.Element.default_value;
        std.mem.writeInt(u64, record.pubkey[0..8], i, .little);
        record.effective_balance = 32_000_000_000;
        record.activation_epoch = i % 1024;
    }

    const records_bytes = try allocator.alloc(u8, Records.serializedSize(&records));
    defer allocator.free(records_bytes);
    _ = Records.serializeIntoBytes(&records, records_bytes);
    const records_out = try allocator.alloc(u8, records_bytes.len);
    defer allocator.free(records_out);

    const records_container = try Records.tree.fromValue(&pool, &records);
    defer pool.unref(records_container);
    const records_struct = try RecordsStruct.tree.fromValue(&pool, &records);
    defer pool.unref(records_struct);

    const fv_leaf = FromValue(Numbers){ .pool = &pool, .value = &numbers };
    const fv_chunked = FromValue(NumbersChunked){ .pool = &pool, .value = &numbers };
    try bench.addParam("fromValue 1M leaf", &fv_leaf, .{});
    try bench.addParam("fromValue 1M chunked_leaf", &fv_chunked, .{});

    const gr_leaf = FromValueGetRoot(Numbers){ .pool = &pool, .value = &numbers };
    const gr_chunked = FromValueGetRoot(NumbersChunked){ .pool = &pool, .value = &numbers };
    try bench.addParam("fromValue+getRoot 1M leaf", &gr_leaf, .{});
    try bench.addParam("fromValue+getRoot 1M chunked_leaf", &gr_chunked, .{});

    const tv_leaf = ToValue(Numbers){ .pool = &pool, .root = numbers_leaf };
    const tv_chunked = ToValue(NumbersChunked){ .pool = &pool, .root = numbers_chunked };
    try bench.addParam("toValue 1M leaf", &tv_leaf, .{});
    try bench.addParam("toValue 1M chunked_leaf", &tv_chunked, .{});

    const se_leaf = Serialize(Numbers){ .pool = &pool, .root = numbers_leaf, .out = numbers_out };
    const se_chunked = Serialize(NumbersChunked){
        .pool = &pool,
        .root = numbers_chunked,
        .out = numbers_out,
    };
    try bench.addParam("serialize 1M leaf", &se_leaf, .{});
    try bench.addParam("serialize 1M chunked_leaf", &se_chunked, .{});

    const de_leaf = Deserialize(Numbers){ .pool = &pool, .bytes = numbers_bytes };
    const de_chunked = Deserialize(NumbersChunked){ .pool = &pool, .bytes = numbers_bytes };
    try bench.addParam("deserialize 1M leaf", &de_leaf, .{});
    try bench.addParam("deserialize 1M chunked_leaf", &de_chunked, .{});

    const fv_container = FromValue(Records){ .pool = &pool, .value = &records };
    const fv_struct = FromValue(RecordsStruct){ .pool = &pool, .value = &records };
    try bench.addParam("fromValue 100K container", &fv_container, .{});
    try bench.addParam("fromValue 100K container_struct", &fv_struct, .{});

    const gr_container = FromValueGetRoot(Records){ .pool = &pool, .value = &records };
    const gr_struct = FromValueGetRoot(RecordsStruct){ .pool = &pool, .value = &records };
    try bench.addParam("fromValue+getRoot 100K container", &gr_container, .{});
    try bench.addParam("fromValue+getRoot 100K container_struct", &gr_struct, .{});

    const tv_container = ToValue(Records){ .pool = &pool, .root = records_container };
    const tv_struct = ToValue(RecordsStruct){ .pool = &pool, .root = records_struct };
    try bench.addParam("toValue 100K container", &tv_container, .{});
    try bench.addParam("toValue 100K container_struct", &tv_struct, .{});

    const se_container = Serialize(Records){
        .pool = &pool,
        .root = records_container,
        .out = records_out,
    };
    const se_struct = Serialize(RecordsStruct){
        .pool = &pool,
        .root = records_struct,
        .out = records_out,
    };
    try bench.addParam("serialize 100K container", &se_container, .{});
    try bench.addParam("serialize 100K container_struct", &se_struct, .{});

    const de_container = Deserialize(Records){ .pool = &pool, .bytes = records_bytes };
    const de_struct = Deserialize(RecordsStruct){ .pool = &pool, .bytes = records_bytes };
    try bench.addParam("deserialize 100K container", &de_container, .{});
    try bench.addParam("deserialize 100K container_struct", &de_struct, .{});

    try bench.run(io, std.Io.File.stdout());
}
