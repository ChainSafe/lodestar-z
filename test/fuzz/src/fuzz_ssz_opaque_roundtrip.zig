// Round-trip fuzz for the opaque-node SSZ tree paths:
//   chunked_leaf list/vector — tree.deserializeFromBytes / serializeIntoBytes /
//                              toValue / fromValue
//   container_struct         — the same four, plus tree.getValuePtr
//
// `fuzz_ssz_chunked_leaf_set` already covers the chunked_leaf TreeView ops
// (set/get/push/clone/commit/sliceTo); this target covers the byte- and
// value-level tree conversions that target never exercises.
//
// Input: [selector_byte][ssz_data...]
//   selector % 4: 0 = chunked_leaf List(u64)
//                 1 = chunked_leaf List(u32)
//                 2 = StructContainerType (fixed 52-byte container)
//                 3 = chunked_leaf Vector(u64)

const std = @import("std");
const assert = std.debug.assert;
const fuzz_options = @import("fuzz_options");
const ssz = @import("ssz");
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;
const ChunkedLeaf = pmt.ChunkedLeaf;

const fuzz_buffer_size: u32 = 64 * 1024 * 1024;
var fuzz_buf: [fuzz_buffer_size]u8 = undefined;

const Capacity: usize = 1 << 20;
const selector_count: u8 = 4;

// All-fixed fields with no bool, so every 52-byte input deserializes and the
// whole round-trip past deserialize gets exercised.
const ContainerT = ssz.StructContainerType(struct {
    x: ssz.UintType(64),
    y: ssz.UintType(32),
    z: ssz.UintType(64),
    blob: ssz.ByteVectorType(32),
});

// Length 2*K*4 + 7: spans two chunked_leaves with an odd tail, so the last
// chunked_leaf is partial.
const VecChunkedLeaf = ssz.FixedVectorType(ssz.UintType(64), ChunkedLeaf.K * 4 * 2 + 7, .{ .chunked_leaf = true });

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(buf: [*]const u8, len: usize) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    if (len < 1) return;

    var fba = std.heap.FixedBufferAllocator.init(&fuzz_buf);
    const allocator = fba.allocator();

    const data = buf[1..len];
    switch (buf[0] % selector_count) {
        0 => fuzzListRoundtrip(ssz.FixedListType(ssz.UintType(64), Capacity, .{ .chunked_leaf = true }), allocator, data),
        1 => fuzzListRoundtrip(ssz.FixedListType(ssz.UintType(32), Capacity, .{ .chunked_leaf = true }), allocator, data),
        2 => fuzzContainerRoundtrip(allocator, data),
        3 => fuzzVectorRoundtrip(VecChunkedLeaf, allocator, data),
        else => unreachable,
    }
}

fn fuzzListRoundtrip(comptime ListT: type, allocator: std.mem.Allocator, data: []const u8) void {
    var pool = Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 8192,
    }) catch return;
    defer pool.deinit();

    // Pool baseline = pre-populated zero sentinels. Any tree id the round-trip
    // fails to unref accumulates here and trips the assert at function exit.
    const baseline_in_use = pool.getNodesInUse();
    var leak_check_armed = false;
    defer {
        if (leak_check_armed) {
            assert(pool.getNodesInUse() == baseline_in_use);
        }
    }

    const node = ListT.tree.deserializeFromBytes(&pool, data) catch |err| switch (err) {
        error.UnexpectedRemainder,
        error.OutOfMemory,
        => return,
        else => panicUnexpected("deserializing opaque list tree", err),
    };
    defer pool.unref(node);
    leak_check_armed = true;

    // tree -> bytes round-trips back to the input.
    const size = ListT.tree.serializedSize(node, &pool) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("sizing opaque list tree", err),
    };
    assert(size == data.len);
    const out = allocator.alloc(u8, size) catch return;
    defer allocator.free(out);
    const written = ListT.tree.serializeIntoBytes(node, &pool, out) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("serializing opaque list tree", err),
    };
    assert(written == size);
    assert(std.mem.eql(u8, out, data));

    // tree -> value -> bytes round-trips too.
    var value: ListT.Type = .empty;
    defer value.deinit(allocator);
    ListT.tree.toValue(allocator, node, &pool, &value) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("reading opaque list tree value", err),
    };
    const value_size = ListT.serializedSize(&value);
    assert(value_size == data.len);
    const value_out = allocator.alloc(u8, value_size) catch return;
    defer allocator.free(value_out);
    const value_written = ListT.serializeIntoBytes(&value, value_out);
    assert(value_written == value_size);
    assert(std.mem.eql(u8, value_out, data));

    // value -> tree rebuilds the same root.
    const rebuilt = ListT.tree.fromValue(&pool, &value) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("rebuilding opaque list tree", err),
    };
    defer pool.unref(rebuilt);
    assert(std.mem.eql(u8, node.getRoot(&pool), rebuilt.getRoot(&pool)));
}

fn fuzzContainerRoundtrip(allocator: std.mem.Allocator, data: []const u8) void {
    var pool = Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 256,
    }) catch return;
    defer pool.deinit();

    const baseline_in_use = pool.getNodesInUse();
    var leak_check_armed = false;
    defer {
        if (leak_check_armed) {
            assert(pool.getNodesInUse() == baseline_in_use);
        }
    }

    const node = ContainerT.tree.deserializeFromBytes(&pool, data) catch |err| switch (err) {
        error.InvalidSize,
        error.OutOfMemory,
        => return,
        else => panicUnexpected("deserializing opaque container tree", err),
    };
    defer pool.unref(node);
    leak_check_armed = true;

    // tree -> bytes round-trips back to the input.
    var out: [ContainerT.fixed_size]u8 = undefined;
    const written = ContainerT.tree.serializeIntoBytes(
        node,
        &pool,
        &out,
    ) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("serializing opaque container tree", err),
    };
    assert(written == ContainerT.fixed_size);
    assert(std.mem.eql(u8, &out, data));

    // tree -> value -> bytes round-trips too.
    var value: ContainerT.Type = undefined;
    ContainerT.tree.toValue(node, &pool, &value) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("reading opaque container tree value", err),
    };
    var value_out: [ContainerT.fixed_size]u8 = undefined;
    const value_written = ContainerT.serializeIntoBytes(&value, &value_out);
    assert(value_written == ContainerT.fixed_size);
    assert(std.mem.eql(u8, &value_out, data));

    // getValuePtr hands back the same struct toValue produced, with no copy.
    const value_ptr = ContainerT.tree.getValuePtr(node, &pool) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("borrowing opaque container value", err),
    };
    assert(ContainerT.equals(value_ptr, &value));
    const same_value_ptr = ContainerT.tree.getValuePtr(node, &pool) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("reborrowing opaque container value", err),
    };
    assert(same_value_ptr == value_ptr);

    // value -> tree rebuilds the same root.
    const rebuilt = ContainerT.tree.fromValue(&pool, &value) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("rebuilding opaque container tree", err),
    };
    defer pool.unref(rebuilt);
    assert(std.mem.eql(u8, node.getRoot(&pool), rebuilt.getRoot(&pool)));
}

fn fuzzVectorRoundtrip(comptime VecT: type, allocator: std.mem.Allocator, data: []const u8) void {
    var pool = Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 4096,
    }) catch return;
    defer pool.deinit();

    const baseline_in_use = pool.getNodesInUse();
    var leak_check_armed = false;
    defer {
        if (leak_check_armed) {
            assert(pool.getNodesInUse() == baseline_in_use);
        }
    }

    const node = VecT.tree.deserializeFromBytes(&pool, data) catch |err| switch (err) {
        error.InvalidSize,
        error.OutOfMemory,
        => return,
        else => panicUnexpected("deserializing opaque vector tree", err),
    };
    defer pool.unref(node);
    leak_check_armed = true;

    // tree -> bytes round-trips back to the input.
    var out: [VecT.fixed_size]u8 = undefined;
    const written = VecT.tree.serializeIntoBytes(node, &pool, &out) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("serializing opaque vector tree", err),
    };
    assert(written == VecT.fixed_size);
    assert(std.mem.eql(u8, &out, data));

    // tree -> value -> bytes round-trips too.
    var value: VecT.Type = undefined;
    VecT.tree.toValue(node, &pool, &value) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("reading opaque vector tree value", err),
    };
    var value_out: [VecT.fixed_size]u8 = undefined;
    const value_written = VecT.serializeIntoBytes(&value, &value_out);
    assert(value_written == VecT.fixed_size);
    assert(std.mem.eql(u8, &value_out, data));

    // value -> tree rebuilds the same root.
    const rebuilt = VecT.tree.fromValue(&pool, &value) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("rebuilding opaque vector tree", err),
    };
    defer pool.unref(rebuilt);
    assert(std.mem.eql(u8, node.getRoot(&pool), rebuilt.getRoot(&pool)));
}

fn panicUnexpected(comptime context: []const u8, err: anyerror) noreturn {
    std.debug.panic("{s}: {s}", .{ context, @errorName(err) });
}
