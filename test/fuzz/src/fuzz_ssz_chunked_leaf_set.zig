// Input: [selector_byte][op records of 4 bytes each]
//   selector % 4: 0/1 = u64 populated/empty, 2/3 = u32 populated/empty
//   op % 7: 0=set, 1=commit+root check, 2=get, 3=push, 4=clone isolation,
//           5=sliceTo, 6=getAllInto
//   'G' rejects invalid growth; 'g' grows within the bounded reference model.
//   record layout: [op, arg_lo, arg_hi, val_seed]

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
const op_size: usize = 4;
const selector_count: u8 = 4;
const grow_to_opcode: u8 = 'G';
const valid_grow_to_opcode: u8 = 'g';

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(buf: [*]const u8, len: usize) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    if (len < 1 + op_size) return;

    var fba = std.heap.FixedBufferAllocator.init(&fuzz_buf);
    var tracker = std.testing.FailingAllocator.init(fba.allocator(), .{});
    defer assert(tracker.allocated_bytes == tracker.freed_bytes);
    const allocator = tracker.allocator();

    const data = buf[1..len];
    switch (buf[0] % selector_count) {
        0 => fuzzListOps(ssz.FixedListType(ssz.UintType(64), Capacity, .{ .chunked_leaf = true }), allocator, data, 64),
        1 => fuzzListOps(ssz.FixedListType(ssz.UintType(64), Capacity, .{ .chunked_leaf = true }), allocator, data, 0),
        2 => fuzzListOps(ssz.FixedListType(ssz.UintType(32), Capacity, .{ .chunked_leaf = true }), allocator, data, 64),
        3 => fuzzListOps(ssz.FixedListType(ssz.UintType(32), Capacity, .{ .chunked_leaf = true }), allocator, data, 0),
        else => unreachable,
    }
}

fn fuzzListOps(
    comptime ListT: type,
    allocator: std.mem.Allocator,
    data: []const u8,
    initial_count: usize,
) void {
    const Element = ListT.Element.Type;
    const items_per_chunk: usize = 32 / ListT.Element.fixed_size;
    const item_count: usize = ChunkedLeaf.K * items_per_chunk + 1;
    const K: usize = ChunkedLeaf.K;
    // +1 for the list length-mixin level above the data subtree.
    const cl_depth = ListT.chunk_depth + 1 - ChunkedLeaf.k_log2;

    var pool = Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 4096,
    }) catch return;
    defer pool.deinit();

    const baseline_in_use = pool.getNodesInUse();
    defer assert(pool.getNodesInUse() == baseline_in_use);

    var reference = std.ArrayList(Element).empty;
    defer reference.deinit(allocator);
    reference.ensureTotalCapacity(allocator, item_count) catch return;
    for (0..initial_count) |i| reference.append(allocator, computeInitial(Element, i)) catch return;

    var committed: [item_count]Element = undefined;
    var committed_len = reference.items.len;
    @memcpy(committed[0..committed_len], reference.items);
    const leaf_count = (item_count + K * items_per_chunk - 1) / (K * items_per_chunk);
    var leaf_lengths: [leaf_count]u16 = @splat(0);
    leaf_lengths[0] = @intCast((initial_count + items_per_chunk - 1) / items_per_chunk);

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    src.ensureTotalCapacity(allocator, initial_count) catch return;
    for (reference.items) |v| src.append(allocator, v) catch return;

    var view = ListT.TreeView.fromValue(allocator, &pool, &src) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => panicUnexpected("constructing chunked list view", err),
    };
    defer view.deinit();

    var i: usize = 0;
    while (i + op_size <= data.len) : (i += op_size) {
        const op = data[i] % 7;
        const arg_lo = data[i + 1];
        const arg_hi = data[i + 2];
        const val_seed = data[i + 3];

        if (data[i] == grow_to_opcode) {
            assertInvalidGrowTo(ListT, view, reference.items.len, arg_lo);
            continue;
        }
        if (data[i] == valid_grow_to_opcode) {
            const old_length = reference.items.len;
            const argument = @as(usize, arg_hi) << 8 | @as(usize, arg_lo);
            const new_length = old_length + argument % (item_count - old_length + 1);
            view.growTo(new_length) catch |err| panicUnexpected("growing chunked list", err);
            reference.resize(allocator, new_length) catch return;
            @memset(reference.items[old_length..], 0);
            assertListMatches(ListT, view, &reference) catch return;
            committed_len = reference.items.len;
            @memcpy(committed[0..committed_len], reference.items);
            continue;
        }

        switch (op) {
            0 => {
                if (reference.items.len == 0) continue;
                const idx = (@as(usize, arg_hi) << 8 | @as(usize, arg_lo)) % reference.items.len;
                const val = elementFromSeed(Element, val_seed);
                reference.items[idx] = val;
                view.set(idx, val) catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("setting chunked list item", err),
                };
                const leaf_index = idx / (K * items_per_chunk);
                const chunk_count = (reference.items.len + items_per_chunk - 1) / items_per_chunk;
                leaf_lengths[leaf_index] = @intCast(@min(K, chunk_count - leaf_index * K));
            },
            1 => {
                const view_root = (view.hashTreeRoot() catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("committing chunked list view", err),
                }).*;

                var ref_root: [32]u8 = undefined;
                ListT.hashTreeRoot(allocator, &reference, &ref_root) catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("hashing chunked list reference", err),
                };
                assert(std.mem.eql(u8, &ref_root, &view_root));
                committed_len = reference.items.len;
                @memcpy(committed[0..committed_len], reference.items);

                // growTo leaves zero subtrees sparse; set/push materialize up to the logical length.
                const len = reference.items.len;
                if (len > 0) {
                    const total_chunks = (len + items_per_chunk - 1) / items_per_chunk;
                    const cl_count = (total_chunks + K - 1) / K;
                    for (0..cl_count) |cl_idx| {
                        const cl = view.chunks.state.root.getNodeAtDepth(
                            &pool,
                            cl_depth,
                            cl_idx,
                        ) catch |err| switch (err) {
                            error.OutOfMemory => return,
                            else => panicUnexpected("reading chunked leaf", err),
                        };
                        if (leaf_lengths[cl_idx] == 0) {
                            assert(pool.nodes.items(.state)[@intFromEnum(cl)].kind() == .zero);
                            continue;
                        }
                        const chunked_leaf_len = cl.getChunkedLeafLen(&pool) catch |err| switch (err) {
                            error.OutOfMemory => return,
                            else => panicUnexpected("reading chunked leaf length", err),
                        };
                        assert(chunked_leaf_len == leaf_lengths[cl_idx]);
                    }
                }
            },
            2 => {
                if (reference.items.len == 0) continue;
                const idx = (@as(usize, arg_hi) << 8 | @as(usize, arg_lo)) % reference.items.len;
                const got = view.get(idx) catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("reading chunked list item", err),
                };
                assert(elementEql(Element, got, reference.items[idx]));
            },
            3 => {
                if (reference.items.len >= item_count) continue;
                const val = elementFromSeed(Element, val_seed);
                reference.append(allocator, val) catch return;
                view.push(val) catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("pushing chunked list item", err),
                };
                const leaf_index = (reference.items.len - 1) / (K * items_per_chunk);
                const chunk_count = (reference.items.len + items_per_chunk - 1) / items_per_chunk;
                leaf_lengths[leaf_index] = @intCast(@min(K, chunk_count - leaf_index * K));
            },
            4 => {
                // Clones start at the last committed state; false preserves the source's pending writes.
                const clone = view.clone(.{ .transfer_cache = false }) catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("cloning chunked list view", err),
                };
                defer clone.deinit();

                var clone_reference: ListT.Type = .empty;
                defer clone_reference.deinit(allocator);
                clone_reference.appendSlice(allocator, committed[0..committed_len]) catch return;
                assertListMatches(ListT, clone, &clone_reference) catch return;
                if (clone_reference.items.len > 0) {
                    const index = (@as(usize, arg_hi) << 8 | @as(usize, arg_lo)) % committed_len;
                    clone_reference.items[index] ^= @as(Element, val_seed) + 1;
                    clone.set(index, clone_reference.items[index]) catch |err| switch (err) {
                        error.OutOfMemory => return,
                        else => panicUnexpected("mutating cloned chunked list", err),
                    };
                } else {
                    const value = @as(Element, val_seed) + 1;
                    clone_reference.append(allocator, value) catch return;
                    clone.push(value) catch |err| switch (err) {
                        error.OutOfMemory => return,
                        else => panicUnexpected("pushing cloned chunked list", err),
                    };
                }
                assertListMatches(ListT, clone, &clone_reference) catch return;
                assertListMatches(ListT, view, &reference) catch return;
                committed_len = reference.items.len;
                @memcpy(committed[0..committed_len], reference.items);

                if (reference.items.len > 0) {
                    const index = (@as(usize, arg_hi) << 8 | @as(usize, arg_lo)) % reference.items.len;
                    reference.items[index] ^= (@as(Element, val_seed) + 1) << 8;
                    view.set(index, reference.items[index]) catch |err| switch (err) {
                        error.OutOfMemory => return,
                        else => panicUnexpected("mutating source after clone", err),
                    };
                    const leaf_index = index / (K * items_per_chunk);
                    const chunk_count = (reference.items.len + items_per_chunk - 1) / items_per_chunk;
                    leaf_lengths[leaf_index] = @intCast(@min(K, chunk_count - leaf_index * K));
                    assertListMatches(ListT, clone, &clone_reference) catch return;
                }
            },
            5 => {
                if (reference.items.len == 0) continue;
                const idx = (@as(usize, arg_hi) << 8 | @as(usize, arg_lo)) % reference.items.len;
                const sliced = view.sliceTo(idx) catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("slicing chunked list view", err),
                };
                defer sliced.deinit();
                committed_len = reference.items.len;
                @memcpy(committed[0..committed_len], reference.items);
                const sliced_root = (sliced.hashTreeRoot() catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("committing sliced chunked list", err),
                }).*;

                // sliceTo(idx) keeps elements 0..=idx; idx is in [0, len-1].
                const expected_len = idx + 1;
                var ref_src: ListT.Type = .empty;
                defer ref_src.deinit(allocator);
                ref_src.ensureTotalCapacity(allocator, expected_len) catch return;
                for (reference.items[0..expected_len]) |v| ref_src.append(allocator, v) catch return;

                const ref_root_id = ListT.tree.fromValue(&pool, &ref_src) catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("constructing sliced reference root", err),
                };
                defer pool.unref(ref_root_id);

                assert(std.mem.eql(u8, ref_root_id.getRoot(&pool), &sliced_root));
            },
            6 => {
                // getAllInto sees uncommitted set/push, so it must match the
                // running reference without a commit.
                const buf = allocator.alloc(Element, reference.items.len) catch return;
                defer allocator.free(buf);
                const filled = view.getAllInto(buf) catch |err| switch (err) {
                    error.OutOfMemory => return,
                    else => panicUnexpected("reading all chunked list items", err),
                };
                assert(filled.len == reference.items.len);
                for (filled, reference.items) |a, b| assert(elementEql(Element, a, b));
            },
            else => unreachable,
        }
    }
    assertListMatches(ListT, view, &reference) catch return;
}

fn assertListMatches(
    comptime ListT: type,
    view: *ListT.TreeView,
    reference: *const ListT.Type,
) error{OutOfMemory}!void {
    const values = try view.allocator.alloc(ListT.Element.Type, reference.items.len);
    defer view.allocator.free(values);
    const filled = view.getAllInto(values) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => panicUnexpected("reading chunked list oracle values", err),
    };
    assert(std.mem.eql(ListT.Element.Type, filled, reference.items));

    var expected_root: [32]u8 = undefined;
    ListT.hashTreeRoot(view.allocator, reference, &expected_root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => panicUnexpected("hashing chunked list oracle values", err),
    };
    const actual_root = view.hashTreeRoot() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => panicUnexpected("hashing chunked list oracle view", err),
    };
    assert(std.mem.eql(u8, actual_root, &expected_root));
}

fn assertInvalidGrowTo(
    comptime ListT: type,
    view: *ListT.TreeView,
    length: usize,
    argument: u8,
) void {
    const shrink = length > 0 and argument & 1 == 0;
    const new_length = if (shrink) length - 1 else ListT.limit + 1;
    const expected_error = if (shrink) error.InvalidLength else error.LengthOverLimit;

    view.growTo(new_length) catch |err| {
        assert(err == expected_error);
        const length_after = view.length() catch |length_err| {
            panicUnexpected("reading list length after rejected growth", length_err);
        };
        assert(length_after == length);
        return;
    };
    @panic("invalid growTo length accepted");
}

fn panicUnexpected(comptime context: []const u8, err: anyerror) noreturn {
    std.debug.panic("{s}: {s}", .{ context, @errorName(err) });
}

inline fn computeInitial(comptime Element: type, i: usize) Element {
    if (Element == u64) return @as(u64, @intCast(i)) *% 31 +% 7;
    if (Element == u32) return @as(u32, @intCast((i *% 31 +% 7) & 0xFFFFFFFF));
    @compileError("computeInitial: unsupported Element type");
}

inline fn elementFromSeed(comptime Element: type, seed: u8) Element {
    return @as(Element, @intCast(seed));
}

inline fn elementEql(comptime Element: type, a: Element, b: Element) bool {
    return a == b;
}
