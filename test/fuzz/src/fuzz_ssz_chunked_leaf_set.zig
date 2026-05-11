// Input: [selector_byte][op records of 4 bytes each]
//   selector % 4: 0/1 = u64 populated/empty, 2/3 = u32 populated/empty
//   op % 5: 0=set, 1=commit+root check, 2=get, 3=push, 4=clone-deinit
//   record layout: [op, arg_lo, arg_hi, val_seed]

const std = @import("std");
const assert = std.debug.assert;
const ssz = @import("ssz");
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;

const fuzz_buffer_size: u32 = 64 * 1024 * 1024;
var fuzz_buf: [fuzz_buffer_size]u8 = undefined;

const Capacity: usize = 1 << 20;
const ItemCount: usize = 4097; // one past CL0 so push hits Path 1 on CL1 boundary

const op_size: usize = 4;
const selector_count: u8 = 4;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(buf: [*]const u8, len: usize) callconv(.c) void {
    if (len < 1 + op_size) return;

    var fba = std.heap.FixedBufferAllocator.init(&fuzz_buf);
    const allocator = fba.allocator();

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

    var pool = Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 4096,
    }) catch return;
    defer pool.deinit();

    var reference = std.ArrayList(Element).empty;
    defer reference.deinit(allocator);
    reference.ensureTotalCapacity(allocator, ItemCount) catch return;
    for (0..initial_count) |i| reference.append(allocator, computeInitial(Element, i)) catch return;

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    src.ensureTotalCapacity(allocator, initial_count) catch return;
    for (reference.items) |v| src.append(allocator, v) catch return;

    const root_id = ListT.tree.fromValue(&pool, &src) catch return;
    var view = ListT.TreeView.init(allocator, &pool, root_id) catch return;
    defer view.deinit();

    var i: usize = 0;
    while (i + op_size <= data.len) : (i += op_size) {
        const op = data[i] % 5;
        const arg_lo = data[i + 1];
        const arg_hi = data[i + 2];
        const val_seed = data[i + 3];

        switch (op) {
            0 => {
                if (reference.items.len == 0) continue;
                const idx = (@as(usize, arg_hi) << 8 | @as(usize, arg_lo)) % reference.items.len;
                const val = elementFromSeed(Element, val_seed);
                reference.items[idx] = val;
                view.set(idx, val) catch return;
            },
            1 => {
                const view_root = (view.hashTreeRoot() catch return).*;

                var ref_src: ListT.Type = .empty;
                defer ref_src.deinit(allocator);
                ref_src.ensureTotalCapacity(allocator, reference.items.len) catch return;
                for (reference.items) |v| ref_src.append(allocator, v) catch return;

                const ref_root_id = ListT.tree.fromValue(&pool, &ref_src) catch return;
                defer pool.unref(ref_root_id);
                const ref_root = ref_root_id.getRoot(&pool).*;

                assert(std.mem.eql(u8, &ref_root, &view_root));
            },
            2 => {
                if (reference.items.len == 0) continue;
                const idx = (@as(usize, arg_hi) << 8 | @as(usize, arg_lo)) % reference.items.len;
                const got = view.get(idx) catch return;
                assert(elementEql(Element, got, reference.items[idx]));
            },
            3 => {
                if (reference.items.len >= ItemCount) continue;
                const val = elementFromSeed(Element, val_seed);
                reference.append(allocator, val) catch return;
                view.push(val) catch return;
            },
            4 => {
                // transfer_cache=false so source's pending writes survive; the
                // default true clears source's `changed`, which would silently
                // drift `reference` ahead of `view`.
                const clone = view.clone(.{ .transfer_cache = false }) catch return;
                clone.deinit();
            },
            else => unreachable,
        }
    }
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
