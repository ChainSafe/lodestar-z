// Fuzz target for the chunked_leaf write path in BasicPackedChunks.set().
//
// Decodes the input bytes into a stream of (op, idx, val) records and replays
// them against a chunked_leaf-enabled list, maintaining a reference []u64
// as ground truth. The strongest invariant — `view.hashTreeRoot() ==
// fromValue(reference).getRoot()` — is checked at every commit op.
//
// This complements the deterministic property test in
// src/ssz/tree_view/list_basic.zig (`property test cross-commit set sequences`)
// by exploring random op sequences AFL evolves to maximize edge coverage.
//
// Input format (4 bytes per op, leftover trailing bytes ignored):
//   [op, arg_lo, arg_hi, val_seed]
//     op % 3 selects:
//       0 -> set(idx, val): idx = (arg_hi << 8 | arg_lo) % ItemCount, val = val_seed
//       1 -> commit + root cross-check (idx/val ignored)
//       2 -> get(idx) spot-check (val_seed ignored)
//
// What this exercises:
//   * Path 3 (rc>=1 shared chunked_leaf, CoW): first set to a chunked_leaf
//     after init or commit.
//   * Path 2 (rc=0 transient chunked_leaf, in-place byte write): subsequent
//     sets to the same chunked_leaf within one commit cycle.
//   * Path 2's debug asserts (existing_kind == .chunked_leaf, gindex in
//     `changed`): tripped if the rc state machine drifts on any op.
//
// Out of scope: Path 1 (zero -> materialize via push) — covered by the
// `iteratorReadonly on sparsely grown list` test; would need push ops here
// and dynamic reference length.

const std = @import("std");
const assert = std.debug.assert;
const ssz = @import("ssz");
const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;

const fuzz_buffer_size: u32 = 64 * 1024 * 1024;
var fuzz_buf: [fuzz_buffer_size]u8 = undefined;

const Uint64 = ssz.UintType(64);
const Capacity: usize = 1 << 20;
// 2 full ChunkedLeaves (K=1024 chunks/CL * 4 items/chunk = 4096 items/CL).
// Indices [0, 4095] live in CL0, [4096, 8191] in CL1. The remaining 254
// chunked_leaf slots in the depth-8 chunked_leaf subtree stay as zero
// sentinels — set never visits them (ItemCount caps idx), but the read path
// (op=2, the hashTreeRoot tree walk) crosses zero sentinels in the upper
// branches.
const ItemCount: usize = 8192;

const ListT = ssz.FixedListType(Uint64, Capacity, .{ .chunked_leaf = true });

const op_size: usize = 4;

pub export fn zig_fuzz_init() callconv(.c) void {
    // Per-iteration setup happens in zig_fuzz_test; nothing to do once.
}

pub export fn zig_fuzz_test(buf: [*]const u8, len: usize) callconv(.c) void {
    // Precondition: at least one op worth of input.
    if (len < op_size) return;

    var fba = std.heap.FixedBufferAllocator.init(&fuzz_buf);
    const allocator = fba.allocator();

    var pool = Node.Pool.init(.{
        .page_allocator = allocator,
        .allocator = allocator,
        .pool_size = 4096,
    }) catch return;
    defer pool.deinit();

    // Reference array — initialized to deterministic content so the initial
    // view's root is well-defined. Op replays mutate `reference` in lockstep
    // with `view.set`, so the cross-check at commit ops can rebuild the
    // expected tree from scratch.
    const reference = allocator.alloc(u64, ItemCount) catch return;
    for (0..ItemCount) |i| reference[i] = @as(u64, @intCast(i));

    var src: ListT.Type = .empty;
    defer src.deinit(allocator);
    src.ensureTotalCapacity(allocator, ItemCount) catch return;
    for (reference) |v| src.append(allocator, v) catch return;

    const root_id = ListT.tree.fromValue(&pool, &src) catch return;
    var view = ListT.TreeView.init(allocator, &pool, root_id) catch return;
    defer view.deinit();

    var i: usize = 0;
    while (i + op_size <= len) : (i += op_size) {
        const op = buf[i] % 3;
        const arg_lo = buf[i + 1];
        const arg_hi = buf[i + 2];
        const val_seed = buf[i + 3];
        const idx = (@as(usize, arg_hi) << 8 | @as(usize, arg_lo)) % ItemCount;
        const val = @as(u64, val_seed);

        switch (op) {
            0 => {
                // set: mutate both reference and view; the Debug-build assert
                // inside chunks.zig set() validates the rc state machine on
                // every invocation.
                reference[idx] = val;
                view.set(idx, val) catch return;
            },
            1 => {
                // commit + root cross-check. hashTreeRoot internally commits,
                // then returns a pointer to the freshly-computed root. We
                // dereference immediately because subsequent fromValue calls
                // may grow the pool's MAL columns.
                const view_root_ptr = view.hashTreeRoot() catch return;
                const view_root = view_root_ptr.*;

                var ref_src: ListT.Type = .empty;
                defer ref_src.deinit(allocator);
                ref_src.ensureTotalCapacity(allocator, ItemCount) catch return;
                for (reference) |v| ref_src.append(allocator, v) catch return;

                const ref_root_id = ListT.tree.fromValue(&pool, &ref_src) catch return;
                defer pool.unref(ref_root_id);
                const ref_root = ref_root_id.getRoot(&pool).*;

                assert(std.mem.eql(u8, &ref_root, &view_root));
            },
            2 => {
                // Spot-check: view.get must agree with reference even
                // when transient chunked_leaves are staged in the view's
                // children_nodes cache (rc=0, only the view holds them).
                const got = view.get(idx) catch return;
                assert(got == reference[idx]);
            },
            else => unreachable,
        }
    }
}
