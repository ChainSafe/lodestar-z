const std = @import("std");
const Allocator = std.mem.Allocator;

const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

/// Deserialize an SSZ container into its TreeView, while ignoring (not deserializing) selected
/// fields by name and overriding them with precomputed subtrees.
///
/// `overrides` should be a struct literal where field names match container field names,
/// e.g. `. { .validators = seed_validators_node }`.
pub fn deserializeContainerOverrideFieldsWithRanges(
    allocator: Allocator,
    pool: *Node.Pool,
    comptime ContainerST: type,
    bytes: []const u8,
    ranges: *const [ContainerST.fields.len][2]usize,
    overrides: anytype,
) !ContainerST.TreeView {
    var nodes: [ContainerST.chunk_count]Node.Id = undefined;
    var owned_nodes: [ContainerST.chunk_count]Node.Id = undefined;
    var owned_len: usize = 0;

    // Important: `deserializeFromBytes` returns nodes with refcount 0. If we error out before
    // they're anchored under a committed root, they must be `unref`'d to avoid leaking Pool nodes.
    // Once container root is created, it becomes the sole owner: unref'ing the root is enough
    // and unref'ing child nodes again would be a double-unref.
    errdefer {
        var i: usize = 0;
        while (i < owned_len) : (i += 1) pool.unref(owned_nodes[i]);
    }

    inline for (ContainerST.fields, 0..) |field, i| {
        if (comptime @hasField(@TypeOf(overrides), field.name)) {
            nodes[i] = @field(overrides, field.name);
            continue;
        }

        const start = ranges[i][0];
        const end = ranges[i][1];
        const field_bytes = bytes[start..end];

        nodes[i] = try field.type.tree.deserializeFromBytes(pool, field_bytes);
        owned_nodes[owned_len] = nodes[i];
        owned_len += 1;
    }

    const root = try Node.fillWithContents(pool, &nodes, ContainerST.chunk_depth);
    errdefer pool.unref(root);
    owned_len = 0;

    return try ContainerST.TreeView.init(allocator, pool, root);
}

test "deserializeContainerOverrideFields... cleans up pool nodes on error" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 64);
    defer pool.deinit();

    const U64 = ssz.UintType(64);
    const U64List = ssz.FixedListType(U64, 4);
    const Fields = struct {
        a: U64,
        b: U64List,
    };
    const ContainerST = ssz.VariableContainerType(Fields);

    // Valid offsets for `b`, but `b` payload length is 1 which is not divisible by 8.
    var bytes: [13]u8 = undefined;
    @memset(&bytes, 0);
    std.mem.writeInt(u32, bytes[8..12], 12, .little);

    const baseline_in_use = pool.getNodesInUse();
    const ranges = try ContainerST.readFieldRanges(bytes[0..]);
    try std.testing.expectError(
        error.UnexpectedRemainder,
        deserializeContainerOverrideFieldsWithRanges(
            allocator,
            &pool,
            ContainerST,
            bytes[0..],
            &ranges,
            .{},
        ),
    );
    try std.testing.expectEqual(baseline_in_use, pool.getNodesInUse());
}
