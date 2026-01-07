const std = @import("std");

const container = @import("./tree_view/container.zig");
const array_basic = @import("./tree_view/array_basic.zig");
const array_composite = @import("./tree_view/array_composite.zig");
const list_basic = @import("./tree_view/list_basic.zig");
const list_composite = @import("./tree_view/list_composite.zig");
const bit_vector = @import("./tree_view/bit_vector.zig");
const bit_list = @import("./tree_view/bit_list.zig");

test {
    const testing = std.testing;
    testing.refAllDecls(container);
    testing.refAllDecls(array_basic);
    testing.refAllDecls(array_composite);
    testing.refAllDecls(list_basic);
    testing.refAllDecls(list_composite);
    testing.refAllDecls(bit_vector);
    testing.refAllDecls(bit_list);
}
