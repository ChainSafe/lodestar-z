const std = @import("std");

const container = @import("./tree_view/container.zig");
const array_basic = @import("./tree_view/array_basic.zig");
const array_composite = @import("./tree_view/array_composite.zig");
const list_basic = @import("./tree_view/list_basic.zig");
const list_composite = @import("./tree_view/list_composite.zig");

test {
    const testing = std.testing;
    testing.refAllDecls(container);
    testing.refAllDecls(array_basic);
    testing.refAllDecls(array_composite);
    testing.refAllDecls(list_basic);
    testing.refAllDecls(list_composite);
}
