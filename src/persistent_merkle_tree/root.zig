const std = @import("std");
const testing = std.testing;

// re-export depth for convenience
pub const Depth = @import("hashing").Depth;
pub const max_depth = @import("hashing").max_depth;

pub const Gindex = @import("gindex.zig").Gindex;
pub const Node = @import("Node.zig");
pub const View = @import("View.zig");
pub const proof = @import("proof.zig");

test {
    testing.refAllDeclsRecursive(@This());
    testing.refAllDecls(@import("node_test.zig"));
    testing.refAllDecls(@import("proof_test.zig"));
    testing.refAllDecls(@import("view_test.zig"));
}
