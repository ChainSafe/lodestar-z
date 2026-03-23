//! Route handler index.
//!
//! Re-exports all handler modules for convenient access from the router.

const std = @import("std");
const testing = std.testing;

pub const node = @import("node.zig");
pub const beacon = @import("beacon.zig");
pub const config = @import("config.zig");

test {
    testing.refAllDecls(node);
    testing.refAllDecls(beacon);
    testing.refAllDecls(config);
}
