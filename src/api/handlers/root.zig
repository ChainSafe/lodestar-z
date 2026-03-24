//! Route handler index.
//!
//! Re-exports all handler modules for convenient access from the router.

const std = @import("std");
const testing = std.testing;

pub const node = @import("node.zig");
pub const beacon = @import("beacon.zig");
pub const config = @import("config.zig");
pub const debug = @import("debug.zig");
pub const events = @import("events.zig");
pub const validator = @import("validator.zig");

test {
    testing.refAllDecls(node);
    testing.refAllDecls(beacon);
    testing.refAllDecls(config);
    testing.refAllDecls(debug);
    testing.refAllDecls(events);
    testing.refAllDecls(validator);
}
