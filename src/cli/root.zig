//! CLI entrypoints and command wiring.

const std = @import("std");
const testing = std.testing;
const main_mod = @import("main.zig");

pub const main = main_mod.main;
pub const std_options = main_mod.std_options;
pub const bootnode = @import("bootnode.zig");
pub const shutdown = @import("shutdown.zig");
pub const genesis_util = @import("genesis_util.zig");

test {
    testing.refAllDecls(@This());
}
