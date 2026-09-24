//! Configuration snapshots share one application-wide validator-index to pubkey mapping.

const std = @import("std");
const js = @import("zapi:zapi").js;
const owned_config = @import("./owned_config.zig");
const BeaconStateView = @import("./BeaconStateView.zig");

pub const js_meta = js.class(.{});

config_rc: *owned_config.OwnedConfigRc,
const StateTransition = @This();

pub fn init(chain_config: js.Value, genesis_validators_root: js.Uint8Array) !StateTransition {
    return .{ .config_rc = try owned_config.create(std.heap.c_allocator, chain_config, genesis_validators_root) };
}

pub fn deinit(self: *StateTransition) void {
    self.config_rc.unref();
}

pub fn createFromBytes(self: *const StateTransition, bytes: js.Uint8Array) !BeaconStateView {
    return BeaconStateView.createFromBytes(bytes, self);
}
