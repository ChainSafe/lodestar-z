const js = @import("zapi:zapi").js;
const snapshot = @import("./config_snapshot.zig");
const BeaconStateView = @import("./BeaconStateView.zig");

pub const js_meta = js.class(.{});

config_rc: *snapshot.SnapshotRc,
const StateTransition = @This();

pub fn init(chain_config: js.Value, genesis_validators_root: js.Uint8Array) !StateTransition {
    return .{ .config_rc = try snapshot.create(chain_config, genesis_validators_root) };
}

pub fn deinit(self: *StateTransition) void {
    self.config_rc.unref();
}

pub fn createFromBytes(self: *const StateTransition, bytes: js.Uint8Array) !BeaconStateView {
    return BeaconStateView.createFromBytes(bytes, self);
}
