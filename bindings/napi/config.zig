const js = @import("zapi:zapi").js;
const snapshot = @import("./config_snapshot.zig");

const State = struct {
    current: ?*snapshot.SnapshotRc = null,

    pub fn init(self: *State) !void {
        self.current = try snapshot.createDefault();
    }

    pub fn deinit(self: *State) void {
        if (self.current) |current| current.unref();
        self.current = null;
    }
};

pub threadlocal var state: State = .{};

/// Sets the configuration used by subsequent static BeaconStateView construction.
pub fn set(object: js.Value, genesis_root: js.Uint8Array) !void {
    const next = try snapshot.create(object, genesis_root);
    errdefer next.unref();
    const previous = state.current orelse return error.ConfigNotInitialized;
    state.current = next;
    previous.unref();
}
