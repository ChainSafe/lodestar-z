const std = @import("std");
const js = @import("zapi:zapi").js;
const owned_config = @import("./owned_config.zig");

const State = struct {
    current: ?*owned_config.OwnedConfigRc = null,

    pub fn init(self: *State) !void {
        self.current = try owned_config.createDefault(std.heap.c_allocator);
    }

    pub fn deinit(self: *State) void {
        if (self.current) |current| current.unref();
        self.current = null;
    }
};

pub threadlocal var state: State = .{};

/// Sets the configuration used by subsequent static BeaconStateView construction.
pub fn set(object: js.Value, genesis_root: js.Uint8Array) !void {
    const next = try owned_config.create(std.heap.c_allocator, object, genesis_root);
    errdefer next.unref();
    const previous = state.current orelse return error.ConfigNotInitialized;
    state.current = next;
    previous.unref();
}
