const std = @import("std");
const js = @import("zapi:zapi").js;
const Node = @import("persistent_merkle_tree").Node;

pub const State = struct {
    pool: Node.Pool = undefined,
    initialized: bool = false,

    pub fn init(self: *State) !void {
        if (self.initialized) return;
        self.pool = try Node.Pool.init(.{});
        self.initialized = true;
    }

    pub fn deinit(self: *State) void {
        if (!self.initialized) return;
        self.pool.deinit();
        self.initialized = false;
    }
};

pub var state: State = .{};

/// JS: pool.ensureCapacity(newSize)
pub fn ensureCapacity(new_size: js.Number) !void {
    if (!state.initialized) {
        return error.PoolNotInitialized;
    }

    const requested = new_size.assertU32();
    const old_size = state.pool.nodes.capacity;
    if (requested <= old_size) {
        return;
    }
    try state.pool.preheat(@intCast(requested - state.pool.nodes.capacity));
}
