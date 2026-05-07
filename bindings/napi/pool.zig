const std = @import("std");
const js = @import("zapi:zapi").js;
const Node = @import("persistent_merkle_tree").Node;
const RefCount = @import("state_transition").RefCount;

/// Pool uses page allocator for internal allocations.
/// It's recommended to never reallocate the pool after initialization.
const allocator = std.heap.page_allocator;

const default_pool_size: u32 = 0;

pub const PoolRc = RefCount(Node.Pool);

/// Pool is wrapped in `RefCount` so binding objects holding pool refs at
/// process exit keep the pool alive until their JS finalizer runs. NAPI
/// env cleanup hook fires before module-level JS holders are finalized,
/// so an unconditional `pool.deinit()` there would free memory that
/// `pool.unref()` calls in those finalizers still need.
pub const State = struct {
    pool_rc: ?*PoolRc = null,

    pub fn init(self: *State) !void {
        if (self.pool_rc != null) return;
        var pool_value = try Node.Pool.init(allocator, default_pool_size);
        errdefer pool_value.deinit();
        self.pool_rc = try PoolRc.init(allocator, pool_value);
    }

    pub fn deinit(self: *State) void {
        if (self.pool_rc) |rc| {
            rc.unref();
            self.pool_rc = null;
        }
    }

    pub fn pool(self: *State) *Node.Pool {
        return &self.pool_rc.?.instance;
    }

    pub fn poolRc(self: *State) *PoolRc {
        return self.pool_rc.?;
    }
};

pub var state: State = .{};

/// JS: pool.ensureCapacity(newSize)
pub fn ensureCapacity(new_size: js.Number) !void {
    if (state.pool_rc == null) {
        return error.PoolNotInitialized;
    }

    const requested = new_size.assertU32();
    const old_size = state.pool().nodes.capacity;
    if (requested <= old_size) {
        return;
    }
    try state.pool().preheat(@intCast(requested - state.pool().nodes.capacity));
}
