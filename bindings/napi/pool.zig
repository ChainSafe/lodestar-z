const std = @import("std");
const js = @import("zapi:zapi").js;
const Node = @import("persistent_merkle_tree").Node;
const RefCount = @import("state_transition").RefCount;

/// Backs the `PoolRc` wrapper allocation only — `Node.Pool` uses its own
/// `InitOptions` allocators.
const allocator = std.heap.page_allocator;

const default_pool_size: u32 = 0;

// NOTE: not `pub`. zapi's `exportModule` auto-exports every `pub` decl of this
// module and recurses into any `pub` struct type, trying to wrap its methods as
// JS functions. A `pub const PoolRc = RefCount(Node.Pool)` makes zapi descend
// into `RefCount(Node.Pool).init`, whose params aren't zapi DSL types, which is
// a compile error. Keeping it private hides it from the exporter. Consumers in
// other files declare their own `RefCount(Node.Pool)` alias — generic
// instantiations are memoized, so it's the same type.
const PoolRc = RefCount(Node.Pool);

/// Pool is wrapped in `RefCount` so binding objects holding pool refs at
/// process exit keep the pool alive until their JS finalizer runs. NAPI
/// env cleanup hook fires before module-level JS holders are finalized,
/// so an unconditional `pool.deinit()` there would free memory that
/// `pool.unref()` calls in those finalizers still need.
// Not `pub`: internal helper. zapi's exporter recurses into every `pub` struct
// type and rejects its non-DSL methods (`init(self: *State)` etc.). `state`
// below stays `pub` (a value, which the exporter skips) so other files can use it.
const State = struct {
    pool_rc: ?*PoolRc = null,

    pub fn init(self: *State) !void {
        if (self.pool_rc != null) return;

        // Small-object lane must stay non-page: page_allocator rounds each
        // alloc to 4 KB and blows up once the binding preheats 10M nodes.
        var pool_value = try Node.Pool.init(.{ .allocator = std.heap.c_allocator, .pool_size = default_pool_size });
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
        std.debug.assert(self.pool_rc != null);
        return &self.pool_rc.?.instance;
    }

    pub fn poolRc(self: *State) *PoolRc {
        std.debug.assert(self.pool_rc != null);
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
