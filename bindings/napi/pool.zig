const std = @import("std");
const napi = @import("zapi:napi");
const Node = @import("persistent_merkle_tree").Node;

/// Pool uses page allocator for internal allocations.
/// It's recommended to never reallocate the pool after initialization.
const allocator = std.heap.page_allocator;

/// A global pool for N-API bindings to use.
pub var pool: Node.Pool = undefined;
var initialized: bool = false;

const default_pool_size: u32 = 0;

pub fn init() !void {
    if (initialized) {
        return;
    }

    pool = try Node.Pool.init(allocator, default_pool_size);
    initialized = true;
}

pub fn deinit() void {
    if (!initialized) {
        return;
    }

    pool.deinit();
    initialized = false;
}

pub fn Pool_ensureCapacity(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.PoolNotInitialized;
    }

    const old_size = pool.nodes.capacity;
    const new_size = try cb.arg(0).getValueUint32();
    if (new_size <= old_size) {
        return env.getUndefined();
    }
    try pool.preheat(@intCast(new_size - pool.nodes.capacity));
    return env.getUndefined();
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const pool_obj = try env.createObject();
    try pool_obj.setNamedProperty("ensureCapacity", try env.createFunction(
        "ensureCapacity",
        1,
        Pool_ensureCapacity,
        null,
    ));
    try exports.setNamedProperty("pool", pool_obj);
}
