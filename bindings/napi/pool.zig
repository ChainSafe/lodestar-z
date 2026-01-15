const std = @import("std");
const napi = @import("zapi:napi");
const Node = @import("persistent_merkle_tree").Node;

/// Pool uses page allocator for internal allocations.
/// It's recommended to never reallocate the pool after initialization.
const allocator = std.heap.page_allocator;

/// A global pool for N-API bindings to use.
var pool: Node.Pool = undefined;
var initialized: bool = false;

pub fn poolInit(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (initialized) {
        return env.getUndefined();
    }

    const pool_size = try cb.arg(0).getValueUint32();
    pool = try Node.Pool.init(allocator, pool_size);
    initialized = true;
    return env.getUndefined();
}

pub fn poolDeinit(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    if (!initialized) {
        return env.getUndefined();
    }

    pool.deinit();
    initialized = false;
    return env.getUndefined();
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const pool_obj = try env.createObject();
    try pool_obj.setNamedProperty("init", try env.createFunction(
        "init",
        1,
        poolInit,
        null,
    ));
    try pool_obj.setNamedProperty("deinit", try env.createFunction(
        "deinit",
        0,
        poolDeinit,
        null,
    ));

    try exports.setNamedProperty("pool", pool_obj);
}
