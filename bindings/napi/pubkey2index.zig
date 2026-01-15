const std = @import("std");
const napi = @import("zapi:napi");
const PubkeyIndexMap = @import("state_transition").PubkeyIndexMap;

/// Pool uses page allocator for internal allocations.
/// It's recommended to never reallocate the pubkey2index after initialization.
const allocator = std.heap.page_allocator;

/// A global pubkey2index for N-API bindings to use.
pub var pubkey2index: PubkeyIndexMap = undefined;
var initialized: bool = false;

const default_initial_capacity: u32 = 2_000_000;

pub fn pubkey2indexInit(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (initialized) {
        return env.getUndefined();
    }
    const initial_capacity_value = cb.getArg(0);
    const initial_capacity = if (initial_capacity_value) |i| try i.getValueUint32() else default_initial_capacity;

    pubkey2index = PubkeyIndexMap.init(allocator);
    try pubkey2index.ensureTotalCapacity(initial_capacity);
    initialized = true;

    return env.getUndefined();
}

pub fn pubkey2indexDeinit(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    if (!initialized) {
        return env.getUndefined();
    }

    pubkey2index.deinit();
    initialized = false;
    return env.getUndefined();
}

pub fn pubkey2indexGet(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.Pubkey2IndexNotInitialized;
    }

    const pubkey_info = try cb.arg(0).getTypedarrayInfo();
    if (pubkey_info.data.len != 48) {
        return error.InvalidPubkeyLength;
    }

    const index = pubkey2index.get(pubkey_info.data[0..48].*) orelse return env.getUndefined();
    return try env.createUint32(@intCast(index));
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const pubkey2index_obj = try env.createObject();
    try pubkey2index_obj.setNamedProperty("init", try env.createFunction(
        "init",
        1,
        pubkey2indexInit,
        null,
    ));
    try pubkey2index_obj.setNamedProperty("deinit", try env.createFunction(
        "deinit",
        0,
        pubkey2indexDeinit,
        null,
    ));
    try pubkey2index_obj.setNamedProperty("get", try env.createFunction(
        "get",
        1,
        pubkey2indexGet,
        null,
    ));

    try exports.setNamedProperty("pubkey2index", pubkey2index_obj);
}
