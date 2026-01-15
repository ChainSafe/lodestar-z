const std = @import("std");
const napi = @import("zapi:napi");
const Index2PubkeyCache = @import("state_transition").Index2PubkeyCache;

/// Pool uses page allocator for internal allocations.
/// It's recommended to never reallocate the index2pubkey after initialization.
const allocator = std.heap.page_allocator;

/// A global index2pubkey for N-API bindings to use.
pub var index2pubkey: Index2PubkeyCache = undefined;
var initialized: bool = false;

const default_initial_capacity: u32 = 2_000_000;

pub fn index2pubkeyInit(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (initialized) {
        return env.getUndefined();
    }
    const initial_capacity_value = cb.getArg(0);
    const initial_capacity = if (initial_capacity_value) |i| try i.getValueUint32() else default_initial_capacity;

    index2pubkey = try Index2PubkeyCache.initCapacity(allocator, initial_capacity);
    initialized = true;

    return env.getUndefined();
}

pub fn index2pubkeyDeinit(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    if (!initialized) {
        return env.getUndefined();
    }

    index2pubkey.deinit();
    initialized = false;
    return env.getUndefined();
}

pub fn index2pubkeyIsInitialized(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    return try env.getBoolean(initialized);
}

pub fn index2pubkeyGet(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.Index2PubkeyNotInitialized;
    }

    const index = try cb.arg(0).getValueUint32();
    if (index >= index2pubkey.items.len) {
        return env.getUndefined();
    }

    // TODO expose bls classes
    const pubkey = index2pubkey.items[@intCast(index)];
    var pubkey_arraybuffer_bytes: *[48]u8 = undefined;
    const pubkey_arraybuffer = try env.createArrayBuffer(48, &pubkey_arraybuffer_bytes);
    const pubkey_array = try env.createTypedarray(napi.Value.TypedarrayType.uint8, 48, pubkey_arraybuffer, 0);
    @memcpy(pubkey_arraybuffer_bytes, pubkey.compress());
    return pubkey_array;
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const index2pubkey_obj = try env.createObject();
    try index2pubkey_obj.setNamedProperty("init", try env.createFunction(
        "init",
        1,
        index2pubkeyInit,
        null,
    ));
    try index2pubkey_obj.setNamedProperty("deinit", try env.createFunction(
        "deinit",
        0,
        index2pubkeyDeinit,
        null,
    ));
    try index2pubkey_obj.setNamedProperty("get", try env.createFunction(
        "get",
        1,
        index2pubkeyGet,
        null,
    ));

    try exports.setNamedProperty("index2pubkey", index2pubkey_obj);
}
