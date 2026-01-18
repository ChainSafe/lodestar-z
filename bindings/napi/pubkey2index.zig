const std = @import("std");
const napi = @import("zapi:napi");
const PubkeyIndexMap = @import("state_transition").PubkeyIndexMap;
const Index2PubkeyCache = @import("state_transition").Index2PubkeyCache;

/// Pool uses page allocator for internal allocations.
/// It's recommended to never reallocate the pubkey2index after initialization.
const allocator = std.heap.page_allocator;

/// A global pubkey2index for N-API bindings to use.
pub var pubkey2index: PubkeyIndexMap = undefined;
/// A global index2pubkey for N-API bindings to use.
pub var index2pubkey: Index2PubkeyCache = undefined;
var initialized: bool = false;

const default_initial_capacity: u32 = 0;

pub fn init() !void {
    if (initialized) {
        return;
    }

    pubkey2index = PubkeyIndexMap.init(allocator);
    try pubkey2index.ensureTotalCapacity(default_initial_capacity);
    index2pubkey = try Index2PubkeyCache.initCapacity(allocator, default_initial_capacity);
    initialized = true;
}

pub fn deinit() void {
    if (!initialized) {
        return;
    }

    pubkey2index.deinit();
    index2pubkey.deinit();
    initialized = false;
}

pub fn pubkey2indexGet(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const pubkey_info = try cb.arg(0).getTypedarrayInfo();
    if (pubkey_info.data.len != 48) {
        return error.InvalidPubkeyLength;
    }

    const index = pubkey2index.get(pubkey_info.data[0..48].*) orelse return env.getUndefined();
    return try env.createUint32(@intCast(index));
}

pub fn index2pubkeyGet(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const index = try cb.arg(0).getValueUint32();
    if (index >= index2pubkey.items.len) {
        return env.getUndefined();
    }

    // TODO expose bls classes, this is not what we want at all
    const pubkey = index2pubkey.items[@intCast(index)];
    var pubkey_arraybuffer_bytes: [*]u8 = undefined;
    const pubkey_arraybuffer = try env.createArrayBuffer(48, &pubkey_arraybuffer_bytes);
    const pubkey_array = try env.createTypedarray(.uint8, 48, pubkey_arraybuffer, 0);
    @memcpy(pubkey_arraybuffer_bytes, &pubkey.compress());
    return pubkey_array;
}

pub fn ensureCapacity(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const old_size = index2pubkey.capacity;
    const new_size = try cb.arg(0).getValueUint32();
    if (new_size <= old_size) {
        return env.getUndefined();
    }
    try pubkey2index.ensureTotalCapacity(new_size);
    try index2pubkey.ensureTotalCapacity(new_size);
    return env.getUndefined();
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const pubkey2index_obj = try env.createObject();
    const index2pubkey_obj = try env.createObject();

    try pubkey2index_obj.setNamedProperty("get", try env.createFunction(
        "get",
        1,
        pubkey2indexGet,
        null,
    ));

    try index2pubkey_obj.setNamedProperty("get", try env.createFunction(
        "get",
        1,
        index2pubkeyGet,
        null,
    ));

    const ensureCapacityValue = try env.createFunction(
        "get",
        1,
        index2pubkeyGet,
        null,
    );
    try pubkey2index_obj.setNamedProperty("ensureCapacity", ensureCapacityValue);
    try index2pubkey_obj.setNamedProperty("ensureCapacity", ensureCapacityValue);

    try exports.setNamedProperty("pubkey2index", pubkey2index_obj);
    try exports.setNamedProperty("index2pubkey", index2pubkey_obj);
}
