const std = @import("std");
const napi = @import("zapi:napi");
const innerShuffleList = @import("state_transition").shuffle.innerShuffleList;

pub fn Shuffle_shuffleList(env: napi.Env, cb: napi.CallbackInfo(4)) !napi.Value {
    const list_info = try cb.arg(0).getTypedarrayInfo();
    // TODO: should we still put the check here because ts already specify it to be a Uint32Array
    if (list_info.array_type != .uint32) {
        return error.InvalidShuffleListType;
    }
    const list: []u32 = @alignCast(std.mem.bytesAsSlice(u32, list_info.data));
    const seed_info = try cb.arg(1).getTypedarrayInfo();
    const seed = seed_info.data;

    const rounds_u32 = try cb.arg(2).getValueUint32();
    if (rounds_u32 > 255 or rounds_u32 < 0) {
        return error.InvalidRoundsSize;
    }
    const rounds: u8 = @intCast(rounds_u32);
    const forwards = try cb.arg(3).getValueBool();

    try innerShuffleList(u32, list, seed, rounds, forwards);

    return env.getUndefined();
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const shuffle_obj = try env.createObject();
    try shuffle_obj.setNamedProperty("innerShuffleList", try env.createFunction(
        "innerShuffleList",
        4,
        Shuffle_shuffleList,
        null,
    ));
    try exports.setNamedProperty("shuffle", shuffle_obj);
}
