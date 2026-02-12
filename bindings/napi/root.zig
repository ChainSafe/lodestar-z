const napi = @import("zapi:napi");
const pool = @import("./pool.zig");
const pubkeys = @import("./pubkeys.zig");
const config = @import("./config.zig");
const shuffle = @import("./shuffle.zig");
const state_transition = @import("./state_transition.zig");
const BeaconStateView = @import("./BeaconStateView.zig");
const blst = @import("./blst.zig");

comptime {
    napi.module.register(register);
}

pub fn deinit(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    pool.deinit();
    pubkeys.deinit();
    config.deinit();

    return env.getUndefined();
}

fn register(env: napi.Env, exports: napi.Value) !void {
    try pool.init();
    try pubkeys.init();
    config.init();

    try state_transition.register(env, exports);
    try pool.register(env, exports);
    try pubkeys.register(env, exports);
    try config.register(env, exports);
    try shuffle.register(env, exports);
    try BeaconStateView.register(env, exports);
    try blst.register(env, exports);

    try exports.setNamedProperty("deinit", try env.createFunction(
        "deinit",
        0,
        deinit,
        null,
    ));
}
