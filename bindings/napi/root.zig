const napi = @import("zapi:napi");
const pool = @import("./pool.zig");
const pubkey2index = @import("./pubkey2index.zig");
const config = @import("./config.zig");
const shuffle = @import("./shuffle.zig");

comptime {
    napi.module.register(register);
}

pub fn deinit(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    pool.deinit();
    pubkey2index.deinit();
    config.deinit();

    return env.getUndefined();
}

fn register(env: napi.Env, exports: napi.Value) !void {
    try pool.register(env, exports);
    try pubkey2index.register(env, exports);
    try config.register(env, exports);
    try shuffle.register(env, exports);

    try exports.setNamedProperty("deinit", try env.createFunction(
        "deinit",
        0,
        deinit,
        null,
    ));
}
