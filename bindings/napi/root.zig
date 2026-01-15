const napi = @import("zapi:napi");

comptime {
    napi.module.register(register);
}

fn register(env: napi.Env, exports: napi.Value) !void {
    try @import("./pool.zig").register(env, exports);
    try @import("./pubkey2index.zig").register(env, exports);
    try @import("./index2pubkey.zig").register(env, exports);
}
