const napi = @import("zapi:napi");

comptime {
    napi.module.register(mod);
}

fn mod(env: napi.Env, exports: napi.Value) !void {
    try @import("./pool.zig").mod(env, exports);
}
