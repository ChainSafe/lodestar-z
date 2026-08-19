const std = @import("std");
const zapi = @import("zapi");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const manifest = @import("build.zig.zon");
    const result = try zbuild.configureBuild(b, manifest, .{});

    // zapi derives each DSL class's `napi_type_tag` from this identity, so class
    // objects from a differently-built addon are rejected instead of unwrapped.
    zapi.addAddonIdentity(b, result.library("bindings").?, manifest);
}
