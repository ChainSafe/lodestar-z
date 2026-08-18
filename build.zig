const std = @import("std");
const zapi_build = @import("zapi");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const manifest = @import("build.zig.zon");
    const result = try zbuild.configureBuild(b, manifest, .{});

    zapi_build.addAddonIdentity(
        b,
        result.library("bindings").?,
        manifest,
    );
}
