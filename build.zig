const std = @import("std");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const zbuild_result = try zbuild.configureBuild(b, @import("build.zig.zon"), .{});

    const bls_module = zbuild_result.module("bls").?;
    const blst_artifact = zbuild_result.dependency("blst").?.artifact("blst");
    const translate_blst = b.addTranslateC(.{
        .root_source_file = b.path("src/bls/blst_c.h"),
        .target = bls_module.resolved_target.?,
        .optimize = bls_module.optimize.?,
    });
    translate_blst.addIncludePath(blst_artifact.getEmittedIncludeTree());
    bls_module.addImport("blst_c", translate_blst.createModule());
}
