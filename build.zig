const std = @import("std");
const zapi = @import("zapi");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const manifest = @import("build.zig.zon");
    const result = try zbuild.configureBuild(b, manifest, .{});

    zapi.addAddonIdentity(
        b,
        result.library("bindings").?,
        manifest,
    );

    const spec_test_options = manifest.options_modules.spec_test_options;
    const print_spec_test_versions = b.addSystemCommand(&.{
        "echo",
        spec_test_options.spec_test_version.default,
        spec_test_options.ssz_spec_test_version.default,
    });
    b.step("spec-test-version", "Print the pinned consensus and ssz spec tests versions").dependOn(&print_spec_test_versions.step);
}
