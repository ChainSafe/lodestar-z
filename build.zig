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
    const print_spec_test_version = b.addSystemCommand(&.{
        "echo",
        b.fmt("{s}-ssz-{s}-{s}", .{
            spec_test_options.spec_test_version.default,
            spec_test_options.ssz_spec_test_version.default,
            spec_test_options.ssz_spec_test_sha256.default,
        }),
    });
    b.step("spec-test-version", "Print the pinned spec test cache key").dependOn(&print_spec_test_version.step);
}
