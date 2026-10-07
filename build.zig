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

    configureEreVerifier(b, result);
}

/// ere.zig links `libere_verifier_c` into the `ere` module.
/// Two things stay on the consumer side: Zig's self-hosted x86_64 ELF linker
/// cannot read the archive, so x86_64 Linux Debug binaries use LLVM and LLD,
/// and on native macOS the verifier is a dylib that must sit beside
/// `bindings.node`.
fn configureEreVerifier(b: *std.Build, result: zbuild.BuildResult) void {
    const target = result.module("ere").?.resolved_target.?.result;
    if (target.os.tag == .linux and target.cpu.arch == .x86_64) {
        const compiles = [_]*std.Build.Step.Compile{
            result.library("bindings").?,
            result.testArtifact("ere").?,
        };
        for (compiles) |compile| {
            compile.use_llvm = true;
            compile.use_lld = true;
        }
    }

    const package = result.dependency("ere_zig").?;
    if (package.builder.named_lazy_paths.get("libere_verifier_c.dylib")) |dylib| {
        const install = b.addInstallLibFile(dylib, "libere_verifier_c.dylib");
        b.top_level_steps.get("build-lib:bindings").?.step.dependOn(&install.step);
    }
}
