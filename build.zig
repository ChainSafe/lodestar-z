const std = @import("std");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const result = try zbuild.configureBuild(b, @import("build.zig.zon"), .{});

    // blst compiles CPU dispatch at build time: on x86_64 targets whose CPU baseline
    // lacks ADX (e.g. the generic x86_64 used for published npm artifacts) it emits
    // only the slow mulq path — measured 15-19% slower verification than the mulx
    // path actually supported by virtually all production hardware (Broadwell+,
    // 2015). __BLST_PORTABLE__ compiles BOTH backends with cpuid runtime dispatch
    // instead, costing one predictable branch. Targets that already guarantee ADX
    // (-Dcpu=native on modern hardware) keep the leaner ADX-only build.
    //
    // The blst dependency exposes this as -Dportable, but zbuild's declarative
    // manifest cannot forward dep args without dropping target/optimize inheritance
    // (a .zon literal cannot reference the resolved target), so the macro is added
    // here, post-configure — the build graph is lazy, nothing has compiled yet.
    // Fail loudly if the dependency is renamed/missing: a silent miss here would
    // ship a 15-19% slower (mulq-only) x86_64 binary with no error anywhere.
    const blst_dep = result.dependencies.get("blst") orelse return error.MissingBlstDependency;
    const lib = blst_dep.artifact("blst");
    const cpu = lib.root_module.resolved_target.?.result.cpu;
    if (cpu.arch == .x86_64 and !std.Target.x86.featureSetHas(cpu.features, .adx)) {
        lib.root_module.addCMacro("__BLST_PORTABLE__", "");
    }
}
