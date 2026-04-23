const std = @import("std");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const result = try zbuild.configureBuild(b, @import("build.zig.zon"), .{});

    // Workaround for ChainSafe/zbuild: configureBuild passes empty args to
    // `b.dependency(...)`, so deps get built at Debug regardless of -Doptimize.
    // Debug's default `sanitize_c=.full` emits `__ubsan_handle_*` calls that
    // can't be resolved when `bindings.node` is loaded by Node (no libubsan).
    // Force trap mode on every C-containing dep so failures trap locally.
    // Remove once zbuild forwards optimize/target to deps.
    const c_deps = [_]struct { []const u8, []const u8 }{
        .{ "blst", "blst" },
        .{ "hashtree", "hashtree" },
        .{ "snappy", "snappy" },
    };
    for (c_deps) |entry| {
        if (result.dependencies.get(entry[0])) |dep| {
            dep.artifact(entry[1]).root_module.sanitize_c = .trap;
        }
    }
}
