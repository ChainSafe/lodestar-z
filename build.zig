const std = @import("std");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    _ = try zbuild.configureBuild(b, @import("build.zig.zon"), .{});
}
