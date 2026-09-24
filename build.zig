const std = @import("std");
const zapi = @import("zapi");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const manifest = @import("build.zig.zon");
    const result = try zbuild.configureBuild(b, manifest, .{});

    const network_tools = b.step("check:network-tools", "Compile network examples, interoperability peers, and benchmark");
    for ([_][]const u8{ "discv5_interop", "discv5_crawl", "ping_peer", "reqresp_peer", "managed_peer", "network_interop_peer", "managed_interop_peer", "bench_network" }) |name| {
        network_tools.dependOn(&result.executable(name).?.step);
    }

    zapi.addAddonIdentity(
        b,
        result.library("bindings").?,
        manifest,
    );
}
