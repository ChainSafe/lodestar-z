const std = @import("std");
const zapi = @import("zapi");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const manifest = @import("build.zig.zon");
    const result = try zbuild.configureBuild(b, manifest, .{});
    addGossipSha256(b, result.module("network").?);

    const network_tools = b.step("check:network-tools", "Compile network examples, interoperability peers, and benchmark");
    for ([_][]const u8{ "discv5_interop", "discv5_crawl", "ping_peer", "reqresp_peer", "core_peer", "network_interop_peer", "core_interop_peer", "bench_network" }) |name| {
        network_tools.dependOn(&result.executable(name).?.step);
    }

    zapi.addAddonIdentity(
        b,
        result.library("bindings").?,
        manifest,
    );
}

/// Links the network module, and so every test, tool and addon that imports it, to an object that
/// hashes gossip message ids and fingerprints with the CPU features Zig's Sha256 accelerates. Only
/// this object is compiled with them; `gossipsub/sha256.zig` runs it after detecting them.
fn addGossipSha256(b: *std.Build, network: *std.Build.Module) void {
    const dispatch = b.option(bool, "gossip-sha256-dispatch", "Link the accelerated gossip SHA-256 object and select it at run time (default: true)") orelse true;
    const target = network.resolved_target.?;
    const features: ?std.Target.Cpu.Feature.Set = switch (target.result.cpu.arch) {
        .x86_64 => std.Target.x86.featureSet(&.{ .sha, .avx2 }),
        else => null,
    };
    const options = b.addOptions();
    options.addOption(bool, "accelerated", dispatch and features != null);
    network.addOptions("gossip_sha256_options", options);
    if (!dispatch) return;

    var query = target.query;
    query.cpu_model = .baseline;
    query.cpu_features_add = features orelse return;
    query.cpu_features_sub = .empty;
    const object = b.addObject(.{
        .name = "gossip_sha256",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/network/gossipsub/sha256_accelerated.zig"),
            .target = b.resolveTargetQuery(query),
            .optimize = network.optimize,
            .pic = true,
        }),
    });
    // Without link-time optimization, none of the object's code can be inlined into baseline code.
    object.lto = .none;
    object.bundle_compiler_rt = false;
    object.bundle_ubsan_rt = false;
    network.addObject(object);
}
