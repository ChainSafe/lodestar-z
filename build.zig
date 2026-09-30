const std = @import("std");
const zapi = @import("zapi");
const zbuild = @import("zbuild");

pub fn build(b: *std.Build) !void {
    @setEvalBranchQuota(200_000);
    const manifest = @import("build.zig.zon");
    const result = try zbuild.configureBuild(b, manifest, .{});
    addGossipSha256(b, result.module("network").?);
    const leveldb = result.dependency("leveldb_c").?.artifact("leveldb").root_module;
    leveldb.pic = true;
    // The pinned upstream build spells O_CLOEXEC with a zero; keep database descriptors out of child processes.
    if (leveldb.resolved_target.?.result.os.tag != .windows) leveldb.addCMacro("HAVE_O_CLOEXEC", "1");
    // snappy.zig leaves its static library to the target's default, which is not position independent for musl, and
    // the addon links it into a shared library.
    result.dependency("snappy").?.artifact("snappy").root_module.pic = true;
    // binding.zig checks its quiche_send_info against the C compiler's layout for the target.
    const network = result.module("network").?;
    const send_info_layout = b.addTranslateC(.{
        .root_source_file = b.path("src/network/quic/send_info_layout.h"),
        .target = network.resolved_target.?,
        .optimize = network.optimize.?,
    });
    send_info_layout.addIncludePath(result.dependency("quiche_zig").?.builder.dependency("quiche", .{}).path("include"));
    network.addImport("quiche_send_info_layout", send_info_layout.createModule());

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
    const arm = b.option(bool, "gossip-sha256-arm", "Also dispatch on aarch64 Linux and macOS, before ARM hardware has qualified it (default: false)") orelse false;
    const target = network.resolved_target.?;
    const os = target.result.os.tag;
    const features: ?std.Target.Cpu.Feature.Set = switch (target.result.cpu.arch) {
        .x86_64 => std.Target.x86.featureSet(&.{ .sha, .avx2 }),
        .aarch64 => if (arm and (os == .linux or os == .macos)) std.Target.aarch64.featureSet(&.{ .neon, .sha2 }) else null,
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
