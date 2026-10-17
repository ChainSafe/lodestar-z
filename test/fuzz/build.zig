const std = @import("std");
const afl = @import("afl");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lodestar_z = b.dependency("lodestar_z", .{
        .target = target,
        .optimize = optimize,
    });

    const dep_blst = b.dependency("blst", .{
        .optimize = optimize,
        .target = target,
    });

    const dep_snappy = b.dependency("snappy", .{
        .target = target,
        .optimize = optimize,
    });

    const dep_hashtree = b.dependency("hashtree", .{
        .target = target,
        .optimize = optimize,
    });

    const quiche_module = lodestar_z.module("network").import_table.get("quiche_zig:quiche").?;
    std.debug.assert(quiche_module.link_objects.items.len == 1);
    // A harness links its bitcode, so it takes the network module's own objects (the accelerated
    // gossip SHA-256 object where the target has one) explicitly, as it takes quiche's.
    const network_objects = lodestar_z.module("network").link_objects.items;
    std.debug.assert(network_objects.len <= 1);
    const gossip_objects: []const std.Build.LazyPath = if (network_objects.len == 1)
        b.allocator.dupe(std.Build.LazyPath, &.{network_objects[0].other_step.getEmittedBin()}) catch @panic("out of memory")
    else
        &.{};
    const quiche_objects = std.mem.concat(b.allocator, std.Build.LazyPath, &.{ &.{quiche_module.link_objects.items[0].static_path}, gossip_objects }) catch @panic("out of memory");
    const network_fixture = b.createModule(.{
        .root_source_file = b.path("tools/network_fixture.zig"),
        .target = target,
        .optimize = optimize,
    });
    network_fixture.addImport("network", lodestar_z.module("network"));
    const seeds_module = b.createModule(.{
        .root_source_file = b.path("tools/network_corpus.zig"),
        .target = target,
        .optimize = optimize,
    });
    seeds_module.addImport("network_fixture", network_fixture);
    seeds_module.addImport("network", lodestar_z.module("network"));
    seeds_module.addImport("discv5", lodestar_z.module("discv5"));
    const seeds = b.addRunArtifact(b.addExecutable(.{ .name = "network_corpus", .root_module = seeds_module }));
    seeds.setCwd(b.path("."));
    if (b.args) |args| seeds.addArgs(args);
    b.step("network-corpus", "Generate valid QUIC TLS and DiscV5 fuzz seeds").dependOn(&seeds.step);

    // Tool: extract corpus seeds from spec test vectors
    {
        const extract_mod = b.createModule(.{
            .root_source_file = b.path(
                "tools/extract_spec_corpus.zig",
            ),
            .target = target,
            .optimize = optimize,
        });
        extract_mod.addImport(
            "snappy",
            dep_snappy.module("snappy"),
        );
        const extract_exe = b.addExecutable(.{
            .name = "extract_spec_corpus",
            .root_module = extract_mod,
        });
        const run_extract = b.addRunArtifact(extract_exe);
        run_extract.setCwd(b.path("."));
        const extract_step = b.step(
            "extract-corpus",
            "Extract spec test vectors as corpus seeds",
        );
        extract_step.dependOn(&run_extract.step);
    }

    const Fuzzer = struct {
        name: []const u8,
        corpus_suffix: []const u8 = "cmin",
        extra_libs: []const *std.Build.Step.Compile = &.{},
        extra_objects: []const std.Build.LazyPath = &.{},
        extra_args: []const []const u8 = &.{},
        input_max: ?u32 = null,

        /// Returns the corpus directory path for this fuzzer.
        /// Change the suffix to switch between -cmin and -initial.
        fn corpus(self: @This(), bb: *std.Build) []const u8 {
            return bb.fmt("corpus/{s}-{s}", .{ self.name, self.corpus_suffix });
        }

        fn source(self: @This(), bb: *std.Build) []const u8 {
            return bb.fmt("src/fuzz_{s}.zig", .{self.name});
        }
    };

    const base_fuzzers = &[_]Fuzzer{
        .{ .name = "ssz_basic" },
        .{ .name = "ssz_bitlist" },
        .{ .name = "ssz_bitvector" },
        .{ .name = "ssz_bytelist" },
        .{ .name = "ssz_containers" },
        .{ .name = "ssz_lists" },
        .{ .name = "ssz_chunked_leaf_set", .extra_libs = &.{dep_hashtree.artifact("hashtree")} },
        .{ .name = "ssz_nested_opaque_proof", .extra_libs = &.{dep_hashtree.artifact("hashtree")} },
        .{ .name = "ssz_opaque_roundtrip", .extra_libs = &.{dep_hashtree.artifact("hashtree")} },
        .{ .name = "bls_public_key", .extra_libs = &.{dep_blst.artifact("blst")} },
        .{ .name = "bls_signature", .extra_libs = &.{dep_blst.artifact("blst")} },
        .{ .name = "bls_aggregate_pk", .extra_libs = &.{dep_blst.artifact("blst")} },
        .{ .name = "bls_aggregate_sig", .extra_libs = &.{dep_blst.artifact("blst")} },
    };

    var fuzzers: std.ArrayList(Fuzzer) = .empty;
    fuzzers.appendSlice(b.allocator, base_fuzzers) catch @panic("out of memory");
    const snappy_libs = [_]*std.Build.Step.Compile{dep_snappy.artifact("snappy")};
    var rows = std.mem.tokenizeScalar(u8, @embedFile("network-targets.tsv"), '\n');
    while (rows.next()) |row| {
        var fields = std.mem.tokenizeAny(u8, row, " \t");
        const name = fields.next().?;
        const corpus = fields.next().?;
        const input_max = std.fmt.parseInt(u32, fields.next().?, 10) catch @panic("invalid network fuzz input bound");
        const link = fields.next().?;
        std.debug.assert(fields.next() == null);
        const snappy = std.mem.eql(u8, link, "snappy");
        const quiche = std.mem.eql(u8, link, "quiche");
        std.debug.assert(snappy or quiche or std.mem.eql(u8, link, "none"));
        fuzzers.append(b.allocator, .{
            .name = name,
            .corpus_suffix = corpus,
            .input_max = input_max,
            .extra_libs = if (snappy) &snappy_libs else &.{},
            .extra_objects = if (quiche) quiche_objects else gossip_objects,
            .extra_args = if (snappy or quiche) &.{ "-lc++", "-lc++abi", "-lunwind" } else &.{},
        }) catch @panic("out of memory");
    }
    const build_network = b.step("build-network", "Build every network harness from network-targets.tsv");

    for (fuzzers.items) |fuzzer| {
        const run_step = b.step(
            b.fmt("run-{s}", .{fuzzer.name}),
            b.fmt("Run {s} with afl-fuzz", .{fuzzer.name}),
        );

        const lib_mod = b.createModule(.{
            .root_source_file = b.path(fuzzer.source(b)),
            .target = target,
            .optimize = optimize,
        });
        lib_mod.addImport("ssz", lodestar_z.module("ssz"));
        lib_mod.addImport("bls", lodestar_z.module("bls"));
        lib_mod.addImport(
            "consensus_types",
            lodestar_z.module("consensus_types"),
        );
        lib_mod.addImport("preset", lodestar_z.module("preset"));
        lib_mod.addImport("constants", lodestar_z.module("constants"));
        lib_mod.addImport("discv5", lodestar_z.module("discv5"));
        lib_mod.addImport(
            "persistent_merkle_tree",
            lodestar_z.module("persistent_merkle_tree"),
        );
        lib_mod.addImport("network", lodestar_z.module("network"));
        lib_mod.addImport("network_fixture", network_fixture);

        const lib = b.addLibrary(.{
            .name = fuzzer.name,
            .root_module = lib_mod,
        });
        lib.root_module.stack_check = false;
        lib.root_module.fuzz = true;

        const exe = afl.addInstrumentedExe(b, lib, fuzzer.extra_libs, fuzzer.extra_objects, fuzzer.extra_args);
        const mkdir = b.addSystemCommand(&.{
            "mkdir", "-p",
        });
        mkdir.addDirectoryArg(
            b.path(b.fmt("afl-out/{s}", .{fuzzer.name})),
        );
        const run = b.addSystemCommand(&.{b.findProgram(&.{"afl-fuzz"}, &.{}) catch @panic("afl-fuzz is required")});
        run.addArg("-i");
        run.addDirectoryArg(b.path(fuzzer.corpus(b)));
        run.addArg("-o");
        run.addDirectoryArg(b.path(b.fmt("afl-out/{s}", .{fuzzer.name})));
        if (fuzzer.input_max) |maximum| run.addArgs(&.{ "-G", b.fmt("{d}", .{maximum}) });
        const dictionary = b.fmt("dictionaries/{s}.dict", .{fuzzer.name});
        const has_dictionary = found: {
            b.build_root.handle.access(b.graph.io, dictionary, .{}) catch |err| switch (err) {
                error.FileNotFound => break :found false,
                else => @panic("cannot read fuzz dictionary"),
            };
            break :found true;
        };
        if (has_dictionary) {
            run.addArg("-x");
            run.addFileArg(b.path(dictionary));
        }
        run.addArg("--");
        run.addFileArg(exe);
        run.step.dependOn(&mkdir.step);
        run_step.dependOn(&run.step);

        const install = b.addInstallBinFile(
            exe,
            b.fmt("fuzz-{s}", .{fuzzer.name}),
        );
        b.getInstallStep().dependOn(&install.step);
        const build_step = b.step(
            b.fmt("build-{s}", .{fuzzer.name}),
            b.fmt("Build {s} AFL harness", .{fuzzer.name}),
        );
        build_step.dependOn(&install.step);
        if (std.mem.startsWith(u8, fuzzer.name, "network_") or std.mem.eql(u8, fuzzer.name, "discv5_wire")) build_network.dependOn(&install.step);
    }
}
