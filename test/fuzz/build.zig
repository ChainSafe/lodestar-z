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
        max_input_len: u32,
        corpus_version: u32 = 1,
        extra_libs: []const *std.Build.Step.Compile = &.{},

        fn corpus(self: @This(), bb: *std.Build) []const u8 {
            return bb.fmt("corpus/{s}-cmin", .{self.name});
        }
    };

    const fuzzers = &[_]Fuzzer{
        .{ .name = "ssz_basic", .max_input_len = 34 },
        .{ .name = "ssz_bitlist", .max_input_len = 259 },
        .{ .name = "ssz_bitvector", .max_input_len = 66 },
        .{ .name = "ssz_bytelist", .max_input_len = 1026 },
        .{ .name = "ssz_containers", .max_input_len = 16614 },
        .{
            .name = "ssz_lists",
            .max_input_len = 4161,
            .extra_libs = &.{dep_hashtree.artifact("hashtree")},
        },
        .{
            .name = "ssz_chunked_leaf_set",
            .max_input_len = 4097,
            .extra_libs = &.{dep_hashtree.artifact("hashtree")},
        },
        .{
            .name = "ssz_nested_opaque_proof",
            .max_input_len = 8191,
            .extra_libs = &.{dep_hashtree.artifact("hashtree")},
        },
        .{
            .name = "ssz_opaque_roundtrip",
            .max_input_len = 1048576,
            .extra_libs = &.{dep_hashtree.artifact("hashtree")},
        },
        .{
            .name = "bls_public_key",
            .max_input_len = 97,
            .extra_libs = &.{dep_blst.artifact("blst")},
        },
        .{
            .name = "bls_signature",
            .max_input_len = 193,
            .extra_libs = &.{dep_blst.artifact("blst")},
        },
        .{
            .name = "bls_aggregate_pk",
            .max_input_len = 6144,
            .extra_libs = &.{dep_blst.artifact("blst")},
        },
        .{
            .name = "bls_aggregate_sig",
            .max_input_len = 12288,
            .extra_libs = &.{dep_blst.artifact("blst")},
        },
    };

    const fuzz_target = b.option(
        []const u8,
        "fuzz-target",
        "Build and replay only the named fuzz target",
    );
    if (fuzz_target) |selected_target| {
        var found = false;
        for (fuzzers) |fuzzer| {
            if (std.mem.eql(u8, selected_target, fuzzer.name)) {
                found = true;
                break;
            }
        }
        if (!found) {
            std.process.fatal("unknown fuzz target: {s}", .{selected_target});
        }
    }

    var targets_json: std.Io.Writer.Allocating = .init(b.allocator);
    defer targets_json.deinit();

    targets_json.writer.writeAll("{\"include\":[") catch @panic("OOM");
    for (fuzzers, 0..) |fuzzer, index| {
        if (index > 0) {
            targets_json.writer.writeByte(',') catch @panic("OOM");
        }
        targets_json.writer.print(
            "{{\"target\":\"{s}\",\"max_input_len\":{d},\"corpus_version\":{d}}}",
            .{ fuzzer.name, fuzzer.max_input_len, fuzzer.corpus_version },
        ) catch @panic("OOM");
    }
    targets_json.writer.writeAll("]}") catch @panic("OOM");

    const write_files = b.addWriteFiles();
    const targets_json_file = write_files.add("targets.json", targets_json.written());
    const install_targets_json = b.addInstallFile(
        targets_json_file,
        "share/lodestar-z-fuzz/targets.json",
    );
    const metadata_step = b.step(
        "fuzz-metadata",
        "Write the fuzz target matrix without compiling fuzzers",
    );
    metadata_step.dependOn(&install_targets_json.step);

    const replay_corpus_step = b.step(
        "replay-corpus",
        "Replay committed bootstrap fuzz corpora",
    );

    for (fuzzers) |fuzzer| {
        if (fuzz_target) |selected_target| {
            if (!std.mem.eql(u8, selected_target, fuzzer.name)) continue;
        }

        const run_step = b.step(
            b.fmt("run-{s}", .{fuzzer.name}),
            b.fmt("Run {s} with afl-fuzz", .{fuzzer.name}),
        );

        const lib_mod = b.createModule(.{
            .root_source_file = b.path(b.fmt("src/fuzz_{s}.zig", .{fuzzer.name})),
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
        lib_mod.addImport(
            "persistent_merkle_tree",
            lodestar_z.module("persistent_merkle_tree"),
        );
        const fuzz_options = b.addOptions();
        fuzz_options.addOption(u32, "max_input_len", fuzzer.max_input_len);
        const fuzz_options_mod = fuzz_options.createModule();
        lib_mod.addImport("fuzz_options", fuzz_options_mod);

        const lib = b.addLibrary(.{
            .name = fuzzer.name,
            .root_module = lib_mod,
        });
        lib.root_module.stack_check = false;
        lib.root_module.fuzz = true;

        const exe = afl.addInstrumentedExe(b, lib, fuzzer.extra_libs);
        const mkdir = b.addSystemCommand(&.{
            "mkdir", "-p",
        });
        mkdir.addDirectoryArg(
            b.path(b.fmt("afl-out/{s}", .{fuzzer.name})),
        );
        const run = afl.addFuzzerRun(
            b,
            exe,
            b.path(fuzzer.corpus(b)),
            b.path(b.fmt("afl-out/{s}", .{fuzzer.name})),
        );
        run.step.dependOn(&mkdir.step);
        run_step.dependOn(&run.step);

        const install = b.addInstallBinFile(
            exe,
            b.fmt("fuzz-{s}", .{fuzzer.name}),
        );
        b.getInstallStep().dependOn(&install.step);

        const repro_mod = b.createModule(.{
            .root_source_file = b.path("src/repro.zig"),
            .target = target,
            .optimize = optimize,
        });
        repro_mod.addImport("fuzz_target", lib_mod);
        repro_mod.addImport("fuzz_options", fuzz_options_mod);

        const repro_exe = b.addExecutable(.{
            .name = b.fmt("repro-{s}", .{fuzzer.name}),
            .root_module = repro_mod,
        });
        for (fuzzer.extra_libs) |extra_lib| {
            repro_exe.root_module.linkLibrary(extra_lib);
        }
        b.installArtifact(repro_exe);

        const replay_corpus = b.addRunArtifact(repro_exe);
        replay_corpus.addDirectoryArg(b.path(fuzzer.corpus(b)));
        replay_corpus_step.dependOn(&replay_corpus.step);
    }
}
