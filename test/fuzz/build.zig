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
        extra_libs: []const *std.Build.Step.Compile = &.{},

        /// Returns the corpus directory path for this fuzzer.
        /// Prefers the edge-deduplicated -cmin corpus and falls back to the
        /// hand-crafted -initial seeds for targets that have not been
        /// minimized yet.
        fn corpus(self: @This(), bb: *std.Build) []const u8 {
            const cmin = bb.fmt("corpus/{s}-cmin", .{self.name});
            bb.build_root.handle.access(bb.graph.io, cmin, .{}) catch {
                return bb.fmt("corpus/{s}-initial", .{self.name});
            };
            return cmin;
        }

        fn source(self: @This(), bb: *std.Build) []const u8 {
            return bb.fmt("src/fuzz_{s}.zig", .{self.name});
        }
    };

    const fuzzers = &[_]Fuzzer{
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

    const addHarnessImports = struct {
        fn add(mod: *std.Build.Module, lz: *std.Build.Dependency) void {
            mod.addImport("ssz", lz.module("ssz"));
            mod.addImport("bls", lz.module("bls"));
            mod.addImport(
                "consensus_types",
                lz.module("consensus_types"),
            );
            mod.addImport("preset", lz.module("preset"));
            mod.addImport("constants", lz.module("constants"));
            mod.addImport(
                "persistent_merkle_tree",
                lz.module("persistent_merkle_tree"),
            );
        }
    }.add;

    const replay_step = b.step(
        "replay",
        "Replay the committed corpus through every harness natively (no AFL++)",
    );

    // Instrumented builds need afl-cc; the native replay path does not.
    // Degrade the AFL++ steps to a clear failure instead of panicking at
    // configure time, so `zig build replay` works on hosts without AFL++.
    const have_afl = if (b.findProgram(&.{"afl-cc"}, &.{})) |_| true else |_| false;
    const afl_missing_msg =
        "afl-cc not found; install AFL++ to build instrumented fuzzers " ++
        "(see test/fuzz/README.md). `zig build replay` works without it.";

    inline for (fuzzers) |fuzzer| {
        const run_step = b.step(
            b.fmt("run-{s}", .{fuzzer.name}),
            b.fmt("Run {s} with afl-fuzz", .{fuzzer.name}),
        );

        if (have_afl) {
            const lib_mod = b.createModule(.{
                .root_source_file = b.path(fuzzer.source(b)),
                .target = target,
                .optimize = optimize,
            });
            addHarnessImports(lib_mod, lodestar_z);

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
        } else {
            const fail = b.addFail(afl_missing_msg);
            run_step.dependOn(&fail.step);
            b.getInstallStep().dependOn(&fail.step);
        }

        // Native corpus replay: the same harness (uninstrumented) linked into
        // the replay driver, so the committed corpus runs as a deterministic
        // regression check on any host without afl-cc.
        const replay_lib_mod = b.createModule(.{
            .root_source_file = b.path(fuzzer.source(b)),
            .target = target,
            .optimize = optimize,
        });
        addHarnessImports(replay_lib_mod, lodestar_z);

        const replay_lib = b.addLibrary(.{
            .name = b.fmt("{s}_replay", .{fuzzer.name}),
            .root_module = replay_lib_mod,
        });

        const replay_exe_mod = b.createModule(.{
            .root_source_file = b.path("tools/replay_corpus.zig"),
            .target = target,
            .optimize = optimize,
        });
        const replay_exe = b.addExecutable(.{
            .name = b.fmt("replay-{s}", .{fuzzer.name}),
            .root_module = replay_exe_mod,
        });
        replay_exe.root_module.linkLibrary(replay_lib);
        for (fuzzer.extra_libs) |extra_lib| {
            replay_exe.root_module.linkLibrary(extra_lib);
        }

        const run_replay = b.addRunArtifact(replay_exe);
        run_replay.setCwd(b.path("."));
        run_replay.addArg(b.fmt("corpus/{s}-cmin", .{fuzzer.name}));
        run_replay.addArg(b.fmt("corpus/{s}-initial", .{fuzzer.name}));
        replay_step.dependOn(&run_replay.step);

        const replay_target_step = b.step(
            b.fmt("replay-{s}", .{fuzzer.name}),
            b.fmt("Replay the committed corpus through {s} natively", .{fuzzer.name}),
        );
        replay_target_step.dependOn(&run_replay.step);
    }
}
