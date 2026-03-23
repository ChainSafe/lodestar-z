// Zig 0.16 migration — zbuild-free build.zig
// Skipped deps: zbench, metrics, httpz (not yet 0.16-compatible)
// Skipped modules: bench_*, metrics_stf, bindings (zapi)

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // === Options ===
    const options_build_options = b.addOptions();
    const option_zero_hash_max_depth = b.option(u8, "zero_hash_max_depth", "");
    options_build_options.addOption(?u8, "zero_hash_max_depth", option_zero_hash_max_depth);
    const option_preset = b.option([]const u8, "preset", "") orelse "mainnet";
    options_build_options.addOption([]const u8, "preset", option_preset);
    const options_module_build_options = options_build_options.createModule();

    const options_download_era_options = b.addOptions();
    const option_era_base_url = b.option([]const u8, "era_base_url", "") orelse "https://mainnet.era.nimbus.team";
    options_download_era_options.addOption([]const u8, "era_base_url", option_era_base_url);
    const option_era_files = b.option([]const []const u8, "era_files", "") orelse &[_][]const u8{ "mainnet-01628-47ac89fb.era", "mainnet-01629-f4b834bc.era" };
    options_download_era_options.addOption([]const []const u8, "era_files", option_era_files);
    const option_era_out_dir = b.option([]const u8, "era_out_dir", "") orelse "fixtures/era";
    options_download_era_options.addOption([]const u8, "era_out_dir", option_era_out_dir);
    const options_module_download_era_options = options_download_era_options.createModule();

    const options_spec_test_options = b.addOptions();
    const option_spec_test_url = b.option([]const u8, "spec_test_url", "") orelse "https://github.com/ethereum/consensus-specs";
    options_spec_test_options.addOption([]const u8, "spec_test_url", option_spec_test_url);
    const option_spec_test_version = b.option([]const u8, "spec_test_version", "") orelse "v1.6.0-beta.2";
    options_spec_test_options.addOption([]const u8, "spec_test_version", option_spec_test_version);
    const option_spec_test_out_dir = b.option([]const u8, "spec_test_out_dir", "") orelse "test/spec/spec_tests";
    options_spec_test_options.addOption([]const u8, "spec_test_out_dir", option_spec_test_out_dir);
    const options_module_spec_test_options = options_spec_test_options.createModule();

    // === Dependencies ===
    const dep_blst = b.dependency("blst", .{
        .optimize = optimize,
        .target = target,
    });

    const dep_hashtree = b.dependency("hashtree", .{
        .optimize = optimize,
        .target = target,
    });

    const dep_snappy = b.dependency("snappy", .{
        .optimize = optimize,
        .target = target,
    });

    // eth-p2p-z: optional libp2p dependency for gossipsub/req-resp integration
    const dep_eth_p2p_z = b.dependency("eth_p2p_z", .{
        .optimize = optimize,
        .target = target,
    });

    const dep_yaml = b.dependency("yaml", .{
        .optimize = optimize,
        .target = target,
    });

    // === Modules ===
    const module_constants = b.createModule(.{
        .root_source_file = b.path("src/constants/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("constants"), module_constants) catch @panic("OOM");

    const module_config = b.createModule(.{
        .root_source_file = b.path("src/config/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("config"), module_config) catch @panic("OOM");

    const module_consensus_types = b.createModule(.{
        .root_source_file = b.path("src/consensus_types/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("consensus_types"), module_consensus_types) catch @panic("OOM");

    const module_era = b.createModule(.{
        .root_source_file = b.path("src/era/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("era"), module_era) catch @panic("OOM");

    const module_hashing = b.createModule(.{
        .root_source_file = b.path("src/hashing/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("hashing"), module_hashing) catch @panic("OOM");

    const module_hex = b.createModule(.{
        .root_source_file = b.path("src/hex.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("hex"), module_hex) catch @panic("OOM");

    const module_fork_types = b.createModule(.{
        .root_source_file = b.path("src/fork_types/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("fork_types"), module_fork_types) catch @panic("OOM");

    const module_persistent_merkle_tree = b.createModule(.{
        .root_source_file = b.path("src/persistent_merkle_tree/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("persistent_merkle_tree"), module_persistent_merkle_tree) catch @panic("OOM");

    const module_preset = b.createModule(.{
        .root_source_file = b.path("src/preset/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("preset"), module_preset) catch @panic("OOM");

    const module_ssz = b.createModule(.{
        .root_source_file = b.path("src/ssz/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("ssz"), module_ssz) catch @panic("OOM");

    const module_bls = b.createModule(.{
        .root_source_file = b.path("src/bls/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    module_bls.linkLibrary(dep_blst.artifact("blst"));
    b.modules.put(b.dupe("bls"), module_bls) catch @panic("OOM");

    const module_state_transition = b.createModule(.{
        .root_source_file = b.path("src/state_transition/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("state_transition"), module_state_transition) catch @panic("OOM");


    const module_networking = b.createModule(.{
        .root_source_file = b.path("src/networking/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("networking"), module_networking) catch @panic("OOM");

    const module_testing = b.createModule(.{
        .root_source_file = b.path("src/testing/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("testing"), module_testing) catch @panic("OOM");
    // === Executables ===
    const module_download_era_files = b.createModule(.{
        .root_source_file = b.path("scripts/download_era_files.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_download_era_files = b.addExecutable(.{
        .name = "download_era_files",
        .root_module = module_download_era_files,
    });
    const install_exe_download_era_files = b.addInstallArtifact(exe_download_era_files, .{});
    const tls_install_exe_download_era_files = b.step("build-exe:download_era_files", "Install the download_era_files executable");
    tls_install_exe_download_era_files.dependOn(&install_exe_download_era_files.step);
    b.getInstallStep().dependOn(&install_exe_download_era_files.step);
    const run_exe_download_era_files = b.addRunArtifact(exe_download_era_files);
    if (b.args) |args| run_exe_download_era_files.addArgs(args);
    const tls_run_exe_download_era_files = b.step("run:download_era_files", "Run the download_era_files executable");
    tls_run_exe_download_era_files.dependOn(&run_exe_download_era_files.step);

    const module_download_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/download_spec_tests.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_download_spec_tests = b.addExecutable(.{
        .name = "download_spec_tests",
        .root_module = module_download_spec_tests,
    });
    const install_exe_download_spec_tests = b.addInstallArtifact(exe_download_spec_tests, .{});
    const tls_install_exe_download_spec_tests = b.step("build-exe:download_spec_tests", "Install the download_spec_tests executable");
    tls_install_exe_download_spec_tests.dependOn(&install_exe_download_spec_tests.step);
    b.getInstallStep().dependOn(&install_exe_download_spec_tests.step);
    const run_exe_download_spec_tests = b.addRunArtifact(exe_download_spec_tests);
    if (b.args) |args| run_exe_download_spec_tests.addArgs(args);
    const tls_run_exe_download_spec_tests = b.step("run:download_spec_tests", "Run the download_spec_tests executable");
    tls_run_exe_download_spec_tests.dependOn(&run_exe_download_spec_tests.step);

    const module_write_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/write_spec_tests.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_write_spec_tests = b.addExecutable(.{
        .name = "write_spec_tests",
        .root_module = module_write_spec_tests,
    });
    const install_exe_write_spec_tests = b.addInstallArtifact(exe_write_spec_tests, .{});
    const tls_install_exe_write_spec_tests = b.step("build-exe:write_spec_tests", "Install the write_spec_tests executable");
    tls_install_exe_write_spec_tests.dependOn(&install_exe_write_spec_tests.step);
    b.getInstallStep().dependOn(&install_exe_write_spec_tests.step);
    const run_exe_write_spec_tests = b.addRunArtifact(exe_write_spec_tests);
    if (b.args) |args| run_exe_write_spec_tests.addArgs(args);
    const tls_run_exe_write_spec_tests = b.step("run:write_spec_tests", "Run the write_spec_tests executable");
    tls_run_exe_write_spec_tests.dependOn(&run_exe_write_spec_tests.step);

    const module_write_ssz_generic_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/ssz/write_generic_tests.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_write_ssz_generic_spec_tests = b.addExecutable(.{
        .name = "write_ssz_generic_spec_tests",
        .root_module = module_write_ssz_generic_spec_tests,
    });
    const install_exe_write_ssz_generic_spec_tests = b.addInstallArtifact(exe_write_ssz_generic_spec_tests, .{});
    const tls_install_exe_write_ssz_generic_spec_tests = b.step("build-exe:write_ssz_generic_spec_tests", "Install the write_ssz_generic_spec_tests executable");
    tls_install_exe_write_ssz_generic_spec_tests.dependOn(&install_exe_write_ssz_generic_spec_tests.step);
    b.getInstallStep().dependOn(&install_exe_write_ssz_generic_spec_tests.step);
    const run_exe_write_ssz_generic_spec_tests = b.addRunArtifact(exe_write_ssz_generic_spec_tests);
    if (b.args) |args| run_exe_write_ssz_generic_spec_tests.addArgs(args);
    const tls_run_exe_write_ssz_generic_spec_tests = b.step("run:write_ssz_generic_spec_tests", "Run the write_ssz_generic_spec_tests executable");
    tls_run_exe_write_ssz_generic_spec_tests.dependOn(&run_exe_write_ssz_generic_spec_tests.step);

    const module_write_ssz_static_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/ssz/write_static_tests.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_write_ssz_static_spec_tests = b.addExecutable(.{
        .name = "write_ssz_static_spec_tests",
        .root_module = module_write_ssz_static_spec_tests,
    });
    const install_exe_write_ssz_static_spec_tests = b.addInstallArtifact(exe_write_ssz_static_spec_tests, .{});
    const tls_install_exe_write_ssz_static_spec_tests = b.step("build-exe:write_ssz_static_spec_tests", "Install the write_ssz_static_spec_tests executable");
    tls_install_exe_write_ssz_static_spec_tests.dependOn(&install_exe_write_ssz_static_spec_tests.step);
    b.getInstallStep().dependOn(&install_exe_write_ssz_static_spec_tests.step);
    const run_exe_write_ssz_static_spec_tests = b.addRunArtifact(exe_write_ssz_static_spec_tests);
    if (b.args) |args| run_exe_write_ssz_static_spec_tests.addArgs(args);
    const tls_run_exe_write_ssz_static_spec_tests = b.step("run:write_ssz_static_spec_tests", "Run the write_ssz_static_spec_tests executable");
    tls_run_exe_write_ssz_static_spec_tests.dependOn(&run_exe_write_ssz_static_spec_tests.step);

    const module_write_bls_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/bls/write_spec_tests.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_write_bls_spec_tests = b.addExecutable(.{
        .name = "write_bls_spec_tests",
        .root_module = module_write_bls_spec_tests,
    });
    const install_exe_write_bls_spec_tests = b.addInstallArtifact(exe_write_bls_spec_tests, .{});
    const tls_install_exe_write_bls_spec_tests = b.step("build-exe:write_bls_spec_tests", "Install the write_bls_spec_tests executable");
    tls_install_exe_write_bls_spec_tests.dependOn(&install_exe_write_bls_spec_tests.step);
    b.getInstallStep().dependOn(&install_exe_write_bls_spec_tests.step);
    const run_exe_write_bls_spec_tests = b.addRunArtifact(exe_write_bls_spec_tests);
    if (b.args) |args| run_exe_write_bls_spec_tests.addArgs(args);
    const tls_run_exe_write_bls_spec_tests = b.step("run:write_bls_spec_tests", "Run the write_bls_spec_tests executable");
    tls_run_exe_write_bls_spec_tests.dependOn(&run_exe_write_bls_spec_tests.step);

    // === Tests ===
    const tls_run_test = b.step("test", "Run all tests");

    const test_constants = b.addTest(.{
        .name = "constants",
        .root_module = module_constants,
        .filters = b.option([][]const u8, "constants.filters", "constants test filters") orelse &[_][]const u8{},
    });
    const run_test_constants = b.addRunArtifact(test_constants);
    const tls_run_test_constants = b.step("test:constants", "Run the constants test");
    tls_run_test_constants.dependOn(&run_test_constants.step);
    tls_run_test.dependOn(&run_test_constants.step);

    const test_config = b.addTest(.{
        .name = "config",
        .root_module = module_config,
        .filters = b.option([][]const u8, "config.filters", "config test filters") orelse &[_][]const u8{},
    });
    const run_test_config = b.addRunArtifact(test_config);
    const tls_run_test_config = b.step("test:config", "Run the config test");
    tls_run_test_config.dependOn(&run_test_config.step);
    tls_run_test.dependOn(&run_test_config.step);

    const test_consensus_types = b.addTest(.{
        .name = "consensus_types",
        .root_module = module_consensus_types,
        .filters = b.option([][]const u8, "consensus_types.filters", "consensus_types test filters") orelse &[_][]const u8{},
    });
    const run_test_consensus_types = b.addRunArtifact(test_consensus_types);
    const tls_run_test_consensus_types = b.step("test:consensus_types", "Run the consensus_types test");
    tls_run_test_consensus_types.dependOn(&run_test_consensus_types.step);
    tls_run_test.dependOn(&run_test_consensus_types.step);

    const test_hashing = b.addTest(.{
        .name = "hashing",
        .root_module = module_hashing,
        .filters = b.option([][]const u8, "hashing.filters", "hashing test filters") orelse &[_][]const u8{},
    });
    const run_test_hashing = b.addRunArtifact(test_hashing);
    const tls_run_test_hashing = b.step("test:hashing", "Run the hashing test");
    tls_run_test_hashing.dependOn(&run_test_hashing.step);
    tls_run_test.dependOn(&run_test_hashing.step);

    const test_hex = b.addTest(.{
        .name = "hex",
        .root_module = module_hex,
        .filters = b.option([][]const u8, "hex.filters", "hex test filters") orelse &[_][]const u8{},
    });
    const run_test_hex = b.addRunArtifact(test_hex);
    const tls_run_test_hex = b.step("test:hex", "Run the hex test");
    tls_run_test_hex.dependOn(&run_test_hex.step);
    tls_run_test.dependOn(&run_test_hex.step);

    const test_persistent_merkle_tree = b.addTest(.{
        .name = "persistent_merkle_tree",
        .root_module = module_persistent_merkle_tree,
        .filters = b.option([][]const u8, "persistent_merkle_tree.filters", "persistent_merkle_tree test filters") orelse &[_][]const u8{},
    });
    const run_test_persistent_merkle_tree = b.addRunArtifact(test_persistent_merkle_tree);
    const tls_run_test_persistent_merkle_tree = b.step("test:persistent_merkle_tree", "Run the persistent_merkle_tree test");
    tls_run_test_persistent_merkle_tree.dependOn(&run_test_persistent_merkle_tree.step);
    tls_run_test.dependOn(&run_test_persistent_merkle_tree.step);

    const test_preset = b.addTest(.{
        .name = "preset",
        .root_module = module_preset,
        .filters = b.option([][]const u8, "preset.filters", "preset test filters") orelse &[_][]const u8{},
    });
    const run_test_preset = b.addRunArtifact(test_preset);
    const tls_run_test_preset = b.step("test:preset", "Run the preset test");
    tls_run_test_preset.dependOn(&run_test_preset.step);
    tls_run_test.dependOn(&run_test_preset.step);

    const test_ssz = b.addTest(.{
        .name = "ssz",
        .root_module = module_ssz,
        .filters = b.option([][]const u8, "ssz.filters", "ssz test filters") orelse &[_][]const u8{},
    });
    const run_test_ssz = b.addRunArtifact(test_ssz);
    const tls_run_test_ssz = b.step("test:ssz", "Run the ssz test");
    tls_run_test_ssz.dependOn(&run_test_ssz.step);
    tls_run_test.dependOn(&run_test_ssz.step);

    const test_bls = b.addTest(.{
        .name = "bls",
        .root_module = module_bls,
        .filters = b.option([][]const u8, "bls.filters", "bls test filters") orelse &[_][]const u8{},
    });
    const run_test_bls = b.addRunArtifact(test_bls);
    const tls_run_test_bls = b.step("test:bls", "Run the bls test");
    tls_run_test_bls.dependOn(&run_test_bls.step);
    tls_run_test.dependOn(&run_test_bls.step);

    const test_state_transition = b.addTest(.{
        .name = "state_transition",
        .root_module = module_state_transition,
        .filters = b.option([][]const u8, "state_transition.filters", "state_transition test filters") orelse &[_][]const u8{},
    });
    const run_test_state_transition = b.addRunArtifact(test_state_transition);
    const tls_run_test_state_transition = b.step("test:state_transition", "Run the state_transition test");
    tls_run_test_state_transition.dependOn(&run_test_state_transition.step);
    tls_run_test.dependOn(&run_test_state_transition.step);

    const test_fork_types = b.addTest(.{
        .name = "fork_types",
        .root_module = module_fork_types,
        .filters = b.option([][]const u8, "fork_types.filters", "fork_types test filters") orelse &[_][]const u8{},
    });
    const run_test_fork_types = b.addRunArtifact(test_fork_types);
    const tls_run_test_fork_types = b.step("test:fork_types", "Run the fork_types test");
    tls_run_test_fork_types.dependOn(&run_test_fork_types.step);
    tls_run_test.dependOn(&run_test_fork_types.step);

    const test_era = b.addTest(.{
        .name = "era",
        .root_module = module_era,
        .filters = b.option([][]const u8, "era.filters", "era test filters") orelse &[_][]const u8{},
    });
    const run_test_era = b.addRunArtifact(test_era);
    const tls_run_test_era = b.step("test:era", "Run the era test");
    tls_run_test_era.dependOn(&run_test_era.step);
    tls_run_test.dependOn(&run_test_era.step);

    const test_networking = b.addTest(.{
        .name = "networking",
        .root_module = module_networking,
        .filters = b.option([][]const u8, "networking.filters", "networking test filters") orelse &[_][]const u8{},
    });
    // Link eth-p2p-z's C dependencies (lsquic via transitive dep)
    const lsquic_dep = dep_eth_p2p_z.builder.dependency("lsquic", .{
        .target = target,
        .optimize = optimize,
    });
    test_networking.root_module.linkLibrary(lsquic_dep.artifact("lsquic"));
    test_networking.root_module.addIncludePath(lsquic_dep.path("include"));
    const run_test_networking = b.addRunArtifact(test_networking);
    const tls_run_test_networking = b.step("test:networking", "Run the networking test");
    tls_run_test_networking.dependOn(&run_test_networking.step);
    tls_run_test.dependOn(&run_test_networking.step);

    const test_testing = b.addTest(.{
        .name = "testing",
        .root_module = module_testing,
        .filters = b.option([][]const u8, "testing.filters", "testing test filters") orelse &[_][]const u8{},
    });
    const run_test_testing = b.addRunArtifact(test_testing);
    const tls_run_test_testing = b.step("test:testing", "Run the simulation testing primitives tests");
    tls_run_test_testing.dependOn(&run_test_testing.step);
    tls_run_test.dependOn(&run_test_testing.step);
    // Spec test modules
    const module_int = b.createModule(.{
        .root_source_file = b.path("test/int/era/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_int = b.addTest(.{
        .name = "int",
        .root_module = module_int,
        .filters = b.option([][]const u8, "int.filters", "int test filters") orelse &[_][]const u8{},
    });
    const run_test_int = b.addRunArtifact(test_int);
    const tls_run_test_int = b.step("test:int", "Run the int test");
    tls_run_test_int.dependOn(&run_test_int.step);

    const module_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_spec_tests = b.addTest(.{
        .name = "spec_tests",
        .root_module = module_spec_tests,
        .filters = b.option([][]const u8, "spec_tests.filters", "spec_tests test filters") orelse &[_][]const u8{},
    });
    const run_test_spec_tests = b.addRunArtifact(test_spec_tests);
    const tls_run_test_spec_tests = b.step("test:spec_tests", "Run the spec_tests test");
    tls_run_test_spec_tests.dependOn(&run_test_spec_tests.step);

    const module_ssz_generic_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/ssz/generic_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_ssz_generic_spec_tests = b.addTest(.{
        .name = "ssz_generic_spec_tests",
        .root_module = module_ssz_generic_spec_tests,
        .filters = b.option([][]const u8, "ssz_generic_spec_tests.filters", "ssz_generic_spec_tests test filters") orelse &[_][]const u8{},
    });
    const run_test_ssz_generic_spec_tests = b.addRunArtifact(test_ssz_generic_spec_tests);
    const tls_run_test_ssz_generic_spec_tests = b.step("test:ssz_generic_spec_tests", "Run the ssz_generic_spec_tests test");
    tls_run_test_ssz_generic_spec_tests.dependOn(&run_test_ssz_generic_spec_tests.step);

    const module_ssz_static_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/ssz/static_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_ssz_static_spec_tests = b.addTest(.{
        .name = "ssz_static_spec_tests",
        .root_module = module_ssz_static_spec_tests,
        .filters = b.option([][]const u8, "ssz_static_spec_tests.filters", "ssz_static_spec_tests test filters") orelse &[_][]const u8{},
    });
    const run_test_ssz_static_spec_tests = b.addRunArtifact(test_ssz_static_spec_tests);
    const tls_run_test_ssz_static_spec_tests = b.step("test:ssz_static_spec_tests", "Run the ssz_static_spec_tests test");
    tls_run_test_ssz_static_spec_tests.dependOn(&run_test_ssz_static_spec_tests.step);

    const module_bls_spec_tests = b.createModule(.{
        .root_source_file = b.path("test/spec/bls/spec_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_bls_spec_tests = b.addTest(.{
        .name = "bls_spec_tests",
        .root_module = module_bls_spec_tests,
        .filters = b.option([][]const u8, "bls_spec_tests.filters", "bls_spec_tests test filters") orelse &[_][]const u8{},
    });
    const run_test_bls_spec_tests = b.addRunArtifact(test_bls_spec_tests);
    const tls_run_test_bls_spec_tests = b.step("test:bls_spec_tests", "Run the bls_spec_tests test");
    tls_run_test_bls_spec_tests.dependOn(&run_test_bls_spec_tests.step);

    // === Module imports ===
    module_config.addImport("build_options", options_module_build_options);
    module_config.addImport("preset", module_preset);
    module_config.addImport("consensus_types", module_consensus_types);
    module_config.addImport("hex", module_hex);
    module_config.addImport("constants", module_constants);

    module_consensus_types.addImport("build_options", options_module_build_options);
    module_consensus_types.addImport("ssz", module_ssz);
    module_consensus_types.addImport("constants", module_constants);
    module_consensus_types.addImport("preset", module_preset);

    module_era.addImport("consensus_types", module_consensus_types);
    module_era.addImport("config", module_config);
    module_era.addImport("fork_types", module_fork_types);
    module_era.addImport("preset", module_preset);
    module_era.addImport("state_transition", module_state_transition);
    module_era.addImport("snappy", dep_snappy.module("snappy"));
    module_era.addImport("persistent_merkle_tree", module_persistent_merkle_tree);

    module_hashing.addImport("build_options", options_module_build_options);
    module_hashing.addImport("hex", module_hex);
    module_hashing.addImport("hashtree", dep_hashtree.module("hashtree"));

    module_fork_types.addImport("consensus_types", module_consensus_types);
    module_fork_types.addImport("constants", module_constants);
    module_fork_types.addImport("config", module_config);
    module_fork_types.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    module_fork_types.addImport("preset", module_preset);
    module_fork_types.addImport("ssz", module_ssz);

    module_persistent_merkle_tree.addImport("build_options", options_module_build_options);
    module_persistent_merkle_tree.addImport("hex", module_hex);
    module_persistent_merkle_tree.addImport("hashing", module_hashing);

    module_preset.addImport("build_options", options_module_build_options);
    module_preset.addImport("constants", module_constants);

    module_ssz.addImport("build_options", options_module_build_options);
    module_ssz.addImport("hex", module_hex);
    module_ssz.addImport("hashing", module_hashing);
    module_ssz.addImport("persistent_merkle_tree", module_persistent_merkle_tree);

    module_state_transition.addImport("build_options", options_module_build_options);
    module_state_transition.addImport("ssz", module_ssz);
    module_state_transition.addImport("config", module_config);
    module_state_transition.addImport("consensus_types", module_consensus_types);
    module_state_transition.addImport("bls", module_bls);
    module_state_transition.addImport("fork_types", module_fork_types);
    module_state_transition.addImport("preset", module_preset);
    module_state_transition.addImport("constants", module_constants);
    module_state_transition.addImport("hex", module_hex);
    module_state_transition.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    // TODO: metrics dep not yet 0.16-compatible
    // module_state_transition.addImport("metrics", dep_metrics.module("metrics"));

    module_networking.addImport("snappy", dep_snappy.module("snappy"));
    module_networking.addImport("ssz", module_ssz);
    module_networking.addImport("consensus_types", module_consensus_types);
    module_networking.addImport("preset", module_preset);
    module_networking.addImport("constants", module_constants);
    module_networking.addImport("zig-libp2p", dep_eth_p2p_z.module("zig-libp2p"));

    module_download_era_files.addImport("download_era_options", options_module_download_era_options);

    module_download_spec_tests.addImport("spec_test_options", options_module_spec_test_options);

    module_write_spec_tests.addImport("spec_test_options", options_module_spec_test_options);
    module_write_spec_tests.addImport("config", module_config);
    module_write_spec_tests.addImport("preset", module_preset);
    module_write_spec_tests.addImport("consensus_types", module_consensus_types);
    module_write_spec_tests.addImport("state_transition", module_state_transition);

    module_write_ssz_generic_spec_tests.addImport("spec_test_options", options_module_spec_test_options);
    module_write_ssz_static_spec_tests.addImport("spec_test_options", options_module_spec_test_options);
    module_write_bls_spec_tests.addImport("spec_test_options", options_module_spec_test_options);

    module_int.addImport("config", module_config);
    module_int.addImport("download_era_options", options_module_download_era_options);
    module_int.addImport("era", module_era);

    module_spec_tests.addImport("spec_test_options", options_module_spec_test_options);
    module_spec_tests.addImport("consensus_types", module_consensus_types);
    module_spec_tests.addImport("config", module_config);
    module_spec_tests.addImport("fork_types", module_fork_types);
    module_spec_tests.addImport("preset", module_preset);
    module_spec_tests.addImport("snappy", dep_snappy.module("snappy"));
    module_spec_tests.addImport("state_transition", module_state_transition);
    module_spec_tests.addImport("ssz", module_ssz);
    module_spec_tests.addImport("bls", module_bls);
    module_spec_tests.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    module_spec_tests.addImport("hex", module_hex);

    module_ssz_generic_spec_tests.addImport("hex", module_hex);
    module_ssz_generic_spec_tests.addImport("snappy", dep_snappy.module("snappy"));
    module_ssz_generic_spec_tests.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    module_ssz_generic_spec_tests.addImport("ssz", module_ssz);
    module_ssz_generic_spec_tests.addImport("spec_test_options", options_module_spec_test_options);
    module_ssz_generic_spec_tests.addImport("yaml", dep_yaml.module("yaml"));

    module_ssz_static_spec_tests.addImport("hex", module_hex);
    module_ssz_static_spec_tests.addImport("snappy", dep_snappy.module("snappy"));
    module_ssz_static_spec_tests.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    module_ssz_static_spec_tests.addImport("ssz", module_ssz);
    module_ssz_static_spec_tests.addImport("build_options", options_module_build_options);
    module_ssz_static_spec_tests.addImport("spec_test_options", options_module_spec_test_options);
    module_ssz_static_spec_tests.addImport("consensus_types", module_consensus_types);
    module_ssz_static_spec_tests.addImport("yaml", dep_yaml.module("yaml"));

    module_bls_spec_tests.addImport("bls", module_bls);
    module_bls_spec_tests.addImport("hex", module_hex);
    module_bls_spec_tests.addImport("yaml", dep_yaml.module("yaml"));
    module_bls_spec_tests.addImport("spec_test_options", options_module_spec_test_options);
}
