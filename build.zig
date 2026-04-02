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

    const dep_c_kzg = b.dependency("c_kzg", .{
        .optimize = optimize,
        .target = target,
    });

    const dep_metrics = b.dependency("metrics", .{
        .optimize = optimize,
        .target = target,
    });

    const dep_yaml = b.dependency("yaml", .{
        .optimize = optimize,
        .target = target,
    });

    const dep_zig_cli = b.dependency("zig_cli", .{
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

    // KZG module (c-kzg-4844 bindings for blob/cell verification)
    const module_kzg = b.createModule(.{
        .root_source_file = b.path("src/kzg/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module_kzg.linkLibrary(dep_c_kzg.artifact("c_kzg"));
    module_kzg.linkLibrary(dep_blst.artifact("blst"));
    module_kzg.addIncludePath(dep_c_kzg.artifact("c_kzg").getEmittedIncludeTree());
    module_kzg.addImport("trusted_setup", dep_c_kzg.module("trusted_setup"));
    b.modules.put(b.dupe("kzg"), module_kzg) catch @panic("OOM");

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

    const module_db = b.createModule(.{
        .root_source_file = b.path("src/db/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    // LMDB C dependency — compile vendored sources
    module_db.addCSourceFiles(.{
        .files = &.{ "vendor/lmdb/mdb.c", "vendor/lmdb/midl.c" },
        .flags = &.{ "-pthread", "-DMDB_USE_POSIX_MUTEX" },
    });
    module_db.addIncludePath(b.path("vendor/lmdb"));
    module_db.linkSystemLibrary("c", .{});
    b.modules.put(b.dupe("db"), module_db) catch @panic("OOM");

    const module_api = b.createModule(.{
        .root_source_file = b.path("src/api/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("api"), module_api) catch @panic("OOM");

    const module_fork_choice = b.createModule(.{
        .root_source_file = b.path("src/fork_choice/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("fork_choice"), module_fork_choice) catch @panic("OOM");

    const module_chain = b.createModule(.{
        .root_source_file = b.path("src/chain/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("chain"), module_chain) catch @panic("OOM");

    const module_sync = b.createModule(.{
        .root_source_file = b.path("src/sync/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("sync"), module_sync) catch @panic("OOM");

    const module_log = b.createModule(.{
        .root_source_file = b.path("src/log/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("log"), module_log) catch @panic("OOM");

    const module_node = b.createModule(.{
        .root_source_file = b.path("src/node/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("node"), module_node) catch @panic("OOM");

    const module_validator = b.createModule(.{
        .root_source_file = b.path("src/validator/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("validator"), module_validator) catch @panic("OOM");
    module_validator.addImport("bls", module_bls);
    module_validator.addImport("consensus_types", module_consensus_types);
    module_validator.addImport("config", module_config);
    module_validator.addImport("preset", module_preset);
    module_validator.addImport("constants", module_constants);
    module_validator.addImport("state_transition", module_state_transition);
    module_validator.addImport("log", module_log);
    module_validator.addImport("fork_types", module_fork_types);
    module_validator.addImport("ssz", module_ssz);
    module_validator.addImport("api", module_api);

    const module_processor = b.createModule(.{
        .root_source_file = b.path("src/processor/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("processor"), module_processor) catch @panic("OOM");
    const module_execution = b.createModule(.{
        .root_source_file = b.path("src/execution/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.modules.put(b.dupe("execution"), module_execution) catch @panic("OOM");
    module_execution.addImport("consensus_types", module_consensus_types);
    module_execution.addImport("fork_types", module_fork_types);
    module_execution.addImport("preset", module_preset);

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

    const test_chain = b.addTest(.{
        .name = "chain",
        .root_module = module_chain,
        .filters = b.option([][]const u8, "chain.filters", "chain test filters") orelse &[_][]const u8{},
    });
    const run_test_chain = b.addRunArtifact(test_chain);
    const tls_run_test_chain = b.step("test:chain", "Run the chain module tests");
    tls_run_test_chain.dependOn(&run_test_chain.step);
    tls_run_test.dependOn(&run_test_chain.step);

    const test_kzg = b.addTest(.{
        .name = "kzg",
        .root_module = module_kzg,
        .filters = b.option([][]const u8, "kzg.filters", "kzg test filters") orelse &[_][]const u8{},
    });
    const run_test_kzg = b.addRunArtifact(test_kzg);
    const tls_run_test_kzg = b.step("test:kzg", "Run the KZG module tests");
    tls_run_test_kzg.dependOn(&run_test_kzg.step);
    tls_run_test.dependOn(&run_test_kzg.step);

    const test_sync = b.addTest(.{
        .name = "sync",
        .root_module = module_sync,
        .filters = b.option([][]const u8, "sync.filters", "sync test filters") orelse &[_][]const u8{},
    });
    const run_test_sync = b.addRunArtifact(test_sync);
    const tls_run_test_sync = b.step("test:sync", "Run the sync module tests");
    tls_run_test_sync.dependOn(&run_test_sync.step);
    tls_run_test.dependOn(&run_test_sync.step);

    const test_execution = b.addTest(.{
        .name = "execution",
        .root_module = module_execution,
        .filters = b.option([][]const u8, "execution.filters", "execution test filters") orelse &[_][]const u8{},
    });
    const run_test_execution = b.addRunArtifact(test_execution);
    const tls_run_test_execution = b.step("test:execution", "Run the execution engine tests");
    tls_run_test_execution.dependOn(&run_test_execution.step);
    tls_run_test.dependOn(&run_test_execution.step);

    const test_db = b.addTest(.{
        .name = "db",
        .root_module = module_db,
        .filters = b.option([][]const u8, "db.filters", "db test filters") orelse &[_][]const u8{},
    });
    const run_test_db = b.addRunArtifact(test_db);
    const tls_run_test_db = b.step("test:db", "Run the db test");
    tls_run_test_db.dependOn(&run_test_db.step);
    tls_run_test.dependOn(&run_test_db.step);

    const test_api = b.addTest(.{
        .name = "api",
        .root_module = module_api,
        .filters = b.option([][]const u8, "api.filters", "api test filters") orelse &[_][]const u8{},
    });
    const run_test_api = b.addRunArtifact(test_api);
    const tls_run_test_api = b.step("test:api", "Run the api test");
    tls_run_test_api.dependOn(&run_test_api.step);
    tls_run_test.dependOn(&run_test_api.step);

    const test_validator = b.addTest(.{
        .name = "validator",
        .root_module = module_validator,
        .filters = b.option([][]const u8, "validator.filters", "validator test filters") orelse &[_][]const u8{},
    });
    const run_test_validator = b.addRunArtifact(test_validator);
    const tls_run_test_validator = b.step("test:validator", "Run the validator client tests");
    tls_run_test_validator.dependOn(&run_test_validator.step);
    tls_run_test.dependOn(&run_test_validator.step);

    const test_log = b.addTest(.{
        .name = "log",
        .root_module = module_log,
        .filters = b.option([][]const u8, "log.filters", "log test filters") orelse &[_][]const u8{},
    });
    const run_test_log = b.addRunArtifact(test_log);
    const tls_run_test_log = b.step("test:log", "Run the log test");
    tls_run_test_log.dependOn(&run_test_log.step);
    tls_run_test.dependOn(&run_test_log.step);

    const test_node = b.addTest(.{
        .name = "node",
        .root_module = module_node,
        .filters = b.option([][]const u8, "node.filters", "node test filters") orelse &[_][]const u8{},
    });
    const run_test_node = b.addRunArtifact(test_node);
    const tls_run_test_node = b.step("test:node", "Run the node orchestrator tests");
    tls_run_test_node.dependOn(&run_test_node.step);
    tls_run_test.dependOn(&run_test_node.step);

    const test_processor = b.addTest(.{
        .name = "processor",
        .root_module = module_processor,
        .filters = b.option([][]const u8, "processor.filters", "processor test filters") orelse &[_][]const u8{},
    });
    const run_test_processor = b.addRunArtifact(test_processor);
    const tls_run_test_processor = b.step("test:processor", "Run the processor tests");
    tls_run_test_processor.dependOn(&run_test_processor.step);
    tls_run_test.dependOn(&run_test_processor.step);

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
    module_config.addImport("yaml", dep_yaml.module("yaml"));

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
    module_state_transition.addImport("db", module_db);
    module_state_transition.addImport("metrics", dep_metrics.module("metrics"));
    module_state_transition.addImport("kzg", module_kzg);
    // TODO: metrics dep not yet 0.16-compatible
    // module_state_transition.addImport("metrics", dep_metrics.module("metrics"));

    module_networking.addImport("snappy", dep_snappy.module("snappy"));
    module_networking.addImport("ssz", module_ssz);
    module_networking.addImport("consensus_types", module_consensus_types);
    module_networking.addImport("config", module_config);
    module_networking.addImport("preset", module_preset);
    module_networking.addImport("constants", module_constants);
    module_networking.addImport("zig-libp2p", dep_eth_p2p_z.module("zig-libp2p"));
    // Add ssl (boringssl) module so networking can reference ssl.EVP_PKEY for host key.
    const boringssl_dep = dep_eth_p2p_z.builder.dependency("boringssl", .{ .optimize = optimize, .target = target });
    module_networking.addImport("ssl", boringssl_dep.module("ssl"));
    // Add multiaddr module for P2pService listen/dial APIs.
    const multiaddr_dep2 = dep_eth_p2p_z.builder.dependency("multiaddr", .{ .optimize = optimize, .target = target });
    module_networking.addImport("multiaddr", multiaddr_dep2.module("multiaddr"));

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

    // testing module imports for DST simulation
    module_testing.addImport("state_transition", module_state_transition);
    module_testing.addImport("consensus_types", module_consensus_types);
    module_testing.addImport("fork_types", module_fork_types);
    module_testing.addImport("config", module_config);
    module_testing.addImport("preset", module_preset);
    module_testing.addImport("ssz", module_ssz);
    module_testing.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    module_testing.addImport("bls", module_bls);
    module_testing.addImport("hex", module_hex);
    module_testing.addImport("constants", module_constants);
    module_testing.addImport("build_options", options_module_build_options);
    module_testing.addImport("db", module_db);
    module_testing.addImport("node", module_node);
    module_testing.addImport("networking", module_networking);
    module_testing.addImport("api", module_api);
    module_testing.addImport("chain", module_chain);

    // chain module imports
    module_chain.addImport("consensus_types", module_consensus_types);
    module_chain.addImport("preset", module_preset);
    module_chain.addImport("state_transition", module_state_transition);
    module_chain.addImport("constants", module_constants);
    module_chain.addImport("ssz", module_ssz);
    module_chain.addImport("config", module_config);
    module_chain.addImport("fork_types", module_fork_types);
    module_chain.addImport("db", module_db);
    module_chain.addImport("fork_choice", module_fork_choice);
    module_chain.addImport("networking", module_networking);
    module_chain.addImport("bls", module_bls);
    module_chain.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    module_chain.addImport("kzg", module_kzg);
    module_chain.addImport("log", module_log);

    // sync module imports
    module_sync.addImport("db", module_db);
    module_sync.addImport("networking", module_networking);
    module_sync.addImport("preset", module_preset);

    // api module imports
    module_api.addImport("fork_types", module_fork_types);
    module_api.addImport("consensus_types", module_consensus_types);
    module_api.addImport("config", module_config);
    module_api.addImport("preset", module_preset);
    module_api.addImport("db", module_db);
    module_api.addImport("ssz", module_ssz);
    module_api.addImport("hex", module_hex);
    module_api.addImport("constants", module_constants);
    module_api.addImport("build_options", options_module_build_options);
    module_api.addImport("state_transition", module_state_transition);
    module_api.addImport("persistent_merkle_tree", module_persistent_merkle_tree);

    // === discv5 module ===
    const secp256k1_dep = dep_eth_p2p_z.builder.dependency("secp256k1", .{
        .optimize = optimize,
        .target = target,
    });
    const secp256k1_lib = secp256k1_dep.artifact("libsecp");

    const module_discv5 = b.createModule(.{
        .root_source_file = b.path("src/discv5/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    module_discv5.linkLibrary(secp256k1_lib);
    module_discv5.addIncludePath(secp256k1_dep.builder.dependency("libsecp256k1", .{}).path("include"));
    b.modules.put(b.dupe("discv5"), module_discv5) catch @panic("OOM");
    module_networking.addImport("discv5", module_discv5);

    const test_discv5 = b.addTest(.{
        .name = "discv5",
        .root_module = module_discv5,
        .filters = b.option([][]const u8, "discv5.filters", "discv5 test filters") orelse &[_][]const u8{},
    });
    const run_test_discv5 = b.addRunArtifact(test_discv5);
    const tls_run_test_discv5 = b.step("test:discv5", "Run discv5 tests");
    tls_run_test_discv5.dependOn(&run_test_discv5.step);
    tls_run_test.dependOn(&run_test_discv5.step);

    // === Beacon node executable ===
    const module_node_main = b.createModule(.{
        .root_source_file = b.path("src/cli/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    module_node_main.addImport("node", module_node);
    module_node_main.addImport("config", module_config);
    module_node_main.addImport("state_transition", module_state_transition);
    module_node_main.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    module_node_main.addImport("yaml", dep_yaml.module("yaml"));
    module_node_main.addImport("zig_cli", dep_zig_cli.module("zig-cli"));
    module_node_main.addImport("sync", module_sync);
    module_node_main.addImport("preset", module_preset);
    module_node_main.addImport("log", module_log);
    module_node_main.addImport("discv5", module_discv5);
    module_node_main.addImport("networking", module_networking);
    module_node_main.addImport("validator", module_validator);
    module_node_main.addImport("constants", module_constants);
    module_node_main.addImport("api", module_api);
    module_node_main.addImport("db", module_db);

    const exe_node = b.addExecutable(.{
        .name = "lodestar-z",
        .root_module = module_node_main,
    });
    const install_exe_node = b.addInstallArtifact(exe_node, .{});
    const tls_install_exe_node = b.step("build-exe:lodestar-z", "Install the lodestar-z beacon node executable");
    tls_install_exe_node.dependOn(&install_exe_node.step);
    b.getInstallStep().dependOn(&install_exe_node.step);
    const run_exe_node = b.addRunArtifact(exe_node);
    if (b.args) |args| run_exe_node.addArgs(args);
    const tls_run_exe_node = b.step("run", "Run the lodestar-z beacon node");
    tls_run_exe_node.dependOn(&run_exe_node.step);

    // node module imports
    module_node.addImport("consensus_types", module_consensus_types);
    module_node.addImport("preset", module_preset);
    module_node.addImport("config", module_config);
    module_node.addImport("fork_types", module_fork_types);
    module_node.addImport("state_transition", module_state_transition);
    module_node.addImport("db", module_db);
    module_node.addImport("chain", module_chain);
    module_node.addImport("networking", module_networking);
    module_node.addImport("api", module_api);
    module_node.addImport("ssz", module_ssz);
    module_node.addImport("constants", module_constants);
    module_node.addImport("persistent_merkle_tree", module_persistent_merkle_tree);
    module_node.addImport("bls", module_bls);
    module_node.addImport("kzg", module_kzg);
    module_node.addImport("hex", module_hex);
    module_node.addImport("build_options", options_module_build_options);
    module_node.addImport("fork_choice", module_fork_choice);
    module_node.addImport("execution", module_execution);
    module_node.addImport("metrics", dep_metrics.module("metrics"));
    module_node.addImport("multiaddr", multiaddr_dep2.module("multiaddr"));
    module_node.addImport("zig-libp2p", dep_eth_p2p_z.module("zig-libp2p"));
    module_node.addImport("ssl", boringssl_dep.module("ssl"));
    module_node.addImport("sync", module_sync);
    module_node.addImport("snappy", dep_snappy.module("snappy"));
    module_node.addImport("discv5", module_discv5);
    module_node.addImport("processor", module_processor);
    module_node.addImport("log", module_log);

    module_processor.addImport("consensus_types", module_consensus_types);
    module_processor.addImport("fork_types", module_fork_types);
    module_processor.addImport("config", module_config);
    module_processor.addImport("preset", module_preset);
    module_processor.addImport("constants", module_constants);

    // fork_choice module imports
    module_fork_choice.addImport("consensus_types", module_consensus_types);
    module_fork_choice.addImport("constants", module_constants);
    module_fork_choice.addImport("preset", module_preset);
    module_fork_choice.addImport("state_transition", module_state_transition);
    module_fork_choice.addImport("config", module_config);
    module_fork_choice.addImport("fork_types", module_fork_types);

    // === discv5 integration test (manual, requires network) ===
    const discv5_integration_exe = b.addExecutable(.{
        .name = "discv5-integration-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/discv5/integration_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    discv5_integration_exe.root_module.linkLibrary(secp256k1_lib);
    discv5_integration_exe.root_module.addIncludePath(secp256k1_dep.builder.dependency("libsecp256k1", .{}).path("include"));
    b.installArtifact(discv5_integration_exe);
    const run_discv5_integration = b.addRunArtifact(discv5_integration_exe);
    const tls_run_discv5_integration = b.step("run:discv5-integration-test", "Run discv5 mainnet bootnode integration test");
    tls_run_discv5_integration.dependOn(&run_discv5_integration.step);
}

// NOTE: discv5 module is appended below — this comment is a sentinel
