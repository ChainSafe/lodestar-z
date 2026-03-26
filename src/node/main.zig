//! lodestar-z beacon node entry point.
//!
//! Boots a BeaconNode with:
//! - LMDB database (or in-memory if no --data-dir given)
//! - Beacon REST API on --api-port (default 5052)
//! - P2P networking on --p2p-port (default 9000)
//! - discv5 discovery
//!
//! Usage: lodestar-z [options]
//!   --data-dir <path>             Data directory (default: none, uses in-memory DB)
//!   --network <name>              Network: mainnet|sepolia|holesky|hoodi|minimal (default: mainnet)
//!   --api-port <port>             REST API port (default: 5052)
//!   --p2p-port <port>             P2P listen port (default: 9000)
//!   --checkpoint-state <file>     Bootstrap from checkpoint state SSZ file
//!   --checkpoint-block <file>     Bootstrap from checkpoint block SSZ file
//!   --bootnodes <enr,...>         Comma-separated list of bootnode ENRs
//!   --verify-signatures           Enable BLS signature verification (default: disabled)
//!   --help                        Print this help and exit

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const node_mod = @import("node");
const BeaconNode = node_mod.BeaconNode;
const NodeOptions = node_mod.NodeOptions;
const NetworkName = node_mod.NetworkName;

const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const config_loader = config_mod.config_loader;

const state_transition = @import("state_transition");
const Node = @import("persistent_merkle_tree").Node;

const genesis_util = @import("genesis_util.zig");
const ShutdownHandler = @import("shutdown.zig").ShutdownHandler;

// ---------------------------------------------------------------------------
// Parsed CLI arguments
// ---------------------------------------------------------------------------

const Args = struct {
    data_dir: []const u8 = "",
    network: NetworkName = .mainnet,
    api_port: u16 = 5052,
    p2p_port: u16 = 9000,
    checkpoint_state: ?[]const u8 = null,
    checkpoint_block: ?[]const u8 = null,
    config: ?[]const u8 = null,
    bootnodes_raw: ?[]const u8 = null,
    verify_signatures: bool = false,
    help: bool = false,
};

fn printHelp() void {
    std.debug.print(
        "Usage: lodestar-z [options]\n" ++
        "\n" ++
        "Options:\n" ++
        "  --data-dir <path>          Data directory (default: in-memory storage)\n" ++
        "  --network <name>           Network: mainnet|sepolia|holesky|hoodi|minimal\n" ++
        "                             (default: mainnet)\n" ++
        "  --api-port <port>          Beacon REST API port (default: 5052)\n" ++
        "  --p2p-port <port>          P2P listen port (default: 9000)\n" ++
        "  --checkpoint-state <file>  Bootstrap from checkpoint state SSZ file\n" ++
        "  --checkpoint-block <file>  Bootstrap from checkpoint block SSZ file\n" ++
        "  --verify-signatures        Enable BLS signature verification (slower)\n" ++
        "  --help                     Print this help and exit\n",
        .{},
    );
}

/// Parse CLI arguments from std.process.Args.
fn parseArgs(process_args: std.process.Args) Args {
    var result = Args{};
    var it = process_args.iterate();
    // Skip binary name.
    _ = it.next();

    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            result.help = true;
            return result;
        } else if (std.mem.eql(u8, arg, "--data-dir")) {
            result.data_dir = it.next() orelse {
                std.log.err("--data-dir requires a path argument", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--network")) {
            const net = it.next() orelse {
                std.log.err("--network requires a name argument", .{});
                std.process.exit(1);
            };
            result.network = parseNetwork(net) orelse {
                std.log.err("Unknown network '{s}'. Valid: mainnet, sepolia, holesky, hoodi, minimal", .{net});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--api-port")) {
            const port_str = it.next() orelse {
                std.log.err("--api-port requires a port number", .{});
                std.process.exit(1);
            };
            result.api_port = std.fmt.parseInt(u16, port_str, 10) catch {
                std.log.err("Invalid port number: {s}", .{port_str});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--p2p-port")) {
            const port_str = it.next() orelse {
                std.log.err("--p2p-port requires a port number", .{});
                std.process.exit(1);
            };
            result.p2p_port = std.fmt.parseInt(u16, port_str, 10) catch {
                std.log.err("Invalid port number: {s}", .{port_str});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--checkpoint-state")) {
            result.checkpoint_state = it.next() orelse {
                std.log.err("--checkpoint-state requires a file path", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--checkpoint-block")) {
            result.checkpoint_block = it.next() orelse {
                std.log.err("--checkpoint-block requires a file path", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--config")) {
            result.config = it.next() orelse {
                std.log.err("--config requires a file path", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--bootnodes")) {
            result.bootnodes_raw = it.next() orelse {
                std.log.err("--bootnodes requires a comma-separated ENR list", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--verify-signatures")) {
            result.verify_signatures = true;
        } else {
            std.log.warn("Unknown argument: {s}", .{arg});
        }
    }

    return result;
}

fn parseNetwork(name: []const u8) ?NetworkName {
    if (std.mem.eql(u8, name, "mainnet")) return .mainnet;
    if (std.mem.eql(u8, name, "sepolia")) return .sepolia;
    if (std.mem.eql(u8, name, "holesky")) return .holesky;
    if (std.mem.eql(u8, name, "hoodi")) return .hoodi;
    if (std.mem.eql(u8, name, "minimal")) return .minimal;
    return null;
}

/// Load the BeaconConfig for the selected network.
fn loadBeaconConfig(network: NetworkName) *const BeaconConfig {
    return switch (network) {
        .mainnet => &config_mod.mainnet.config,
        .goerli => &config_mod.mainnet.config,
        .sepolia => &config_mod.sepolia.config,
        .holesky => &config_mod.hoodi.config,
        .hoodi => &config_mod.hoodi.config,
        .minimal => &config_mod.minimal.config,
    };
}

/// Read a file's entire contents into a newly-allocated slice.
fn readFile(io: Io, allocator: Allocator, path: []const u8) ![]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const s = try file.stat(io);
    const buf = try allocator.alloc(u8, s.size);
    errdefer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    if (n != s.size) return error.ShortRead;
    return buf;
}

// ---------------------------------------------------------------------------
// Concurrent service tasks
// ---------------------------------------------------------------------------

/// Context passed to each concurrent service task.
const RunContext = struct {
    node: *BeaconNode,
    api_port: u16,
    p2p_port: u16,
};

/// Slot clock loop: ticks at each new slot boundary, logging head info.
/// Runs as a concurrent task on the same Io instance.
fn slotClockLoop(io: Io, node: *BeaconNode) !void {
    const clock = node.clock orelse return error.ClockNotInitialized;

    std.log.info("Entering slot clock loop...", .{});

    while (!ShutdownHandler.shouldStop()) {
        const current_slot = clock.currentSlot(io) orelse {
            // Before genesis — sleep 1 s and check again.
            io.sleep(.{ .nanoseconds = std.time.ns_per_s }, .real) catch return;
            continue;
        };

        const head = node.getHead();
        if (current_slot > head.slot) {
            std.log.info("slot {d} | head: {d} | finalized epoch: {d}", .{
                current_slot,
                head.slot,
                head.finalized_epoch,
            });
        }

        // Drive the sync state machine forward on each slot.
        if (node.sync_controller) |sc| {
            sc.tick() catch |err| {
                std.log.warn("sync tick error: {}", .{err});
            };
        }

        // Sleep until the start of the next slot.
        const next_slot_ns: i96 = @intCast(clock.slotStartNs(current_slot + 1));
        const now = std.Io.Clock.real.now(io);
        const now_ns: i96 = now.nanoseconds;
        if (next_slot_ns > now_ns) {
            const sleep_ns: u64 = @intCast(next_slot_ns - now_ns);
            io.sleep(.{ .nanoseconds = @intCast(sleep_ns) }, .real) catch return;
        }
    }
}

/// API server task: starts the HTTP server and blocks until it exits.
fn runApiServer(io: Io, ctx: *RunContext) void {
    ctx.node.startApi(io, "0.0.0.0", ctx.api_port) catch |err| {
        std.log.err("API server failed: {}", .{err});
    };
}

/// P2P networking task: starts the libp2p Switch and blocks until it exits.
fn runP2p(io: Io, ctx: *RunContext) void {
    ctx.node.startP2p(io, "0.0.0.0", ctx.p2p_port) catch |err| {
        std.log.err("P2P networking failed: {}", .{err});
    };
}

/// Slot clock task wrapper (returns void for Group.async compatibility).
fn runSlotClock(io: Io, node: *BeaconNode) void {
    slotClockLoop(io, node) catch |err| {
        std.log.err("Slot clock failed: {}", .{err});
    };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    // Parse CLI arguments.
    const args = parseArgs(init.minimal.args);

    if (args.help) {
        printHelp();
        return;
    }

    // Load beacon configuration for the selected network, or from a custom YAML file.
    var custom_chain_config: config_mod.ChainConfig = undefined;
    var custom_beacon_config: BeaconConfig = undefined;
    const beacon_config: *const BeaconConfig = if (args.config) |config_path| blk: {
        std.log.info("Loading custom network config from: {s}", .{config_path});
        var arena = std.heap.ArenaAllocator.init(allocator);
        // Note: arena is intentionally not freed — chain config strings must outlive the node.
        const config_arena = arena.allocator();
        const config_bytes = readFile(io, allocator, config_path) catch |err| {
            std.log.err("Failed to read config file '{s}': {}", .{ config_path, err });
            std.process.exit(1);
        };
        defer allocator.free(config_bytes);
        const base = loadBeaconConfig(args.network);
        custom_chain_config = config_loader.loadConfigFromYaml(config_arena, config_bytes, &base.chain) catch |err| {
            std.log.err("Failed to parse config YAML '{s}': {}", .{ config_path, err });
            std.process.exit(1);
        };
        // Use zero genesis_validators_root; will be set from checkpoint state.
        custom_beacon_config = BeaconConfig.init(custom_chain_config, [_]u8{0} ** 32);
        break :blk &custom_beacon_config;
    } else loadBeaconConfig(args.network);

    // Install signal handlers for graceful shutdown (SIGINT/SIGTERM).
    ShutdownHandler.installSignalHandlers();

    std.log.info("lodestar-z starting", .{});
    std.log.info("  network:    {s}", .{@tagName(args.network)});
    std.log.info("  data-dir:   {s}", .{if (args.data_dir.len > 0) args.data_dir else "(in-memory)"});
    std.log.info("  api-port:   {d}", .{args.api_port});
    std.log.info("  p2p-port:   {d}", .{args.p2p_port});

    // Ensure data directory exists (LMDB requires it).
    if (args.data_dir.len > 0) {
        try Io.Dir.cwd().createDirPath(io, args.data_dir);
        std.log.info("  data directory ready: {s}", .{args.data_dir});
    }

    // Create a PMT node pool — shared across all CachedBeaconState instances.
    // 2M nodes ~= 64 MB at 32 bytes/node; plenty for a minimal-network genesis.
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    // Parse bootnodes: split comma-separated ENR string into individual entries.
    const bootnodes: []const []const u8 = if (args.bootnodes_raw) |raw| blk: {
        var list: std.ArrayList([]const u8) = .empty;
        var it2 = std.mem.splitScalar(u8, raw, ',');
        while (it2.next()) |enr| {
            const trimmed = std.mem.trim(u8, enr, " \t");
            if (trimmed.len > 0) try list.append(allocator, trimmed);
        }
        break :blk try list.toOwnedSlice(allocator);
    } else &.{};
    defer if (bootnodes.len > 0) allocator.free(bootnodes);

    // Create the BeaconNode with LMDB (or in-memory if no data-dir).
    const node = try BeaconNode.init(allocator, beacon_config, .{
        .data_dir = args.data_dir,
        .bootnodes = bootnodes,
        .verify_signatures = args.verify_signatures,
    });
    defer node.deinit();

    std.log.info("BeaconNode initialized", .{});

    // Load genesis / checkpoint state and call initFromGenesis.
    if (args.checkpoint_state) |state_path| {
        // --checkpoint-state given: deserialize from SSZ file.
        std.log.info("Loading checkpoint state from: {s}", .{state_path});

        const genesis_state = genesis_util.loadGenesisFromFile(
            allocator,
            &pool,
            beacon_config,
            io,
            state_path,
        ) catch |err| {
            std.log.err("Failed to load checkpoint state '{s}': {}", .{ state_path, err });
            std.process.exit(1);
        };
        // genesis_state is intentionally not freed — it's owned by the node for its lifetime.

        try node.initFromGenesis(genesis_state);
        // Update the custom BeaconConfig's genesis_validators_root from the loaded state.
        // When using --config, BeaconConfig was initialized with zeros; the real root
        // comes from the checkpoint state.
        if (args.config != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        // Verify genesis state_root matches expected + roundtrip test
        {
            try genesis_state.state.commit();
            const sr = (try genesis_state.state.hashTreeRoot()).*;
            std.log.info("Genesis state_root: 0x{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}...", .{
                sr[0], sr[1], sr[2], sr[3], sr[4], sr[5], sr[6], sr[7],
            });
            // Roundtrip: re-serialize and compare byte count
            const reserialized = genesis_state.state.serialize(allocator) catch |err| {
                std.log.warn("Roundtrip serialize failed: {}", .{err});
                return;
            };
            defer allocator.free(reserialized);
            // Read original file for comparison
            const orig = readFile(io, allocator, state_path) catch return;
            defer allocator.free(orig);
            std.log.info("Roundtrip: original={d} bytes, reserialized={d} bytes", .{orig.len, reserialized.len});
            if (orig.len == reserialized.len) {
                var diffs: usize = 0;
                var first_diff: ?usize = null;
                for (orig, reserialized, 0..) |a, b, i| {
                    if (a != b) {
                        diffs += 1;
                        if (first_diff == null) first_diff = i;
                    }
                }
                if (diffs == 0) {
                    std.log.info("Roundtrip: PERFECT match - all bytes identical", .{});
                } else {
                    std.log.warn("Roundtrip: {d} byte differences, first at offset {d}", .{diffs, first_diff.?});
                }
            }
        }
        std.log.info("Initialized from checkpoint state at slot {d}", .{genesis_state.state.slot() catch 0});
    } else if (args.network == .minimal) {
        // --network minimal: generate a synthetic genesis state with 64 validators.
        std.log.info("Generating minimal genesis state with 64 validators...", .{});

        const genesis_state = genesis_util.createMinimalGenesis(
            allocator,
            &pool,
            64,
        ) catch |err| {
            std.log.err("Failed to generate minimal genesis state: {}", .{err});
            std.process.exit(1);
        };
        // genesis_state ownership transferred to node; not freed here.

        try node.initFromGenesis(genesis_state);
        if (args.config != null) {
            custom_beacon_config.genesis_validator_root = node.genesis_validators_root;
        }
        std.log.info("Initialized from minimal genesis state", .{});
    } else {
        std.log.err("Please provide --checkpoint-state <file> or use --network minimal", .{});
        std.process.exit(1);
    }

    // Log initial head state.
    {
        const head = node.getHead();
        std.log.info("Head: slot={d} root=0x{s}", .{ head.slot, &std.fmt.bytesToHex(head.root, .lower) });
        std.log.info("  finalized_epoch={d} justified_epoch={d}", .{ head.finalized_epoch, head.justified_epoch });
    }

    // Build the run context shared by all concurrent service tasks.
    var run_ctx = RunContext{
        .node = node,
        .api_port = args.api_port,
        .p2p_port = args.p2p_port,
    };

    std.log.info("Starting services concurrently via Io.Group...", .{});
    std.log.info("  REST API: http://0.0.0.0:{d}", .{args.api_port});
    std.log.info("  P2P:      /ip4/0.0.0.0/udp/{d}/quic-v1", .{args.p2p_port});

    // Launch all three services as concurrent tasks on the same Io instance.
    // Each task suspends on I/O (accept, sleep, recv) and the runtime multiplexes.
    var group: Io.Group = .init;
    group.async(io, runApiServer, .{ io, &run_ctx });
    group.async(io, runP2p, .{ io, &run_ctx });
    group.async(io, runSlotClock, .{ io, node });

    // Block until all tasks finish (i.e., forever — Ctrl-C kills the process).
    group.await(io) catch {};

    std.log.info("Shutting down...", .{});
    // node is deferred via `defer node.deinit()` above.
    std.log.info("Goodbye.", .{});
}
