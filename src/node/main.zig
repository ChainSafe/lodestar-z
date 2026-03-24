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

    // Load beacon configuration for the selected network.
    const beacon_config = loadBeaconConfig(args.network);

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

    // Create the BeaconNode with LMDB (or in-memory if no data-dir).
    const node = try BeaconNode.init(allocator, beacon_config, .{
        .data_dir = args.data_dir,
        .verify_signatures = args.verify_signatures,
    });
    defer node.deinit();

    std.log.info("BeaconNode initialized", .{});

    // Initialize from checkpoint or genesis.
    if (args.checkpoint_state) |state_path| {
        std.log.info("Loading checkpoint state from: {s}", .{state_path});

        // Read state SSZ bytes.
        const state_bytes = readFile(io, allocator, state_path) catch |err| {
            std.log.err("Failed to read checkpoint state file '{s}': {}", .{ state_path, err });
            std.process.exit(1);
        };
        defer allocator.free(state_bytes);

        // Read checkpoint block if provided.
        const block_bytes: ?[]u8 = if (args.checkpoint_block) |block_path| blk: {
            std.log.info("Loading checkpoint block from: {s}", .{block_path});
            const b = readFile(io, allocator, block_path) catch |err| {
                std.log.err("Failed to read checkpoint block file '{s}': {}", .{ block_path, err });
                std.process.exit(1);
            };
            break :blk b;
        } else null;
        defer if (block_bytes) |b| allocator.free(b);

        // TODO: Deserialize state + block SSZ and call node.initFromCheckpoint().
        // Requires SSZ deserialization support for AnyBeaconState.
        std.log.info("TODO: initFromCheckpoint({d} bytes state, {d} bytes block)", .{
            state_bytes.len,
            if (block_bytes) |b| b.len else 0,
        });
    } else {
        // No checkpoint — genesis loading is network-specific.
        std.log.info("TODO: Load genesis state for network '{s}'", .{@tagName(args.network)});
        std.log.info("  Use --checkpoint-state to bootstrap from a checkpoint.", .{});
    }

    // Start REST API server (TODO: needs std.Io for fiber-based serving).
    std.log.info("TODO: Start REST API on 0.0.0.0:{d}", .{args.api_port});
    std.log.info("  node.startApi(io, \"0.0.0.0\", {d})", .{args.api_port});

    // Start P2P networking (TODO: needs std.Io and libp2p Switch).
    std.log.info("TODO: Start P2P networking on 0.0.0.0:{d}", .{args.p2p_port});
    std.log.info("  node.startP2p(io, \"0.0.0.0\", {d})", .{args.p2p_port});

    // Start discv5 discovery (TODO: requires discv5 integration).
    std.log.info("TODO: Start discv5 discovery on UDP port {d}", .{args.p2p_port});

    // Main slot clock loop (TODO: needs std.Io timer support).
    std.log.info("TODO: Run slot clock loop", .{});
    std.log.info("  At each slot: check for new head, produce block if validator key loaded.", .{});

    // Log head state.
    const head = node.getHead();
    std.log.info("Head: slot={d} root=0x{s}", .{ head.slot, &std.fmt.bytesToHex(head.root, .lower) });
    std.log.info("  finalized_epoch={d} justified_epoch={d}", .{ head.finalized_epoch, head.justified_epoch });

    std.log.info("lodestar-z node ready (stubs active; full I/O requires Zig 0.16 std.Io)", .{});
}
