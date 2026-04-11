const std = @import("std");
const config = @import("config");
const fork_types = @import("fork_types");
const state_transition = @import("state_transition");
const Node = @import("persistent_merkle_tree").Node;

const BeaconConfig = config.BeaconConfig;
const AnyBeaconState = fork_types.AnyBeaconState;
const readGenesisValidatorsRootFromAnyBeaconStateBytes = fork_types.readGenesisValidatorsRootFromAnyBeaconStateBytes;
const readSlotFromAnyBeaconStateBytes = fork_types.readSlotFromAnyBeaconStateBytes;
const SharedValidatorPubkeys = state_transition.SharedValidatorPubkeys;

fn usage() noreturn {
    std.debug.print(
        \\Usage:
        \\  pkix-dump dump <state.ssz> <pkix-path> [mainnet|sepolia|hoodi|minimal]
        \\  pkix-dump verify <state.ssz> <pkix-path> [mainnet|sepolia|hoodi|minimal]
        \\
    , .{});
    std.process.exit(1);
}

fn readFileAlloc(io: std.Io, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    const buffer = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(buffer);
    const bytes_read = try file.readPositionalAll(io, buffer, 0);
    if (bytes_read != stat.size) return error.ShortRead;
    return buffer;
}

fn loadBeaconConfig(network_name: []const u8) *const BeaconConfig {
    if (std.mem.eql(u8, network_name, "mainnet")) return &config.mainnet.config;
    if (std.mem.eql(u8, network_name, "sepolia")) return &config.sepolia.config;
    if (std.mem.eql(u8, network_name, "hoodi")) return &config.hoodi.config;
    if (std.mem.eql(u8, network_name, "minimal")) return &config.minimal.config;
    usage();
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    var args = init.minimal.args.iterate();
    _ = args.skip();
    const mode = args.next() orelse usage();
    const state_path = args.next() orelse usage();
    const cache_path = args.next() orelse usage();
    const network_name = args.next() orelse "mainnet";
    if (args.next() != null) usage();

    const beacon_config = loadBeaconConfig(network_name);
    const state_bytes = try readFileAlloc(io, allocator, state_path);
    defer allocator.free(state_bytes);

    const genesis_validators_root = readGenesisValidatorsRootFromAnyBeaconStateBytes(state_bytes);
    const slot = readSlotFromAnyBeaconStateBytes(state_bytes);
    const fork_seq = beacon_config.forkSeq(slot);

    var pool = try Node.Pool.init(allocator, 500_000);
    defer pool.deinit();

    var any_state = try AnyBeaconState.deserialize(allocator, &pool, fork_seq, state_bytes);
    defer any_state.deinit();

    const validators = try any_state.validatorsSlice(allocator);
    defer allocator.free(validators);

    var shared_pubkeys = SharedValidatorPubkeys.init(allocator);
    defer shared_pubkeys.deinit();
    if (std.mem.eql(u8, mode, "dump")) {
        try shared_pubkeys.syncFromValidators(validators);
        try shared_pubkeys.saveOpaqueCache(io, cache_path, genesis_validators_root);

        std.debug.print(
            "wrote {s} with {d} validators from slot {d}\n",
            .{ cache_path, validators.len, slot },
        );
        return;
    }

    if (std.mem.eql(u8, mode, "verify")) {
        const loaded = try shared_pubkeys.tryLoadOpaqueCache(io, cache_path, genesis_validators_root);
        std.debug.print(
            "loaded={any} count={d} validators={d} slot={d}\n",
            .{ loaded, shared_pubkeys.index_to_pubkey.items.len, validators.len, slot },
        );
        return;
    }

    usage();
}
