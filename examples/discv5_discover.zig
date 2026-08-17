//! End-to-end discv5 discovery smoke test.
//!
//! Run with:
//!   zig build run:discv5_discover -- --timeout-ms 30000 --max-results 16

const std = @import("std");
const discv5 = @import("discv5");

pub const std_options: std.Options = .{ .log_level = .info };

const Allocator = std.mem.Allocator;
const Address = discv5.Address;
const NodeId = discv5.NodeId;

// Source, fetched 2026-05-15:
// https://github.com/eth-clients/eth2-networks/blob/master/shared/mainnet/bootstrap_nodes.txt
const default_bootnodes = [_][]const u8{
    "enr:-KG4QNTx85fjxABbSq_Rta9wy56nQ1fHK0PewJbGjLm1M4bMGx5-3Qq4ZX2-iFJ0pys_O90sVXNNOxp2E7afBsGsBrgDhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQEnfA2iXNlY3AyNTZrMaECGXWQ-rQ2KZKRH1aOW4IlPDBkY4XDphxg9pxKytFCkayDdGNwgiMog3VkcIIjKA",
    "enr:-KG4QF4B5WrlFcRhUU6dZETwY5ZzAXnA0vGC__L1Kdw602nDZwXSTs5RFXFIFUnbQJmhNGVU6OIX7KVrCSTODsz1tK4DhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQExNYEiXNlY3AyNTZrMaECQmM9vp7KhaXhI-nqL_R0ovULLCFSFTa9CPPSdb1zPX6DdGNwgiMog3VkcIIjKA",
    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
};

const Options = struct {
    timeout_ms: u64 = 30_000,
    max_results: usize = 16,
    use_default_bootnodes: bool = true,
    target: ?NodeId = null,
    extra_bootnodes: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *Options, alloc: Allocator) void {
        for (self.extra_bootnodes.items) |bootnode| alloc.free(bootnode);
        self.extra_bootnodes.deinit(alloc);
    }

    fn appendBootnode(self: *Options, alloc: Allocator, bootnode: []const u8) !void {
        const owned = try alloc.dupe(u8, bootnode);
        errdefer alloc.free(owned);
        try self.extra_bootnodes.append(alloc, owned);
    }
};

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);

    const alloc = gpa.allocator();
    const output_io = init.io;

    var options = (try parseOptions(alloc, init.minimal.args)) orelse {
        var stdout_buf: [8192]u8 = undefined;
        var stdout_file_writer = std.Io.File.stdout().writer(output_io, &stdout_buf);
        const stdout = &stdout_file_writer.interface;
        try printUsage(stdout);
        try stdout.flush();
        return;
    };
    defer options.deinit(alloc);

    var runtime = std.Io.Threaded.init(alloc, .{});
    defer runtime.deinit();

    try runDiscovery(alloc, runtime.io(), output_io, &options);
}

fn runDiscovery(alloc: Allocator, io: std.Io, output_io: std.Io, options: *const Options) !void {
    var stdout_buf: [8192]u8 = undefined;
    var stdout_file_writer = std.Io.File.stdout().writer(output_io, &stdout_buf);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    const target = options.target orelse blk: {
        var random_target: NodeId = undefined;
        io.random(&random_target);
        break :blk random_target;
    };

    const key_pair = discv5.secp256k1.KeyPair.generate(io);
    const pubkey = discv5.secp256k1.compressedPubkey(&key_pair);
    const local_node_id = discv5.enr.nodeIdFromCompressedPubkey(&pubkey);

    const service_config = discv5.service.Config{
        .bind_addresses = .{
            .ip4 = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        },
        .protocol_config = .{
            .local_key_pair = key_pair,
            .local_node_id = local_node_id,
            .request_timeout_ms = 2_000,
            .request_retries = 1,
        },
        .lookup_num_results = options.max_results,
        .lookup_timeout_ms = options.timeout_ms,
        .receive_timeout_ms = 5,
    };
    const runtime_options = discv5.RuntimeService.Options{
        .command_queue_capacity = 1024,
        .event_queue_capacity = 1024,
        .maintenance_interval_ms = 100,
    };

    var runtime_service = try discv5.RuntimeService.initWithOptions(io, alloc, service_config, runtime_options);
    var runtime_group: std.Io.Group = .init;
    runtime_group.concurrent(io, runRuntimeService, .{ &runtime_service, runtime_options }) catch |err| {
        runtime_service.deinit();
        return err;
    };
    defer {
        runtime_service.stop();
        runtime_group.await(io) catch {};
        runtime_service.deinit();
    }

    try waitForRuntime(&runtime_service);
    try setLocalEnr(alloc, &runtime_service, key_pair);

    var added_bootnodes: usize = 0;
    if (options.use_default_bootnodes) {
        for (default_bootnodes) |bootnode| {
            if (try addBootnode(alloc, &runtime_service, bootnode)) added_bootnodes += 1;
        }
    }
    for (options.extra_bootnodes.items) |bootnode| {
        if (try addBootnode(alloc, &runtime_service, bootnode)) added_bootnodes += 1;
    }
    if (added_bootnodes == 0) return error.NoBootnodes;

    const lookup_id = try runtime_service.startLookup(&target);
    try stdout.print("discv5 discovery lookup {d}\n", .{lookup_id});
    try stdout.print("bound: ", .{});
    if (runtime_service.boundAddress(.ip4)) |addr| {
        try addr.format(stdout);
    } else {
        try stdout.print("<none>", .{});
    }
    try stdout.print("\nbootnodes: {d}\ntarget: ", .{added_bootnodes});
    try printNodeId(stdout, &target);
    try stdout.print("\n\n", .{});
    try stdout.flush();

    var seen = std.AutoHashMap(NodeId, void).init(alloc);
    defer seen.deinit();

    var found: usize = 0;
    var finished = false;
    var lookup_timed_out = false;

    while (!finished) {
        const event_value = runtime_service.nextEvent() catch |err| switch (err) {
            error.Closed => break,
            error.Canceled => return err,
        };
        var event = event_value;
        defer event.deinit(alloc);

        switch (event) {
            .discovered_enr => |discovered| {
                if (found >= options.max_results) {
                    finished = true;
                    continue;
                }
                if (try printFoundParsedEnr(alloc, stdout, &seen, discovered.raw.slice(), &discovered.enr)) {
                    found += 1;
                    try stdout.flush();
                }
                if (found >= options.max_results) finished = true;
            },
            .lookup_finished => |lookup_finished| {
                if (lookup_finished.lookup_id != lookup_id) continue;
                lookup_timed_out = lookup_finished.timed_out;
                for (lookup_finished.enrs) |raw_enr| {
                    if (found >= options.max_results) break;
                    if (try printFoundEnr(alloc, stdout, &seen, raw_enr)) found += 1;
                }
                finished = true;
                try stdout.flush();
            },
            else => {},
        }
    }

    if (!finished and found < options.max_results) lookup_timed_out = true;

    try stdout.print("\nsummary: {d} ENRs printed; lookup {s}\n", .{
        found,
        if (lookup_timed_out) "timed out" else "finished",
    });
}

fn runRuntimeService(runtime_service: *discv5.RuntimeService, options: discv5.RuntimeService.Options) void {
    runtime_service.run(options) catch |err| std.debug.print("runtime service stopped with {}\n", .{err});
}

fn waitForRuntime(runtime_service: *const discv5.RuntimeService) !void {
    while (!runtime_service.isRunning()) {
        if (runtime_service.isClosed()) return error.ServiceStopped;
        try std.Thread.yield();
    }
}

fn setLocalEnr(
    alloc: Allocator,
    runtime_service: *discv5.RuntimeService,
    key_pair: discv5.secp256k1.KeyPair,
) !void {
    var builder = discv5.enr.Builder.init(alloc, key_pair, 1);
    if (runtime_service.boundAddress(.ip4)) |addr| {
        builder.udp = addr.getPort();
    }

    const local_enr = try builder.encode();
    defer alloc.free(local_enr);

    try runtime_service.setLocalEnr(local_enr);
}

fn parseOptions(alloc: Allocator, args_value: std.process.Args) !?Options {
    var options = Options{};
    errdefer options.deinit(alloc);

    var args = try std.process.Args.Iterator.initAllocator(args_value, alloc);
    defer args.deinit();

    _ = args.next();
    while (args.next()) |arg_z| {
        const arg = arg_z[0..arg_z.len];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            options.deinit(alloc);
            return null;
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            const value = args.next() orelse return error.MissingTimeout;
            options.timeout_ms = try parsePositiveInt(u64, value);
        } else if (std.mem.eql(u8, arg, "--max-results")) {
            const value = args.next() orelse return error.MissingMaxResults;
            options.max_results = try parsePositiveInt(usize, value);
            if (options.max_results > discv5.service.MAX_LOOKUP_RESULTS) return error.TooManyResults;
        } else if (std.mem.eql(u8, arg, "--target")) {
            const value = args.next() orelse return error.MissingTarget;
            options.target = try parseNodeId(value);
        } else if (std.mem.eql(u8, arg, "--bootnode")) {
            const value = args.next() orelse return error.MissingBootnode;
            try options.appendBootnode(alloc, value);
        } else if (std.mem.eql(u8, arg, "--no-default-bootnodes")) {
            options.use_default_bootnodes = false;
        } else if (std.mem.startsWith(u8, arg, "enr:")) {
            try options.appendBootnode(alloc, arg);
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            return error.InvalidArgument;
        }
    }

    return options;
}

fn parsePositiveInt(comptime T: type, text: []const u8) !T {
    const value = try std.fmt.parseUnsigned(T, text, 10);
    if (value == 0) return error.ValueMustBePositive;
    return value;
}

fn parseNodeId(text: []const u8) !NodeId {
    if (text.len != 64 and text.len != 66) return error.InvalidNodeId;
    if (text.len == 66 and !std.mem.startsWith(u8, text, "0x")) return error.InvalidNodeId;

    var node_id: NodeId = undefined;
    _ = discv5.hex.hexToBytes(&node_id, text) catch return error.InvalidNodeId;
    return node_id;
}

fn addBootnode(alloc: Allocator, runtime_service: *discv5.RuntimeService, bootnode: []const u8) !bool {
    const raw = discv5.enr.decodeText(alloc, bootnode) catch |err| {
        std.debug.print("skipping invalid bootnode: {}\n", .{err});
        return false;
    };
    defer alloc.free(raw);

    if (!try runtime_service.addEnr(raw)) {
        std.debug.print("skipping unusable bootnode ENR\n", .{});
        return false;
    }
    return true;
}

fn printFoundEnr(
    alloc: Allocator,
    stdout: *std.Io.Writer,
    seen: *std.AutoHashMap(NodeId, void),
    raw_enr: []const u8,
) !bool {
    const parsed = discv5.enr.decode(raw_enr) catch return false;
    return try printFoundParsedEnr(alloc, stdout, seen, raw_enr, &parsed);
}

fn printFoundParsedEnr(
    alloc: Allocator,
    stdout: *std.Io.Writer,
    seen: *std.AutoHashMap(NodeId, void),
    raw_enr: []const u8,
    parsed: *const discv5.Enr,
) !bool {
    const node_id = parsed.nodeId() orelse return false;
    const seen_entry = try seen.getOrPut(node_id);
    if (seen_entry.found_existing) return false;

    const text = try discv5.enr.encodeText(alloc, raw_enr);
    defer alloc.free(text);

    try stdout.print("found ", .{});
    try printNodeId(stdout, &node_id);
    try printEnrAddresses(stdout, parsed);
    try stdout.print("\n{s}\n", .{text});
    return true;
}

fn printNodeId(stdout: *std.Io.Writer, node_id: *const NodeId) !void {
    try stdout.print("0x{x}", .{node_id});
}

fn printEnrAddresses(stdout: *std.Io.Writer, parsed: *const discv5.Enr) !void {
    if (parsed.ip) |ip| {
        if (parsed.udp) |port| {
            const addr = Address{ .ip4 = .{ .bytes = ip, .port = port } };
            try stdout.print(" ", .{});
            try addr.format(stdout);
        }
    }
    if (parsed.ip6) |ip6| {
        if (parsed.udp6) |port| {
            const addr = Address{ .ip6 = .{ .bytes = ip6, .port = port } };
            try stdout.print(" ", .{});
            try addr.format(stdout);
        }
    }
}

fn printUsage(stdout: *std.Io.Writer) !void {
    try stdout.print(
        \\Usage:
        \\  zig build run:discv5_discover -- [options] [enr:...]
        \\
        \\Options:
        \\  --timeout-ms N            Stop after N milliseconds (default: 30000)
        \\  --max-results N           Stop after N printed ENRs, max 16 (default: 16)
        \\  --target 0xHEX            Lookup a specific 32-byte node id; random by default
        \\  --bootnode enr:...        Add an extra bootnode ENR
        \\  --no-default-bootnodes    Use only bootnodes passed on the command line
        \\  -h, --help                Show this help
        \\
    , .{});
}
