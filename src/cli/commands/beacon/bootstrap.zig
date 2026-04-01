const std = @import("std");

const Allocator = std.mem.Allocator;

const node_mod = @import("node");
const networking = @import("networking");
const cli_paths = @import("../../paths.zig");
const common = @import("../../spec_common.zig");

const BeaconNode = node_mod.BeaconNode;
const NodeIdentity = node_mod.NodeIdentity;
const NodeOptions = node_mod.NodeOptions;
const NetworkName = node_mod.NetworkName;
const BootnodeInfo = networking.bootnodes.BootnodeInfo;

const default_identify_agent_version = std.fmt.comptimePrint("lodestar-z/{s}", .{common.VERSION});

pub const PrepareConfig = struct {
    network: NetworkName,
    data_dir: []const u8,
    db_path_override: ?[]const u8 = null,
    jwt_secret_override: ?[]const u8 = null,
    cli_bootnodes: ?[]const u8 = null,
    bootnodes_file: ?[]const u8 = null,
    node_options: NodeOptions,
    needs_execution_auth: bool,
    persist_network_identity: bool = true,
    private: bool = false,
};

pub const PreparedRuntime = struct {
    paths: cli_paths.DataPaths,
    node_identity: ?NodeIdentity,
    jwt_secret: ?[32]u8,
    bootstrap_peers: []const []const u8 = &.{},
    discovery_bootnodes: []const []const u8 = &.{},
    identify_agent_version: ?[]const u8 = default_identify_agent_version,

    pub fn deinit(self: *PreparedRuntime) void {
        if (self.node_identity) |*node_identity| {
            node_identity.deinit();
        }
        freeOwnedStringList(self.paths.allocator, self.bootstrap_peers);
        freeOwnedStringList(self.paths.allocator, self.discovery_bootnodes);
        self.paths.deinit();
    }

    pub fn takeInitConfig(self: *PreparedRuntime, options: NodeOptions) BeaconNode.InitConfig {
        const node_identity = self.node_identity.?;
        self.node_identity = null;
        return .{
            .options = options,
            .db_path = self.paths.beacon_db,
            .node_identity = node_identity,
            .jwt_secret = self.jwt_secret,
            .bootstrap_peers = self.bootstrap_peers,
            .discovery_bootnodes = self.discovery_bootnodes,
            .identify_agent_version = self.identify_agent_version,
        };
    }
};

pub fn prepareRuntime(
    allocator: Allocator,
    io: std.Io,
    config: PrepareConfig,
) !PreparedRuntime {
    var paths = try cli_paths.DataPaths.resolve(allocator, .{
        .data_dir = config.data_dir,
        .network = config.network,
        .beacon_db = config.db_path_override,
        .jwt_secret = config.jwt_secret_override,
    });
    errdefer paths.deinit();

    try paths.ensureDirs(io);

    const node_identity = if (config.persist_network_identity)
        try node_mod.identity.loadOrCreatePersistentIdentity(
            allocator,
            io,
            .{
                .secret_key = paths.enr_key,
                .enr = paths.enr,
            },
            config.node_options,
        )
    else
        try node_mod.identity.createEphemeralIdentity(
            allocator,
            io,
            config.node_options,
        );
    errdefer {
        var identity = node_identity;
        identity.deinit();
    }

    const bootstrap_peers = try collectExplicitBootstrapPeers(
        allocator,
        io,
        config.cli_bootnodes,
        config.bootnodes_file,
    );
    errdefer freeOwnedStringList(allocator, bootstrap_peers);

    const discovery_bootnodes = try collectDiscoveryBootnodes(
        allocator,
        config.network,
        bootstrap_peers,
    );
    errdefer freeOwnedStringList(allocator, discovery_bootnodes);

    const jwt_secret = if (config.needs_execution_auth)
        try node_mod.jwt_mod.loadOrGenerate(io, paths.jwt_secret)
    else
        null;

    return .{
        .paths = paths,
        .node_identity = node_identity,
        .jwt_secret = jwt_secret,
        .bootstrap_peers = bootstrap_peers,
        .discovery_bootnodes = discovery_bootnodes,
        .identify_agent_version = if (config.private) null else default_identify_agent_version,
    };
}

fn collectExplicitBootstrapPeers(
    allocator: Allocator,
    io: std.Io,
    cli_bootnodes: ?[]const u8,
    bootnodes_file: ?[]const u8,
) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    try appendBootnodesFromCsv(allocator, &list, cli_bootnodes);
    try appendBootnodesFromFile(allocator, io, &list, bootnodes_file);
    return try takeOwnedStringList(allocator, &list);
}

fn collectDiscoveryBootnodes(
    allocator: Allocator,
    network: NetworkName,
    explicit_bootstrap_peers: []const []const u8,
) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    for (explicit_bootstrap_peers) |bootnode| {
        try appendUniqueOwned(allocator, &list, bootnode);
    }
    try appendNetworkBootnodes(allocator, &list, networkDefaultBootnodes(network));
    return try takeOwnedStringList(allocator, &list);
}

fn networkDefaultBootnodes(network: NetworkName) []const BootnodeInfo {
    return switch (network) {
        .mainnet => &networking.bootnodes.mainnet,
        else => &.{},
    };
}

fn appendNetworkBootnodes(
    allocator: Allocator,
    list: *std.ArrayListUnmanaged([]const u8),
    bootnodes: []const BootnodeInfo,
) !void {
    for (bootnodes) |bootnode| {
        try appendUniqueOwned(allocator, list, bootnode.enr);
    }
}

fn appendBootnodesFromCsv(
    allocator: Allocator,
    list: *std.ArrayListUnmanaged([]const u8),
    raw_bootnodes: ?[]const u8,
) !void {
    const raw = raw_bootnodes orelse return;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " \t\r\n");
        if (trimmed.len == 0) continue;
        try appendUniqueOwned(allocator, list, trimmed);
    }
}

fn appendBootnodesFromFile(
    allocator: Allocator,
    io: std.Io,
    list: *std.ArrayListUnmanaged([]const u8),
    bootnodes_file: ?[]const u8,
) !void {
    const path = bootnodes_file orelse return;
    const contents = try readFileAlloc(io, allocator, path);
    defer allocator.free(contents);

    var it = std.mem.splitScalar(u8, contents, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        try appendUniqueOwned(allocator, list, trimmed);
    }
}

fn appendUniqueOwned(
    allocator: Allocator,
    list: *std.ArrayListUnmanaged([]const u8),
    value: []const u8,
) !void {
    for (list.items) |existing| {
        if (std.mem.eql(u8, existing, value)) return;
    }
    try list.append(allocator, try allocator.dupe(u8, value));
}

fn takeOwnedStringList(
    allocator: Allocator,
    list: *std.ArrayListUnmanaged([]const u8),
) ![]const []const u8 {
    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return try list.toOwnedSlice(allocator);
}

fn freeOwnedStringList(allocator: Allocator, items: []const []const u8) void {
    if (items.len == 0) return;
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

fn readFileAlloc(io: std.Io, allocator: Allocator, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    const buffer = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(buffer);
    const bytes_read = try file.readPositionalAll(io, buffer, 0);
    if (bytes_read != stat.size) return error.ShortRead;
    return buffer;
}

test "collectExplicitBootstrapPeers merges csv and file without duplicates" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "bootnodes.txt",
        .data =
        \\# comment
        \\enr:one
        \\enr:two
        \\enr:one
        \\
        ,
    });

    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const file_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "bootnodes.txt" });
    defer std.testing.allocator.free(file_path);

    const peers = try collectExplicitBootstrapPeers(
        std.testing.allocator,
        std.testing.io,
        " enr:two , enr:three ",
        file_path,
    );
    defer freeOwnedStringList(std.testing.allocator, peers);

    try std.testing.expectEqual(@as(usize, 3), peers.len);
    try std.testing.expectEqualStrings("enr:two", peers[0]);
    try std.testing.expectEqualStrings("enr:three", peers[1]);
    try std.testing.expectEqualStrings("enr:one", peers[2]);
}

test "collectDiscoveryBootnodes appends network defaults without duplicating explicit peers" {
    const explicit = [_][]const u8{
        networking.bootnodes.mainnet[0].enr,
        "enr:custom",
    };

    const peers = try collectDiscoveryBootnodes(
        std.testing.allocator,
        .mainnet,
        &explicit,
    );
    defer freeOwnedStringList(std.testing.allocator, peers);

    try std.testing.expectEqual(@as(usize, networking.bootnodes.mainnet.len + 1), peers.len);
    try std.testing.expectEqualStrings(networking.bootnodes.mainnet[0].enr, peers[0]);
    try std.testing.expectEqualStrings("enr:custom", peers[1]);
}
