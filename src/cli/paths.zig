//! CLI-owned path resolution for lodestar-z.
//!
//! This is launcher/bootstrap policy, not beacon-node runtime behavior.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const NetworkName = @import("node").NetworkName;

const log = std.log.scoped(.paths);

pub const ResolveOptions = struct {
    data_dir: []const u8 = "",
    network: NetworkName = .mainnet,
    beacon_db: ?[]const u8 = null,
    jwt_secret: ?[]const u8 = null,
};

pub const DataPaths = struct {
    allocator: Allocator,
    root: []const u8,
    network: []const u8,
    beacon_db: []const u8,
    enr_key: []const u8,
    enr: []const u8,
    peer_db: []const u8,
    state_cache: []const u8,
    pubkey_cache: []const u8,
    jwt_secret: []const u8,
    log_file: []const u8,

    pub fn resolve(allocator: Allocator, opts: ResolveOptions) !DataPaths {
        const root: []const u8 = if (opts.data_dir.len > 0)
            try allocator.dupe(u8, opts.data_dir)
        else
            try defaultRoot(allocator, @tagName(opts.network));

        const network = try allocator.dupe(u8, @tagName(opts.network));

        const beacon_base = try std.fs.path.join(allocator, &.{ root, "beacon-node" });
        defer allocator.free(beacon_base);

        const beacon_db: []const u8 = if (opts.beacon_db) |p|
            try allocator.dupe(u8, p)
        else
            try std.fs.path.join(allocator, &.{ beacon_base, "db" });

        const network_base = try std.fs.path.join(allocator, &.{ beacon_base, "network" });
        defer allocator.free(network_base);

        const enr_key = try std.fs.path.join(allocator, &.{ network_base, "enr-key" });
        const enr = try std.fs.path.join(allocator, &.{ network_base, "enr" });
        const peer_db = try std.fs.path.join(allocator, &.{ network_base, "peer-db" });
        const state_cache = try std.fs.path.join(allocator, &.{ beacon_base, "state-cache" });
        const pubkey_cache = try std.fs.path.join(allocator, &.{ root, "pkix" });

        const jwt_secret: []const u8 = if (opts.jwt_secret) |p|
            try allocator.dupe(u8, p)
        else
            try std.fs.path.join(allocator, &.{ root, "jwt.hex" });

        const logs_base = try std.fs.path.join(allocator, &.{ root, "logs" });
        defer allocator.free(logs_base);
        const log_file = try std.fs.path.join(allocator, &.{ logs_base, "lodestar-z.log" });

        return .{
            .allocator = allocator,
            .root = root,
            .network = network,
            .beacon_db = beacon_db,
            .enr_key = enr_key,
            .enr = enr,
            .peer_db = peer_db,
            .state_cache = state_cache,
            .pubkey_cache = pubkey_cache,
            .jwt_secret = jwt_secret,
            .log_file = log_file,
        };
    }

    pub fn ensureDirs(self: DataPaths, io: std.Io) !void {
        const cwd = std.Io.Dir.cwd();

        try cwd.createDirPath(io, self.root);
        try cwd.createDirPath(io, self.beacon_db);
        try cwd.createDirPath(io, self.peer_db);
        try cwd.createDirPath(io, self.state_cache);

        if (std.fs.path.dirname(self.log_file)) |logs_dir| {
            try cwd.createDirPath(io, logs_dir);
        }
        if (std.fs.path.dirname(self.enr_key)) |network_dir| {
            try cwd.createDirPath(io, network_dir);
        }

        log.debug("Data directories ready under {s}", .{self.root});
    }

    pub fn deinit(self: *DataPaths) void {
        const a = self.allocator;
        a.free(self.root);
        a.free(self.network);
        a.free(self.beacon_db);
        a.free(self.enr_key);
        a.free(self.enr);
        a.free(self.peer_db);
        a.free(self.state_cache);
        a.free(self.pubkey_cache);
        a.free(self.jwt_secret);
        a.free(self.log_file);
    }
};

pub fn defaultRoot(allocator: Allocator, network: []const u8) ![]const u8 {
    const home_raw: ?[*:0]const u8 = std.c.getenv("HOME");
    const home: []const u8 = if (home_raw) |h| std.mem.span(h) else "";

    switch (builtin.os.tag) {
        .macos => {
            if (home.len == 0) return error.NoHomeDir;
            return std.fs.path.join(allocator, &.{ home, "Library", "Application Support", "lodestar-z", network });
        },
        else => {
            if (std.c.getenv("XDG_DATA_HOME")) |xdg_raw| {
                const xdg = std.mem.span(xdg_raw);
                if (xdg.len > 0) {
                    return std.fs.path.join(allocator, &.{ xdg, "lodestar-z", network });
                }
            }

            if (home.len == 0) return error.NoHomeDir;
            return std.fs.path.join(allocator, &.{ home, ".local", "share", "lodestar-z", network });
        },
    }
}

const testing = std.testing;

test "DataPaths.resolve - explicit data_dir" {
    const allocator = testing.allocator;
    var paths = try DataPaths.resolve(allocator, .{
        .data_dir = "/tmp/test-datadir",
        .network = .mainnet,
    });
    defer paths.deinit();

    try testing.expectEqualStrings("/tmp/test-datadir", paths.root);
    try testing.expectEqualStrings("mainnet", paths.network);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/db", paths.beacon_db);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/network/enr-key", paths.enr_key);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/network/enr", paths.enr);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/network/peer-db", paths.peer_db);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/state-cache", paths.state_cache);
    try testing.expectEqualStrings("/tmp/test-datadir/pkix", paths.pubkey_cache);
    try testing.expectEqualStrings("/tmp/test-datadir/jwt.hex", paths.jwt_secret);
    try testing.expectEqualStrings("/tmp/test-datadir/logs/lodestar-z.log", paths.log_file);
}

test "DataPaths.resolve - db override" {
    const allocator = testing.allocator;
    var paths = try DataPaths.resolve(allocator, .{
        .data_dir = "/tmp/test-datadir",
        .network = .sepolia,
        .beacon_db = "/data/fast-ssd/chain-db",
    });
    defer paths.deinit();

    try testing.expectEqualStrings("/data/fast-ssd/chain-db", paths.beacon_db);
    try testing.expectEqualStrings("/tmp/test-datadir/jwt.hex", paths.jwt_secret);
}

test "DataPaths.resolve - jwt override" {
    const allocator = testing.allocator;
    var paths = try DataPaths.resolve(allocator, .{
        .data_dir = "/tmp/test-datadir",
        .network = .mainnet,
        .jwt_secret = "/etc/ethereum/jwt.hex",
    });
    defer paths.deinit();

    try testing.expectEqualStrings("/etc/ethereum/jwt.hex", paths.jwt_secret);
}

test "DataPaths.resolve - different networks produce different roots" {
    const allocator = testing.allocator;

    var paths1 = try DataPaths.resolve(allocator, .{ .network = .mainnet });
    defer paths1.deinit();

    var paths2 = try DataPaths.resolve(allocator, .{ .network = .sepolia });
    defer paths2.deinit();

    try testing.expect(!std.mem.eql(u8, paths1.root, paths2.root));
}
