const std = @import("std");

const Allocator = std.mem.Allocator;

const common = @import("../../spec_common.zig");
const root_paths = @import("../../paths.zig");

const log = std.log.scoped(.validator_paths);

pub const ResolveOptions = struct {
    data_dir: []const u8 = "",
    network: common.Network = .mainnet,
    validators_db_dir: ?[]const u8 = null,
    keystores_dir: ?[]const u8 = null,
    secrets_dir: ?[]const u8 = null,
    remote_keys_dir: ?[]const u8 = null,
    proposer_dir: ?[]const u8 = null,
    cache_dir: ?[]const u8 = null,
};

pub const Paths = struct {
    allocator: Allocator,
    root: []const u8,
    validators_db_dir: []const u8,
    slashing_protection_db: []const u8,
    metadata_file: []const u8,
    keymanager_token_file: []const u8,
    cache_dir: []const u8,
    keystores_dir: []const u8,
    secrets_dir: []const u8,
    remote_keys_dir: []const u8,
    proposer_dir: []const u8,
    log_file: []const u8,

    pub fn resolve(allocator: Allocator, opts: ResolveOptions) !Paths {
        const root = if (opts.data_dir.len > 0)
            try allocator.dupe(u8, opts.data_dir)
        else
            try root_paths.defaultRoot(allocator, @tagName(opts.network.toNetworkName()));

        const validators_db_dir = if (opts.validators_db_dir) |path|
            try allocator.dupe(u8, path)
        else
            try std.fs.path.join(allocator, &.{ root, "validator-db" });

        const slashing_protection_db = try std.fs.path.join(allocator, &.{ validators_db_dir, "slashing-protection.db" });
        const metadata_file = try std.fs.path.join(allocator, &.{ validators_db_dir, "metadata.json" });
        const keymanager_token_file = try std.fs.path.join(allocator, &.{ validators_db_dir, "api-token.txt" });

        const cache_dir = if (opts.cache_dir) |path|
            try allocator.dupe(u8, path)
        else
            try std.fs.path.join(allocator, &.{ root, "cache" });

        const keystores_dir = if (opts.keystores_dir) |path|
            try allocator.dupe(u8, path)
        else
            try std.fs.path.join(allocator, &.{ root, "keystores" });

        const secrets_dir = if (opts.secrets_dir) |path|
            try allocator.dupe(u8, path)
        else
            try std.fs.path.join(allocator, &.{ root, "secrets" });

        const remote_keys_dir = if (opts.remote_keys_dir) |path|
            try allocator.dupe(u8, path)
        else
            try std.fs.path.join(allocator, &.{ root, "remoteKeys" });

        const proposer_dir = if (opts.proposer_dir) |path|
            try allocator.dupe(u8, path)
        else
            try std.fs.path.join(allocator, &.{ root, "proposerConfigs" });

        const log_file = try std.fs.path.join(allocator, &.{ root, "validator.log" });

        return .{
            .allocator = allocator,
            .root = root,
            .validators_db_dir = validators_db_dir,
            .slashing_protection_db = slashing_protection_db,
            .metadata_file = metadata_file,
            .keymanager_token_file = keymanager_token_file,
            .cache_dir = cache_dir,
            .keystores_dir = keystores_dir,
            .secrets_dir = secrets_dir,
            .remote_keys_dir = remote_keys_dir,
            .proposer_dir = proposer_dir,
            .log_file = log_file,
        };
    }

    pub fn ensureDirs(self: Paths, io: std.Io) !void {
        const cwd = std.Io.Dir.cwd();
        try cwd.createDirPath(io, self.root);
        try cwd.createDirPath(io, self.validators_db_dir);
        try cwd.createDirPath(io, self.cache_dir);
        try cwd.createDirPath(io, self.keystores_dir);
        try cwd.createDirPath(io, self.secrets_dir);
        try cwd.createDirPath(io, self.remote_keys_dir);
        try cwd.createDirPath(io, self.proposer_dir);
        log.debug("Validator directories ready under {s}", .{self.root});
    }

    pub fn deinit(self: *Paths) void {
        const allocator = self.allocator;
        allocator.free(self.root);
        allocator.free(self.validators_db_dir);
        allocator.free(self.slashing_protection_db);
        allocator.free(self.metadata_file);
        allocator.free(self.keymanager_token_file);
        allocator.free(self.cache_dir);
        allocator.free(self.keystores_dir);
        allocator.free(self.secrets_dir);
        allocator.free(self.remote_keys_dir);
        allocator.free(self.proposer_dir);
        allocator.free(self.log_file);
    }
};

const testing = std.testing;

test "Paths.resolve uses Lodestar-style validator layout" {
    var paths = try Paths.resolve(testing.allocator, .{
        .data_dir = "/tmp/validator-data",
        .network = .mainnet,
    });
    defer paths.deinit();

    try testing.expectEqualStrings("/tmp/validator-data", paths.root);
    try testing.expectEqualStrings("/tmp/validator-data/validator-db", paths.validators_db_dir);
    try testing.expectEqualStrings("/tmp/validator-data/validator-db/slashing-protection.db", paths.slashing_protection_db);
    try testing.expectEqualStrings("/tmp/validator-data/validator-db/metadata.json", paths.metadata_file);
    try testing.expectEqualStrings("/tmp/validator-data/validator-db/api-token.txt", paths.keymanager_token_file);
    try testing.expectEqualStrings("/tmp/validator-data/cache", paths.cache_dir);
    try testing.expectEqualStrings("/tmp/validator-data/keystores", paths.keystores_dir);
    try testing.expectEqualStrings("/tmp/validator-data/secrets", paths.secrets_dir);
    try testing.expectEqualStrings("/tmp/validator-data/remoteKeys", paths.remote_keys_dir);
    try testing.expectEqualStrings("/tmp/validator-data/proposerConfigs", paths.proposer_dir);
    try testing.expectEqualStrings("/tmp/validator-data/validator.log", paths.log_file);
}

test "Paths.resolve honors path overrides" {
    var paths = try Paths.resolve(testing.allocator, .{
        .data_dir = "/tmp/validator-data",
        .network = .sepolia,
        .validators_db_dir = "/data/validator-db",
        .keystores_dir = "/data/keystores",
        .secrets_dir = "/data/secrets",
        .remote_keys_dir = "/data/remote-keys",
        .proposer_dir = "/data/proposer-configs",
        .cache_dir = "/data/cache",
    });
    defer paths.deinit();

    try testing.expectEqualStrings("/data/validator-db", paths.validators_db_dir);
    try testing.expectEqualStrings("/data/validator-db/slashing-protection.db", paths.slashing_protection_db);
    try testing.expectEqualStrings("/data/validator-db/metadata.json", paths.metadata_file);
    try testing.expectEqualStrings("/data/validator-db/api-token.txt", paths.keymanager_token_file);
    try testing.expectEqualStrings("/data/cache", paths.cache_dir);
    try testing.expectEqualStrings("/data/keystores", paths.keystores_dir);
    try testing.expectEqualStrings("/data/secrets", paths.secrets_dir);
    try testing.expectEqualStrings("/data/remote-keys", paths.remote_keys_dir);
    try testing.expectEqualStrings("/data/proposer-configs", paths.proposer_dir);
}
