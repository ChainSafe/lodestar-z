//! DataDir: coherent data directory management for lodestar-z.
//!
//! Resolves all on-disk paths from a single root directory and network name.
//! Provides helpers to construct every well-known sub-path and to create all
//! required directories before the node starts.
//!
//! Directory layout:
//!
//! ```
//! <root>/
//! ├── beacon-node/
//! │   ├── db/              — LMDB chain database
//! │   ├── network/
//! │   │   ├── enr-key      — secp256k1 secret key for discv5/libp2p
//! │   │   ├── enr          — persisted local ENR text
//! │   │   └── peer-db/     — persistent peer store
//! │   └── state-cache/     — (future) persistent checkpoint states
//! ├── validator/
//! │   ├── slashing-protection.db
//! │   ├── keystores/       — EIP-2335 keystore directories
//! │   └── secrets/         — keystore password files
//! ├── logs/
//! └── jwt.hex              — Engine API JWT secret
//! ```

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const options_mod = @import("options.zig");
const NodeOptions = options_mod.NodeOptions;

const log = std.log.scoped(.data_dir);

/// All resolved paths for a lodestar-z data directory.
///
/// Paths are owned by the allocator passed to `resolve()` / `init()`.
/// Call `deinit()` when done.
pub const DataDir = struct {
    allocator: Allocator,

    /// Resolved root data directory (e.g. `~/.local/share/lodestar-z/mainnet`).
    root: []const u8,

    /// Network name used to construct the default root.
    network: []const u8,

    // ── Beacon-node paths ────────────────────────────────────────
    /// Path to the LMDB directory (`<root>/beacon-node/db`).
    beacon_db: []const u8,
    /// Path to the ENR secp256k1 key file (`<root>/beacon-node/network/enr-key`).
    enr_key: []const u8,
    /// Path to the local ENR file (`<root>/beacon-node/network/enr`).
    enr: []const u8,
    /// Path to the peer store directory (`<root>/beacon-node/network/peer-db`).
    peer_db: []const u8,
    /// Path to the state cache directory (`<root>/beacon-node/state-cache`).
    state_cache: []const u8,

    // ── Validator paths ──────────────────────────────────────────
    /// Path to the slashing protection file (`<root>/validator/slashing-protection.db`).
    slashing_protection: []const u8,
    /// Path to the keystores directory (`<root>/validator/keystores`).
    keystores: []const u8,
    /// Path to the secrets directory (`<root>/validator/secrets`).
    secrets: []const u8,

    // ── Shared paths ─────────────────────────────────────────────
    /// Path to the JWT secret file (`<root>/jwt.hex`).
    jwt_secret: []const u8,
    /// Path to the log file (`<root>/logs/lodestar-z.log`).
    log_file: []const u8,

    /// Resolve a DataDir from NodeOptions.
    ///
    /// When `opts.data_dir` is non-empty it is used as-is.
    /// Otherwise the platform-default is computed from `opts.network`.
    /// Individual overrides (`db_path`, `jwt_secret_path`) take precedence
    /// over the default sub-paths.
    pub fn resolve(allocator: Allocator, opts: NodeOptions) !DataDir {
        // Resolve root.
        const root: []const u8 = if (opts.data_dir.len > 0)
            try allocator.dupe(u8, opts.data_dir)
        else
            try defaultRoot(allocator, @tagName(opts.network));

        const network = try allocator.dupe(u8, @tagName(opts.network));

        // Beacon-node sub-paths.
        const beacon_base = try std.fs.path.join(allocator, &.{ root, "beacon-node" });
        defer allocator.free(beacon_base);

        const beacon_db: []const u8 = if (opts.db_path) |p|
            try allocator.dupe(u8, p)
        else
            try std.fs.path.join(allocator, &.{ beacon_base, "db" });

        const network_base = try std.fs.path.join(allocator, &.{ beacon_base, "network" });
        defer allocator.free(network_base);

        const enr_key = try std.fs.path.join(allocator, &.{ network_base, "enr-key" });
        const enr = try std.fs.path.join(allocator, &.{ network_base, "enr" });
        const peer_db = try std.fs.path.join(allocator, &.{ network_base, "peer-db" });
        const state_cache = try std.fs.path.join(allocator, &.{ beacon_base, "state-cache" });

        // Validator sub-paths.
        const validator_base = try std.fs.path.join(allocator, &.{ root, "validator" });
        defer allocator.free(validator_base);

        const slashing_protection = try std.fs.path.join(allocator, &.{ validator_base, "slashing-protection.db" });
        const keystores = try std.fs.path.join(allocator, &.{ validator_base, "keystores" });
        const secrets = try std.fs.path.join(allocator, &.{ validator_base, "secrets" });

        // Shared paths.
        const jwt_secret: []const u8 = if (opts.jwt_secret_path) |p|
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
            .slashing_protection = slashing_protection,
            .keystores = keystores,
            .secrets = secrets,
            .jwt_secret = jwt_secret,
            .log_file = log_file,
        };
    }

    /// Create all directories required before the node starts.
    ///
    /// Equivalent to `mkdir -p` for each sub-directory (but not the leaf
    /// files like `enr-key` or `jwt.hex`).
    pub fn ensureDirs(self: DataDir, io: std.Io) !void {
        const cwd = std.Io.Dir.cwd();

        try cwd.createDirPath(io, self.root);
        try cwd.createDirPath(io, self.beacon_db);
        try cwd.createDirPath(io, self.peer_db);
        try cwd.createDirPath(io, self.state_cache);
        try cwd.createDirPath(io, self.keystores);
        try cwd.createDirPath(io, self.secrets);

        // Logs directory (parent of log_file).
        if (std.fs.path.dirname(self.log_file)) |logs_dir| {
            try cwd.createDirPath(io, logs_dir);
        }

        // network/ directory (parent of enr-key).
        if (std.fs.path.dirname(self.enr_key)) |network_dir| {
            try cwd.createDirPath(io, network_dir);
        }

        // validator/ directory (parent of slashing-protection.db).
        if (std.fs.path.dirname(self.slashing_protection)) |val_dir| {
            try cwd.createDirPath(io, val_dir);
        }

        log.info("Data directories ready under {s}", .{self.root});
    }

    /// Free all heap-allocated path strings.
    pub fn deinit(self: *DataDir) void {
        const a = self.allocator;
        a.free(self.root);
        a.free(self.network);
        a.free(self.beacon_db);
        a.free(self.enr_key);
        a.free(self.enr);
        a.free(self.peer_db);
        a.free(self.state_cache);
        a.free(self.slashing_protection);
        a.free(self.keystores);
        a.free(self.secrets);
        a.free(self.jwt_secret);
        a.free(self.log_file);
    }
};

/// Compute the platform-default data root for a given network name.
///
/// - Linux/BSD: `$XDG_DATA_HOME/lodestar-z/<network>` or
///              `~/.local/share/lodestar-z/<network>`
/// - macOS:     `~/Library/Application Support/lodestar-z/<network>`
pub fn defaultRoot(allocator: Allocator, network: []const u8) ![]const u8 {
    // Use libc getenv — zero-copy, no allocation needed for the env read itself.
    const home_raw: ?[*:0]const u8 = std.c.getenv("HOME");
    const home: []const u8 = if (home_raw) |h| std.mem.span(h) else "";

    switch (builtin.os.tag) {
        .macos => {
            if (home.len == 0) return error.NoHomeDir;
            return std.fs.path.join(allocator, &.{ home, "Library", "Application Support", "lodestar-z", network });
        },
        else => {
            // XDG_DATA_HOME takes precedence on Linux/BSD.
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

// ── Tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "DataDir.resolve - explicit data_dir" {
    const allocator = testing.allocator;
    const opts = NodeOptions{
        .data_dir = "/tmp/test-datadir",
        .network = .mainnet,
    };
    var dd = try DataDir.resolve(allocator, opts);
    defer dd.deinit();

    try testing.expectEqualStrings("/tmp/test-datadir", dd.root);
    try testing.expectEqualStrings("mainnet", dd.network);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/db", dd.beacon_db);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/network/enr-key", dd.enr_key);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/network/enr", dd.enr);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/network/peer-db", dd.peer_db);
    try testing.expectEqualStrings("/tmp/test-datadir/beacon-node/state-cache", dd.state_cache);
    try testing.expectEqualStrings("/tmp/test-datadir/validator/slashing-protection.db", dd.slashing_protection);
    try testing.expectEqualStrings("/tmp/test-datadir/validator/keystores", dd.keystores);
    try testing.expectEqualStrings("/tmp/test-datadir/validator/secrets", dd.secrets);
    try testing.expectEqualStrings("/tmp/test-datadir/jwt.hex", dd.jwt_secret);
    try testing.expectEqualStrings("/tmp/test-datadir/logs/lodestar-z.log", dd.log_file);
}

test "DataDir.resolve - db_path override" {
    const allocator = testing.allocator;
    const opts = NodeOptions{
        .data_dir = "/tmp/test-datadir",
        .network = .sepolia,
        .db_path = "/data/fast-ssd/chain-db",
    };
    var dd = try DataDir.resolve(allocator, opts);
    defer dd.deinit();

    try testing.expectEqualStrings("/data/fast-ssd/chain-db", dd.beacon_db);
    try testing.expectEqualStrings("/tmp/test-datadir/jwt.hex", dd.jwt_secret);
}

test "DataDir.resolve - jwt_secret_path override" {
    const allocator = testing.allocator;
    const opts = NodeOptions{
        .data_dir = "/tmp/test-datadir",
        .network = .mainnet,
        .jwt_secret_path = "/etc/ethereum/jwt.hex",
    };
    var dd = try DataDir.resolve(allocator, opts);
    defer dd.deinit();

    try testing.expectEqualStrings("/etc/ethereum/jwt.hex", dd.jwt_secret);
}

test "DataDir.resolve - different networks produce different roots" {
    const allocator = testing.allocator;

    var dd1 = try DataDir.resolve(allocator, .{ .network = .mainnet });
    defer dd1.deinit();

    var dd2 = try DataDir.resolve(allocator, .{ .network = .sepolia });
    defer dd2.deinit();

    // Both roots must end with the network name.
    try testing.expect(std.mem.endsWith(u8, dd1.root, "mainnet"));
    try testing.expect(std.mem.endsWith(u8, dd2.root, "sepolia"));
    try testing.expect(!std.mem.eql(u8, dd1.root, dd2.root));
}

test "defaultRoot - xdg env override" {
    const allocator = testing.allocator;
    // Can't set env in tests portably, but we can at least verify the
    // fallback path contains expected components.
    const root = try defaultRoot(allocator, "hoodi");
    defer allocator.free(root);

    try testing.expect(root.len > 0);
    try testing.expect(std.mem.endsWith(u8, root, "hoodi"));
    // Must contain 'lodestar-z' somewhere.
    try testing.expect(std.mem.indexOf(u8, root, "lodestar-z") != null);
}
