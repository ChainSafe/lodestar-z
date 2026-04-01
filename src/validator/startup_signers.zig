const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const fs = @import("fs.zig");
const key_discovery_mod = @import("key_discovery.zig");
const KeystoreLock = @import("keystore_lock.zig").KeystoreLock;
const keystore_mod = @import("keystore.zig");
const RemoteSigner = @import("remote_signer.zig").RemoteSigner;

const log = std.log.scoped(.validator_startup);

pub const LoadedKey = key_discovery_mod.LoadedKey;

pub const StartupSigners = struct {
    allocator: Allocator,
    local_keys: []LoadedKey = &.{},
    local_keystore_locks: []KeystoreLock = &.{},
    remote_pubkeys: [][48]u8 = &.{},

    pub const Counts = struct {
        total: usize,
        local: usize,
        remote: usize,
    };

    pub fn deinit(self: *StartupSigners, io: Io) void {
        for (self.local_keys) |key| key.deinit(self.allocator);
        if (self.local_keys.len > 0) self.allocator.free(self.local_keys);

        for (self.local_keystore_locks) |*lock| lock.deinit(io);
        if (self.local_keystore_locks.len > 0) self.allocator.free(self.local_keystore_locks);

        if (self.remote_pubkeys.len > 0) self.allocator.free(self.remote_pubkeys);

        self.* = .{
            .allocator = self.allocator,
        };
    }

    pub fn counts(self: *const StartupSigners) Counts {
        return .{
            .total = self.local_keys.len + self.remote_pubkeys.len,
            .local = self.local_keys.len,
            .remote = self.remote_pubkeys.len,
        };
    }
};

pub const LoadLocalOptions = struct {
    force: bool = false,
};

pub fn loadLocalSigners(
    io: Io,
    allocator: Allocator,
    keystores_dir: []const u8,
    secrets_dir: []const u8,
    options: LoadLocalOptions,
) !StartupSigners {
    const discovered = try key_discovery_mod.KeyDiscovery.scanKeystores(io, allocator, keystores_dir);
    defer {
        for (discovered) |key| key.deinit(allocator);
        allocator.free(discovered);
    }

    var loaded: std.ArrayListUnmanaged(LoadedKey) = .empty;
    errdefer {
        for (loaded.items) |key| key.deinit(allocator);
        loaded.deinit(allocator);
    }

    var locks: std.ArrayListUnmanaged(KeystoreLock) = .empty;
    errdefer {
        for (locks.items) |*lock| lock.deinit(io);
        locks.deinit(allocator);
    }

    for (discovered) |key| {
        if (!options.force) {
            const lock = KeystoreLock.acquire(io, allocator, key.keystore_path) catch |err| {
                log.err("failed to lock keystore {s}: {s}", .{ key.keystore_path, @errorName(err) });
                return err;
            };
            try locks.append(allocator, lock);
        } else {
            log.warn("force-loading keystore without acquiring ownership lock: {s}", .{key.keystore_path});
        }

        const password = key_discovery_mod.KeyDiscovery.loadPassword(io, allocator, secrets_dir, key.pubkey_hex) catch |err| {
            log.err("failed to load password for {s}: {s}", .{ key.pubkey_hex, @errorName(err) });
            return err;
        };
        defer allocator.free(password);

        const json_bytes = fs.readFileAlloc(io, allocator, key.keystore_path, 1024 * 1024) catch |err| {
            log.err("failed to read keystore {s}: {s}", .{ key.keystore_path, @errorName(err) });
            return err;
        };
        defer allocator.free(json_bytes);

        const secret_key = keystore_mod.loadKeystore(allocator, json_bytes, password) catch |err| {
            log.err("failed to decrypt keystore {s}: {s}", .{ key.keystore_path, @errorName(err) });
            return err;
        };

        try loaded.append(allocator, .{
            .pubkey = key.pubkey,
            .secret_key = secret_key,
            .keystore_path = try allocator.dupe(u8, key.keystore_path),
        });
    }

    log.info("loaded {d} local validator keystore(s)", .{loaded.items.len});

    return .{
        .allocator = allocator,
        .local_keys = try loaded.toOwnedSlice(allocator),
        .local_keystore_locks = try locks.toOwnedSlice(allocator),
    };
}

pub fn fetchRemoteSignerPubkeys(io: Io, allocator: Allocator, url: []const u8) ![][48]u8 {
    var signer = RemoteSigner.init(allocator, url);
    const pubkeys = try signer.listKeys(io);
    log.info("fetched {d} remote validator key(s) from {s}", .{ pubkeys.len, url });
    return pubkeys;
}

const testing = std.testing;
const keystore_create = @import("keystore_create.zig");

test "loadLocalSigners loads and locks local keystores" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("keystores");
    try tmp.dir.makeDir("secrets");

    const created = try keystore_create.createKeystore(testing.io, testing.allocator, "secret-pass", .{
        .n = 16,
        .r = 8,
        .p = 1,
    });
    defer created.deinit(testing.allocator);

    const keystore_rel_dir = try std.fs.path.join(testing.allocator, &.{ "keystores", created.pubkey_hex });
    defer testing.allocator.free(keystore_rel_dir);
    try tmp.dir.makeDir(keystore_rel_dir);
    var validator_dir = try tmp.dir.openDir(keystore_rel_dir, .{});
    defer validator_dir.close();
    try validator_dir.writeFile(.{
        .sub_path = "voting-keystore.json",
        .data = created.keystore_json,
    });
    const secret_rel_path = try std.fs.path.join(testing.allocator, &.{ "secrets", created.pubkey_hex });
    defer testing.allocator.free(secret_rel_path);
    try tmp.dir.writeFile(.{
        .sub_path = secret_rel_path,
        .data = "secret-pass\n",
    });

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const keystores_dir = try std.fs.path.join(testing.allocator, &.{ root, "keystores" });
    defer testing.allocator.free(keystores_dir);
    const secrets_dir = try std.fs.path.join(testing.allocator, &.{ root, "secrets" });
    defer testing.allocator.free(secrets_dir);

    var signers = try loadLocalSigners(testing.io, testing.allocator, keystores_dir, secrets_dir, .{});
    defer signers.deinit(testing.io);

    try testing.expectEqual(@as(usize, 1), signers.local_keys.len);
    try testing.expectEqual(@as(usize, 1), signers.local_keystore_locks.len);
    try testing.expectEqualSlices(u8, &created.pubkey, &signers.local_keys[0].pubkey);
}

test "loadLocalSigners fails fast when a password file is missing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("keystores");
    try tmp.dir.makeDir("secrets");

    const created = try keystore_create.createKeystore(testing.io, testing.allocator, "secret-pass", .{
        .n = 16,
        .r = 8,
        .p = 1,
    });
    defer created.deinit(testing.allocator);

    const keystore_rel_dir = try std.fs.path.join(testing.allocator, &.{ "keystores", created.pubkey_hex });
    defer testing.allocator.free(keystore_rel_dir);
    try tmp.dir.makeDir(keystore_rel_dir);
    var validator_dir = try tmp.dir.openDir(keystore_rel_dir, .{});
    defer validator_dir.close();
    try validator_dir.writeFile(.{
        .sub_path = "voting-keystore.json",
        .data = created.keystore_json,
    });

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const keystores_dir = try std.fs.path.join(testing.allocator, &.{ root, "keystores" });
    defer testing.allocator.free(keystores_dir);
    const secrets_dir = try std.fs.path.join(testing.allocator, &.{ root, "secrets" });
    defer testing.allocator.free(secrets_dir);

    try testing.expectError(error.FileNotFound, loadLocalSigners(testing.io, testing.allocator, keystores_dir, secrets_dir, .{}));
}
