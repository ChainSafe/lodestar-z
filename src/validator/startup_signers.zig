const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const fs = @import("fs.zig");
const key_discovery_mod = @import("key_discovery.zig");
const KeystoreLock = @import("keystore_lock.zig").KeystoreLock;
const keystore_mod = @import("keystore.zig");
const persisted_keys = @import("persisted_keys.zig");
const RemoteSigner = @import("remote_signer.zig").RemoteSigner;
const PersistencePaths = @import("types.zig").PersistencePaths;

const log = std.log.scoped(.validator_startup);

pub const LoadedKey = key_discovery_mod.LoadedKey;

pub const RemoteSignerKeys = struct {
    url: []const u8,
    pubkeys: [][48]u8 = &.{},

    pub fn deinit(self: *RemoteSignerKeys, allocator: Allocator) void {
        allocator.free(self.url);
        if (self.pubkeys.len > 0) allocator.free(self.pubkeys);
        self.* = .{
            .url = "",
            .pubkeys = &.{},
        };
    }
};

pub const RemoteSignerDefinition = struct {
    pubkey: [48]u8,
    url: []const u8,
};

pub const StartupSigners = struct {
    allocator: Allocator,
    local_keys: []LoadedKey = &.{},
    local_keystore_locks: []KeystoreLock = &.{},
    remote_signers: []RemoteSignerKeys = &.{},

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

        for (self.remote_signers) |*remote_signer| remote_signer.deinit(self.allocator);
        if (self.remote_signers.len > 0) self.allocator.free(self.remote_signers);

        self.* = .{
            .allocator = self.allocator,
        };
    }

    pub fn counts(self: *const StartupSigners) Counts {
        var remote: usize = 0;
        for (self.remote_signers) |remote_signer| remote += remote_signer.pubkeys.len;

        return .{
            .total = self.local_keys.len + remote,
            .local = self.local_keys.len,
            .remote = remote,
        };
    }
};

pub const LoadLocalOptions = struct {
    force: bool = false,
};

pub const ImportExternalKeystoresResult = struct {
    imported: usize,
    skipped_duplicates: usize,
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
            const lock = KeystoreLock.acquireWithPubkey(io, allocator, key.keystore_path, key.pubkey) catch |err| {
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

pub fn importExternalKeystores(
    io: Io,
    allocator: Allocator,
    paths: PersistencePaths,
    import_paths: []const []const u8,
    password_file: []const u8,
) !ImportExternalKeystoresResult {
    const password = try readImportPassword(io, allocator, password_file);
    defer allocator.free(password);

    var source_paths = std.ArrayListUnmanaged([]const u8).empty;
    defer {
        for (source_paths.items) |path| allocator.free(path);
        source_paths.deinit(allocator);
    }

    for (import_paths) |import_path| {
        try collectImportKeystorePaths(io, allocator, import_path, &source_paths);
    }

    if (source_paths.items.len == 0) {
        return error.NoImportKeystoresFound;
    }

    var seen_pubkeys = std.AutoHashMap([48]u8, void).init(allocator);
    defer seen_pubkeys.deinit();

    var imported: usize = 0;
    var skipped_duplicates: usize = 0;

    for (source_paths.items) |source_path| {
        const json_bytes = try fs.readFileAlloc(io, allocator, source_path, 1024 * 1024);
        defer allocator.free(json_bytes);

        var secret_key = keystore_mod.loadKeystore(allocator, json_bytes, password) catch |err| {
            log.err("failed to decrypt imported keystore {s}: {s}", .{ source_path, @errorName(err) });
            return err;
        };
        defer std.crypto.secureZero(u8, &secret_key.value.b);

        const pubkey = secret_key.toPublicKey().compress();
        const seen = try seen_pubkeys.getOrPut(pubkey);
        if (seen.found_existing) {
            skipped_duplicates += 1;
            log.warn(
                "skipping duplicate imported keystore pubkey=0x{s} path={s}",
                .{ std.fmt.bytesToHex(pubkey, .lower), source_path },
            );
            continue;
        }

        const pubkey_hex = persisted_keys.formatPubkeyHex(pubkey);
        const destination = try std.fs.path.join(allocator, &.{ paths.keystores_dir, &pubkey_hex, "voting-keystore.json" });
        defer allocator.free(destination);

        pathExists(io, destination) catch |err| switch (err) {
            error.FileNotFound => {
                _ = try persisted_keys.writeKeystore(io, allocator, paths, pubkey, json_bytes, password, .{});
                imported += 1;
                continue;
            },
            else => return err,
        };

        skipped_duplicates += 1;
        log.warn(
            "skipping already-imported keystore pubkey=0x{s} existing_path={s} source_path={s}",
            .{ std.fmt.bytesToHex(pubkey, .lower), destination, source_path },
        );
    }

    log.info(
        "imported {d} external validator keystore(s) into {s} (skipped_duplicates={d})",
        .{ imported, paths.keystores_dir, skipped_duplicates },
    );

    return .{
        .imported = imported,
        .skipped_duplicates = skipped_duplicates,
    };
}

pub fn fetchRemoteSignerKeys(
    io: Io,
    allocator: Allocator,
    urls: []const []const u8,
) ![]RemoteSignerKeys {
    var by_url = std.ArrayListUnmanaged(RemoteSignerKeys).empty;
    errdefer {
        for (by_url.items) |*item| item.deinit(allocator);
        by_url.deinit(allocator);
    }

    var seen_pubkeys = std.AutoHashMap([48]u8, []const u8).init(allocator);
    defer seen_pubkeys.deinit();

    for (urls) |url| {
        var signer = RemoteSigner.init(allocator, url);
        const fetched_pubkeys = try signer.listKeys(io);
        defer if (fetched_pubkeys.len > 0) allocator.free(fetched_pubkeys);

        var unique_pubkeys = std.ArrayListUnmanaged([48]u8).empty;
        errdefer unique_pubkeys.deinit(allocator);

        for (fetched_pubkeys) |pubkey| {
            const existing = try seen_pubkeys.getOrPut(pubkey);
            if (existing.found_existing) {
                log.warn(
                    "duplicate remote validator pubkey=0x{s} first_url={s} duplicate_url={s} - keeping first occurrence",
                    .{
                        std.fmt.bytesToHex(pubkey, .lower),
                        existing.value_ptr.*,
                        url,
                    },
                );
                continue;
            }

            existing.value_ptr.* = url;
            try unique_pubkeys.append(allocator, pubkey);
        }

        log.info("fetched {d} remote validator key(s) from {s}", .{ unique_pubkeys.items.len, url });
        try by_url.append(allocator, .{
            .url = try allocator.dupe(u8, url),
            .pubkeys = try unique_pubkeys.toOwnedSlice(allocator),
        });
    }

    return try by_url.toOwnedSlice(allocator);
}

pub fn loadPersistedRemoteSignerKeys(
    io: Io,
    allocator: Allocator,
    remote_keys_dir: []const u8,
) ![]RemoteSignerKeys {
    var dir = std.Io.Dir.cwd().openDir(io, remote_keys_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    defer dir.close(io);

    var definitions = std.ArrayListUnmanaged(RemoteSignerDefinition).empty;
    defer {
        for (definitions.items) |definition| allocator.free(definition.url);
        definitions.deinit(allocator);
    }

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;

        const definition_path = try std.fs.path.join(allocator, &.{ remote_keys_dir, entry.name });
        defer allocator.free(definition_path);

        const bytes = try fs.readFileAlloc(io, allocator, definition_path, 16 * 1024);
        defer allocator.free(bytes);

        const definition = try parseRemoteSignerDefinition(allocator, bytes);
        errdefer allocator.free(definition.url);
        try definitions.append(allocator, definition);
    }

    return groupRemoteSignerDefinitions(allocator, definitions.items);
}

fn parseRemoteSignerDefinition(allocator: Allocator, bytes: []const u8) !RemoteSignerDefinition {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), bytes, .{});
    const object = switch (parsed.value) {
        .object => |value| value,
        else => return error.InvalidRemoteSignerDefinition,
    };

    const pubkey_string = switch (object.get("pubkey") orelse return error.InvalidRemoteSignerDefinition) {
        .string => |value| value,
        else => return error.InvalidRemoteSignerDefinition,
    };
    const url = switch (object.get("url") orelse return error.InvalidRemoteSignerDefinition) {
        .string => |value| value,
        else => return error.InvalidRemoteSignerDefinition,
    };

    try validateRemoteSignerUrl(url);

    return .{
        .pubkey = try parseRemoteSignerPubkey(pubkey_string),
        .url = try allocator.dupe(u8, url),
    };
}

fn groupRemoteSignerDefinitions(
    allocator: Allocator,
    definitions: []const RemoteSignerDefinition,
) ![]RemoteSignerKeys {
    var grouped = std.ArrayListUnmanaged(RemoteSignerKeys).empty;
    errdefer {
        for (grouped.items) |*item| item.deinit(allocator);
        grouped.deinit(allocator);
    }

    var seen_pubkeys = std.AutoHashMap([48]u8, []const u8).init(allocator);
    defer seen_pubkeys.deinit();

    for (definitions) |definition| {
        const existing_pubkey = try seen_pubkeys.getOrPut(definition.pubkey);
        if (existing_pubkey.found_existing) {
            log.warn(
                "duplicate persisted remote validator pubkey=0x{s} first_url={s} duplicate_url={s} - keeping first occurrence",
                .{
                    std.fmt.bytesToHex(definition.pubkey, .lower),
                    existing_pubkey.value_ptr.*,
                    definition.url,
                },
            );
            continue;
        }
        existing_pubkey.value_ptr.* = definition.url;

        const signer_idx = findRemoteSignerGroup(grouped.items, definition.url) orelse blk: {
            try grouped.append(allocator, .{
                .url = try allocator.dupe(u8, definition.url),
                .pubkeys = &.{},
            });
            break :blk grouped.items.len - 1;
        };

        var pubkeys = std.ArrayListUnmanaged([48]u8).fromOwnedSlice(grouped.items[signer_idx].pubkeys);
        defer grouped.items[signer_idx].pubkeys = pubkeys.items;
        try pubkeys.append(allocator, definition.pubkey);
    }

    return try grouped.toOwnedSlice(allocator);
}

fn findRemoteSignerGroup(items: []const RemoteSignerKeys, url: []const u8) ?usize {
    for (items, 0..) |item, idx| {
        if (std.mem.eql(u8, item.url, url)) return idx;
    }
    return null;
}

pub fn parseRemoteSignerPubkey(raw: []const u8) ![48]u8 {
    const hex = if (std.mem.startsWith(u8, raw, "0x") or std.mem.startsWith(u8, raw, "0X"))
        raw[2..]
    else
        raw;
    if (hex.len != 96) return error.InvalidRemoteSignerPubkey;

    var pubkey: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pubkey, hex);
    return pubkey;
}

pub fn validateRemoteSignerUrl(url: []const u8) !void {
    const uri = try std.Uri.parse(url);
    if (uri.scheme.len == 0) return error.InvalidRemoteSignerUrl;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and !std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
        return error.InvalidRemoteSignerUrl;
    }
}

fn readImportPassword(io: Io, allocator: Allocator, password_file: []const u8) ![]const u8 {
    const password_raw = try fs.readFileAlloc(io, allocator, password_file, 4096);
    errdefer allocator.free(password_raw);

    const password = std.mem.trimEnd(u8, password_raw, &[_]u8{ '\n', '\r', ' ', '\t' });
    if (password.len == 0) return error.EmptyImportPassword;

    if (password.len < password_raw.len) {
        defer allocator.free(password_raw);
        return allocator.dupe(u8, password);
    }

    return password_raw;
}

fn collectImportKeystorePaths(
    io: Io,
    allocator: Allocator,
    input_path: []const u8,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    var dir = std.Io.Dir.cwd().openDir(io, input_path, .{ .iterate = true }) catch {
        var file = try std.Io.Dir.cwd().openFile(io, input_path, .{});
        file.close(io);

        if (isVotingKeystorePath(input_path) and !stringSliceContains(out.items, input_path)) {
            try out.append(allocator, try allocator.dupe(u8, input_path));
        }
        return;
    };
    defer dir.close(io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        switch (entry.kind) {
            .file => {
                if (!isVotingKeystorePath(entry.name)) continue;

                const child_path = try std.fs.path.join(allocator, &.{ input_path, entry.name });
                errdefer allocator.free(child_path);
                if (stringSliceContains(out.items, child_path)) {
                    allocator.free(child_path);
                    continue;
                }
                try out.append(allocator, child_path);
            },
            .directory => {
                const child_path = try std.fs.path.join(allocator, &.{ input_path, entry.name });
                defer allocator.free(child_path);
                try collectImportKeystorePaths(io, allocator, child_path, out);
            },
            else => {},
        }
    }
}

fn isVotingKeystorePath(path: []const u8) bool {
    return isVotingKeystoreFilename(std.fs.path.basename(path));
}

fn isVotingKeystoreFilename(filename: []const u8) bool {
    if (!std.mem.endsWith(u8, filename, ".json")) return false;
    if (isDepositDataFilename(filename)) return false;
    return true;
}

fn isDepositDataFilename(filename: []const u8) bool {
    const prefix = "deposit_data-";
    const suffix = ".json";
    if (!std.mem.startsWith(u8, filename, prefix) or !std.mem.endsWith(u8, filename, suffix)) return false;
    const digits = filename[prefix.len .. filename.len - suffix.len];
    if (digits.len == 0) return false;
    for (digits) |ch| {
        if (ch < '0' or ch > '9') return false;
    }
    return true;
}

fn stringSliceContains(items: []const []const u8, needle: []const u8) bool {
    for (items) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

fn pathExists(io: Io, path: []const u8) !void {
    try Io.Dir.cwd().access(io, path, .{});
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

test "loadPersistedRemoteSignerKeys groups definitions by URL" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("remoteKeys");
    try tmp.dir.writeFile(.{
        .sub_path = "remoteKeys/0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        .data = "{\"pubkey\":\"0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111\",\"url\":\"http://signer-a:9000\",\"readonly\":false}",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "remoteKeys/0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
        .data = "{\"pubkey\":\"0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222\",\"url\":\"http://signer-a:9000\",\"readonly\":false}",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "remoteKeys/0x333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333",
        .data = "{\"pubkey\":\"0x333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333\",\"url\":\"https://signer-b:9000\",\"readonly\":false}",
    });

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const remote_keys_dir = try std.fs.path.join(testing.allocator, &.{ root, "remoteKeys" });
    defer testing.allocator.free(remote_keys_dir);

    const groups = try loadPersistedRemoteSignerKeys(testing.io, testing.allocator, remote_keys_dir);
    defer {
        for (groups) |*group| group.deinit(testing.allocator);
        if (groups.len > 0) testing.allocator.free(groups);
    }

    try testing.expectEqual(@as(usize, 2), groups.len);
    try testing.expectEqualStrings("http://signer-a:9000", groups[0].url);
    try testing.expectEqual(@as(usize, 2), groups[0].pubkeys.len);
    try testing.expectEqualStrings("https://signer-b:9000", groups[1].url);
    try testing.expectEqual(@as(usize, 1), groups[1].pubkeys.len);
}

test "validateRemoteSignerUrl rejects unsupported schemes" {
    try testing.expectError(error.InvalidRemoteSignerUrl, validateRemoteSignerUrl("ftp://signer.example"));
}

test "importExternalKeystores recursively imports voting keystores into managed dirs" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("managed");
    try tmp.dir.makeDir("managed/keystores");
    try tmp.dir.makeDir("managed/secrets");
    try tmp.dir.makeDir("external");
    try tmp.dir.makeDir("external/nested");

    const created = try keystore_create.createKeystore(testing.io, testing.allocator, "import-pass", .{
        .n = 16,
        .r = 8,
        .p = 1,
    });
    defer created.deinit(testing.allocator);

    try tmp.dir.writeFile(.{
        .sub_path = "external/nested/validator-keystore.json",
        .data = created.keystore_json,
    });
    try tmp.dir.writeFile(.{
        .sub_path = "external/deposit_data-123.json",
        .data = "{}",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "password.txt",
        .data = "import-pass\n",
    });

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    const managed_keystores = try std.fs.path.join(testing.allocator, &.{ root, "managed", "keystores" });
    defer testing.allocator.free(managed_keystores);
    const managed_secrets = try std.fs.path.join(testing.allocator, &.{ root, "managed", "secrets" });
    defer testing.allocator.free(managed_secrets);
    const external_dir = try std.fs.path.join(testing.allocator, &.{ root, "external" });
    defer testing.allocator.free(external_dir);
    const password_file = try std.fs.path.join(testing.allocator, &.{ root, "password.txt" });
    defer testing.allocator.free(password_file);

    const result = try importExternalKeystores(testing.io, testing.allocator, .{
        .keystores_dir = managed_keystores,
        .secrets_dir = managed_secrets,
        .remote_keys_dir = "",
        .proposer_dir = "",
    }, &.{external_dir}, password_file);

    try testing.expectEqual(@as(usize, 1), result.imported);
    try testing.expectEqual(@as(usize, 0), result.skipped_duplicates);

    var signers = try loadLocalSigners(testing.io, testing.allocator, managed_keystores, managed_secrets, .{});
    defer signers.deinit(testing.io);

    try testing.expectEqual(@as(usize, 1), signers.local_keys.len);
    try testing.expectEqualSlices(u8, &created.pubkey, &signers.local_keys[0].pubkey);
}
