const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const SecretKey = @import("bls").SecretKey;

const fs = @import("fs.zig");
const key_discovery_mod = @import("key_discovery.zig");
const DiscoveredKey = key_discovery_mod.DiscoveredKey;
const LoadedKey = key_discovery_mod.LoadedKey;
const keystore_mod = @import("keystore.zig");
const keystore_create = @import("keystore_create.zig");

const log = std.log.scoped(.validator_keystore_cache);

pub const cache_filename = "local_keystores.cache";

pub fn loadLocalCache(
    io: Io,
    allocator: Allocator,
    cache_dir: []const u8,
    discovered: []const DiscoveredKey,
    passwords: []const []const u8,
) ![]SecretKey {
    if (discovered.len == 0) return &.{};
    if (discovered.len != passwords.len) return error.InvalidKeystoreCache;

    const cache_path = try std.fs.path.join(allocator, &.{ cache_dir, cache_filename });
    defer allocator.free(cache_path);

    const json_bytes = try fs.readFileAlloc(io, allocator, cache_path, 128 * 1024 * 1024);
    defer allocator.free(json_bytes);

    const expected_pubkey_hex = try allocConcatenatedPubkeyHex(allocator, discovered);
    defer allocator.free(expected_pubkey_hex);

    const actual_pubkey_hex = try keystore_mod.loadKeystorePubkeyHex(allocator, json_bytes);
    defer allocator.free(actual_pubkey_hex);

    if (!std.mem.eql(u8, expected_pubkey_hex, actual_pubkey_hex)) {
        return error.StaleKeystoreCache;
    }

    const password_blob = try allocConcatenatedPasswords(allocator, passwords);
    defer {
        std.crypto.secureZero(u8, password_blob);
        allocator.free(password_blob);
    }

    const plaintext = try keystore_mod.loadKeystoreBytes(allocator, json_bytes, password_blob);
    defer {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
    }

    if (plaintext.len != discovered.len * 32) return error.StaleKeystoreCache;

    var secret_keys = try allocator.alloc(SecretKey, discovered.len);
    errdefer allocator.free(secret_keys);

    for (discovered, 0..) |key, idx| {
        var secret_key_bytes: [32]u8 = undefined;
        @memcpy(&secret_key_bytes, plaintext[idx * 32 ..][0..32]);
        defer std.crypto.secureZero(u8, &secret_key_bytes);

        const secret_key = SecretKey.deserialize(&secret_key_bytes) catch return error.StaleKeystoreCache;
        const derived_pubkey = secret_key.toPublicKey().compress();
        if (!std.mem.eql(u8, &derived_pubkey, &key.pubkey)) {
            return error.StaleKeystoreCache;
        }
        secret_keys[idx] = secret_key;
    }

    return secret_keys;
}

pub fn writeLocalCache(
    io: Io,
    allocator: Allocator,
    cache_dir: []const u8,
    loaded_keys: []const LoadedKey,
    passwords: []const []const u8,
) !void {
    if (loaded_keys.len == 0) return;
    if (loaded_keys.len != passwords.len) return error.InvalidKeystoreCache;

    const secret_key_blob = try allocConcatenatedSecretKeys(allocator, loaded_keys);
    defer {
        std.crypto.secureZero(u8, secret_key_blob);
        allocator.free(secret_key_blob);
    }

    const password_blob = try allocConcatenatedPasswords(allocator, passwords);
    defer {
        std.crypto.secureZero(u8, password_blob);
        allocator.free(password_blob);
    }

    const pubkey_blob = try allocConcatenatedPubkeys(allocator, loaded_keys);
    defer allocator.free(pubkey_blob);

    const cache_json = try keystore_create.encryptKeystoreBytes(
        io,
        allocator,
        secret_key_blob,
        password_blob,
        pubkey_blob,
        .{},
    );
    defer allocator.free(cache_json);

    try Io.Dir.cwd().createDirPath(io, cache_dir);

    const cache_path = try std.fs.path.join(allocator, &.{ cache_dir, cache_filename });
    defer allocator.free(cache_path);

    var atomic_file = try Io.Dir.cwd().createFileAtomic(io, cache_path, .{
        .permissions = .fromMode(0o600),
        .replace = true,
    });
    defer atomic_file.deinit(io);

    try atomic_file.file.writePositionalAll(io, cache_json, 0);
    try atomic_file.file.sync(io);
    try atomic_file.replace(io);
}

pub fn invalidateLocalCache(io: Io, allocator: Allocator, cache_dir: []const u8) void {
    const cache_path = std.fs.path.join(allocator, &.{ cache_dir, cache_filename }) catch return;
    defer allocator.free(cache_path);

    Io.Dir.cwd().deleteFile(io, cache_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => log.warn("failed to delete stale keystore cache {s}: {s}", .{ cache_path, @errorName(err) }),
    };
}

fn allocConcatenatedPasswords(allocator: Allocator, passwords: []const []const u8) ![]u8 {
    var total_len: usize = 0;
    for (passwords) |password| total_len += password.len;

    const blob = try allocator.alloc(u8, total_len);
    errdefer allocator.free(blob);

    var offset: usize = 0;
    for (passwords) |password| {
        @memcpy(blob[offset..][0..password.len], password);
        offset += password.len;
    }
    return blob;
}

fn allocConcatenatedSecretKeys(allocator: Allocator, loaded_keys: []const LoadedKey) ![]u8 {
    const blob = try allocator.alloc(u8, loaded_keys.len * 32);
    errdefer allocator.free(blob);

    for (loaded_keys, 0..) |key, idx| {
        const secret_key_bytes = key.secret_key.serialize();
        @memcpy(blob[idx * 32 ..][0..32], &secret_key_bytes);
    }
    return blob;
}

fn allocConcatenatedPubkeys(allocator: Allocator, keys: anytype) ![]u8 {
    const blob = try allocator.alloc(u8, keys.len * 48);
    errdefer allocator.free(blob);

    for (keys, 0..) |key, idx| {
        @memcpy(blob[idx * 48 ..][0..48], &key.pubkey);
    }
    return blob;
}

fn allocConcatenatedPubkeyHex(allocator: Allocator, keys: anytype) ![]u8 {
    const blob = try allocConcatenatedPubkeys(allocator, keys);
    defer allocator.free(blob);

    const hex = try allocator.alloc(u8, blob.len * 2);
    errdefer allocator.free(hex);
    _ = std.fmt.bufPrint(hex, "{x}", .{blob}) catch unreachable;
    return hex;
}

const testing = std.testing;
const keystore_create_mod = @import("keystore_create.zig");

test "local keystore cache round-trips concatenated validator secrets" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("cache");

    const created_a = try keystore_create_mod.createKeystore(testing.io, testing.allocator, "cache-pass-a", .{
        .n = 16,
        .r = 8,
        .p = 1,
    });
    defer created_a.deinit(testing.allocator);

    const created_b = try keystore_create_mod.createKeystore(testing.io, testing.allocator, "cache-pass-b", .{
        .n = 16,
        .r = 8,
        .p = 1,
    });
    defer created_b.deinit(testing.allocator);

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const cache_dir = try std.fs.path.join(testing.allocator, &.{ root, "cache" });
    defer testing.allocator.free(cache_dir);

    const discovered = [_]DiscoveredKey{
        .{
            .pubkey = created_a.pubkey,
            .pubkey_hex = try testing.allocator.dupe(u8, created_a.pubkey_hex),
            .keystore_path = try testing.allocator.dupe(u8, "/tmp/a"),
        },
        .{
            .pubkey = created_b.pubkey,
            .pubkey_hex = try testing.allocator.dupe(u8, created_b.pubkey_hex),
            .keystore_path = try testing.allocator.dupe(u8, "/tmp/b"),
        },
    };
    defer {
        for (discovered) |key| key.deinit(testing.allocator);
    }

    const loaded = [_]LoadedKey{
        .{
            .pubkey = created_a.pubkey,
            .secret_key = created_a.secret_key,
            .keystore_path = try testing.allocator.dupe(u8, "/tmp/a"),
        },
        .{
            .pubkey = created_b.pubkey,
            .secret_key = created_b.secret_key,
            .keystore_path = try testing.allocator.dupe(u8, "/tmp/b"),
        },
    };
    defer {
        for (loaded) |key| key.deinit(testing.allocator);
    }

    const passwords = [_][]const u8{ "cache-pass-a", "cache-pass-b" };
    try writeLocalCache(testing.io, testing.allocator, cache_dir, &loaded, &passwords);

    const recovered = try loadLocalCache(testing.io, testing.allocator, cache_dir, &discovered, &passwords);
    defer testing.allocator.free(recovered);

    try testing.expectEqual(@as(usize, 2), recovered.len);
    try testing.expectEqualSlices(u8, &created_a.secret_key.serialize(), &recovered[0].serialize());
    try testing.expectEqualSlices(u8, &created_b.secret_key.serialize(), &recovered[1].serialize());
}
