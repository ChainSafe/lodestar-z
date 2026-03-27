//! Key discovery for the Validator Client.
//!
//! Scans the data directory for EIP-2335 keystore files and loads passwords
//! from the secrets directory, then decrypts them into BLS secret keys.
//!
//! Expected layout:
//! ```
//! keystores/
//!   0xaabb...ccdd/
//!     voting-keystore.json
//!   0xeeff...1122/
//!     voting-keystore.json
//! secrets/
//!   0xaabb...ccdd   (file containing password)
//!   0xeeff...1122
//! ```
//!
//! TS equivalent: packages/keymanager/src/local/keystoreManager.ts (LocalKeystoreManager)

const std = @import("std");
const Allocator = std.mem.Allocator;

const bls = @import("bls");
const SecretKey = bls.SecretKey;

const keystore_mod = @import("keystore.zig");

const log = std.log.scoped(.key_discovery);

/// A discovered keystore before decryption.
pub const DiscoveredKey = struct {
    /// Compressed BLS public key (48 bytes).
    pubkey: [48]u8,
    /// Hex-encoded pubkey string ("0x..."), owned.
    pubkey_hex: []const u8,
    /// Path to the voting-keystore.json file, owned.
    keystore_path: []const u8,

    pub fn deinit(self: DiscoveredKey, allocator: Allocator) void {
        allocator.free(self.pubkey_hex);
        allocator.free(self.keystore_path);
    }
};

/// A loaded (decrypted) validator key.
pub const LoadedKey = struct {
    /// Compressed BLS public key (48 bytes).
    pubkey: [48]u8,
    /// Decrypted BLS secret key.
    secret_key: SecretKey,
    /// Path to the keystore JSON file, owned.
    keystore_path: []const u8,

    pub fn deinit(self: LoadedKey, allocator: Allocator) void {
        allocator.free(self.keystore_path);
    }
};

/// Key discovery and loading utilities.
pub const KeyDiscovery = struct {
    /// Scan `keystores_dir` for EIP-2335 keystore files.
    ///
    /// Expected layout: keystores/<0xPUBKEY>/voting-keystore.json
    ///
    /// Returns a caller-owned slice of DiscoveredKey. Caller must free each
    /// entry via `entry.deinit(allocator)` and then free the slice itself.
    pub fn scanKeystores(allocator: Allocator, keystores_dir: []const u8) ![]DiscoveredKey {
        var results = std.ArrayList(DiscoveredKey).init(allocator);
        errdefer {
            for (results.items) |k| k.deinit(allocator);
            results.deinit();
        }

        var dir = std.fs.openDirAbsolute(keystores_dir, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return results.toOwnedSlice(),
            else => return err,
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            // Directory name should be the pubkey hex (e.g. "0xaabb...").
            const dir_name = entry.name;
            if (dir_name.len < 3 or !std.mem.startsWith(u8, dir_name, "0x")) continue;

            // Decode the pubkey from the directory name.
            const hex_without_prefix = dir_name[2..];
            if (hex_without_prefix.len != 96) {
                log.debug("skipping keystore dir with unexpected length: {s}", .{dir_name});
                continue;
            }

            var pubkey_bytes: [48]u8 = undefined;
            std.fmt.hexToBytes(&pubkey_bytes, hex_without_prefix) catch {
                log.debug("skipping keystore dir with non-hex name: {s}", .{dir_name});
                continue;
            };

            // Construct path to voting-keystore.json.
            const keystore_path = try std.fs.path.join(allocator, &.{ keystores_dir, dir_name, "voting-keystore.json" });
            errdefer allocator.free(keystore_path);

            // Check the file exists.
            std.fs.accessAbsolute(keystore_path, .{}) catch {
                allocator.free(keystore_path);
                log.debug("skipping {s}: no voting-keystore.json", .{dir_name});
                continue;
            };

            const pubkey_hex = try allocator.dupe(u8, dir_name);
            errdefer allocator.free(pubkey_hex);

            try results.append(.{
                .pubkey = pubkey_bytes,
                .pubkey_hex = pubkey_hex,
                .keystore_path = keystore_path,
            });

            log.debug("discovered keystore pubkey={s}", .{dir_name});
        }

        log.info("discovered {d} keystores in {s}", .{ results.items.len, keystores_dir });
        return results.toOwnedSlice();
    }

    /// Load password for a keystore from `secrets_dir`.
    ///
    /// Expected: `secrets/<pubkey_hex>` containing the plaintext password.
    /// The `pubkey_hex` should be the "0x..."-prefixed hex string (directory name).
    ///
    /// Returns an owned slice. Caller must free.
    pub fn loadPassword(allocator: Allocator, secrets_dir: []const u8, pubkey_hex: []const u8) ![]const u8 {
        const secret_path = try std.fs.path.join(allocator, &.{ secrets_dir, pubkey_hex });
        defer allocator.free(secret_path);

        const file = try std.fs.openFileAbsolute(secret_path, .{});
        defer file.close();

        const password_raw = try file.readToEndAlloc(allocator, 4096);
        errdefer allocator.free(password_raw);

        // Trim trailing newline/whitespace.
        const password = std.mem.trimRight(u8, password_raw, &[_]u8{ '\n', '\r', ' ', '\t' });

        // Return a clean copy if we trimmed.
        if (password.len < password_raw.len) {
            defer allocator.free(password_raw);
            return allocator.dupe(u8, password);
        }

        return password_raw;
    }

    /// Load all keys: scan keystores → load passwords → decrypt → return LoadedKeys.
    ///
    /// Returns a caller-owned slice. Each entry's `keystore_path` must be freed via
    /// `entry.deinit(allocator)`. The slice itself must be freed with `allocator.free`.
    ///
    /// Keys that fail to load (missing password, wrong password, corrupt keystore)
    /// are logged as warnings and skipped rather than causing a hard error.
    pub fn loadAllKeys(allocator: Allocator, keystores_dir: []const u8, secrets_dir: []const u8) ![]LoadedKey {
        const discovered = try scanKeystores(allocator, keystores_dir);
        defer {
            for (discovered) |k| k.deinit(allocator);
            allocator.free(discovered);
        }

        var loaded = std.ArrayList(LoadedKey).init(allocator);
        errdefer {
            for (loaded.items) |k| k.deinit(allocator);
            loaded.deinit();
        }

        for (discovered) |key| {
            // Load password.
            const password = loadPassword(allocator, secrets_dir, key.pubkey_hex) catch |err| {
                log.warn("failed to load password for {s}: {s}", .{ key.pubkey_hex, @errorName(err) });
                continue;
            };
            defer allocator.free(password);

            // Read keystore JSON.
            const json_bytes = std.fs.cwd().readFileAlloc(allocator, key.keystore_path, 1024 * 1024) catch |err| {
                log.warn("failed to read keystore {s}: {s}", .{ key.keystore_path, @errorName(err) });
                continue;
            };
            defer allocator.free(json_bytes);

            // Decrypt.
            const secret_key = keystore_mod.loadKeystore(allocator, json_bytes, password) catch |err| {
                log.warn("failed to decrypt keystore {s}: {s}", .{ key.keystore_path, @errorName(err) });
                continue;
            };

            const keystore_path_copy = try allocator.dupe(u8, key.keystore_path);
            errdefer allocator.free(keystore_path_copy);

            try loaded.append(.{
                .pubkey = key.pubkey,
                .secret_key = secret_key,
                .keystore_path = keystore_path_copy,
            });

            log.info("loaded validator key pubkey={s}", .{key.pubkey_hex});
        }

        log.info("loaded {d}/{d} validator keys", .{ loaded.items.len, discovered.len });
        return loaded.toOwnedSlice();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "KeyDiscovery.scanKeystores: nonexistent dir returns empty slice" {
    const keys = try KeyDiscovery.scanKeystores(testing.allocator, "/nonexistent/path/to/keystores");
    defer testing.allocator.free(keys);
    try testing.expectEqual(@as(usize, 0), keys.len);
}

test "KeyDiscovery.scanKeystores: scans directory layout" {
    // Create a temp directory structure.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    // Create keystores/0xaabb.../voting-keystore.json.
    const pubkey_hex = "0x" ++ "ab" ** 48;
    try tmp.dir.makeDir(pubkey_hex);
    var ks_dir = try tmp.dir.openDir(pubkey_hex, .{});
    defer ks_dir.close();

    // Write a minimal (fake) voting-keystore.json.
    const fake_keystore = "{\"version\":4,\"uuid\":\"test\"}";
    try ks_dir.writeFile(.{ .sub_path = "voting-keystore.json", .data = fake_keystore });

    // Also create a non-directory entry (should be skipped).
    try tmp.dir.writeFile(.{ .sub_path = "somefile.txt", .data = "ignored" });

    const keys = try KeyDiscovery.scanKeystores(testing.allocator, tmp_path);
    defer {
        for (keys) |k| k.deinit(testing.allocator);
        testing.allocator.free(keys);
    }

    try testing.expectEqual(@as(usize, 1), keys.len);
    try testing.expectEqualStrings(pubkey_hex, keys[0].pubkey_hex);
    try testing.expect(std.mem.endsWith(u8, keys[0].keystore_path, "voting-keystore.json"));
}

test "KeyDiscovery.loadPassword: reads and trims password" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    const pubkey_hex = "0xaabbcc";
    try tmp.dir.writeFile(.{ .sub_path = pubkey_hex, .data = "mysecretpassword\n" });

    const password = try KeyDiscovery.loadPassword(testing.allocator, tmp_path, pubkey_hex);
    defer testing.allocator.free(password);

    try testing.expectEqualStrings("mysecretpassword", password);
}

test "KeyDiscovery.loadPassword: missing file returns error" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    const result = KeyDiscovery.loadPassword(testing.allocator, tmp_path, "0xmissing");
    try testing.expectError(error.FileNotFound, result);
}
