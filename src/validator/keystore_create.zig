//! EIP-2335 keystore creation for the Validator Client.
//!
//! Generates a new random BLS secret key, encrypts it with a password using
//! the EIP-2335 format (scrypt KDF), and writes the keystore JSON.
//!
//! Useful for:
//! - Dev mode / local testing
//! - `lodestar-z validator create` CLI command
//! - Tests that need live keystores
//!
//! References:
//!   https://eips.ethereum.org/EIPS/eip-2335
//!
//! TS equivalent: packages/keymanager/src/local/keystoreManager.ts (createLocalKeystore)

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const bls = @import("bls");
const SecretKey = bls.SecretKey;

const fs = @import("fs.zig");
const keystore_mod = @import("keystore.zig");

const log = std.log.scoped(.keystore_create);

/// Scrypt parameters for keystore creation.
/// These match what the TS Lodestar uses (n=262144, r=8, p=1).
pub const ScryptParams = struct {
    n: u64 = 262144,
    r: u32 = 8,
    p: u32 = 1,
};

/// Result of creating a keystore.
pub const CreatedKeystore = struct {
    /// The BLS secret key.
    secret_key: SecretKey,
    /// Compressed BLS public key.
    pubkey: [48]u8,
    /// Hex-encoded pubkey ("0x..."), owned.
    pubkey_hex: []const u8,
    /// Keystore JSON content, owned.
    keystore_json: []const u8,

    pub fn deinit(self: CreatedKeystore, allocator: Allocator) void {
        allocator.free(self.pubkey_hex);
        allocator.free(self.keystore_json);
    }
};

/// Generate a new random BLS secret key and encrypt as EIP-2335 keystore.
///
/// Returns an owned CreatedKeystore. Caller must call .deinit(allocator).
pub fn createKeystore(io: Io, allocator: Allocator, password: []const u8, params: ScryptParams) !CreatedKeystore {
    // Generate random 32-byte scalar.
    var sk_bytes: [32]u8 = undefined;
    io.random(&sk_bytes);

    // Create BLS secret key. Retry if we happen to generate zero (astronomically rare).
    const secret_key: SecretKey = sk: {
        // Extremely unlikely — just increment byte 31 and try again.
        break :sk SecretKey.deserialize(&sk_bytes) catch {
            sk_bytes[31] +%= 1;
            break :sk SecretKey.deserialize(&sk_bytes) catch return error.InvalidBLSSecretKey;
        };
    };

    const pubkey = secret_key.toPublicKey().compress();
    const pubkey_hex = try std.fmt.allocPrint(allocator, "0x{x}", .{pubkey});
    errdefer allocator.free(pubkey_hex);

    const keystore_json = try encryptKeystore(io, allocator, secret_key, password, params);
    errdefer allocator.free(keystore_json);

    return .{
        .secret_key = secret_key,
        .pubkey = pubkey,
        .pubkey_hex = pubkey_hex,
        .keystore_json = keystore_json,
    };
}

/// Encrypt an existing BLS secret key as an EIP-2335 keystore JSON string.
///
/// Uses scrypt KDF with the given parameters.
/// Returns an owned JSON string. Caller must free.
pub fn encryptKeystore(io: Io, allocator: Allocator, secret_key: SecretKey, password: []const u8, params: ScryptParams) ![]const u8 {
    const sk_bytes = secret_key.serialize();
    const pubkey = secret_key.toPublicKey().compress();
    return encryptKeystoreBytes(io, allocator, &sk_bytes, password, &pubkey, params);
}

/// Encrypt arbitrary plaintext bytes as an EIP-2335-compatible keystore JSON string.
///
/// This is used for the validator startup cache, where the plaintext is the
/// concatenated local validator secret keys and the pubkey field stores the
/// concatenated public keys for self-validation.
pub fn encryptKeystoreBytes(
    io: Io,
    allocator: Allocator,
    plaintext: []const u8,
    password: []const u8,
    pubkey_bytes: []const u8,
    params: ScryptParams,
) ![]const u8 {
    if (plaintext.len == 0) return error.InvalidKeystoreSize;

    // Generate random 32-byte salt and 16-byte IV.
    var salt: [32]u8 = undefined;
    var iv: [16]u8 = undefined;
    io.random(&salt);
    io.random(&iv);

    // Generate UUID (v4).
    var uuid_bytes: [16]u8 = undefined;
    io.random(&uuid_bytes);
    // Set version (4) and variant bits per RFC 4122.
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;

    // Derive 32-byte key via scrypt.
    var decryption_key: [32]u8 = undefined;
    if (params.n == 0 or (params.n & (params.n - 1)) != 0) return error.InvalidScryptN;
    const ln: u6 = @intCast(std.math.log2(params.n));
    try std.crypto.pwhash.scrypt.kdf(
        allocator,
        &decryption_key,
        password,
        &salt,
        .{ .ln = ln, .r = @intCast(params.r), .p = @intCast(params.p) },
    );

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);
    aesCtr128Xor(ciphertext, plaintext, decryption_key[0..16].*, iv);

    // Compute checksum: SHA256(decryption_key[16..32] || ciphertext).
    const checksum_input = try allocator.alloc(u8, 16 + ciphertext.len);
    defer {
        std.crypto.secureZero(u8, checksum_input);
        allocator.free(checksum_input);
    }
    @memcpy(checksum_input[0..16], decryption_key[16..32]);
    @memcpy(checksum_input[16..], ciphertext);
    var checksum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(checksum_input, &checksum, .{});

    // Build keystore JSON.
    const json = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "crypto": {{
        \\    "kdf": {{
        \\      "function": "scrypt",
        \\      "params": {{
        \\        "dklen": 32,
        \\        "n": {d},
        \\        "p": {d},
        \\        "r": {d},
        \\        "salt": "{x}"
        \\      }},
        \\      "message": ""
        \\    }},
        \\    "checksum": {{
        \\      "function": "sha256",
        \\      "params": {{}},
        \\      "message": "{x}"
        \\    }},
        \\    "cipher": {{
        \\      "function": "aes-128-ctr",
        \\      "params": {{
        \\        "iv": "{x}"
        \\      }},
        \\      "message": "{x}"
        \\    }}
        \\  }},
        \\  "description": "",
        \\  "pubkey": "{x}",
        \\  "path": "",
        \\  "uuid": "{s}",
        \\  "version": 4
        \\}}
    , .{
        params.n,
        params.p,
        params.r,
        salt,
        checksum,
        iv,
        ciphertext,
        pubkey_bytes,
        formatUuid(uuid_bytes),
    });

    return json;
}

/// Write a keystore to the data directory layout.
///
/// Creates:
///   <keystores_dir>/<pubkey_hex>/voting-keystore.json
///   <secrets_dir>/<pubkey_hex>  (password file)
pub fn writeKeystoreToDir(
    io: Io,
    keystores_dir: []const u8,
    secrets_dir: []const u8,
    pubkey_hex: []const u8,
    keystore_json: []const u8,
    password: []const u8,
) !void {
    // Create <keystores_dir>/<pubkey_hex>/ directory.
    var ks_base = try Io.Dir.openDirAbsolute(io, keystores_dir, .{});
    defer ks_base.close(io);
    ks_base.createDir(io, pubkey_hex, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Write voting-keystore.json.
    var ks_subdir = try ks_base.openDir(io, pubkey_hex, .{});
    defer ks_subdir.close(io);
    try ks_subdir.writeFile(io, .{ .sub_path = "voting-keystore.json", .data = keystore_json });

    // Write password file.
    var secrets_base = try Io.Dir.openDirAbsolute(io, secrets_dir, .{});
    defer secrets_base.close(io);
    try secrets_base.writeFile(io, .{ .sub_path = pubkey_hex, .data = password });

    log.info("wrote keystore for {s}", .{pubkey_hex});
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// AES-128-CTR: XOR src into dst using big-endian counter starting at iv.
fn aesCtr128Xor(dst: []u8, src: []const u8, key: [16]u8, iv: [16]u8) void {
    std.debug.assert(dst.len == src.len);
    const Aes128 = std.crypto.core.aes.Aes128;
    const enc_ctx = Aes128.initEnc(key);

    var counter: [16]u8 = iv;
    var i: usize = 0;
    while (i < src.len) {
        var keystream: [16]u8 = undefined;
        enc_ctx.encrypt(&keystream, &counter);
        const chunk_len = @min(16, src.len - i);
        for (0..chunk_len) |j| dst[i + j] = src[i + j] ^ keystream[j];
        i += chunk_len;
        var k: usize = 15;
        while (true) {
            counter[k] +%= 1;
            if (counter[k] != 0 or k == 0) break;
            k -= 1;
        }
    }
}

/// UUID formatter: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
fn formatUuid(bytes: [16]u8) [36]u8 {
    var out: [36]u8 = undefined;
    const hex = "0123456789abcdef";
    var i: usize = 0;
    var o: usize = 0;
    while (i < 16) : (i += 1) {
        if (o == 8 or o == 13 or o == 18 or o == 23) {
            out[o] = '-';
            o += 1;
        }
        out[o] = hex[bytes[i] >> 4];
        out[o + 1] = hex[bytes[i] & 0x0f];
        o += 2;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "createKeystore: roundtrip encrypt/decrypt" {
    // Use very small scrypt params for test speed.
    const params = ScryptParams{ .n = 2, .r = 1, .p = 1 };
    const password = "testpass";

    const created = try createKeystore(testing.io, testing.allocator, password, params);
    defer created.deinit(testing.allocator);

    // The pubkey_hex should start with "0x" and have 98 chars (0x + 96 hex chars).
    try testing.expectEqual(@as(usize, 98), created.pubkey_hex.len);
    try testing.expect(std.mem.startsWith(u8, created.pubkey_hex, "0x"));

    // Decrypt and verify we get the same secret key back.
    const recovered_sk = try keystore_mod.loadKeystore(testing.allocator, created.keystore_json, password);
    const recovered_bytes = recovered_sk.serialize();
    const original_bytes = created.secret_key.serialize();
    try testing.expectEqualSlices(u8, &original_bytes, &recovered_bytes);
}

test "createKeystore: wrong password fails" {
    const params = ScryptParams{ .n = 2, .r = 1, .p = 1 };

    const created = try createKeystore(testing.io, testing.allocator, "correct", params);
    defer created.deinit(testing.allocator);

    try testing.expectError(
        error.InvalidChecksum,
        keystore_mod.loadKeystore(testing.allocator, created.keystore_json, "wrong"),
    );
}

test "encryptKeystore: known key roundtrip" {
    const params = ScryptParams{ .n = 2, .r = 1, .p = 1 };
    var sk_bytes: [32]u8 = [_]u8{0} ** 32;
    sk_bytes[31] = 1;
    const sk = try SecretKey.deserialize(&sk_bytes);

    const json = try encryptKeystore(testing.io, testing.allocator, sk, "mypassword", params);
    defer testing.allocator.free(json);

    const recovered = try keystore_mod.loadKeystore(testing.allocator, json, "mypassword");
    try testing.expectEqualSlices(u8, &sk.serialize(), &recovered.serialize());
}

test "writeKeystoreToDir: writes files correctly" {
    var tmp_ks = testing.tmpDir(.{});
    defer tmp_ks.cleanup();
    var tmp_sec = testing.tmpDir(.{});
    defer tmp_sec.cleanup();

    const ks_path = try tmp_ks.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ks_path);
    const sec_path = try tmp_sec.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(sec_path);

    const pubkey_hex = "0x" ++ "ab" ** 48;
    const keystore_json = "{\"version\":4}";
    const password = "hunter2";

    try writeKeystoreToDir(testing.io, ks_path, sec_path, pubkey_hex, keystore_json, password);

    // Verify voting-keystore.json exists.
    const ks_file_path = try std.fs.path.join(testing.allocator, &.{ ks_path, pubkey_hex, "voting-keystore.json" });
    defer testing.allocator.free(ks_file_path);
    const ks_content = try fs.readFileAlloc(testing.io, testing.allocator, ks_file_path, 4096);
    defer testing.allocator.free(ks_content);
    try testing.expectEqualStrings(keystore_json, ks_content);

    // Verify password file exists.
    const sec_file_path = try std.fs.path.join(testing.allocator, &.{ sec_path, pubkey_hex });
    defer testing.allocator.free(sec_file_path);
    const sec_content = try fs.readFileAlloc(testing.io, testing.allocator, sec_file_path, 4096);
    defer testing.allocator.free(sec_content);
    try testing.expectEqualStrings(password, sec_content);
}
