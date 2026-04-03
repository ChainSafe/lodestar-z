//! EIP-2335 keystore loading for the Validator Client.
//!
//! Parses the EIP-2335 JSON keystore format (BIP-39 / eth2 key standard).
//! Implements the full decryption flow:
//!   scrypt/pbkdf2 → checksum verify → AES-128-CTR decrypt → BLS SecretKey.
//!
//! References:
//!   https://eips.ethereum.org/EIPS/eip-2335
//!   https://github.com/ChainSafe/lodestar/blob/unstable/packages/keymanager/src/local/keystoreManager.ts
//!
//! TS equivalent: packages/keymanager/src/local/keystoreManager.ts (LocalKeystoreManager)

const std = @import("std");
const Allocator = std.mem.Allocator;

const bls = @import("bls");
const SecretKey = bls.SecretKey;

const log = std.log.scoped(.keystore);

fn optionalStringField(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const value = obj.get(key) orelse return "";
    return switch (value) {
        .string => |s| s,
        else => "",
    };
}

// ---------------------------------------------------------------------------
// EIP-2335 JSON schema types
// ---------------------------------------------------------------------------

/// KDF function name.
pub const KdfFunction = enum {
    scrypt,
    pbkdf2,
};

/// Scrypt KDF parameters.
pub const ScryptParams = struct {
    /// Memory factor (log2(N)).
    n: u64,
    /// Block size.
    r: u64,
    /// Parallelism factor.
    p: u64,
    /// Key length.
    dklen: u64,
    /// Salt (hex encoded in JSON).
    salt: []const u8,
};

/// PBKDF2 KDF parameters.
pub const Pbkdf2Params = struct {
    /// PRF algorithm (e.g., "hmac-sha256").
    prf: []const u8,
    /// Iteration count.
    c: u64,
    /// Key length.
    dklen: u64,
    /// Salt (hex encoded in JSON).
    salt: []const u8,
};

/// KDF module from EIP-2335 crypto section.
pub const KdfModule = struct {
    function: KdfFunction,
    /// AES message (hex encoded).
    message: []const u8,
    // Raw params stored for dispatch.
    params_json: std.json.Value,
};

/// Cipher module (always aes-128-ctr per EIP-2335).
pub const CipherModule = struct {
    /// Function name ("aes-128-ctr").
    function: []const u8,
    /// IV for AES-128-CTR (hex encoded).
    iv: []const u8,
    /// Ciphertext (hex encoded).
    message: []const u8,
};

/// Checksum module.
pub const ChecksumModule = struct {
    /// Function name ("sha256").
    function: []const u8,
    /// Expected checksum (hex encoded).
    message: []const u8,
};

/// EIP-2335 keystore crypto section.
pub const KeystoreCrypto = struct {
    kdf: KdfModule,
    checksum: ChecksumModule,
    cipher: CipherModule,
};

/// Top-level EIP-2335 keystore.
pub const Keystore = struct {
    /// Keystore format version (must be 4).
    version: u64,
    /// UUID (string).
    uuid: []const u8,
    /// Human-readable description (optional).
    description: []const u8,
    /// BLS public key (hex, optional — omitted for blind keystores).
    pubkey: []const u8,
    /// Path within the HD tree (optional, can be empty).
    path: []const u8,
    /// Crypto section.
    crypto: KeystoreCrypto,
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decode a hex string into a freshly-allocated byte slice.
fn hexDecodeAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// AES-128-CTR: XOR `src` into `dst` using big-endian counter starting at 0.
///
/// EIP-2335 uses AES-128-CTR with a 16-byte IV as the initial counter value,
/// incrementing as a 128-bit big-endian integer.
fn aesCtr128Xor(dst: []u8, src: []const u8, key: [16]u8, iv: [16]u8) void {
    std.debug.assert(dst.len == src.len);
    const Aes128 = std.crypto.core.aes.Aes128;
    const enc_ctx = Aes128.initEnc(key);

    var counter: [16]u8 = iv;
    var i: usize = 0;
    while (i < src.len) {
        // Encrypt the counter block to produce keystream block.
        var keystream: [16]u8 = undefined;
        enc_ctx.encrypt(&keystream, &counter);

        // XOR up to 16 bytes.
        const chunk_len = @min(16, src.len - i);
        for (0..chunk_len) |j| {
            dst[i + j] = src[i + j] ^ keystream[j];
        }
        i += chunk_len;

        // Increment counter as big-endian 128-bit integer.
        var k: usize = 15;
        while (true) {
            counter[k] +%= 1;
            if (counter[k] != 0 or k == 0) break;
            k -= 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Decryptor
// ---------------------------------------------------------------------------

/// Handles the multi-step EIP-2335 decrypt flow.
///
/// Steps:
///   1. Derive decryption key from password via KDF (scrypt or pbkdf2).
///   2. Verify checksum: SHA256(decryption_key[16..32] ++ cipher.message) == checksum.message
///   3. Decrypt: AES-128-CTR(key=decryption_key[0..16], iv=cipher.iv, cipher.message) → secret_key_bytes
///   4. Return BLS SecretKey from secret_key_bytes.
pub const KeystoreDecryptor = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) KeystoreDecryptor {
        return .{ .allocator = allocator };
    }

    /// Decrypt a keystore and return the plaintext bytes.
    ///
    /// The returned slice is owned by the caller and must be securely zeroed
    /// and freed after use.
    pub fn decryptBytes(self: *KeystoreDecryptor, keystore: *const Keystore, password: []const u8) ![]u8 {
        // Step 1: KDF — derive 32-byte decryption key.
        var decryption_key: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &decryption_key);
        switch (keystore.crypto.kdf.function) {
            .scrypt => {
                const params_obj = switch (keystore.crypto.kdf.params_json) {
                    .object => |obj| obj,
                    else => return error.InvalidKeystoreJson,
                };
                const n_val = params_obj.get("n") orelse return error.MissingKdfParam;
                const r_val = params_obj.get("r") orelse return error.MissingKdfParam;
                const p_val = params_obj.get("p") orelse return error.MissingKdfParam;
                const dklen_val = params_obj.get("dklen") orelse return error.MissingKdfParam;
                const salt_val = params_obj.get("salt") orelse return error.MissingKdfParam;

                const n: u64 = switch (n_val) {
                    .integer => |v| @intCast(v),
                    else => return error.InvalidKdfParam,
                };
                const r: u30 = @intCast(switch (r_val) {
                    .integer => |v| @as(u64, @intCast(v)),
                    else => return error.InvalidKdfParam,
                });
                const p: u30 = @intCast(switch (p_val) {
                    .integer => |v| @as(u64, @intCast(v)),
                    else => return error.InvalidKdfParam,
                });
                const dklen: u64 = switch (dklen_val) {
                    .integer => |v| @intCast(v),
                    else => return error.InvalidKdfParam,
                };
                const salt_hex = switch (salt_val) {
                    .string => |s| s,
                    else => return error.InvalidKdfParam,
                };

                if (dklen != 32) return error.UnsupportedDklen;

                const salt = try hexDecodeAlloc(self.allocator, salt_hex);
                defer self.allocator.free(salt);

                // Compute ln = log2(N).
                if (n == 0 or (n & (n - 1)) != 0) return error.InvalidScryptN;
                const ln: u6 = @intCast(std.math.log2(n));

                const scrypt_params = std.crypto.pwhash.scrypt.Params{
                    .ln = ln,
                    .r = r,
                    .p = p,
                };
                try std.crypto.pwhash.scrypt.kdf(
                    self.allocator,
                    &decryption_key,
                    password,
                    salt,
                    scrypt_params,
                );
                log.debug("scrypt KDF complete ln={d} r={d} p={d}", .{ ln, r, p });
            },
            .pbkdf2 => {
                const params_obj = switch (keystore.crypto.kdf.params_json) {
                    .object => |obj| obj,
                    else => return error.InvalidKeystoreJson,
                };
                const c_val = params_obj.get("c") orelse return error.MissingKdfParam;
                const dklen_val = params_obj.get("dklen") orelse return error.MissingKdfParam;
                const salt_val = params_obj.get("salt") orelse return error.MissingKdfParam;

                const c: u32 = @intCast(switch (c_val) {
                    .integer => |v| @as(u64, @intCast(v)),
                    else => return error.InvalidKdfParam,
                });
                const dklen: u64 = switch (dklen_val) {
                    .integer => |v| @intCast(v),
                    else => return error.InvalidKdfParam,
                };
                const salt_hex = switch (salt_val) {
                    .string => |s| s,
                    else => return error.InvalidKdfParam,
                };

                if (dklen != 32) return error.UnsupportedDklen;

                const salt = try hexDecodeAlloc(self.allocator, salt_hex);
                defer self.allocator.free(salt);

                const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
                try std.crypto.pwhash.pbkdf2(&decryption_key, password, salt, c, HmacSha256);
                log.debug("pbkdf2 KDF complete c={d}", .{c});
            },
        }

        // Step 2: verify checksum.
        // checksum = SHA256(decryption_key[16..32] || cipher_message_bytes)
        const cipher_bytes = try hexDecodeAlloc(self.allocator, keystore.crypto.cipher.message);
        defer self.allocator.free(cipher_bytes);

        var checksum_input = try self.allocator.alloc(u8, 16 + cipher_bytes.len);
        defer {
            std.crypto.secureZero(u8, checksum_input);
            self.allocator.free(checksum_input);
        }
        @memcpy(checksum_input[0..16], decryption_key[16..32]);
        @memcpy(checksum_input[16..], cipher_bytes);

        var computed_checksum: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(checksum_input, &computed_checksum, .{});

        const expected_checksum = try hexDecodeAlloc(self.allocator, keystore.crypto.checksum.message);
        defer self.allocator.free(expected_checksum);

        if (!std.mem.eql(u8, &computed_checksum, expected_checksum)) {
            log.warn("keystore checksum mismatch — wrong password or corrupted keystore", .{});
            return error.InvalidChecksum;
        }

        // Step 3: AES-128-CTR decrypt.
        var iv_bytes: [16]u8 = undefined;
        const iv_hex = keystore.crypto.cipher.iv;
        if (iv_hex.len != 32) return error.InvalidIvLength;
        _ = try std.fmt.hexToBytes(&iv_bytes, iv_hex);

        var key_bytes: [16]u8 = undefined;
        defer std.crypto.secureZero(u8, &key_bytes);
        @memcpy(&key_bytes, decryption_key[0..16]);

        const plaintext = try self.allocator.alloc(u8, cipher_bytes.len);
        aesCtr128Xor(plaintext, cipher_bytes, key_bytes, iv_bytes);

        log.debug("keystore decryption successful", .{});
        return plaintext;
    }

    /// Decrypt a keystore and return the BLS secret key.
    pub fn decrypt(self: *KeystoreDecryptor, keystore: *const Keystore, password: []const u8) !SecretKey {
        const plaintext = try self.decryptBytes(keystore, password);
        defer {
            std.crypto.secureZero(u8, plaintext);
            self.allocator.free(plaintext);
        }

        // Step 4: interpret 32-byte plaintext as BLS secret key.
        if (plaintext.len != 32) return error.InvalidKeystoreSize;
        var sk_bytes: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &sk_bytes);
        @memcpy(&sk_bytes, plaintext[0..32]);

        return SecretKey.deserialize(&sk_bytes) catch return error.InvalidBLSSecretKey;
    }
};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Load a keystore from JSON bytes and decrypt with the given password.
///
/// Allocator is used for JSON parsing (freed on return).
/// Returns the decrypted BLS SecretKey on success.
///
/// TS: LocalKeystoreManager.importKeystore(keystoreStr, password)
pub fn loadKeystore(allocator: Allocator, json_bytes: []const u8, password: []const u8) !SecretKey {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Parse the outer JSON.
    const parsed = try std.json.parseFromSlice(std.json.Value, a, json_bytes, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };

    // Version check.
    const version_val = root_obj.get("version") orelse return error.MissingKeystoreField;
    const version: u64 = switch (version_val) {
        .integer => |n| @intCast(n),
        else => return error.InvalidKeystoreVersion,
    };
    if (version != 4) {
        log.warn("keystore version {d} is not supported (expected 4)", .{version});
        return error.UnsupportedKeystoreVersion;
    }

    // Extract crypto section.
    const crypto_val = root_obj.get("crypto") orelse return error.MissingKeystoreField;
    const crypto_obj = switch (crypto_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };

    // Parse KDF.
    const kdf_val = crypto_obj.get("kdf") orelse return error.MissingKeystoreField;
    const kdf_obj = switch (kdf_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    const kdf_fn_val = kdf_obj.get("function") orelse return error.MissingKeystoreField;
    const kdf_fn_str = switch (kdf_fn_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };
    const kdf_fn = if (std.mem.eql(u8, kdf_fn_str, "scrypt"))
        KdfFunction.scrypt
    else if (std.mem.eql(u8, kdf_fn_str, "pbkdf2"))
        KdfFunction.pbkdf2
    else
        return error.UnsupportedKdfFunction;

    const kdf_params_val = kdf_obj.get("params") orelse return error.MissingKeystoreField;
    const kdf_msg = optionalStringField(kdf_obj, "message");

    // Parse cipher.
    const cipher_val = crypto_obj.get("cipher") orelse return error.MissingKeystoreField;
    const cipher_obj = switch (cipher_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    const cipher_fn_val = cipher_obj.get("function") orelse return error.MissingKeystoreField;
    const cipher_fn_str = switch (cipher_fn_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };
    const cipher_params_val = cipher_obj.get("params") orelse return error.MissingKeystoreField;
    const cipher_params_obj = switch (cipher_params_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    const cipher_iv_val = cipher_params_obj.get("iv") orelse return error.MissingKeystoreField;
    const cipher_iv = switch (cipher_iv_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };
    const cipher_msg_val = cipher_obj.get("message") orelse return error.MissingKeystoreField;
    const cipher_msg = switch (cipher_msg_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };

    // Parse checksum.
    const cksum_val = crypto_obj.get("checksum") orelse return error.MissingKeystoreField;
    const cksum_obj = switch (cksum_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    const cksum_fn_val = cksum_obj.get("function") orelse return error.MissingKeystoreField;
    const cksum_fn = switch (cksum_fn_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };
    const cksum_msg_val = cksum_obj.get("message") orelse return error.MissingKeystoreField;
    const cksum_msg = switch (cksum_msg_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };

    // Build Keystore struct.
    const uuid_str = optionalStringField(root_obj, "uuid");
    const desc_str = optionalStringField(root_obj, "description");
    const pk_str = optionalStringField(root_obj, "pubkey");
    const path_str = optionalStringField(root_obj, "path");

    const keystore = Keystore{
        .version = version,
        .uuid = uuid_str,
        .description = desc_str,
        .pubkey = pk_str,
        .path = path_str,
        .crypto = .{
            .kdf = .{
                .function = kdf_fn,
                .message = kdf_msg,
                .params_json = kdf_params_val,
            },
            .checksum = .{
                .function = cksum_fn,
                .message = cksum_msg,
            },
            .cipher = .{
                .function = cipher_fn_str,
                .iv = cipher_iv,
                .message = cipher_msg,
            },
        },
    };

    log.debug("loading keystore uuid={s} kdf={s} cipher={s}", .{
        keystore.uuid,
        kdf_fn_str,
        keystore.crypto.cipher.function,
    });

    var decryptor = KeystoreDecryptor.init(allocator);
    return decryptor.decrypt(&keystore, password);
}

/// Load a keystore from JSON bytes and decrypt it into caller-owned plaintext.
///
/// This supports the normal one-secret-key EIP-2335 path and the validator
/// startup cache path, where the plaintext contains concatenated validator
/// secret keys rather than a single 32-byte secret.
pub fn loadKeystoreBytes(allocator: Allocator, json_bytes: []const u8, password: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = try std.json.parseFromSlice(std.json.Value, a, json_bytes, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };

    const version_val = root_obj.get("version") orelse return error.MissingKeystoreField;
    const version: u64 = switch (version_val) {
        .integer => |n| @intCast(n),
        else => return error.InvalidKeystoreVersion,
    };
    if (version != 4) return error.UnsupportedKeystoreVersion;

    const crypto_val = root_obj.get("crypto") orelse return error.MissingKeystoreField;
    const crypto_obj = switch (crypto_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };

    const kdf_val = crypto_obj.get("kdf") orelse return error.MissingKeystoreField;
    const kdf_obj = switch (kdf_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    const kdf_fn_val = kdf_obj.get("function") orelse return error.MissingKeystoreField;
    const kdf_fn_str = switch (kdf_fn_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };
    const kdf_fn = if (std.mem.eql(u8, kdf_fn_str, "scrypt"))
        KdfFunction.scrypt
    else if (std.mem.eql(u8, kdf_fn_str, "pbkdf2"))
        KdfFunction.pbkdf2
    else
        return error.UnsupportedKdfFunction;

    const kdf_params_val = kdf_obj.get("params") orelse return error.MissingKeystoreField;
    const kdf_msg = optionalStringField(kdf_obj, "message");

    const cipher_val = crypto_obj.get("cipher") orelse return error.MissingKeystoreField;
    const cipher_obj = switch (cipher_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    const cipher_fn_val = cipher_obj.get("function") orelse return error.MissingKeystoreField;
    const cipher_fn_str = switch (cipher_fn_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };
    const cipher_params_val = cipher_obj.get("params") orelse return error.MissingKeystoreField;
    const cipher_params_obj = switch (cipher_params_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    const cipher_iv_val = cipher_params_obj.get("iv") orelse return error.MissingKeystoreField;
    const cipher_iv = switch (cipher_iv_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };
    const cipher_msg_val = cipher_obj.get("message") orelse return error.MissingKeystoreField;
    const cipher_msg = switch (cipher_msg_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };

    const cksum_val = crypto_obj.get("checksum") orelse return error.MissingKeystoreField;
    const cksum_obj = switch (cksum_val) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    const cksum_fn_val = cksum_obj.get("function") orelse return error.MissingKeystoreField;
    const cksum_fn = switch (cksum_fn_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };
    const cksum_msg_val = cksum_obj.get("message") orelse return error.MissingKeystoreField;
    const cksum_msg = switch (cksum_msg_val) {
        .string => |s| s,
        else => return error.InvalidKeystoreJson,
    };

    const keystore = Keystore{
        .version = version,
        .uuid = optionalStringField(root_obj, "uuid"),
        .description = optionalStringField(root_obj, "description"),
        .pubkey = optionalStringField(root_obj, "pubkey"),
        .path = optionalStringField(root_obj, "path"),
        .crypto = .{
            .kdf = .{
                .function = kdf_fn,
                .message = kdf_msg,
                .params_json = kdf_params_val,
            },
            .checksum = .{
                .function = cksum_fn,
                .message = cksum_msg,
            },
            .cipher = .{
                .function = cipher_fn_str,
                .iv = cipher_iv,
                .message = cipher_msg,
            },
        },
    };

    var decryptor = KeystoreDecryptor.init(allocator);
    return decryptor.decryptBytes(&keystore, password);
}

/// Read the `pubkey` field from a keystore JSON document as an owned slice.
///
/// This is used by the validator startup cache to verify that the encrypted
/// aggregate cache still matches the currently discovered validator set before
/// trusting the cached secret material.
pub fn loadKeystorePubkeyHex(allocator: Allocator, json_bytes: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), json_bytes, .{});
    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidKeystoreJson,
    };
    return allocator.dupe(u8, optionalStringField(root_obj, "pubkey"));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "loadKeystore: rejects non-v4 keystore" {
    const json =
        \\{"version":3,"uuid":"test","crypto":{"kdf":{"function":"scrypt","params":{},"message":""},"checksum":{"function":"sha256","message":""},"cipher":{"function":"aes-128-ctr","params":{"iv":""},"message":""}}}
    ;
    try testing.expectError(error.UnsupportedKeystoreVersion, loadKeystore(testing.allocator, json, "password"));
}

test "loadKeystore: rejects invalid json" {
    try testing.expectError(error.InvalidKeystoreJson, loadKeystore(testing.allocator, "not-json", "password"));
}

test "loadKeystore: EIP-2335 scrypt test vector" {
    // Test vector from https://eips.ethereum.org/EIPS/eip-2335#test-vectors
    // Password: "testpassword"
    // Secret key: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    const json =
        \\{
        \\  "crypto": {
        \\    "kdf": {
        \\      "function": "scrypt",
        \\      "params": {
        \\        "dklen": 32,
        \\        "n": 262144,
        \\        "p": 1,
        \\        "r": 8,
        \\        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
        \\      },
        \\      "message": ""
        \\    },
        \\    "checksum": {
        \\      "function": "sha256",
        \\      "params": {},
        \\      "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846abde07dd3dccbbe"
        \\    },
        \\    "cipher": {
        \\      "function": "aes-128-ctr",
        \\      "params": {
        \\        "iv": "264daa3f303d7259501c93d997d84fe6"
        \\      },
        \\      "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
        \\    }
        \\  },
        \\  "description": "This is a test keystore that uses scrypt to secure the secret.",
        \\  "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        \\  "path": "m/12381/60/3141592653/0",
        \\  "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
        \\  "version": 4
        \\}
    ;
    const sk = try loadKeystore(testing.allocator, json, "testpassword");
    const sk_bytes = sk.serialize();
    const expected_hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, &sk_bytes);
}

test "loadKeystore: EIP-2335 pbkdf2 test vector" {
    // Test vector from https://eips.ethereum.org/EIPS/eip-2335#test-vectors
    // Password: "testpassword"
    // Secret key: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    const json =
        \\{
        \\  "crypto": {
        \\    "kdf": {
        \\      "function": "pbkdf2",
        \\      "params": {
        \\        "dklen": 32,
        \\        "c": 262144,
        \\        "prf": "hmac-sha256",
        \\        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
        \\      },
        \\      "message": ""
        \\    },
        \\    "checksum": {
        \\      "function": "sha256",
        \\      "params": {},
        \\      "message": "8a9f5d9912ed7ad069bee7d9f2571b500884c5cc8e29ef9ef18a5bd3e7b3ca71"
        \\    },
        \\    "cipher": {
        \\      "function": "aes-128-ctr",
        \\      "params": {
        \\        "iv": "264daa3f303d7259501c93d997d84fe6"
        \\      },
        \\      "message": "cee418436f7c26a2d7bb61bf51e81d3a3f9f8be92e93fbf6d3cef1e0e8c0ba7b"
        \\    }
        \\  },
        \\  "description": "This is a test keystore that uses pbkdf2 to secure the secret.",
        \\  "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        \\  "path": "m/12381/60/0/0",
        \\  "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        \\  "version": 4
        \\}
    ;
    const sk = try loadKeystore(testing.allocator, json, "testpassword");
    const sk_bytes = sk.serialize();
    const expected_hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, &sk_bytes);
}

test "loadKeystore: wrong password → InvalidChecksum" {
    const json =
        \\{
        \\  "crypto": {
        \\    "kdf": {
        \\      "function": "pbkdf2",
        \\      "params": {
        \\        "dklen": 32,
        \\        "c": 262144,
        \\        "prf": "hmac-sha256",
        \\        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
        \\      },
        \\      "message": ""
        \\    },
        \\    "checksum": {
        \\      "function": "sha256",
        \\      "params": {},
        \\      "message": "8a9f5d9912ed7ad069bee7d9f2571b500884c5cc8e29ef9ef18a5bd3e7b3ca71"
        \\    },
        \\    "cipher": {
        \\      "function": "aes-128-ctr",
        \\      "params": {
        \\        "iv": "264daa3f303d7259501c93d997d84fe6"
        \\      },
        \\      "message": "cee418436f7c26a2d7bb61bf51e81d3a3f9f8be92e93fbf6d3cef1e0e8c0ba7b"
        \\    }
        \\  },
        \\  "description": "test",
        \\  "pubkey": "",
        \\  "path": "",
        \\  "uuid": "test-uuid",
        \\  "version": 4
        \\}
    ;
    try testing.expectError(error.InvalidChecksum, loadKeystore(testing.allocator, json, "wrongpassword"));
}
