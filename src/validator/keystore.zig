//! EIP-2335 keystore loading for the Validator Client.
//!
//! Parses the EIP-2335 JSON keystore format (BIP-39 / eth2 key standard).
//! Decryption (scrypt/pbkdf2 + AES-128-CTR + checksum) is type-complete
//! but returns error.NotImplemented for the actual crypto until we have
//! scrypt/pbkdf2 in zig std.
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

    /// Decrypt a keystore and return the BLS secret key.
    ///
    /// Returns error.NotImplemented for the actual KDF+AES crypto.
    /// The type flow is complete — callers can use this stub in tests.
    pub fn decrypt(self: *KeystoreDecryptor, keystore: *const Keystore, password: []const u8) !SecretKey {
        _ = password;

        switch (keystore.crypto.kdf.function) {
            .scrypt => {
                // TODO: scrypt(N=params.n, r=params.r, p=params.p, dk_len=params.dklen, password, salt)
                log.warn("scrypt KDF not yet implemented", .{});
                return error.NotImplemented;
            },
            .pbkdf2 => {
                // TODO: pbkdf2_hmac_sha256(password, salt, c=params.c, dk_len=params.dklen)
                log.warn("pbkdf2 KDF not yet implemented", .{});
                return error.NotImplemented;
            },
        }

        // Post-KDF steps (unreachable until KDF is implemented):
        //
        //   const decryption_key: [32]u8 = <kdf output>;
        //
        //   // Step 2: verify checksum
        //   var cipher_bytes: []u8 = try hexDecode(self.allocator, keystore.crypto.cipher.message);
        //   defer self.allocator.free(cipher_bytes);
        //   var checksum_input: [48]u8 = undefined;
        //   @memcpy(checksum_input[0..16], decryption_key[16..32]);
        //   @memcpy(checksum_input[16..48], cipher_bytes[0..32]);
        //   var computed_checksum: [32]u8 = undefined;
        //   std.crypto.hash.sha2.Sha256.hash(&checksum_input, &computed_checksum, .{});
        //   const expected_checksum = try hexDecode(self.allocator, keystore.crypto.checksum.message);
        //   defer self.allocator.free(expected_checksum);
        //   if (!std.mem.eql(u8, &computed_checksum, expected_checksum)) return error.InvalidChecksum;
        //
        //   // Step 3: AES-128-CTR decrypt
        //   var iv_bytes: [16]u8 = undefined;
        //   _ = try std.fmt.hexToBytes(&iv_bytes, ...) // iv
        //   var plaintext = try self.allocator.dupe(u8, cipher_bytes);
        //   defer self.allocator.free(plaintext);
        //   std.crypto.stream.aes.Aes128Ctr.xor(plaintext, cipher_bytes, decryption_key[0..16].*, iv_bytes, 0);
        //
        //   // Step 4: interpret 32-byte plaintext as BLS secret key
        //   var sk_bytes: [32]u8 = undefined;
        //   @memcpy(&sk_bytes, plaintext[0..32]);
        //   return SecretKey.fromBytes(sk_bytes);

        _ = self;
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
/// Currently returns error.NotImplemented for actual decryption.
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
    const kdf_msg_val = kdf_obj.get("message") orelse .{ .string = "" };
    const kdf_msg = switch (kdf_msg_val) {
        .string => |s| s,
        else => "",
    };

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
    const uuid_val = root_obj.get("uuid") orelse .{ .string = "" };
    const uuid_str = switch (uuid_val) {
        .string => |s| s,
        else => "",
    };
    const desc_val = root_obj.get("description") orelse .{ .string = "" };
    const desc_str = switch (desc_val) {
        .string => |s| s,
        else => "",
    };
    const pk_val = root_obj.get("pubkey") orelse .{ .string = "" };
    const pk_str = switch (pk_val) {
        .string => |s| s,
        else => "",
    };
    const path_val = root_obj.get("path") orelse .{ .string = "" };
    const path_str = switch (path_val) {
        .string => |s| s,
        else => "",
    };

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

test "loadKeystore: parses v4 scrypt keystore and returns NotImplemented" {
    const json =
        \\{"version":4,"uuid":"1234","description":"test","pubkey":"","path":"m/12381/3600/0/0/0","crypto":{"kdf":{"function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"ab0c7876052600dd703518d83ec67bf294ea5d3f08db28bfdb0028de58975843"},"message":""},"checksum":{"function":"sha256","message":"8a9f5d9912ed7ad069bee7d9f2571b500884c5cc8e29ef9ef18a5bd3e7b3ca71"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"cee418436f7c26a2d7bb61bf51e81d3a3f9f8be92e93fbf6d3cef1e0e8c0ba7b"}}}
    ;
    try testing.expectError(error.NotImplemented, loadKeystore(testing.allocator, json, "testpassword"));
}
