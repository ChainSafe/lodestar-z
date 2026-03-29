//! Keymanager API bearer token authentication.
//!
//! The Keymanager API (EIP-3042) requires a separate bearer token from the
//! Engine API JWT. The token is either loaded from a file or auto-generated
//! on first startup, then persisted.
//!
//! Token file location: <data-dir>/validator/api-token.txt
//!
//! References:
//!   https://ethereum.github.io/keymanager-APIs/#section/Authentication
//!   https://github.com/ChainSafe/lodestar/blob/unstable/packages/validator/src/api/impl/keymanager/server.ts
//!
//! TS equivalent: packages/validator/src/api/impl/keymanager/server.ts (getApiToken)

const std = @import("std");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.keymanager_auth);

/// Token length in bytes (generates 32 random bytes → 64 hex chars).
const TOKEN_BYTES = 32;

/// Keymanager API bearer token authenticator.
pub const KeymanagerAuth = struct {
    allocator: Allocator,
    /// The bearer token (hex string, owned).
    token: []const u8,

    /// Initialize with a given token (takes ownership).
    pub fn initWithToken(allocator: Allocator, token: []const u8) KeymanagerAuth {
        return .{ .allocator = allocator, .token = token };
    }

    /// Free the token.
    pub fn deinit(self: *KeymanagerAuth) void {
        self.allocator.free(self.token);
    }

    /// Load token from file, or generate and persist it if absent.
    ///
    /// TS: getApiToken(tokenFilepath)
    pub fn loadOrGenerate(allocator: Allocator, path: []const u8) !KeymanagerAuth {
        const token = loadToken(allocator, path) catch |err| switch (err) {
            error.FileNotFound => {
                log.info("Keymanager API token not found, generating new token at {s}", .{path});
                const new_token = try generateToken(allocator, path);
                return .{ .allocator = allocator, .token = new_token };
            },
            else => return err,
        };
        log.info("Loaded Keymanager API token from {s}", .{path});
        return .{ .allocator = allocator, .token = token };
    }

    /// Validate a bearer token from an Authorization header.
    ///
    /// Expected format: "Bearer <token>"
    /// Returns error.Unauthorized if the header is missing or the token doesn't match.
    pub fn validateRequest(self: KeymanagerAuth, auth_header: ?[]const u8) !void {
        const header = auth_header orelse return error.Unauthorized;
        const prefix = "Bearer ";
        if (!std.mem.startsWith(u8, header, prefix)) return error.Unauthorized;
        const provided_token = header[prefix.len..];
        // Use constant-time comparison to prevent timing attacks.
        if (provided_token.len != self.token.len) return error.Unauthorized;
        if (!std.mem.eql(u8, provided_token, self.token)) {
            return error.Unauthorized;
        }
    }

    /// Generate a random token, persist to file, and return it.
    ///
    /// The token is 32 random bytes encoded as a 64-char hex string.
    /// Creates parent directories if needed.
    pub fn generateToken(allocator: Allocator, path: []const u8) ![]const u8 {
        var random_bytes: [TOKEN_BYTES]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        const token = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&random_bytes)});
        errdefer allocator.free(token);

        // Create parent directory if needed.
        if (std.fs.path.dirname(path)) |dir_path| {
            std.fs.makeDirAbsolute(dir_path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        // Write token to file.
        const file = try std.fs.createFileAbsolute(path, .{ .exclusive = false });
        defer file.close();
        try file.writeAll(token);
        try file.writeAll("\n");

        log.debug("generated Keymanager API token (length={d})", .{token.len});
        return token;
    }

    /// Load token from file.
    ///
    /// Trims trailing whitespace/newlines.
    pub fn loadToken(allocator: Allocator, path: []const u8) ![]const u8 {
        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();

        const raw = try file.readToEndAlloc(allocator, 4096);
        errdefer allocator.free(raw);

        const trimmed = std.mem.trimRight(u8, raw, &[_]u8{ '\n', '\r', ' ', '\t' });
        if (trimmed.len == 0) return error.EmptyToken;

        if (trimmed.len < raw.len) {
            defer allocator.free(raw);
            return allocator.dupe(u8, trimmed);
        }
        return raw;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "KeymanagerAuth.validateRequest: valid token" {
    var auth = KeymanagerAuth.initWithToken(testing.allocator, try testing.allocator.dupe(u8, "deadbeef"));
    defer auth.deinit();

    try auth.validateRequest("Bearer deadbeef");
}

test "KeymanagerAuth.validateRequest: wrong token returns Unauthorized" {
    var auth = KeymanagerAuth.initWithToken(testing.allocator, try testing.allocator.dupe(u8, "deadbeef"));
    defer auth.deinit();

    try testing.expectError(error.Unauthorized, auth.validateRequest("Bearer wrongtoken"));
}

test "KeymanagerAuth.validateRequest: missing header returns Unauthorized" {
    var auth = KeymanagerAuth.initWithToken(testing.allocator, try testing.allocator.dupe(u8, "deadbeef"));
    defer auth.deinit();

    try testing.expectError(error.Unauthorized, auth.validateRequest(null));
}

test "KeymanagerAuth.validateRequest: missing Bearer prefix returns Unauthorized" {
    var auth = KeymanagerAuth.initWithToken(testing.allocator, try testing.allocator.dupe(u8, "deadbeef"));
    defer auth.deinit();

    try testing.expectError(error.Unauthorized, auth.validateRequest("Token deadbeef"));
}

test "KeymanagerAuth: generateToken and loadToken roundtrip" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    const token_path = try std.fs.path.join(testing.allocator, &.{ tmp_path, "api-token.txt" });
    defer testing.allocator.free(token_path);

    const generated = try KeymanagerAuth.generateToken(testing.allocator, token_path);
    defer testing.allocator.free(generated);

    try testing.expectEqual(@as(usize, TOKEN_BYTES * 2), generated.len);

    const loaded = try KeymanagerAuth.loadToken(testing.allocator, token_path);
    defer testing.allocator.free(loaded);

    try testing.expectEqualStrings(generated, loaded);
}
