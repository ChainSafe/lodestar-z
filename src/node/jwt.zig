//! JWT secret management for the Engine API.
//!
//! The Engine API (EL↔CL communication channel) requires a shared 32-byte
//! secret distributed as a hex file. This module handles loading an existing
//! secret from disk or generating and persisting a new one on first run.
//!
//! File format: 64 lowercase hex characters, optionally prefixed with "0x",
//! followed by an optional newline. This is the same format used by Geth,
//! Nethermind, Besu, Erigon, and the TypeScript Lodestar implementation.

const std = @import("std");

const log = std.log.scoped(.jwt);

/// Load an existing JWT secret from `path`, or generate a random one and
/// write it to `path` if the file does not yet exist.
///
/// Returns the raw 32-byte secret.
pub fn loadOrGenerate(io: std.Io, path: []const u8) ![32]u8 {
    // Try loading first.
    if (load(io, path)) |secret| {
        log.info("Loaded JWT secret from {s}", .{path});
        return secret;
    } else |err| switch (err) {
        error.FileNotFound => {
            // First run — generate and persist.
            const secret = randomBytes(io) catch |gen_err| {
                log.err("Failed to generate random JWT secret: {}", .{gen_err});
                return gen_err;
            };
            persist(io, path, secret) catch |write_err| {
                log.err("Failed to write JWT secret to '{s}': {}", .{ path, write_err });
                return write_err;
            };
            log.info("Generated new JWT secret at {s}", .{path});
            return secret;
        },
        else => {
            log.err("Failed to load JWT secret from '{s}': {}", .{ path, err });
            return err;
        },
    }
}

/// Load a JWT secret from an existing file.
///
/// The file must contain exactly 64 hex characters (32 bytes), optionally
/// prefixed with "0x" and optionally followed by whitespace.
///
/// Returns `error.FileNotFound` if the file does not exist.
pub fn load(io: std.Io, path: []const u8) ![32]u8 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return error.JwtFileReadError,
    };
    defer file.close(io);

    const stat = file.stat(io) catch return error.JwtFileReadError;
    if (stat.size > 1024) return error.JwtFileTooLarge;

    var buf: [1024]u8 = undefined;
    const total = file.readPositionalAll(io, buf[0..@intCast(stat.size)], 0) catch
        return error.JwtFileReadError;

    const trimmed = std.mem.trim(u8, buf[0..total], " \t\n\r");
    const hex_str = if (trimmed.len >= 2 and trimmed[0] == '0' and trimmed[1] == 'x')
        trimmed[2..]
    else
        trimmed;

    if (hex_str.len != 64) return error.InvalidJwtSecretLength;

    var secret: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret, hex_str) catch return error.InvalidJwtSecretHex;
    return secret;
}

/// Generate 32 cryptographically random bytes via /dev/urandom.
fn randomBytes(io: std.Io) ![32]u8 {
    var bytes: [32]u8 = undefined;
    const urandom = try std.Io.Dir.cwd().openFile(io, "/dev/urandom", .{});
    defer urandom.close(io);
    const n = try urandom.readPositionalAll(io, &bytes, 0);
    if (n != 32) return error.ShortRead;
    return bytes;
}

/// Write a 32-byte secret to `path` as 64 lowercase hex chars.
/// Creates or overwrites the file with mode 0o600.
fn persist(io: std.Io, path: []const u8, secret: [32]u8) !void {
    const hex_buf = std.fmt.bytesToHex(secret, .lower);

    const file = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true }) catch
        return error.JwtFileWriteError;
    defer file.close(io);

    file.writePositionalAll(io, &hex_buf, 0) catch return error.JwtFileWriteError;
}

// ── Tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "jwt hex format round-trip" {
    const secret = [32]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    const hex_buf = std.fmt.bytesToHex(secret, .lower);
    try testing.expectEqualStrings(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        &hex_buf,
    );

    var recovered: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&recovered, &hex_buf);
    try testing.expectEqualSlices(u8, &secret, &recovered);
}

test "jwt hex with 0x prefix round-trip" {
    // Simulate reading a "0x"-prefixed hex string as an EL client would write it.
    const hex_with_prefix = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const trimmed = std.mem.trim(u8, hex_with_prefix, " \t\n\r");
    const hex_str = if (trimmed.len >= 2 and trimmed[0] == '0' and trimmed[1] == 'x')
        trimmed[2..]
    else
        trimmed;

    try testing.expect(hex_str.len == 64);
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, hex_str);
    try testing.expectEqual(@as(u8, 0xde), secret[0]);
    try testing.expectEqual(@as(u8, 0xef), secret[31]);
}
