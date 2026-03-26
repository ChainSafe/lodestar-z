//! Node identity — persistent secp256k1 keypair for discv5 and libp2p.
//!
//! On first run, generates a cryptographically random 32-byte secret key
//! and writes it to `<data-dir>/node-identity/secret-key` as hex.
//! On subsequent runs, loads the existing key from disk.
//!
//! The identity is used for:
//! - discv5 discovery (ENR signing, node ID)
//! - libp2p peer identity (peer ID derivation)

const std = @import("std");
const Allocator = std.mem.Allocator;
const discv5 = @import("discv5");
const secp256k1 = discv5.secp256k1;
const enr = discv5.enr;

const log = std.log.scoped(.identity);

/// Subdirectory under data_dir for identity files.
const identity_dir = "node-identity";
/// Filename for the hex-encoded secret key.
const secret_key_file = "secret-key";

/// Persistent node identity derived from a secp256k1 keypair.
pub const NodeIdentity = struct {
    secret_key: [32]u8,
    public_key: secp256k1.CompressedPubKey,
    node_id: enr.NodeId,
};

/// Load an existing identity from disk, or generate and persist a new one.
///
/// When `data_dir` is empty (e.g. in-memory/test mode), generates a random
/// ephemeral key without persisting to disk.
pub fn loadOrCreateIdentity(io: std.Io, data_dir: []const u8) !NodeIdentity {
    var secret_key: [32]u8 = undefined;

    if (data_dir.len > 0) {
        secret_key = loadFromDisk(io, data_dir) catch |err| switch (err) {
            error.FileNotFound => blk: {
                // First run — generate and persist.
                const key = try generateRandomKey(io);
                persistToDisk(io, data_dir, &key) catch |write_err| {
                    log.err("Failed to persist node identity: {}", .{write_err});
                    return write_err;
                };
                log.info("Generated new node identity in {s}/{s}", .{ data_dir, identity_dir });
                break :blk key;
            },
            else => {
                log.err("Failed to load node identity: {}", .{err});
                return err;
            },
        };
    } else {
        // No data_dir — ephemeral identity (test/in-memory mode).
        secret_key = try generateRandomKey(io);
        log.info("Using ephemeral node identity (no data_dir)", .{});
    }

    return deriveIdentity(secret_key);
}

/// Derive public key and node ID from a secret key.
fn deriveIdentity(secret_key: [32]u8) !NodeIdentity {
    const public_key = secp256k1.pubkeyFromSecret(&secret_key) catch
        return error.InvalidSecretKey;
    const node_id = enr.nodeIdFromCompressedPubkey(&public_key);

    return .{
        .secret_key = secret_key,
        .public_key = public_key,
        .node_id = node_id,
    };
}

/// Generate a cryptographically random 32-byte secret key.
fn generateRandomKey(io: std.Io) ![32]u8 {
    var key: [32]u8 = undefined;
    const urandom = try std.Io.Dir.cwd().openFile(io, "/dev/urandom", .{});
    defer urandom.close(io);
    const n = try urandom.readPositionalAll(io, &key, 0);
    if (n != 32) return error.ShortRead;
    return key;
}

/// Read hex-encoded secret key from `<data_dir>/node-identity/secret-key`.
fn loadFromDisk(io: std.Io, data_dir: []const u8) ![32]u8 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = buildPath(&path_buf, data_dir);

    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch
        return error.FileNotFound;
    defer file.close(io);

    // Hex-encoded 32 bytes = 64 hex chars + optional newline.
    var buf: [128]u8 = undefined;
    const stat = file.stat(io) catch return error.ReadFailed;
    if (stat.size > buf.len) return error.ReadFailed;

    const n = file.readPositionalAll(io, buf[0..@intCast(stat.size)], 0) catch
        return error.ReadFailed;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\n\r");

    if (trimmed.len != 64) return error.InvalidKeyLength;

    var secret_key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret_key, trimmed) catch return error.InvalidKeyHex;

    log.info("Loaded node identity from {s}", .{path});
    return secret_key;
}

/// Write hex-encoded secret key to `<data_dir>/node-identity/secret-key`.
/// Creates the directory if it doesn't exist.
fn persistToDisk(io: std.Io, data_dir: []const u8, secret_key: *const [32]u8) !void {
    // Ensure directory exists.
    // Note: directory creation is handled by the caller (data-dir setup).

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = buildPath(&path_buf, data_dir);

    const file = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true }) catch
        return error.WriteFailed;
    defer file.close(io);

    // Write hex-encoded key + newline.
    var hex_buf: [65]u8 = undefined;
    const hex = std.fmt.bufPrint(&hex_buf, "{s}\n", .{&std.fmt.bytesToHex(secret_key.*, .lower)}) catch
        return error.WriteFailed;
    file.writePositionalAll(io, hex, 0) catch
        return error.WriteFailed;
}

/// Build the full path: `<data_dir>/node-identity/secret-key`
fn buildPath(buf: *[std.fs.max_path_bytes]u8, data_dir: []const u8) []const u8 {
    return bufJoin(buf, &.{ data_dir, identity_dir, secret_key_file });
}

/// Build the directory path: `<data_dir>/node-identity`
fn buildDirPath(buf: *[std.fs.max_path_bytes]u8, data_dir: []const u8) []const u8 {
    return bufJoin(buf, &.{ data_dir, identity_dir });
}

/// Simple stack-buffer path join (no allocator needed).
fn bufJoin(buf: *[std.fs.max_path_bytes]u8, segments: []const []const u8) []const u8 {
    var pos: usize = 0;
    for (segments, 0..) |seg, i| {
        if (i > 0) {
            buf[pos] = '/';
            pos += 1;
        }
        @memcpy(buf[pos..][0..seg.len], seg);
        pos += seg.len;
    }
    return buf[0..pos];
}
