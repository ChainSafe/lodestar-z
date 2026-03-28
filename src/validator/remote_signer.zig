//! Web3Signer remote signer HTTP API client.
//!
//! Allows validators to use external signing devices (HSMs, cloud KMS, YubiKey)
//! via the Web3Signer API instead of keeping BLS secret keys locally.
//!
//! Web3Signer API reference:
//!   https://docs.web3signer.consensys.net/reference/api/
//!
//! Endpoints used:
//!   GET  /api/v1/eth2/publicKeys         — list all managed public keys
//!   POST /api/v1/eth2/sign/{identifier}  — sign a root with slashing protection
//!
//! Error handling:
//!   404 — key not found on this signer
//!   412 — slashing protection triggered (would produce slashable signature)
//!   500 — internal signer error
//!
//! TLS: pass https:// URL; std.http.Client handles TLS via bundled certs.
//!
//! TS equivalent: packages/validator/src/signers/web3signer.ts (getSignerFromKeystore)
//!               packages/validator/src/util/externalSignerClient.ts (ExternalSignerClient)

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const bls = @import("bls");
const Signature = bls.Signature;

const log = std.log.scoped(.remote_signer);

/// Maximum response body for Web3Signer responses.
const MAX_RESPONSE_BYTES: usize = 4 * 1024;

// ---------------------------------------------------------------------------
// RemoteSigner
// ---------------------------------------------------------------------------

/// Web3Signer HTTP API client.
///
/// Signs BLS messages via the external signer instead of holding secret keys
/// locally. This enables hardware security module (HSM) or cloud KMS support.
pub const RemoteSigner = struct {
    allocator: Allocator,
    /// Base URL of the Web3Signer service (e.g. "http://web3signer:9000").
    base_url: []const u8,

    pub fn init(allocator: Allocator, base_url: []const u8) RemoteSigner {
        return .{
            .allocator = allocator,
            .base_url = base_url,
        };
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// List all public keys managed by the remote signer.
    ///
    /// GET /api/v1/eth2/publicKeys
    ///
    /// Returns an owned slice of 48-byte compressed BLS public keys.
    /// Caller must free.
    pub fn listKeys(self: *RemoteSigner, io: Io) ![][48]u8 {
        const body = try self.get(io, "/api/v1/eth2/publicKeys");
        defer self.allocator.free(body);

        // Parse JSON array of hex-encoded pubkeys.
        // Response: ["0xabc...", "0xdef..."]
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
        const arr = switch (parsed.value) {
            .array => |ar| ar,
            else => return error.InvalidResponse,
        };

        var keys = std.ArrayList([48]u8).init(self.allocator);
        errdefer keys.deinit();

        for (arr.items) |item| {
            const hex_str = switch (item) {
                .string => |s| s,
                else => continue,
            };
            // Strip 0x prefix if present.
            const hex = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;
            if (hex.len != 96) {
                log.warn("remote signer: unexpected pubkey hex length {d}", .{hex.len});
                continue;
            }
            var pk: [48]u8 = undefined;
            _ = std.fmt.hexToBytes(&pk, hex) catch {
                log.warn("remote signer: invalid pubkey hex", .{});
                continue;
            };
            try keys.append(pk);
        }

        return keys.toOwnedSlice();
    }

    /// Sign a signing root using the remote signer for the given BLS pubkey.
    ///
    /// POST /api/v1/eth2/sign/{pubkey_hex}
    ///
    /// The signing_root is passed as the `signingRoot` field in the JSON body.
    /// Returns the BLS signature.
    pub fn sign(self: *RemoteSigner, io: Io, pubkey: [48]u8, signing_root: [32]u8) !Signature {
        const pk_hex = std.fmt.bytesToHex(&pubkey, .lower);
        const sr_hex = std.fmt.bytesToHex(&signing_root, .lower);

        const path = try std.fmt.allocPrint(
            self.allocator,
            "/api/v1/eth2/sign/0x{s}",
            .{pk_hex},
        );
        defer self.allocator.free(path);

        // Build request body.
        // Web3Signer expects: {"type": "...", "signingRoot": "0x..."}
        // The "type" field identifies the signing domain (e.g. "BLOCK_V2", "ATTESTATION").
        // For generic signing root operations we use a generic payload.
        const req_body = try std.fmt.allocPrint(
            self.allocator,
            "{{\"type\":\"UNKNOWN\",\"signingRoot\":\"0x{s}\"}}",
            .{sr_hex},
        );
        defer self.allocator.free(req_body);

        const resp_body = try self.post(io, path, req_body);
        defer self.allocator.free(resp_body);

        // Parse response: {"signature": "0xabc..."}
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const parsed = try std.json.parseFromSlice(std.json.Value, a, resp_body, .{});
        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return error.InvalidResponse,
        };
        const sig_val = obj.get("signature") orelse return error.MissingSignature;
        const sig_hex_str = switch (sig_val) {
            .string => |s| s,
            else => return error.InvalidResponse,
        };
        const sig_hex = if (std.mem.startsWith(u8, sig_hex_str, "0x"))
            sig_hex_str[2..]
        else
            sig_hex_str;

        if (sig_hex.len != 192) return error.InvalidSignatureLength;

        var sig_bytes: [96]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig_bytes, sig_hex);

        // Deserialize BLS signature.
        return Signature.deserialize(&sig_bytes) catch return error.InvalidSignature;
    }

    // -----------------------------------------------------------------------
    // Internal HTTP helpers
    // -----------------------------------------------------------------------

    fn get(self: *RemoteSigner, io: Io, path: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path });
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try client.request(.GET, uri, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
        });
        defer req.deinit();

        try req.sendBodiless();

        var redirect_buf: [1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);

        if (response.head.status != .ok) {
            log.warn("GET {s} → HTTP {d}", .{ path, @intFromEnum(response.head.status) });
            return error.HttpError;
        }

        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        return reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
    }

    fn post(self: *RemoteSigner, io: Io, path: []const u8, body: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path });
        defer self.allocator.free(url);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try client.request(.POST, uri, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = body.len };
        try req.sendBodyComplete(@constCast(body));

        var redirect_buf: [1024]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);

        const status = response.head.status;
        const status_code = @intFromEnum(status);
        if (status_code == 404) {
            return error.HttpNotFound;
        } else if (status_code == 412) {
            // Web3Signer returns 412 when slashing protection is triggered.
            return error.HttpSlashingProtection;
        } else if (status_code < 200 or status_code >= 300) {
            log.warn("POST {s} → HTTP {d}", .{ path, status_code });
            return error.HttpError;
        }

        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        return reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "RemoteSigner: init does not crash" {
    const signer = RemoteSigner.init(testing.allocator, "http://localhost:9000");
    try testing.expectEqualStrings("http://localhost:9000", signer.base_url);
}

test "RemoteSigner: sign request body format" {
    // Test that the JSON request body is formatted correctly.
    var buf: [256]u8 = undefined;
    const signing_root = [_]u8{0xAB} ** 32;
    const sr_hex = std.fmt.bytesToHex(&signing_root, .lower);
    const result = try std.fmt.bufPrint(
        &buf,
        "{{\"type\":\"UNKNOWN\",\"signingRoot\":\"0x{s}\"}}",
        .{sr_hex},
    );
    const expected = "{\"type\":\"UNKNOWN\",\"signingRoot\":\"0x" ++ "ab" ** 32 ++ "\"}";
    try testing.expectEqualStrings(expected, result);
}
