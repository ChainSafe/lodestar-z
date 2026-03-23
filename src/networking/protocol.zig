//! Eth2 req/resp protocol definitions.
//!
//! Defines response codes, protocol methods, and protocol ID string generation
//! as specified in the Ethereum consensus P2P interface.
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md

const std = @import("std");
const testing = std.testing;

/// Result code for response chunks.
///
/// The first byte of each response chunk indicates the status:
/// - 0x00: Success — a normal response.
/// - 0x01: InvalidRequest — the request was malformed.
/// - 0x02: ServerError — the server encountered an internal error.
/// - 0x03: ResourceUnavailable — the requested resource is not available.
pub const ResponseCode = enum(u8) {
    success = 0x00,
    invalid_request = 0x01,
    server_error = 0x02,
    resource_unavailable = 0x03,

    /// Returns true if this response code indicates a successful response.
    pub fn isSuccess(self: ResponseCode) bool {
        return self == .success;
    }

    /// Convert a raw byte to a ResponseCode, returning null for unknown values.
    pub fn fromByte(byte: u8) ?ResponseCode {
        return switch (byte) {
            0x00 => .success,
            0x01 => .invalid_request,
            0x02 => .server_error,
            0x03 => .resource_unavailable,
            else => null,
        };
    }
};

/// The encoding used for the wire protocol.
pub const Encoding = enum {
    ssz_snappy,

    /// Returns the encoding suffix for protocol ID strings.
    pub fn suffix(self: Encoding) []const u8 {
        return switch (self) {
            .ssz_snappy => "ssz_snappy",
        };
    }
};

/// Req/resp protocol methods.
///
/// Each method corresponds to a distinct request/response protocol
/// with its own message types and semantics.
pub const Method = enum {
    status,
    goodbye,
    beacon_blocks_by_range,
    beacon_blocks_by_root,
    blob_sidecars_by_range,
    blob_sidecars_by_root,
    ping,
    metadata,
    light_client_bootstrap,
    light_client_updates_by_range,
    light_client_finality_update,
    light_client_optimistic_update,

    /// Returns the method name as used in protocol ID strings.
    pub fn name(self: Method) []const u8 {
        return switch (self) {
            .status => "status",
            .goodbye => "goodbye",
            .beacon_blocks_by_range => "beacon_blocks_by_range",
            .beacon_blocks_by_root => "beacon_blocks_by_root",
            .blob_sidecars_by_range => "blob_sidecars_by_range",
            .blob_sidecars_by_root => "blob_sidecars_by_root",
            .ping => "ping",
            .metadata => "metadata",
            .light_client_bootstrap => "light_client_bootstrap",
            .light_client_updates_by_range => "light_client_updates_by_range",
            .light_client_finality_update => "light_client_finality_update",
            .light_client_optimistic_update => "light_client_optimistic_update",
        };
    }

    /// Returns the protocol version number for this method.
    pub fn version(self: Method) u8 {
        return switch (self) {
            .beacon_blocks_by_range => 2,
            .beacon_blocks_by_root => 2,
            else => 1,
        };
    }

    /// Returns true if response chunks for this method include context bytes (fork digest).
    ///
    /// Context bytes are present for methods that return fork-versioned types.
    /// Methods returning single, non-versioned types omit context bytes.
    pub fn hasContextBytes(self: Method) bool {
        return switch (self) {
            .beacon_blocks_by_range,
            .beacon_blocks_by_root,
            .blob_sidecars_by_range,
            .blob_sidecars_by_root,
            .light_client_bootstrap,
            .light_client_updates_by_range,
            .light_client_finality_update,
            .light_client_optimistic_update,
            => true,
            .status,
            .goodbye,
            .ping,
            .metadata,
            => false,
        };
    }

    /// Returns true if this method can return multiple response chunks.
    pub fn hasMultipleResponses(self: Method) bool {
        return switch (self) {
            .beacon_blocks_by_range,
            .beacon_blocks_by_root,
            .blob_sidecars_by_range,
            .blob_sidecars_by_root,
            .light_client_updates_by_range,
            => true,
            .status,
            .goodbye,
            .ping,
            .metadata,
            .light_client_bootstrap,
            .light_client_finality_update,
            .light_client_optimistic_update,
            => false,
        };
    }
};

/// The protocol prefix used in all eth2 protocol IDs.
pub const protocol_prefix = "/eth2/beacon_chain/req";

/// Context bytes length (fork digest).
pub const context_bytes_length: usize = 4;

/// Format a protocol ID string.
///
/// The format is: `/eth2/beacon_chain/req/<method>/<version>/<encoding>`
/// For example: `/eth2/beacon_chain/req/status/1/ssz_snappy`
pub fn protocolId(
    buf: []u8,
    method: Method,
    encoding: Encoding,
) []const u8 {
    const result = std.fmt.bufPrint(buf, "{s}/{s}/{d}/{s}", .{
        protocol_prefix,
        method.name(),
        method.version(),
        encoding.suffix(),
    }) catch unreachable;
    return result;
}

// === Tests ===

test "ResponseCode byte values" {
    try testing.expectEqual(@as(u8, 0x00), @intFromEnum(ResponseCode.success));
    try testing.expectEqual(@as(u8, 0x01), @intFromEnum(ResponseCode.invalid_request));
    try testing.expectEqual(@as(u8, 0x02), @intFromEnum(ResponseCode.server_error));
    try testing.expectEqual(@as(u8, 0x03), @intFromEnum(ResponseCode.resource_unavailable));
}

test "ResponseCode.fromByte" {
    try testing.expectEqual(ResponseCode.success, ResponseCode.fromByte(0x00).?);
    try testing.expectEqual(ResponseCode.server_error, ResponseCode.fromByte(0x02).?);
    try testing.expect(ResponseCode.fromByte(0xFF) == null);
}

test "ResponseCode.isSuccess" {
    try testing.expect(ResponseCode.success.isSuccess());
    try testing.expect(!ResponseCode.invalid_request.isSuccess());
    try testing.expect(!ResponseCode.server_error.isSuccess());
    try testing.expect(!ResponseCode.resource_unavailable.isSuccess());
}

test "Method.hasContextBytes" {
    try testing.expect(!Method.status.hasContextBytes());
    try testing.expect(!Method.goodbye.hasContextBytes());
    try testing.expect(!Method.ping.hasContextBytes());
    try testing.expect(!Method.metadata.hasContextBytes());
    try testing.expect(Method.beacon_blocks_by_range.hasContextBytes());
    try testing.expect(Method.beacon_blocks_by_root.hasContextBytes());
    try testing.expect(Method.blob_sidecars_by_range.hasContextBytes());
    try testing.expect(Method.blob_sidecars_by_root.hasContextBytes());
}

test "protocolId formatting" {
    var buf: [128]u8 = undefined;
    const id = protocolId(&buf, .status, .ssz_snappy);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/status/1/ssz_snappy", id);

    const id2 = protocolId(&buf, .beacon_blocks_by_range, .ssz_snappy);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy", id2);
}
