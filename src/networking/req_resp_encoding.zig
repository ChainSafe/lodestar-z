//! SSZ-Snappy req/resp wire encoding for the Ethereum consensus P2P protocol.
//!
//! Implements the encoding strategies defined in the consensus specs:
//! https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#encoding-strategies
//!
//! ## Wire format
//!
//! **Request:**
//! ```
//! <varint(len(ssz_bytes))> | <snappy_frame(ssz_bytes)>
//! ```
//!
//! **Response chunk:**
//! ```
//! <result_byte> | [<context_bytes>] | <varint(len(ssz_bytes))> | <snappy_frame(ssz_bytes)>
//! ```
//!
//! The `<context_bytes>` are a 4-byte fork digest, present only for fork-versioned response types.

const std = @import("std");
const testing = std.testing;
const snappy = @import("snappy").frame;
const varint = @import("varint.zig");
const protocol = @import("protocol.zig");

const ResponseCode = protocol.ResponseCode;

pub const EncodeError = snappy.CompressError;

/// Maximum allowed uncompressed size for a single req/resp message (10 MiB).
/// The consensus spec defines MAX_CHUNK_SIZE = 10 * 2^20.  We reject any
/// message whose declared SSZ length exceeds this limit, and we verify that
/// the decompressed output matches the declared length exactly.
pub const MAX_REQ_RESP_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

pub const DecodeError = varint.DecodeError || snappy.UncompressError || error{
    /// The result byte is not a known response code.
    InvalidResponseCode,
    /// The wire data is shorter than required.
    InsufficientData,
    /// Snappy decompression returned null (empty payload where data was expected).
    EmptyPayload,
    /// The declared SSZ length exceeds MAX_REQ_RESP_SIZE (10 MiB).
    /// Reject before decompressing to prevent memory exhaustion.
    PayloadTooLarge,
    /// The decompressed payload length does not match the declared SSZ length.
    /// Per spec, these must be equal (varint is an exact-size prefix).
    LengthMismatch,
};

/// Result of decoding a request from the wire.
pub const DecodedRequest = struct {
    ssz_bytes: []const u8,
    bytes_consumed: usize,
};

/// Result of decoding a response chunk from the wire.
pub const DecodedResponseChunk = struct {
    result: ResponseCode,
    context_bytes: ?[4]u8,
    ssz_bytes: []const u8,
    bytes_consumed: usize,
};

/// Encode a request payload for the wire.
///
/// Wire format: `<varint(len(ssz_bytes))> | <snappy_frame(ssz_bytes)>`
///
/// Caller owns the returned memory.
pub fn encodeRequest(
    allocator: std.mem.Allocator,
    ssz_bytes: []const u8,
) EncodeError![]u8 {
    // Encode the varint length prefix.
    var varint_buf: [varint.max_length]u8 = undefined;
    const varint_len = varint.encode(ssz_bytes.len, &varint_buf);

    // Compress the SSZ payload with Snappy framing.
    const compressed = try snappy.compress(allocator, ssz_bytes);
    defer allocator.free(compressed);

    // Concatenate varint + compressed payload.
    const total_len = varint_len + compressed.len;
    const result = try allocator.alloc(u8, total_len);
    @memcpy(result[0..varint_len], varint_buf[0..varint_len]);
    @memcpy(result[varint_len..], compressed);

    return result;
}

/// Decode a request payload from the wire.
///
/// Parses: `<varint(len(ssz_bytes))> | <snappy_frame(ssz_bytes)>`
///
/// Caller owns the returned `ssz_bytes`.
pub fn decodeRequest(
    allocator: std.mem.Allocator,
    wire_bytes: []const u8,
) DecodeError!DecodedRequest {
    // Decode the varint length prefix.
    const varint_result = try varint.decode(wire_bytes);
    const ssz_length = varint_result.value;

    // Reject obviously-oversized payloads before decompressing (decompression-bomb guard).
    if (ssz_length > MAX_REQ_RESP_SIZE) return DecodeError.PayloadTooLarge;

    const payload_start = varint_result.bytes_consumed;
    if (payload_start >= wire_bytes.len) {
        return DecodeError.InsufficientData;
    }

    // Decompress the Snappy-framed payload.
    const decompressed = try snappy.uncompress(allocator, wire_bytes[payload_start..]);
    const ssz_bytes = decompressed orelse return DecodeError.EmptyPayload;

    // Per spec, the varint is an exact-size prefix: decompressed length must equal ssz_length.
    if (ssz_bytes.len != ssz_length) {
        allocator.free(ssz_bytes);
        return DecodeError.LengthMismatch;
    }

    return .{
        .ssz_bytes = ssz_bytes,
        .bytes_consumed = wire_bytes.len,
    };
}

/// Encode a response chunk for the wire.
///
/// Wire format: `<result> | [<context_bytes>] | <varint(len(ssz_bytes))> | <snappy_frame(ssz_bytes)>`
///
/// If `context_bytes` is non-null, a 4-byte fork digest is included after the result byte.
/// For error responses, `ssz_bytes` should contain the UTF-8 error message.
///
/// Caller owns the returned memory.
pub fn encodeResponseChunk(
    allocator: std.mem.Allocator,
    result_code: ResponseCode,
    context_bytes: ?[4]u8,
    ssz_bytes: []const u8,
) EncodeError![]u8 {
    // Encode the varint length prefix.
    var varint_buf: [varint.max_length]u8 = undefined;
    const varint_len = varint.encode(ssz_bytes.len, &varint_buf);

    // Compress the SSZ payload with Snappy framing.
    const compressed = try snappy.compress(allocator, ssz_bytes);
    defer allocator.free(compressed);

    // Calculate total size: result(1) + context(0 or 4) + varint + compressed.
    const context_len: usize = if (context_bytes != null) 4 else 0;
    const total_len = 1 + context_len + varint_len + compressed.len;

    const buf = try allocator.alloc(u8, total_len);
    var offset: usize = 0;

    // Result byte.
    buf[offset] = @intFromEnum(result_code);
    offset += 1;

    // Context bytes (fork digest), if present.
    if (context_bytes) |ctx| {
        @memcpy(buf[offset .. offset + 4], &ctx);
        offset += 4;
    }

    // Varint length prefix.
    @memcpy(buf[offset .. offset + varint_len], varint_buf[0..varint_len]);
    offset += varint_len;

    // Compressed payload.
    @memcpy(buf[offset..], compressed);

    return buf;
}

/// Decode a response chunk from the wire.
///
/// Parses: `<result> | [<context_bytes>] | <varint(len(ssz_bytes))> | <snappy_frame(ssz_bytes)>`
///
/// `has_context_bytes` indicates whether this method's responses include fork digest context.
///
/// Caller owns the returned `ssz_bytes`.
pub fn decodeResponseChunk(
    allocator: std.mem.Allocator,
    wire_bytes: []const u8,
    has_context_bytes: bool,
) DecodeError!DecodedResponseChunk {
    if (wire_bytes.len == 0) {
        return DecodeError.InsufficientData;
    }

    var offset: usize = 0;

    // Parse result byte.
    const result_code = ResponseCode.fromByte(wire_bytes[offset]) orelse
        return DecodeError.InvalidResponseCode;
    offset += 1;

    // Parse context bytes if expected.
    var context_bytes: ?[4]u8 = null;
    if (has_context_bytes) {
        if (offset + 4 > wire_bytes.len) {
            return DecodeError.InsufficientData;
        }
        context_bytes = wire_bytes[offset..][0..4].*;
        offset += 4;
    }

    // Parse varint length prefix.
    if (offset >= wire_bytes.len) {
        return DecodeError.InsufficientData;
    }
    const varint_result = try varint.decode(wire_bytes[offset..]);
    offset += varint_result.bytes_consumed;

    // Decompress the Snappy-framed payload.
    // We must calculate the exact number of wire bytes consumed by the snappy
    // framing, since the input may contain data from subsequent response chunks.
    if (offset >= wire_bytes.len) {
        return DecodeError.InsufficientData;
    }
    const snappy_start = offset;
    const snappy_data = wire_bytes[snappy_start..];

    // Reject payloads that declare an oversized SSZ length before any decompression.
    if (varint_result.value > MAX_REQ_RESP_SIZE) return DecodeError.PayloadTooLarge;

    // Calculate snappy frame boundaries: identifier (10 bytes) + data chunks
    // Each chunk: type(1) + length(3) + payload(length)
    const snappy_consumed = calcSnappyFrameSize(snappy_data, varint_result.value) catch
        return DecodeError.InsufficientData;

    const decompressed = try snappy.uncompress(allocator, snappy_data[0..snappy_consumed]);
    const ssz_bytes = decompressed orelse return DecodeError.EmptyPayload;

    // Per spec, the varint is an exact-size prefix: decompressed length must equal declared length.
    if (ssz_bytes.len != varint_result.value) {
        allocator.free(ssz_bytes);
        return DecodeError.LengthMismatch;
    }

    return .{
        .result = result_code,
        .context_bytes = context_bytes,
        .ssz_bytes = ssz_bytes,
        .bytes_consumed = snappy_start + snappy_consumed,
    };
}

/// Calculate the total size of snappy-framed data for one logical message.
/// Walks the frame headers (identifier + data chunks) until enough uncompressed
/// bytes have been accounted for.
fn calcSnappyFrameSize(data: []const u8, expected_uncompressed: usize) !usize {
    const IDENTIFIER_SIZE = 10; // ff 06 00 00 73 4e 61 50 70 59
    if (data.len < IDENTIFIER_SIZE) return error.InsufficientData;

    // Verify stream identifier
    if (data[0] != 0xff or data[1] != 0x06 or data[2] != 0x00) {
        return error.InsufficientData;
    }

    var pos: usize = IDENTIFIER_SIZE;
    var uncompressed_so_far: usize = 0;

    while (pos + 4 <= data.len and uncompressed_so_far < expected_uncompressed) {
        const chunk_type = data[pos];
        const frame_size: usize = @intCast(std.mem.readInt(u24, data[pos + 1 ..][0..3], .little));

        if (pos + 4 + frame_size > data.len) {
            return error.InsufficientData;
        }

        switch (chunk_type) {
            0x00 => { // compressed
                // frame = crc(4) + compressed_data
                // We can't know the exact uncompressed size without decompressing,
                // so use a conservative estimate: frame payload minus the 4-byte checksum.
                // This keeps us walking all chunks until we've accounted for enough bytes.
                if (frame_size >= 4) {
                    uncompressed_so_far += frame_size - 4;
                }
            },
            0x01 => { // uncompressed
                // frame = crc(4) + raw_data
                if (frame_size >= 4) {
                    uncompressed_so_far += frame_size - 4;
                }
            },
            0xff => { // identifier (can repeat)
                // skip
            },
            else => {
                // skip (padding, etc.)
            },
        }

        pos += 4 + frame_size;
    }

    return pos;
}

// === Tests ===

test "encodeRequest and decodeRequest roundtrip" {
    const allocator = testing.allocator;

    // Simulate a StatusMessage SSZ payload (84 bytes).
    var ssz_payload: [84]u8 = undefined;
    for (&ssz_payload, 0..) |*byte, i| {
        byte.* = @truncate(i);
    }

    const encoded = try encodeRequest(allocator, &ssz_payload);
    defer allocator.free(encoded);

    // First byte(s) should be the varint of 84 (single byte since 84 < 128).
    try testing.expectEqual(@as(u8, 84), encoded[0]);

    const decoded = try decodeRequest(allocator, encoded);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqualSlices(u8, &ssz_payload, decoded.ssz_bytes);
}

test "encodeResponseChunk and decodeResponseChunk roundtrip without context bytes" {
    const allocator = testing.allocator;

    // A ping response: 8 bytes of SSZ (uint64).
    var ssz_payload = [_]u8{ 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    const encoded = try encodeResponseChunk(allocator, .success, null, &ssz_payload);
    defer allocator.free(encoded);

    // First byte should be 0x00 (success).
    try testing.expectEqual(@as(u8, 0x00), encoded[0]);

    const decoded = try decodeResponseChunk(allocator, encoded, false);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    try testing.expect(decoded.context_bytes == null);
    try testing.expectEqualSlices(u8, &ssz_payload, decoded.ssz_bytes);
}

test "encodeResponseChunk and decodeResponseChunk roundtrip with context bytes" {
    const allocator = testing.allocator;

    const fork_digest = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    // Some SSZ payload.
    var ssz_payload: [32]u8 = undefined;
    for (&ssz_payload, 0..) |*byte, i| {
        byte.* = @truncate(i * 7);
    }

    const encoded = try encodeResponseChunk(allocator, .success, fork_digest, &ssz_payload);
    defer allocator.free(encoded);

    // First byte: result code.
    try testing.expectEqual(@as(u8, 0x00), encoded[0]);
    // Next 4 bytes: fork digest.
    try testing.expectEqualSlices(u8, &fork_digest, encoded[1..5]);

    const decoded = try decodeResponseChunk(allocator, encoded, true);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    try testing.expect(decoded.context_bytes != null);
    try testing.expectEqualSlices(u8, &fork_digest, &decoded.context_bytes.?);
    try testing.expectEqualSlices(u8, &ssz_payload, decoded.ssz_bytes);
}

test "encodeResponseChunk with error response code" {
    const allocator = testing.allocator;

    const error_msg = "Invalid request parameters";
    const encoded = try encodeResponseChunk(allocator, .invalid_request, null, error_msg);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(u8, 0x01), encoded[0]);

    const decoded = try decodeResponseChunk(allocator, encoded, false);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.invalid_request, decoded.result);
    try testing.expectEqualSlices(u8, error_msg, decoded.ssz_bytes);
}

test "decodeResponseChunk with invalid response code" {
    const allocator = testing.allocator;
    const bad_wire = [_]u8{0xFF};
    try testing.expectError(
        DecodeError.InvalidResponseCode,
        decodeResponseChunk(allocator, &bad_wire, false),
    );
}

test "decodeRequest with empty input" {
    const allocator = testing.allocator;
    try testing.expectError(
        DecodeError.EndOfInput,
        decodeRequest(allocator, &[_]u8{}),
    );
}

test "decodeResponseChunk with empty input" {
    const allocator = testing.allocator;
    try testing.expectError(
        DecodeError.InsufficientData,
        decodeResponseChunk(allocator, &[_]u8{}, false),
    );
}

test "roundtrip with large payload" {
    const allocator = testing.allocator;

    // Simulate a larger payload (1024 bytes).
    var ssz_payload: [1024]u8 = undefined;
    for (&ssz_payload, 0..) |*byte, i| {
        byte.* = @truncate(i ^ (i >> 3));
    }

    const encoded = try encodeRequest(allocator, &ssz_payload);
    defer allocator.free(encoded);

    const decoded = try decodeRequest(allocator, encoded);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqualSlices(u8, &ssz_payload, decoded.ssz_bytes);
}


test "full wire encoding roundtrip with StatusMessage" {
    const messages = @import("messages.zig");
    const allocator = testing.allocator;

    const status: messages.StatusMessage.Type = .{
        .fork_digest = .{ 0x01, 0x02, 0x03, 0x04 },
        .finalized_root = [_]u8{0xAA} ** 32,
        .finalized_epoch = 100,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 200,
    };

    // SSZ serialize.
    var ssz_buf: [messages.StatusMessage.fixed_size]u8 = undefined;
    _ = messages.StatusMessage.serializeIntoBytes(&status, &ssz_buf);

    // Wire encode.
    const wire = try encodeRequest(allocator, &ssz_buf);
    defer allocator.free(wire);

    // Wire decode.
    const decoded_wire = try decodeRequest(allocator, wire);
    defer allocator.free(decoded_wire.ssz_bytes);

    // SSZ deserialize.
    var decoded_status: messages.StatusMessage.Type = undefined;
    try messages.StatusMessage.deserializeFromBytes(decoded_wire.ssz_bytes, &decoded_status);

    try testing.expectEqual(status.finalized_epoch, decoded_status.finalized_epoch);
    try testing.expectEqual(status.head_slot, decoded_status.head_slot);
    try testing.expectEqualSlices(u8, &status.fork_digest, &decoded_status.fork_digest);
}

test "full wire encoding roundtrip with Ping" {
    const messages = @import("messages.zig");
    const allocator = testing.allocator;

    const ping: messages.Ping.Type = 42;

    var ssz_buf: [messages.Ping.fixed_size]u8 = undefined;
    _ = messages.Ping.serializeIntoBytes(&ping, &ssz_buf);

    // Encode as response chunk without context bytes (ping has no context).
    const wire = try encodeResponseChunk(allocator, .success, null, &ssz_buf);
    defer allocator.free(wire);

    const decoded = try decodeResponseChunk(allocator, wire, false);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    try testing.expect(decoded.context_bytes == null);

    var decoded_ping: messages.Ping.Type = undefined;
    try messages.Ping.deserializeFromBytes(decoded.ssz_bytes, &decoded_ping);
    try testing.expectEqual(ping, decoded_ping);
}

test "response chunk roundtrip with context bytes and BeaconBlocksByRange" {
    const messages = @import("messages.zig");
    const allocator = testing.allocator;

    const request: messages.BeaconBlocksByRangeRequest.Type = .{
        .start_slot = 1000,
        .count = 64,
        .step = 1,
    };

    var ssz_buf: [messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &ssz_buf);

    // Response with context bytes (fork digest).
    const fork_digest = [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE };
    const wire = try encodeResponseChunk(allocator, .success, fork_digest, &ssz_buf);
    defer allocator.free(wire);

    const decoded = try decodeResponseChunk(allocator, wire, true);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    try testing.expectEqualSlices(u8, &fork_digest, &decoded.context_bytes.?);

    var decoded_req: messages.BeaconBlocksByRangeRequest.Type = undefined;
    try messages.BeaconBlocksByRangeRequest.deserializeFromBytes(decoded.ssz_bytes, &decoded_req);
    try testing.expectEqual(request.start_slot, decoded_req.start_slot);
    try testing.expectEqual(request.count, decoded_req.count);
    try testing.expectEqual(request.step, decoded_req.step);
}

/// Decode all response chunks from a complete response wire buffer.
///
/// Iterates through the wire bytes, decoding one chunk at a time until all
/// bytes are consumed. Stops early on the first non-success chunk.
///
/// Caller owns the returned slice and each `ssz_bytes` field within it.
/// Use `freeResponseChunks` to release all memory.
///
/// This is used by the outbound request API to parse responses from peers.
pub fn decodeResponseChunks(
    allocator: std.mem.Allocator,
    wire_bytes: []const u8,
    has_context_bytes: bool,
    has_multiple_responses: bool,
) ![]DecodedResponseChunk {
    var chunks: std.ArrayListUnmanaged(DecodedResponseChunk) = .empty;
    errdefer {
        for (chunks.items) |chunk| {
            allocator.free(chunk.ssz_bytes);
        }
        chunks.deinit(allocator);
    }

    var offset: usize = 0;
    while (offset < wire_bytes.len) {
        const chunk = try decodeResponseChunk(allocator, wire_bytes[offset..], has_context_bytes);
        offset += chunk.bytes_consumed;
        try chunks.append(allocator, chunk);

        // Single-response protocols (Status, Goodbye, Ping, Metadata) return
        // exactly one chunk. Stop after reading it.
        if (!has_multiple_responses) break;

        // Error responses terminate the stream.
        if (!chunk.result.isSuccess()) break;
    }

    return chunks.toOwnedSlice(allocator);
}

/// Free a slice of response chunks allocated by `decodeResponseChunks`.
///
/// Frees both the ssz_bytes within each chunk and the slice itself.
pub fn freeDecodedResponseChunks(allocator: std.mem.Allocator, chunks: []DecodedResponseChunk) void {
    for (chunks) |chunk| {
        allocator.free(chunk.ssz_bytes);
    }
    allocator.free(chunks);
}

test "decodeRequest rejects declared length > MAX_REQ_RESP_SIZE" {
    const allocator = testing.allocator;

    // Craft a varint that declares MAX_REQ_RESP_SIZE + 1 bytes, followed by a minimal
    // valid snappy stream (the actual content doesn't matter — we reject before decompressing).
    var varint_buf: [varint.max_length]u8 = undefined;
    const varint_len = varint.encode(MAX_REQ_RESP_SIZE + 1, &varint_buf);

    // We need some placeholder bytes after the varint so `payload_start < wire_bytes.len`.
    // Use a dummy byte; decodeRequest rejects on length before calling snappy.
    var wire: [varint.max_length + 1]u8 = undefined;
    @memcpy(wire[0..varint_len], varint_buf[0..varint_len]);
    wire[varint_len] = 0xFF; // padding — never reached

    const result = decodeRequest(allocator, wire[0 .. varint_len + 1]);
    try testing.expectError(DecodeError.PayloadTooLarge, result);
}

test "decodeRequest detects length mismatch" {
    const allocator = testing.allocator;

    // Encode a 4-byte payload but declare 8 bytes in the varint.
    const real_payload = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    // Compress the 4-byte payload.
    const compressed = try snappy.compress(allocator, &real_payload);
    defer allocator.free(compressed);

    // Build wire bytes: varint(8) + snappy(4 bytes of real data).
    var varint_buf: [varint.max_length]u8 = undefined;
    const varint_len = varint.encode(8, &varint_buf); // declares 8 bytes

    const wire = try allocator.alloc(u8, varint_len + compressed.len);
    defer allocator.free(wire);
    @memcpy(wire[0..varint_len], varint_buf[0..varint_len]);
    @memcpy(wire[varint_len..], compressed);

    const result = decodeRequest(allocator, wire);
    try testing.expectError(DecodeError.LengthMismatch, result);
}
