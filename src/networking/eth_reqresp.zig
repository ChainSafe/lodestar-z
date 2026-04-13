//! Ethereum req/resp adapter — bridges eth-p2p-z's stream protocol to the
//! Ethereum consensus req/resp handler layer.
//!
//! This adapter translates between raw wire bytes (varint + snappy-compressed SSZ)
//! and our typed request/response handlers. It can be used as the handler for
//! incoming streams from the Switch, and also provides `sendRequest` for
//! outbound requests.
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const protocol = @import("protocol.zig");
const messages = @import("messages.zig");
const req_resp_encoding = @import("req_resp_encoding.zig");
const req_resp_handler = @import("req_resp_handler.zig");
const ForkSeq = @import("config").ForkSeq;

const Method = protocol.Method;
const ResponseCode = protocol.ResponseCode;
const ReqRespContext = req_resp_handler.ReqRespContext;
const ResponseChunk = req_resp_handler.ResponseChunk;
const PayloadSink = req_resp_handler.PayloadSink;

const log = std.log.scoped(.eth_reqresp);

/// Bridges eth-p2p-z's stream protocol to the Ethereum req/resp handlers.
///
/// On the inbound side: parses the protocol ID to determine the method,
/// decodes the request from the wire, routes to the handler, and encodes
/// the response chunks back to wire format.
///
/// On the outbound side: encodes a request for the wire so the caller
/// can send it via a libp2p stream.
pub const EthReqRespAdapter = struct {
    const Self = @This();

    context: *const ReqRespContext,
    allocator: Allocator,

    pub fn init(allocator: Allocator, context: *const ReqRespContext) Self {
        return .{
            .allocator = allocator,
            .context = context,
        };
    }

    /// Handle an incoming req/resp stream.
    ///
    /// This is the function that would be called by the Switch when a peer
    /// opens a stream with an Ethereum protocol ID (e.g.,
    /// `/eth2/beacon_chain/req/status/1/ssz_snappy`).
    ///
    /// Steps:
    /// 1. Parse protocol_id → Method
    /// 2. Decode request bytes (varint + snappy decompress)
    /// 3. Route to the appropriate handler
    /// 4. Encode response chunks (result byte + context + varint + snappy)
    /// 5. Return concatenated wire bytes
    ///
    /// Caller owns the returned bytes.
    pub fn handleStream(
        self: *Self,
        protocol_id: []const u8,
        request_wire_bytes: []const u8,
    ) HandleError![]const u8 {
        // 1. Parse protocol ID → Method.
        const info = protocol.parseProtocolIdInfo(protocol_id) orelse {
            log.debug("Unknown protocol ID: {s}", .{protocol_id});
            return error.UnknownProtocol;
        };
        const method = info.method;

        // 2. Decode the request from the wire (varint + snappy).
        //    For zero-length request methods (metadata), request_wire_bytes may be empty.
        var ssz_bytes: []const u8 = &.{};
        var should_free_ssz = false;
        if (request_wire_bytes.len > 0) {
            const decoded = req_resp_encoding.decodeRequest(
                self.allocator,
                request_wire_bytes,
            ) catch |err| {
                log.debug("Failed to decode request for {s}: {}", .{ method.name(), err });
                return error.DecodeError;
            };
            ssz_bytes = decoded.ssz_bytes;
            should_free_ssz = true;
        }
        defer if (should_free_ssz) self.allocator.free(ssz_bytes);

        // 3. Route to handler.
        var collector = req_resp_handler.CollectingWriter{ .allocator = self.allocator };
        defer collector.deinit();
        var writer = collector.writer();
        req_resp_handler.serveRequestVersioned(
            self.allocator,
            method,
            info.version,
            ssz_bytes,
            .{},
            self.context,
            &writer,
        ) catch |err| {
            log.debug("handler error for {s}: {}", .{ method.name(), err });
            try writer.writeError(.server_error, "Internal server error");
        };
        const chunks = try collector.finish();
        defer req_resp_handler.freeResponseChunks(self.allocator, chunks);

        // 4. Encode all response chunks to wire format.
        var wire_parts: std.ArrayListUnmanaged([]const u8) = .empty;
        defer {
            for (wire_parts.items) |part| {
                self.allocator.free(part);
            }
            wire_parts.deinit(self.allocator);
        }

        var total_len: usize = 0;
        for (chunks) |chunk| {
            const encoded = req_resp_encoding.encodeResponseChunk(
                self.allocator,
                chunk.result,
                chunk.context_bytes,
                chunk.ssz_payload,
            ) catch |err| {
                log.debug("failed to encode response chunk: {}", .{err});
                return error.EncodeError;
            };
            total_len += encoded.len;
            try wire_parts.append(self.allocator, encoded);
        }

        // 5. Concatenate all wire parts.
        const result = try self.allocator.alloc(u8, total_len);
        var offset: usize = 0;
        for (wire_parts.items) |part| {
            @memcpy(result[offset..][0..part.len], part);
            offset += part.len;
        }

        return result;
    }

    /// Encode a request for sending over the wire.
    ///
    /// Takes raw SSZ bytes and encodes them with varint length prefix + Snappy
    /// compression. The caller sends the result via a libp2p stream.
    ///
    /// Caller owns the returned bytes.
    pub fn encodeRequest(
        self: *Self,
        ssz_bytes: []const u8,
    ) ![]const u8 {
        return req_resp_encoding.encodeRequest(self.allocator, ssz_bytes);
    }

    /// Get the protocol ID string for a given method.
    ///
    /// Returns a protocol ID like `/eth2/beacon_chain/req/status/1/ssz_snappy`.
    /// Caller owns the returned string.
    pub fn protocolIdFor(self: *Self, method: Method) ![]const u8 {
        return protocol.formatProtocolId(self.allocator, method);
    }

    pub fn protocolIdForVersion(self: *Self, method: Method, version: u8) ![]const u8 {
        return protocol.formatProtocolIdVersioned(self.allocator, method, version);
    }

    pub const HandleError = error{
        UnknownProtocol,
        DecodeError,
        HandlerError,
        EncodeError,
        OutOfMemory,
    };
};

// ============================================================================
// Tests
// ============================================================================

/// Mock ReqRespContext for testing.
fn testStatus(_: *anyopaque) messages.StatusMessage.Type {
    return .{
        .fork_digest = .{ 0x01, 0x02, 0x03, 0x04 },
        .finalized_root = std.mem.zeroes([32]u8),
        .finalized_epoch = 10,
        .head_root = std.mem.zeroes([32]u8),
        .head_slot = 320,
    };
}

fn testMetadata(_: *anyopaque) messages.MetadataV2.Type {
    return .{
        .seq_number = 1,
        .attnets = .{ .data = std.mem.zeroes([8]u8) },
        .syncnets = .{ .data = std.mem.zeroes([1]u8) },
    };
}

fn testPingSeq(_: *anyopaque) u64 {
    return 42;
}

fn testEarliestAvailableSlot(_: *anyopaque) u64 {
    return 64;
}

fn testCustodyGroupCount(_: *anyopaque) u64 {
    return 8;
}

fn testFindBlockByRoot(_: *anyopaque, _: [32]u8, _: *const PayloadSink) anyerror!void {}

fn testStreamBlocksByRange(_: *anyopaque, _: u64, _: u64, _: *const PayloadSink) anyerror!void {}

fn testFindBlobByRoot(_: *anyopaque, _: [32]u8, _: u64, _: *const PayloadSink) anyerror!void {}

fn testStreamBlobsByRange(_: *anyopaque, _: u64, _: u64, _: *const PayloadSink) anyerror!void {}

fn testGetCurrentForkSeq(_: *anyopaque) ForkSeq {
    return .phase0;
}

fn testGetForkSeqForSlot(_: *anyopaque, _: u64) ForkSeq {
    return .phase0;
}

fn testGetForkDigest(_: *anyopaque, _: u64) [4]u8 {
    return .{ 0x01, 0x02, 0x03, 0x04 };
}

fn testOnGoodbye(_: *anyopaque, _: ?[]const u8, _: u64) void {}

fn testOnPeerStatus(_: *anyopaque, _: ?[]const u8, _: messages.StatusMessage.Type, _: ?u64) void {}

fn testOnRequestCompleted(_: *anyopaque, _: protocol.Method, _: protocol.ReqRespRequestOutcome, _: f64, _: u64, _: u64, _: u64) void {}

var _test_sentinel: u8 = 0;
const test_context = ReqRespContext{
    .ptr = &_test_sentinel,
    .getStatus = &testStatus,
    .getMetadata = &testMetadata,
    .getEarliestAvailableSlot = &testEarliestAvailableSlot,
    .getCustodyGroupCount = &testCustodyGroupCount,
    .getPingSequence = &testPingSeq,
    .findBlockByRoot = &testFindBlockByRoot,
    .streamBlocksByRange = &testStreamBlocksByRange,
    .findBlobByRoot = &testFindBlobByRoot,
    .streamBlobsByRange = &testStreamBlobsByRange,
    .getCurrentForkSeq = &testGetCurrentForkSeq,
    .getForkSeqForSlot = &testGetForkSeqForSlot,
    .getForkDigest = &testGetForkDigest,
    .onGoodbye = &testOnGoodbye,
    .onPeerStatus = &testOnPeerStatus,
    .onRequestCompleted = &testOnRequestCompleted,
};

test "EthReqRespAdapter: handle status request roundtrip" {
    const allocator = testing.allocator;

    var adapter = EthReqRespAdapter.init(allocator, &test_context);

    // Create a Status request.
    const status = testStatus(&_test_sentinel);
    var ssz_buf: [messages.StatusMessage.fixed_size]u8 = undefined;
    _ = messages.StatusMessage.serializeIntoBytes(&status, &ssz_buf);

    // Encode to wire format.
    const wire_request = try req_resp_encoding.encodeRequest(allocator, &ssz_buf);
    defer allocator.free(wire_request);

    // Handle via adapter.
    const protocol_id = try protocol.formatProtocolId(allocator, .status);
    defer allocator.free(protocol_id);

    const wire_response = try adapter.handleStream(protocol_id, wire_request);
    defer allocator.free(wire_response);

    // Decode the response.
    const decoded = try req_resp_encoding.decodeResponseChunk(allocator, wire_response, false);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    try testing.expectEqual(messages.StatusMessage.fixed_size, decoded.ssz_bytes.len);
}

test "EthReqRespAdapter: handle ping request roundtrip" {
    const allocator = testing.allocator;

    var adapter = EthReqRespAdapter.init(allocator, &test_context);

    // Encode a ping request (8 bytes, little-endian u64).
    var ping_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &ping_bytes, 1, .little);

    const wire_request = try req_resp_encoding.encodeRequest(allocator, &ping_bytes);
    defer allocator.free(wire_request);

    const protocol_id = try protocol.formatProtocolId(allocator, .ping);
    defer allocator.free(protocol_id);

    const wire_response = try adapter.handleStream(protocol_id, wire_request);
    defer allocator.free(wire_response);

    const decoded = try req_resp_encoding.decodeResponseChunk(allocator, wire_response, false);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    // Ping response is 8 bytes (u64 seq number).
    try testing.expectEqual(@as(usize, 8), decoded.ssz_bytes.len);
    const seq = std.mem.readInt(u64, decoded.ssz_bytes[0..8], .little);
    try testing.expectEqual(@as(u64, 42), seq);
}

test "EthReqRespAdapter: handle metadata request (empty body)" {
    const allocator = testing.allocator;

    var adapter = EthReqRespAdapter.init(allocator, &test_context);

    const protocol_id = try protocol.formatProtocolId(allocator, .metadata);
    defer allocator.free(protocol_id);

    // Metadata has no request body.
    const wire_response = try adapter.handleStream(protocol_id, &.{});
    defer allocator.free(wire_response);

    const decoded = try req_resp_encoding.decodeResponseChunk(allocator, wire_response, false);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    // MetadataV2 is seq_number(8) + attnets(8) + syncnets(1) = 17 bytes.
    try testing.expectEqual(@as(usize, 17), decoded.ssz_bytes.len);
}

test "EthReqRespAdapter: handle StatusV2 request roundtrip" {
    const allocator = testing.allocator;

    var adapter = EthReqRespAdapter.init(allocator, &test_context);

    const status = messages.StatusMessageV2.Type{
        .fork_digest = .{ 0x01, 0x02, 0x03, 0x04 },
        .finalized_root = std.mem.zeroes([32]u8),
        .finalized_epoch = 10,
        .head_root = std.mem.zeroes([32]u8),
        .head_slot = 320,
        .earliest_available_slot = 16,
    };
    var ssz_buf: [messages.StatusMessageV2.fixed_size]u8 = undefined;
    _ = messages.StatusMessageV2.serializeIntoBytes(&status, &ssz_buf);

    const wire_request = try req_resp_encoding.encodeRequest(allocator, &ssz_buf);
    defer allocator.free(wire_request);

    const wire_response = try adapter.handleStream("/eth2/beacon_chain/req/status/2/ssz_snappy", wire_request);
    defer allocator.free(wire_response);

    const decoded = try req_resp_encoding.decodeResponseChunk(allocator, wire_response, false);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    try testing.expectEqual(messages.StatusMessageV2.fixed_size, decoded.ssz_bytes.len);
}

test "EthReqRespAdapter: handle MetadataV3 request (empty body)" {
    const allocator = testing.allocator;

    var adapter = EthReqRespAdapter.init(allocator, &test_context);

    const wire_response = try adapter.handleStream("/eth2/beacon_chain/req/metadata/3/ssz_snappy", &.{});
    defer allocator.free(wire_response);

    const decoded = try req_resp_encoding.decodeResponseChunk(allocator, wire_response, false);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqual(ResponseCode.success, decoded.result);
    try testing.expectEqual(messages.MetadataV3.fixed_size, decoded.ssz_bytes.len);
}

fn testDecodeWireResponse(
    allocator: Allocator,
    wire_bytes: []const u8,
    method: Method,
) ![]req_resp_encoding.DecodedResponseChunk {
    return req_resp_encoding.decodeResponseChunks(
        allocator,
        wire_bytes,
        method.hasContextBytes(),
        method.hasMultipleResponses(),
    );
}

const RangeStreamTestContext = struct {
    chunks: []const req_resp_handler.SlotPayload,
    fail_after_chunks: ?usize = null,

    fn streamBlocksByRange(ptr: *anyopaque, _: u64, _: u64, sink: *const PayloadSink) anyerror!void {
        const self: *RangeStreamTestContext = @ptrCast(@alignCast(ptr));
        for (self.chunks, 0..) |chunk, i| {
            try sink.write(chunk);
            if (self.fail_after_chunks) |fail_after| {
                if (i + 1 == fail_after) return error.TestServerFailure;
            }
        }
    }
};

fn makeRangeStreamContext(test_ctx: *RangeStreamTestContext) ReqRespContext {
    var ctx = test_context;
    ctx.ptr = test_ctx;
    ctx.streamBlocksByRange = &RangeStreamTestContext.streamBlocksByRange;
    return ctx;
}

test "EthReqRespAdapter: BeaconBlocksByRange streams multiple response chunks with context bytes" {
    const allocator = testing.allocator;

    const chunk_0 = [_]u8{ 0xAA, 0xBB, 0xCC };
    const chunk_1 = [_]u8{ 0xDD, 0xEE };
    const slot_payloads = [_]req_resp_handler.SlotPayload{
        .{ .slot = 11, .ssz_payload = &chunk_0 },
        .{ .slot = 13, .ssz_payload = &chunk_1 },
    };
    var range_ctx_data = RangeStreamTestContext{ .chunks = &slot_payloads };
    const range_ctx = makeRangeStreamContext(&range_ctx_data);
    var adapter = EthReqRespAdapter.init(allocator, &range_ctx);

    const request = messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = 11,
        .count = 3,
        .step = 1,
    };
    var request_ssz: [messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_ssz);
    const wire_request = try req_resp_encoding.encodeRequest(allocator, &request_ssz);
    defer allocator.free(wire_request);

    const wire_response = try adapter.handleStream("/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy", wire_request);
    defer allocator.free(wire_response);

    const decoded = try testDecodeWireResponse(allocator, wire_response, .beacon_blocks_by_range);
    defer req_resp_encoding.freeDecodedResponseChunks(allocator, decoded);

    try testing.expectEqual(@as(usize, 2), decoded.len);
    try testing.expectEqual(ResponseCode.success, decoded[0].result);
    try testing.expectEqual(ResponseCode.success, decoded[1].result);
    try testing.expectEqual(@as(?[4]u8, .{ 0x01, 0x02, 0x03, 0x04 }), decoded[0].context_bytes);
    try testing.expectEqual(@as(?[4]u8, .{ 0x01, 0x02, 0x03, 0x04 }), decoded[1].context_bytes);
    try testing.expectEqualSlices(u8, &chunk_0, decoded[0].ssz_bytes);
    try testing.expectEqualSlices(u8, &chunk_1, decoded[1].ssz_bytes);
}

test "EthReqRespAdapter: BeaconBlocksByRange emits server error after streamed success chunks" {
    const allocator = testing.allocator;

    const chunk_0 = [_]u8{0xA1};
    const chunk_1 = [_]u8{0xB2};
    const slot_payloads = [_]req_resp_handler.SlotPayload{
        .{ .slot = 1, .ssz_payload = &chunk_0 },
        .{ .slot = 2, .ssz_payload = &chunk_1 },
    };
    var range_ctx_data = RangeStreamTestContext{
        .chunks = &slot_payloads,
        .fail_after_chunks = 2,
    };
    const range_ctx = makeRangeStreamContext(&range_ctx_data);
    var adapter = EthReqRespAdapter.init(allocator, &range_ctx);

    const request = messages.BeaconBlocksByRangeRequest.Type{
        .start_slot = 1,
        .count = 3,
        .step = 1,
    };
    var request_ssz: [messages.BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = messages.BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_ssz);
    const wire_request = try req_resp_encoding.encodeRequest(allocator, &request_ssz);
    defer allocator.free(wire_request);

    const wire_response = try adapter.handleStream("/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy", wire_request);
    defer allocator.free(wire_response);

    const decoded = try testDecodeWireResponse(allocator, wire_response, .beacon_blocks_by_range);
    defer req_resp_encoding.freeDecodedResponseChunks(allocator, decoded);

    try testing.expectEqual(@as(usize, 3), decoded.len);
    try testing.expectEqual(ResponseCode.success, decoded[0].result);
    try testing.expectEqual(ResponseCode.success, decoded[1].result);
    try testing.expectEqual(ResponseCode.server_error, decoded[2].result);
    try testing.expectEqual(@as(?[4]u8, null), decoded[2].context_bytes);
    try testing.expectEqualStrings("Internal server error", decoded[2].ssz_bytes);
}

test "EthReqRespAdapter: unknown protocol returns error" {
    const allocator = testing.allocator;

    var adapter = EthReqRespAdapter.init(allocator, &test_context);

    const result = adapter.handleStream("/eth2/beacon_chain/req/unknown/1/ssz_snappy", &.{});
    try testing.expectError(EthReqRespAdapter.HandleError.UnknownProtocol, result);
}

test "EthReqRespAdapter: encodeRequest roundtrip" {
    const allocator = testing.allocator;

    var adapter = EthReqRespAdapter.init(allocator, &test_context);

    const original = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const encoded = try adapter.encodeRequest(original);
    defer allocator.free(encoded);

    // Decode it back.
    const decoded = try req_resp_encoding.decodeRequest(allocator, encoded);
    defer allocator.free(decoded.ssz_bytes);

    try testing.expectEqualSlices(u8, original, decoded.ssz_bytes);
}
