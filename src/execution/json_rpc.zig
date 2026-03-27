//! JSON-RPC 2.0 encoding and decoding for Engine API communication.
//!
//! The Engine API uses JSON-RPC 2.0 over HTTP (with JWT authentication).
//! This module provides request/response types and helper functions for
//! encoding requests and decoding responses.
//!
//! Reference: https://www.jsonrpc.org/specification

const std = @import("std");
const testing = std.testing;
const json = std.json;
const Allocator = std.mem.Allocator;
const Io = std.Io;

// ── Engine API error codes ────────────────────────────────────────────────────

/// Engine API specific JSON-RPC error codes.
///
/// Standard JSON-RPC codes: -32700 to -32600
/// Engine API codes: -38001 to -38005
pub const EngineErrorCode = enum(i64) {
    // Standard JSON-RPC errors
    parse_error = -32700,
    invalid_request = -32600,
    method_not_found = -32601,
    invalid_params = -32602,
    internal_error = -32603,
    // Server errors (-32000 to -32099)
    server_error = -32000,
    // Engine API specific errors
    unknown_payload = -38001,
    invalid_forkchoice_state = -38002,
    invalid_payload_attributes = -38003,
    too_large_request = -38004,
    unsupported_fork = -38005,
    _,
};

/// Errors that can result from JSON-RPC responses.
pub const JsonRpcResponseError = error{
    /// JSON parsing failed (-32700)
    ParseError,
    /// Request is malformed (-32600)
    InvalidRequest,
    /// Method does not exist (-32601)
    MethodNotFound,
    /// Invalid method parameters (-32602)
    InvalidParams,
    /// Internal JSON-RPC error (-32603)
    InternalError,
    /// Generic server error (-32000 to -32099)
    ServerError,
    /// Payload is unknown to the engine (-38001)
    UnknownPayload,
    /// Invalid forkchoice state (-38002)
    InvalidForkchoiceState,
    /// Invalid payload attributes (-38003)
    InvalidPayloadAttributes,
    /// Request body too large (-38004)
    TooLargeRequest,
    /// Fork is not supported (-38005)
    UnsupportedFork,
    /// Unknown error code
    UnknownErrorCode,
    /// Response missing result field
    MissingResult,
    /// Result field is null
    NullResult,
};

/// JSON-RPC 2.0 error object.
pub const JsonRpcError = struct {
    code: i64,
    message: []const u8,
    /// Optional structured error data (kept as raw JSON).
    data: ?[]const u8 = null,
};

/// Parsed JSON-RPC 2.0 response wrapper.
///
/// Owns all memory backing the parsed value. Call `deinit()` when done.
pub fn ParsedResponse(comptime T: type) type {
    return struct {
        value: T,
        _arena: std.heap.ArenaAllocator,

        pub fn deinit(self: *@This()) void {
            self._arena.deinit();
        }
    };
}

/// Map a JSON-RPC error code to a Zig error.
pub fn mapErrorCode(code: i64) JsonRpcResponseError {
    return switch (code) {
        -32700 => error.ParseError,
        -32600 => error.InvalidRequest,
        -32601 => error.MethodNotFound,
        -32602 => error.InvalidParams,
        -32603 => error.InternalError,
        -38001 => error.UnknownPayload,
        -38002 => error.InvalidForkchoiceState,
        -38003 => error.InvalidPayloadAttributes,
        -38004 => error.TooLargeRequest,
        -38005 => error.UnsupportedFork,
        else => if (code <= -32000 and code >= -32099)
            error.ServerError
        else
            error.UnknownErrorCode,
    };
}

/// Encode a JSON-RPC 2.0 request.
///
/// `method` is the RPC method name (e.g. "engine_newPayloadV3").
/// `params` is a tuple or struct that will be serialized as the params array.
/// `id` is the request identifier.
///
/// Returns an allocated JSON byte string. Caller owns the memory.
pub fn encodeRequest(
    allocator: Allocator,
    method: []const u8,
    params: anytype,
    id: u64,
) ![]const u8 {
    var out: Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();

    var writer: json.Stringify = .{ .writer = &out.writer };
    try writer.beginObject();

    try writer.objectField("jsonrpc");
    try writer.write("2.0");

    try writer.objectField("method");
    try writer.write(method);

    try writer.objectField("params");
    try writer.write(params);

    try writer.objectField("id");
    try writer.write(id);

    try writer.endObject();

    const result = try allocator.dupe(u8, out.written());
    out.deinit();
    return result;
}

/// Decode a JSON-RPC 2.0 response, extracting the result as type T.
///
/// Returns a `ParsedResponse(T)` that owns its memory. Call `.deinit()` when done.
/// Returns a specific error based on the JSON-RPC error code if the response
/// contains a JSON-RPC error object, or if the result cannot be parsed as T.
pub fn decodeResponse(
    comptime T: type,
    allocator: Allocator,
    json_bytes: []const u8,
) !ParsedResponse(T) {
    // Use an arena so all allocations (source parse, re-serialized JSON, inner parse)
    // live together and are freed atomically.
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_alloc = arena.allocator();

    var source_parsed = try json.parseFromSlice(json.Value, arena_alloc, json_bytes, .{});
    defer source_parsed.deinit();

    const root = source_parsed.value;

    // Check for JSON-RPC error — map to specific error type.
    if (root.object.get("error")) |err_val| {
        if (err_val != .null) {
            // Extract error code and message for logging.
            if (err_val == .object) {
                const code = if (err_val.object.get("code")) |c| c.integer else -1;
                const msg = if (err_val.object.get("message")) |m| m.string else "unknown";
                std.log.debug("JSON-RPC error code={d} message={s}", .{ code, msg });
                return mapErrorCode(code);
            }
            return error.UnknownErrorCode;
        }
    }

    // Extract result.
    const result_val = root.object.get("result") orelse return error.MissingResult;
    if (result_val == .null) return error.NullResult;

    // Re-serialize the result value into the arena.
    var result_out: Io.Writer.Allocating = .init(arena_alloc);
    var result_writer: json.Stringify = .{ .writer = &result_out.writer };
    try result_val.jsonStringify(&result_writer);

    // Parse the inner result. Uses arena_alloc so all backing memory persists.
    const value = try json.parseFromSliceLeaky(T, arena_alloc, result_out.written(), .{});

    return .{
        .value = value,
        ._arena = arena,
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "encodeRequest basic" {
    const allocator = testing.allocator;
    const encoded = try encodeRequest(allocator, "engine_newPayloadV3", .{ "param1", "param2" }, 1);
    defer allocator.free(encoded);

    // Verify it's valid JSON.
    var parsed = try json.parseFromSlice(json.Value, allocator, encoded, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try testing.expectEqualStrings("2.0", obj.get("jsonrpc").?.string);
    try testing.expectEqualStrings("engine_newPayloadV3", obj.get("method").?.string);
    try testing.expectEqual(@as(i64, 1), obj.get("id").?.integer);
}

test "encodeRequest with struct params" {
    const allocator = testing.allocator;

    const Params = struct {
        block_hash: []const u8,
        number: u64,
    };
    const params = Params{ .block_hash = "0xabc", .number = 42 };

    const encoded = try encodeRequest(allocator, "engine_getPayloadV3", params, 5);
    defer allocator.free(encoded);

    var parsed = try json.parseFromSlice(json.Value, allocator, encoded, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try testing.expectEqualStrings("engine_getPayloadV3", obj.get("method").?.string);
    try testing.expectEqual(@as(i64, 5), obj.get("id").?.integer);

    // params should be the struct serialized as an object.
    const params_obj = obj.get("params").?.object;
    try testing.expectEqualStrings("0xabc", params_obj.get("block_hash").?.string);
    try testing.expectEqual(@as(i64, 42), params_obj.get("number").?.integer);
}

test "decodeResponse success" {
    const allocator = testing.allocator;
    const response_json =
        \\{"jsonrpc":"2.0","id":1,"result":{"value":42}}
    ;

    const Result = struct { value: u64 };
    var resp = try decodeResponse(Result, allocator, response_json);
    defer resp.deinit();
    try testing.expectEqual(@as(u64, 42), resp.value.value);
}

test "decodeResponse: JsonRpcError maps error codes" {
    const allocator = testing.allocator;

    // Test known Engine API error codes.
    const test_cases = [_]struct { code: i64, expected: anyerror }{
        .{ .code = -32700, .expected = error.ParseError },
        .{ .code = -32600, .expected = error.InvalidRequest },
        .{ .code = -32601, .expected = error.MethodNotFound },
        .{ .code = -32602, .expected = error.InvalidParams },
        .{ .code = -32603, .expected = error.InternalError },
        .{ .code = -38001, .expected = error.UnknownPayload },
        .{ .code = -38002, .expected = error.InvalidForkchoiceState },
        .{ .code = -38003, .expected = error.InvalidPayloadAttributes },
        .{ .code = -38004, .expected = error.TooLargeRequest },
        .{ .code = -38005, .expected = error.UnsupportedFork },
    };

    for (test_cases) |tc| {
        const response_json = try std.fmt.allocPrint(
            allocator,
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{{\"code\":{d},\"message\":\"test error\"}}}}",
            .{tc.code},
        );
        defer allocator.free(response_json);

        const Result = struct { value: u64 };
        const result = decodeResponse(Result, allocator, response_json);
        try testing.expectError(tc.expected, result);
    }
}

test "decodeResponse: server error range" {
    const allocator = testing.allocator;
    const response_json =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32050,"message":"server error"}}
    ;
    const Result = struct { value: u64 };
    const result = decodeResponse(Result, allocator, response_json);
    try testing.expectError(error.ServerError, result);
}

test "decodeResponse: unknown error code" {
    const allocator = testing.allocator;
    const response_json =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-99999,"message":"unknown"}}
    ;
    const Result = struct { value: u64 };
    const result = decodeResponse(Result, allocator, response_json);
    try testing.expectError(error.UnknownErrorCode, result);
}

test "decodeResponse with null result" {
    const allocator = testing.allocator;
    const response_json =
        \\{"jsonrpc":"2.0","id":1,"result":null}
    ;

    const Result = struct { value: u64 };
    const result = decodeResponse(Result, allocator, response_json);
    try testing.expectError(error.NullResult, result);
}

test "decodeResponse missing result field" {
    const allocator = testing.allocator;
    const response_json =
        \\{"jsonrpc":"2.0","id":1}
    ;
    const Result = struct { value: u64 };
    const result = decodeResponse(Result, allocator, response_json);
    try testing.expectError(error.MissingResult, result);
}

test "mapErrorCode covers all engine API codes" {
    try testing.expectEqual(error.ParseError, mapErrorCode(-32700));
    try testing.expectEqual(error.InvalidRequest, mapErrorCode(-32600));
    try testing.expectEqual(error.MethodNotFound, mapErrorCode(-32601));
    try testing.expectEqual(error.InvalidParams, mapErrorCode(-32602));
    try testing.expectEqual(error.InternalError, mapErrorCode(-32603));
    try testing.expectEqual(error.UnknownPayload, mapErrorCode(-38001));
    try testing.expectEqual(error.InvalidForkchoiceState, mapErrorCode(-38002));
    try testing.expectEqual(error.InvalidPayloadAttributes, mapErrorCode(-38003));
    try testing.expectEqual(error.TooLargeRequest, mapErrorCode(-38004));
    try testing.expectEqual(error.UnsupportedFork, mapErrorCode(-38005));
    try testing.expectEqual(error.ServerError, mapErrorCode(-32000));
    try testing.expectEqual(error.ServerError, mapErrorCode(-32099));
}

test "encodeRequest and decodeResponse roundtrip" {
    const allocator = testing.allocator;

    // Encode a request.
    const encoded = try encodeRequest(allocator, "test_method", .{"hello"}, 99);
    defer allocator.free(encoded);

    // Verify request is valid JSON with correct fields.
    var parsed = try json.parseFromSlice(json.Value, allocator, encoded, .{});
    defer parsed.deinit();

    try testing.expectEqualStrings("test_method", parsed.value.object.get("method").?.string);
    try testing.expectEqual(@as(i64, 99), parsed.value.object.get("id").?.integer);

    // Simulate a response.
    const response_json =
        \\{"jsonrpc":"2.0","id":99,"result":{"status":"valid"}}
    ;
    const Resp = struct { status: []const u8 };
    var resp = try decodeResponse(Resp, allocator, response_json);
    defer resp.deinit();
    try testing.expectEqualStrings("valid", resp.value.status);
}
