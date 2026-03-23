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
/// Returns an error if the response contains a JSON-RPC error object,
/// or if the result cannot be parsed as T.
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

    // Check for JSON-RPC error.
    if (root.object.get("error")) |err_val| {
        if (err_val != .null) {
            return error.JsonRpcError;
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

test "decodeResponse with error" {
    const allocator = testing.allocator;
    const response_json =
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unknown payload"}}
    ;

    const Result = struct { value: u64 };
    const result = decodeResponse(Result, allocator, response_json);
    try testing.expectError(error.JsonRpcError, result);
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
