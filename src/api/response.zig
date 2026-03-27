//! Response encoding for the Beacon REST API.
//!
//! Handles serializing handler responses into JSON or SSZ bytes based on
//! the client's Accept header (content negotiation).
//!
//! JSON responses follow the Beacon API envelope:
//! - With metadata: `{ "data": ..., "version": "deneb", "execution_optimistic": false, "finalized": true }`
//! - Without metadata: `{ "data": ... }`
//! SSZ responses return raw `application/octet-stream` bytes.

const std = @import("std");
const types = @import("types.zig");

const content_negotiation = @import("content_negotiation.zig");
const response_meta = @import("response_meta.zig");
const error_response = @import("error_response.zig");
const handler_result = @import("handler_result.zig");

/// Re-exports: content negotiation
pub const WireFormat = content_negotiation.WireFormat;
pub const NegotiationResult = content_negotiation.NegotiationResult;
pub const parseAcceptHeader = content_negotiation.parseAcceptHeader;
pub const parseContentTypeHeader = content_negotiation.parseContentTypeHeader;

/// Re-exports: response metadata
pub const ResponseMeta = response_meta.ResponseMeta;
pub const Fork = response_meta.Fork;
pub const MetaHeader = response_meta.MetaHeader;
pub const buildMetaHeaders = response_meta.buildHeaders;

/// Re-exports: error responses
pub const ApiError = error_response.ApiError;
pub const ErrorCode = error_response.ErrorCode;
pub const fromZigError = error_response.fromZigError;
pub const formatZigError = error_response.formatZigError;

/// Re-exports: handler result
pub const HandlerResult = handler_result.HandlerResult;
pub const VoidResult = handler_result.VoidResult;

const IoWriter = std.Io.Writer;
const IoError = IoWriter.Error;

/// Encode a HandlerResult as JSON bytes, including ResponseMeta in the body.
///
/// For endpoints WITH meta (version, execution_optimistic, etc.):
/// ```json
/// { "data": {...}, "version": "deneb", "execution_optimistic": false, "finalized": true }
/// ```
///
/// For endpoints WITHOUT meta (all fields null):
/// ```json
/// { "data": {...} }
/// ```
pub fn encodeHandlerResultJson(
    allocator: std.mem.Allocator,
    comptime T: type,
    result: handler_result.HandlerResult(T),
) (IoError || std.mem.Allocator.Error)![]u8 {
    var aw: IoWriter.Allocating = .init(allocator);
    errdefer aw.deinit();

    const w = &aw.writer;
    try writeAll(w, "{");

    // Emit "data" field
    try writeAll(w, "\"data\":");
    try writeJsonValue(w, T, &result.data);

    // Emit metadata fields inline (only those that are non-null)
    const meta = result.meta;
    if (meta.version) |fork| {
        try writeAll(w, ",\"version\":\"");
        try writeAll(w, fork.toString());
        try writeAll(w, "\"");
    }
    if (meta.execution_optimistic) |opt| {
        try writeAll(w, ",\"execution_optimistic\":");
        try writeAll(w, if (opt) "true" else "false");
    }
    if (meta.finalized) |fin| {
        try writeAll(w, ",\"finalized\":");
        try writeAll(w, if (fin) "true" else "false");
    }
    if (meta.dependent_root) |root| {
        try writeAll(w, ",\"dependent_root\":\"0x");
        const hex = std.fmt.bytesToHex(&root, .lower);
        try writeAll(w, &hex);
        try writeAll(w, "\"");
    }

    try writeAll(w, "}");
    return aw.toOwnedSlice();
}

/// Encode an ApiResponse as a JSON byte string (legacy format, kept for compat).
///
/// Produces the standard Beacon API envelope:
/// ```json
/// {
///   "execution_optimistic": false,
///   "finalized": false,
///   "data": { ... }
/// }
/// ```
pub fn encodeJsonResponse(
    allocator: std.mem.Allocator,
    comptime T: type,
    response: types.ApiResponse(T),
) (IoError || std.mem.Allocator.Error)![]u8 {
    var aw: IoWriter.Allocating = .init(allocator);
    errdefer aw.deinit();

    writeAll(&aw.writer, "{") catch return error.OutOfMemory;

    // Metadata fields
    writeAll(&aw.writer, "\"execution_optimistic\":") catch return error.OutOfMemory;
    if (response.execution_optimistic) {
        writeAll(&aw.writer, "true") catch return error.OutOfMemory;
    } else {
        writeAll(&aw.writer, "false") catch return error.OutOfMemory;
    }
    writeAll(&aw.writer, ",\"finalized\":") catch return error.OutOfMemory;
    if (response.finalized) {
        writeAll(&aw.writer, "true") catch return error.OutOfMemory;
    } else {
        writeAll(&aw.writer, "false") catch return error.OutOfMemory;
    }

    // Data field
    writeAll(&aw.writer, ",\"data\":") catch return error.OutOfMemory;
    writeJsonValue(&aw.writer, T, &response.data) catch return error.OutOfMemory;

    writeAll(&aw.writer, "}") catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

/// Format an ApiError as JSON bytes.
///
/// Returns `{ "statusCode": N, "message": "..." }` per Beacon API spec.
pub fn encodeErrorJson(
    allocator: std.mem.Allocator,
    api_err: error_response.ApiError,
) std.mem.Allocator.Error![]u8 {
    var buf: [512]u8 = undefined;
    const json = api_err.formatJson(&buf);
    return allocator.dupe(u8, json);
}

fn writeAll(writer: *IoWriter, data: []const u8) IoError!void {
    return writer.writeAll(data);
}

fn writeByte(writer: *IoWriter, byte: u8) IoError!void {
    return writer.writeByte(byte);
}

fn print(writer: *IoWriter, comptime fmt: []const u8, args: anytype) IoError!void {
    return writer.print(fmt, args);
}

/// Write a single value as JSON. Dispatches on type.
fn writeJsonValue(writer: *IoWriter, comptime T: type, value: *const T) IoError!void {
    const info = @typeInfo(T);

    switch (info) {
        .bool => {
            if (value.*) {
                try writeAll(writer, "true");
            } else {
                try writeAll(writer, "false");
            }
        },
        .int, .comptime_int => {
            try print(writer, "{d}", .{value.*});
        },
        .pointer => |ptr| {
            if (ptr.size == .slice) {
                if (ptr.child == u8) {
                    // String
                    try writeByte(writer, '"');
                    try writeAll(writer, value.*);
                    try writeByte(writer, '"');
                } else if (comptime isSliceOfSliceOfU8(T)) {
                    // []const []const u8
                    try writeByte(writer, '[');
                    for (value.*, 0..) |item, i| {
                        if (i > 0) try writeByte(writer, ',');
                        try writeByte(writer, '"');
                        try writeAll(writer, item);
                        try writeByte(writer, '"');
                    }
                    try writeByte(writer, ']');
                } else {
                    // Slice of structs or other types
                    try writeByte(writer, '[');
                    for (value.*, 0..) |*item, i| {
                        if (i > 0) try writeByte(writer, ',');
                        try writeJsonValue(writer, ptr.child, item);
                    }
                    try writeByte(writer, ']');
                }
            } else {
                try writeAll(writer, "null");
            }
        },
        .optional => {
            if (value.*) |*v| {
                try writeJsonValue(writer, info.optional.child, v);
            } else {
                try writeAll(writer, "null");
            }
        },
        .@"struct" => |s| {
            try writeByte(writer, '{');
            var first = true;
            inline for (s.fields) |field| {
                if (!first) try writeByte(writer, ',');
                first = false;
                try writeByte(writer, '"');
                try writeAll(writer, field.name);
                try writeAll(writer, "\":");
                try writeJsonValue(writer, field.type, &@field(value.*, field.name));
            }
            try writeByte(writer, '}');
        },
        .@"enum" => {
            try writeByte(writer, '"');
            try writeAll(writer, @tagName(value.*));
            try writeByte(writer, '"');
        },
        .array => |arr| {
            if (arr.child == u8) {
                // Byte array -> hex string
                try writeAll(writer, "\"0x");
                for (value.*) |byte| {
                    try print(writer, "{x:0>2}", .{byte});
                }
                try writeByte(writer, '"');
            } else {
                try writeByte(writer, '[');
                for (value.*, 0..) |*item, i| {
                    if (i > 0) try writeByte(writer, ',');
                    try writeJsonValue(writer, arr.child, item);
                }
                try writeByte(writer, ']');
            }
        },
        .void => {
            // void type writes nothing (no body for 204/void responses)
        },
        else => {
            try writeAll(writer, "null");
        },
    }
}

fn isSliceOfSliceOfU8(comptime T: type) bool {
    const info = @typeInfo(T);
    if (info != .pointer) return false;
    if (info.pointer.size != .slice) return false;
    const child_info = @typeInfo(info.pointer.child);
    if (child_info != .pointer) return false;
    if (child_info.pointer.size != .slice) return false;
    return child_info.pointer.child == u8;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encodeJsonResponse simple struct" {
    const TestData = struct {
        name: []const u8,
        value: u64,
    };

    const resp = types.ApiResponse(TestData){
        .data = .{
            .name = "test",
            .value = 42,
        },
        .execution_optimistic = false,
        .finalized = true,
    };

    const json = try encodeJsonResponse(std.testing.allocator, TestData, resp);
    defer std.testing.allocator.free(json);

    // Check envelope fields present
    try std.testing.expect(std.mem.indexOf(u8, json, "\"execution_optimistic\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"finalized\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"data\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"value\":42") != null);
}

test "encodeJsonResponse byte array as hex" {
    const TestData = struct {
        root: [4]u8,
    };

    const resp = types.ApiResponse(TestData){
        .data = .{ .root = .{ 0xde, 0xad, 0xbe, 0xef } },
    };

    const json = try encodeJsonResponse(std.testing.allocator, TestData, resp);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"0xdeadbeef\"") != null);
}

test "encodeJsonResponse empty slice" {
    const TestData = struct {
        items: []const u64,
    };

    const resp = types.ApiResponse(TestData){
        .data = .{ .items = &[_]u64{} },
    };

    const json = try encodeJsonResponse(std.testing.allocator, TestData, resp);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"items\":[]") != null);
}

test "encodeHandlerResultJson with metadata" {
    const TestData = struct {
        value: u64,
    };

    const meta = ResponseMeta{
        .version = .deneb,
        .execution_optimistic = false,
        .finalized = true,
    };

    const result = HandlerResult(TestData){
        .data = .{ .value = 123 },
        .meta = meta,
    };

    const json = try encodeHandlerResultJson(std.testing.allocator, TestData, result);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"data\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"version\":\"deneb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"execution_optimistic\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"finalized\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"value\":123") != null);
}

test "encodeHandlerResultJson without metadata" {
    const TestData = struct {
        value: u64,
    };

    const result = HandlerResult(TestData){
        .data = .{ .value = 42 },
        .meta = .{},
    };

    const json = try encodeHandlerResultJson(std.testing.allocator, TestData, result);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"data\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "version") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "execution_optimistic") == null);
}

test "encodeHandlerResultJson dependent_root" {
    const TestData = struct {
        x: u64,
    };
    const root = [_]u8{0xab} ** 32;
    const result = HandlerResult(TestData){
        .data = .{ .x = 1 },
        .meta = .{ .dependent_root = root },
    };

    const json = try encodeHandlerResultJson(std.testing.allocator, TestData, result);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"dependent_root\":\"0x") != null);
}

test "encodeErrorJson" {
    const err = error_response.ApiError{ .code = .not_found, .message = "Block not found" };
    const json = try encodeErrorJson(std.testing.allocator, err);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"statusCode\":404") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "Block not found") != null);
}
