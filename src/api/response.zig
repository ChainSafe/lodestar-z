//! Response encoding for the Beacon REST API.
//!
//! Handles serializing handler responses into JSON or SSZ bytes based on
//! the client's Accept header (content negotiation).
//!
//! JSON responses follow the Beacon API envelope: `{ "data": ..., "execution_optimistic": ..., "finalized": ... }`.
//! SSZ responses return raw `application/octet-stream` bytes.

const std = @import("std");
const types = @import("types.zig");

const IoWriter = std.Io.Writer;
const IoError = IoWriter.Error;

/// Encode an ApiResponse as a JSON byte string.
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
                try writeJsonValue(writer, field.type, &@field(value, field.name));
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
