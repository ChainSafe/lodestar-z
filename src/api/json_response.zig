//! SSZ-aware JSON response encoding for the Beacon REST API.
//!
//! Provides envelope helpers that delegate to the SSZ type system's
//! `serializeIntoJson` methods, producing spec-compliant Beacon API JSON
//! without hand-rolled string concatenation.
//!
//! Usage:
//!   const body = try writeBeaconEnvelope(alloc, consensus.phase0.BeaconBlock, &block, meta);
//!   // => {"data":{...},"version":"phase0","execution_optimistic":false,"finalized":true}
//!
//! For array-returning endpoints:
//!   const body = try writeBeaconArrayEnvelope(alloc, MyItemSszType, items, meta);
//!   // => {"data":[{...},{...}],"execution_optimistic":false}

const std = @import("std");
const Allocator = std.mem.Allocator;
const response_meta = @import("response_meta.zig");
const ResponseMeta = response_meta.ResponseMeta;
const fork_types = @import("fork_types");
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;

const isFixedType = @import("ssz").isFixedType;

/// Write a Beacon API JSON envelope around an SSZ-typed value.
///
/// Produces: `{"data":<ssz_json>,"version":"...", ...}`
///
/// `SszType` is the SSZ type wrapper (e.g., `phase0.BeaconBlock`),
/// NOT the inner `.Type` struct. The value must be `*const SszType.Type`.
pub fn writeBeaconEnvelope(
    alloc: Allocator,
    comptime SszType: type,
    value: *const SszType.Type,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");

    if (comptime isFixedType(SszType)) {
        try SszType.serializeIntoJson(&stream, value);
    } else {
        try SszType.serializeIntoJson(alloc, &stream, value);
    }

    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}

/// Write a Beacon API JSON envelope around an array of SSZ-typed values.
///
/// Produces: `{"data":[<ssz_json>,...],"version":"...", ...}`
pub fn writeBeaconArrayEnvelope(
    alloc: Allocator,
    comptime SszType: type,
    items: []const SszType.Type,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");
    try stream.beginArray();

    for (items) |*item| {
        if (comptime isFixedType(SszType)) {
            try SszType.serializeIntoJson(&stream, item);
        } else {
            try SszType.serializeIntoJson(alloc, &stream, item);
        }
    }

    try stream.endArray();
    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}

/// Write a raw JSON string as the "data" field (already serialized).
///
/// Useful when data is pre-serialized or from non-SSZ types.
pub fn writeRawEnvelope(
    alloc: Allocator,
    data_json: []const u8,
    meta: ResponseMeta,
) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"data\":");
    try buf.appendSlice(alloc, data_json);

    // Append meta fields via string building (data_json is already raw)
    if (meta.version) |fork| {
        try buf.appendSlice(alloc, ",\"version\":\"");
        try buf.appendSlice(alloc, fork.toString());
        try buf.appendSlice(alloc, "\"");
    }
    if (meta.execution_optimistic) |opt| {
        try buf.appendSlice(alloc, if (opt)
            ",\"execution_optimistic\":true"
        else
            ",\"execution_optimistic\":false");
    }
    if (meta.finalized) |fin| {
        try buf.appendSlice(alloc, if (fin)
            ",\"finalized\":true"
        else
            ",\"finalized\":false");
    }
    if (meta.dependent_root) |root| {
        try buf.appendSlice(alloc, ",\"dependent_root\":\"0x");
        const hex = std.fmt.bytesToHex(&root, .lower);
        try buf.appendSlice(alloc, &hex);
        try buf.appendSlice(alloc, "\"");
    }

    try buf.appendSlice(alloc, "}");
    return buf.toOwnedSlice(alloc);
}

/// Write a fork-polymorphic block as JSON using the AnySignedBeaconBlock union.
///
/// Dispatches to the correct SSZ type's serializer based on the active fork.
pub fn writeBlockEnvelope(
    alloc: Allocator,
    any_block: anytype,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");

    try serializeAnyBlock(alloc, &stream, any_block);

    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}

/// Write a Beacon API JSON envelope around fork-polymorphic attester slashings.
pub fn writeAnyAttesterSlashingArrayEnvelope(
    alloc: Allocator,
    items: []const AnyAttesterSlashing,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");
    try stream.beginArray();

    for (items) |*item| {
        try serializeAnyAttesterSlashing(alloc, &stream, item.*);
    }

    try stream.endArray();
    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}

// ── Internal helpers ─────────────────────────────────────────────────────

/// Serialize the active variant of an AnySignedBeaconBlock union.
fn serializeAnyBlock(alloc: Allocator, stream: *std.json.Stringify, any_block: anytype) !void {
    const ct = @import("consensus_types");
    switch (any_block) {
        .phase0 => |blk| try ct.phase0.SignedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .altair => |blk| try ct.altair.SignedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_bellatrix => |blk| try ct.bellatrix.SignedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_bellatrix => |blk| try ct.bellatrix.SignedBlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_capella => |blk| try ct.capella.SignedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_capella => |blk| try ct.capella.SignedBlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_deneb => |blk| try ct.deneb.SignedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_deneb => |blk| try ct.deneb.SignedBlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_electra => |blk| try ct.electra.SignedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_electra => |blk| try ct.electra.SignedBlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_fulu => |blk| try ct.fulu.SignedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_fulu => |blk| try ct.fulu.SignedBlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
    }
}

fn serializeAnyAttesterSlashing(
    alloc: Allocator,
    stream: *std.json.Stringify,
    slashing: AnyAttesterSlashing,
) !void {
    const ct = @import("consensus_types");
    switch (slashing) {
        .phase0 => |item| try ct.phase0.AttesterSlashing.serializeIntoJson(alloc, stream, &item),
        .electra => |item| try ct.electra.AttesterSlashing.serializeIntoJson(alloc, stream, &item),
    }
}

/// Write metadata fields into a JSON Stringify stream.
fn writeMetaFields(stream: *std.json.Stringify, meta: ResponseMeta) !void {
    if (meta.version) |fork| {
        try stream.objectField("version");
        try stream.write(fork.toString());
    }
    if (meta.execution_optimistic) |opt| {
        try stream.objectField("execution_optimistic");
        try stream.write(opt);
    }
    if (meta.finalized) |fin| {
        try stream.objectField("finalized");
        try stream.write(fin);
    }
    if (meta.dependent_root) |root| {
        try stream.objectField("dependent_root");
        var hex_buf: [66]u8 = undefined;
        hex_buf[0] = '0';
        hex_buf[1] = 'x';
        const hex = std.fmt.bytesToHex(&root, .lower);
        @memcpy(hex_buf[2..66], &hex);
        try stream.write(hex_buf[0..66]);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "writeRawEnvelope basic" {
    const alloc = std.testing.allocator;
    const body = try writeRawEnvelope(alloc, "{\"x\":1}", .{
        .execution_optimistic = false,
        .finalized = true,
    });
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"data\":{\"x\":1}") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"execution_optimistic\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"finalized\":true") != null);
}

test "writeRawEnvelope with version" {
    const alloc = std.testing.allocator;
    const body = try writeRawEnvelope(alloc, "42", .{
        .version = .deneb,
    });
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"data\":42") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"version\":\"deneb\"") != null);
}

test "writeRawEnvelope with dependent_root" {
    const alloc = std.testing.allocator;
    const root = [_]u8{0xab} ** 32;
    const body = try writeRawEnvelope(alloc, "[]", .{
        .dependent_root = root,
    });
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"dependent_root\":\"0x") != null);
}

test "writeRawEnvelope empty meta" {
    const alloc = std.testing.allocator;
    const body = try writeRawEnvelope(alloc, "null", .{});
    defer alloc.free(body);

    try std.testing.expectEqualStrings("{\"data\":null}", body);
}

/// Serialize a Beacon API struct value into a JSON Stringify stream.
///
/// Applies Beacon API conventions:
/// - [N]u8 byte arrays → "0x<hex>"
/// - u64 fields → quoted decimal strings (Beacon API convention for uint64)
/// - other integers → bare numbers
/// - bools → true/false
/// - slices of u64 → arrays of bare numbers
/// - []const u8 → quoted strings
pub fn writeApiValue(stream: *std.json.Stringify, comptime T: type, value: *const T) !void {
    const info = @typeInfo(T);
    switch (info) {
        .@"struct" => |s| {
            try stream.beginObject();
            inline for (s.fields) |field| {
                try stream.objectField(field.name);
                try writeApiValue(stream, field.type, &@field(value.*, field.name));
            }
            try stream.endObject();
        },
        .bool => {
            try stream.write(value.*);
        },
        .int => {
            // Beacon API: all integers are quoted decimal strings
            try stream.print("\"{d}\"", .{value.*});
        },
        .@"enum" => {
            try stream.write(@tagName(value.*));
        },
        .array => |arr| {
            if (arr.child == u8) {
                // Byte array → hex string "0x..."
                var hex_buf: [2 + 2 * arr.len]u8 = undefined;
                hex_buf[0] = '0';
                hex_buf[1] = 'x';
                const hex = std.fmt.bytesToHex(value, .lower);
                @memcpy(hex_buf[2..], &hex);
                try stream.print("\"{s}\"", .{hex_buf[0..]});
            } else {
                try stream.beginArray();
                for (value.*) |*item| {
                    try writeApiValue(stream, arr.child, item);
                }
                try stream.endArray();
            }
        },
        .pointer => |ptr| {
            if (ptr.size == .slice) {
                if (ptr.child == u8) {
                    // []const u8 → string
                    try stream.write(value.*);
                } else {
                    // Slice → array
                    try stream.beginArray();
                    for (value.*) |*item| {
                        try writeApiValue(stream, ptr.child, item);
                    }
                    try stream.endArray();
                }
            } else {
                try stream.write(null);
            }
        },
        .optional => |opt| {
            if (value.*) |*v| {
                try writeApiValue(stream, opt.child, v);
            } else {
                try stream.write(null);
            }
        },
        else => {
            try stream.write(null);
        },
    }
}

/// Serialize a slice of API structs into a JSON envelope with "data" array.
///
/// Produces: `{"data":[{...},{...}],"dependent_root":"0x...", ...}`
pub fn writeApiArrayEnvelope(
    alloc: Allocator,
    comptime T: type,
    items: []const T,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");
    try stream.beginArray();
    for (items) |*item| {
        try writeApiValue(&stream, T, item);
    }
    try stream.endArray();
    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}

/// Serialize a single API struct into a JSON envelope.
///
/// Produces: `{"data":{...},"version":"...", ...}`
pub fn writeApiObjectEnvelope(
    alloc: Allocator,
    comptime T: type,
    value: *const T,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");
    try writeApiValue(&stream, T, value);
    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}
