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
const api_types = @import("types.zig");
const config_mod = @import("config");
const preset_mod = @import("preset");
const constants_mod = @import("constants");
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

/// Deserialize a concatenated SSZ byte slice of fixed-size items and wrap it
/// in a Beacon API JSON array envelope.
pub fn writeFixedSszArrayEnvelope(
    alloc: Allocator,
    comptime SszType: type,
    encoded_items: []const u8,
    meta: ResponseMeta,
) ![]u8 {
    if (!comptime isFixedType(SszType)) @compileError("writeFixedSszArrayEnvelope requires a fixed-size SSZ type");
    if (encoded_items.len == 0) return writeBeaconArrayEnvelope(alloc, SszType, &.{}, meta);
    if (encoded_items.len % SszType.fixed_size != 0) return error.InvalidResponseData;

    const count = encoded_items.len / SszType.fixed_size;
    const items = try alloc.alloc(SszType.Type, count);
    defer alloc.free(items);

    for (items, 0..) |*item, i| {
        const offset = i * SszType.fixed_size;
        try SszType.deserializeFromBytes(encoded_items[offset..][0..SszType.fixed_size], item);
    }

    return writeBeaconArrayEnvelope(alloc, SszType, items, meta);
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

pub fn writeUnsignedBlockEnvelope(
    alloc: Allocator,
    any_block: anytype,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");

    try serializeAnyUnsignedBlock(alloc, &stream, any_block);

    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}

pub fn writeStateBytesEnvelope(
    alloc: Allocator,
    fork: response_meta.Fork,
    state_bytes: []const u8,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");
    try serializeStateBytes(alloc, &stream, fork, state_bytes);
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
        .full_gloas => |blk| try ct.gloas.SignedBeaconBlock.serializeIntoJson(alloc, stream, blk),
    }
}

fn serializeAnyUnsignedBlock(alloc: Allocator, stream: *std.json.Stringify, any_block: anytype) !void {
    const ct = @import("consensus_types");
    switch (any_block) {
        .phase0 => |blk| try ct.phase0.BeaconBlock.serializeIntoJson(alloc, stream, blk),
        .altair => |blk| try ct.altair.BeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_bellatrix => |blk| try ct.bellatrix.BeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_bellatrix => |blk| try ct.bellatrix.BlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_capella => |blk| try ct.capella.BeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_capella => |blk| try ct.capella.BlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_deneb => |blk| try ct.deneb.BeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_deneb => |blk| try ct.deneb.BlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_electra => |blk| try ct.electra.BeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_electra => |blk| try ct.electra.BlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_fulu => |blk| try ct.fulu.BeaconBlock.serializeIntoJson(alloc, stream, blk),
        .blinded_fulu => |blk| try ct.fulu.BlindedBeaconBlock.serializeIntoJson(alloc, stream, blk),
        .full_gloas => |blk| try ct.gloas.BeaconBlock.serializeIntoJson(alloc, stream, blk),
    }
}

fn serializeStateBytes(
    alloc: Allocator,
    stream: *std.json.Stringify,
    fork: response_meta.Fork,
    state_bytes: []const u8,
) !void {
    const ct = @import("consensus_types");
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    switch (fork) {
        .phase0 => {
            var state: ct.phase0.BeaconState.Type = undefined;
            try ct.phase0.BeaconState.deserializeFromBytes(a, state_bytes, &state);
            try ct.phase0.BeaconState.serializeIntoJson(a, stream, &state);
        },
        .altair => {
            var state: ct.altair.BeaconState.Type = undefined;
            try ct.altair.BeaconState.deserializeFromBytes(a, state_bytes, &state);
            try ct.altair.BeaconState.serializeIntoJson(a, stream, &state);
        },
        .bellatrix => {
            var state: ct.bellatrix.BeaconState.Type = undefined;
            try ct.bellatrix.BeaconState.deserializeFromBytes(a, state_bytes, &state);
            try ct.bellatrix.BeaconState.serializeIntoJson(a, stream, &state);
        },
        .capella => {
            var state: ct.capella.BeaconState.Type = undefined;
            try ct.capella.BeaconState.deserializeFromBytes(a, state_bytes, &state);
            try ct.capella.BeaconState.serializeIntoJson(a, stream, &state);
        },
        .deneb => {
            var state: ct.deneb.BeaconState.Type = undefined;
            try ct.deneb.BeaconState.deserializeFromBytes(a, state_bytes, &state);
            try ct.deneb.BeaconState.serializeIntoJson(a, stream, &state);
        },
        .electra => {
            var state: ct.electra.BeaconState.Type = undefined;
            try ct.electra.BeaconState.deserializeFromBytes(a, state_bytes, &state);
            try ct.electra.BeaconState.serializeIntoJson(a, stream, &state);
        },
        .fulu => {
            var state: ct.fulu.BeaconState.Type = undefined;
            try ct.fulu.BeaconState.deserializeFromBytes(a, state_bytes, &state);
            try ct.fulu.BeaconState.serializeIntoJson(a, stream, &state);
        },
        .gloas => {
            var state: ct.gloas.BeaconState.Type = undefined;
            try ct.gloas.BeaconState.deserializeFromBytes(a, state_bytes, &state);
            try ct.gloas.BeaconState.serializeIntoJson(a, stream, &state);
        },
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
    if (meta.execution_payload_blinded) |blinded| {
        try stream.objectField("execution_payload_blinded");
        try stream.write(blinded);
    }
    if (meta.execution_payload_source) |source| {
        try stream.objectField("execution_payload_source");
        try stream.write(source.headerValue());
    }
    if (meta.execution_payload_value) |value| {
        try stream.objectField("execution_payload_value");
        var buf: [80]u8 = undefined;
        const formatted = std.fmt.bufPrint(buf[0..], "{d}", .{value}) catch unreachable;
        try stream.write(formatted);
    }
    if (meta.consensus_block_value) |value| {
        try stream.objectField("consensus_block_value");
        var buf: [80]u8 = undefined;
        const formatted = std.fmt.bufPrint(buf[0..], "{d}", .{value}) catch unreachable;
        try stream.write(formatted);
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

test "writeApiEnvelope serializes floats and signed integers" {
    const alloc = std.testing.allocator;
    const value = struct {
        ratio: f64,
        delta: i64,
    }{
        .ratio = 0.875,
        .delta = -12,
    };
    const body = try writeApiEnvelope(alloc, @TypeOf(value), &value, .{});
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"ratio\":0.875") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"delta\":\"-12\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "null") == null);
}

test "writeApiEnvelope serializes top-level slices as arrays" {
    const alloc = std.testing.allocator;
    const Item = struct { index: u64 };
    const values = [_]Item{ .{ .index = 1 }, .{ .index = 2 } };
    const slice: []const Item = values[0..];
    const body = try writeApiEnvelope(alloc, []const Item, &slice, .{});
    defer alloc.free(body);

    try std.testing.expect(std.mem.startsWith(u8, body, "{\"data\":["));
    try std.testing.expect(std.mem.indexOf(u8, body, "\"index\":\"1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"index\":\"2\"") != null);
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
        .float, .comptime_float => {
            try stream.write(value.*);
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
                for (0..arr.len) |i| {
                    try writeApiValue(stream, arr.child, &value.*[i]);
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

/// Serialize an API value into a JSON envelope.
///
/// Top-level slices become `{"data":[...],...}`. All other values become
/// `{"data":<value>,...}`.
pub fn writeApiEnvelope(
    alloc: Allocator,
    comptime T: type,
    value: *const T,
    meta: ResponseMeta,
) ![]u8 {
    return switch (@typeInfo(T)) {
        .pointer => |ptr| if (ptr.size == .slice and ptr.child != u8)
            writeApiArrayEnvelope(alloc, ptr.child, value.*, meta)
        else
            writeApiObjectEnvelope(alloc, T, value, meta),
        else => writeApiObjectEnvelope(alloc, T, value, meta),
    };
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

const ChainConfig = config_mod.ChainConfig;
const SpecConstants = struct {
    GENESIS_SLOT: u64 = constants_mod.GENESIS_SLOT,
    GENESIS_EPOCH: u64 = preset_mod.GENESIS_EPOCH,
    FAR_FUTURE_EPOCH: u64 = constants_mod.FAR_FUTURE_EPOCH,
    BASE_REWARDS_PER_EPOCH: u64 = constants_mod.BASE_REWARDS_PER_EPOCH,
    DEPOSIT_CONTRACT_TREE_DEPTH: u64 = constants_mod.DEPOSIT_CONTRACT_TREE_DEPTH,
    JUSTIFICATION_BITS_LENGTH: u64 = constants_mod.JUSTIFICATION_BITS_LENGTH,
    ENDIANNESS: []const u8 = "little",
    BLS_WITHDRAWAL_PREFIX: [1]u8 = .{constants_mod.BLS_WITHDRAWAL_PREFIX},
    ETH1_ADDRESS_WITHDRAWAL_PREFIX: [1]u8 = .{constants_mod.ETH1_ADDRESS_WITHDRAWAL_PREFIX},
    COMPOUNDING_WITHDRAWAL_PREFIX: [1]u8 = .{constants_mod.COMPOUNDING_WITHDRAWAL_PREFIX},
    DOMAIN_BEACON_PROPOSER: [4]u8 = constants_mod.DOMAIN_BEACON_PROPOSER,
    DOMAIN_BEACON_ATTESTER: [4]u8 = constants_mod.DOMAIN_BEACON_ATTESTER,
    DOMAIN_RANDAO: [4]u8 = constants_mod.DOMAIN_RANDAO,
    DOMAIN_DEPOSIT: [4]u8 = constants_mod.DOMAIN_DEPOSIT,
    DOMAIN_VOLUNTARY_EXIT: [4]u8 = constants_mod.DOMAIN_VOLUNTARY_EXIT,
    DOMAIN_SELECTION_PROOF: [4]u8 = constants_mod.DOMAIN_SELECTION_PROOF,
    DOMAIN_AGGREGATE_AND_PROOF: [4]u8 = constants_mod.DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_APPLICATION_MASK: [4]u8 = constants_mod.DOMAIN_APPLICATION_MASK,
    DOMAIN_APPLICATION_BUILDER: [4]u8 = constants_mod.DOMAIN_APPLICATION_BUILDER,
    TARGET_AGGREGATORS_PER_COMMITTEE: u64 = constants_mod.TARGET_AGGREGATORS_PER_COMMITTEE,
    NODE_ID_BITS: u64 = constants_mod.NODE_ID_BITS,
    ATTESTATION_SUBNET_COUNT: u64 = constants_mod.ATTESTATION_SUBNET_COUNT,
    ATTESTATION_SUBNET_PREFIX_BITS: u64 = constants_mod.ATTESTATION_SUBNET_PREFIX_BITS,
    TIMELY_SOURCE_FLAG_INDEX: u64 = constants_mod.TIMELY_SOURCE_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX: u64 = constants_mod.TIMELY_TARGET_FLAG_INDEX,
    TIMELY_HEAD_FLAG_INDEX: u64 = constants_mod.TIMELY_HEAD_FLAG_INDEX,
    TIMELY_SOURCE_WEIGHT: u64 = constants_mod.TIMELY_SOURCE_WEIGHT,
    TIMELY_TARGET_WEIGHT: u64 = constants_mod.TIMELY_TARGET_WEIGHT,
    TIMELY_HEAD_WEIGHT: u64 = constants_mod.TIMELY_HEAD_WEIGHT,
    SYNC_REWARD_WEIGHT: u64 = constants_mod.SYNC_REWARD_WEIGHT,
    PROPOSER_WEIGHT: u64 = constants_mod.PROPOSER_WEIGHT,
    WEIGHT_DENOMINATOR: u64 = constants_mod.WEIGHT_DENOMINATOR,
    DOMAIN_SYNC_COMMITTEE: [4]u8 = constants_mod.DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: [4]u8 = constants_mod.DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    DOMAIN_CONTRIBUTION_AND_PROOF: [4]u8 = constants_mod.DOMAIN_CONTRIBUTION_AND_PROOF,
    TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = constants_mod.TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    SYNC_COMMITTEE_SUBNET_COUNT: u64 = constants_mod.SYNC_COMMITTEE_SUBNET_COUNT,
    DOMAIN_BLS_TO_EXECUTION_CHANGE: [4]u8 = constants_mod.DOMAIN_BLS_TO_EXECUTION_CHANGE,
    BLOB_TX_TYPE: [1]u8 = .{constants_mod.BLOB_TX_TYPE},
    VERSIONED_HASH_VERSION_KZG: [1]u8 = .{constants_mod.VERSIONED_HASH_VERSION_KZG},
    UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = constants_mod.UNSET_DEPOSIT_REQUESTS_START_INDEX,
    FULL_EXIT_REQUEST_AMOUNT: u64 = constants_mod.FULL_EXIT_REQUEST_AMOUNT,
    DEPOSIT_REQUEST_TYPE: [1]u8 = .{constants_mod.DEPOSIT_REQUEST_TYPE},
    WITHDRAWAL_REQUEST_TYPE: [1]u8 = .{constants_mod.WITHDRAWAL_REQUEST_TYPE},
    CONSOLIDATION_REQUEST_TYPE: [1]u8 = .{constants_mod.CONSOLIDATION_REQUEST_TYPE},
};

const PresetValues = struct {
    MAX_COMMITTEES_PER_SLOT: @TypeOf(preset_mod.preset.MAX_COMMITTEES_PER_SLOT) = preset_mod.preset.MAX_COMMITTEES_PER_SLOT,
    TARGET_COMMITTEE_SIZE: @TypeOf(preset_mod.preset.TARGET_COMMITTEE_SIZE) = preset_mod.preset.TARGET_COMMITTEE_SIZE,
    MAX_VALIDATORS_PER_COMMITTEE: @TypeOf(preset_mod.preset.MAX_VALIDATORS_PER_COMMITTEE) = preset_mod.preset.MAX_VALIDATORS_PER_COMMITTEE,
    SHUFFLE_ROUND_COUNT: @TypeOf(preset_mod.preset.SHUFFLE_ROUND_COUNT) = preset_mod.preset.SHUFFLE_ROUND_COUNT,
    HYSTERESIS_QUOTIENT: @TypeOf(preset_mod.preset.HYSTERESIS_QUOTIENT) = preset_mod.preset.HYSTERESIS_QUOTIENT,
    HYSTERESIS_DOWNWARD_MULTIPLIER: @TypeOf(preset_mod.preset.HYSTERESIS_DOWNWARD_MULTIPLIER) = preset_mod.preset.HYSTERESIS_DOWNWARD_MULTIPLIER,
    HYSTERESIS_UPWARD_MULTIPLIER: @TypeOf(preset_mod.preset.HYSTERESIS_UPWARD_MULTIPLIER) = preset_mod.preset.HYSTERESIS_UPWARD_MULTIPLIER,
    MIN_DEPOSIT_AMOUNT: @TypeOf(preset_mod.preset.MIN_DEPOSIT_AMOUNT) = preset_mod.preset.MIN_DEPOSIT_AMOUNT,
    MAX_EFFECTIVE_BALANCE: @TypeOf(preset_mod.preset.MAX_EFFECTIVE_BALANCE) = preset_mod.preset.MAX_EFFECTIVE_BALANCE,
    EFFECTIVE_BALANCE_INCREMENT: @TypeOf(preset_mod.preset.EFFECTIVE_BALANCE_INCREMENT) = preset_mod.preset.EFFECTIVE_BALANCE_INCREMENT,
    MIN_ATTESTATION_INCLUSION_DELAY: @TypeOf(preset_mod.preset.MIN_ATTESTATION_INCLUSION_DELAY) = preset_mod.preset.MIN_ATTESTATION_INCLUSION_DELAY,
    SLOTS_PER_EPOCH: @TypeOf(preset_mod.preset.SLOTS_PER_EPOCH) = preset_mod.preset.SLOTS_PER_EPOCH,
    MIN_SEED_LOOKAHEAD: @TypeOf(preset_mod.preset.MIN_SEED_LOOKAHEAD) = preset_mod.preset.MIN_SEED_LOOKAHEAD,
    MAX_SEED_LOOKAHEAD: @TypeOf(preset_mod.preset.MAX_SEED_LOOKAHEAD) = preset_mod.preset.MAX_SEED_LOOKAHEAD,
    EPOCHS_PER_ETH1_VOTING_PERIOD: @TypeOf(preset_mod.preset.EPOCHS_PER_ETH1_VOTING_PERIOD) = preset_mod.preset.EPOCHS_PER_ETH1_VOTING_PERIOD,
    SLOTS_PER_HISTORICAL_ROOT: @TypeOf(preset_mod.preset.SLOTS_PER_HISTORICAL_ROOT) = preset_mod.preset.SLOTS_PER_HISTORICAL_ROOT,
    MIN_EPOCHS_TO_INACTIVITY_PENALTY: @TypeOf(preset_mod.preset.MIN_EPOCHS_TO_INACTIVITY_PENALTY) = preset_mod.preset.MIN_EPOCHS_TO_INACTIVITY_PENALTY,
    EPOCHS_PER_HISTORICAL_VECTOR: @TypeOf(preset_mod.preset.EPOCHS_PER_HISTORICAL_VECTOR) = preset_mod.preset.EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR: @TypeOf(preset_mod.preset.EPOCHS_PER_SLASHINGS_VECTOR) = preset_mod.preset.EPOCHS_PER_SLASHINGS_VECTOR,
    HISTORICAL_ROOTS_LIMIT: @TypeOf(preset_mod.preset.HISTORICAL_ROOTS_LIMIT) = preset_mod.preset.HISTORICAL_ROOTS_LIMIT,
    VALIDATOR_REGISTRY_LIMIT: @TypeOf(preset_mod.preset.VALIDATOR_REGISTRY_LIMIT) = preset_mod.preset.VALIDATOR_REGISTRY_LIMIT,
    BASE_REWARD_FACTOR: @TypeOf(preset_mod.preset.BASE_REWARD_FACTOR) = preset_mod.preset.BASE_REWARD_FACTOR,
    WHISTLEBLOWER_REWARD_QUOTIENT: @TypeOf(preset_mod.preset.WHISTLEBLOWER_REWARD_QUOTIENT) = preset_mod.preset.WHISTLEBLOWER_REWARD_QUOTIENT,
    PROPOSER_REWARD_QUOTIENT: @TypeOf(preset_mod.preset.PROPOSER_REWARD_QUOTIENT) = preset_mod.preset.PROPOSER_REWARD_QUOTIENT,
    INACTIVITY_PENALTY_QUOTIENT: @TypeOf(preset_mod.preset.INACTIVITY_PENALTY_QUOTIENT) = preset_mod.preset.INACTIVITY_PENALTY_QUOTIENT,
    MIN_SLASHING_PENALTY_QUOTIENT: @TypeOf(preset_mod.preset.MIN_SLASHING_PENALTY_QUOTIENT) = preset_mod.preset.MIN_SLASHING_PENALTY_QUOTIENT,
    PROPORTIONAL_SLASHING_MULTIPLIER: @TypeOf(preset_mod.preset.PROPORTIONAL_SLASHING_MULTIPLIER) = preset_mod.preset.PROPORTIONAL_SLASHING_MULTIPLIER,
    MAX_PROPOSER_SLASHINGS: @TypeOf(preset_mod.preset.MAX_PROPOSER_SLASHINGS) = preset_mod.preset.MAX_PROPOSER_SLASHINGS,
    MAX_ATTESTER_SLASHINGS: @TypeOf(preset_mod.preset.MAX_ATTESTER_SLASHINGS) = preset_mod.preset.MAX_ATTESTER_SLASHINGS,
    MAX_ATTESTATIONS: @TypeOf(preset_mod.preset.MAX_ATTESTATIONS) = preset_mod.preset.MAX_ATTESTATIONS,
    MAX_DEPOSITS: @TypeOf(preset_mod.preset.MAX_DEPOSITS) = preset_mod.preset.MAX_DEPOSITS,
    MAX_VOLUNTARY_EXITS: @TypeOf(preset_mod.preset.MAX_VOLUNTARY_EXITS) = preset_mod.preset.MAX_VOLUNTARY_EXITS,
    SYNC_COMMITTEE_SIZE: @TypeOf(preset_mod.preset.SYNC_COMMITTEE_SIZE) = preset_mod.preset.SYNC_COMMITTEE_SIZE,
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD: @TypeOf(preset_mod.preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD) = preset_mod.preset.EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
    INACTIVITY_PENALTY_QUOTIENT_ALTAIR: @TypeOf(preset_mod.preset.INACTIVITY_PENALTY_QUOTIENT_ALTAIR) = preset_mod.preset.INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
    MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: @TypeOf(preset_mod.preset.MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR) = preset_mod.preset.MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
    PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: @TypeOf(preset_mod.preset.PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR) = preset_mod.preset.PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR,
    MIN_SYNC_COMMITTEE_PARTICIPANTS: @TypeOf(preset_mod.preset.MIN_SYNC_COMMITTEE_PARTICIPANTS) = preset_mod.preset.MIN_SYNC_COMMITTEE_PARTICIPANTS,
    UPDATE_TIMEOUT: @TypeOf(preset_mod.preset.UPDATE_TIMEOUT) = preset_mod.preset.UPDATE_TIMEOUT,
    INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: @TypeOf(preset_mod.preset.INACTIVITY_PENALTY_QUOTIENT_BELLATRIX) = preset_mod.preset.INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
    MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: @TypeOf(preset_mod.preset.MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX) = preset_mod.preset.MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
    PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: @TypeOf(preset_mod.preset.PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX) = preset_mod.preset.PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
    MAX_BYTES_PER_TRANSACTION: @TypeOf(preset_mod.preset.MAX_BYTES_PER_TRANSACTION) = preset_mod.preset.MAX_BYTES_PER_TRANSACTION,
    MAX_TRANSACTIONS_PER_PAYLOAD: @TypeOf(preset_mod.preset.MAX_TRANSACTIONS_PER_PAYLOAD) = preset_mod.preset.MAX_TRANSACTIONS_PER_PAYLOAD,
    BYTES_PER_LOGS_BLOOM: @TypeOf(preset_mod.preset.BYTES_PER_LOGS_BLOOM) = preset_mod.preset.BYTES_PER_LOGS_BLOOM,
    MAX_EXTRA_DATA_BYTES: @TypeOf(preset_mod.preset.MAX_EXTRA_DATA_BYTES) = preset_mod.preset.MAX_EXTRA_DATA_BYTES,
    MAX_BLS_TO_EXECUTION_CHANGES: @TypeOf(preset_mod.preset.MAX_BLS_TO_EXECUTION_CHANGES) = preset_mod.preset.MAX_BLS_TO_EXECUTION_CHANGES,
    MAX_WITHDRAWALS_PER_PAYLOAD: @TypeOf(preset_mod.preset.MAX_WITHDRAWALS_PER_PAYLOAD) = preset_mod.preset.MAX_WITHDRAWALS_PER_PAYLOAD,
    MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: @TypeOf(preset_mod.preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) = preset_mod.preset.MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP,
    FIELD_ELEMENTS_PER_BLOB: @TypeOf(preset_mod.preset.FIELD_ELEMENTS_PER_BLOB) = preset_mod.preset.FIELD_ELEMENTS_PER_BLOB,
    MAX_BLOB_COMMITMENTS_PER_BLOCK: @TypeOf(preset_mod.preset.MAX_BLOB_COMMITMENTS_PER_BLOCK) = preset_mod.preset.MAX_BLOB_COMMITMENTS_PER_BLOCK,
    MAX_BLOBS_PER_BLOCK: @TypeOf(preset_mod.preset.MAX_BLOBS_PER_BLOCK) = preset_mod.preset.MAX_BLOBS_PER_BLOCK,
    KZG_COMMITMENT_INCLUSION_PROOF_DEPTH: @TypeOf(preset_mod.preset.KZG_COMMITMENT_INCLUSION_PROOF_DEPTH) = preset_mod.preset.KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
    MIN_ACTIVATION_BALANCE: @TypeOf(preset_mod.preset.MIN_ACTIVATION_BALANCE) = preset_mod.preset.MIN_ACTIVATION_BALANCE,
    MAX_EFFECTIVE_BALANCE_ELECTRA: @TypeOf(preset_mod.preset.MAX_EFFECTIVE_BALANCE_ELECTRA) = preset_mod.preset.MAX_EFFECTIVE_BALANCE_ELECTRA,
    PENDING_DEPOSITS_LIMIT: @TypeOf(preset_mod.preset.PENDING_DEPOSITS_LIMIT) = preset_mod.preset.PENDING_DEPOSITS_LIMIT,
    PENDING_PARTIAL_WITHDRAWALS_LIMIT: @TypeOf(preset_mod.preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT) = preset_mod.preset.PENDING_PARTIAL_WITHDRAWALS_LIMIT,
    PENDING_CONSOLIDATIONS_LIMIT: @TypeOf(preset_mod.preset.PENDING_CONSOLIDATIONS_LIMIT) = preset_mod.preset.PENDING_CONSOLIDATIONS_LIMIT,
    MAX_ATTESTER_SLASHINGS_ELECTRA: @TypeOf(preset_mod.preset.MAX_ATTESTER_SLASHINGS_ELECTRA) = preset_mod.preset.MAX_ATTESTER_SLASHINGS_ELECTRA,
    MAX_ATTESTATIONS_ELECTRA: @TypeOf(preset_mod.preset.MAX_ATTESTATIONS_ELECTRA) = preset_mod.preset.MAX_ATTESTATIONS_ELECTRA,
    MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: @TypeOf(preset_mod.preset.MAX_DEPOSIT_REQUESTS_PER_PAYLOAD) = preset_mod.preset.MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
    MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: @TypeOf(preset_mod.preset.MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD) = preset_mod.preset.MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
    MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: @TypeOf(preset_mod.preset.MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD) = preset_mod.preset.MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: @TypeOf(preset_mod.preset.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA) = preset_mod.preset.WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
    MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: @TypeOf(preset_mod.preset.MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA) = preset_mod.preset.MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
    FIELD_ELEMENTS_PER_CELL: @TypeOf(preset_mod.preset.FIELD_ELEMENTS_PER_CELL) = preset_mod.preset.FIELD_ELEMENTS_PER_CELL,
    FIELD_ELEMENTS_PER_EXT_BLOB: @TypeOf(preset_mod.preset.FIELD_ELEMENTS_PER_EXT_BLOB) = preset_mod.preset.FIELD_ELEMENTS_PER_EXT_BLOB,
    KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: @TypeOf(preset_mod.preset.KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH) = preset_mod.preset.KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
    MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: @TypeOf(preset_mod.preset.MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP) = preset_mod.preset.MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP,
    DEPOSIT_CONTRACT_TREE_DEPTH: @TypeOf(preset_mod.preset.DEPOSIT_CONTRACT_TREE_DEPTH) = preset_mod.preset.DEPOSIT_CONTRACT_TREE_DEPTH,
    GENESIS_SLOT: @TypeOf(preset_mod.preset.GENESIS_SLOT) = preset_mod.preset.GENESIS_SLOT,
    MAX_PENDING_DEPOSITS_PER_EPOCH: @TypeOf(preset_mod.preset.MAX_PENDING_DEPOSITS_PER_EPOCH) = preset_mod.preset.MAX_PENDING_DEPOSITS_PER_EPOCH,
    PTC_SIZE: @TypeOf(preset_mod.preset.PTC_SIZE) = preset_mod.preset.PTC_SIZE,
    MAX_PAYLOAD_ATTESTATIONS: @TypeOf(preset_mod.preset.MAX_PAYLOAD_ATTESTATIONS) = preset_mod.preset.MAX_PAYLOAD_ATTESTATIONS,
    BUILDER_REGISTRY_LIMIT: @TypeOf(preset_mod.preset.BUILDER_REGISTRY_LIMIT) = preset_mod.preset.BUILDER_REGISTRY_LIMIT,
    BUILDER_PENDING_WITHDRAWALS_LIMIT: @TypeOf(preset_mod.preset.BUILDER_PENDING_WITHDRAWALS_LIMIT) = preset_mod.preset.BUILDER_PENDING_WITHDRAWALS_LIMIT,
};

pub fn writeConfigSpecEnvelope(
    alloc: Allocator,
    chain_config: *const ChainConfig,
    meta: ResponseMeta,
) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"data\":{");
    var first = true;

    inline for (std.meta.fields(ChainConfig)) |field| {
        try appendSpecField(alloc, &buf, &first, field.name, @field(chain_config.*, field.name));
    }

    const preset_values = PresetValues{};
    inline for (std.meta.fields(PresetValues)) |field| {
        if (!@hasField(SpecConstants, field.name)) {
            try appendSpecField(alloc, &buf, &first, field.name, @field(preset_values, field.name));
        }
    }

    const spec_constants = SpecConstants{};
    inline for (std.meta.fields(SpecConstants)) |field| {
        try appendSpecField(alloc, &buf, &first, field.name, @field(spec_constants, field.name));
    }

    try buf.append(alloc, '}');
    try appendMetaFieldsRaw(alloc, &buf, meta);
    try buf.append(alloc, '}');
    return buf.toOwnedSlice(alloc);
}

fn appendSpecField(
    alloc: Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    first: *bool,
    comptime name: []const u8,
    value: anytype,
) !void {
    if (!first.*) try buf.append(alloc, ',');
    first.* = false;
    try buf.append(alloc, '"');
    try buf.appendSlice(alloc, name);
    try buf.appendSlice(alloc, "\":");
    try appendSpecValue(alloc, buf, value);
}

fn appendSpecValue(alloc: Allocator, buf: *std.ArrayListUnmanaged(u8), value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int, .comptime_int => {
            const text = try std.fmt.allocPrint(alloc, "{d}", .{value});
            defer alloc.free(text);
            try appendJsonString(alloc, buf, text);
        },
        .bool => try appendJsonString(alloc, buf, if (value) "true" else "false"),
        .@"enum" => {
            const text = if (@hasDecl(T, "name")) value.name() else @tagName(value);
            try appendJsonString(alloc, buf, text);
        },
        .array => |arr| {
            if (arr.child != u8) return error.InvalidResponseData;
            const hex = std.fmt.bytesToHex(&value, .lower);
            const text = try std.fmt.allocPrint(alloc, "0x{s}", .{&hex});
            defer alloc.free(text);
            try appendJsonString(alloc, buf, text);
        },
        .pointer => |ptr| {
            if (ptr.size == .slice and ptr.child == u8) {
                try appendJsonString(alloc, buf, value);
            } else if (ptr.size == .slice) {
                try buf.append(alloc, '[');
                for (value, 0..) |item, i| {
                    if (i > 0) try buf.append(alloc, ',');
                    try appendSpecStructObject(alloc, buf, item);
                }
                try buf.append(alloc, ']');
            } else {
                return error.InvalidResponseData;
            }
        },
        .@"struct" => try appendSpecStructObject(alloc, buf, value),
        else => return error.InvalidResponseData,
    }
}

fn appendSpecStructObject(alloc: Allocator, buf: *std.ArrayListUnmanaged(u8), value: anytype) !void {
    try buf.append(alloc, '{');
    var first = true;
    inline for (std.meta.fields(@TypeOf(value))) |field| {
        try appendSpecField(alloc, buf, &first, field.name, @field(value, field.name));
    }
    try buf.append(alloc, '}');
}

fn appendJsonString(alloc: Allocator, buf: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try stream.write(value);
    const encoded = try aw.toOwnedSlice();
    defer alloc.free(encoded);
    try buf.appendSlice(alloc, encoded);
}

fn appendMetaFieldsRaw(alloc: Allocator, buf: *std.ArrayListUnmanaged(u8), meta: ResponseMeta) !void {
    if (meta.version) |fork| {
        try buf.appendSlice(alloc, ",\"version\":\"");
        try buf.appendSlice(alloc, fork.toString());
        try buf.append(alloc, '"');
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
        try buf.append(alloc, '"');
    }
}

pub fn writeKeymanagerDeleteKeystoresEnvelope(
    alloc: Allocator,
    value: api_types.KeymanagerDeleteKeystoresResponse,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");
    try writeApiValue(&stream, []const api_types.KeymanagerOperationResult, &value.data);
    try stream.objectField("slashing_protection");
    if (value.slashing_protection) |slashing_protection| {
        try writeApiValue(&stream, api_types.KeymanagerInterchangeFormat, &slashing_protection);
    } else {
        try stream.beginObject();
        try stream.endObject();
    }
    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}

fn encodeApiValueAlloc(alloc: Allocator, comptime T: type, value: *const T) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };
    try writeApiValue(&stream, T, value);
    return aw.toOwnedSlice();
}

pub fn writeKeymanagerProposerConfigEnvelope(
    alloc: Allocator,
    value: ?api_types.KeymanagerProposerConfigData,
    meta: ResponseMeta,
) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(alloc);
    errdefer aw.deinit();
    var stream: std.json.Stringify = .{ .writer = &aw.writer };

    try stream.beginObject();
    try stream.objectField("data");
    if (value) |config| {
        try writeKeymanagerProposerConfig(&stream, config);
    } else {
        try stream.write(null);
    }
    try writeMetaFields(&stream, meta);
    try stream.endObject();

    return aw.toOwnedSlice();
}

fn writeKeymanagerProposerConfig(stream: *std.json.Stringify, value: api_types.KeymanagerProposerConfigData) !void {
    try stream.beginObject();

    if (value.graffiti) |graffiti| {
        try stream.objectField("graffiti");
        try stream.write(graffiti);
    }
    if (value.strictFeeRecipientCheck) |strict| {
        try stream.objectField("strictFeeRecipientCheck");
        try stream.write(strict);
    }
    if (value.feeRecipient) |fee_recipient| {
        var fee_hex: [42]u8 = undefined;
        fee_hex[0] = '0';
        fee_hex[1] = 'x';
        _ = std.fmt.bufPrint(fee_hex[2..], "{x}", .{fee_recipient}) catch unreachable;
        try stream.objectField("feeRecipient");
        try stream.write(fee_hex[0..]);
    }
    if (value.builder) |builder| {
        if (builder.selection != null or builder.gasLimit != null or builder.boostFactor != null) {
            try stream.objectField("builder");
            try stream.beginObject();
            if (builder.selection) |selection| {
                try stream.objectField("selection");
                try stream.write(selection.queryValue());
            }
            if (builder.gasLimit) |gas_limit| {
                try stream.objectField("gasLimit");
                try stream.write(gas_limit);
            }
            if (builder.boostFactor) |boost_factor| {
                var boost_buf: [32]u8 = undefined;
                const boost_text = std.fmt.bufPrint(boost_buf[0..], "{d}", .{boost_factor}) catch unreachable;
                try stream.objectField("boostFactor");
                try stream.write(boost_text);
            }
            try stream.endObject();
        }
    }

    try stream.endObject();
}

test "writeConfigSpecEnvelope renders spec-style keys and string values" {
    const alloc = std.testing.allocator;
    const body = try writeConfigSpecEnvelope(alloc, &config_mod.mainnet.chain_config, .{});
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"CONFIG_NAME\":\"mainnet\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"SECONDS_PER_ETH1_BLOCK\":\"14\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"DEPOSIT_CONTRACT_ADDRESS\":\"0x00000000219ab540356cbb839cbe05303d7705fa\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"DEPOSIT_REQUEST_TYPE\":\"0x00\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"BLOB_SCHEDULE\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "config_name") == null);
}

test "writeKeymanagerDeleteKeystoresEnvelope writes typed slashing protection" {
    const alloc = std.testing.allocator;
    const statuses = try alloc.dupe(api_types.KeymanagerOperationResult, &.{.{ .status = .deleted }});
    defer alloc.free(statuses);

    const signed_blocks = try alloc.dupe(api_types.KeymanagerInterchangeSignedBlock, &.{.{ .slot = "12", .signing_root = null }});
    defer alloc.free(signed_blocks);
    const signed_attestations = try alloc.dupe(api_types.KeymanagerInterchangeSignedAttestation, &.{.{ .source_epoch = "3", .target_epoch = "5", .signing_root = null }});
    defer alloc.free(signed_attestations);
    const data = try alloc.dupe(api_types.KeymanagerInterchangeData, &.{.{
        .pubkey = "0x" ++ "11" ** 48,
        .signed_blocks = signed_blocks,
        .signed_attestations = signed_attestations,
    }});
    defer alloc.free(data);

    const body = try writeKeymanagerDeleteKeystoresEnvelope(alloc, .{
        .data = statuses,
        .slashing_protection = .{
            .metadata = .{
                .interchange_format_version = "5",
                .genesis_validators_root = "0x" ++ "22" ** 32,
            },
            .data = data,
        },
    }, .{});
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"slashing_protection\":{\"metadata\":{\"interchange_format_version\":\"5\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"pubkey\":\"0x" ++ "11" ** 48 ++ "\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"slot\":\"12\"") != null);
}

test "writeKeymanagerProposerConfigEnvelope omits absent fields" {
    const alloc = std.testing.allocator;
    const value = api_types.KeymanagerProposerConfigData{
        .feeRecipient = [_]u8{0x11} ** 20,
        .builder = .{ .gasLimit = 60_000_000, .boostFactor = 125 },
    };
    const body = try writeKeymanagerProposerConfigEnvelope(alloc, value, .{});
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\"feeRecipient\":\"0x1111111111111111111111111111111111111111\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"gasLimit\":60000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"boostFactor\":\"125\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "strictFeeRecipientCheck") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "graffiti") == null);
}
