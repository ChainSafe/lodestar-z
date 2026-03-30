# JSON Serializer Design — Beacon API

## Status

**Draft** — 2026-03-29

## Problem

The Beacon REST API requires ~60 endpoints to serialize responses as JSON. Currently, ~30 handlers build JSON via string concatenation (`appendSlice`, `allocPrint`, `std.fmt.format`). This approach:

1. **Is brittle** — missing commas, wrong nesting, broken hex encoding (multiple bugs traced here)
2. **Duplicates the envelope** — every handler re-implements `{"data":...,"execution_optimistic":...}`
3. **Is inconsistent** — some handlers use `writeJsonValue` (recursive, type-dispatched), others use `allocPrint` templates, others use manual `appendSlice` chains
4. **Doesn't follow Beacon API encoding rules** — `u64` values must be quoted decimal strings (`"12345"`), but `writeJsonValue` emits bare integers (`12345`)
5. **Allocates heavily** — per-field `allocPrint` + intermediate strings + final concatenation

The existing `writeJsonValue` in `response.zig` is the right idea but incomplete:
- Doesn't quote `u64` (Beacon API requires quoted decimals)
- Doesn't handle SSZ type wrappers (`ssz.UintType(64).Type` is just `u64`, but `ssz.BitListType(N).Type` is a `BitList(N)` struct)
- Doesn't handle optional fields (emits `null` instead of omitting)
- Doesn't know about the API types that sit between handlers and consensus types

## Design

### 1. API Design

A single generic function `beaconJsonStringify` that:
- Accepts any type and a writer
- Uses comptime type introspection to select the correct encoding
- Streams directly to the writer (zero intermediate allocations)

Plus an envelope helper that wraps the data with `ResponseMeta`.

#### Public API

```zig
/// src/api/json.zig

const std = @import("std");

pub const BeaconJsonError = std.Io.Writer.Error;

/// Serialize any Beacon API type to JSON, following Beacon API encoding rules.
/// Streams directly to writer — zero heap allocation.
pub fn beaconJsonStringify(
    writer: anytype, // std.Io.Writer or std.io.Writer
    comptime T: type,
    value: *const T,
) BeaconJsonError!void { ... }

/// Write the full Beacon API envelope: {"data": <payload>, ...metadata...}
pub fn writeEnvelope(
    writer: anytype,
    comptime T: type,
    value: *const T,
    meta: ResponseMeta,
) BeaconJsonError!void { ... }

/// Write the full Beacon API envelope for an array payload:
/// {"data": [<items>], ...metadata...}
pub fn writeArrayEnvelope(
    writer: anytype,
    comptime T: type,
    items: []const T,
    meta: ResponseMeta,
) BeaconJsonError!void { ... }
```

#### Example Usage

**Simple object — `getNodeVersion`:**
```zig
fn hGetNodeVersion(self: *HttpServer, _: DispatchContext) !HandlerResult {
    const result = handlers.node.getVersion(self.api_context);
    return self.makeJsonResultV2(types.NodeVersion, result);
}

// In makeJsonResultV2:
fn makeJsonResultV2(self: *HttpServer, comptime T: type, result: handler_result_mod.HandlerResult(T)) !HandlerResult {
    var aw: IoWriter.Allocating = .init(self.allocator);
    errdefer aw.deinit();
    try json.writeEnvelope(&aw.writer, T, &result.data, result.meta);
    return .{ .status = 200, .content_type = "application/json", .body = aw.toOwnedSlice() };
}
```

Output: `{"data":{"version":"lodestar-z/v0.0.1/x86_64-linux"}}`

**Array of objects — `getValidators`:**
```zig
fn hGetStateValidatorsV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
    // ... parse state_id ...
    const handler_res = try handlers.beacon.getValidators(self.api_context, state_id, .{});
    defer self.allocator.free(handler_res.data);

    var aw: IoWriter.Allocating = .init(self.allocator);
    errdefer aw.deinit();
    try json.writeArrayEnvelope(&aw.writer, types.ValidatorData, handler_res.data, handler_res.meta);
    return .{ .status = 200, .content_type = "application/json", .body = aw.toOwnedSlice() };
}
```

Output:
```json
{"data":[{"index":"0","balance":"32000000000","status":"active_ongoing","validator":{"pubkey":"0xabcd...","withdrawal_credentials":"0x0100...","effective_balance":"32000000000","slashed":false,"activation_eligibility_epoch":"0","activation_epoch":"0","exit_epoch":"18446744073709551615","withdrawable_epoch":"18446744073709551615"}}],"execution_optimistic":false,"finalized":false}
```

Note: `u64` fields like `index`, `balance`, `effective_balance`, `activation_epoch` are all quoted strings. `[48]u8` pubkey is hex-encoded. `bool` stays as JSON boolean. `enum` (status) is a lowercase string.

**Nested with hex bytes — `getBlockHeader`:**
```zig
fn hGetBlockHeader(self: *HttpServer, dc: DispatchContext) !HandlerResult {
    const block_id = try types.BlockId.parse(dc.match.getParam("block_id") orelse return error.InvalidBlockId);
    const result = try handlers.beacon.getBlockHeader(self.api_context, block_id);
    return self.makeJsonResultV2(types.BlockHeaderData, result);
}
```

Output:
```json
{"data":{"root":"0x1234...","canonical":true,"header":{"message":{"slot":"100","proposer_index":"42","parent_root":"0xabcd...","state_root":"0xef01...","body_root":"0x2345..."},"signature":"0x9876..."}},"execution_optimistic":false,"finalized":true}
```

The serializer recursively descends: `BlockHeaderData` → struct → `root: [32]u8` → hex, `header: SignedHeaderData` → struct → `message: BlockHeaderMessage` → struct → `slot: u64` → quoted decimal, etc.

**Fork-polymorphic — `getBlockV2` (raw SSZ bytes):**

For endpoints that return raw SSZ bytes (block, state), the serializer isn't used for the payload directly. These endpoints already return pre-serialized SSZ and need special handling:

```zig
fn hGetBlockV2(self: *HttpServer, dc: DispatchContext) !HandlerResult {
    const block_result = try handlers.beacon.getBlock(self.api_context, block_id);
    const meta = ResponseMeta{
        .version = block_result.fork_name,
        .execution_optimistic = block_result.execution_optimistic,
        .finalized = block_result.finalized,
    };

    if (dc.format == .ssz) {
        return .{ .status = 200, .content_type = "application/octet-stream",
                  .body = try alloc.dupe(u8, block_result.data), .meta = meta };
    }

    // For JSON: wrap raw SSZ bytes as hex in the envelope
    var aw: IoWriter.Allocating = .init(alloc);
    errdefer aw.deinit();
    try json.writeRawBytesEnvelope(&aw.writer, block_result.data, meta);
    return .{ .status = 200, .content_type = "application/json",
              .body = aw.toOwnedSlice(), .meta = meta };
}
```

For endpoints that will eventually deserialize and re-serialize as typed JSON (future work), the fork-polymorphic pattern uses `ForkTypes`:

```zig
// Future: typed block JSON serialization
fn writeBlockJson(writer: anytype, fork: Fork, block_bytes: []const u8) !void {
    switch (fork) {
        .phase0 => {
            var block: consensus_types.phase0.SignedBeaconBlock.Type = undefined;
            try consensus_types.phase0.SignedBeaconBlock.deserializeFromBytes(block_bytes, &block);
            try beaconJsonStringify(writer, consensus_types.phase0.SignedBeaconBlock.Type, &block);
        },
        .altair => { /* same pattern with altair types */ },
        // ...
    }
}
```

### 2. Type Mapping Rules

#### Core Mapping Table

| Zig Type | JSON Output | Example |
|---|---|---|
| `bool` | `true` / `false` | `true` |
| `u8`, `u16`, `u32` | Bare number | `42` |
| `u64`, `u128`, `u256` | Quoted decimal string | `"18446744073709551615"` |
| `i64` | Quoted decimal string | `"-100"` |
| `[N]u8` (byte arrays) | `"0x"` + hex | `"0xdeadbeef"` |
| `[]const u8` (strings) | Quoted string | `"hello"` |
| `[]const T` (slices) | JSON array | `[1, 2, 3]` |
| `enum` | Lowercase tag name | `"active_ongoing"` |
| `?T` (optional) | **Omit field** if null | field not present |
| `struct` | JSON object | `{"a": 1, "b": 2}` |
| `void` | Nothing (empty body) | |

#### Why `u64` is quoted but `u32` is not

The Beacon API spec explicitly requires quantities that can exceed JavaScript's `Number.MAX_SAFE_INTEGER` (2^53) to be encoded as quoted strings. In practice, the spec quotes all `uint64` values. Smaller integers (`u8`, `u16`, `u32`) are always safe as bare numbers.

**Detection rule (comptime):**
```zig
fn shouldQuoteInt(comptime T: type) bool {
    return @typeInfo(T).int.bits >= 64;
}
```

#### SSZ Type Wrappers

The consensus types use SSZ type constructors. The `.Type` field is what handlers work with at runtime:

| SSZ Type | `.Type` | JSON treatment |
|---|---|---|
| `ssz.UintType(64)` | `u64` | Quoted decimal `"12345"` |
| `ssz.UintType(8)` | `u8` | Bare number `8` |
| `ssz.BoolType()` | `bool` | `true`/`false` |
| `ssz.ByteVectorType(32)` | `[32]u8` | `"0x..."` (64 hex chars) |
| `ssz.ByteVectorType(48)` | `[48]u8` | `"0x..."` (96 hex chars) |
| `ssz.ByteVectorType(96)` | `[96]u8` | `"0x..."` (192 hex chars) |
| `ssz.BitListType(N)` | `BitList(N)` | `"0x..."` (serialized hex) |
| `ssz.BitVectorType(N)` | `BitVector(N)` | `"0x..."` (raw bytes hex) |
| `ssz.FixedContainerType(S)` | `@Struct(...)` | JSON object, recurse fields |
| `ssz.VariableContainerType(S)` | `@Struct(...)` | JSON object, recurse fields |
| `ssz.FixedListType(E, N)` | `ArrayListUnmanaged(E.Type)` | JSON array via `.items` |
| `ssz.FixedVectorType(E, N)` | depends | JSON array |

**Key insight:** Handlers don't work with SSZ types directly — they work with the `.Type` inner types. The serializer only sees standard Zig types (`u64`, `[32]u8`, `bool`, structs, `ArrayListUnmanaged`). The SSZ wrapper is invisible at runtime.

**Exception: `BitList` and `BitVector`** — these are custom structs with a `.data` field (byte slice/array). The serializer needs special detection for these.

#### Detecting BitList and BitVector

```zig
fn isBitList(comptime T: type) bool {
    return @hasField(T, "data") and @hasField(T, "bit_len") and
           @hasDecl(T, "empty");
}

fn isBitVector(comptime T: type) bool {
    return @hasField(T, "data") and @hasDecl(T, "length") and
           !@hasField(T, "bit_len");
}
```

For `BitList`: serialize `data.items[0..byte_len]` as `"0x"` + hex (where byte_len includes the length bit per SSZ bitlist encoding).\
For `BitVector`: serialize `data` array directly as `"0x"` + hex.

#### Custom Field Names

Currently, the API types in `types.zig` use Zig field names that match the Beacon API spec (snake_case). This is intentional and should be maintained. If a Zig name ever diverges from the API name, we support a comptime override map:

```zig
/// Optional: per-type field name mapping.
/// If T has a `pub const json_field_names` declaration, use it.
///
/// Example:
///   const MyType = struct {
///       pub const json_field_names = .{
///           .zig_field = "apiFieldName",
///       };
///       zig_field: u64,
///   };
fn jsonFieldName(comptime T: type, comptime field_name: []const u8) []const u8 {
    if (@hasDecl(T, "json_field_names")) {
        const map = T.json_field_names;
        if (@hasField(@TypeOf(map), field_name)) {
            return @field(map, field_name);
        }
    }
    return field_name;
}
```

**Current state:** Not needed today. All API types already use spec-matching names. This is a future escape hatch.

### 3. Implementation Strategy

#### Comptime Type Introspection

The core serializer is a single recursive `fn beaconJsonStringify` that dispatches on `@typeInfo(T)`:

```zig
fn beaconJsonStringify(writer: anytype, comptime T: type, value: *const T) !void {
    const info = @typeInfo(T);

    // 1. Check for special types first (BitList, BitVector, ArrayListUnmanaged)
    if (comptime isBitList(T)) return writeBitListHex(writer, value);
    if (comptime isBitVector(T)) return writeBitVectorHex(writer, value);
    if (comptime isArrayList(T)) return writeArrayList(writer, T, value);

    switch (info) {
        .bool => try writer.writeAll(if (value.*) "true" else "false"),

        .int => |int_info| {
            if (int_info.bits >= 64) {
                // Quoted decimal: "12345"
                try writer.writeByte('"');
                try std.fmt.formatInt(value.*, 10, .lower, .{}, writer);
                try writer.writeByte('"');
            } else {
                // Bare decimal: 12345
                try std.fmt.formatInt(value.*, 10, .lower, .{}, writer);
            }
        },

        .array => |arr| {
            if (arr.child == u8) {
                // Byte array → "0x" + hex
                try writeHexBytes(writer, &value.*);
            } else {
                // Regular array → JSON array
                try writeJsonArray(writer, arr.child, &value.*);
            }
        },

        .pointer => |ptr| {
            if (ptr.size == .slice) {
                if (ptr.child == u8) {
                    // []const u8 → quoted string
                    try writeJsonString(writer, value.*);
                } else {
                    // []const T → JSON array
                    try writeJsonSlice(writer, ptr.child, value.*);
                }
            }
        },

        .optional => |opt| {
            // Optionals at top level: emit "null"
            // Optionals as struct fields: handled by struct serializer (omit if null)
            if (value.*) |*inner| {
                try beaconJsonStringify(writer, opt.child, inner);
            } else {
                try writer.writeAll("null");
            }
        },

        .@"struct" => try writeJsonStruct(writer, T, value),

        .@"enum" => {
            try writer.writeByte('"');
            try writer.writeAll(@tagName(value.*));
            try writer.writeByte('"');
        },

        else => try writer.writeAll("null"),
    }
}
```

#### Struct Serialization with Optional Field Omission

```zig
fn writeJsonStruct(writer: anytype, comptime T: type, value: *const T) !void {
    const fields = @typeInfo(T).@"struct".fields;
    try writer.writeByte('{');
    var first = true;

    inline for (fields) |field| {
        const field_value = &@field(value.*, field.name);

        // Skip optional fields that are null
        if (@typeInfo(field.type) == .optional) {
            if (field_value.* == null) continue;
        }

        if (!first) try writer.writeByte(',');
        first = false;

        // Write field name (with possible rename)
        try writer.writeByte('"');
        try writer.writeAll(comptime jsonFieldName(T, field.name));
        try writer.writeAll("\":");

        // Write field value
        if (@typeInfo(field.type) == .optional) {
            // Unwrap the optional (we know it's non-null from the check above)
            try beaconJsonStringify(writer, @typeInfo(field.type).optional.child, &field_value.*.?);
        } else {
            try beaconJsonStringify(writer, field.type, field_value);
        }
    }

    try writer.writeByte('}');
}
```

#### Streaming Hex Encoding (Zero Allocation)

```zig
fn writeHexBytes(writer: anytype, bytes: []const u8) !void {
    try writer.writeAll("\"0x");
    for (bytes) |byte| {
        const hex = "0123456789abcdef";
        try writer.writeByte(hex[byte >> 4]);
        try writer.writeByte(hex[byte & 0x0f]);
    }
    try writer.writeByte('"');
}
```

This writes hex character-by-character with zero allocation. For large byte arrays (e.g., 96-byte BLS signatures), this is 192 writer calls but each is a single byte — the underlying buffered writer batches these efficiently.

Alternative: use `std.fmt.bytesToHex` which returns a stack array, then write it in one call. Trade-off: stack usage vs call count. For arrays up to 96 bytes (192 hex chars), the stack approach is fine:

```zig
fn writeHexBytes(writer: anytype, bytes: anytype) !void {
    try writer.writeAll("\"0x");
    // bytesToHex returns [bytes.len * 2]u8 on the stack
    const hex = std.fmt.bytesToHex(bytes, .lower);
    try writer.writeAll(&hex);
    try writer.writeByte('"');
}
```

For `BitList` (variable-length data in `ArrayListUnmanaged`), we must use the byte-by-byte approach since the length isn't comptime-known.

#### Handling ArrayListUnmanaged (SSZ Lists)

SSZ list types produce `std.ArrayListUnmanaged(T)` as their `.Type`. The serializer detects this:

```zig
fn isArrayList(comptime T: type) bool {
    return @hasField(T, "items") and @hasField(T, "capacity") and
           @typeInfo(@TypeOf(@as(T, undefined).items)) == .pointer;
}

fn writeArrayList(writer: anytype, comptime T: type, value: *const T) !void {
    const ItemType = @typeInfo(@TypeOf(value.items)).pointer.child;
    try writer.writeByte('[');
    for (value.items, 0..) |*item, i| {
        if (i > 0) try writer.writeByte(',');
        try beaconJsonStringify(writer, ItemType, item);
    }
    try writer.writeByte(']');
}
```

**Note:** In practice, API handler response types use `[]const T` slices, not `ArrayListUnmanaged`. The `ArrayListUnmanaged` detection is needed only if we ever directly serialize consensus types (SSZ `.Type` values). For the API layer, slice handling suffices.

#### Error Handling

The serializer only propagates writer errors (`std.Io.Writer.Error`). There are no logical errors — every valid Zig value of a supported type has a valid JSON representation. Invalid types (e.g., `*anyopaque`) fall through to `"null"`.

The writer error type is generic (works with any writer implementing `writeAll`/`writeByte`), enabling use with:
- `std.Io.Writer.Allocating` — heap-backed, returns `OutOfMemory`
- `std.io.fixedBufferStream` — stack-backed, returns `NoSpaceLeft`
- Any network writer — returns I/O errors

### 4. Envelope Helper

```zig
pub fn writeEnvelope(
    writer: anytype,
    comptime T: type,
    value: *const T,
    meta: ResponseMeta,
) !void {
    try writer.writeAll("{\"data\":");
    try beaconJsonStringify(writer, T, value);
    try writeMeta(writer, meta);
    try writer.writeByte('}');
}

pub fn writeArrayEnvelope(
    writer: anytype,
    comptime T: type,
    items: []const T,
    meta: ResponseMeta,
) !void {
    try writer.writeAll("{\"data\":[");
    for (items, 0..) |*item, i| {
        if (i > 0) try writer.writeByte(',');
        try beaconJsonStringify(writer, T, item);
    }
    try writer.writeByte(']');
    try writeMeta(writer, meta);
    try writer.writeByte('}');
}

/// Write raw bytes as a hex string in an envelope.
/// For endpoints that return pre-serialized SSZ (blocks, states).
pub fn writeRawBytesEnvelope(
    writer: anytype,
    data: []const u8,
    meta: ResponseMeta,
) !void {
    try writer.writeAll("{\"data\":\"0x");
    for (data) |byte| {
        const hex = "0123456789abcdef";
        try writer.writeByte(hex[byte >> 4]);
        try writer.writeByte(hex[byte & 0x0f]);
    }
    try writer.writeByte('"');
    try writeMeta(writer, meta);
    try writer.writeByte('}');
}

fn writeMeta(writer: anytype, meta: ResponseMeta) !void {
    if (meta.version) |fork| {
        try writer.writeAll(",\"version\":\"");
        try writer.writeAll(fork.toString());
        try writer.writeByte('"');
    }
    if (meta.execution_optimistic) |opt| {
        try writer.writeAll(if (opt) ",\"execution_optimistic\":true" else ",\"execution_optimistic\":false");
    }
    if (meta.finalized) |fin| {
        try writer.writeAll(if (fin) ",\"finalized\":true" else ",\"finalized\":false");
    }
    if (meta.dependent_root) |root| {
        try writer.writeAll(",\"dependent_root\":\"0x");
        const hex = std.fmt.bytesToHex(&root, .lower);
        try writer.writeAll(&hex);
        try writer.writeByte('"');
    }
}
```

### 5. Integration Path

#### Incremental Migration (Not Big-Bang)

The new serializer coexists with the old code. Migration per handler:

1. **Phase 1: Add `json.zig`** — new module alongside `response.zig`. No changes to existing code.

2. **Phase 2: Add `makeJsonResultV2`** — new method on `HttpServer` that uses the new serializer. Old `makeJsonResult` stays.

3. **Phase 3: Migrate simple handlers** — handlers that already use `makeJsonResult` (node, genesis, state fork, etc.) switch to `makeJsonResultV2` one at a time. Each is a one-line change:
   ```diff
   - return self.makeJsonResult(types.NodeVersion, result);
   + return self.makeJsonResultV2(types.NodeVersion, result);
   ```

4. **Phase 4: Migrate complex handlers** — handlers with manual `allocPrint`/`appendSlice` JSON building (proposer duties, attester duties, debug heads, etc.) switch to using `writeArrayEnvelope` or `writeEnvelope`. These are larger changes but each is isolated to one handler function.

5. **Phase 5: Migrate keymanager** — the most complex manual JSON builders. May require API type changes (adding proper response types).

6. **Phase 6: Remove old code** — delete `makeJsonResult`, `encodeHandlerResultJson`, `encodeJsonResponse`, `writeJsonValue`, `jsonEnvelope`.

#### SSZ Content Negotiation

The serializer only handles JSON. SSZ is already handled separately (raw bytes pass-through). The dispatch layer's existing pattern works:

```zig
if (dc.format == .ssz) {
    // Return raw SSZ bytes
    return .{ .content_type = "application/octet-stream", .body = ssz_bytes };
}
// Fall through to JSON serialization
var aw = IoWriter.Allocating.init(alloc);
try json.writeEnvelope(&aw.writer, T, &result.data, result.meta);
return .{ .content_type = "application/json", .body = aw.toOwnedSlice() };
```

No interaction between the two paths.

#### Response Metadata

Metadata is already handled correctly by `ResponseMeta` + `buildHeaders` for HTTP headers. The envelope helper writes it into the JSON body. No changes to the metadata system itself.

### 6. Alternatives Considered

#### Why not `std.json.stringify`?

`std.json.stringify` (Zig's built-in JSON serializer) doesn't work for Beacon API because:

1. **No quoted integers** — emits `12345` for `u64`, but the spec requires `"12345"`
2. **No hex encoding** — emits `[222, 173, 190, 239]` for `[4]u8`, but the spec requires `"0xdeadbeef"`
3. **No field omission** — emits `"field": null` for optionals, but the spec requires omitting the field entirely
4. **No BitList/BitVector awareness** — would serialize internal struct fields instead of hex-encoded bytes
5. **No streaming** — allocates the full string upfront

These are fundamental mismatches, not minor formatting differences. A custom serializer is unavoidable.

#### Why not hand-rolled per-type? (current approach)

This is what we have today. Problems:

- **30+ copy-paste `allocPrint` templates** with format strings like `"{{\"pubkey\":\"0x{s}\",\"validator_index\":\"{d}\",\"slot\":\"{d}\"}}"` — one missing `\\\"` and the output is broken
- **Every new endpoint** requires writing another template
- **Encoding rules applied inconsistently** — some handlers quote `u64`, some don't; some use `bytesToHex`, some use `fmtSliceHexLower`
- **Each handler re-implements the envelope** — code duplication, divergence
- **Testing is integration-only** — can't unit test serialization of a single type

A generic serializer reduces each handler to 1-3 lines and ensures encoding consistency across all endpoints.

#### What can we learn from TS Lodestar?

TypeScript Lodestar uses `@chainsafe/ssz`'s built-in `toJson`/`fromJson` on every SSZ type. Each SSZ type knows how to serialize itself to JSON. The API layer then uses codec objects:

```typescript
// packages/api/src/utils/codecs.ts
export function WithMeta<T, M extends {version: ForkName}>(
    getType: (m: M) => Type<T>
): ResponseDataCodec<T, M> {
    return {
        toJson: (data, meta) => getType(meta).toJson(data),
        fromJson: (data, meta) => getType(meta).fromJson(data),
        serialize: (data, meta) => getType(meta).serialize(data),
        deserialize: (data, meta) => getType(meta).deserialize(data),
    };
}
```

Key insight: the TS approach couples serialization to the SSZ type system. Each type has `toJson()`. In Zig, we can't add methods to types we don't own, but we achieve the same effect with comptime type introspection — the serializer inspects the type structure at compile time and generates the correct code.

The TS approach also separates the codec from the handler, with a registry of `{data: DataCodec, meta: MetaCodec}` per endpoint. We don't need this complexity because:
1. Zig's comptime dispatch is more powerful (single function handles all types)
2. We don't need `fromJson` deserialization in the same module (request parsing is separate)
3. The fork-polymorphic pattern is simpler when the handler already resolved the fork

### 7. File Organization

```
src/api/
├── json.zig                 # NEW: beaconJsonStringify, writeEnvelope, etc.
├── json_test.zig            # NEW: unit tests for every type mapping
├── response.zig             # EXISTING: keep until migration complete
├── handler_result.zig       # UNCHANGED
├── response_meta.zig        # UNCHANGED
├── http_server.zig          # MODIFY: add makeJsonResultV2, migrate handlers
└── types.zig                # UNCHANGED (possibly add json_field_names later)
```

### 8. Testing Strategy

Unit tests per type mapping:

```zig
test "u64 quoted" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try beaconJsonStringify(fbs.writer(), u64, &@as(u64, 12345));
    try std.testing.expectEqualStrings("\"12345\"", fbs.getWritten());
}

test "u32 not quoted" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try beaconJsonStringify(fbs.writer(), u32, &@as(u32, 42));
    try std.testing.expectEqualStrings("42", fbs.getWritten());
}

test "[32]u8 hex" {
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const root = [_]u8{0xab} ** 32;
    try beaconJsonStringify(fbs.writer(), [32]u8, &root);
    try std.testing.expect(std.mem.startsWith(u8, fbs.getWritten(), "\"0x"));
    try std.testing.expectEqual(@as(usize, 66), fbs.getWritten().len); // "0x" + 64 hex + quotes
}

test "optional field omitted" {
    const T = struct { a: u32, b: ?u64 };
    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const val = T{ .a = 1, .b = null };
    try beaconJsonStringify(fbs.writer(), T, &val);
    try std.testing.expectEqualStrings("{\"a\":1}", fbs.getWritten());
}

test "envelope with meta" {
    const T = struct { value: u64 };
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const val = T{ .value = 42 };
    const meta = ResponseMeta{ .version = .deneb, .finalized = true };
    try writeEnvelope(fbs.writer(), T, &val, meta);
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"data\":{\"value\":\"42\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"version\":\"deneb\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"finalized\":true") != null);
}
```

Integration tests: compare output against known-good JSON from the Beacon API spec test vectors.

### 9. Performance Notes

- **Zero allocation for serialization itself** — streams to writer
- **One allocation for the final byte buffer** — `IoWriter.Allocating` or `fixedBufferStream`
- **Comptime dispatch** — no runtime type checks, no vtables. The compiler generates specialized code per type.
- **Hex encoding** — 2 bytes per input byte, streamed. No intermediate hex string allocation.
- **Benchmark target:** serialize a full `ValidatorData` (with `[48]u8` pubkey + `[32]u8` credentials + 6× `u64` + `bool` + `enum`) in <1μs

### 10. Open Questions

1. **Signed integers (`i64`)** — Used in `TotalAttestationReward` and `SyncCommitteeReward`. Should they be quoted? The Beacon API spec doesn't have many signed integers; check spec test vectors. **Tentative answer: yes, quote them (same as `u64`).**

2. **String escaping** — Current `[]const u8` handling writes raw bytes. If a string ever contains `"`, `\`, or control characters, output would be invalid JSON. For now, all string values are version strings, peer IDs, ENRs — no special characters. Add proper JSON string escaping if this changes.

3. **`ArrayListUnmanaged` in API types** — Currently, API handler response types use `[]const T` slices. If we ever need to serialize consensus types directly (their `.Type` uses `ArrayListUnmanaged`), the `isArrayList` detection handles it. Low priority.

4. **Pretty printing** — Not needed for API responses (clients parse, not humans). Could add an optional `indent` parameter later for debug endpoints.
