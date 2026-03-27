# Zig API Framework Design

Based on analysis of the TypeScript Lodestar API framework (`packages/api/src/`).

## Executive Summary

The TS framework is built around a **typed route definition DSL** that captures request/response schemas, SSZ types, JSON codecs, and metadata in a single declaration. The Zig implementation should follow the same principle but leverage comptime for zero-cost abstractions.

---

## 1. TS Framework Key Patterns

### Route Definition DSL

The TS framework defines routes as typed `Endpoint<Method, Args, Request, Return, Meta>` tuples. Each route bundles:
- HTTP method + path
- Application-level args (typed)
- HTTP request shape (params, query, body)
- Return type
- Metadata type (version, execution_optimistic, finalized)
- Request codec (writeReq/parseReq + SSZ variants)
- Response codec (JSON toJson/fromJson + SSZ serialize/deserialize + metadata toHeadersObject/fromHeaders)

### Content Negotiation (handlers/handler.ts)
1. Parse `Accept` header → select `MediaType` (json or ssz)
2. Parse `Content-Type` header for POST bodies
3. If `definition.resp.isEmpty` → skip
4. Default to JSON if Accept is absent
5. Return 406 if Accept lists only unsupported types
6. Route to `WireFormat.json` or `WireFormat.ssz` serialize path

### Response Metadata (utils/metadata.ts)
Metadata is carried in HTTP headers:
- `Eth-Consensus-Version` → fork name (phase0/altair/bellatrix/capella/deneb/electra)
- `Eth-Execution-Optimistic` → "true"/"false"
- `Eth-Consensus-Finalized` → "true"/"false"
- `Eth-Consensus-Dependent-Root` → hex root
- `Access-Control-Expose-Headers` → comma list of exposed headers

Response codecs also inject metadata into JSON body for some routes (e.g., `{ data, version, execution_optimistic, finalized }`).

### Error Format (utils/server/error.ts)
```json
{ "statusCode": 404, "message": "Block not found" }
```
Returned as `application/json` with matching HTTP status code.

### SSZ Response Encoding
- Blocks, states, attestations support `application/octet-stream`
- Fork-aware: the SSZ type depends on the fork (different struct layout per fork)
- Large responses (full state ≈ 100MB) may need chunked transfer

---

## 2. Current Zig Implementation Analysis

### What's There
- `types.zig` — BlockId/StateId/ValidatorId parsing, ApiResponse(T) envelope, ContentType enum
- `routes.zig` — Static route table with method/path/operation_id/supports_ssz
- `response.zig` — Custom JSON serializer via writeJsonValue dispatch
- `http_server.zig` — std.http.Server loop, dispatches to operation_id match
- `context.zig` — ApiContext with callbacks for all dependencies
- `handlers/*.zig` — Pure handler functions returning ApiResponse(T)

### Gaps vs Production

| Gap | Impact |
|-----|--------|
| Accept header parsing is `indexOf("octet-stream")` — no q-value, no RFC-9110 | Wrong format selection in practice |
| No metadata HTTP headers — version/execution_optimistic only in JSON body | Non-compliant with Beacon API spec |
| Error format `{ "message": "..." }` — missing `statusCode` field | Non-standard, clients may fail |
| No standard error JSON (uses raw strings like `"{\"message\":\"Not implemented\"}"`) | Inconsistent, not spec-compliant |
| SSZ response path stubs — getBlockV2 hardcodes version=phase0 placeholder | Can't serve SSZ |
| dispatchHandler is one huge if-chain — adding routes requires editing core function | Not scalable |
| No fork-aware encoding | Fork detection missing entirely |
| No chunked/streaming for large state responses | Full state would OOM |
| Content-Type header not set on error responses | Missing |

---

## 3. Route Definition Pattern for Zig

### Proposed comptime Route Definition

```zig
// Route descriptor — all metadata in one place
pub const RouteSpec = struct {
    method: HttpMethod,
    path: []const u8,
    operation_id: []const u8,
    supports_ssz: bool = false,
    meta_flags: MetaFlags = .{},  // which metadata headers to emit
    ssz_endpoints: bool = false,  // true = SSZ-first (blocks, states)
};

// Per-endpoint metadata flags
pub const MetaFlags = struct {
    version: bool = false,          // Eth-Consensus-Version
    execution_optimistic: bool = false,  // Eth-Execution-Optimistic
    finalized: bool = false,        // Eth-Consensus-Finalized
    dependent_root: bool = false,   // Eth-Consensus-Dependent-Root
};
```

### Handler return type

```zig
// Handlers return this instead of bare ApiResponse(T)
pub fn HandlerResult(comptime T: type) type {
    return struct {
        data: T,
        meta: ResponseMeta,
        ssz_bytes: ?[]const u8 = null,  // pre-serialized SSZ if available
        status: u16 = 200,
    };
}
```

### Example route definition (getBlockV2)

```zig
pub const getBlockV2 = RouteSpec{
    .method = .GET,
    .path = "/eth/v2/beacon/blocks/{block_id}",
    .operation_id = "getBlockV2",
    .supports_ssz = true,
    .meta_flags = .{
        .version = true,
        .execution_optimistic = true,
        .finalized = true,
    },
};
```

---

## 4. Content Negotiation Design

### src/api/content_negotiation.zig

```zig
pub const WireFormat = enum { json, ssz };

pub const ContentNegotiation = struct {
    /// Parse Accept header → preferred wire format
    /// Returns .json as default if Accept absent or "*/*"
    /// Returns null if Accept present but no supported type found (→ 406)
    pub fn parseAccept(accept: ?[]const u8) ?WireFormat;
    
    /// Parse Content-Type header → wire format for request body
    pub fn parseContentType(content_type: ?[]const u8) ?WireFormat;
};
```

Accept header parsing follows RFC-9110:
- Split on `,`
- Each entry: `type/subtype[;q=value]`
- `*/*` → json
- `application/json` → json
- `application/octet-stream` → ssz
- Pick highest q-value (default 1.0)
- Return null if no supported type → 406

---

## 5. Response Metadata Design

### src/api/response_meta.zig

```zig
pub const Fork = enum {
    phase0, altair, bellatrix, capella, deneb, electra, fulu,
    
    pub fn toString(self: Fork) []const u8;
    pub fn fromString(s: []const u8) ?Fork;
};

pub const ResponseMeta = struct {
    version: ?Fork = null,
    execution_optimistic: ?bool = null,
    finalized: ?bool = null,
    dependent_root: ?[32]u8 = null,

    /// Write meta fields to HTTP response headers
    pub fn writeHeaders(self: ResponseMeta, headers: *HeaderList) void;
    
    /// Get the value of `Access-Control-Expose-Headers` for these meta fields
    pub fn exposeHeaders(self: ResponseMeta, buf: []u8) []const u8;
};

// Standard header names
pub const MetaHeader = struct {
    pub const version = "Eth-Consensus-Version";
    pub const execution_optimistic = "Eth-Execution-Optimistic";
    pub const finalized = "Eth-Consensus-Finalized";
    pub const dependent_root = "Eth-Consensus-Dependent-Root";
    pub const expose_headers = "Access-Control-Expose-Headers";
};
```

Handlers populate ResponseMeta, the server layer writes headers before sending.

---

## 6. Error Response Design

### src/api/error_response.zig

Beacon API error format: `{ "statusCode": N, "message": "..." }`

```zig
pub const ErrorCode = enum(u16) {
    bad_request = 400,
    unauthorized = 401,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    unsupported_media_type = 415,
    internal_server_error = 500,
    not_implemented = 501,
    service_unavailable = 503,
};

pub const ApiError = struct {
    code: ErrorCode,
    message: []const u8,

    /// Format to JSON: {"statusCode":N,"message":"..."}
    pub fn toJson(self: ApiError, buf: []u8) []const u8;
};

/// Map Zig errors to ApiError
pub fn fromZigError(err: anyerror) ApiError;
```

Error → HTTP status mapping:
- `error.BlockNotFound`, `error.StateNotFound`, `error.ValidatorNotFound` → 404
- `error.InvalidBlockId`, `error.InvalidStateId`, `error.InvalidValidatorId` → 400
- `error.NotImplemented` → 501
- `error.BadRequest` → 400
- `error.NotAcceptable` → 406
- `error.UnsupportedMediaType` → 415
- everything else → 500

---

## 7. SSZ Response Encoding

### Endpoints requiring SSZ support
- `GET /eth/v2/beacon/blocks/{block_id}` — SignedBeaconBlock (fork-aware)
- `GET /eth/v2/beacon/blinded_blocks/{block_id}` — SignedBlindedBeaconBlock
- `GET /eth/v2/debug/beacon/states/{state_id}` — BeaconState (fork-aware, huge)
- `GET /eth/v1/beacon/blob_sidecars/{block_id}` — BlobSidecar list
- POST block publishing endpoints

### Fork-aware encoding
The SSZ type depends on the fork of the block/state. The handler must:
1. Determine the fork from the object
2. Return the SSZ bytes (pre-computed if cached, else serialize on demand)
3. Set `Eth-Consensus-Version` header to the fork name

```zig
pub const ForkSszEncoder = struct {
    pub fn encodeBlock(allocator: Allocator, block: AnySignedBlock) ![]u8;
    pub fn encodeState(allocator: Allocator, state: AnyBeaconState) ![]u8;
};
```

### Chunked/streaming for large responses
Full beacon state can be 100MB+. Options:
1. **Allocate-and-send** — works for now, needs memory limit
2. **Chunked transfer encoding** — requires std.http.Server chunked write support
3. **Memory-mapped SSZ** — if state is stored as raw SSZ in DB

Recommendation: Start with allocate-and-send with a configurable size limit. Add streaming when std.Io supports it cleanly.

---

## 8. Concrete File Changes

### New files to create
- `src/api/content_negotiation.zig` — RFC-9110 Accept parsing
- `src/api/response_meta.zig` — ResponseMeta struct + header emission
- `src/api/error_response.zig` — Standard error format + Zig error mapping

### Files to update
- `src/api/types.zig` — Remove `ContentType.fromAcceptHeader` (superseded by content_negotiation.zig)
- `src/api/response.zig` — Accept `ResponseMeta` param, emit version in JSON when present
- `src/api/http_server.zig` — Use `content_negotiation.parseAccept()`, emit meta headers, use `error_response.fromZigError()`
- `src/api/routes.zig` — Add `MetaFlags` to `Route` struct
- `src/api/root.zig` — Export new modules

### Not yet: route handler refactor
The `dispatchHandler` if-chain in `http_server.zig` is a known technical debt.
A future refactor would move to a comptime-generated dispatch table.
Out of scope for this framework layer addition.

---

## 9. Design Principles (Zig-specific)

1. **Comptime for zero cost** — MetaFlags, RouteSpec known at compile time → no runtime overhead
2. **No heap in hot path** — ResponseMeta is stack-allocated, headers written inline
3. **Error-as-value** — `anyerror!T` propagates through all handler calls, mapped at server boundary
4. **No allocator in content_negotiation** — pure parsing functions return enums or null
5. **Backward compat** — Existing handlers don't change; new meta goes through ResponseMeta optionals
