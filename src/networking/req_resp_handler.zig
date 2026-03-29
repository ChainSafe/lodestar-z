//! Req/resp protocol handler logic for the Ethereum consensus P2P layer.
//!
//! Implements request handling for each protocol method defined in the consensus spec:
//! https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md
//!
//! This module is pure business logic — it decodes SSZ request bytes, looks up data via
//! a provided context interface, and returns response chunks. The transport layer
//! (wire encoding, framing) is handled by `req_resp_encoding.zig`.

const std = @import("std");
const log = std.log.scoped(.req_resp);
const testing = std.testing;
const Allocator = std.mem.Allocator;
const protocol = @import("protocol.zig");
const messages = @import("messages.zig");

const Method = protocol.Method;
const ResponseCode = protocol.ResponseCode;
const StatusMessage = messages.StatusMessage;
const Ping = messages.Ping;
const GoodbyeReason = messages.GoodbyeReason;
const MetadataV2 = messages.MetadataV2;
const BeaconBlocksByRangeRequest = messages.BeaconBlocksByRangeRequest;
const BeaconBlocksByRootRequest = messages.BeaconBlocksByRootRequest;
const BlobSidecarsByRangeRequest = messages.BlobSidecarsByRangeRequest;
const BlobSidecarsByRootRequest = messages.BlobSidecarsByRootRequest;

/// Maximum request payload size: 10 MiB.
pub const max_payload_size: u32 = 10 * 1024 * 1024;

/// Maximum blocks per BeaconBlocksByRange / BeaconBlocksByRoot request.
pub const max_request_blocks: u64 = 1024;

/// Maximum blob sidecars per BlobSidecarsByRange / BlobSidecarsByRoot request.
pub const max_request_blob_sidecars: u64 = 768;

/// Maximum data column sidecars per DataColumnSidecarsByRange / Root request.
pub const max_request_data_column_sidecars: u64 = 16384;

/// A single response chunk returned by a handler.
///
/// The encoding layer (req_resp_encoding.zig) is responsible for wire-encoding these
/// chunks with Snappy compression and varint framing.
/// A single response chunk returned by `handleRequest`.
///
/// Memory ownership
/// ----------------
/// Both the `[]ResponseChunk` slice and each `ssz_payload` slice are allocated
/// with the `allocator` passed to `handleRequest`.  The caller owns this memory
/// and MUST release it by calling `freeResponseChunks(allocator, chunks)`.
///
/// Example:
/// ```zig
/// const chunks = try handleRequest(alloc, method, bytes, ctx);
/// defer freeResponseChunks(alloc, chunks);
/// // ... encode and send chunks ...
/// ```
pub const ResponseChunk = struct {
    /// The result code for this chunk.
    result: ResponseCode,
    /// Fork digest context bytes, present for fork-versioned response types.
    context_bytes: ?[4]u8,
    /// Raw SSZ payload bytes (not yet Snappy-compressed).
    /// For error responses, this contains the UTF-8 error message.
    /// Freed by `freeResponseChunks` — do not free individually.
    ssz_payload: []const u8,
};

pub const HandlerError = error{
    OutOfMemory,
};

/// Callback interface that the beacon node provides to req/resp handlers.
///
/// Each function pointer returns the data needed to service a particular request type.
/// The handler module never accesses beacon state directly — all data access goes
/// through these callbacks.
pub const ReqRespContext = struct {
    /// Erased pointer to the concrete implementation (e.g. *BeaconNode or *MockContext).
    ptr: *anyopaque,
    /// Returns our node's current status (chain head, finalized checkpoint).
    getStatus: *const fn (ptr: *anyopaque) StatusMessage.Type,
    /// Returns our node's metadata (sequence number, subnet subscriptions).
    getMetadata: *const fn (ptr: *anyopaque) MetadataV2.Type,
    /// Returns our current ping sequence number.
    getPingSequence: *const fn (ptr: *anyopaque) u64,
    /// Looks up a signed beacon block by its root. Returns SSZ bytes or null if unknown.
    getBlockByRoot: *const fn (ptr: *anyopaque, root: [32]u8) ?[]const u8,
    /// Returns signed beacon blocks for a contiguous slot range. Each element is SSZ bytes.
    getBlocksByRange: *const fn (ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8,
    /// Looks up a blob sidecar by block root and blob index. Returns SSZ bytes or null.
    getBlobByRoot: *const fn (ptr: *anyopaque, root: [32]u8, index: u64) ?[]const u8,
    /// Returns blob sidecars for a contiguous slot range. Each element is SSZ bytes.
    getBlobsByRange: *const fn (ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8,
    /// Looks up a data column sidecar by block root and column index. Returns SSZ bytes or null.
    getDataColumnByRoot: ?*const fn (ptr: *anyopaque, root: [32]u8, index: u64) ?[]const u8 = null,
    /// Returns data column sidecars for a contiguous slot range. Each element is SSZ bytes.
    getDataColumnsByRange: ?*const fn (ptr: *anyopaque, start_slot: u64, count: u64) []const []const u8 = null,
    /// Looks up the slot for a block root (for correct fork digest computation).
    /// Returns null if the root is unknown; callers should use a fallback slot or skip.
    getSlotByRoot: ?*const fn (ptr: *anyopaque, root: [32]u8) ?u64 = null,
    /// Returns the fork digest (4 bytes) for the given slot.
    getForkDigest: *const fn (ptr: *anyopaque, slot: u64) [4]u8,
    /// Called when a peer sends Goodbye. The reason code indicates why they are disconnecting.
    onGoodbye: *const fn (ptr: *anyopaque, reason: u64) void,
    /// Called when a peer sends their Status. Used for sync checking.
    onPeerStatus: *const fn (ptr: *anyopaque, status: StatusMessage.Type) void,
};

/// Top-level request dispatcher.
///
/// Routes an incoming request to the appropriate handler based on the protocol method.
/// The `request_bytes` must be raw SSZ bytes (already Snappy-decompressed by the encoding layer).
///
/// Returns a slice of response chunks. Caller owns the returned memory (both the slice
/// and each chunk's ssz_payload).
///
/// Preconditions:
/// - `request_bytes.len <= max_payload_size`
/// - `method` is a supported req/resp method
pub fn handleRequest(
    allocator: Allocator,
    method: Method,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    // Validate request size.
    if (request_bytes.len > max_payload_size) {
        return makeErrorResponse(allocator, .invalid_request, "Request payload exceeds maximum size");
    }

    return switch (method) {
        .status => handleStatus(allocator, request_bytes, context),
        .goodbye => handleGoodbye(allocator, request_bytes, context),
        .ping => handlePing(allocator, request_bytes, context),
        .metadata => handleMetadata(allocator, context),
        .beacon_blocks_by_range => handleBeaconBlocksByRange(allocator, request_bytes, context),
        .beacon_blocks_by_root => handleBeaconBlocksByRoot(allocator, request_bytes, context),
        .blob_sidecars_by_range => handleBlobSidecarsByRange(allocator, request_bytes, context),
        .blob_sidecars_by_root => handleBlobSidecarsByRoot(allocator, request_bytes, context),
        .data_column_sidecars_by_root => handleDataColumnSidecarsByRoot(allocator, request_bytes, context),
        .data_column_sidecars_by_range => handleDataColumnSidecarsByRange(allocator, request_bytes, context),
        .light_client_bootstrap,
        .light_client_updates_by_range,
        .light_client_finality_update,
        .light_client_optimistic_update,
        => makeErrorResponse(allocator, .server_error, "Light client methods not yet implemented"),
    };
}

// === Individual method handlers ===

/// Handle a Status request.
///
/// Decodes the peer's StatusMessage, notifies the context, and returns our own status.
/// This is bidirectional — both peers exchange status during the handshake.
fn handleStatus(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    // Validate size: StatusMessage is fixed-size.
    if (request_bytes.len != StatusMessage.fixed_size) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid StatusMessage size");
    }

    // Decode the peer's status.
    var peer_status: StatusMessage.Type = undefined;
    StatusMessage.deserializeFromBytes(request_bytes, &peer_status) catch {
        return makeErrorResponse(allocator, .invalid_request, "Malformed StatusMessage");
    };

    // Notify context about the peer's status (for sync checking).
    context.onPeerStatus(context.ptr, peer_status);

    // Serialize our status as the response.
    const our_status = context.getStatus(context.ptr);
    const payload = try allocator.alloc(u8, StatusMessage.fixed_size);
    _ = StatusMessage.serializeIntoBytes(&our_status, payload);

    const chunks = try allocator.alloc(ResponseChunk, 1);
    chunks[0] = .{
        .result = .success,
        .context_bytes = null,
        .ssz_payload = payload,
    };
    return chunks;
}

/// Handle a Goodbye request.
///
/// Decodes the reason code and notifies the context. Returns an empty response
/// (the connection will be closed by the transport layer after this).
fn handleGoodbye(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    // GoodbyeReason is a uint64 (8 bytes).
    if (request_bytes.len != GoodbyeReason.fixed_size) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid GoodbyeReason size");
    }

    var reason: GoodbyeReason.Type = undefined;
    GoodbyeReason.deserializeFromBytes(request_bytes, &reason) catch {
        return makeErrorResponse(allocator, .invalid_request, "Malformed GoodbyeReason");
    };

    log.info("Goodbye received: reason={d}", .{reason});
    context.onGoodbye(context.ptr, reason);

    // Return empty response — Goodbye has no response body per spec.
    return &.{};
}

/// Handle a Ping request.
///
/// Returns our sequence number in response to the peer's ping.
fn handlePing(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    // Ping is a uint64 (8 bytes).
    if (request_bytes.len != Ping.fixed_size) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid Ping size");
    }

    // We don't need to decode the peer's ping value for the response,
    // but we validate it's well-formed.
    var _peer_seq: Ping.Type = undefined;
    Ping.deserializeFromBytes(request_bytes, &_peer_seq) catch {
        return makeErrorResponse(allocator, .invalid_request, "Malformed Ping");
    };

    // Respond with our sequence number.
    const our_seq = context.getPingSequence(context.ptr);
    const payload = try allocator.alloc(u8, Ping.fixed_size);
    _ = Ping.serializeIntoBytes(&our_seq, payload);

    const chunks = try allocator.alloc(ResponseChunk, 1);
    chunks[0] = .{
        .result = .success,
        .context_bytes = null,
        .ssz_payload = payload,
    };
    return chunks;
}

/// Handle a MetaData request.
///
/// Returns our node's metadata. The request body is empty per the spec.
fn handleMetadata(
    allocator: Allocator,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    const metadata = context.getMetadata(context.ptr);
    const payload = try allocator.alloc(u8, MetadataV2.fixed_size);
    _ = MetadataV2.serializeIntoBytes(&metadata, payload);

    const chunks = try allocator.alloc(ResponseChunk, 1);
    chunks[0] = .{
        .result = .success,
        .context_bytes = null,
        .ssz_payload = payload,
    };
    return chunks;
}

/// Handle a BeaconBlocksByRange request.
///
/// Returns multiple response chunks, each with context bytes (fork digest).
/// Caps the count at `max_request_blocks` and returns ResourceUnavailable if
/// no blocks are found in the requested range.
fn handleBeaconBlocksByRange(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    if (request_bytes.len != BeaconBlocksByRangeRequest.fixed_size) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid BeaconBlocksByRangeRequest size");
    }

    var request: BeaconBlocksByRangeRequest.Type = undefined;
    BeaconBlocksByRangeRequest.deserializeFromBytes(request_bytes, &request) catch {
        return makeErrorResponse(allocator, .invalid_request, "Malformed BeaconBlocksByRangeRequest");
    };

    // Validate count.
    if (request.count == 0) {
        return makeErrorResponse(allocator, .invalid_request, "Count must be greater than zero");
    }
    if (request.count > max_request_blocks) {
        return makeErrorResponse(allocator, .invalid_request, "Count exceeds MAX_REQUEST_BLOCKS");
    }

    // Look up blocks.
    const blocks = context.getBlocksByRange(context.ptr, request.start_slot, request.count);
    if (blocks.len == 0) {
        return &.{};
    }

    // Build response chunks with context bytes.
    const chunks = try allocator.alloc(ResponseChunk, blocks.len);
    var filled: usize = 0;
    errdefer {
        for (chunks[0..filled]) |c| allocator.free(c.ssz_payload);
        allocator.free(chunks);
    }
    for (blocks, 0..) |block_ssz, i| {
        const payload = try allocator.alloc(u8, block_ssz.len);
        @memcpy(payload, block_ssz);

        // Get fork digest for this block's actual slot.
        // Blocks may not be at sequential slots (skip slots), so we extract
        // the actual slot from the SSZ bytes.
        //
        // SignedBeaconBlock SSZ layout (variable-length container):
        //   bytes 0..4:   offset to `message` field (u32 LE)
        //   bytes 4..100: BLS signature (96 bytes)
        //   bytes offset..: BeaconBlock starts here; slot is first 8 bytes (u64 LE)
        const actual_slot = blk: {
            if (block_ssz.len < 4) break :blk request.start_slot + i;
            const msg_offset = std.mem.readInt(u32, block_ssz[0..4], .little);
            if (block_ssz.len >= @as(usize, msg_offset) + 8) {
                break :blk std.mem.readInt(u64, block_ssz[msg_offset..][0..8], .little);
            }
            break :blk request.start_slot + i;
        };
        chunks[i] = .{
            .result = .success,
            .context_bytes = context.getForkDigest(context.ptr, actual_slot),
            .ssz_payload = payload,
        };
        filled += 1;
    }
    return chunks;
}

/// Handle a BeaconBlocksByRoot request.
///
/// Looks up each requested block root and returns matching blocks.
/// Unknown roots are silently skipped (no error, just omitted from response).
fn handleBeaconBlocksByRoot(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    // Validate minimum size: must be a multiple of 32 (root size).
    if (request_bytes.len == 0 or request_bytes.len % 32 != 0) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid BeaconBlocksByRootRequest size");
    }

    const num_roots = request_bytes.len / 32;
    if (num_roots > max_request_blocks) {
        return makeErrorResponse(allocator, .invalid_request, "Too many roots requested");
    }

    // Collect found blocks into a dynamic list.
    var found: std.ArrayListUnmanaged(ResponseChunk) = .empty;
    errdefer {
        for (found.items) |chunk| allocator.free(chunk.ssz_payload);
        found.deinit(allocator);
    }

    for (0..num_roots) |i| {
        const root: [32]u8 = request_bytes[i * 32 ..][0..32].*;
        if (context.getBlockByRoot(context.ptr, root)) |block_ssz| {
            const payload = try allocator.alloc(u8, block_ssz.len);
            @memcpy(payload, block_ssz);

            // Look up the block's actual slot for correct fork digest computation.
            // Falls back to slot 0 (genesis fork) if the context doesn't implement
            // getSlotByRoot or the root is not found.
            const slot: u64 = if (context.getSlotByRoot) |get_slot|
                get_slot(context.ptr, root) orelse 0
            else
                0;
            try found.append(allocator, .{
                .result = .success,
                .context_bytes = context.getForkDigest(context.ptr, slot),
                .ssz_payload = payload,
            });
        }
        // Unknown roots are silently skipped per spec.
    }

    // Transfer ownership of the backing array to the caller.
    if (found.items.len == 0) {
        found.deinit(allocator);
        return &.{};
    }
    return try found.toOwnedSlice(allocator);
}

/// Handle a BlobSidecarsByRange request.
///
/// Returns blob sidecar chunks for the requested slot range with context bytes.
fn handleBlobSidecarsByRange(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    if (request_bytes.len != BlobSidecarsByRangeRequest.fixed_size) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid BlobSidecarsByRangeRequest size");
    }

    var request: BlobSidecarsByRangeRequest.Type = undefined;
    BlobSidecarsByRangeRequest.deserializeFromBytes(request_bytes, &request) catch {
        return makeErrorResponse(allocator, .invalid_request, "Malformed BlobSidecarsByRangeRequest");
    };

    // Validate count.
    if (request.count == 0) {
        return makeErrorResponse(allocator, .invalid_request, "Count must be greater than zero");
    }
    if (request.count > max_request_blob_sidecars) {
        return makeErrorResponse(allocator, .invalid_request, "Count exceeds MAX_REQUEST_BLOB_SIDECARS");
    }

    // Look up blob sidecars.
    const blobs = context.getBlobsByRange(context.ptr, request.start_slot, request.count);
    if (blobs.len == 0) {
        return &.{};
    }

    // Build response chunks with context bytes.
    const chunks = try allocator.alloc(ResponseChunk, blobs.len);
    var filled: usize = 0;
    errdefer {
        for (chunks[0..filled]) |c| allocator.free(c.ssz_payload);
        allocator.free(chunks);
    }
    for (blobs, 0..) |blob_ssz, i| {
        const payload = try allocator.alloc(u8, blob_ssz.len);
        @memcpy(payload, blob_ssz);

        // Extract the actual slot from the BlobSidecar SSZ bytes.
        //
        // BlobSidecar is a fixed container (Deneb/Electra, FIELD_ELEMENTS_PER_BLOB=4096):
        //   index:               8 bytes  @ offset 0
        //   blob:           131072 bytes  @ offset 8       (4096 * 32 bytes per field element)
        //   kzg_commitment:     48 bytes  @ offset 131080
        //   kzg_proof:          48 bytes  @ offset 131128
        //   signed_block_header:          @ offset 131176
        //     message (BeaconBlockHeader):
        //       slot:            8 bytes  @ offset 131176  (first field of message)
        //
        // Falls back to range-start + index if the SSZ is too short.
        const BLOB_SIDECAR_SLOT_OFFSET = 8 + (4096 * 32) + 48 + 48; // 131176
        const actual_slot = if (blob_ssz.len >= BLOB_SIDECAR_SLOT_OFFSET + 8)
            std.mem.readInt(u64, blob_ssz[BLOB_SIDECAR_SLOT_OFFSET..][0..8], .little)
        else
            request.start_slot + i;
        chunks[i] = .{
            .result = .success,
            .context_bytes = context.getForkDigest(context.ptr, actual_slot),
            .ssz_payload = payload,
        };
        filled += 1;
    }
    return chunks;
}

/// Handle a BlobSidecarsByRoot request.
///
/// Looks up each requested blob identifier and returns matching blob sidecars.
/// Unknown identifiers are silently skipped.
fn handleBlobSidecarsByRoot(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    // BlobIdentifier is (root: [32]u8, index: u64) = 40 bytes each.
    const blob_id_size = 40;
    if (request_bytes.len == 0 or request_bytes.len % blob_id_size != 0) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid BlobSidecarsByRootRequest size");
    }

    const num_ids = request_bytes.len / blob_id_size;
    if (num_ids > max_request_blob_sidecars) {
        return makeErrorResponse(allocator, .invalid_request, "Too many blob identifiers requested");
    }

    var found: std.ArrayListUnmanaged(ResponseChunk) = .empty;
    errdefer {
        for (found.items) |chunk| allocator.free(chunk.ssz_payload);
        found.deinit(allocator);
    }

    for (0..num_ids) |i| {
        const offset = i * blob_id_size;
        const root: [32]u8 = request_bytes[offset..][0..32].*;
        const index = std.mem.readInt(u64, request_bytes[offset + 32 ..][0..8], .little);

        if (context.getBlobByRoot(context.ptr, root, index)) |blob_ssz| {
            const payload = try allocator.alloc(u8, blob_ssz.len);
            @memcpy(payload, blob_ssz);

            // Look up the blob's block slot for correct fork digest computation.
            const slot: u64 = if (context.getSlotByRoot) |get_slot|
                get_slot(context.ptr, root) orelse 0
            else
                0;
            try found.append(allocator, .{
                .result = .success,
                .context_bytes = context.getForkDigest(context.ptr, slot),
                .ssz_payload = payload,
            });
        }
    }

    if (found.items.len == 0) {
        found.deinit(allocator);
        return &.{};
    }
    return try found.toOwnedSlice(allocator);
}

/// Handle a DataColumnSidecarsByRoot request.
///
/// Looks up each requested (root, column_index) pair and returns matching sidecars.
/// Unknown identifiers are silently skipped.
fn handleDataColumnSidecarsByRoot(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    const getDataColumn = context.getDataColumnByRoot orelse
        return makeErrorResponse(allocator, .server_error, "DataColumnSidecarsByRoot not supported");

    // DataColumnIdentifier is (root: [32]u8, index: u64) = 40 bytes each.
    const id_size = 40;
    if (request_bytes.len == 0 or request_bytes.len % id_size != 0) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid DataColumnSidecarsByRootRequest size");
    }

    const num_ids = request_bytes.len / id_size;
    if (num_ids > max_request_data_column_sidecars) {
        return makeErrorResponse(allocator, .invalid_request, "Too many data column identifiers requested");
    }

    var found: std.ArrayListUnmanaged(ResponseChunk) = .empty;
    errdefer {
        for (found.items) |chunk| allocator.free(chunk.ssz_payload);
        found.deinit(allocator);
    }

    for (0..num_ids) |i| {
        const offset = i * id_size;
        const root: [32]u8 = request_bytes[offset..][0..32].*;
        const index = std.mem.readInt(u64, request_bytes[offset + 32 ..][0..8], .little);

        if (getDataColumn(context.ptr, root, index)) |sidecar_ssz| {
            const payload = try allocator.alloc(u8, sidecar_ssz.len);
            @memcpy(payload, sidecar_ssz);

            // Look up the block's actual slot for correct fork digest computation.
            const slot: u64 = if (context.getSlotByRoot) |get_slot|
                get_slot(context.ptr, root) orelse 0
            else
                0;
            try found.append(allocator, .{
                .result = .success,
                .context_bytes = context.getForkDigest(context.ptr, slot),
                .ssz_payload = payload,
            });
        }
    }

    if (found.items.len == 0) {
        found.deinit(allocator);
        return &.{};
    }
    return try found.toOwnedSlice(allocator);
}

/// Handle a DataColumnSidecarsByRange request.
///
/// Returns data column sidecar chunks for the requested slot range with context bytes.
fn handleDataColumnSidecarsByRange(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) HandlerError![]const ResponseChunk {
    const getDataColumns = context.getDataColumnsByRange orelse
        return makeErrorResponse(allocator, .server_error, "DataColumnSidecarsByRange not supported");

    // DataColumnSidecarsByRangeRequest has variable size due to columns list.
    // Minimum: start_slot(8) + count(8) = 16 bytes.
    if (request_bytes.len < 16) {
        return makeErrorResponse(allocator, .invalid_request, "Invalid DataColumnSidecarsByRangeRequest size");
    }

    const start_slot = std.mem.readInt(u64, request_bytes[0..8], .little);
    const count = std.mem.readInt(u64, request_bytes[8..16], .little);

    if (count == 0) {
        return makeErrorResponse(allocator, .invalid_request, "Count must be greater than zero");
    }
    if (count > max_request_blocks) {
        return makeErrorResponse(allocator, .invalid_request, "Count exceeds MAX_REQUEST_BLOCKS");
    }

    const data_columns = getDataColumns(context.ptr, start_slot, count);
    if (data_columns.len == 0) {
        return &.{};
    }

    const chunks = try allocator.alloc(ResponseChunk, data_columns.len);
    var filled: usize = 0;
    errdefer {
        for (chunks[0..filled]) |c| allocator.free(c.ssz_payload);
        allocator.free(chunks);
    }
    for (data_columns, 0..) |dc_ssz, i| {
        const payload = try allocator.alloc(u8, dc_ssz.len);
        @memcpy(payload, dc_ssz);

        // Extract the actual slot from the DataColumnSidecar SSZ bytes.
        //
        // DataColumnSidecar is a variable container (Fulu):
        //   index:                    8 bytes  @ offset 0     (u64, fixed inline)
        //   column offset:            4 bytes  @ offset 8     (variable-field offset)
        //   kzg_commitments offset:   4 bytes  @ offset 12    (variable-field offset)
        //   kzg_proofs offset:        4 bytes  @ offset 16    (variable-field offset)
        //   signed_block_header:    208 bytes  @ offset 20    (fixed inline)
        //     message (BeaconBlockHeader):
        //       slot:                 8 bytes  @ offset 20    (first field of message)
        //
        // Falls back to range-start + index if the SSZ is too short.
        const DC_SIDECAR_SLOT_OFFSET = 8 + 4 + 4 + 4; // 20
        const actual_slot = if (dc_ssz.len >= DC_SIDECAR_SLOT_OFFSET + 8)
            std.mem.readInt(u64, dc_ssz[DC_SIDECAR_SLOT_OFFSET..][0..8], .little)
        else
            start_slot + i;
        chunks[i] = .{
            .result = .success,
            .context_bytes = context.getForkDigest(context.ptr, actual_slot),
            .ssz_payload = payload,
        };
        filled += 1;
    }
    return chunks;
}

// === Helpers ===

/// Create a single-chunk error response.
///
/// The SSZ payload contains the UTF-8 error message string.
fn makeErrorResponse(
    allocator: Allocator,
    code: ResponseCode,
    message: []const u8,
) HandlerError![]const ResponseChunk {
    const payload = try allocator.alloc(u8, message.len);
    @memcpy(payload, message);

    const chunks = try allocator.alloc(ResponseChunk, 1);
    chunks[0] = .{
        .result = code,
        .context_bytes = null,
        .ssz_payload = payload,
    };
    return chunks;
}

/// Free all response chunks and their payloads.
///
/// Must be called exactly once for every successful `handleRequest` return.
/// Frees each `ssz_payload` slice, then frees the outer `chunks` slice.
/// It is safe to call with an empty slice (e.g. Goodbye returns 0 chunks).
pub fn freeResponseChunks(allocator: Allocator, chunks: []const ResponseChunk) void {
    for (chunks) |chunk| {
        if (chunk.ssz_payload.len > 0) allocator.free(chunk.ssz_payload);
    }
    if (chunks.len > 0) allocator.free(chunks);
}

// === Tests ===

// Mock context for testing.
const MockContext = struct {
    var status_received: ?StatusMessage.Type = null;
    var goodbye_reason: ?u64 = null;

    const mock_status: StatusMessage.Type = .{
        .fork_digest = .{ 0x01, 0x02, 0x03, 0x04 },
        .finalized_root = [_]u8{0xAA} ** 32,
        .finalized_epoch = 100,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 200,
    };

    const mock_metadata: MetadataV2.Type = .{
        .seq_number = 42,
        .attnets = .{ .data = [_]u8{0xFF} ** 8 },
        .syncnets = .{ .data = [_]u8{0x0F} },
    };

    const mock_fork_digest = [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE };

    // Mock block data: 3 blocks of 64 bytes each.
    const mock_block_1 = [_]u8{0x11} ** 64;
    const mock_block_2 = [_]u8{0x22} ** 64;
    const mock_block_3 = [_]u8{0x33} ** 64;
    const mock_blocks: []const []const u8 = &.{ &mock_block_1, &mock_block_2, &mock_block_3 };

    const mock_blob_1 = [_]u8{0xAA} ** 48;
    const mock_blob_2 = [_]u8{0xBB} ** 48;
    const mock_blobs: []const []const u8 = &.{ &mock_blob_1, &mock_blob_2 };

    // Root that maps to mock_block_1.
    const known_root_1: [32]u8 = [_]u8{0x01} ** 32;
    // Root that maps to mock_block_2.
    const known_root_2: [32]u8 = [_]u8{0x02} ** 32;
    // Unknown root.
    const unknown_root: [32]u8 = [_]u8{0xFF} ** 32;

    // Known blob identifier.
    const known_blob_root: [32]u8 = [_]u8{0x10} ** 32;
    const known_blob_index: u64 = 0;

    fn reset() void {
        status_received = null;
        goodbye_reason = null;
    }

    fn getStatus(_: *anyopaque) StatusMessage.Type {
        return mock_status;
    }

    fn getMetadata(_: *anyopaque) MetadataV2.Type {
        return mock_metadata;
    }

    fn getPingSequence(_: *anyopaque) u64 {
        return 99;
    }

    fn getBlockByRoot(_: *anyopaque, root: [32]u8) ?[]const u8 {
        if (std.mem.eql(u8, &root, &known_root_1)) return &mock_block_1;
        if (std.mem.eql(u8, &root, &known_root_2)) return &mock_block_2;
        return null;
    }

    fn getBlocksByRange(_: *anyopaque, _start_slot: u64, _count: u64) []const []const u8 {
        _ = _start_slot;
        _ = _count;
        return mock_blocks;
    }

    fn getBlobByRoot(_: *anyopaque, root: [32]u8, index: u64) ?[]const u8 {
        if (std.mem.eql(u8, &root, &known_blob_root) and index == known_blob_index) return &mock_blob_1;
        return null;
    }

    fn getBlobsByRange(_: *anyopaque, _start_slot: u64, _count: u64) []const []const u8 {
        _ = _start_slot;
        _ = _count;
        return mock_blobs;
    }

    fn getForkDigest(_: *anyopaque, _slot: u64) [4]u8 {
        _ = _slot;
        return mock_fork_digest;
    }

    fn onGoodbye(_: *anyopaque, reason: u64) void {
        goodbye_reason = reason;
    }

    fn onPeerStatus(_: *anyopaque, status: StatusMessage.Type) void {
        status_received = status;
    }

    var _sentinel: u8 = 0;
    const req_resp_context: ReqRespContext = .{
        .ptr = &_sentinel,
        .getStatus = &getStatus,
        .getMetadata = &getMetadata,
        .getPingSequence = &getPingSequence,
        .getBlockByRoot = &getBlockByRoot,
        .getBlocksByRange = &getBlocksByRange,
        .getBlobByRoot = &getBlobByRoot,
        .getBlobsByRange = &getBlobsByRange,
        .getForkDigest = &getForkDigest,
        .onGoodbye = &onGoodbye,
        .onPeerStatus = &onPeerStatus,
    };
};

test "Status exchange: send a StatusMessage, get one back" {
    const allocator = testing.allocator;
    MockContext.reset();

    // Build a peer status.
    const peer_status: StatusMessage.Type = .{
        .fork_digest = .{ 0x05, 0x06, 0x07, 0x08 },
        .finalized_root = [_]u8{0xCC} ** 32,
        .finalized_epoch = 50,
        .head_root = [_]u8{0xDD} ** 32,
        .head_slot = 150,
    };
    var request_bytes: [StatusMessage.fixed_size]u8 = undefined;
    _ = StatusMessage.serializeIntoBytes(&peer_status, &request_bytes);

    const chunks = try handleRequest(allocator, .status, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    // Should return exactly one success chunk.
    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);
    try testing.expect(chunks[0].context_bytes == null);

    // Decode the response and verify it's our mock status.
    var response_status: StatusMessage.Type = undefined;
    try StatusMessage.deserializeFromBytes(chunks[0].ssz_payload, &response_status);
    try testing.expectEqual(MockContext.mock_status.head_slot, response_status.head_slot);
    try testing.expectEqual(MockContext.mock_status.finalized_epoch, response_status.finalized_epoch);

    // Verify onPeerStatus was called with the peer's status.
    try testing.expect(MockContext.status_received != null);
    try testing.expectEqual(peer_status.head_slot, MockContext.status_received.?.head_slot);
}

test "Ping roundtrip" {
    const allocator = testing.allocator;
    MockContext.reset();

    const peer_seq: Ping.Type = 7;
    var request_bytes: [Ping.fixed_size]u8 = undefined;
    _ = Ping.serializeIntoBytes(&peer_seq, &request_bytes);

    const chunks = try handleRequest(allocator, .ping, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);
    try testing.expect(chunks[0].context_bytes == null);

    // Decode response — should be our sequence number (99).
    var response_seq: Ping.Type = undefined;
    try Ping.deserializeFromBytes(chunks[0].ssz_payload, &response_seq);
    try testing.expectEqual(@as(u64, 99), response_seq);
}

test "MetaData request: empty body returns metadata response" {
    const allocator = testing.allocator;
    MockContext.reset();

    const chunks = try handleRequest(allocator, .metadata, &[_]u8{}, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);
    try testing.expect(chunks[0].context_bytes == null);

    var response_meta: MetadataV2.Type = undefined;
    try MetadataV2.deserializeFromBytes(chunks[0].ssz_payload, &response_meta);
    try testing.expectEqual(MockContext.mock_metadata.seq_number, response_meta.seq_number);
}

test "Goodbye handling" {
    const allocator = testing.allocator;
    MockContext.reset();

    // Reason 1: client shut down.
    const reason: GoodbyeReason.Type = 1;
    var request_bytes: [GoodbyeReason.fixed_size]u8 = undefined;
    _ = GoodbyeReason.serializeIntoBytes(&reason, &request_bytes);

    const chunks = try handleRequest(allocator, .goodbye, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    // Goodbye returns no response chunks.
    try testing.expectEqual(@as(usize, 0), chunks.len);

    // Verify onGoodbye was called.
    try testing.expect(MockContext.goodbye_reason != null);
    try testing.expectEqual(@as(u64, 1), MockContext.goodbye_reason.?);
}

test "BeaconBlocksByRange: request 3 blocks, get 3 response chunks with context bytes" {
    const allocator = testing.allocator;
    MockContext.reset();

    const request: BeaconBlocksByRangeRequest.Type = .{
        .start_slot = 100,
        .count = 3,
    };
    var request_bytes: [BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try handleRequest(allocator, .beacon_blocks_by_range, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    // Mock returns 3 blocks.
    try testing.expectEqual(@as(usize, 3), chunks.len);

    for (chunks) |chunk| {
        try testing.expectEqual(ResponseCode.success, chunk.result);
        try testing.expect(chunk.context_bytes != null);
        try testing.expectEqualSlices(u8, &MockContext.mock_fork_digest, &chunk.context_bytes.?);
    }

    // Verify block contents.
    try testing.expectEqualSlices(u8, &MockContext.mock_block_1, chunks[0].ssz_payload);
    try testing.expectEqualSlices(u8, &MockContext.mock_block_2, chunks[1].ssz_payload);
    try testing.expectEqualSlices(u8, &MockContext.mock_block_3, chunks[2].ssz_payload);
}

test "BeaconBlocksByRange: count exceeding MAX_REQUEST_BLOCKS returns InvalidRequest" {
    const allocator = testing.allocator;
    MockContext.reset();

    const request: BeaconBlocksByRangeRequest.Type = .{
        .start_slot = 0,
        .count = max_request_blocks + 1,
    };
    var request_bytes: [BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try handleRequest(allocator, .beacon_blocks_by_range, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "BeaconBlocksByRoot: 2 known + 1 unknown root returns 2 response chunks" {
    const allocator = testing.allocator;
    MockContext.reset();

    // Build request: 3 roots concatenated (96 bytes).
    var request_bytes: [96]u8 = undefined;
    @memcpy(request_bytes[0..32], &MockContext.known_root_1);
    @memcpy(request_bytes[32..64], &MockContext.unknown_root);
    @memcpy(request_bytes[64..96], &MockContext.known_root_2);

    const chunks = try handleRequest(allocator, .beacon_blocks_by_root, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    // Should return 2 chunks (unknown root skipped).
    try testing.expectEqual(@as(usize, 2), chunks.len);

    for (chunks) |chunk| {
        try testing.expectEqual(ResponseCode.success, chunk.result);
        try testing.expect(chunk.context_bytes != null);
    }

    // First found block is mock_block_1, second is mock_block_2.
    try testing.expectEqualSlices(u8, &MockContext.mock_block_1, chunks[0].ssz_payload);
    try testing.expectEqualSlices(u8, &MockContext.mock_block_2, chunks[1].ssz_payload);
}

test "BlobSidecarsByRange: basic request/response" {
    const allocator = testing.allocator;
    MockContext.reset();

    const request: BlobSidecarsByRangeRequest.Type = .{
        .start_slot = 500,
        .count = 2,
    };
    var request_bytes: [BlobSidecarsByRangeRequest.fixed_size]u8 = undefined;
    _ = BlobSidecarsByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try handleRequest(allocator, .blob_sidecars_by_range, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    // Mock returns 2 blobs.
    try testing.expectEqual(@as(usize, 2), chunks.len);

    for (chunks) |chunk| {
        try testing.expectEqual(ResponseCode.success, chunk.result);
        try testing.expect(chunk.context_bytes != null);
        try testing.expectEqualSlices(u8, &MockContext.mock_fork_digest, &chunk.context_bytes.?);
    }

    try testing.expectEqualSlices(u8, &MockContext.mock_blob_1, chunks[0].ssz_payload);
    try testing.expectEqualSlices(u8, &MockContext.mock_blob_2, chunks[1].ssz_payload);
}

test "BlobSidecarsByRoot: known identifier returns 1 chunk, unknown returns empty" {
    const allocator = testing.allocator;
    MockContext.reset();

    // Build request: 1 known BlobIdentifier (root + index = 40 bytes).
    var request_bytes: [40]u8 = undefined;
    @memcpy(request_bytes[0..32], &MockContext.known_blob_root);
    std.mem.writeInt(u64, request_bytes[32..40], MockContext.known_blob_index, .little);

    const chunks = try handleRequest(allocator, .blob_sidecars_by_root, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);
    try testing.expectEqualSlices(u8, &MockContext.mock_blob_1, chunks[0].ssz_payload);
}

test "Oversized request returns InvalidRequest" {
    const allocator = testing.allocator;
    MockContext.reset();

    // Create a request exceeding max_payload_size.
    const oversized = try allocator.alloc(u8, max_payload_size + 1);
    defer allocator.free(oversized);
    @memset(oversized, 0);

    const chunks = try handleRequest(allocator, .status, oversized, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "Malformed SSZ returns InvalidRequest" {
    const allocator = testing.allocator;
    MockContext.reset();

    // Status expects 84 bytes; send 10.
    const bad_bytes = [_]u8{0x00} ** 10;

    const chunks = try handleRequest(allocator, .status, &bad_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "BeaconBlocksByRange: zero count returns InvalidRequest" {
    const allocator = testing.allocator;
    MockContext.reset();

    const request: BeaconBlocksByRangeRequest.Type = .{
        .start_slot = 0,
        .count = 0,
    };
    var request_bytes: [BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try handleRequest(allocator, .beacon_blocks_by_range, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "BlobSidecarsByRange: count exceeding MAX_REQUEST_BLOB_SIDECARS returns InvalidRequest" {
    const allocator = testing.allocator;
    MockContext.reset();

    const request: BlobSidecarsByRangeRequest.Type = .{
        .start_slot = 0,
        .count = max_request_blob_sidecars + 1,
    };
    var request_bytes: [BlobSidecarsByRangeRequest.fixed_size]u8 = undefined;
    _ = BlobSidecarsByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try handleRequest(allocator, .blob_sidecars_by_range, &request_bytes, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "Light client methods return ServerError (not yet implemented)" {
    const allocator = testing.allocator;
    MockContext.reset();

    const chunks = try handleRequest(allocator, .light_client_bootstrap, &[_]u8{}, &MockContext.req_resp_context);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.server_error, chunks[0].result);
}
