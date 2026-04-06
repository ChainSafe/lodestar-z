//! Streaming req/resp business logic for the Ethereum consensus P2P layer.
//!
//! This module owns request validation and protocol semantics. It does not own
//! transport framing or buffering. Callers provide a `ResponseWriter` that is
//! invoked synchronously for each response chunk as the data becomes available.

const std = @import("std");
const log = std.log.scoped(.req_resp);
const testing = std.testing;
const Allocator = std.mem.Allocator;
const constants = @import("constants");
const config_mod = @import("config");
const protocol = @import("protocol.zig");
const messages = @import("messages.zig");

const ForkSeq = config_mod.ForkSeq;
const Method = protocol.Method;
const ResponseCode = protocol.ResponseCode;
const StatusMessage = messages.StatusMessage;
const StatusMessageV2 = messages.StatusMessageV2;
const Ping = messages.Ping;
const GoodbyeReason = messages.GoodbyeReason;
const MetadataV2 = messages.MetadataV2;
const MetadataV3 = messages.MetadataV3;
const BeaconBlocksByRangeRequest = messages.BeaconBlocksByRangeRequest;
const BeaconBlocksByRootRequest = messages.BeaconBlocksByRootRequest;
const BlobSidecarsByRangeRequest = messages.BlobSidecarsByRangeRequest;
const BlobSidecarsByRootRequest = messages.BlobSidecarsByRootRequest;
const DataColumnSidecarsByRangeRequest = messages.DataColumnSidecarsByRangeRequest;

/// Maximum request payload size: 10 MiB.
pub const max_payload_size: u32 = 10 * 1024 * 1024;

/// Maximum blocks per BeaconBlocksByRange / BeaconBlocksByRoot request pre-Deneb.
pub const max_request_blocks: u64 = constants.MAX_REQUEST_BLOCKS;

/// Maximum blocks per BeaconBlocksByRange / BeaconBlocksByRoot request Deneb+.
pub const max_request_blocks_deneb: u64 = constants.MAX_REQUEST_BLOCKS_DENEB;

/// Maximum blob sidecars per BlobSidecarsByRoot request.
pub const max_request_blob_sidecars: u64 = 768;

/// Maximum data column sidecars per DataColumnSidecarsByRange / Root request.
pub const max_request_data_column_sidecars: u64 = 16384;

/// Request metadata supplied by the transport layer.
pub const RequestMeta = struct {
    peer_id: ?[]const u8 = null,
};

/// A single emitted response chunk.
///
/// This is useful for testing and for any caller that wants to collect a full
/// response in memory, but `serveRequest` itself streams through `ResponseWriter`.
pub const ResponseChunk = struct {
    result: ResponseCode,
    context_bytes: ?[4]u8,
    ssz_payload: []const u8,
};

/// A discovered SSZ payload tagged with the slot used to compute fork context.
pub const SlotPayload = struct {
    slot: u64,
    ssz_payload: []const u8,
};

/// Synchronous payload sink used by the node-facing context callbacks.
///
/// The sink MUST NOT retain `ssz_payload` after `write` returns.
pub const PayloadSink = struct {
    ptr: *anyopaque,
    writePayloadFn: *const fn (ptr: *anyopaque, payload: SlotPayload) anyerror!void,

    pub fn write(self: *const PayloadSink, payload: SlotPayload) anyerror!void {
        return self.writePayloadFn(self.ptr, payload);
    }
};

/// Streaming response writer used by `serveRequest`.
///
/// The writer MUST fully consume `ssz_payload` before returning.
pub const ResponseWriter = struct {
    ptr: *anyopaque,
    writeChunkFn: *const fn (ptr: *anyopaque, chunk: ResponseChunk) anyerror!void,

    pub fn writeChunk(self: *const ResponseWriter, chunk: ResponseChunk) anyerror!void {
        return self.writeChunkFn(self.ptr, chunk);
    }

    pub fn writeSuccess(self: *const ResponseWriter, context_bytes: ?[4]u8, ssz_payload: []const u8) anyerror!void {
        return self.writeChunk(.{
            .result = .success,
            .context_bytes = context_bytes,
            .ssz_payload = ssz_payload,
        });
    }

    pub fn writeError(self: *const ResponseWriter, code: ResponseCode, message: []const u8) anyerror!void {
        return self.writeChunk(.{
            .result = code,
            .context_bytes = null,
            .ssz_payload = message,
        });
    }
};

/// Callback interface that the beacon node provides to req/resp handlers.
///
/// Range and lookup methods stream discovered items through a `PayloadSink`
/// instead of returning pre-materialized slices.
pub const ReqRespContext = struct {
    ptr: *anyopaque,
    getStatus: *const fn (ptr: *anyopaque) StatusMessage.Type,
    getMetadata: *const fn (ptr: *anyopaque) MetadataV2.Type,
    getEarliestAvailableSlot: *const fn (ptr: *anyopaque) u64,
    getCustodyGroupCount: *const fn (ptr: *anyopaque) u64,
    getPingSequence: *const fn (ptr: *anyopaque) u64,
    findBlockByRoot: *const fn (ptr: *anyopaque, root: [32]u8, sink: *const PayloadSink) anyerror!void,
    streamBlocksByRange: *const fn (ptr: *anyopaque, start_slot: u64, count: u64, sink: *const PayloadSink) anyerror!void,
    findBlobByRoot: *const fn (ptr: *anyopaque, root: [32]u8, index: u64, sink: *const PayloadSink) anyerror!void,
    streamBlobsByRange: *const fn (ptr: *anyopaque, start_slot: u64, count: u64, sink: *const PayloadSink) anyerror!void,
    findDataColumnByRoot: ?*const fn (ptr: *anyopaque, root: [32]u8, index: u64, sink: *const PayloadSink) anyerror!void = null,
    streamDataColumnsByRange: ?*const fn (ptr: *anyopaque, start_slot: u64, count: u64, columns: []const u64, sink: *const PayloadSink) anyerror!void = null,
    getCurrentForkSeq: *const fn (ptr: *anyopaque) ForkSeq,
    getForkSeqForSlot: *const fn (ptr: *anyopaque, slot: u64) ForkSeq,
    getForkDigest: *const fn (ptr: *anyopaque, slot: u64) [4]u8,
    onGoodbye: *const fn (ptr: *anyopaque, peer_id: ?[]const u8, reason: u64) void,
    onPeerStatus: *const fn (ptr: *anyopaque, peer_id: ?[]const u8, status: StatusMessage.Type, earliest_available_slot: ?u64) void,
    onRequestCompleted: *const fn (ptr: *anyopaque, method: Method, outcome: protocol.ReqRespRequestOutcome, response_time_seconds: f64) void,
};

/// Dispatch an incoming request into zero or more streamed response chunks.
pub fn serveRequest(
    allocator: Allocator,
    method: Method,
    request_bytes: []const u8,
    request_meta: RequestMeta,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    return serveRequestVersioned(allocator, method, method.version(), request_bytes, request_meta, context, writer);
}

pub fn serveRequestVersioned(
    allocator: Allocator,
    method: Method,
    protocol_version: u8,
    request_bytes: []const u8,
    request_meta: RequestMeta,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    if (request_bytes.len > max_payload_size) {
        return writer.writeError(.invalid_request, "Request payload exceeds maximum size");
    }

    return switch (method) {
        .status => serveStatus(protocol_version, request_bytes, request_meta, context, writer),
        .goodbye => serveGoodbye(request_bytes, request_meta, context, writer),
        .ping => servePing(request_bytes, context, writer),
        .metadata => serveMetadata(protocol_version, request_bytes, context, writer),
        .beacon_blocks_by_range => serveBeaconBlocksByRange(request_bytes, context, writer),
        .beacon_blocks_by_root => serveBeaconBlocksByRoot(request_bytes, context, writer),
        .blob_sidecars_by_range => serveBlobSidecarsByRange(request_bytes, context, writer),
        .blob_sidecars_by_root => serveBlobSidecarsByRoot(request_bytes, context, writer),
        .data_column_sidecars_by_root => serveDataColumnSidecarsByRoot(request_bytes, context, writer),
        .data_column_sidecars_by_range => serveDataColumnSidecarsByRange(allocator, request_bytes, context, writer),
        .light_client_bootstrap,
        .light_client_updates_by_range,
        .light_client_finality_update,
        .light_client_optimistic_update,
        => writer.writeError(.server_error, "Light client methods not yet implemented"),
    };
}

pub fn handleRequest(
    allocator: Allocator,
    method: Method,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) ![]const ResponseChunk {
    return handleRequestVersioned(allocator, method, method.version(), request_bytes, context);
}

pub fn handleRequestVersioned(
    allocator: Allocator,
    method: Method,
    protocol_version: u8,
    request_bytes: []const u8,
    context: *const ReqRespContext,
) ![]const ResponseChunk {
    var collector = CollectingWriter{ .allocator = allocator };
    errdefer collector.deinit();
    var writer = collector.writer();
    try serveRequestVersioned(allocator, method, protocol_version, request_bytes, .{}, context, &writer);
    return try collector.finish();
}

fn serveStatus(
    protocol_version: u8,
    request_bytes: []const u8,
    request_meta: RequestMeta,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    switch (protocol_version) {
        1 => {
            if (request_bytes.len != StatusMessage.fixed_size) {
                return writer.writeError(.invalid_request, "Invalid StatusMessage size");
            }

            var peer_status: StatusMessage.Type = undefined;
            StatusMessage.deserializeFromBytes(request_bytes, &peer_status) catch {
                return writer.writeError(.invalid_request, "Malformed StatusMessage");
            };

            context.onPeerStatus(context.ptr, request_meta.peer_id, peer_status, null);

            const our_status = context.getStatus(context.ptr);
            var payload: [StatusMessage.fixed_size]u8 = undefined;
            _ = StatusMessage.serializeIntoBytes(&our_status, &payload);
            return writer.writeSuccess(null, &payload);
        },
        2 => {
            if (request_bytes.len != StatusMessageV2.fixed_size) {
                return writer.writeError(.invalid_request, "Invalid StatusMessageV2 size");
            }

            var peer_status: StatusMessageV2.Type = undefined;
            StatusMessageV2.deserializeFromBytes(request_bytes, &peer_status) catch {
                return writer.writeError(.invalid_request, "Malformed StatusMessageV2");
            };

            context.onPeerStatus(context.ptr, request_meta.peer_id, .{
                .fork_digest = peer_status.fork_digest,
                .finalized_root = peer_status.finalized_root,
                .finalized_epoch = peer_status.finalized_epoch,
                .head_root = peer_status.head_root,
                .head_slot = peer_status.head_slot,
            }, peer_status.earliest_available_slot);

            const our_status = context.getStatus(context.ptr);
            const our_status_v2: StatusMessageV2.Type = .{
                .fork_digest = our_status.fork_digest,
                .finalized_root = our_status.finalized_root,
                .finalized_epoch = our_status.finalized_epoch,
                .head_root = our_status.head_root,
                .head_slot = our_status.head_slot,
                .earliest_available_slot = context.getEarliestAvailableSlot(context.ptr),
            };
            var payload: [StatusMessageV2.fixed_size]u8 = undefined;
            _ = StatusMessageV2.serializeIntoBytes(&our_status_v2, &payload);
            return writer.writeSuccess(null, &payload);
        },
        else => return writer.writeError(.invalid_request, "Unsupported Status protocol version"),
    }
}

fn serveGoodbye(
    request_bytes: []const u8,
    request_meta: RequestMeta,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    if (request_bytes.len != GoodbyeReason.fixed_size) {
        return writer.writeError(.invalid_request, "Invalid GoodbyeReason size");
    }

    var reason: GoodbyeReason.Type = undefined;
    GoodbyeReason.deserializeFromBytes(request_bytes, &reason) catch {
        return writer.writeError(.invalid_request, "Malformed GoodbyeReason");
    };

    log.info("Goodbye received: reason={d}", .{reason});
    context.onGoodbye(context.ptr, request_meta.peer_id, reason);
}

fn servePing(
    request_bytes: []const u8,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    if (request_bytes.len != Ping.fixed_size) {
        return writer.writeError(.invalid_request, "Invalid Ping size");
    }

    var peer_seq: Ping.Type = undefined;
    Ping.deserializeFromBytes(request_bytes, &peer_seq) catch {
        return writer.writeError(.invalid_request, "Malformed Ping");
    };

    const our_seq = context.getPingSequence(context.ptr);
    var payload: [Ping.fixed_size]u8 = undefined;
    _ = Ping.serializeIntoBytes(&our_seq, &payload);
    return writer.writeSuccess(null, &payload);
}

fn serveMetadata(
    protocol_version: u8,
    request_bytes: []const u8,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    if (request_bytes.len != 0) {
        return writer.writeError(.invalid_request, "Metadata request body must be empty");
    }

    switch (protocol_version) {
        2 => {
            const metadata = context.getMetadata(context.ptr);
            var payload: [MetadataV2.fixed_size]u8 = undefined;
            _ = MetadataV2.serializeIntoBytes(&metadata, &payload);
            return writer.writeSuccess(null, &payload);
        },
        3 => {
            const metadata = context.getMetadata(context.ptr);
            const metadata_v3: MetadataV3.Type = .{
                .seq_number = metadata.seq_number,
                .attnets = metadata.attnets,
                .syncnets = metadata.syncnets,
                .custody_group_count = context.getCustodyGroupCount(context.ptr),
            };
            var payload: [MetadataV3.fixed_size]u8 = undefined;
            _ = MetadataV3.serializeIntoBytes(&metadata_v3, &payload);
            return writer.writeSuccess(null, &payload);
        },
        else => return writer.writeError(.invalid_request, "Unsupported Metadata protocol version"),
    }
}

fn serveBeaconBlocksByRange(
    request_bytes: []const u8,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    if (request_bytes.len != BeaconBlocksByRangeRequest.fixed_size) {
        return writer.writeError(.invalid_request, "Invalid BeaconBlocksByRangeRequest size");
    }

    var request: BeaconBlocksByRangeRequest.Type = undefined;
    BeaconBlocksByRangeRequest.deserializeFromBytes(request_bytes, &request) catch {
        return writer.writeError(.invalid_request, "Malformed BeaconBlocksByRangeRequest");
    };

    if (request.count == 0) {
        return writer.writeError(.invalid_request, "Count must be greater than zero");
    }
    const max_blocks = maxRequestBlocksForRange(context, request.start_slot);
    if (request.count > max_blocks) {
        request.count = max_blocks;
    }

    var emitter = ContextualEmitter{ .context = context, .writer = writer };
    var sink = emitter.asSink();
    return context.streamBlocksByRange(context.ptr, request.start_slot, request.count, &sink);
}

fn currentMaxRequestBlocks(context: *const ReqRespContext) u64 {
    return if (context.getCurrentForkSeq(context.ptr).gte(.deneb))
        max_request_blocks_deneb
    else
        max_request_blocks;
}

fn maxRequestBlocksForRange(context: *const ReqRespContext, slot: u64) u64 {
    return if (context.getForkSeqForSlot(context.ptr, slot).gte(.deneb))
        max_request_blocks_deneb
    else
        max_request_blocks;
}

fn serveBeaconBlocksByRoot(
    request_bytes: []const u8,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    if (request_bytes.len == 0 or request_bytes.len % 32 != 0) {
        return writer.writeError(.invalid_request, "Invalid BeaconBlocksByRootRequest size");
    }

    const num_roots = request_bytes.len / 32;
    if (num_roots > currentMaxRequestBlocks(context)) {
        return writer.writeError(.invalid_request, "Too many roots requested");
    }

    var emitter = ContextualEmitter{ .context = context, .writer = writer };
    var sink = emitter.asSink();
    for (0..num_roots) |i| {
        const root: [32]u8 = request_bytes[i * 32 ..][0..32].*;
        try context.findBlockByRoot(context.ptr, root, &sink);
    }
}

fn serveBlobSidecarsByRange(
    request_bytes: []const u8,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    if (request_bytes.len != BlobSidecarsByRangeRequest.fixed_size) {
        return writer.writeError(.invalid_request, "Invalid BlobSidecarsByRangeRequest size");
    }

    var request: BlobSidecarsByRangeRequest.Type = undefined;
    BlobSidecarsByRangeRequest.deserializeFromBytes(request_bytes, &request) catch {
        return writer.writeError(.invalid_request, "Malformed BlobSidecarsByRangeRequest");
    };

    if (request.count == 0) {
        return writer.writeError(.invalid_request, "Count must be greater than zero");
    }
    if (request.count > max_request_blocks_deneb) {
        request.count = max_request_blocks_deneb;
    }

    var emitter = ContextualEmitter{ .context = context, .writer = writer };
    var sink = emitter.asSink();
    return context.streamBlobsByRange(context.ptr, request.start_slot, request.count, &sink);
}

fn serveBlobSidecarsByRoot(
    request_bytes: []const u8,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    const blob_id_size = 40;
    if (request_bytes.len == 0 or request_bytes.len % blob_id_size != 0) {
        return writer.writeError(.invalid_request, "Invalid BlobSidecarsByRootRequest size");
    }

    const num_ids = request_bytes.len / blob_id_size;
    if (num_ids > max_request_blob_sidecars) {
        return writer.writeError(.invalid_request, "Too many blob identifiers requested");
    }

    var emitter = ContextualEmitter{ .context = context, .writer = writer };
    var sink = emitter.asSink();
    for (0..num_ids) |i| {
        const offset = i * blob_id_size;
        const root: [32]u8 = request_bytes[offset..][0..32].*;
        const index = std.mem.readInt(u64, request_bytes[offset + 32 ..][0..8], .little);
        try context.findBlobByRoot(context.ptr, root, index, &sink);
    }
}

fn serveDataColumnSidecarsByRoot(
    request_bytes: []const u8,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    const findDataColumnByRoot = context.findDataColumnByRoot orelse {
        return writer.writeError(.server_error, "DataColumnSidecarsByRoot not supported");
    };

    const id_size = 40;
    if (request_bytes.len == 0 or request_bytes.len % id_size != 0) {
        return writer.writeError(.invalid_request, "Invalid DataColumnSidecarsByRootRequest size");
    }

    const num_ids = request_bytes.len / id_size;
    if (num_ids > max_request_data_column_sidecars) {
        return writer.writeError(.invalid_request, "Too many data column identifiers requested");
    }

    var emitter = ContextualEmitter{ .context = context, .writer = writer };
    var sink = emitter.asSink();
    for (0..num_ids) |i| {
        const offset = i * id_size;
        const root: [32]u8 = request_bytes[offset..][0..32].*;
        const index = std.mem.readInt(u64, request_bytes[offset + 32 ..][0..8], .little);
        try findDataColumnByRoot(context.ptr, root, index, &sink);
    }
}

fn serveDataColumnSidecarsByRange(
    allocator: Allocator,
    request_bytes: []const u8,
    context: *const ReqRespContext,
    writer: *const ResponseWriter,
) anyerror!void {
    const streamDataColumnsByRange = context.streamDataColumnsByRange orelse {
        return writer.writeError(.server_error, "DataColumnSidecarsByRange not supported");
    };

    var request: DataColumnSidecarsByRangeRequest.Type = .{
        .start_slot = 0,
        .count = 0,
        .columns = .empty,
    };
    DataColumnSidecarsByRangeRequest.deserializeFromBytes(allocator, request_bytes, &request) catch {
        return writer.writeError(.invalid_request, "Malformed DataColumnSidecarsByRangeRequest");
    };
    defer DataColumnSidecarsByRangeRequest.deinit(allocator, &request);

    if (request.count == 0) {
        return writer.writeError(.invalid_request, "Count must be greater than zero");
    }
    if (request.columns.items.len == 0) {
        return writer.writeError(.invalid_request, "Columns must not be empty");
    }
    if (request.count > max_request_blocks_deneb) {
        request.count = max_request_blocks_deneb;
    }

    var emitter = ContextualEmitter{ .context = context, .writer = writer };
    var sink = emitter.asSink();
    return streamDataColumnsByRange(context.ptr, request.start_slot, request.count, request.columns.items, &sink);
}

const ContextualEmitter = struct {
    context: *const ReqRespContext,
    writer: *const ResponseWriter,

    fn asSink(self: *ContextualEmitter) PayloadSink {
        return .{
            .ptr = self,
            .writePayloadFn = &writePayload,
        };
    }

    fn writePayload(ptr: *anyopaque, payload: SlotPayload) anyerror!void {
        const self: *ContextualEmitter = @ptrCast(@alignCast(ptr));
        return self.writer.writeSuccess(
            self.context.getForkDigest(self.context.ptr, payload.slot),
            payload.ssz_payload,
        );
    }
};

pub fn freeResponseChunks(allocator: Allocator, chunks: []const ResponseChunk) void {
    for (chunks) |chunk| {
        if (chunk.ssz_payload.len > 0) allocator.free(chunk.ssz_payload);
    }
    if (chunks.len > 0) allocator.free(chunks);
}

pub const CollectingWriter = struct {
    allocator: Allocator,
    chunks: std.ArrayListUnmanaged(ResponseChunk) = .empty,

    pub fn deinit(self: *CollectingWriter) void {
        for (self.chunks.items) |chunk| {
            if (chunk.ssz_payload.len > 0) self.allocator.free(chunk.ssz_payload);
        }
        self.chunks.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn finish(self: *CollectingWriter) ![]const ResponseChunk {
        const items = try self.chunks.toOwnedSlice(self.allocator);
        self.chunks = .empty;
        return items;
    }

    pub fn writer(self: *CollectingWriter) ResponseWriter {
        return .{
            .ptr = self,
            .writeChunkFn = &collectChunk,
        };
    }

    fn collectChunk(ptr: *anyopaque, chunk: ResponseChunk) anyerror!void {
        const self: *CollectingWriter = @ptrCast(@alignCast(ptr));
        const payload = try self.allocator.alloc(u8, chunk.ssz_payload.len);
        @memcpy(payload, chunk.ssz_payload);
        try self.chunks.append(self.allocator, .{
            .result = chunk.result,
            .context_bytes = chunk.context_bytes,
            .ssz_payload = payload,
        });
    }
};

// === Tests ===

const MockContext = struct {
    var status_received: ?StatusMessage.Type = null;
    var status_received_earliest_available_slot: ?u64 = null;
    var status_peer_id: ?[]const u8 = null;
    var goodbye_reason: ?u64 = null;
    var goodbye_peer_id: ?[]const u8 = null;
    var current_fork_seq: ForkSeq = .phase0;
    var range_fork_seq: ForkSeq = .phase0;
    var last_blocks_by_range_count: ?u64 = null;
    var last_blobs_by_range_count: ?u64 = null;
    var last_columns_by_range_count: ?u64 = null;
    var last_columns_by_range_columns_len: ?usize = null;

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
    const mock_block_1 = [_]u8{0x11} ** 64;
    const mock_block_2 = [_]u8{0x22} ** 64;
    const mock_block_3 = [_]u8{0x33} ** 64;
    const mock_blob_1 = [_]u8{0xAA} ** 48;
    const mock_blob_2 = [_]u8{0xBB} ** 48;
    const mock_column_1 = [_]u8{0xC1} ** 80;
    const mock_column_2 = [_]u8{0xC2} ** 80;

    const known_root_1: [32]u8 = [_]u8{0x01} ** 32;
    const known_root_2: [32]u8 = [_]u8{0x02} ** 32;
    const unknown_root: [32]u8 = [_]u8{0xFF} ** 32;
    const known_blob_root: [32]u8 = [_]u8{0x10} ** 32;
    const known_blob_index: u64 = 0;

    fn reset() void {
        status_received = null;
        status_received_earliest_available_slot = null;
        status_peer_id = null;
        goodbye_reason = null;
        goodbye_peer_id = null;
        current_fork_seq = .phase0;
        range_fork_seq = .phase0;
        last_blocks_by_range_count = null;
        last_blobs_by_range_count = null;
        last_columns_by_range_count = null;
        last_columns_by_range_columns_len = null;
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

    fn getEarliestAvailableSlot(_: *anyopaque) u64 {
        return 64;
    }

    fn getCustodyGroupCount(_: *anyopaque) u64 {
        return 12;
    }

    fn findBlockByRoot(_: *anyopaque, root: [32]u8, sink: *const PayloadSink) anyerror!void {
        if (std.mem.eql(u8, &root, &known_root_1)) {
            try sink.write(.{ .slot = 64, .ssz_payload = &mock_block_1 });
        } else if (std.mem.eql(u8, &root, &known_root_2)) {
            try sink.write(.{ .slot = 65, .ssz_payload = &mock_block_2 });
        }
    }

    fn streamBlocksByRange(_: *anyopaque, start_slot: u64, count: u64, sink: *const PayloadSink) anyerror!void {
        last_blocks_by_range_count = count;
        var slot = start_slot;
        if (count > 0) {
            try sink.write(.{ .slot = slot, .ssz_payload = &mock_block_1 });
            slot += 1;
        }
        if (count > 1) {
            try sink.write(.{ .slot = slot, .ssz_payload = &mock_block_2 });
            slot += 1;
        }
        if (count > 2) {
            try sink.write(.{ .slot = slot, .ssz_payload = &mock_block_3 });
        }
    }

    fn findBlobByRoot(_: *anyopaque, root: [32]u8, index: u64, sink: *const PayloadSink) anyerror!void {
        if (std.mem.eql(u8, &root, &known_blob_root) and index == known_blob_index) {
            try sink.write(.{ .slot = 500, .ssz_payload = &mock_blob_1 });
        }
    }

    fn streamBlobsByRange(_: *anyopaque, start_slot: u64, count: u64, sink: *const PayloadSink) anyerror!void {
        last_blobs_by_range_count = count;
        if (count > 0) try sink.write(.{ .slot = start_slot, .ssz_payload = &mock_blob_1 });
        if (count > 1) try sink.write(.{ .slot = start_slot + 1, .ssz_payload = &mock_blob_2 });
    }

    fn findDataColumnByRoot(_: *anyopaque, root: [32]u8, index: u64, sink: *const PayloadSink) anyerror!void {
        if (std.mem.eql(u8, &root, &known_root_1) and index == 7) {
            try sink.write(.{ .slot = 700, .ssz_payload = &mock_column_1 });
        }
    }

    fn streamDataColumnsByRange(_: *anyopaque, start_slot: u64, count: u64, columns: []const u64, sink: *const PayloadSink) anyerror!void {
        last_columns_by_range_count = count;
        last_columns_by_range_columns_len = columns.len;
        if (count == 0 or columns.len == 0) return;
        try sink.write(.{ .slot = start_slot, .ssz_payload = &mock_column_1 });
        if (count > 1 and columns.len > 1) {
            try sink.write(.{ .slot = start_slot + 1, .ssz_payload = &mock_column_2 });
        }
    }

    fn getCurrentForkSeq(_: *anyopaque) ForkSeq {
        return current_fork_seq;
    }

    fn getForkSeqForSlot(_: *anyopaque, _: u64) ForkSeq {
        return range_fork_seq;
    }

    fn getForkDigest(_: *anyopaque, _: u64) [4]u8 {
        return mock_fork_digest;
    }

    fn onGoodbye(_: *anyopaque, peer_id: ?[]const u8, reason: u64) void {
        goodbye_peer_id = peer_id;
        goodbye_reason = reason;
    }

    fn onPeerStatus(_: *anyopaque, peer_id: ?[]const u8, status: StatusMessage.Type, earliest_available_slot: ?u64) void {
        status_peer_id = peer_id;
        status_received = status;
        status_received_earliest_available_slot = earliest_available_slot;
    }

    fn onRequestCompleted(_: *anyopaque, _: Method, _: protocol.ReqRespRequestOutcome, _: f64) void {}

    var sentinel: u8 = 0;
    const req_resp_context: ReqRespContext = .{
        .ptr = &sentinel,
        .getStatus = &getStatus,
        .getMetadata = &getMetadata,
        .getEarliestAvailableSlot = &getEarliestAvailableSlot,
        .getCustodyGroupCount = &getCustodyGroupCount,
        .getPingSequence = &getPingSequence,
        .findBlockByRoot = &findBlockByRoot,
        .streamBlocksByRange = &streamBlocksByRange,
        .findBlobByRoot = &findBlobByRoot,
        .streamBlobsByRange = &streamBlobsByRange,
        .findDataColumnByRoot = &findDataColumnByRoot,
        .streamDataColumnsByRange = &streamDataColumnsByRange,
        .getCurrentForkSeq = &getCurrentForkSeq,
        .getForkSeqForSlot = &getForkSeqForSlot,
        .getForkDigest = &getForkDigest,
        .onGoodbye = &onGoodbye,
        .onPeerStatus = &onPeerStatus,
        .onRequestCompleted = &onRequestCompleted,
    };
};

fn collectRequest(
    allocator: Allocator,
    method: Method,
    request_bytes: []const u8,
    peer_id: ?[]const u8,
) ![]const ResponseChunk {
    return collectRequestVersioned(allocator, method, method.version(), request_bytes, peer_id);
}

fn collectRequestVersioned(
    allocator: Allocator,
    method: Method,
    protocol_version: u8,
    request_bytes: []const u8,
    peer_id: ?[]const u8,
) ![]const ResponseChunk {
    var collector = CollectingWriter{ .allocator = allocator };
    errdefer collector.deinit();
    var writer = collector.writer();
    try serveRequestVersioned(allocator, method, protocol_version, request_bytes, .{ .peer_id = peer_id }, &MockContext.req_resp_context, &writer);
    return try collector.finish();
}

test "Status exchange streams a response and preserves peer metadata" {
    const allocator = testing.allocator;
    MockContext.reset();

    const peer_status: StatusMessage.Type = .{
        .fork_digest = .{ 0x05, 0x06, 0x07, 0x08 },
        .finalized_root = [_]u8{0xCC} ** 32,
        .finalized_epoch = 50,
        .head_root = [_]u8{0xDD} ** 32,
        .head_slot = 150,
    };
    var request_bytes: [StatusMessage.fixed_size]u8 = undefined;
    _ = StatusMessage.serializeIntoBytes(&peer_status, &request_bytes);

    const chunks = try collectRequest(allocator, .status, &request_bytes, "peer-a");
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);
    try testing.expect(chunks[0].context_bytes == null);

    var response_status: StatusMessage.Type = undefined;
    try StatusMessage.deserializeFromBytes(chunks[0].ssz_payload, &response_status);
    try testing.expectEqual(MockContext.mock_status.head_slot, response_status.head_slot);
    try testing.expectEqual(peer_status.head_slot, MockContext.status_received.?.head_slot);
    try testing.expectEqualStrings("peer-a", MockContext.status_peer_id.?);
}

test "StatusV2 exchange preserves earliestAvailableSlot" {
    const allocator = testing.allocator;
    MockContext.reset();

    const peer_status: StatusMessageV2.Type = .{
        .fork_digest = .{ 0x05, 0x06, 0x07, 0x08 },
        .finalized_root = [_]u8{0xCC} ** 32,
        .finalized_epoch = 50,
        .head_root = [_]u8{0xDD} ** 32,
        .head_slot = 150,
        .earliest_available_slot = 32,
    };
    var request_bytes: [StatusMessageV2.fixed_size]u8 = undefined;
    _ = StatusMessageV2.serializeIntoBytes(&peer_status, &request_bytes);

    const chunks = try collectRequestVersioned(allocator, .status, 2, &request_bytes, "peer-v2");
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);

    var response_status: StatusMessageV2.Type = undefined;
    try StatusMessageV2.deserializeFromBytes(chunks[0].ssz_payload, &response_status);
    try testing.expectEqual(@as(u64, 64), response_status.earliest_available_slot);
    try testing.expectEqual(@as(?u64, 32), MockContext.status_received_earliest_available_slot);
    try testing.expectEqualStrings("peer-v2", MockContext.status_peer_id.?);
}

test "Ping roundtrip" {
    const allocator = testing.allocator;

    const peer_seq: Ping.Type = 7;
    var request_bytes: [Ping.fixed_size]u8 = undefined;
    _ = Ping.serializeIntoBytes(&peer_seq, &request_bytes);

    const chunks = try collectRequest(allocator, .ping, &request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);

    var response_seq: Ping.Type = undefined;
    try Ping.deserializeFromBytes(chunks[0].ssz_payload, &response_seq);
    try testing.expectEqual(@as(u64, 99), response_seq);
}

test "Metadata request returns metadata response" {
    const allocator = testing.allocator;

    const chunks = try collectRequest(allocator, .metadata, &.{}, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);

    var response_meta: MetadataV2.Type = undefined;
    try MetadataV2.deserializeFromBytes(chunks[0].ssz_payload, &response_meta);
    try testing.expectEqual(MockContext.mock_metadata.seq_number, response_meta.seq_number);
}

test "MetadataV3 request returns custody group count" {
    const allocator = testing.allocator;

    const chunks = try collectRequestVersioned(allocator, .metadata, 3, &.{}, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.success, chunks[0].result);

    var response_meta: MetadataV3.Type = undefined;
    try MetadataV3.deserializeFromBytes(chunks[0].ssz_payload, &response_meta);
    try testing.expectEqual(@as(u64, 12), response_meta.custody_group_count);
}

test "Goodbye handling notifies context and emits no chunks" {
    const allocator = testing.allocator;
    MockContext.reset();

    const reason: GoodbyeReason.Type = 1;
    var request_bytes: [GoodbyeReason.fixed_size]u8 = undefined;
    _ = GoodbyeReason.serializeIntoBytes(&reason, &request_bytes);

    const chunks = try collectRequest(allocator, .goodbye, &request_bytes, "peer-b");
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 0), chunks.len);
    try testing.expectEqual(@as(u64, 1), MockContext.goodbye_reason.?);
    try testing.expectEqualStrings("peer-b", MockContext.goodbye_peer_id.?);
}

test "BeaconBlocksByRange streams success chunks with context bytes" {
    const allocator = testing.allocator;
    MockContext.reset();

    const request: BeaconBlocksByRangeRequest.Type = .{
        .start_slot = 100,
        .count = 3,
    };
    var request_bytes: [BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try collectRequest(allocator, .beacon_blocks_by_range, &request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 3), chunks.len);
    for (chunks) |chunk| {
        try testing.expectEqual(ResponseCode.success, chunk.result);
        try testing.expectEqualSlices(u8, &MockContext.mock_fork_digest, &chunk.context_bytes.?);
    }
}

test "BeaconBlocksByRange clamps Deneb-era requests instead of rejecting them" {
    const allocator = testing.allocator;
    MockContext.reset();
    MockContext.range_fork_seq = .deneb;

    const request: BeaconBlocksByRangeRequest.Type = .{
        .start_slot = 100,
        .count = max_request_blocks_deneb + 1,
    };
    var request_bytes: [BeaconBlocksByRangeRequest.fixed_size]u8 = undefined;
    _ = BeaconBlocksByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try collectRequest(allocator, .beacon_blocks_by_range, &request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(max_request_blocks_deneb, MockContext.last_blocks_by_range_count.?);
    try testing.expectEqual(@as(usize, 3), chunks.len);
}

test "BeaconBlocksByRoot skips unknown roots without allocating placeholder chunks" {
    const allocator = testing.allocator;
    MockContext.reset();

    var request_bytes: [96]u8 = undefined;
    @memcpy(request_bytes[0..32], &MockContext.known_root_1);
    @memcpy(request_bytes[32..64], &MockContext.unknown_root);
    @memcpy(request_bytes[64..96], &MockContext.known_root_2);

    const chunks = try collectRequest(allocator, .beacon_blocks_by_root, &request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 2), chunks.len);
    try testing.expectEqualSlices(u8, &MockContext.mock_block_1, chunks[0].ssz_payload);
    try testing.expectEqualSlices(u8, &MockContext.mock_block_2, chunks[1].ssz_payload);
}

test "BeaconBlocksByRoot enforces Deneb-era root request limits" {
    const allocator = testing.allocator;
    MockContext.reset();
    MockContext.current_fork_seq = .deneb;

    const request_bytes = try allocator.alloc(u8, (max_request_blocks_deneb + 1) * 32);
    defer allocator.free(request_bytes);
    @memset(request_bytes, 0);

    const chunks = try collectRequest(allocator, .beacon_blocks_by_root, request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "BlobSidecarsByRange streams chunked responses" {
    const allocator = testing.allocator;
    MockContext.reset();

    const request: BlobSidecarsByRangeRequest.Type = .{
        .start_slot = 500,
        .count = 2,
    };
    var request_bytes: [BlobSidecarsByRangeRequest.fixed_size]u8 = undefined;
    _ = BlobSidecarsByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try collectRequest(allocator, .blob_sidecars_by_range, &request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 2), chunks.len);
    try testing.expectEqualSlices(u8, &MockContext.mock_blob_1, chunks[0].ssz_payload);
    try testing.expectEqualSlices(u8, &MockContext.mock_blob_2, chunks[1].ssz_payload);
}

test "BlobSidecarsByRange clamps slot count at the Deneb request limit" {
    const allocator = testing.allocator;
    MockContext.reset();

    const request: BlobSidecarsByRangeRequest.Type = .{
        .start_slot = 500,
        .count = max_request_blocks_deneb + 1,
    };
    var request_bytes: [BlobSidecarsByRangeRequest.fixed_size]u8 = undefined;
    _ = BlobSidecarsByRangeRequest.serializeIntoBytes(&request, &request_bytes);

    const chunks = try collectRequest(allocator, .blob_sidecars_by_range, &request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(max_request_blocks_deneb, MockContext.last_blobs_by_range_count.?);
    try testing.expectEqual(@as(usize, 2), chunks.len);
}

test "DataColumnSidecarsByRange forwards requested columns to the context" {
    const allocator = testing.allocator;
    MockContext.reset();

    var request: DataColumnSidecarsByRangeRequest.Type = .{
        .start_slot = 700,
        .count = 2,
        .columns = .empty,
    };
    defer DataColumnSidecarsByRangeRequest.deinit(allocator, &request);
    try request.columns.appendSlice(allocator, &.{ 7, 8 });

    const request_bytes = try allocator.alloc(u8, DataColumnSidecarsByRangeRequest.serializedSize(&request));
    _ = DataColumnSidecarsByRangeRequest.serializeIntoBytes(&request, request_bytes);
    defer allocator.free(request_bytes);

    const chunks = try collectRequest(allocator, .data_column_sidecars_by_range, request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 2), chunks.len);
    try testing.expectEqualSlices(u8, &MockContext.mock_column_1, chunks[0].ssz_payload);
    try testing.expectEqualSlices(u8, &MockContext.mock_column_2, chunks[1].ssz_payload);
}

test "DataColumnSidecarsByRange rejects empty column lists" {
    const allocator = testing.allocator;
    MockContext.reset();

    var request: DataColumnSidecarsByRangeRequest.Type = .{
        .start_slot = 700,
        .count = 1,
        .columns = .empty,
    };
    defer DataColumnSidecarsByRangeRequest.deinit(allocator, &request);

    const request_bytes = try allocator.alloc(u8, DataColumnSidecarsByRangeRequest.serializedSize(&request));
    _ = DataColumnSidecarsByRangeRequest.serializeIntoBytes(&request, request_bytes);
    defer allocator.free(request_bytes);

    const chunks = try collectRequest(allocator, .data_column_sidecars_by_range, request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "DataColumnSidecarsByRange clamps slot count at the Deneb request limit" {
    const allocator = testing.allocator;
    MockContext.reset();

    var request: DataColumnSidecarsByRangeRequest.Type = .{
        .start_slot = 700,
        .count = max_request_blocks_deneb + 1,
        .columns = .empty,
    };
    defer DataColumnSidecarsByRangeRequest.deinit(allocator, &request);
    try request.columns.append(allocator, 7);

    const request_bytes = try allocator.alloc(u8, DataColumnSidecarsByRangeRequest.serializedSize(&request));
    _ = DataColumnSidecarsByRangeRequest.serializeIntoBytes(&request, request_bytes);
    defer allocator.free(request_bytes);

    const chunks = try collectRequest(allocator, .data_column_sidecars_by_range, request_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(max_request_blocks_deneb, MockContext.last_columns_by_range_count.?);
    try testing.expectEqual(@as(usize, 1), MockContext.last_columns_by_range_columns_len.?);
    try testing.expectEqual(@as(usize, 1), chunks.len);
}

test "Oversized request returns InvalidRequest" {
    const allocator = testing.allocator;

    const oversized = try allocator.alloc(u8, max_payload_size + 1);
    defer allocator.free(oversized);
    @memset(oversized, 0);

    const chunks = try collectRequest(allocator, .status, oversized, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "Malformed SSZ returns InvalidRequest" {
    const allocator = testing.allocator;

    const bad_bytes = [_]u8{0x00} ** 10;
    const chunks = try collectRequest(allocator, .status, &bad_bytes, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.invalid_request, chunks[0].result);
}

test "Light client methods return ServerError" {
    const allocator = testing.allocator;

    const chunks = try collectRequest(allocator, .light_client_bootstrap, &.{}, null);
    defer freeResponseChunks(allocator, chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);
    try testing.expectEqual(ResponseCode.server_error, chunks[0].result);
}
