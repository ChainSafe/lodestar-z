//! Eth2 req/resp protocol handlers for eth-p2p-z integration.
//!
//! These handlers are deliberately thin:
//! - read exactly one request message from the stream
//! - hand it to `req_resp_handler.serveRequest`
//! - stream response chunks directly back to the peer

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const protocol = @import("protocol.zig");
const req_resp_encoding = @import("req_resp_encoding.zig");
const req_resp_handler = @import("req_resp_handler.zig");

const ReqRespContext = req_resp_handler.ReqRespContext;
const RequestMeta = req_resp_handler.RequestMeta;
const ResponseChunk = req_resp_handler.ResponseChunk;

const log = std.log.scoped(.eth2_protocols);

pub const ReqRespServerDecision = enum {
    allow,
    deny_peer,
    deny_global,
};

pub const ReqRespRequestOutcome = protocol.ReqRespRequestOutcome;

pub const ReqRespServerPolicy = struct {
    ptr: *anyopaque,
    allowInboundRequestFn: *const fn (ptr: *anyopaque, peer_id: ?[]const u8, method: protocol.Method, request_bytes: []const u8) ReqRespServerDecision,

    pub fn allowInboundRequest(self: *const ReqRespServerPolicy, peer_id: ?[]const u8, method: protocol.Method, request_bytes: []const u8) ReqRespServerDecision {
        return self.allowInboundRequestFn(self.ptr, peer_id, method, request_bytes);
    }
};

fn peerIdFromCtx(ctx: anytype) ?[]const u8 {
    return if (@hasField(@TypeOf(ctx), "peer_id")) ctx.peer_id else null;
}

fn requestElapsedSeconds(io: Io, started_ns: i128) f64 {
    const now_ns = std.Io.Clock.awake.now(io).nanoseconds;
    const elapsed_ns = @max(now_ns - started_ns, 0);
    return @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
}

fn notifyRequestCompleted(
    context: *const ReqRespContext,
    io: Io,
    method: protocol.Method,
    started_ns: i128,
    outcome: ReqRespRequestOutcome,
) void {
    context.onRequestCompleted(context.ptr, method, outcome, requestElapsedSeconds(io, started_ns));
}

fn makeProtocolHandler(
    comptime method: protocol.Method,
    comptime id_literal: []const u8,
    comptime version: u8,
) type {
    return struct {
        allocator: Allocator,
        context: *const ReqRespContext,
        server_policy: ?*const ReqRespServerPolicy,

        pub const id: []const u8 = id_literal;

        const Self = @This();

        pub fn init(allocator: Allocator, context: *const ReqRespContext, server_policy: ?*const ReqRespServerPolicy) Self {
            return .{ .allocator = allocator, .context = context, .server_policy = server_policy };
        }

        pub fn handleInbound(self: *Self, io: Io, stream: anytype, ctx: anytype) !void {
            var response_writer_ctx = StreamResponseWriter(@TypeOf(stream)){
                .allocator = self.allocator,
                .io = io,
                .stream = stream,
            };
            var response_writer = response_writer_ctx.asWriter();
            const started_ns = std.Io.Clock.awake.now(io).nanoseconds;

            const request_bytes = req_resp_encoding.readRequestFromStream(self.allocator, io, stream) catch |err| {
                log.debug("{s} request decode error: {}", .{ id, err });
                try response_writer.writeError(.invalid_request, "Malformed request");
                notifyRequestCompleted(self.context, io, method, started_ns, .decode_error);
                stream.closeWrite(io);
                return;
            };
            defer self.allocator.free(request_bytes);

            if (self.server_policy) |server_policy| {
                switch (server_policy.allowInboundRequest(peerIdFromCtx(ctx), method, request_bytes)) {
                    .allow => {},
                    .deny_peer => {
                        notifyRequestCompleted(self.context, io, method, started_ns, .rate_limited_peer);
                        stream.closeWrite(io);
                        return;
                    },
                    .deny_global => {
                        notifyRequestCompleted(self.context, io, method, started_ns, .rate_limited_global);
                        stream.closeWrite(io);
                        return;
                    },
                }
            }

            req_resp_handler.serveRequestVersioned(
                self.allocator,
                method,
                version,
                request_bytes,
                RequestMeta{ .peer_id = peerIdFromCtx(ctx) },
                self.context,
                &response_writer,
            ) catch |err| {
                log.debug("{s} handler error: {}", .{ id, err });
                notifyRequestCompleted(self.context, io, method, started_ns, .internal_error);
                try response_writer.writeError(.server_error, "Internal server error");
                stream.closeWrite(io);
                return;
            };

            notifyRequestCompleted(
                self.context,
                io,
                method,
                started_ns,
                if (response_writer_ctx.first_result) |result|
                    protocol.ReqRespRequestOutcome.fromResponseCode(result)
                else
                    .internal_error,
            );
            stream.closeWrite(io);
        }

        pub fn handleOutbound(self: *Self, io: Io, stream: anytype, ctx: anytype) !void {
            const ssz_payload: []const u8 = if (@hasField(@TypeOf(ctx), "ssz_payload"))
                ctx.ssz_payload
            else
                &.{};

            try req_resp_encoding.writeRequestToStream(self.allocator, io, stream, ssz_payload);
            stream.closeWrite(io);

            var reader = req_resp_encoding.ResponseChunkStreamReader{
                .allocator = self.allocator,
                .has_context_bytes = method.hasContextBytes(),
            };
            defer reader.deinit();

            while (try reader.next(io, stream)) |chunk| {
                self.allocator.free(chunk.ssz_bytes);
                if (!chunk.result.isSuccess()) break;
                if (!method.hasMultipleResponses()) break;
            }
        }

        pub const protocol_method = method;
        pub const protocol_version = version;
    };
}

fn StreamResponseWriter(comptime StreamPtr: type) type {
    return struct {
        allocator: Allocator,
        io: Io,
        stream: StreamPtr,
        first_result: ?protocol.ResponseCode = null,

        fn asWriter(self: *@This()) req_resp_handler.ResponseWriter {
            return .{
                .ptr = self,
                .writeChunkFn = &writeChunk,
            };
        }

        fn writeChunk(ptr: *anyopaque, chunk: ResponseChunk) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.first_result == null) self.first_result = chunk.result;
            return req_resp_encoding.writeResponseChunkToStream(
                self.allocator,
                self.io,
                self.stream,
                chunk.result,
                chunk.context_bytes,
                chunk.ssz_payload,
            );
        }
    };
}

pub const StatusProtocol = makeProtocolHandler(
    .status,
    "/eth2/beacon_chain/req/status/1/ssz_snappy",
    1,
);

pub const StatusV2Protocol = makeProtocolHandler(
    .status,
    "/eth2/beacon_chain/req/status/2/ssz_snappy",
    2,
);

pub const GoodbyeProtocol = makeProtocolHandler(
    .goodbye,
    "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
    1,
);

pub const PingProtocol = makeProtocolHandler(
    .ping,
    "/eth2/beacon_chain/req/ping/1/ssz_snappy",
    1,
);

pub const MetadataProtocol = makeProtocolHandler(
    .metadata,
    "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
    2,
);

pub const MetadataV3Protocol = makeProtocolHandler(
    .metadata,
    "/eth2/beacon_chain/req/metadata/3/ssz_snappy",
    3,
);

pub const BlocksByRangeProtocol = makeProtocolHandler(
    .beacon_blocks_by_range,
    "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
    2,
);

pub const BlocksByRootProtocol = makeProtocolHandler(
    .beacon_blocks_by_root,
    "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
    2,
);

pub const BlobSidecarsByRangeProtocol = makeProtocolHandler(
    .blob_sidecars_by_range,
    "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy",
    1,
);

pub const BlobSidecarsByRootProtocol = makeProtocolHandler(
    .blob_sidecars_by_root,
    "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy",
    1,
);

pub const DataColumnsByRangeProtocol = makeProtocolHandler(
    .data_column_sidecars_by_range,
    "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy",
    1,
);

pub const DataColumnsByRootProtocol = makeProtocolHandler(
    .data_column_sidecars_by_root,
    "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy",
    1,
);

pub const LightClientBootstrapProtocol = makeProtocolHandler(
    .light_client_bootstrap,
    "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy",
    1,
);

pub const LightClientUpdatesByRangeProtocol = makeProtocolHandler(
    .light_client_updates_by_range,
    "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy",
    1,
);

pub const LightClientFinalityUpdateProtocol = makeProtocolHandler(
    .light_client_finality_update,
    "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy",
    1,
);

pub const LightClientOptimisticUpdateProtocol = makeProtocolHandler(
    .light_client_optimistic_update,
    "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy",
    1,
);

test "eth2_protocols: protocol IDs match spec" {
    const testing = std.testing;

    try testing.expectEqualStrings("/eth2/beacon_chain/req/status/1/ssz_snappy", StatusProtocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/status/2/ssz_snappy", StatusV2Protocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/goodbye/1/ssz_snappy", GoodbyeProtocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/ping/1/ssz_snappy", PingProtocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/metadata/2/ssz_snappy", MetadataProtocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/metadata/3/ssz_snappy", MetadataV3Protocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy", BlocksByRangeProtocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy", BlocksByRootProtocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy", BlobSidecarsByRangeProtocol.id);
    try testing.expectEqualStrings("/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy", BlobSidecarsByRootProtocol.id);
}

test "eth2_protocols: all handlers have required declarations" {
    const testing = std.testing;
    inline for (.{
        StatusProtocol,
        StatusV2Protocol,
        GoodbyeProtocol,
        PingProtocol,
        MetadataProtocol,
        MetadataV3Protocol,
        BlocksByRangeProtocol,
        BlocksByRootProtocol,
        BlobSidecarsByRangeProtocol,
        BlobSidecarsByRootProtocol,
        DataColumnsByRangeProtocol,
        DataColumnsByRootProtocol,
        LightClientBootstrapProtocol,
        LightClientUpdatesByRangeProtocol,
        LightClientFinalityUpdateProtocol,
        LightClientOptimisticUpdateProtocol,
    }) |Handler| {
        try testing.expect(@hasDecl(Handler, "id"));
        try testing.expect(@hasDecl(Handler, "handleInbound"));
        try testing.expect(@hasDecl(Handler, "handleOutbound"));
    }
}
