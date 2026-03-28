//! Eth2 req/resp protocol handlers for eth-p2p-z integration.
//!
//! Each struct satisfies eth-p2p-z's protocol handler interface:
//!   - `pub const id: []const u8`
//!   - `pub fn handleInbound(self, io, stream, ctx) !void`
//!   - `pub fn handleOutbound(self, io, stream, ctx) !void`
//!
//! These are thin wrappers that read wire-encoded bytes from the stream
//! (varint + snappy), dispatch to EthReqRespAdapter, then write the
//! wire-encoded response bytes back.
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const protocol = @import("protocol.zig");
const req_resp_encoding = @import("req_resp_encoding.zig");
const eth_reqresp = @import("eth_reqresp.zig");

const EthReqRespAdapter = eth_reqresp.EthReqRespAdapter;
const ReqRespContext = @import("req_resp_handler.zig").ReqRespContext;

const log = std.log.scoped(.eth2_protocols);

/// Maximum wire bytes to read for a single request (10 MiB + framing overhead).
const max_request_wire_bytes: usize = 11 * 1024 * 1024;

// ─── Comptime ID generation ───────────────────────────────────────────────────
//
// Each protocol needs a stable comptime const []const u8 for `pub const id`.
// We generate these as module-level constants so the slice pointer is stable.

fn makeId(comptime method: protocol.Method) *const [64]u8 {
    comptime {
        var buf: [64]u8 = undefined;
        const s = protocol.protocolId(&buf, method, .ssz_snappy);
        var result: [64]u8 = undefined;
        @memcpy(result[0..s.len], s);
        @memset(result[s.len..], 0);
        const static: [64]u8 = result;
        return &static;
    }
}

// Module-level constant protocol ID buffers.
const status_id_buf = makeId(.status);
const goodbye_id_buf = makeId(.goodbye);
const ping_id_buf = makeId(.ping);
const metadata_id_buf = makeId(.metadata);
const blocks_by_range_id_buf = makeId(.beacon_blocks_by_range);
const blocks_by_root_id_buf = makeId(.beacon_blocks_by_root);
const blobs_by_range_id_buf = makeId(.blob_sidecars_by_range);
const blobs_by_root_id_buf = makeId(.blob_sidecars_by_root);

fn idSlice(comptime method: protocol.Method) []const u8 {
    comptime {
        var buf: [64]u8 = undefined;
        const s = protocol.protocolId(&buf, method, .ssz_snappy);
        return s;
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn readAllFromStream(
    allocator: Allocator,
    io: Io,
    stream: anytype,
    max_len: usize,
) ![]u8 {
    var buf = try std.ArrayListUnmanaged(u8).initCapacity(allocator, 4096);
    errdefer buf.deinit(allocator);

    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = try stream.read(io, &tmp);
        if (n == 0) break;
        if (buf.items.len + n > max_len) return error.RequestTooLarge;
        try buf.appendSlice(allocator, tmp[0..n]);
    }
    return buf.toOwnedSlice(allocator);
}

fn writeAllToStream(io: Io, stream: anytype, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const n = try stream.write(io, data[written..]);
        if (n == 0) return error.StreamClosed;
        written += n;
    }
}

fn handleInboundForProtocol(
    allocator: Allocator,
    context: *const ReqRespContext,
    protocol_id: []const u8,
    io: Io,
    stream: anytype,
) !void {
    const wire_bytes = readAllFromStream(allocator, io, stream, max_request_wire_bytes) catch |err| {
        log.warn("Failed to read request from stream for {s}: {}", .{ protocol_id, err });
        return;
    };
    defer allocator.free(wire_bytes);

    var adapter = EthReqRespAdapter.init(allocator, context);
    const response_wire = adapter.handleStream(protocol_id, wire_bytes) catch |err| {
        log.warn("Failed to handle request for {s}: {}", .{ protocol_id, err });
        return;
    };
    defer allocator.free(response_wire);

    writeAllToStream(io, stream, response_wire) catch |err| {
        log.warn("Failed to write response for {s}: {}", .{ protocol_id, err });
    };
}

// ─── Comptime protocol handler factory ───────────────────────────────────────

fn makeProtocolHandler(
    comptime method: protocol.Method,
    comptime id_literal: []const u8,
) type {
    return struct {
        allocator: Allocator,
        context: *const ReqRespContext,

        /// Protocol ID for multistream-select negotiation.
        pub const id: []const u8 = id_literal;

        const Self = @This();

        pub fn init(allocator: Allocator, context: *const ReqRespContext) Self {
            return .{ .allocator = allocator, .context = context };
        }

        pub fn handleInbound(self: *Self, io: Io, stream: anytype, _: anytype) !void {
            handleInboundForProtocol(self.allocator, self.context, id, io, stream) catch |err| {
                log.warn("{s} handleInbound error: {}", .{ id, err });
            };
        }

        /// Handle an outbound request: encode SSZ and write to stream.
        ///
        /// Expects `ctx` to have `ssz_payload: []const u8` (use `&.{}` for zero-body methods).
        pub fn handleOutbound(self: *Self, io: Io, stream: anytype, ctx: anytype) !void {
            const ssz_bytes: []const u8 = if (@hasField(@TypeOf(ctx), "ssz_payload"))
                ctx.ssz_payload
            else
                &.{};

            const wire_bytes = req_resp_encoding.encodeRequest(self.allocator, ssz_bytes) catch |err| {
                log.warn("{s} handleOutbound encode error: {}", .{ id, err });
                return err;
            };
            defer self.allocator.free(wire_bytes);

            writeAllToStream(io, stream, wire_bytes) catch |err| {
                log.warn("{s} handleOutbound write error: {}", .{ id, err });
                return err;
            };

            // Read response from peer (for request-response protocols).
            const response_wire = readAllFromStream(self.allocator, io, stream, max_request_wire_bytes) catch |err| {
                log.warn("{s} handleOutbound read response error: {}", .{ id, err });
                return;
            };
            defer self.allocator.free(response_wire);
            log.info("{s} handleOutbound: received {d} byte response", .{ id, response_wire.len });
        }

        // Store method for diagnostics.
        pub const protocol_method = method;
    };
}

// ─── Concrete handler types ───────────────────────────────────────────────────
//
// Protocol IDs from the eth2 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#messages

/// Status exchange (phase0).
pub const StatusProtocol = makeProtocolHandler(
    .status,
    "/eth2/beacon_chain/req/status/1/ssz_snappy",
);

/// Goodbye (peer disconnection notice).
pub const GoodbyeProtocol = makeProtocolHandler(
    .goodbye,
    "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
);

/// Ping / metadata sequence number exchange.
pub const PingProtocol = makeProtocolHandler(
    .ping,
    "/eth2/beacon_chain/req/ping/1/ssz_snappy",
);

/// Metadata request (no request body).
///
/// Uses /metadata/2/ssz_snappy — post-Altair, peers negotiate v2 which returns
/// MetadataV2 (includes syncnets field). Using v1 while returning v2 bytes
/// confuses other clients.
pub const MetadataProtocol = makeProtocolHandler(
    .metadata,
    "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
);

/// BeaconBlocksByRange v2 (includes fork-digest context bytes).
pub const BlocksByRangeProtocol = makeProtocolHandler(
    .beacon_blocks_by_range,
    "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
);

/// BeaconBlocksByRoot v2 (includes fork-digest context bytes).
pub const BlocksByRootProtocol = makeProtocolHandler(
    .beacon_blocks_by_root,
    "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
);

/// BlobSidecarsByRange (deneb+).
pub const BlobSidecarsByRangeProtocol = makeProtocolHandler(
    .blob_sidecars_by_range,
    "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy",
);

/// BlobSidecarsByRoot (deneb+).
pub const BlobSidecarsByRootProtocol = makeProtocolHandler(
    .blob_sidecars_by_root,
    "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy",
);

// ─── Tests ───────────────────────────────────────────────────────────────────

test "eth2_protocols: protocol IDs match spec" {
    const testing = std.testing;

    try testing.expectEqualStrings(
        "/eth2/beacon_chain/req/status/1/ssz_snappy",
        StatusProtocol.id,
    );
    try testing.expectEqualStrings(
        "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
        GoodbyeProtocol.id,
    );
    try testing.expectEqualStrings(
        "/eth2/beacon_chain/req/ping/1/ssz_snappy",
        PingProtocol.id,
    );
    try testing.expectEqualStrings(
        "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
        MetadataProtocol.id,
    );
    try testing.expectEqualStrings(
        "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
        BlocksByRangeProtocol.id,
    );
    try testing.expectEqualStrings(
        "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
        BlocksByRootProtocol.id,
    );
    try testing.expectEqualStrings(
        "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy",
        BlobSidecarsByRangeProtocol.id,
    );
    try testing.expectEqualStrings(
        "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy",
        BlobSidecarsByRootProtocol.id,
    );
}

test "eth2_protocols: all handlers have required declarations" {
    const testing = std.testing;
    inline for (.{
        StatusProtocol,
        GoodbyeProtocol,
        PingProtocol,
        MetadataProtocol,
        BlocksByRangeProtocol,
        BlocksByRootProtocol,
        BlobSidecarsByRangeProtocol,
        BlobSidecarsByRootProtocol,
    }) |Handler| {
        try testing.expect(@hasDecl(Handler, "id"));
        try testing.expect(@hasDecl(Handler, "handleInbound"));
        try testing.expect(@hasDecl(Handler, "handleOutbound"));
    }
}

test "eth2_protocols: all IDs are distinct" {
    const testing = std.testing;
    const ids = [_][]const u8{
        StatusProtocol.id,
        GoodbyeProtocol.id,
        PingProtocol.id,
        MetadataProtocol.id,
        BlocksByRangeProtocol.id,
        BlocksByRootProtocol.id,
        BlobSidecarsByRangeProtocol.id,
        BlobSidecarsByRootProtocol.id,
    };
    for (ids, 0..) |id_a, i| {
        for (ids, 0..) |id_b, j| {
            if (i != j) {
                try testing.expect(!std.mem.eql(u8, id_a, id_b));
            }
        }
    }
}

test "eth2_protocols: IDs match what protocolId() generates" {
    const testing = std.testing;
    var buf: [128]u8 = undefined;

    try testing.expectEqualStrings(
        protocol.protocolId(&buf, .status, .ssz_snappy),
        StatusProtocol.id,
    );
    try testing.expectEqualStrings(
        protocol.protocolId(&buf, .beacon_blocks_by_range, .ssz_snappy),
        BlocksByRangeProtocol.id,
    );
    try testing.expectEqualStrings(
        protocol.protocolId(&buf, .blob_sidecars_by_root, .ssz_snappy),
        BlobSidecarsByRootProtocol.id,
    );
}

// ─── PeerDAS and LightClient protocol handlers ────────────────────────────────

/// DataColumnSidecarsByRange (fulu/PeerDAS).
pub const DataColumnsByRangeProtocol = makeProtocolHandler(
    .data_column_sidecars_by_range,
    "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy",
);

/// DataColumnSidecarsByRoot (fulu/PeerDAS).
pub const DataColumnsByRootProtocol = makeProtocolHandler(
    .data_column_sidecars_by_root,
    "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy",
);

/// LightClientBootstrap stub (altair+).
pub const LightClientBootstrapProtocol = makeProtocolHandler(
    .light_client_bootstrap,
    "/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy",
);

/// LightClientUpdatesByRange stub (altair+).
pub const LightClientUpdatesByRangeProtocol = makeProtocolHandler(
    .light_client_updates_by_range,
    "/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy",
);

/// LightClientFinalityUpdate stub (altair+).
pub const LightClientFinalityUpdateProtocol = makeProtocolHandler(
    .light_client_finality_update,
    "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy",
);

/// LightClientOptimisticUpdate stub (altair+).
pub const LightClientOptimisticUpdateProtocol = makeProtocolHandler(
    .light_client_optimistic_update,
    "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy",
);
