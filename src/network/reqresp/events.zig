const config = @import("config");
const codec = @import("codec.zig");
const constants = @import("constants.zig");
const negotiate = @import("../negotiate.zig");
const types = @import("../types.zig");
const Handle = types.Handle;
const Protocol = @import("protocol.zig").Protocol;

pub const RequestPhase = enum { negotiation, request, response };

pub const RequestHandle = struct {
    index: u16,
    generation: u32,
    direction: types.Direction,
};

pub const Failure = union(enum) {
    timeout,
    host_timeout,
    quota_timeout,
    cancelled,
    negotiation_rejected,
    negotiation_failed: negotiate.Failure,
    invalid_response: (codec.Error || error{InvalidResponseContext}),
    invalid_request: codec.Error,
    too_many_chunks,
    unknown_context: [constants.context_bytes_length]u8,
    peer_error: struct { code: u8, message_len: u16 },
    connection_closed,
    stream_closed,
    transport,
};

pub const Event = union(enum) {
    chunk: struct { request: RequestHandle, bytes: []const u8, fork: ?config.ForkSeq },
    done: struct { request: RequestHandle, chunks: u32 },
    failed: struct { request: RequestHandle, reason: Failure, phase: ?RequestPhase = null },
    request: struct { request: RequestHandle, peer: Handle, protocol: Protocol, bytes: []const u8 },
    chunk_sent: struct { request: RequestHandle, chunks: u32 },
    served: struct { request: RequestHandle, chunks: u32 },
};
