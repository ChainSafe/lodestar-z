//! Response helpers for the Beacon REST API.
//!
//! Owns content-negotiation and error-response surfaces used by the HTTP
//! server. JSON body encoding for live endpoints lives in `json_response.zig`.

const std = @import("std");

const content_negotiation = @import("content_negotiation.zig");
const response_meta = @import("response_meta.zig");
const error_response = @import("error_response.zig");
const handler_result = @import("handler_result.zig");

/// Re-exports: content negotiation
pub const WireFormat = content_negotiation.WireFormat;
pub const NegotiationResult = content_negotiation.NegotiationResult;
pub const parseAcceptHeader = content_negotiation.parseAcceptHeader;
pub const parseContentTypeHeader = content_negotiation.parseContentTypeHeader;

/// Re-exports: response metadata
pub const ResponseMeta = response_meta.ResponseMeta;
pub const Fork = response_meta.Fork;
pub const MetaHeader = response_meta.MetaHeader;
pub const buildMetaHeaders = response_meta.buildHeaders;

/// Re-exports: error responses
pub const ApiError = error_response.ApiError;
pub const ErrorCode = error_response.ErrorCode;
pub const fromZigError = error_response.fromZigError;
pub const formatZigErrorAlloc = error_response.formatZigErrorAlloc;

/// Re-exports: handler result
pub const HandlerResult = handler_result.HandlerResult;
pub const VoidResult = handler_result.VoidResult;

/// Format an ApiError as JSON bytes.
///
/// Returns `{ "statusCode": N, "message": "..." }` per Beacon API spec.
pub fn encodeErrorJson(
    allocator: std.mem.Allocator,
    api_err: error_response.ApiError,
) error_response.FormatJsonError![]u8 {
    return api_err.formatJsonAlloc(allocator);
}

test "encodeErrorJson" {
    const err = error_response.ApiError{ .code = .not_found, .message = "Block not found" };
    const json = try encodeErrorJson(std.testing.allocator, err);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"statusCode\":404") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "Block not found") != null);
}
