//! Standard Beacon API error response format.
//!
//! The Ethereum Beacon API specifies a common error response shape:
//!   { "statusCode": N, "message": "..." }
//!
//! This module provides:
//! - `ErrorCode` — HTTP status codes used by the Beacon API
//! - `ApiError` — typed error with status + message
//! - `fromZigError` — maps Zig `anyerror` values to `ApiError`
//! - `formatJson` — formats an `ApiError` into a fixed-size JSON string
//!
//! TypeScript equivalent: packages/api/src/utils/server/error.ts

const std = @import("std");

/// HTTP status codes used by the Beacon API.
pub const ErrorCode = enum(u16) {
    accepted = 202,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    unsupported_media_type = 415,
    internal_server_error = 500,
    not_implemented = 501,
    service_unavailable = 503,

    pub fn statusCode(self: ErrorCode) u16 {
        return @intFromEnum(self);
    }

    pub fn phrase(self: ErrorCode) []const u8 {
        return switch (self) {
            .accepted => "Accepted",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .not_acceptable => "Not Acceptable",
            .unsupported_media_type => "Unsupported Media Type",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .service_unavailable => "Service Unavailable",
        };
    }
};

/// A Beacon API error — HTTP status code + message.
pub const ApiError = struct {
    code: ErrorCode,
    message: []const u8,

    /// Format as JSON: `{"statusCode":N,"message":"..."}`
    ///
    /// Writes into `buf` and returns the populated slice.
    /// `buf` must be large enough for the formatted string.
    /// Minimal required size: 32 + message.len bytes.
    pub fn formatJson(self: ApiError, buf: []u8) []const u8 {
        const result = std.fmt.bufPrint(
            buf,
            "{{\"statusCode\":{d},\"message\":\"{s}\"}}",
            .{ self.code.statusCode(), self.message },
        ) catch buf[0..0];
        return result;
    }
};

/// Map a Zig error value to a Beacon API `ApiError`.
///
/// Covers the errors that handlers in this codebase can return.
/// Any unrecognized error maps to 500 Internal Server Error.
pub fn fromZigError(err: anyerror) ApiError {
    return switch (err) {
        // 202 Accepted (block already known — not an error, but returned through error path)
        error.BlockAlreadyKnown,
        => .{ .code = .accepted, .message = "Block already known" },

        // 400 Bad Request
        error.InvalidBlockId,
        error.InvalidStateId,
        error.InvalidValidatorId,
        error.BadRequest,
        error.InvalidInput,
        error.InvalidRequest,
        error.InvalidHex,
        error.InvalidRequestBody,
        error.MissingField,
        error.MismatchedCounts,
        error.InvalidBlockType,
        error.UnsupportedFork,
        => .{ .code = .bad_request, .message = "Bad request: invalid parameter" },

        // 401 Unauthorized
        error.Unauthorized,
        => .{ .code = .unauthorized, .message = "Unauthorized" },

        // 403 Forbidden
        error.KeymanagerDisabled,
        => .{ .code = .forbidden, .message = "Keymanager is disabled" },
        error.ProposerConfigWriteDisabled,
        => .{ .code = .forbidden, .message = "Proposer config writes are disabled" },

        // 404 Not Found
        error.BlockNotFound,
        error.StateNotFound,
        error.StateNotAvailable,
        error.ValidatorNotFound,
        error.SlotNotFound,
        error.NotFound,
        error.PeerNotFound,
        => .{ .code = .not_found, .message = "Resource not found" },

        // 405 Method Not Allowed
        error.MethodNotAllowed,
        => .{ .code = .method_not_allowed, .message = "Method not allowed" },

        // 406 Not Acceptable (content negotiation failure)
        error.NotAcceptable,
        => .{ .code = .not_acceptable, .message = "Accepted media types not supported" },

        // 415 Unsupported Media Type
        error.UnsupportedMediaType,
        => .{ .code = .unsupported_media_type, .message = "Unsupported media type" },

        // 501 Not Implemented
        error.NotImplemented,
        error.ValidatorMonitorNotConfigured,
        error.UnsupportedBuilderSelection,
        => .{ .code = .not_implemented, .message = "Not implemented" },

        // 503 Service Unavailable
        error.ServiceUnavailable,
        error.NodeNotReady,
        error.BuilderNotConfigured,
        => .{ .code = .service_unavailable, .message = "Service unavailable" },

        // 500 Internal Server Error (default)
        else => .{ .code = .internal_server_error, .message = "Internal server error" },
    };
}

/// Format a Zig error directly to a JSON buffer.
///
/// Convenience wrapper around `fromZigError` + `ApiError.formatJson`.
pub fn formatZigError(err: anyerror, buf: []u8) struct {
    json: []const u8,
    status: u16,
} {
    const api_err = fromZigError(err);
    return .{
        .json = api_err.formatJson(buf),
        .status = api_err.code.statusCode(),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ApiError.formatJson basic" {
    const err = ApiError{ .code = .not_found, .message = "Block not found" };
    var buf: [256]u8 = undefined;
    const json = err.formatJson(&buf);
    try std.testing.expectEqualStrings(
        "{\"statusCode\":404,\"message\":\"Block not found\"}",
        json,
    );
}

test "ApiError.formatJson bad request" {
    const err = ApiError{ .code = .bad_request, .message = "Invalid identifier" };
    var buf: [256]u8 = undefined;
    const json = err.formatJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"statusCode\":400") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "Invalid identifier") != null);
}

test "fromZigError not_found errors" {
    const cases = [_]anyerror{
        error.BlockNotFound,
        error.StateNotFound,
        error.ValidatorNotFound,
        error.SlotNotFound,
    };
    for (cases) |err| {
        const api_err = fromZigError(err);
        try std.testing.expectEqual(ErrorCode.not_found, api_err.code);
        try std.testing.expectEqual(@as(u16, 404), api_err.code.statusCode());
    }
}

test "fromZigError bad_request errors" {
    const cases = [_]anyerror{
        error.InvalidBlockId,
        error.InvalidStateId,
        error.InvalidValidatorId,
    };
    for (cases) |err| {
        const api_err = fromZigError(err);
        try std.testing.expectEqual(ErrorCode.bad_request, api_err.code);
    }
}

test "fromZigError not_implemented" {
    const api_err = fromZigError(error.NotImplemented);
    try std.testing.expectEqual(ErrorCode.not_implemented, api_err.code);
    try std.testing.expectEqual(@as(u16, 501), api_err.code.statusCode());
}

test "fromZigError unknown error maps to 500" {
    const api_err = fromZigError(error.SomeRandomError);
    try std.testing.expectEqual(ErrorCode.internal_server_error, api_err.code);
    try std.testing.expectEqual(@as(u16, 500), api_err.code.statusCode());
}

test "fromZigError not_acceptable" {
    const api_err = fromZigError(error.NotAcceptable);
    try std.testing.expectEqual(ErrorCode.not_acceptable, api_err.code);
    try std.testing.expectEqual(@as(u16, 406), api_err.code.statusCode());
}

test "formatZigError convenience wrapper" {
    var buf: [256]u8 = undefined;
    const result = formatZigError(error.BlockNotFound, &buf);
    try std.testing.expectEqual(@as(u16, 404), result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.json, "404") != null);
}

test "ErrorCode.phrase" {
    try std.testing.expectEqualStrings("Not Found", ErrorCode.not_found.phrase());
    try std.testing.expectEqualStrings("Internal Server Error", ErrorCode.internal_server_error.phrase());
}
