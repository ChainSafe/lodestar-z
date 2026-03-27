//! HandlerResult — typed response wrapper for Beacon API handlers.
//!
//! Handlers return `ApiErrorDetail!HandlerResult(T)` where:
//! - Errors are propagated as Zig errors (mapped to ApiError at dispatch boundary)
//! - Values carry data + metadata
//!
//! The dispatch layer serializes HandlerResult into JSON or SSZ, emitting
//! ResponseMeta fields both in HTTP headers and the JSON body.

const std = @import("std");
const response_meta = @import("response_meta.zig");
pub const ResponseMeta = response_meta.ResponseMeta;
pub const Fork = response_meta.Fork;

/// A handler's successful response: data + metadata + optional status override.
///
/// T = void for POST/empty responses
/// T = ?U for optional responses (null → 204 No Content)
pub fn HandlerResult(comptime T: type) type {
    return struct {
        /// Response data. void for empty responses.
        data: T,
        /// Response metadata (version, execution_optimistic, etc.)
        meta: ResponseMeta = .{},
        /// Pre-serialized SSZ bytes (optional, avoids double-serialization).
        ssz_bytes: ?[]const u8 = null,
        /// HTTP status override. 0 = use default (200 for data, 204 for void).
        status: u16 = 0,
    };
}

/// Result for void (POST/empty) responses.
pub const VoidResult = HandlerResult(void);

/// Get the effective HTTP status for a result.
/// Returns the override if set, otherwise 200 (or 204 for void type).
pub fn effectiveStatus(comptime T: type, result: HandlerResult(T)) u16 {
    if (result.status != 0) return result.status;
    if (T == void) return 204;
    return 200;
}
