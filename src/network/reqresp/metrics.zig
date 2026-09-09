const std = @import("std");
const Histogram = @import("../metrics_histogram.zig").Histogram;
const rr = @import("reqresp.zig");

pub const OutgoingTime = Histogram(&.{ 100, 200, 500, 1000, 5000, 10000, 15000, 60000 });
pub const IncomingTime = Histogram(&.{ 100, 200, 500, 1000, 5000, 10000 });
pub const ErrorReason = enum {
    REQUEST_ERROR_DIAL_TIMEOUT,
    REQUEST_ERROR_REQUEST_TIMEOUT,
    REQUEST_ERROR_RESP_TIMEOUT,
    REQUEST_ERROR_INVALID_RESPONSE_SSZ,
    REQUEST_ERROR_INVALID_REQUEST,
    REQUEST_ERROR_SERVER_ERROR,
    RESOURCE_UNAVAILABLE_ERROR,
    REQUEST_ERROR_UNKNOWN_ERROR_STATUS,
    REQUEST_ERROR_REQUEST_ERROR,

    pub fn fromFailure(reason: rr.Failure, phase: rr.RequestPhase) ErrorReason {
        return switch (reason) {
            .timeout => switch (phase) {
                .negotiation => .REQUEST_ERROR_DIAL_TIMEOUT,
                .request => .REQUEST_ERROR_REQUEST_TIMEOUT,
                .response => .REQUEST_ERROR_RESP_TIMEOUT,
            },
            .negotiation_failed => |failure| if (failure == .timeout) .REQUEST_ERROR_DIAL_TIMEOUT else .REQUEST_ERROR_REQUEST_ERROR,
            .invalid_response, .too_many_chunks, .unknown_context => .REQUEST_ERROR_INVALID_RESPONSE_SSZ,
            .peer_error => |err| switch (err.code) {
                1 => .REQUEST_ERROR_INVALID_REQUEST,
                2 => .REQUEST_ERROR_SERVER_ERROR,
                3 => .RESOURCE_UNAVAILABLE_ERROR,
                else => .REQUEST_ERROR_UNKNOWN_ERROR_STATUS,
            },
            else => .REQUEST_ERROR_REQUEST_ERROR,
        };
    }
};
pub const error_reason_count = @typeInfo(ErrorReason).@"enum".fields.len;

pub const ProtocolCounters = struct {
    outgoing: u64 = 0,
    incoming: u64 = 0,
    outgoing_errors: u64 = 0,
    outgoing_cancelled: u64 = 0,
    incoming_cancelled: u64 = 0,
    request_write_stops: u64 = 0,
    response_finish_stops: u64 = 0,
    incoming_errors: u64 = 0,
    rate_limited: u64 = 0,
    outgoing_time: OutgoingTime = .{},
    incoming_time: IncomingTime = .{},
};

test "request error labels match host timeout phases and response status mapping" {
    try std.testing.expectEqual(ErrorReason.REQUEST_ERROR_DIAL_TIMEOUT, ErrorReason.fromFailure(.timeout, .negotiation));
    try std.testing.expectEqual(ErrorReason.REQUEST_ERROR_DIAL_TIMEOUT, ErrorReason.fromFailure(.{ .negotiation_failed = .timeout }, .negotiation));
    try std.testing.expectEqual(ErrorReason.REQUEST_ERROR_REQUEST_TIMEOUT, ErrorReason.fromFailure(.timeout, .request));
    try std.testing.expectEqual(ErrorReason.REQUEST_ERROR_RESP_TIMEOUT, ErrorReason.fromFailure(.timeout, .response));
    try std.testing.expectEqual(ErrorReason.REQUEST_ERROR_SERVER_ERROR, ErrorReason.fromFailure(.{ .peer_error = .{ .code = 2, .message_len = 0 } }, .response));
    try std.testing.expectEqual(ErrorReason.REQUEST_ERROR_UNKNOWN_ERROR_STATUS, ErrorReason.fromFailure(.{ .peer_error = .{ .code = 255, .message_len = 0 } }, .response));
}
