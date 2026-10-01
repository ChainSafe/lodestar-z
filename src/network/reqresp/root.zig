pub const testing = if (@import("builtin").is_test) @import("test_pair.zig") else struct {};
pub const codec = @import("codec.zig");
pub const constants = @import("constants.zig");
pub const request_policy = @import("request_policy.zig");
pub const admission = @import("admission.zig");
pub const limiter = @import("limiter.zig");
pub const response_bounds = @import("response_bounds.zig");
pub const protocol = @import("protocol.zig");
pub const reqresp = @import("reqresp.zig");

pub const Protocol = protocol.Protocol;
pub const Info = protocol.Info;
pub const ReqResp = reqresp.ReqResp;
pub const Options = reqresp.Options;
pub const RequestOptions = reqresp.RequestOptions;
pub const AbsoluteTimeouts = reqresp.AbsoluteTimeouts;
pub const RequestPhase = reqresp.RequestPhase;
pub const ResponseReadiness = reqresp.ResponseReadiness;
pub const RequestHandle = reqresp.RequestHandle;
pub const Event = reqresp.Event;
pub const Outputs = reqresp.Outputs;
pub const OutputCounts = reqresp.OutputCounts;
pub const Capacities = reqresp.Capacities;
pub const Failure = reqresp.Failure;
pub const ForkEntry = reqresp.ForkEntry;
pub const Counters = reqresp.Counters;

test {
    _ = @import("admission.zig");
    _ = @import("request_policy.zig");
    _ = codec;
    _ = constants;
    _ = limiter;
    _ = protocol;
    _ = reqresp;
    _ = @import("reqresp.zig");
    _ = @import("codec.zig");
    _ = @import("limiter.zig");
    _ = @import("protocol.zig");
}
