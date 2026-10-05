const std = @import("std");
const rr = @import("ReqResp.zig");
const protocol = @import("protocol.zig");
const policy_fixture = @import("policy_fixture.zig");

pub fn reservedOptions() !rr.Options {
    var options: rr.Options = .{ .admission = try rr.Options.Admission.defaults(&policy_fixture.config(), 8, 2, 2), .outbound_max = 4, .serving_max = 4, .forks = &.{} };
    options.outbound_control_reserved = 2;
    options.serving_control_reserved = 2;
    return options;
}
