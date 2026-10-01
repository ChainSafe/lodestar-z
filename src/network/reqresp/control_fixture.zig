const std = @import("std");
const rr = @import("ReqResp.zig");
const protocol = @import("protocol.zig");

pub fn reservedOptions() !rr.Options {
    var options: rr.Options = .{ .admission = try rr.Options.Admission.defaults(&@import("policy_fixture.zig").config(), 8, 2, 2), .outbound_max = 4, .inbound_max = 4, .forks = &.{} };
    options.outbound_control_reserved = 2;
    options.inbound_control_reserved = 2;
    return options;
}
