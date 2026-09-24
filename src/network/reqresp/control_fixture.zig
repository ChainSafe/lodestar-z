const std = @import("std");
const rr = @import("reqresp.zig");
const protocol = @import("protocol.zig");
const routing = @import("../router.zig");
const support = @import("../test_support.zig");

pub fn reservedOptions() !rr.Options {
    var options: rr.Options = .{ .admission = try rr.AdmissionOptions.defaults(&@import("policy_fixture.zig").config(), 8, 2, 2), .outbound_max = 4, .inbound_max = 4, .forks = &.{} };
    options.outbound_control_reserved = 2;
    options.inbound_control_reserved = 2;
    return options;
}
