const rr = @import("ReqResp.zig");
const policy_fixture = @import("policy_fixture.zig");

pub fn applicationOptions() !rr.Options {
    return .{ .protocols = .application, .outbound_max = 2, .serving_max = 2, .forks = &.{}, .admission = try rr.Options.Admission.defaults(&policy_fixture.config(), 1) };
}

pub fn controlOptions() !rr.Options {
    return .{ .protocols = .control, .routes = .control, .report_non_completion = false, .outbound_max = 2, .serving_max = 2, .serving_per_peer_max = 1, .inbound_per_connection_max = 8, .forks = &.{}, .admission = try rr.Options.Admission.defaults(&policy_fixture.config(), 2) };
}
