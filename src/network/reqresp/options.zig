const std = @import("std");
const config = @import("config");
const constants = @import("constants.zig");
const request_policy = @import("request_policy.zig");
const admission_mod = @import("admission.zig");
const Protocol = @import("protocol.zig").Protocol;
const limits = @import("../quic/limits.zig");
const ForkEntry = @import("../types.zig").ForkEntry;

pub const Error = error{ InvalidOptions, InvalidQuota, InvalidPolicy };

/// Two maintenance and two gossip streams remain outside the application allowance.
pub const outbound_stream_headroom: u8 = 4;

pub fn validateForkTable(table: []const ForkEntry) error{InvalidOptions}!void {
    if (table.len > 64) return error.InvalidOptions;
    for (table, 0..) |entry, i| {
        for (table[0..i]) |old| {
            if (std.mem.eql(u8, &old.digest, &entry.digest)) return error.InvalidOptions;
        }
    }
}

pub const Options = struct {
    connections: u16 = limits.connections_max_default,
    outbound_max: u16 = constants.outbound_max_default,
    /// Shared execution slots, including the control reserve.
    serving_max: u16 = constants.serving_max_default,
    /// Two concurrent sync batches can each request blocks and sidecars.
    serving_per_peer_max: u8 = 2 * constants.MAX_CONCURRENT_REQUESTS,
    /// Nonzero partitions outbound slots between control and application requests.
    outbound_control_reserved: u16 = 0,
    serving_control_reserved: u16 = 0,
    /// Zero preserves raw admission without an aggregate application limit.
    outbound_per_connection_max: u8 = 0,
    inbound_per_connection_max: u8 = constants.inbound_per_connection_max_default,
    /// Concurrent application receivers per connection; zero disables the cap.
    inbound_application_per_connection_max: u8 = 0,
    /// Complete inbound request transfer and each response chunk within this duration.
    progress_timeout_ms: u64 = constants.progress_timeout_ms_default,
    forks: []const ForkEntry,
    request_fork: config.ForkSeq = .phase0,
    admission: Admission,
    host_timeout_ms: u64 = 60_000,
    quota_timeout_ms: u64 = 60_000,
    work_per_pump_max: u16 = 32,

    pub const Admission = struct {
        policy: request_policy.Config,
        limits: admission_mod.Options,

        pub fn defaults(configuration: *const request_policy.Config, identities: u16, control_peers: u16, application_max: u16) error{InvalidPolicy}!Admission {
            if (control_peers == 0 or control_peers > identities) return error.InvalidPolicy;
            const policy = try request_policy.Policy.init(configuration);
            var quotas: admission_mod.Options = undefined;
            quotas.identities = identities;
            quotas.starts = .{ .tokens = Protocol.count * constants.MAX_CONCURRENT_REQUESTS, .period_ms = constants.progress_timeout_ms_default };
            for (0..config.ForkSeq.count) |i| {
                quotas.peer[i] = policy.defaultQuotas(@enumFromInt(i));
                quotas.global[i] = quotas.peer[i];
                for (0..Protocol.count) |j| {
                    const which: Protocol = @enumFromInt(j);
                    if (which.isControl()) {
                        quotas.global[i][j].tokens *= control_peers;
                    } else {
                        quotas.global[i][j].tokens *= @max(1, @as(u32, application_max) / (2 * constants.MAX_CONCURRENT_REQUESTS));
                    }
                }
            }
            return .{ .policy = configuration.*, .limits = quotas };
        }
    };

    pub fn validate(options: Options) Error!void {
        _ = try request_policy.Policy.init(&options.admission.policy);
        try admission_mod.Limiter.validate(&options.admission.limits);
        if (options.outbound_max == 0 or options.outbound_max > constants.slots_ceiling) {
            return error.InvalidOptions;
        }
        if (options.serving_max == 0 or options.serving_max > constants.slots_ceiling) {
            return error.InvalidOptions;
        }
        if (options.outbound_control_reserved > options.outbound_max or
            options.serving_control_reserved > options.serving_max) return error.InvalidOptions;
        const application_max = options.outbound_max - options.outbound_control_reserved;
        if (options.outbound_per_connection_max > limits.peer_streams_bidi - outbound_stream_headroom or
            options.outbound_per_connection_max > application_max) return error.InvalidOptions;
        if (options.inbound_per_connection_max == 0 or options.connections == 0 or options.serving_per_peer_max == 0) return error.InvalidOptions;
        if (options.inbound_application_per_connection_max > options.inbound_per_connection_max) return error.InvalidOptions;
        if (options.connections > constants.slots_ceiling) return error.InvalidOptions;
        if (options.progress_timeout_ms == 0 or options.host_timeout_ms == 0 or
            options.quota_timeout_ms == 0 or options.work_per_pump_max == 0 or
            options.work_per_pump_max > 2 * constants.slots_ceiling) return error.InvalidOptions;
        try validateForkTable(options.forks);
    }
};
