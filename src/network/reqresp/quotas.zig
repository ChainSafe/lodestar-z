const Protocol = @import("protocol.zig").Protocol;
const ForkSeq = @import("config").ForkSeq;
const constants = @import("constants.zig");
const request_policy = @import("request_policy.zig");

const ten_seconds_ms: u64 = 10_000;

pub const Quota = struct {
    tokens: u32,
    period_ms: u64,
};

pub const Quotas = [Protocol.count]Quota;
pub const ByFork = [ForkSeq.count]Quotas;

pub const Options = struct {
    identities: u16,
    peer: ByFork,
    global: ByFork,
    /// Limits fixed per-request overhead independently of the requested blocks or columns.
    /// Each identity has separate control and application allowances.
    starts: Quota = .{ .tokens = Protocol.count * constants.MAX_CONCURRENT_REQUESTS, .period_ms = ten_seconds_ms },

    pub fn defaults(configuration: *const request_policy.Config, identities: u16, control_peers: u16, application_max: u16) error{InvalidPolicy}!Options {
        if (control_peers == 0 or control_peers > identities) return error.InvalidPolicy;
        const policy = try request_policy.Policy.init(configuration);
        const application_scale = @max(1, @as(u32, application_max) / (2 * constants.MAX_CONCURRENT_REQUESTS));
        var result: Options = .{ .identities = identities, .peer = undefined, .global = undefined };
        for (0..ForkSeq.count) |i| {
            for (0..Protocol.count) |j| {
                const which: Protocol = @enumFromInt(j);
                const quota = peerQuota(&policy, which, @enumFromInt(i));
                result.peer[i][j] = quota;
                result.global[i][j] = .{
                    .tokens = quota.tokens * (if (which.isControl()) @as(u32, control_peers) else application_scale),
                    .period_ms = quota.period_ms,
                };
            }
        }
        return result;
    }
};

fn peerQuota(policy: *const request_policy.Policy, which: Protocol, fork: ForkSeq) Quota {
    return switch (which) {
        .status_v1, .status_v2, .light_client_bootstrap_v1 => .{ .tokens = 5, .period_ms = 15_000 },
        .goodbye_v1 => .{ .tokens = 1, .period_ms = ten_seconds_ms },
        .ping_v1 => .{ .tokens = 2, .period_ms = ten_seconds_ms },
        .metadata_v1, .metadata_v2, .metadata_v3 => .{ .tokens = 2, .period_ms = 5_000 },
        .blocks_by_range_v2, .blocks_by_root_v2 => .{ .tokens = policy.blocks(fork), .period_ms = ten_seconds_ms },
        .blocks_by_head_v1 => .{ .tokens = policy.config.blocks_deneb, .period_ms = ten_seconds_ms },
        .blob_sidecars_by_range_v1, .blob_sidecars_by_root_v1 => .{ .tokens = policy.blobs(fork), .period_ms = ten_seconds_ms },
        .data_column_sidecars_by_range_v1, .data_column_sidecars_by_root_v1 => .{ .tokens = policy.config.column_chunks, .period_ms = ten_seconds_ms },
        .light_client_updates_by_range_v1 => .{ .tokens = 128, .period_ms = ten_seconds_ms },
        .light_client_finality_update_v1, .light_client_optimistic_update_v1 => .{ .tokens = 2, .period_ms = 12_000 },
    };
}

test {
    _ = @import("quotas_test.zig");
}
