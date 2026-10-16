const Protocol = @import("protocol.zig").Protocol;
const ForkSeq = @import("config").ForkSeq;
const constants = @import("constants.zig");
const request_policy = @import("request_policy.zig");

const ten_seconds_ms: u64 = 10_000;

pub const Quota = struct {
    tokens: u32,
    period_ms: u64,
};

pub const Rates = struct {
    protocols: [Protocol.count]Quota,
    blocks_pre_deneb: Quota,
    blobs_pre_electra: Quota,

    pub fn get(self: *const Rates, which: Protocol, fork: ForkSeq) Quota {
        return switch (which) {
            .blocks_by_range_v2, .blocks_by_root_v2 => if (fork.gte(.deneb)) self.protocols[@intFromEnum(which)] else self.blocks_pre_deneb,
            .blob_sidecars_by_range_v1, .blob_sidecars_by_root_v1 => if (fork.gte(.electra)) self.protocols[@intFromEnum(which)] else self.blobs_pre_electra,
            else => self.protocols[@intFromEnum(which)],
        };
    }
};

pub const Options = struct {
    identities: u16,
    peer: Rates,
    global: Rates,
    /// Limits fixed per-request overhead independently of the requested blocks or columns.
    starts: Quota = .{ .tokens = Protocol.count * constants.MAX_CONCURRENT_REQUESTS, .period_ms = ten_seconds_ms },

    pub fn defaults(configuration: *const request_policy.Config, identities: u16, global_scale: u16) error{InvalidPolicy}!Options {
        if (global_scale == 0) return error.InvalidPolicy;
        const policy = try request_policy.Policy.init(configuration);
        var result: Options = .{ .identities = identities, .peer = undefined, .global = undefined };
        for (&result.peer.protocols, &result.global.protocols, 0..) |*peer, *global, index| {
            peer.* = peerQuota(&policy, @enumFromInt(index), .fulu);
            global.* = scaled(peer.*, global_scale);
        }
        result.peer.blocks_pre_deneb = peerQuota(&policy, .blocks_by_root_v2, .phase0);
        result.peer.blobs_pre_electra = peerQuota(&policy, .blob_sidecars_by_root_v1, .deneb);
        result.global.blocks_pre_deneb = scaled(result.peer.blocks_pre_deneb, global_scale);
        result.global.blobs_pre_electra = scaled(result.peer.blobs_pre_electra, global_scale);
        return result;
    }
};

fn scaled(quota: Quota, scale: u16) Quota {
    return .{ .tokens = quota.tokens * @as(u32, scale), .period_ms = quota.period_ms };
}

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
