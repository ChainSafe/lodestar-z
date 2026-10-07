const std = @import("std");
const config = @import("config");
const request_policy = @import("request_policy.zig");
const Options = @import("quotas.zig").Options;
const Protocol = @import("protocol.zig").Protocol;
const fixture = @import("policy_fixture.zig");

test "reqresp quotas preserve every protocol rate across chain configurations and forks" {
    const Case = struct { protocol: Protocol, tokens: [3]u32, period_ms: u64 };
    const cases = [_]Case{
        .{ .protocol = .status_v1, .tokens = .{ 5, 5, 5 }, .period_ms = 15_000 },
        .{ .protocol = .status_v2, .tokens = .{ 5, 5, 5 }, .period_ms = 15_000 },
        .{ .protocol = .goodbye_v1, .tokens = .{ 1, 1, 1 }, .period_ms = 10_000 },
        .{ .protocol = .ping_v1, .tokens = .{ 2, 2, 2 }, .period_ms = 10_000 },
        .{ .protocol = .metadata_v1, .tokens = .{ 2, 2, 2 }, .period_ms = 5_000 },
        .{ .protocol = .metadata_v2, .tokens = .{ 2, 2, 2 }, .period_ms = 5_000 },
        .{ .protocol = .metadata_v3, .tokens = .{ 2, 2, 2 }, .period_ms = 5_000 },
        .{ .protocol = .blocks_by_range_v2, .tokens = .{ 1024, 128, 128 }, .period_ms = 10_000 },
        .{ .protocol = .blocks_by_root_v2, .tokens = .{ 1024, 128, 128 }, .period_ms = 10_000 },
        .{ .protocol = .blob_sidecars_by_range_v1, .tokens = .{ 768, 768, 1152 }, .period_ms = 10_000 },
        .{ .protocol = .blob_sidecars_by_root_v1, .tokens = .{ 768, 768, 1152 }, .period_ms = 10_000 },
        .{ .protocol = .data_column_sidecars_by_range_v1, .tokens = .{ 16_384, 16_384, 16_384 }, .period_ms = 10_000 },
        .{ .protocol = .data_column_sidecars_by_root_v1, .tokens = .{ 16_384, 16_384, 16_384 }, .period_ms = 10_000 },
        .{ .protocol = .blocks_by_head_v1, .tokens = .{ 128, 128, 128 }, .period_ms = 10_000 },
        .{ .protocol = .light_client_bootstrap_v1, .tokens = .{ 5, 5, 5 }, .period_ms = 15_000 },
        .{ .protocol = .light_client_updates_by_range_v1, .tokens = .{ 128, 128, 128 }, .period_ms = 10_000 },
        .{ .protocol = .light_client_finality_update_v1, .tokens = .{ 2, 2, 2 }, .period_ms = 12_000 },
        .{ .protocol = .light_client_optimistic_update_v1, .tokens = .{ 2, 2, 2 }, .period_ms = 12_000 },
    };
    try std.testing.expectEqual(Protocol.count, cases.len);
    for ([_]*const config.BeaconConfig{ &config.mainnet.config, &config.minimal.config }) |chain| {
        var points: [request_policy.schedule_max]request_policy.BlobLimit = undefined;
        const policy = try request_policy.Config.fromBeaconConfig(chain, &points);
        const limits = try Options.defaults(&policy, 256, 200, 32);
        try std.testing.expectEqual(@as(u16, 256), limits.identities);
        try std.testing.expectEqual(@as(u32, 36), limits.starts.tokens);
        try std.testing.expectEqual(@as(u64, 10_000), limits.starts.period_ms);
        for (std.enums.values(config.ForkSeq)) |fork| {
            const era: usize = if (fork.gte(.electra)) 2 else if (fork.gte(.deneb)) 1 else 0;
            for (cases, 0..) |case, index| {
                try std.testing.expectEqual(index, @intFromEnum(case.protocol));
                const peer = limits.peer[@intFromEnum(fork)][index];
                const global = limits.global[@intFromEnum(fork)][index];
                try std.testing.expectEqual(case.tokens[era], peer.tokens);
                try std.testing.expectEqual(case.period_ms, peer.period_ms);
                try std.testing.expectEqual(case.tokens[era] * @as(u32, if (case.protocol.isControl()) 200 else 8), global.tokens);
                try std.testing.expectEqual(case.period_ms, global.period_ms);
            }
        }
    }
}

test "reqresp quotas follow configured request bounds and scale application capacity at batch boundaries" {
    var policy = fixture.config();
    policy.blocks_pre_deneb = 16;
    policy.blocks_deneb = 8;
    policy.blob_identifiers_deneb = 24;
    policy.blob_identifiers_electra = 48;
    policy.column_chunks = 96;
    for ([_]u16{ 0, 1, 3, 4, 7, 8, 32 }, [_]u32{ 1, 1, 1, 1, 1, 2, 8 }) |capacity, scale| {
        const limits = try Options.defaults(&policy, 8, 3, capacity);
        for (std.enums.values(config.ForkSeq)) |fork| {
            const peer = limits.peer[@intFromEnum(fork)];
            const global = limits.global[@intFromEnum(fork)];
            try std.testing.expectEqual(@as(u32, if (fork.gte(.deneb)) 8 else 16), peer[@intFromEnum(Protocol.blocks_by_root_v2)].tokens);
            try std.testing.expectEqual(@as(u32, 8), peer[@intFromEnum(Protocol.blocks_by_head_v1)].tokens);
            try std.testing.expectEqual(@as(u32, if (fork.gte(.electra)) 48 else 24), peer[@intFromEnum(Protocol.blob_sidecars_by_root_v1)].tokens);
            try std.testing.expectEqual(@as(u32, 96 * scale), global[@intFromEnum(Protocol.data_column_sidecars_by_range_v1)].tokens);
            try std.testing.expectEqual(@as(u32, 6), global[@intFromEnum(Protocol.ping_v1)].tokens);
        }
    }
    try std.testing.expectError(error.InvalidPolicy, Options.defaults(&policy, 8, 0, 1));
    try std.testing.expectError(error.InvalidPolicy, Options.defaults(&policy, 8, 9, 1));
    policy.blocks_deneb = 0;
    try std.testing.expectError(error.InvalidPolicy, Options.defaults(&policy, 8, 3, 1));
}
