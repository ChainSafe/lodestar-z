const std = @import("std");
const ChainConfig = @import("ChainConfig.zig");

test "merge" {
    const mainnet_config = @import("./networks/mainnet.zig").chain_config;
    const old_altair_epoch = mainnet_config.ALTAIR_FORK_EPOCH;
    const merged_config = mainnet_config.merge(.{
        .ALTAIR_FORK_EPOCH = old_altair_epoch + 1000,
    });
    try std.testing.expect(merged_config.ALTAIR_FORK_EPOCH == old_altair_epoch + 1000);
}

test "Heze timing defaults preserve current slot durations" {
    inline for (.{
        @import("networks/mainnet.zig"),
        @import("networks/minimal.zig"),
        @import("networks/gnosis.zig"),
        @import("networks/hoodi.zig"),
        @import("networks/sepolia.zig"),
        @import("networks/chiado.zig"),
    }) |network| {
        const chain = network.chain_config;
        try std.testing.expectEqual(std.math.maxInt(u64), chain.HEZE_FORK_EPOCH);
        try std.testing.expectEqual(chain.SLOT_DURATION_MS, chain.SLOT_DURATION_MS_HEZE);
    }
}

test "merge preserves or overrides Heze timing independently" {
    const chain = @import("networks/mainnet.zig").chain_config;
    const unchanged = chain.merge(.{});
    try std.testing.expectEqual(chain.HEZE_FORK_EPOCH, unchanged.HEZE_FORK_EPOCH);
    try std.testing.expectEqual(chain.SLOT_DURATION_MS_HEZE, unchanged.SLOT_DURATION_MS_HEZE);

    const overrides: ChainConfig.OptionalChainConfig = .{
        .HEZE_FORK_EPOCH = 3,
        .SLOT_DURATION_MS_HEZE = 4000,
    };
    const merged = chain.merge(overrides);
    try std.testing.expectEqual(3, merged.HEZE_FORK_EPOCH);
    try std.testing.expectEqual(4000, merged.SLOT_DURATION_MS_HEZE);
    try std.testing.expectEqual(chain.SLOT_DURATION_MS, merged.SLOT_DURATION_MS);
    try std.testing.expectEqual(chain.SECONDS_PER_SLOT, merged.SECONDS_PER_SLOT);
}
