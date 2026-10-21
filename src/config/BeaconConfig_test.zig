const std = @import("std");
const BeaconConfig = @import("BeaconConfig.zig");
const DOMAIN_VOLUNTARY_EXIT = @import("constants").DOMAIN_VOLUNTARY_EXIT;

const zero_root = [_]u8{0} ** 32;

test "getSlotComponentDurationMs floors like the spec" {
    const mainnet = BeaconConfig.init(@import("./networks/mainnet.zig").chain_config, zero_root);
    const minimal = BeaconConfig.init(@import("./networks/minimal.zig").chain_config, zero_root);
    const gnosis = BeaconConfig.init(@import("./networks/gnosis.zig").chain_config, zero_root);

    // 12 s slot.
    try std.testing.expectEqual(@as(u64, 3999), mainnet.getSlotComponentDurationMs(3333));
    try std.testing.expectEqual(@as(u64, 2000), mainnet.getSlotComponentDurationMs(1667));
    try std.testing.expectEqual(@as(u64, 8000), mainnet.getSlotComponentDurationMs(6667));
    try std.testing.expectEqual(@as(u64, 11000), mainnet.getSlotComponentDurationMs(9167));
    try std.testing.expectEqual(@as(u64, 3000), mainnet.getSlotComponentDurationMs(2500));

    // 6 s slot.
    try std.testing.expectEqual(@as(u64, 1999), minimal.getSlotComponentDurationMs(3333));
    try std.testing.expectEqual(@as(u64, 1000), minimal.getSlotComponentDurationMs(1667));

    // 5 s slot.
    try std.testing.expectEqual(@as(u64, 833), gnosis.getSlotComponentDurationMs(1667));
    try std.testing.expectEqual(@as(u64, 1666), gnosis.getSlotComponentDurationMs(3333));
    try std.testing.expectEqual(@as(u64, 3333), gnosis.getSlotComponentDurationMs(6667));
    try std.testing.expectEqual(@as(u64, 4583), gnosis.getSlotComponentDurationMs(9167));
    try std.testing.expectEqual(@as(u64, 1250), gnosis.getSlotComponentDurationMs(2500));

    // Derived helpers.
    try std.testing.expectEqual(@as(u64, 2000), mainnet.getProposerReorgCutoffMs(.phase0));
    try std.testing.expectEqual(@as(u64, 3999), mainnet.getAttestationDueMs(.phase0));
    try std.testing.expectEqual(@as(u64, 3000), mainnet.getAttestationDueMs(.gloas));
}

test "getDomain" {
    var beacon_config = BeaconConfig.init(@import("./networks/mainnet.zig").chain_config, zero_root);

    const domain = try beacon_config.getDomain(100, DOMAIN_VOLUNTARY_EXIT, null);
    const domain2 = try beacon_config.getDomain(100, DOMAIN_VOLUNTARY_EXIT, null);
    try std.testing.expectEqualSlices(u8, domain, domain2);
}
