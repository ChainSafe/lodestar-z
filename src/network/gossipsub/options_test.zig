const Options = @import("options.zig").Options;
const constants = @import("constants.zig");
const validate = @import("options.zig").validate;

test "gossip policy default epoch timers follow the selected preset and require entropy" {
    const std = @import("std");
    try std.testing.expectError(error.InvalidLimits, validate(&.{}));
    const o: Options = .{ .random_seed = 1 };
    try validate(&o);
    const expected: u64 = switch (@import("preset").active_preset) {
        .mainnet => 768_000,
        .minimal => 192_000,
        .gnosis => 384_000,
    };
    try std.testing.expectEqual(expected, o.seen_ttl_ms);
    try std.testing.expectEqual(expected * 50, o.retained_score_ms);
}

test "gossip policy wire limits validate inclusive boundaries" {
    const std = @import("std");
    var o: Options = .{ .random_seed = 1, .iwant_followup_ms = 12_000, .idontwant_min_data_size = 0 };
    try validate(&o);
    o.iwant_followup_ms = 86_400_000;
    o.idontwant_min_data_size = constants.GOSSIP_MAX_SIZE;
    try validate(&o);
    o.iwant_followup_ms = 0;
    try std.testing.expectError(error.InvalidLimits, validate(&o));
    o.iwant_followup_ms = 86_400_001;
    try std.testing.expectError(error.InvalidLimits, validate(&o));
    o.iwant_followup_ms = 1;
    o.idontwant_min_data_size = constants.GOSSIP_MAX_SIZE + 1;
    try std.testing.expectError(error.InvalidLimits, validate(&o));
}
