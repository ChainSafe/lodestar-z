const a = @import("admission.zig");
const quota_config = @import("quotas.zig");

pub fn quotas(tokens: u32, period: u64) a.ByFork {
    return @splat(@as(quota_config.Quotas, @splat(.{ .tokens = tokens, .period_ms = period })));
}
