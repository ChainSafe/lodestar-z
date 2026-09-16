const std = @import("std");
const a = @import("admission.zig");
const PeerId = @import("../wire/peer_id.zig").PeerId;
const ForkSeq = @import("config").ForkSeq;
const Protocol = @import("protocol.zig").Protocol;
const limiter = @import("limiter.zig");

pub fn quotas(tokens: u32, period: u64) a.ByFork {
    return @splat(@as(limiter.Quotas, @splat(.{ .tokens = tokens, .period_ms = period })));
}
