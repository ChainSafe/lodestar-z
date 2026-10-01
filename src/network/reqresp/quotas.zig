const protocol = @import("protocol.zig");

const Protocol = protocol.Protocol;

pub const Quota = struct {
    tokens: u32,
    period_ms: u64,
};

pub const Quotas = [Protocol.count]Quota;

pub fn defaultQuotas() Quotas {
    var out: Quotas = undefined;
    inline for (@typeInfo(Protocol).@"enum".fields, 0..) |field, index| {
        const bounds = @as(Protocol, @enumFromInt(field.value)).info();
        out[index] = .{ .tokens = bounds.quota_tokens, .period_ms = bounds.quota_period_ms };
    }
    return out;
}
