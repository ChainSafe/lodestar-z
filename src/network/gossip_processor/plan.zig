const limits_mod = @import("../gossip_limits.zig");
const policy = @import("../gossipsub/topic_policy.zig");
const ForkEntry = @import("../types.zig").ForkEntry;

pub const Plan = struct {
    limits: limits_mod.Limits,
    /// Defaults derive from work limits; explicit overrides also obey execution-specific ceilings.
    execution: ?limits_mod.Limits = null,
    source_maximum: [limits_mod.kind_count]usize = @splat(@import("../constants.zig").MAX_PAYLOAD_SIZE),
    forks: []const ForkEntry = &.{},
    random_seed: u64 = 0,

    pub fn resolve(limits: limits_mod.Limits, execution: ?limits_mod.Limits, boundaries: []const policy.Boundary, forks: []const ForkEntry, seed: u64) !Plan {
        var plan: Plan = .{
            .limits = limits,
            .execution = execution,
            .source_maximum = @splat(0),
            .forks = forks,
            .random_seed = seed,
        };
        try plan.validate();
        for (boundaries) |boundary| for (boundary.rules, 0..) |rule, k| {
            plan.source_maximum[k] = @max(plan.source_maximum[k], rule.ssz_max);
        };
        const resolved_execution = plan.executionLimits();
        for (boundaries) |boundary| for (boundary.rules, resolved_execution) |rule, limit| {
            if (rule.count > 0 and rule.ssz_max > limit.bytes) return error.InvalidGossipProcessorLimits;
        };
        return plan;
    }

    pub fn executionLimits(self: *const Plan) limits_mod.Limits {
        if (self.execution) |execution| return execution;
        var execution = self.limits;
        for (&execution) |*limit| limit.items = @max(1, limit.items / 2);
        return execution;
    }

    pub fn validate(self: *const Plan) !void {
        if (self.forks.len > policy.boundary_max) return error.InvalidGossipProcessorLimits;
        try limits_mod.validate(&self.limits);
        const execution = self.execution orelse return;
        var total_items: usize = 0;
        var total_bytes: usize = 0;
        for (execution, self.limits) |limit, work| {
            if (limit.items == 0 or limit.items > work.items or limit.bytes == 0) return error.InvalidGossipProcessorLimits;
            total_items += limit.items;
            total_bytes += limit.bytes;
        }
        if (total_items > 16384 or total_bytes > 1024 * 1024 * 1024) return error.InvalidGossipProcessorLimits;
    }
};
