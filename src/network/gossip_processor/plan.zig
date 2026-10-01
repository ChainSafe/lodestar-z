const limits_mod = @import("../gossip_limits.zig");
const policy = @import("../gossipsub/topic_policy.zig");
const ForkEntry = @import("../reqresp/root.zig").ReqResp.ForkEntry;

pub const Plan = struct {
    capacity: usize,
    bytes: usize,
    limits: limits_mod.Limits,
    execution: ?limits_mod.Limits = null,
    source_maximum: [limits_mod.kind_count]usize = @splat(10 * 1024 * 1024),
    forks: []const ForkEntry = &.{},
    random_seed: u64 = 0,

    pub fn resolve(limits: limits_mod.Limits, execution: ?limits_mod.Limits, boundaries: []const policy.Boundary, forks: []const ForkEntry, seed: u64) !Plan {
        var plan: Plan = .{
            .capacity = limits_mod.items(&limits),
            .bytes = limits_mod.bytes(&limits),
            .limits = limits,
            .execution = execution,
            .source_maximum = @splat(0),
            .forks = forks,
            .random_seed = seed,
        };
        try limits_mod.validate(&limits);
        for (boundaries) |boundary| for (boundary.rules, 0..) |rule, k| {
            plan.source_maximum[k] = @max(plan.source_maximum[k], rule.ssz_max);
        };
        try plan.validateExecution();
        if (plan.execution == null) {
            plan.execution = plan.limits;
            for (&plan.execution.?) |*limit| limit.items = @max(1, limit.items / 2);
        }
        for (boundaries) |boundary| for (boundary.rules, plan.execution.?) |rule, limit| {
            if (rule.count > 0 and rule.ssz_max > limit.bytes) return error.InvalidGossipProcessorLimits;
        };
        return plan;
    }

    fn validateExecution(self: *const Plan) !void {
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
