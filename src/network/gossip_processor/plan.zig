const gossip = @import("../gossipsub/root.zig");
const limits_mod = @import("../gossip_limits.zig");
const ForkEntry = @import("../reqresp/root.zig").ForkEntry;

pub const Plan = struct {
    capacity: usize,
    bytes: usize,
    limits: ?limits_mod.Limits = null,
    execution: ?limits_mod.Limits = null,
    source_maximum: [limits_mod.kind_count]usize = @splat(10 * 1024 * 1024),
    forks: []const ForkEntry = &.{},
    random_seed: u64 = 0,

    pub fn resolve(options: *const gossip.Options, forks: []const ForkEntry) Plan {
        var plan: Plan = .{
            .capacity = options.validation_capacity,
            .bytes = if (options.processor_limits) |limits| limits_mod.bytes(&limits) else options.mcache_arena_bytes,
            .limits = options.processor_limits,
            .execution = options.execution_limits,
            .source_maximum = @splat(0),
            .forks = forks,
            .random_seed = options.random_seed.?,
        };
        for (options.topic_policy.?) |boundary| for (boundary.rules, 0..) |rule, k| {
            plan.source_maximum[k] = @max(plan.source_maximum[k], rule.ssz_max);
        };
        if (plan.execution == null) if (plan.limits) |limits| {
            plan.execution = limits;
            for (&plan.execution.?) |*limit| limit.items = @max(1, limit.items / 2);
        };
        return plan;
    }
};
