const std = @import("std");
const Allocator = std.mem.Allocator;
const m = @import("metrics");

pub var beacon_engine = m.initializeNoop(Metrics);

const Metrics = struct {
    gossip_block_state_transition_recv_to_validation: GossipHistogram,
    gossip_block_state_transition_validation_time: GossipHistogram,

    const GossipHistogram = m.Histogram(f64, &.{ 0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5 });
};

pub fn init(allocator: Allocator, _: std.Io, comptime opts: m.RegistryOpts) !void {
    _ = allocator;
    const metric_opts = comptime m.RegistryOpts{
        .prefix = if (opts.prefix.len == 0) "lodestar_" else opts.prefix,
        .exclude = opts.exclude,
    };

    beacon_engine = .{
        .gossip_block_state_transition_recv_to_validation = Metrics.GossipHistogram.init(
            "gossip_block_state_transition_recv_to_validation_seconds",
            .{ .help = "Time from block gossip receipt to end of state-transition verification, in seconds" },
            metric_opts,
        ),
        .gossip_block_state_transition_validation_time = Metrics.GossipHistogram.init(
            "gossip_block_state_transition_validation_time_seconds",
            .{ .help = "Wall-clock validation time for a single gossip block state transition, in seconds" },
            metric_opts,
        ),
    };
}

pub fn write(writer: *std.Io.Writer) !void {
    try m.write(&beacon_engine, writer);
}
