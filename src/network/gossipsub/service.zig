const std = @import("std");
const engine_mod = @import("../quic/engine.zig");
const routing = @import("../router.zig");
const sessions_mod = @import("sessions.zig");
const types = @import("../types.zig");
const gossipsub_mod = @import("gossipsub.zig");

const Allocator = std.mem.Allocator;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const TransportEvent = engine_mod.Event;
const Now = types.Now;
const Event = gossipsub_mod.Event;

pub const outcomes_per_pump: usize = 16;

pub const Options = struct {
    gossipsub: gossipsub_mod.Options = .{},
    negotiations_max: u16 = 512,
    versions: []const sessions_mod.Version = &.{ .v1_2, .v1_1, .v1_0 },
};

pub const InitError = routing.Error || gossipsub_mod.InitError;

const Handler = @import("session_driver.zig").Driver;

pub const Service = struct {
    router: routing.Router,
    handler: Handler,

    pub fn init(allocator: Allocator, options: Options) InitError!Service {
        var handler = try Handler.init(allocator, options.gossipsub);
        errdefer handler.deinit();
        const router = try routing.Router.init(allocator, .{
            .negotiations_max = options.negotiations_max,
            .reqresp = false,
            .meshsub_versions = options.versions,
        });
        return .{ .router = router, .handler = handler };
    }

    pub fn deinit(self: *Service) void {
        self.handler.deinit();
        self.router.deinit();
        self.* = undefined;
    }

    pub fn process(
        self: *Service,
        engine: *Engine,
        events: []const TransportEvent,
        activity: []const Handle,
        now: Now,
        out: []Event,
    ) usize {
        std.debug.assert(activity.len <= engine.limits.connections_max);
        for (activity) |conn| self.handler.connectionActivity(conn);
        const router = &self.router;
        router.transportEvents(engine, events, now);
        self.handler.transportEvents(router, engine, events, now);
        var outcomes: [outcomes_per_pump]routing.Outcome = undefined;
        const count = router.pump(engine, now, &outcomes);
        for (outcomes[0..count]) |outcome| self.handler.negotiationResult(engine, outcome, now);
        return self.handler.pump(router, engine, now, out);
    }

    pub fn nextWakeup(self: *Service, now: Now, event_capacity: usize) ?u64 {
        var next = self.handler.nextWakeup(now, event_capacity);
        if (self.router.nextWakeup(now, outcomes_per_pump)) |d| {
            next = @min(next orelse d, d);
        }
        return next;
    }
};
