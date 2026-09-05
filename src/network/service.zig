const std = @import("std");
const routing = @import("router.zig");
const engine_mod = @import("quic/engine.zig");
const types = @import("types.zig");
const reqresp_mod = @import("reqresp/root.zig");
const gossip_mod = @import("gossipsub/root.zig");

pub const Options = struct {
    router: routing.Options = .{},
    reqresp: reqresp_mod.reqresp.Options,
    gossipsub: gossip_mod.Options = .{},
};
pub const Counts = struct { reqresp: usize, gossipsub: usize };
pub const InitError = reqresp_mod.service.InitError || gossip_mod.service.InitError;

pub const Service = struct {
    router: routing.Router,
    reqresp: reqresp_mod.Service,
    gossipsub: gossip_mod.Service,

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!Service {
        if (!options.router.reqresp or !options.router.meshsub) return error.InvalidLimits;
        var router = try routing.Router.init(allocator, options.router);
        errdefer router.deinit();
        var reqresp = try reqresp_mod.Service.initHandler(allocator, options.reqresp);
        errdefer reqresp.deinit();
        const gossipsub = try gossip_mod.Service.initHandler(allocator, options.gossipsub);
        return .{ .router = router, .reqresp = reqresp, .gossipsub = gossipsub };
    }

    pub fn deinit(self: *Service) void {
        self.gossipsub.deinit();
        self.reqresp.deinit();
        self.router.deinit();
        self.* = undefined;
    }

    pub fn request(
        self: *Service,
        engine: *engine_mod.Engine,
        conn: engine_mod.Handle,
        protocol: reqresp_mod.Protocol,
        bytes: []const u8,
        sink: []u8,
        options: reqresp_mod.reqresp.RequestOptions,
        now: types.Now,
    ) reqresp_mod.reqresp.RequestError!reqresp_mod.RequestHandle {
        return self.reqresp.requestRouted(
            &self.router,
            engine,
            conn,
            protocol,
            bytes,
            sink,
            options,
            now,
        );
    }

    /// Combine protocol deadlines and independent host output capacities with the transport wakeup.
    pub fn nextWakeup(self: *Service, now: types.Now, request_event_capacity: usize, gossip_event_capacity: usize) ?u64 {
        const request_due = self.reqresp.nextWakeupRouted(&self.router, now, request_event_capacity);
        const gossip = self.gossipsub.nextWakeupHandler(now, gossip_event_capacity);
        if (request_due) |r| return @min(r, gossip orelse r);
        return gossip;
    }

    /// Forward Driver activity separately from lifecycle events.
    /// The activity batch must not exceed the Engine connection capacity.
    /// Handles retain full transport generations, including connections without a gossip owner.
    pub fn process(
        self: *Service,
        engine: *engine_mod.Engine,
        events: []const engine_mod.Event,
        activity: []const engine_mod.Handle,
        now: types.Now,
        requests: []reqresp_mod.Event,
        gossip: []gossip_mod.Event,
    ) Counts {
        std.debug.assert(activity.len <= engine.limits.connections_max);
        for (activity) |conn| {
            self.reqresp.inner.connectionActivity(conn);
            self.gossipsub.connectionActivity(conn);
        }
        self.reqresp.inner.cleanupPending(engine, &self.router);
        self.router.transportEvents(engine, events, now);
        self.reqresp.transportEvents(events);
        self.gossipsub.transportEvents(engine, events, now);
        var outcomes: [routing.outcomes_per_pump]routing.Outcome = undefined;
        const count = self.router.pump(engine, now, &outcomes);
        for (outcomes[0..count]) |outcome| {
            const owner = outcome.owner orelse continue;
            switch (owner) {
                .reqresp => self.reqresp.negotiationResult(engine, outcome, now),
                .meshsub => self.gossipsub.negotiationResult(engine, outcome, now),
            }
        }
        return .{
            .reqresp = self.reqresp.pumpRouted(&self.router, engine, now, requests),
            .gossipsub = self.gossipsub.pump(&self.router, engine, now, gossip),
        };
    }
};
