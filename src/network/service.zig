const std = @import("std");
const routing = @import("router.zig");
const engine_mod = @import("quic/engine.zig");
const types = @import("types.zig");
const reqresp_mod = @import("reqresp/root.zig");
const gossip_mod = @import("gossipsub/root.zig");

const identify_mod = @import("identify/root.zig");

pub const Options = struct {
    identify: ?identify_mod.Options = null,
    automatic_gossip_admission: bool = true,
    router: routing.Options = .{},
    reqresp: reqresp_mod.reqresp.Options,
    gossipsub: gossip_mod.Options = .{},
};
pub const Counts = struct { reqresp: usize, gossipsub: usize };
pub const PartitionedCounts = struct { application: usize, control: usize, gossipsub: usize };
pub const Outputs = struct { application: []reqresp_mod.Event = &.{}, control: []reqresp_mod.Event = &.{}, gossipsub: []gossip_mod.Event = &.{}, identify: []identify_mod.Result = &.{} };
pub const OutputCounts = struct { application: usize, control: usize, gossipsub: usize, identify: usize };
pub const Capacities = struct { application: usize = 0, control: usize = 0, gossipsub: usize = 0, identify: usize = 0 };
pub const InitError = reqresp_mod.service.InitError || gossip_mod.service.InitError || identify_mod.handler.InitError;

pub const Service = struct {
    identify: ?identify_mod.Handler,
    automatic_gossip_admission: bool,
    applications: enum { active, quiescing, closed } = .active,
    router: routing.Router,
    reqresp: reqresp_mod.Handler,
    gossipsub: gossip_mod.Handler,

    pub fn validateOptions(options: Options) InitError!void {
        if (!options.router.reqresp or !options.router.meshsub) return error.InvalidLimits;
        var router_options = options.router;
        router_options.identify = options.identify != null;
        try routing.Router.validateOptions(router_options);
        if (options.identify) |identify| try identify_mod.Handler.validate(identify);
        _ = try reqresp_mod.ReqResp.validateOptions(options.reqresp);
        try @import("gossipsub/options.zig").validate(&options.gossipsub);
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!Service {
        try validateOptions(options);
        var router_options = options.router;
        router_options.identify = options.identify != null;
        var router = try routing.Router.init(allocator, router_options);
        errdefer router.deinit();
        var reqresp = try reqresp_mod.Handler.init(allocator, options.reqresp);
        errdefer reqresp.deinit();
        var gossipsub = try gossip_mod.Handler.init(allocator, options.gossipsub);
        errdefer gossipsub.deinit();
        const identify = if (options.identify) |value| try identify_mod.Handler.init(allocator, value) else null;
        return .{
            .identify = identify,
            .router = router,
            .reqresp = reqresp,
            .gossipsub = gossipsub,
            .automatic_gossip_admission = options.automatic_gossip_admission,
        };
    }

    pub fn deinit(self: *Service) void {
        if (self.identify) |*identify| identify.deinit();
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
        if (self.applications != .active and !protocol.isControl()) return error.ProtocolDisabled;
        return self.reqresp.request(
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
    pub fn nextWakeup(
        self: *Service,
        now: types.Now,
        request_event_capacity: usize,
        gossip_event_capacity: usize,
    ) ?u64 {
        return self.nextWakeupPartitioned(
            now,
            request_event_capacity,
            request_event_capacity,
            gossip_event_capacity,
        );
    }

    pub fn nextWakeupPartitioned(
        self: *Service,
        now: types.Now,
        application_capacity: usize,
        control_capacity: usize,
        gossip_event_capacity: usize,
    ) ?u64 {
        return self.nextWakeupOutputs(now, .{ .application = application_capacity, .control = control_capacity, .gossipsub = gossip_event_capacity });
    }

    pub fn nextWakeupOutputs(self: *Service, now: types.Now, capacities: Capacities) ?u64 {
        const request_due = self.reqresp.nextWakeupPartitioned(
            &self.router,
            now,
            capacities.application,
            capacities.control,
        );
        const gossip = if (self.applications == .active) self.gossipsub.nextWakeup(now, capacities.gossipsub) else null;
        const identify_due = if (self.identify) |*identify| identify.nextWakeup(now, capacities.identify) else null;
        var due = request_due;
        for ([_]?u64{ gossip, identify_due }) |next| if (next) |value| {
            due = @min(due orelse value, value);
        };
        return due;
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
        self.prepare(engine, events, activity, now);
        if (self.identify) |*identify| _ = identify.pump(&self.router, engine, now, &.{});
        return .{
            .reqresp = self.reqresp.pump(&self.router, engine, now, requests),
            .gossipsub = if (self.applications == .active) self.gossipsub.pump(&self.router, engine, now, gossip) else 0,
        };
    }

    pub fn processPartitioned(
        self: *Service,
        engine: *engine_mod.Engine,
        events: []const engine_mod.Event,
        activity: []const engine_mod.Handle,
        now: types.Now,
        application: []reqresp_mod.Event,
        control: []reqresp_mod.Event,
        gossip: []gossip_mod.Event,
    ) PartitionedCounts {
        const counts = self.processOutputs(engine, events, activity, now, .{ .application = application, .control = control, .gossipsub = gossip });
        return .{ .application = counts.application, .control = counts.control, .gossipsub = counts.gossipsub };
    }

    pub fn processOutputs(self: *Service, engine: *engine_mod.Engine, events: []const engine_mod.Event, activity: []const engine_mod.Handle, now: types.Now, outputs: Outputs) OutputCounts {
        self.prepare(engine, events, activity, now);
        const counts = self.reqresp.pumpPartitioned(&self.router, engine, now, outputs.application, outputs.control);
        return .{ .application = counts.application, .control = counts.control, .gossipsub = if (self.applications == .active) self.gossipsub.pump(&self.router, engine, now, outputs.gossipsub) else 0, .identify = if (self.identify) |*identify| identify.pump(&self.router, engine, now, outputs.identify) else 0 };
    }

    /// Defer stream cleanup until the next process call, preserving the current event borrows.
    pub fn quiesceApplications(self: *Service) void {
        if (self.applications == .active) self.applications = .quiescing;
    }

    fn rejectApplication(self: *const Service, outcome: *const routing.Outcome) bool {
        if (self.applications == .active) return false;
        return switch (outcome.result) {
            .ready => |selection| switch (selection.protocol) {
                .reqresp => |which| !which.isControl(),
                .meshsub => true,
                .identify => false,
            },
            else => false,
        };
    }

    fn prepare(
        self: *Service,
        engine: *engine_mod.Engine,
        events: []const engine_mod.Event,
        activity: []const engine_mod.Handle,
        now: types.Now,
    ) void {
        std.debug.assert(activity.len <= engine.limits.connections_max);
        if (self.applications == .quiescing) {
            self.reqresp.inner.cancelApplications(engine, &self.router);
            self.gossipsub.shutdown(&self.router, engine);
            self.applications = .closed;
        }
        for (activity) |conn| {
            if (self.identify) |*identify| identify.connectionActivity(conn);
            self.reqresp.inner.connectionActivity(conn);
            if (self.applications == .active) self.gossipsub.connectionActivity(conn);
        }
        self.reqresp.inner.cleanupPending(engine, &self.router);
        self.router.transportEvents(engine, events, now);
        self.reqresp.transportEvents(events);
        if (self.identify) |*identify| identify.transportEvents(engine, events);
        for (events) |event| {
            if (self.applications != .active or (!self.automatic_gossip_admission and event == .connected)) continue;
            self.gossipsub.transportEvents(&self.router, engine, &.{event}, now);
        }
        var outcomes: [routing.outcomes_per_pump]routing.Outcome = undefined;
        const count = self.router.pump(engine, now, &outcomes);
        for (outcomes[0..count]) |outcome| {
            const owner = outcome.owner orelse continue;
            if (self.rejectApplication(&outcome)) {
                engine.closeStream(outcome.stream, 0);
                continue;
            }
            switch (owner) {
                .identify => if (self.identify) |*identify| identify.negotiationResult(&self.router, engine, outcome, now),
                .reqresp => self.reqresp.negotiationResult(engine, outcome, now),
                .meshsub => self.gossipsub.negotiationResult(engine, outcome, now),
            }
        }
    }
};
