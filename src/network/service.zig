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
pub const Outputs = struct { application: []reqresp_mod.Event = &.{}, control: []reqresp_mod.Event = &.{}, gossipsub: []gossip_mod.Event = &.{}, identify: []identify_mod.Result = &.{} };
pub const OutputCounts = struct { application: usize, control: usize, gossipsub: usize, identify: usize };
pub const Capacities = struct { application: usize = 0, control: usize = 0, gossipsub: usize = 0, identify: usize = 0 };
pub const InitError = routing.Error || reqresp_mod.reqresp.InitError || gossip_mod.gossipsub.InitError || identify_mod.handler.InitError;

pub const Service = struct {
    identify: ?identify_mod.Handler,
    automatic_gossip_admission: bool,
    applications: enum { active, quiescing, closed } = .active,
    router: routing.Router,
    reqresp: reqresp_mod.ReqResp,
    gossipsub: *gossip_mod.Gossipsub,

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
        var reqresp = try reqresp_mod.ReqResp.init(allocator, options.reqresp);
        errdefer reqresp.deinit();
        const gossipsub = try allocator.create(gossip_mod.Gossipsub);
        errdefer allocator.destroy(gossipsub);
        gossipsub.* = try gossip_mod.Gossipsub.init(allocator, options.gossipsub);
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

    pub fn shutdown(self: *Service, engine: *engine_mod.Engine) void {
        if (self.identify) |*identify| identify.shutdown(&self.router, engine);
        self.reqresp.shutdown(engine, &self.router);
        self.gossipsub.shutdown(&self.router, engine);
        self.router.negotiator.shutdown(engine);
        self.applications = .closed;
    }

    pub fn deinit(self: *Service) void {
        if (self.identify) |*identify| identify.deinit();
        const allocator = self.gossipsub.allocator;
        self.gossipsub.deinit();
        allocator.destroy(self.gossipsub);
        self.reqresp.deinit();
        self.router.deinit();
        self.* = undefined;
    }

    pub fn allocatedBytes(self: *const Service) usize {
        const request_memory = self.reqresp.memoryPlan();
        const gossip_plan = self.gossipsub.memoryPlan();
        const negotiation = @TypeOf(self.router.negotiator.entries[0]);
        return request_memory.total_bytes - request_memory.facade_bytes +
            gossip_plan.total_bytes +
            self.router.negotiator.entries.len * @sizeOf(negotiation) +
            if (self.identify) |*identify| identify.allocatedBytes() else @as(usize, 0);
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
            engine,
            &self.router,
            conn,
            protocol,
            bytes,
            sink,
            options,
            now,
        );
    }

    /// Combine protocol deadlines and independent host output capacities with the transport wakeup.
    pub fn nextWakeup(self: *Service, now: types.Now, capacities: Capacities) ?u64 {
        const request_due = self.reqresp.nextWakeup(now, .{ .application = capacities.application, .control = capacities.control });
        const gossip = if (self.applications == .active) self.gossipsub.nextWakeup(now, capacities.gossipsub) else null;
        const identify_due = if (self.identify) |*identify| identify.nextWakeup(now, capacities.identify) else null;
        var due = request_due;
        for ([_]?u64{ gossip, identify_due, self.router.nextWakeup(now, routing.outcomes_per_pump) }) |next| if (next) |value| {
            due = @min(due orelse value, value);
        };
        return due;
    }

    /// Forward transport activity separately from lifecycle events.
    /// The activity batch must not exceed the Engine connection capacity.
    /// Handles retain full transport generations, including connections without a gossip owner.
    pub fn process(self: *Service, engine: *engine_mod.Engine, events: []const engine_mod.Event, activity: []const engine_mod.Handle, now: types.Now, outputs: Outputs) OutputCounts {
        self.prepare(engine, events, activity, now);
        const counts = self.reqresp.pump(engine, &self.router, now, .{ .application = outputs.application, .control = outputs.control });
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
            self.reqresp.cancelApplications(engine, &self.router);
            self.gossipsub.shutdown(&self.router, engine);
            self.applications = .closed;
        }
        for (activity) |conn| {
            if (self.identify) |*identify| identify.connectionActivity(conn);
            self.reqresp.connectionActivity(conn);
            if (self.applications == .active) self.gossipsub.connectionActivity(conn);
        }
        self.reqresp.cleanupPending(engine, &self.router);
        self.router.transportEvents(engine, events, now);
        for (events) |event| switch (event) {
            .closed => |closed| self.reqresp.connectionClosed(closed.conn),
            .stream_closed => |closed| if (closed.reset_code != null) self.reqresp.streamReset(closed.stream),
            else => {},
        };
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
                .reqresp => {
                    if (outcome.direction == .outbound) {
                        if (!self.reqresp.negotiated(outcome, now)) engine.closeStream(outcome.stream, 0);
                    } else switch (outcome.result) {
                        .ready => |selection| _ = self.reqresp.accept(engine, outcome.stream, selection, now) catch |err| {
                            engine.closeStream(outcome.stream, if (err == error.TooManyRequests) @import("reqresp/constants.zig").app_error_over_limit else 0);
                        },
                        else => {},
                    }
                },
                .meshsub => self.gossipsub.negotiationResult(engine, outcome, now),
            }
        }
    }
};
