const std = @import("std");
const routing = @import("router.zig");
const engine_mod = @import("quic/engine.zig");
const types = @import("types.zig");
const reqresp_mod = @import("reqresp/root.zig");
const gossip_mod = @import("gossipsub/root.zig");

const identify_mod = @import("identify/root.zig");
const wake_sources = @import("wake_sources.zig");

pub const Options = struct {
    identify: identify_mod.Options = .{},
    router: routing.Options = .{},
    reqresp: reqresp_mod.reqresp.Options,
    gossipsub: gossip_mod.Options = .{},
};
pub const Outputs = struct { application: []reqresp_mod.Event = &.{}, control: []reqresp_mod.Event = &.{}, identify: []identify_mod.Result = &.{} };
pub const OutputCounts = struct { application: usize, control: usize, identify: usize };
pub const Capacities = struct { application: usize = 0, control: usize = 0, identify: usize = 0 };
pub const InitError = routing.Error || reqresp_mod.reqresp.InitError || gossip_mod.gossipsub.InitError || identify_mod.handler.InitError;

pub const Service = struct {
    identify: identify_mod.Handler,
    applications: enum { active, quiescing, closed } = .active,
    router: routing.Router,
    reqresp: reqresp_mod.ReqResp,
    gossipsub: *gossip_mod.Gossipsub,
    /// The router outcomes `dispatch` hands to their owners. A field rather than a local so
    /// ReleaseSafe does not fill it every turn.
    outcomes: [routing.outcomes_per_pump]routing.Outcome = undefined,

    pub fn validateOptions(options: Options) InitError!void {
        try routing.Router.validateOptions(options.router);
        try identify_mod.Handler.validate(options.identify);
        try reqresp_mod.ReqResp.validateOptions(options.reqresp);
        try @import("gossipsub/options.zig").validate(&options.gossipsub);
    }

    /// The caller constructs Local from the transport identity and resolved advertisement.
    /// The supplied value is authoritative; Identify options retain startup validation and limits.
    pub fn init(allocator: std.mem.Allocator, options: Options, local: *const identify_mod.Local) InitError!Service {
        try validateOptions(options);
        var router = try routing.Router.init(allocator, options.router);
        errdefer router.deinit();
        var reqresp = try reqresp_mod.ReqResp.init(allocator, options.reqresp);
        errdefer reqresp.deinit();
        const gossipsub = try allocator.create(gossip_mod.Gossipsub);
        errdefer allocator.destroy(gossipsub);
        gossipsub.* = try gossip_mod.Gossipsub.init(allocator, options.gossipsub);
        errdefer gossipsub.deinit();
        const identify = try identify_mod.Handler.init(allocator, options.identify.limits(), local);
        return .{
            .identify = identify,
            .router = router,
            .reqresp = reqresp,
            .gossipsub = gossipsub,
        };
    }

    pub fn shutdown(self: *Service, engine: *engine_mod.Engine) void {
        self.identify.shutdown(&self.router, engine);
        self.reqresp.shutdown(engine, &self.router);
        self.gossipsub.shutdown(&self.router, engine);
        self.router.negotiator.shutdown(engine);
        self.applications = .closed;
    }

    pub fn deinit(self: *Service) void {
        self.identify.deinit();
        const allocator = self.gossipsub.allocator;
        self.gossipsub.deinit();
        allocator.destroy(self.gossipsub);
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
        var wakeups: wake_sources.Wakeups = .{};
        self.collectWakeups(now, capacities, &wakeups);
        return wakeups.earliest();
    }

    pub fn collectWakeups(self: *Service, now: types.Now, capacities: Capacities, wakeups: *wake_sources.Wakeups) void {
        wakeups.note(.reqresp, self.reqresp.nextWakeup(now, .{ .application = capacities.application, .control = capacities.control }));
        if (self.applications == .active) wakeups.note(.gossip, self.gossipsub.nextWakeup(now));
        wakeups.note(.identify, self.identify.nextWakeup(now, capacities.identify));
        wakeups.note(.negotiation, self.router.nextWakeup(now, routing.outcomes_per_pump));
    }

    /// Delivers one turn of engine events, then pumps each owner's ready work and due deadlines.
    pub fn process(self: *Service, engine: *engine_mod.Engine, events: []const engine_mod.Event, now: types.Now, outputs: Outputs) OutputCounts {
        self.dispatch(engine, events, now);
        const counts = self.reqresp.pump(engine, &self.router, now, .{ .application = outputs.application, .control = outputs.control });
        if (self.applications == .active) self.gossipsub.pump(&self.router, engine, now);
        return .{ .application = counts.application, .control = counts.control, .identify = self.identify.pump(&self.router, engine, now, outputs.identify) };
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

    /// Lifecycle events go to the router, reqresp, identify and gossip. Each stream readiness
    /// event goes to the owner its route names, read from the engine at dispatch time; an
    /// unrouted one advances nothing.
    fn dispatch(
        self: *Service,
        engine: *engine_mod.Engine,
        events: []const engine_mod.Event,
        now: types.Now,
    ) void {
        if (self.applications == .quiescing) {
            self.reqresp.cancelApplications(engine, &self.router);
            self.gossipsub.shutdown(&self.router, engine);
            self.applications = .closed;
        }
        for (events) |event| {
            const ready = switch (event) {
                .stream_ready => |ready| ready,
                else => continue,
            };
            const route = engine.route(ready.stream) orelse continue;
            switch (route.owner) {
                .negotiation => self.router.negotiator.streamReady(route.row, ready.stream),
                .identify => self.identify.streamReady(route.row, ready.stream),
                .reqresp_outbound, .reqresp_inbound => self.reqresp.streamReady(route, ready.stream),
                .gossip_inbound, .gossip_outbound => if (self.applications == .active) self.gossipsub.streamReady(engine, route, ready.stream, ready.ready),
                .none => {},
            }
        }
        self.reqresp.cleanupPending(engine, &self.router);
        self.router.transportEvents(engine, events, now);
        for (events) |event| switch (event) {
            .closed => |closed| self.reqresp.connectionClosed(closed.conn),
            .stream_closed => |closed| self.reqresp.streamClosed(closed.route, closed.stream, closed.reset_code),
            else => {},
        };
        self.identify.transportEvents(engine, events);
        for (events) |event| {
            if (self.applications != .active or event == .connected) continue;
            self.gossipsub.transportEvents(&self.router, engine, &.{event}, now);
        }
        self.reqresp.cleanupPending(engine, &self.router);
        const count = self.router.pump(engine, now, &self.outcomes);
        defer self.router.releaseOutcomes();
        for (self.outcomes[0..count]) |outcome| {
            const owner = outcome.owner orelse continue;
            if (self.rejectApplication(&outcome)) {
                engine.closeStream(outcome.stream, 0);
                continue;
            }
            // The negotiator lets go of the stream; the new owner binds its own route.
            if (outcome.result == .ready) engine.bindStream(outcome.stream, .{}) catch {};
            switch (owner) {
                .identify => self.identify.negotiationResult(&self.router, engine, outcome, now),
                .reqresp => {
                    if (outcome.direction == .outbound) {
                        if (!self.reqresp.negotiated(engine, outcome, now)) engine.closeStream(outcome.stream, 0);
                    } else switch (outcome.result) {
                        .ready => |selection| _ = self.reqresp.accept(engine, outcome.stream, selection, now) catch |err| {
                            if (err == error.ProtocolConcurrency) {
                                const codec = @import("reqresp/codec.zig");
                                const message = "Rate limited: already 2 active requests for this protocol";
                                var wire: [codec.encodedLengthMax(message.len)]u8 = undefined;
                                const response = codec.encodeChunk(@import("reqresp/constants.zig").result_rate_limited, null, message, &wire) catch unreachable;
                                if (self.router.finishSelected(engine, outcome.stream, response, now)) continue;
                            }
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
