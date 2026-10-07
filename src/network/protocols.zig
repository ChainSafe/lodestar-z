const std = @import("std");
const Router = @import("router.zig").Router;
const Engine = @import("quic/Engine.zig");
const types = @import("types.zig");
const reqresp_mod = @import("reqresp/root.zig");
const gossip_mod = @import("gossipsub/root.zig");

const identify_mod = @import("identify/root.zig");
const wake_sources = @import("wake_sources.zig");

pub const Protocols = struct {
    identify: identify_mod.Handler,
    applications_open: bool = true,
    stopped: bool = false,
    router: Router,
    reqresp: reqresp_mod.ReqResp,
    gossipsub: *gossip_mod.Gossipsub,
    /// The router outcomes `dispatch` hands to their owners. A field rather than a local so
    /// ReleaseSafe does not fill it every turn.
    outcomes: [Router.outcomes_per_pump]Router.Outcome = undefined,

    pub const Options = struct {
        identify: identify_mod.Handler.Options = .{},
        router: Router.Options = .{},
        reqresp: reqresp_mod.ReqResp.Options,
        gossipsub: gossip_mod.Gossipsub.Options = .{},
    };
    pub const Outputs = struct { application: []reqresp_mod.ReqResp.Event = &.{}, control: []reqresp_mod.ReqResp.Event = &.{}, identify: []identify_mod.Handler.Result = &.{} };
    pub const OutputCounts = struct { application: usize, control: usize, identify: usize };
    pub const Capacities = struct { application: usize = 0, control: usize = 0, identify: usize = 0 };
    pub const InitError = Router.Error || reqresp_mod.ReqResp.InitError || gossip_mod.Gossipsub.InitError || identify_mod.Handler.InitError || identify_mod.Handler.Options.Error;

    pub fn validateOptions(options: Options) InitError!void {
        try Router.validateOptions(options.router);
        try options.identify.validate();
        try options.reqresp.validate();
        try options.gossipsub.validate();
    }

    /// The caller constructs Local from the transport identity and resolved advertisement.
    /// The supplied value is authoritative; Identify options retain startup validation and limits.
    pub fn init(allocator: std.mem.Allocator, options: Options, local: *const identify_mod.Local) InitError!Protocols {
        try validateOptions(options);
        var router = try Router.init(allocator, options.router);
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

    /// Cancels all streams before deinit. No further process calls are allowed.
    pub fn shutdown(self: *Protocols, engine: *Engine, now: types.Now) void {
        if (self.stopped) return;
        self.stopped = true;
        self.identify.shutdown(&self.router, engine);
        self.reqresp.cancelAll(engine, &self.router, now);
        self.gossipsub.closeSessions(&self.router, engine);
        self.router.negotiator.cancelAll(engine);
        self.applications_open = false;
    }

    /// Ends all borrows and discards results that the caller has not drained.
    pub fn deinit(self: *Protocols) void {
        self.identify.deinit();
        const allocator = self.gossipsub.allocator;
        self.gossipsub.deinit();
        allocator.destroy(self.gossipsub);
        self.reqresp.deinit();
        self.router.deinit();
        self.* = undefined;
    }

    pub fn request(
        self: *Protocols,
        engine: *Engine,
        conn: Engine.Handle,
        protocol: reqresp_mod.Protocol,
        bytes: []const u8,
        sink: []u8,
        options: reqresp_mod.ReqResp.RequestOptions,
        now: types.Now,
    ) reqresp_mod.ReqResp.RequestError!reqresp_mod.ReqResp.RequestHandle {
        if (self.stopped or (!self.applications_open and !protocol.isControl())) return error.ProtocolDisabled;
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

    pub fn schedule(self: *const Protocols, capacities: Capacities) types.Schedule {
        var wakeups: wake_sources.Wakeups = .{};
        self.collectWakeups(capacities, &wakeups);
        return wakeups.schedule();
    }

    pub fn collectWakeups(self: *const Protocols, capacities: Capacities, wakeups: *wake_sources.Wakeups) void {
        std.debug.assert(!self.stopped);
        wakeups.note(.reqresp, self.reqresp.schedule(.{ .application = capacities.application, .control = capacities.control }));
        if (self.applications_open) wakeups.note(.gossip, self.gossipsub.schedule());
        wakeups.note(.identify, self.identify.schedule(capacities.identify));
        wakeups.note(.negotiation, self.router.schedule(Router.outcomes_per_pump));
    }

    /// Delivers one turn of engine events, then pumps each owner's ready work and due deadlines.
    pub fn process(self: *Protocols, engine: *Engine, events: []const Engine.Event, now: types.Now, outputs: Outputs) OutputCounts {
        std.debug.assert(!self.stopped);
        self.dispatch(engine, events, now);
        const counts = self.reqresp.pump(engine, &self.router, now, .{ .application = outputs.application, .control = outputs.control });
        if (self.applications_open) self.gossipsub.pump(&self.router, engine, now);
        return .{ .application = counts.application, .control = counts.control, .identify = self.identify.pump(&self.router, engine, now, outputs.identify) };
    }

    /// Cancels application streams. Consume the previous process call's borrowed events first.
    pub fn closeApplications(self: *Protocols, engine: *Engine, now: types.Now) void {
        if (!self.applications_open) return;
        self.applications_open = false;
        self.reqresp.cancelApplications(engine, &self.router, now);
        self.gossipsub.closeSessions(&self.router, engine);
    }

    fn rejectApplication(self: *const Protocols, outcome: *const Router.Outcome) bool {
        if (self.applications_open) return false;
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
        self: *Protocols,
        engine: *Engine,
        events: []const Engine.Event,
        now: types.Now,
    ) void {
        self.routeReadiness(engine, events);
        self.router.transportEvents(engine, events, now);
        for (events) |event| switch (event) {
            .closed => |closed| self.reqresp.connectionClosed(engine, &self.router, closed.conn, now),
            .stream_closed => |closed| self.reqresp.streamClosed(engine, &self.router, closed.route, closed.stream, closed.reset_code, now),
            else => {},
        };
        self.identify.transportEvents(engine, events);
        for (events) |event| {
            if (!self.applications_open or event == .connected) continue;
            self.gossipsub.transportEvents(&self.router, engine, &.{event}, now);
        }

        self.negotiate(engine, now);
    }

    fn routeReadiness(self: *Protocols, engine: *Engine, events: []const Engine.Event) void {
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
                .gossip_inbound, .gossip_outbound => if (self.applications_open) self.gossipsub.streamReady(engine, route, ready.stream, ready.ready),
                .none => {},
            }
        }
    }

    fn negotiate(self: *Protocols, engine: *Engine, now: types.Now) void {
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
                .reqresp => self.reqresp.negotiationResult(&self.router, engine, outcome, now),
                .meshsub => self.gossipsub.negotiationResult(engine, outcome, now),
            }
        }
    }
};

test {
    _ = @import("protocols_test.zig");
    _ = @import("protocols_reqresp_test.zig");
    _ = @import("protocols_gossipsub_test.zig");
}
