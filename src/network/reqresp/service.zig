const std = @import("std");
const engine_mod = @import("../quic/engine.zig");
const routing = @import("../router.zig");
const types = @import("../types.zig");
const protocol = @import("protocol.zig");
const reqresp = @import("reqresp.zig");

const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const Handle = engine_mod.Handle;
const TransportEvent = engine_mod.Event;
const Now = types.Now;
const Protocol = protocol.Protocol;
const RequestHandle = reqresp.RequestHandle;

pub const outcomes_per_pump: usize = 16;

pub const Options = struct {
    reqresp: reqresp.Options,
    negotiations_max: ?u16 = null,
    outbound_control_reserved: u16 = 0,
};

pub const InitError = routing.Error || reqresp.InitError;

const Handler = @import("handler.zig").Handler;

pub const Service = struct {
    router: routing.Router,
    handler: Handler,

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!Service {
        var handler = try Handler.init(allocator, options.reqresp);
        errdefer handler.deinit();
        const default_neg = @as(u32, options.reqresp.outbound_max) + options.reqresp.inbound_max;
        const router = try routing.Router.init(allocator, .{
            .negotiations_max = options.negotiations_max orelse
                @intCast(@min(default_neg, std.math.maxInt(u16))),
            .meshsub = false,
            .outbound_control_reserved = options.outbound_control_reserved,
        });
        return .{ .router = router, .handler = handler };
    }

    pub fn deinit(self: *Service) void {
        self.handler.deinit();
        self.router.deinit();
        self.* = undefined;
    }

    pub fn request(
        self: *Service,
        engine: *Engine,
        conn: Handle,
        which: Protocol,
        request_ssz: []const u8,
        sink: []u8,
        options: reqresp.RequestOptions,
        now: Now,
    ) reqresp.RequestError!RequestHandle {
        return self.handler.request(
            &self.router,
            engine,
            conn,
            which,
            request_ssz,
            sink,
            options,
            now,
        );
    }

    pub fn nextWakeup(self: *Service, now: Now, event_capacity: usize) ?u64 {
        return self.handler.nextWakeup(&self.router, now, event_capacity);
    }

    pub fn nextWakeupPartitioned(
        self: *Service,
        now: Now,
        application_capacity: usize,
        control_capacity: usize,
    ) ?u64 {
        return self.handler.nextWakeupPartitioned(
            &self.router,
            now,
            application_capacity,
            control_capacity,
        );
    }

    /// Forward Driver activity separately from lifecycle events.
    /// The activity batch must not exceed the Engine connection capacity.
    /// Handles retain full transport generations, including connections without a gossip owner.
    pub fn process(
        self: *Service,
        engine: *Engine,
        events: []const TransportEvent,
        activity: []const Handle,
        now: Now,
        out: []reqresp.Event,
    ) usize {
        self.prepare(engine, events, activity, now);
        return self.pump(engine, now, out);
    }

    pub fn processPartitioned(
        self: *Service,
        engine: *Engine,
        events: []const TransportEvent,
        activity: []const Handle,
        now: Now,
        application: []reqresp.Event,
        control: []reqresp.Event,
    ) reqresp.PartitionedCounts {
        self.prepare(engine, events, activity, now);
        return self.handler.pumpPartitioned(&self.router, engine, now, application, control);
    }

    fn prepare(
        self: *Service,
        engine: *Engine,
        events: []const TransportEvent,
        activity: []const Handle,
        now: Now,
    ) void {
        const router = &self.router;
        assert(activity.len <= engine.limits.connections_max);
        for (activity) |conn| self.handler.inner.connectionActivity(conn);
        self.handler.inner.cleanupPending(engine, router);
        router.transportEvents(engine, events, now);
        self.handler.transportEvents(events);
        var outcomes: [outcomes_per_pump]routing.Outcome = undefined;
        const count = router.pump(engine, now, &outcomes);
        for (outcomes[0..count]) |outcome| self.handler.negotiationResult(engine, outcome, now);
    }

    pub fn pump(self: *Service, engine: *Engine, now: Now, out: []reqresp.Event) usize {
        return self.handler.pump(&self.router, engine, now, out);
    }

    pub fn shutdown(self: *Service, engine: *Engine) void {
        self.handler.shutdown(&self.router, engine);
    }

    pub fn pumpPartitioned(
        self: *Service,
        engine: *Engine,
        now: Now,
        application: []reqresp.Event,
        control: []reqresp.Event,
    ) reqresp.PartitionedCounts {
        return self.handler.pumpPartitioned(&self.router, engine, now, application, control);
    }
};
