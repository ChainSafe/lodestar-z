const std = @import("std");
const negotiate = @import("negotiate.zig");
const engine_mod = @import("quic/engine.zig");
const types = @import("types.zig");
const reqresp = @import("reqresp/protocol.zig");
const capability = @import("capabilities.zig");
const Version = @import("gossipsub/protocol.zig").Version;

pub const Kind = @import("protocol.zig").Kind;
pub const Protocol = @import("protocol.zig").Protocol;

/// Leftover bytes remain borrowed until the next router pump. The selected
/// handler must copy or consume them synchronously, including a coalesced FIN.
pub const Selection = struct { protocol: Protocol, leftover: []const u8, fin: bool };
pub const Outcome = struct {
    stream: engine_mod.StreamHandle,
    direction: types.Direction,
    owner: ?Kind,
    result: union(enum) { ready: Selection, rejected, failed: negotiate.Failure },
};

pub const Error = negotiate.Error || error{ InvalidCapabilities, ProtocolDisabled };
pub const Counters = struct {
    refused: u64 = 0,
    inbound_failures: [std.enums.values(negotiate.Failure).len]u64 = @splat(0),
};

pub const Options = struct {
    capabilities: ?capability.Directional = null,
    negotiations_max: u16 = negotiate.negotiations_max_default,
    outbound_control_reserved: u16 = 0,
    outbound_reserved: ?u16 = null,
    inbound_per_connection_max: u16 = 16,
    identify: bool = false,
    reqresp: bool = true,
    meshsub: bool = true,
    meshsub_versions: []const Version = &.{ .v1_2, .v1_1, .v1_0 },
};

pub const Router = struct {
    counters: Counters = .{},
    negotiator: negotiate.Negotiator,
    supported: [capability.protocol_count]negotiate.Protocol = undefined,
    supported_count: u8 = 0,
    available: capability.Set,
    active_capabilities: capability.Directional = .{ .receive = .initEmpty(), .request = .initEmpty() },
    meshsub_versions: [3]Version = undefined,
    meshsub_versions_count: u8,
    meshsub_candidates: [3]negotiate.Protocol = undefined,
    meshsub_count: u8 = 0,

    pub fn validateOptions(options: Options) Error!void {
        if (!options.reqresp and !options.meshsub and !options.identify) return error.InvalidLimits;
        if (options.meshsub_versions.len == 0 or options.meshsub_versions.len > 3) {
            return error.InvalidLimits;
        }
        for (options.meshsub_versions, 0..) |version, index| {
            for (options.meshsub_versions[0..index]) |prior| {
                if (version == prior) return error.InvalidLimits;
            }
        }
        if (options.capabilities) |active| try validateSet(availableFor(options), active);
        try negotiate.Negotiator.validateOptions(.{
            .negotiations_max = options.negotiations_max,
            .outbound_control_reserved = options.outbound_control_reserved,
            .outbound_reserved = options.outbound_reserved,
            .inbound_per_connection_max = options.inbound_per_connection_max,
        });
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) Error!Router {
        try validateOptions(options);
        var negotiator = try negotiate.Negotiator.init(allocator, .{
            .negotiations_max = options.negotiations_max,
            .outbound_control_reserved = options.outbound_control_reserved,
            .outbound_reserved = options.outbound_reserved,
            .inbound_per_connection_max = options.inbound_per_connection_max,
        });
        errdefer negotiator.deinit();
        var router: Router = .{
            .negotiator = negotiator,
            .available = availableFor(options),
            .meshsub_versions_count = @intCast(options.meshsub_versions.len),
        };
        @memcpy(router.meshsub_versions[0..options.meshsub_versions.len], options.meshsub_versions);
        router.setCapabilities(options.capabilities orelse .{ .receive = router.available, .request = router.available });
        return router;
    }

    pub fn deinit(self: *Router) void {
        self.negotiator.deinit();
        self.* = undefined;
    }

    fn availableFor(options: Options) capability.Set {
        var available: capability.Set = .initEmpty();
        if (options.identify) available.insert(.identify);
        if (options.reqresp) for (std.enums.values(reqresp.Protocol)) |which| {
            available.insert(.{ .reqresp = which });
        };
        if (options.meshsub) for (options.meshsub_versions) |version| {
            available.insert(.{ .meshsub = version });
        };
        return available;
    }

    fn validateSet(available: capability.Set, active: capability.Directional) error{InvalidCapabilities}!void {
        if ((active.receive.bits | active.request.bits) & ~available.bits != 0) return error.InvalidCapabilities;
    }

    pub fn validateCapabilities(self: *const Router, active: capability.Directional) error{InvalidCapabilities}!void {
        try validateSet(self.available, active);
    }

    /// Applies to unselected proposals; accepted streams retain their protocol.
    pub fn setCapabilities(self: *Router, active: capability.Directional) void {
        self.validateCapabilities(active) catch unreachable;
        self.active_capabilities = active;
        self.supported_count = 0;
        self.meshsub_count = 0;
        for (std.enums.values(reqresp.Protocol)) |which| {
            if (active.receive.contains(.{ .reqresp = which })) {
                self.supported[self.supported_count] = descriptor(.{ .reqresp = which });
                self.supported_count += 1;
            }
        }
        for (self.meshsub_versions[0..self.meshsub_versions_count]) |version| {
            const protocol: Protocol = .{ .meshsub = version };
            if (active.receive.contains(protocol)) {
                self.supported[self.supported_count] = descriptor(protocol);
                self.supported_count += 1;
            }
            if (active.request.contains(protocol)) {
                self.meshsub_candidates[self.meshsub_count] = descriptor(protocol);
                self.meshsub_count += 1;
            }
        }
        if (active.receive.contains(.identify)) {
            self.supported[self.supported_count] = descriptor(.identify);
            self.supported_count += 1;
        }
        std.debug.assert(self.supported_count == active.receive.count());
    }

    pub fn capabilities(self: *const Router) capability.Directional {
        return self.active_capabilities;
    }

    pub fn cancel(self: *Router, engine: *engine_mod.Engine, stream: engine_mod.StreamHandle) void {
        self.negotiator.cancel(engine, stream);
    }

    pub fn beginOutbound(
        self: *Router,
        engine: *engine_mod.Engine,
        conn: engine_mod.Handle,
        protocol: Protocol,
        now: types.Now,
    ) Error!engine_mod.StreamHandle {
        if (!self.active_capabilities.request.contains(protocol)) return error.ProtocolDisabled;
        return self.negotiator.beginOutbound(engine, conn, &.{descriptor(protocol)}, now, .{
            .control = protocol == .reqresp and protocol.reqresp.isControl(),
        });
    }

    pub fn beginReqRespTimed(
        self: *Router,
        engine: *engine_mod.Engine,
        conn: engine_mod.Handle,
        protocol: @import("reqresp/protocol.zig").Protocol,
        now: types.Now,
        timeout_ms: u64,
    ) Error!engine_mod.StreamHandle {
        if (!self.active_capabilities.request.contains(.{ .reqresp = protocol })) return error.ProtocolDisabled;
        return self.negotiator.beginOutbound(engine, conn, &.{descriptor(.{ .reqresp = protocol })}, now, .{ .control = protocol.isControl(), .timeout_ms = timeout_ms });
    }

    pub fn beginMeshsub(
        self: *Router,
        engine: *engine_mod.Engine,
        conn: engine_mod.Handle,
        now: types.Now,
    ) Error!engine_mod.StreamHandle {
        if (self.meshsub_count == 0) return error.ProtocolDisabled;
        return self.negotiator.beginOutbound(engine, conn, self.meshsub_candidates[0..self.meshsub_count], now, .{});
    }

    pub fn transportEvents(
        self: *Router,
        engine: *engine_mod.Engine,
        events: []const engine_mod.Event,
        now: types.Now,
    ) void {
        for (events) |event| switch (event) {
            .stream_opened => |stream| {
                self.negotiator.acceptInbound(stream, now) catch {
                    self.counters.refused +|= 1;
                    engine.closeStream(stream, types.app_error_negotiation_failed);
                };
            },
            .closed => |closed| self.negotiator.connectionClosed(engine, closed.conn),
            .stream_closed => |closed| if (closed.reset_code != null) {
                self.negotiator.streamClosed(engine, closed.stream);
            },
            else => {},
        };
    }

    pub fn nextWakeup(self: *const Router, now: types.Now, outcome_capacity: usize) ?u64 {
        return self.negotiator.nextWakeup(now, outcome_capacity);
    }

    pub fn pump(self: *Router, engine: *engine_mod.Engine, now: types.Now, out: []Outcome) usize {
        std.debug.assert(out.len <= outcomes_per_pump);
        var raw: [outcomes_per_pump]negotiate.Outcome = undefined;
        const count = self.negotiator.pump(engine, now, self.supported[0..self.supported_count], raw[0..out.len]);
        for (raw[0..count], out[0..count]) |result, *outcome| {
            if (result.direction == .inbound and result.result == .failed) {
                self.counters.inbound_failures[@intFromEnum(result.result.failed)] +|= 1;
                std.log.scoped(.network_quic).debug("inbound_negotiation_failed connection={d}:{d} stream={d} reason={s}", .{ result.stream.conn.index, result.stream.conn.generation, result.stream.id, @tagName(result.result.failed) });
            }
            const selected: ?Protocol = if (result.protocol_index) |index| Protocol.fromIndex(index) else null;
            outcome.* = .{
                .stream = result.stream,
                .direction = result.direction,
                .owner = if (selected) |protocol| std.meta.activeTag(protocol) else null,
                .result = switch (result.result) {
                    .ready => |ready| .{ .ready = .{
                        .protocol = selected.?,
                        .leftover = ready.leftover,
                        .fin = ready.fin,
                    } },
                    .rejected => .rejected,
                    .failed => |failure| .{ .failed = failure },
                },
            };
        }
        return count;
    }
};

fn descriptor(protocol: Protocol) negotiate.Protocol {
    return .{ .id = protocol.id(), .index = protocol.index() };
}

pub const outcomes_per_pump: usize = 16;

comptime {
    std.debug.assert(capability.protocol_count <= negotiate.supported_max);
}

test {
    _ = @import("router_test.zig");
}
