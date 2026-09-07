const std = @import("std");
const negotiate = @import("negotiate.zig");
const engine_mod = @import("quic/engine.zig");
const types = @import("types.zig");
const reqresp = @import("reqresp/protocol.zig");
const capability = @import("capabilities.zig");
const Version = @import("gossipsub/state.zig").Version;

pub const meshsub_ids = [_][]const u8{ "/meshsub/1.2.0", "/meshsub/1.1.0", "/meshsub/1.0.0" };
pub const Kind = enum { reqresp, meshsub, identify };
pub const Protocol = union(Kind) {
    reqresp: reqresp.Protocol,
    meshsub: Version,
    identify,

    pub fn id(self: Protocol) []const u8 {
        return switch (self) {
            .identify => "/ipfs/id/1.0.0",
            .reqresp => |which| which.id(),
            .meshsub => |version| meshsub_ids[2 - @intFromEnum(version)],
        };
    }

    pub fn fromId(id_bytes: []const u8) ?Protocol {
        if (std.mem.eql(u8, id_bytes, "/ipfs/id/1.0.0")) return .identify;
        if (reqresp.Protocol.fromId(id_bytes)) |which| return .{ .reqresp = which };
        for (meshsub_ids, 0..) |id_string, index| {
            if (std.mem.eql(u8, id_string, id_bytes)) return .{
                .meshsub = @enumFromInt(2 - index),
            };
        }
        return null;
    }
};

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

pub const Options = struct {
    capabilities: ?capability.Directional = null,
    negotiations_max: u16 = negotiate.negotiations_max_default,
    outbound_control_reserved: u16 = 0,
    identify: bool = false,
    reqresp: bool = true,
    meshsub: bool = true,
    meshsub_versions: []const Version = &.{ .v1_2, .v1_1, .v1_0 },
};

pub const Router = struct {
    negotiator: negotiate.Negotiator,
    supported: [capability.protocol_count][]const u8 = undefined,
    supported_count: u8 = 0,
    available: capability.Set,
    active_capabilities: capability.Directional = .{ .receive = .initEmpty(), .request = .initEmpty() },
    meshsub_versions: [3]Version = undefined,
    meshsub_versions_count: u8,
    meshsub_candidates: [3][]const u8 = undefined,
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
        try negotiate.Negotiator.validateOptions(.{ .negotiations_max = options.negotiations_max, .outbound_control_reserved = options.outbound_control_reserved });
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) Error!Router {
        try validateOptions(options);
        var negotiator = try negotiate.Negotiator.initWithOptions(allocator, .{
            .negotiations_max = options.negotiations_max,
            .outbound_control_reserved = options.outbound_control_reserved,
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

    /// Commits a validated value without allocation; existing listeners own their prior offers.
    pub fn setCapabilities(self: *Router, active: capability.Directional) void {
        self.validateCapabilities(active) catch unreachable;
        self.active_capabilities = active;
        self.supported_count = 0;
        self.meshsub_count = 0;
        for (std.enums.values(reqresp.Protocol)) |which| {
            if (active.receive.contains(.{ .reqresp = which })) {
                self.supported[self.supported_count] = which.id();
                self.supported_count += 1;
            }
        }
        for (self.meshsub_versions[0..self.meshsub_versions_count]) |version| {
            const protocol: Protocol = .{ .meshsub = version };
            if (active.receive.contains(protocol)) {
                self.supported[self.supported_count] = protocol.id();
                self.supported_count += 1;
            }
            if (active.request.contains(protocol)) {
                self.meshsub_candidates[self.meshsub_count] = protocol.id();
                self.meshsub_count += 1;
            }
        }
        if (active.receive.contains(.identify)) {
            self.supported[self.supported_count] = @as(Protocol, .identify).id();
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
        if (protocol == .reqresp and protocol.reqresp.isControl()) {
            return self.negotiator.beginOutboundControl(engine, conn, protocol.reqresp, now);
        }
        return self.negotiator.beginOutbound(engine, conn, protocol.id(), now);
    }

    pub fn beginMeshsub(
        self: *Router,
        engine: *engine_mod.Engine,
        conn: engine_mod.Handle,
        now: types.Now,
    ) Error!engine_mod.StreamHandle {
        if (self.meshsub_count == 0) return error.ProtocolDisabled;
        return self.negotiator.beginOutboundCandidates(
            engine,
            conn,
            self.meshsub_candidates[0..self.meshsub_count],
            now,
        );
    }

    pub fn transportEvents(
        self: *Router,
        engine: *engine_mod.Engine,
        events: []const engine_mod.Event,
        now: types.Now,
    ) void {
        for (events) |event| switch (event) {
            .stream_opened => |stream| {
                self.negotiator.acceptInbound(stream, self.supported[0..self.supported_count], now) catch {
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
        const count = self.negotiator.pump(engine, now, raw[0..out.len]);
        for (raw[0..count], out[0..count]) |result, *outcome| {
            const selected = Protocol.fromId(result.protocol_id);
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

pub const outcomes_per_pump: usize = 16;

comptime {
    std.debug.assert(capability.protocol_count <= negotiate.supported_max);
}
