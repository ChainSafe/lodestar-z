const std = @import("std");
const negotiate = @import("negotiate.zig");
const engine_mod = @import("quic/engine.zig");
const types = @import("types.zig");
const reqresp = @import("reqresp/protocol.zig");
const Version = @import("gossipsub/state.zig").Version;

pub const meshsub_ids = [_][]const u8{ "/meshsub/1.2.0", "/meshsub/1.1.0", "/meshsub/1.0.0" };
pub const Kind = enum { reqresp, meshsub };
pub const Protocol = union(Kind) {
    reqresp: reqresp.Protocol,
    meshsub: Version,

    pub fn id(self: Protocol) []const u8 {
        return switch (self) {
            .reqresp => |which| which.id(),
            .meshsub => |version| meshsub_ids[2 - @intFromEnum(version)],
        };
    }

    pub fn fromId(id_bytes: []const u8) ?Protocol {
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

pub const Options = struct {
    negotiations_max: u16 = negotiate.negotiations_max_default,
    outbound_control_reserved: u16 = 0,
    reqresp: bool = true,
    meshsub: bool = true,
    meshsub_versions: []const Version = &.{ .v1_2, .v1_1, .v1_0 },
};

pub const Router = struct {
    allocator: std.mem.Allocator,
    negotiator: negotiate.Negotiator,
    supported: [][]const u8,
    meshsub_candidates: [3][]const u8 = undefined,
    meshsub_count: u8 = 0,

    pub fn init(allocator: std.mem.Allocator, options: Options) negotiate.Error!Router {
        if (!options.reqresp and !options.meshsub) return error.InvalidLimits;
        if (options.meshsub_versions.len == 0 or options.meshsub_versions.len > 3) {
            return error.InvalidLimits;
        }
        for (options.meshsub_versions, 0..) |version, index| {
            for (options.meshsub_versions[0..index]) |prior| {
                if (version == prior) return error.InvalidLimits;
            }
        }
        var negotiator = try negotiate.Negotiator.initWithOptions(allocator, .{
            .negotiations_max = options.negotiations_max,
            .outbound_control_reserved = options.outbound_control_reserved,
        });
        errdefer negotiator.deinit();
        const reqresp_count: usize = if (options.reqresp) reqresp.Protocol.count else 0;
        const meshsub_count = if (options.meshsub) options.meshsub_versions.len else 0;
        const supported = try allocator.alloc([]const u8, reqresp_count + meshsub_count);
        var router: Router = .{
            .allocator = allocator,
            .negotiator = negotiator,
            .supported = supported,
            .meshsub_count = @intCast(meshsub_count),
        };
        @memcpy(supported[0..reqresp_count], reqresp.ids[0..reqresp_count]);
        for (options.meshsub_versions[0..meshsub_count], 0..) |version, index| {
            const id = (Protocol{ .meshsub = version }).id();
            supported[reqresp_count + index] = id;
            router.meshsub_candidates[index] = id;
        }
        return router;
    }

    pub fn deinit(self: *Router) void {
        self.allocator.free(self.supported);
        self.negotiator.deinit();
        self.* = undefined;
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
    ) negotiate.Error!engine_mod.StreamHandle {
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
    ) negotiate.Error!engine_mod.StreamHandle {
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
                self.negotiator.acceptInbound(stream, self.supported, now) catch {
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
