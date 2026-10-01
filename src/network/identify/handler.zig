const std = @import("std");
const codec = @import("codec.zig");
const routing = @import("../router.zig");
const Engine = @import("../quic/Engine.zig");
const types = @import("../types.zig");
const PeerRef = types.PeerRef;
const Outbox = @import("../stream_io.zig").Outbox;

pub const Limits = struct {
    inbound_max: u16 = 2,
    outbound_max: u16 = 2,

    pub fn validate(self: Limits) error{InvalidLimits}!void {
        if (self.inbound_max == 0 or self.inbound_max > 64 or self.outbound_max == 0 or self.outbound_max > 64) return error.InvalidLimits;
    }
};
pub const Options = struct {
    inbound_max: u16 = 2,
    outbound_max: u16 = 2,
    agent: []const u8 = "",
    protocol_version: []const u8 = "ipfs/0.1.0",
    addresses: []const types.Address = &.{},

    pub fn limits(self: Options) Limits {
        return .{ .inbound_max = self.inbound_max, .outbound_max = self.outbound_max };
    }

    /// Resolve the complete local value at startup. Explicit addresses replace the usable
    /// bound fallback, and the result owns its text, key and encoded addresses.
    pub fn makeLocal(self: Options, peer: *const @import("../wire/peer_id.zig").PeerId, bound: *const [2]?types.Address) InitError!codec.Local {
        try Handler.validate(self);
        if (self.addresses.len > 0) return codec.Local.init(peer, self.agent, self.protocol_version, self.addresses);
        var addresses: [2]types.Address = undefined;
        var count: usize = 0;
        for (bound) |address| if (address) |value| {
            if (!value.isUsable()) continue;
            addresses[count] = value;
            count += 1;
        };
        return codec.Local.init(peer, self.agent, self.protocol_version, addresses[0..count]);
    }
};
pub const Failure = enum { negotiation, malformed, timeout, reset, transport, shutdown };
pub const Result = struct {
    peer: PeerRef,
    conn: Engine.Handle,
    outcome: union(enum) { success: codec.Metadata, failed: Failure },
};
pub const InitError = std.mem.Allocator.Error || codec.Error || error{InvalidLimits};
pub const StartError = routing.Error || error{ PeerLimit, IdentifyCapacity, Stopped };
const deadline_ms = 5_000;
const Inbound = struct {
    stream: ?Engine.StreamHandle = null,
    deadline: u64 = 0,
    ready: bool = false,
    bytes: [codec.frame_max + 2]u8 = undefined,
    outbox: Outbox = .{},
};
const Outbound = struct {
    stream: ?Engine.StreamHandle = null,
    peer: PeerRef = undefined,
    deadline: u64 = 0,
    ready: bool = false,
    phase: enum { negotiating, reading, terminal } = .negotiating,
    sent_fin: bool = false,
    decoder: codec.Decoder = undefined,
    result: Result = undefined,
};

pub const Handler = struct {
    allocator: std.mem.Allocator,
    inbound: []Inbound,
    outbound: []Outbound,
    local: codec.Local,
    stopped: bool = false,
    delivery_cursor: usize = 0,

    pub fn validate(options: Options) InitError!void {
        try options.limits().validate();
        _ = try codec.Text(256).init(options.agent);
        _ = try codec.Text(64).init(options.protocol_version);
        if (options.addresses.len > 8) return error.OccurrenceLimit;
        var check: codec.Local = undefined;
        check.addresses = @splat(.{});
        try check.setAddresses(options.addresses);
    }

    /// Copies a complete Local constructed for this transport identity. Each inbound stream
    /// encodes its own snapshot, so later publication cannot change an active response.
    pub fn init(allocator: std.mem.Allocator, options: Limits, local: *const codec.Local) InitError!Handler {
        try options.validate();
        const inbound = try allocator.alloc(Inbound, options.inbound_max);
        errdefer allocator.free(inbound);
        const outbound = try allocator.alloc(Outbound, options.outbound_max);
        errdefer allocator.free(outbound);
        @memset(inbound, .{});
        @memset(outbound, .{});
        return .{ .allocator = allocator, .inbound = inbound, .outbound = outbound, .local = local.* };
    }

    pub fn deinit(self: *Handler) void {
        self.allocator.free(self.outbound);
        self.allocator.free(self.inbound);
        self.* = undefined;
    }

    pub fn allocatedBytes(self: *const Handler) usize {
        return self.inbound.len * @sizeOf(Inbound) + self.outbound.len * @sizeOf(Outbound);
    }

    pub fn start(self: *Handler, router: *routing.Router, engine: *Engine, peer: PeerRef, conn: Engine.Handle, now: types.Now) StartError!void {
        if (self.stopped) return error.Stopped;
        for (self.outbound) |*slot| if (slot.stream) |stream| {
            if (std.meta.eql(stream.conn, conn)) return error.PeerLimit;
        };
        var free: ?*Outbound = null;
        for (self.outbound) |*slot| if (slot.stream == null) {
            free = slot;
            break;
        };
        const slot = free orelse return error.IdentifyCapacity;
        const expected = engine.peerId(conn) orelse return error.StaleHandle;
        const stream = try router.beginOutbound(engine, conn, .identify, now);
        slot.* = .{ .stream = stream, .peer = peer, .deadline = now.mono_ms +| deadline_ms, .decoder = .init(&expected) };
    }

    /// A routed stream event. Inbound slot `i` is row `i`; outbound slot `j` is row
    /// `inbound.len + j`. An event for a stream the slot no longer holds is dropped.
    pub fn streamReady(self: *Handler, row: u24, stream: Engine.StreamHandle) void {
        if (row < self.inbound.len) {
            const slot = &self.inbound[row];
            if (slot.stream != null and std.meta.eql(slot.stream.?, stream)) slot.ready = true;
            return;
        }
        if (row - self.inbound.len >= self.outbound.len) return;
        const slot = &self.outbound[row - self.inbound.len];
        if (slot.stream != null and std.meta.eql(slot.stream.?, stream) and slot.phase == .reading) slot.ready = true;
    }

    pub fn transportEvents(self: *Handler, engine: *Engine, events: []const Engine.Event) void {
        for (events) |event| switch (event) {
            .closed => |closed| self.closeMatching(engine, closed.conn, null, .transport),
            .stream_closed => |closed| if (closed.route.owner == .identify) {
                if (closed.reset_code != null) {
                    self.closeMatching(engine, closed.stream.conn, closed.stream, .reset);
                } else self.streamReady(closed.route.row, closed.stream);
            },
            else => {},
        };
    }

    fn bindRow(engine: *Engine, stream: Engine.StreamHandle, row: usize) void {
        // A stream that is already gone has no events to route.
        engine.bindStream(stream, .{ .owner = .identify, .row = @intCast(row) }) catch {};
    }

    fn closeMatching(self: *Handler, engine: *Engine, conn: Engine.Handle, which: ?Engine.StreamHandle, failure: Failure) void {
        for (self.inbound) |*slot| if (slot.stream) |stream| {
            if (std.meta.eql(stream.conn, conn) and (which == null or std.meta.eql(which.?, stream))) {
                engine.closeStream(stream, types.app_error_normal);
                slot.* = .{};
            }
        };
        for (self.outbound) |*slot| if (slot.stream) |stream| {
            if (std.meta.eql(stream.conn, conn) and (which == null or std.meta.eql(which.?, stream)) and slot.phase != .terminal) finish(slot, engine, .{ .failed = failure });
        };
    }

    pub fn negotiationResult(self: *Handler, router: *const routing.Router, engine: *Engine, outcome: routing.Outcome, now: types.Now) void {
        if (outcome.direction == .outbound) {
            for (self.outbound, 0..) |*slot, index| if (std.meta.eql(slot.stream, outcome.stream) and slot.phase == .negotiating) {
                switch (outcome.result) {
                    .ready => |selected| {
                        bindRow(engine, outcome.stream, self.inbound.len + index);
                        slot.phase = .reading;
                        slot.ready = true;
                        slot.decoder.feed(selected.leftover, selected.fin) catch {
                            finish(slot, engine, .{ .failed = .malformed });
                            return;
                        };
                    },
                    else => finish(slot, engine, .{ .failed = .negotiation }),
                }
                return;
            };
            return;
        }
        if (outcome.result != .ready) return;
        const selected = outcome.result.ready;
        if (self.stopped or selected.leftover.len != 0) {
            engine.closeStream(outcome.stream, types.app_error_normal);
            return;
        }
        for (self.inbound) |slot| if (slot.stream) |stream| {
            if (std.meta.eql(stream.conn, outcome.stream.conn)) {
                engine.closeStream(outcome.stream, types.app_error_normal);
                return;
            }
        };
        for (self.inbound, 0..) |*slot, index| if (slot.stream == null) {
            bindRow(engine, outcome.stream, index);
            slot.* = .{ .stream = outcome.stream, .deadline = now.mono_ms +| deadline_ms, .ready = true };
            const bytes = self.local.encode(router.capabilities().receive, engine.peerAddress(outcome.stream.conn), &slot.bytes) catch {
                engine.closeStream(outcome.stream, types.app_error_normal);
                slot.* = .{};
                return;
            };
            slot.outbox.queue(bytes, true);
            return;
        };
        engine.closeStream(outcome.stream, types.app_error_normal);
    }

    fn finish(slot: *Outbound, engine: *Engine, outcome: @FieldType(Result, "outcome")) void {
        const stream = slot.stream.?;
        engine.closeStream(stream, types.app_error_normal);
        slot.result = .{ .peer = slot.peer, .conn = stream.conn, .outcome = outcome };
        slot.phase = .terminal;
        slot.ready = false;
    }

    pub fn pump(self: *Handler, router: *routing.Router, engine: *Engine, now: types.Now, out: []Result) usize {
        for (self.inbound) |*slot| if (slot.stream) |stream| {
            if (now.mono_ms >= slot.deadline) {
                engine.closeStream(stream, types.app_error_normal);
                slot.* = .{};
                continue;
            }
            if (!slot.ready) continue;
            slot.ready = false;
            const done = slot.outbox.pump(engine, stream) catch {
                engine.closeStream(stream, types.app_error_normal);
                slot.* = .{};
                continue;
            };
            slot.ready = done == .yielded;
            if (done == .done) {
                engine.closeStream(stream, types.app_error_normal);
                slot.* = .{};
            }
        };
        var count: usize = 0;
        const start_index = self.delivery_cursor;
        for (0..self.outbound.len) |offset| {
            const index = (start_index + offset) % self.outbound.len;
            const slot = &self.outbound[index];
            const stream = slot.stream orelse continue;
            if (slot.phase != .terminal and now.mono_ms >= slot.deadline) {
                if (slot.phase == .negotiating) router.cancel(engine, stream);
                finish(slot, engine, .{ .failed = .timeout });
            }
            if (slot.phase == .reading and slot.ready) {
                slot.ready = false;
                for (0..8) |_| {
                    slot.ready = false;
                    if (!slot.sent_fin) {
                        // The responder may stop its unused request half before this empty FIN.
                        _ = engine.write(stream, &.{}, true) catch |err| switch (err) {
                            error.StreamStopped => 0,
                            error.WouldBlock => break,
                            else => {
                                finish(slot, engine, .{ .failed = .transport });
                                break;
                            },
                        };
                        slot.sent_fin = true;
                    } else if (slot.decoder.result()) |metadata| {
                        finish(slot, engine, .{ .success = metadata });
                        break;
                    } else {
                        var bytes: [2048]u8 = undefined;
                        const read = engine.read(stream, &bytes) catch |err| {
                            if (err != error.WouldBlock) finish(slot, engine, .{ .failed = .transport });
                            break;
                        };
                        if (read.reset_code != null) {
                            finish(slot, engine, .{ .failed = .reset });
                            break;
                        }
                        slot.decoder.feed(bytes[0..read.len], read.fin) catch {
                            finish(slot, engine, .{ .failed = .malformed });
                            break;
                        };
                        if (slot.decoder.result()) |metadata| {
                            finish(slot, engine, .{ .success = metadata });
                            break;
                        }
                        if (read.len == 0) break;
                    }
                    slot.ready = true;
                }
            }
            if (slot.phase == .terminal and count < out.len) {
                out[count] = slot.result;
                count += 1;
                slot.* = .{};
                self.delivery_cursor = (index + 1) % self.outbound.len;
            }
        }
        return count;
    }

    pub fn nextWakeup(self: *const Handler, now: types.Now, result_capacity: usize) ?u64 {
        var due: ?u64 = null;
        for (self.inbound) |slot| if (slot.stream != null) {
            const next = if (slot.ready) now.mono_ms else @max(now.mono_ms, slot.deadline);
            due = @min(due orelse next, next);
        };
        for (self.outbound) |slot| if (slot.stream != null) {
            if (slot.phase == .terminal) {
                if (result_capacity > 0) return now.mono_ms;
                continue;
            }
            const next = if (slot.phase == .reading and slot.ready) now.mono_ms else @max(now.mono_ms, slot.deadline);
            due = @min(due orelse next, next);
        };
        return due;
    }

    pub fn shutdown(self: *Handler, router: *routing.Router, engine: *Engine) void {
        self.stopped = true;
        for (self.inbound) |*slot| if (slot.stream) |stream| {
            engine.closeStream(stream, types.app_error_normal);
            slot.* = .{};
        };
        for (self.outbound) |*slot| if (slot.stream) |stream| {
            if (slot.phase != .terminal) {
                if (slot.phase == .negotiating) router.cancel(engine, stream);
                finish(slot, engine, .{ .failed = .shutdown });
            }
        };
    }
};

test {
    _ = @import("handler_snapshot_test.zig");
    _ = @import("handler_test.zig");
}
