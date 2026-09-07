const std = @import("std");
const codec = @import("codec.zig");
const routing = @import("../router.zig");
const engine_mod = @import("../quic/engine.zig");
const types = @import("../types.zig");
const PeerRef = @import("../peers/types.zig").PeerRef;
const Outbox = @import("../stream_io.zig").Outbox;

pub const Options = struct {
    inbound_max: u16 = 2,
    outbound_max: u16 = 2,
    agent: []const u8 = "",
    protocol_version: []const u8 = "ipfs/0.1.0",
    addresses: []const types.Address = &.{},
};
pub const Failure = enum { negotiation, malformed, timeout, reset, transport, shutdown };
pub const Result = struct {
    peer: PeerRef,
    conn: engine_mod.Handle,
    outcome: union(enum) { success: codec.Metadata, failed: Failure },
};
pub const InitError = std.mem.Allocator.Error || codec.Error || error{InvalidLimits};
pub const StartError = routing.Error || error{ PeerLimit, IdentifyCapacity, Stopped };
const deadline_ms = 5_000;
const Inbound = struct {
    stream: ?engine_mod.StreamHandle = null,
    deadline: u64 = 0,
    ready: bool = false,
    bytes: [codec.frame_max + 2]u8 = undefined,
    outbox: Outbox = .{},
};
const Outbound = struct {
    stream: ?engine_mod.StreamHandle = null,
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
    agent: codec.Text(256),
    protocol_version: codec.Text(64),
    addresses: [8]types.Address = undefined,
    address_count: u8 = 0,
    local: ?codec.Local = null,
    stopped: bool = false,

    pub fn validate(options: Options) InitError!void {
        if (options.inbound_max == 0 or options.inbound_max > 64 or options.outbound_max == 0 or options.outbound_max > 64) return error.InvalidLimits;
        _ = try codec.Text(256).init(options.agent);
        _ = try codec.Text(64).init(options.protocol_version);
        if (options.addresses.len > 8) return error.OccurrenceLimit;
        var check: codec.Local = undefined;
        check.addresses = @splat(.{});
        try check.setAddresses(options.addresses);
    }

    pub fn init(allocator: std.mem.Allocator, options: Options) InitError!Handler {
        try validate(options);
        const inbound = try allocator.alloc(Inbound, options.inbound_max);
        errdefer allocator.free(inbound);
        const outbound = try allocator.alloc(Outbound, options.outbound_max);
        errdefer allocator.free(outbound);
        @memset(inbound, .{});
        @memset(outbound, .{});
        var self: Handler = .{ .allocator = allocator, .inbound = inbound, .outbound = outbound, .agent = try .init(options.agent), .protocol_version = try .init(options.protocol_version), .address_count = @intCast(options.addresses.len) };
        @memcpy(self.addresses[0..options.addresses.len], options.addresses);
        return self;
    }

    pub fn deinit(self: *Handler) void {
        self.allocator.free(self.outbound);
        self.allocator.free(self.inbound);
        self.* = undefined;
    }

    pub fn allocatedBytes(self: *const Handler) usize {
        return self.inbound.len * @sizeOf(Inbound) + self.outbound.len * @sizeOf(Outbound);
    }

    pub fn bind(self: *Handler, engine: *const engine_mod.Engine) void {
        if (self.local != null) return;
        var local = codec.Local.init(&engine.tls.local_peer_id, self.agent.slice(), self.protocol_version.slice(), self.addresses[0..self.address_count]) catch unreachable;
        if (self.address_count == 0) local.setAddresses(&.{engine.local}) catch {};
        self.local = local;
    }

    pub fn start(self: *Handler, router: *routing.Router, engine: *engine_mod.Engine, peer: PeerRef, conn: engine_mod.Handle, now: types.Now) StartError!void {
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
        self.bind(engine);
    }

    pub fn connectionActivity(self: *Handler, conn: engine_mod.Handle) void {
        for (self.inbound) |*slot| if (slot.stream) |stream| {
            if (std.meta.eql(stream.conn, conn)) slot.ready = true;
        };
        for (self.outbound) |*slot| if (slot.stream) |stream| {
            if (std.meta.eql(stream.conn, conn)) slot.ready = true;
        };
    }

    pub fn transportEvents(self: *Handler, engine: *engine_mod.Engine, events: []const engine_mod.Event) void {
        for (events) |event| switch (event) {
            .closed => |closed| self.closeMatching(engine, closed.conn, null, .transport),
            .stream_closed => |closed| if (closed.reset_code != null) {
                self.closeMatching(engine, closed.stream.conn, closed.stream, .reset);
            },
            else => {},
        };
    }

    fn closeMatching(self: *Handler, engine: *engine_mod.Engine, conn: engine_mod.Handle, which: ?engine_mod.StreamHandle, failure: Failure) void {
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

    pub fn negotiationResult(self: *Handler, router: *const routing.Router, engine: *engine_mod.Engine, outcome: routing.Outcome, now: types.Now) void {
        if (outcome.direction == .outbound) {
            for (self.outbound) |*slot| if (std.meta.eql(slot.stream, outcome.stream) and slot.phase == .negotiating) {
                switch (outcome.result) {
                    .ready => |selected| {
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
        self.bind(engine);
        for (self.inbound) |*slot| if (slot.stream == null) {
            slot.* = .{ .stream = outcome.stream, .deadline = now.mono_ms +| deadline_ms, .ready = true };
            const bytes = self.local.?.encode(router.capabilities().receive, &slot.bytes) catch {
                engine.closeStream(outcome.stream, types.app_error_normal);
                slot.* = .{};
                return;
            };
            slot.outbox.queue(bytes, true);
            return;
        };
        engine.closeStream(outcome.stream, types.app_error_normal);
    }

    fn finish(slot: *Outbound, engine: *engine_mod.Engine, outcome: @FieldType(Result, "outcome")) void {
        const stream = slot.stream.?;
        engine.closeStream(stream, types.app_error_normal);
        slot.result = .{ .peer = slot.peer, .conn = stream.conn, .outcome = outcome };
        slot.phase = .terminal;
        slot.ready = false;
    }

    pub fn pump(self: *Handler, router: *routing.Router, engine: *engine_mod.Engine, now: types.Now, out: []Result) usize {
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
            if (done) {
                engine.closeStream(stream, types.app_error_normal);
                slot.* = .{};
            }
        };
        var count: usize = 0;
        for (self.outbound) |*slot| if (slot.stream) |stream| {
            if (slot.phase != .terminal and now.mono_ms >= slot.deadline) {
                router.cancel(engine, stream);
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
            }
        };
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

    pub fn shutdown(self: *Handler, router: *routing.Router, engine: *engine_mod.Engine) void {
        self.stopped = true;
        for (self.inbound) |*slot| if (slot.stream) |stream| {
            engine.closeStream(stream, types.app_error_normal);
            slot.* = .{};
        };
        for (self.outbound) |*slot| if (slot.stream) |stream| {
            if (slot.phase != .terminal) {
                router.cancel(engine, stream);
                finish(slot, engine, .{ .failed = .shutdown });
            }
        };
    }
};
