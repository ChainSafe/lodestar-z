const std = @import("std");
const constants = @import("constants.zig");
const schedule = @import("quic/schedule.zig");
const engine_mod = @import("quic/engine.zig");
const keys = @import("wire/keys.zig");
const multiaddr = @import("wire/multiaddr.zig");
const peer_id = @import("wire/peer_id.zig");
const tls = @import("tls/context.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const assert = std.debug.assert;

pub const Options = struct {
    host: *const keys.KeyPair,
    bind: udp_mod.Bindings,
    limits: engine_mod.Limits = .{},
    work_limits: WorkLimits = .{},
    keylog_path: ?[]const u8 = null,
};

pub const InitError = tls.Error || engine_mod.Error || std.Io.net.IpAddress.BindError ||
    std.Io.RandomSecureError || std.Io.File.OpenError || std.Io.File.StatError ||
    error{ClockOutOfRange};

pub const send_burst_max: u16 = 256;
pub const work_per_step_ceiling: u16 = 4096;

pub const WorkLimits = struct {
    send_per_step_max: u16 = send_burst_max,
    receive_per_step_max: u16 = constants.receive_batch_max,
    work_per_step_max: u16 = 1024,

    pub fn validate(self: WorkLimits) error{InvalidLimits}!void {
        if (self.send_per_step_max == 0 or self.send_per_step_max > send_burst_max) return error.InvalidLimits;
        if (self.receive_per_step_max == 0 or self.receive_per_step_max > constants.receive_batch_max) return error.InvalidLimits;
        if (self.work_per_step_max < 2 or self.work_per_step_max > work_per_step_ceiling) return error.InvalidLimits;
    }
};

pub const SendBatch = struct {
    buffers: [constants.send_batch_max][constants.datagram_size_max]u8 = undefined,
    sent: [constants.send_batch_max]types.Sent = undefined,
    owner: types.Handle = undefined,
};

/// Host-owned pacing storage and configured QUIC windows, excluding native overhead.
pub const MemoryPlan = struct {
    engine: engine_mod.MemoryPlan,
    scheduled_datagrams: u16,
    scheduled_payload_bytes: u64,
    scheduled_storage_bytes: u64,
    ready_batch_datagrams: u8 = constants.send_batch_max,
    ready_batch_storage_bytes: u64 = @sizeOf(SendBatch),
};

const IoError = udp_mod.ReceiveTimeoutError || udp_mod.SendError || error{
    ClockOutOfRange,
    DestinationUnreachable,
};

pub const StepError = IoError || error{KeylogWriteFailed};
pub const DialError = IoError || engine_mod.DialError || error{MissingPeerId};

pub const StepOptions = struct {
    wait_max_ms: u32 = constants.poll_interval_ms,
};

const Received = union(enum) {
    datagram: udp_mod.Datagram,
    dropped,
    timeout,
};

pub const StepResult = struct {
    now: engine_mod.Now,
    datagrams_received: u32 = 0,
    datagrams_accepted: u32 = 0,
    datagrams_dropped: u32 = 0,
    version_negotiations: u32 = 0,
    datagrams_sent: u32 = 0,
    send_calls: u32 = 0,
    receive_errors: u32 = 0,
    send_failures: u32 = 0,
    events: usize = 0,
    events_pending: bool = false,
    activity: usize = 0,
    activity_pending: bool = false,
    work_processed: u32 = 0,
    work_pending: bool = false,
    scheduled_datagrams: usize = 0,
};

pub const ProgressResult = struct {
    progress: StepResult,
    failure: ?StepError = null,
};

pub const Transport = struct {
    engine: engine_mod.Engine = undefined,
    udp: udp_mod.Udp = undefined,
    work_limits: WorkLimits = .{},
    pending: schedule.Queue = undefined,
    cursor: schedule.Cursor = .{},
    immediate_work: bool = false,
    idle_connections: usize = 0,
    scan_connections: usize = 0,
    batch: SendBatch = .{},
    batch_len: u8 = 0,
    output: [constants.datagram_size_max]u8 = undefined,
    receive_buffer: [constants.datagram_size_max]u8 = undefined,
    keylog: ?std.Io.File = null,
    keylog_offset: u64 = 0,

    /// The I/O provider must honor std.Io.randomSecure's external entropy contract.
    pub fn init(
        target: *Transport,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) InitError!void {
        try options.work_limits.validate();
        var serial: [8]u8 = undefined;
        try std.Io.randomSecure(io, &serial);
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed_bytes);
        try std.Io.randomSecure(io, &seed_bytes);
        const now = try currentTime(io);
        target.keylog = null;
        target.keylog_offset = 0;
        if (options.keylog_path) |path| {
            const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false, .permissions = @enumFromInt(0o600) });
            errdefer file.close(io);
            target.keylog_offset = (try file.stat(io)).size;
            target.keylog = file;
        }
        errdefer if (target.keylog) |file| file.close(io);
        var context = try tls.Context.init(options.host, now.unix_s, serial);
        var context_owned = true;
        errdefer if (context_owned) context.deinit();
        target.udp = try udp_mod.Udp.bind(io, options.bind);
        errdefer target.udp.close(io);
        var engine_limits = options.limits;
        engine_limits.keylog = options.keylog_path != null;
        target.engine = try engine_mod.Engine.init(allocator, .{
            .tls = context,
            .limits = engine_limits,
            .local = target.udp.localAddresses(),
            .seed = &seed_bytes,
        });
        context_owned = false;
        errdefer target.engine.deinit();
        target.pending = try schedule.Queue.init(allocator, options.limits.connections_max);
        target.work_limits = options.work_limits;
        target.cursor = .{};
        target.immediate_work = false;
        target.idle_connections = 0;
        target.scan_connections = 0;
        target.batch_len = 0;
        assert(target.engine.registry.slots.len == options.limits.connections_max);
        assert(target.keylog != null or options.keylog_path == null);
    }

    pub fn deinit(self: *Transport, io: std.Io) void {
        self.pending.deinit(self.engine.allocator);
        self.engine.deinit();
        self.udp.close(io);
        if (self.keylog) |file| file.close(io);
        self.* = undefined;
    }

    pub fn peerId(self: *const Transport) peer_id.PeerId {
        assert(self.engine.registry.slots.len > 0);
        return self.engine.tls.local_peer_id;
    }

    pub fn localAddress(self: *const Transport) types.Address {
        assert(self.engine.registry.slots.len > 0);
        return self.udp.localAddress();
    }

    pub fn localMultiaddr(self: *const Transport) multiaddr.Multiaddr {
        assert(self.engine.registry.slots.len > 0);
        return .{ .address = self.udp.localAddress(), .peer = self.engine.tls.local_peer_id };
    }

    pub fn memoryPlan(self: *const Transport) MemoryPlan {
        return .{
            .engine = self.engine.memoryPlan(),
            .scheduled_datagrams = @intCast(self.pending.entries.len),
            .scheduled_payload_bytes = self.pending.entries.len * constants.datagram_size_max,
            .scheduled_storage_bytes = self.pending.entries.len * @sizeOf(schedule.Entry),
        };
    }

    pub fn dial(
        self: *Transport,
        io: std.Io,
        target: *const multiaddr.Multiaddr,
    ) DialError!engine_mod.Handle {
        const expected = target.peer orelse return error.MissingPeerId;
        return self.dialPeer(io, target.address, expected);
    }

    pub fn nextTimeoutMs(self: *const Transport, now: engine_mod.Now) ?u64 {
        if (self.immediate_work) return 0;
        if (self.engine.hostWorkPending() or self.engine.activityPending()) return 0;
        var next = self.engine.nextTimeoutMs(now);
        if (self.pending.nextDeadline()) |deadline| {
            const remaining = schedule.remainingMs(deadline, now.nanos());
            next = @min(next orelse remaining, remaining);
        }
        return next;
    }

    pub fn dialPeer(
        self: *Transport,
        io: std.Io,
        peer: types.Address,
        expected: peer_id.PeerId,
    ) DialError!engine_mod.Handle {
        const now = try currentTime(io);
        const handle = self.engine.dial(&peer, expected, now) catch |err| switch (err) {
            error.AddressFamilyUnsupported => return error.DestinationUnreachable,
            else => return err,
        };
        errdefer {
            self.pending.remove(handle.index);
            _ = self.engine.abandon(handle);
        }
        var result = StepResult{ .now = now };
        errdefer _ = self.flush(io, &result);
        var turn = schedule.Turn.init(self.work_limits.send_per_step_max, self.work_limits.work_per_step_max);
        while (turn.canSend() and turn.takeWork()) {
            if (!try self.serviceConnection(io, handle.index, false, &turn, &result)) break;
            if (self.flush(io, &result)) |err| return err;
            if (self.pending.owner(handle.index) != null) break;
        }
        if (self.flush(io, &result)) |err| return err;
        self.immediate_work = !turn.canSend() or turn.work == turn.work_max;
        return handle;
    }

    /// Publishes completed work on failure, after pending sends unwind.
    /// A failure to read the initial clock leaves the turn and pending events untouched.
    pub fn step(
        self: *Transport,
        io: std.Io,
        events: []engine_mod.Event,
        activity: []engine_mod.Handle,
        options: StepOptions,
    ) ProgressResult {
        var result = StepResult{ .now = currentTime(io) catch |err| return .{
            .progress = .{ .now = .{ .mono_ms = 0, .unix_s = 0 } },
            .failure = err,
        } };
        const failure: ?StepError = if (self.run(io, &result, options)) |_| null else |err| err;
        self.publish(events, activity, &result);
        if (failure) |err| return .{ .progress = result, .failure = err };
        self.drainKeylog(io) catch |err| return .{ .progress = result, .failure = err };
        return .{ .progress = result };
    }

    fn run(
        self: *Transport,
        io: std.Io,
        result: *StepResult,
        options: StepOptions,
    ) IoError!void {
        assert(self.batch_len == 0);
        errdefer {
            _ = self.flush(io, result);
            self.immediate_work = true;
        }
        self.engine.releaseReported();
        const active_count = self.engine.activeIndices().len;
        const host_work = self.engine.takeHostWork();
        if (host_work or self.idle_connections >= active_count) self.idle_connections = 0;
        for (self.pending.entries, 0..) |*entry, index| {
            if (entry.handle) |owner| {
                const current = self.engine.sendOwner(owner.index);
                if (current == null or !std.meta.eql(current.?, owner)) self.pending.remove(@intCast(index));
            }
        }
        self.immediate_work = false;
        var turn = schedule.Turn.init(self.work_limits.send_per_step_max, self.work_limits.work_per_step_max);
        defer result.work_processed = turn.work;
        var visits: u32 = 0;
        try self.service(io, &turn, result, &visits, turn.work_max / 2);
        _ = self.flush(io, result);
        var received_count: u32 = 0;
        while (received_count < self.work_limits.receive_per_step_max and turn.work < turn.work_max) : (received_count += 1) {
            result.now = try currentTime(io);
            const wait_ms: ?u32 = if (received_count == 0) options.wait_max_ms else null;
            const received = try self.receiveDatagram(io, result, wait_ms);
            if (received == .timeout) break;
            assert(turn.takeWork());
            const admitted = switch (received) {
                .timeout => unreachable,
                .dropped => continue,
                .datagram => |datagram| datagram,
            };
            result.datagrams_received += 1;
            result.now = try currentTime(io);
            const outcome = self.engine.receive(admitted.bytes, &admitted.from, result.now, &self.output);
            switch (outcome) {
                .accepted => {
                    result.datagrams_accepted += 1;
                    self.idle_connections = 0;
                },
                .version_negotiation, .retry => |bytes| {
                    if (turn.canSend()) {
                        turn.recordSend();
                        self.udp.send(io, &admitted.from, bytes) catch {};
                        if (outcome == .version_negotiation) result.version_negotiations += 1;
                    }
                },
                .dropped => result.datagrams_dropped += 1,
            }
        }
        const receive_work_exhausted = turn.work == turn.work_max;
        result.now = try currentTime(io);
        try self.service(io, &turn, result, &visits, turn.work_max);
        _ = self.flush(io, result);
        if (receive_work_exhausted or received_count == self.work_limits.receive_per_step_max) {
            self.immediate_work = true;
        }
        assert(turn.work <= self.work_limits.work_per_step_max);
        assert(turn.sent <= self.work_limits.send_per_step_max);
    }

    fn publish(self: *Transport, events: []engine_mod.Event, activity: []engine_mod.Handle, result: *StepResult) void {
        result.events = self.engine.pollEvents(events);
        result.events_pending = self.engine.eventsPending();
        result.activity = self.engine.takeActivity(activity);
        result.activity_pending = self.engine.activityPending();
        result.work_pending = self.immediate_work;
        result.scheduled_datagrams = self.pending.count;
        assert(result.events <= events.len);
        assert(result.activity <= activity.len);
    }

    fn service(
        self: *Transport,
        io: std.Io,
        turn: *schedule.Turn,
        result: *StepResult,
        visits: *u32,
        work_stop: u32,
    ) IoError!void {
        const active = self.engine.activeIndices();
        if (active.len == 0) return;
        if (self.scan_connections != active.len) {
            self.scan_connections = active.len;
            self.idle_connections = 0;
        }
        while (turn.canSend() and turn.work < work_stop and self.idle_connections < active.len) {
            assert(turn.takeWork());
            const index = self.cursor.next(active).?;
            const progressed = try self.serviceConnection(io, index, visits.* < active.len, turn, result);
            visits.* += 1;
            self.idle_connections = if (progressed) 0 else self.idle_connections + 1;
        }
        if (self.idle_connections < active.len and (!turn.canSend() or turn.work == work_stop)) self.immediate_work = true;
        if (self.idle_connections == active.len) self.immediate_work = false;
    }

    fn serviceConnection(
        self: *Transport,
        io: std.Io,
        index: u16,
        tick: bool,
        turn: *schedule.Turn,
        result: *StepResult,
    ) IoError!bool {
        if (tick) self.engine.tickOne(index, result.now);
        const owner = self.engine.sendOwner(index) orelse {
            self.pending.remove(index);
            return false;
        };
        if (self.pending.owner(index)) |stored| {
            if (!std.meta.eql(stored, owner)) self.pending.remove(index);
        }
        var generated = false;
        if (self.pending.owner(index) == null) {
            const sent = self.engine.sendOne(index, result.now, &self.output) orelse return false;
            self.pending.put(owner, sent) catch unreachable;
            generated = true;
            result.now = try currentTime(io);
        }
        const ready = self.pending.ready(index, result.now.nanos()) orelse return generated;
        assert(turn.canSend());
        // The socket reports only batch-level failure, so a batch must have one owner.
        if (self.batch_len > 0 and !std.meta.eql(self.batch.owner, owner)) {
            _ = self.flush(io, result);
        }
        const at = self.batch_len;
        @memcpy(self.batch.buffers[at][0..ready.bytes.len], ready.bytes);
        self.batch.sent[at] = ready;
        self.batch.sent[at].bytes = self.batch.buffers[at][0..ready.bytes.len];
        self.batch.owner = owner;
        self.batch_len += 1;
        self.pending.remove(index);
        turn.recordSend();
        if (self.batch_len == constants.send_batch_max) _ = self.flush(io, result);
        return true;
    }

    fn flush(self: *Transport, io: std.Io, result: *StepResult) ?IoError {
        const count = self.batch_len;
        if (count == 0) return null;
        defer self.batch_len = 0;
        const owner = self.batch.owner;
        result.send_calls += 1;
        self.udp.sendMany(io, self.batch.sent[0..count]) catch |err| {
            if (self.engine.sendOwner(owner.index)) |current| {
                if (std.meta.eql(current, owner)) {
                    self.engine.failSend(owner.index);
                    self.pending.remove(owner.index);
                    result.send_failures += 1;
                }
            }
            return mapSendError(err);
        };
        result.datagrams_sent += count;
        return null;
    }

    fn receiveDatagram(
        self: *Transport,
        io: std.Io,
        result: *StepResult,
        wait_ms: ?u32,
    ) IoError!Received {
        const earliest = if ((wait_ms orelse 0) > 0) self.nextTimeoutMs(result.now) else null;
        const timeout = receiveTimeout(wait_ms, earliest);
        const datagram = self.udp.receiveTimeout(io, &self.receive_buffer, timeout) catch |err| switch (err) {
            error.Timeout => return .timeout,
            error.DatagramTooLarge,
            error.PortUnreachable,
            error.ConnectionResetByPeer,
            error.NetworkDown,
            error.SystemResources,
            => {
                result.receive_errors += 1;
                return .dropped;
            },
            else => return err,
        };
        return .{ .datagram = datagram };
    }

    fn drainKeylog(self: *Transport, io: std.Io) error{KeylogWriteFailed}!void {
        const file = self.keylog orelse return;
        var lines: [tls.keylog_capacity]u8 = undefined;
        for (self.engine.activeIndices()) |index| {
            const length = self.engine.takeKeylog(index, &lines);
            if (length == 0) continue;
            file.writePositionalAll(io, lines[0..length], self.keylog_offset) catch {
                file.close(io);
                self.keylog = null;
                return error.KeylogWriteFailed;
            };
            self.keylog_offset += length;
        }
    }
};

fn receiveTimeout(wait_ms: ?u32, earliest_ms: ?u64) std.Io.Timeout {
    return if (wait_ms) |bound| blk: {
        var wait: u64 = bound;
        if (earliest_ms) |earliest| wait = @min(wait, earliest);
        break :blk .{ .duration = .{
            .raw = .fromMilliseconds(@intCast(wait)),
            .clock = .awake,
        } };
    } else .{ .duration = .{ .raw = .zero, .clock = .awake } };
}

fn mapSendError(err: udp_mod.SendError) IoError {
    return switch (err) {
        error.AccessDenied,
        error.AddressFamilyUnsupported,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        => error.DestinationUnreachable,
        else => err,
    };
}

pub fn currentTime(io: std.Io) error{ClockOutOfRange}!engine_mod.Now {
    const mono = std.Io.Clock.awake.now(io).nanoseconds;
    const wall = std.Io.Clock.real.now(io).toSeconds();
    if (mono < 0 or mono > std.math.maxInt(u64) or wall < 0) return error.ClockOutOfRange;
    return .{ .mono_ms = @intCast(@divTrunc(mono, std.time.ns_per_ms)), .mono_ns = @intCast(mono), .unix_s = wall };
}

comptime {
    assert(@sizeOf(Transport) <= 32 * 1_024);
    assert(send_burst_max % constants.send_batch_max == 0);
}

test "transport zero wait remains an actual nonblocking timeout" {
    const timeout = receiveTimeout(0, null);
    try std.testing.expectEqual(@as(i96, 0), timeout.duration.raw.nanoseconds);
    try std.testing.expectEqual(@as(i96, 0), receiveTimeout(5, 0).duration.raw.nanoseconds);
}

test {
    _ = @import("transport_io_test.zig");
    _ = @import("transport_test.zig");
}
