const std = @import("std");
const constants = @import("constants.zig");
const engine_mod = @import("quic/engine.zig");
const schedule = @import("quic/schedule.zig");
const limits = @import("quic/limits.zig");
const peer_id = @import("wire/peer_id.zig");
const types = @import("types.zig");
const udp_mod = @import("udp.zig");

const assert = std.debug.assert;
const Engine = engine_mod.Engine;
const Udp = udp_mod.Udp;

pub const StepError = udp_mod.ReceiveTimeoutError || udp_mod.SendError ||
    std.Io.RandomSecureError || error{
    ClockOutOfRange,
    DestinationUnreachable,
};

pub const DialError = StepError || engine_mod.DialError;

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

pub const Driver = struct {
    pool: engine_mod.EntropyPool = .{},
    pending: schedule.Queue = undefined,
    cursor: schedule.Cursor = .{},
    immediate_work: bool = false,
    idle_connections: usize = 0,
    scan_connections: usize = 0,
    batch: engine_mod.SendBatch = .{},
    batch_len: u8 = 0,
    output: [constants.datagram_size_max]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, connections: u16) std.mem.Allocator.Error!Driver {
        return .{ .pending = try schedule.Queue.init(allocator, connections) };
    }

    pub fn deinit(self: *Driver, allocator: std.mem.Allocator) void {
        self.pending.deinit(allocator);
        self.* = undefined;
    }

    pub fn nextTimeoutMs(self: *const Driver, engine: *Engine, now: engine_mod.Now) ?u64 {
        if (self.immediate_work) return 0;
        const view = engine.driverView();
        if (view.hostWorkPending() or view.activityPending()) return 0;
        var next = view.nextTimeoutMs(now);
        if (self.pending.nextDeadline()) |deadline| {
            const remaining = schedule.remainingMs(deadline, now.nanos());
            next = @min(next orelse remaining, remaining);
        }
        return next;
    }

    pub fn dial(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        peer: types.Address,
        expected: peer_id.PeerId,
    ) DialError!engine_mod.Handle {
        const now = try currentTime(io);
        const handle = try engine.dial(&peer, expected, now, try entropy(io));
        errdefer {
            self.pending.remove(handle.index);
            _ = engine.abandon(handle);
        }
        var result = StepResult{ .now = now };
        errdefer _ = self.flush(io, engine, udp, &result);
        var turn = schedule.Turn.init(engine.limits.send_per_step_max, engine.limits.work_per_step_max);
        while (turn.canSend() and turn.takeWork()) {
            if (!try self.serviceConnection(io, engine, udp, handle.index, false, &turn, &result)) break;
            if (self.flush(io, engine, udp, &result)) |err| return err;
            if (self.pending.owner(handle.index) != null) break;
        }
        if (self.flush(io, engine, udp, &result)) |err| return err;
        self.immediate_work = !turn.canSend() or turn.work == turn.work_max;
        return handle;
    }

    pub fn step(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        events: []engine_mod.Event,
        activity: []engine_mod.Handle,
        options: StepOptions,
    ) StepError!StepResult {
        var result = StepResult{ .now = try currentTime(io) };
        try self.run(io, engine, udp, &result, options);
        self.publish(engine, events, activity, &result);
        return result;
    }

    /// Publishes completed work on failure, after receive leases and sends unwind.
    /// A failure to read the initial clock leaves the turn and pending events untouched.
    pub fn stepProgress(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        events: []engine_mod.Event,
        activity: []engine_mod.Handle,
        options: StepOptions,
    ) ProgressResult {
        var result = StepResult{ .now = currentTime(io) catch |err| return .{
            .progress = .{ .now = .{ .mono_ms = 0, .unix_s = 0 } },
            .failure = err,
        } };
        const failure: ?StepError = if (self.run(io, engine, udp, &result, options)) |_| null else |err| err;
        self.publish(engine, events, activity, &result);
        return .{ .progress = result, .failure = failure };
    }

    fn run(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        result: *StepResult,
        options: StepOptions,
    ) StepError!void {
        assert(self.batch_len == 0);
        errdefer {
            _ = self.flush(io, engine, udp, result);
            self.immediate_work = true;
        }
        const view = engine.driverView();
        view.releaseReported();
        const active_count = view.activeIndices().len;
        const host_work = view.takeHostWork();
        if (host_work or self.scan_connections != active_count or self.idle_connections >= active_count) {
            self.idle_connections = 0;
        }
        self.scan_connections = active_count;
        for (self.pending.entries, 0..) |*entry, index| {
            if (entry.handle) |owner| {
                const current = view.sendOwner(owner.index);
                if (current == null or !std.meta.eql(current.?, owner)) self.pending.remove(@intCast(index));
            }
        }
        self.immediate_work = false;
        var turn = schedule.Turn.init(engine.limits.send_per_step_max, engine.limits.work_per_step_max);
        defer result.work_processed = turn.work;
        var visits: u32 = 0;
        try self.service(io, engine, udp, &turn, result, &visits, turn.work_max / 2);
        _ = self.flush(io, engine, udp, result);
        var received_count: u32 = 0;
        while (received_count < engine.limits.receive_per_step_max and turn.work < turn.work_max) : (received_count += 1) {
            if (!self.pool.fresh) self.pool.fill(try entropy(io));
            result.now = try currentTime(io);
            const wait_ms: ?u32 = if (received_count == 0) options.wait_max_ms else null;
            const received = try self.receiveDatagram(io, engine, udp, result, wait_ms);
            if (received == .timeout) break;
            assert(turn.takeWork());
            const admitted = switch (received) {
                .timeout => unreachable,
                .dropped => continue,
                .datagram => |datagram| datagram,
            };
            defer udp.release(admitted.handle) catch unreachable;
            result.datagrams_received += 1;
            result.now = try currentTime(io);
            switch (view.receive(admitted.bytes, &admitted.from, result.now, &self.pool, &self.output)) {
                .accepted => {
                    result.datagrams_accepted += 1;
                    self.idle_connections = 0;
                },
                .version_negotiation => |bytes| {
                    if (turn.canSend()) {
                        turn.recordSend();
                        send(io, udp, &admitted.from, bytes) catch {};
                        result.version_negotiations += 1;
                    }
                },
                .dropped => result.datagrams_dropped += 1,
            }
        }
        const receive_work_exhausted = turn.work == turn.work_max;
        result.now = try currentTime(io);
        try self.service(io, engine, udp, &turn, result, &visits, turn.work_max);
        _ = self.flush(io, engine, udp, result);
        if (receive_work_exhausted or received_count == engine.limits.receive_per_step_max) {
            self.immediate_work = true;
        }
        assert(turn.work <= engine.limits.work_per_step_max);
        assert(turn.sent <= engine.limits.send_per_step_max);
    }

    fn publish(self: *Driver, engine: *Engine, events: []engine_mod.Event, activity: []engine_mod.Handle, result: *StepResult) void {
        result.events = engine.pollEvents(events);
        result.events_pending = engine.eventsPending();
        result.activity = engine.driverView().takeActivity(activity);
        result.activity_pending = engine.driverView().activityPending();
        result.work_pending = self.immediate_work;
        result.scheduled_datagrams = self.pending.count;
        assert(result.events <= events.len);
        assert(result.activity <= activity.len);
    }

    fn service(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        turn: *schedule.Turn,
        result: *StepResult,
        visits: *u32,
        work_stop: u32,
    ) StepError!void {
        const active = engine.driverView().activeIndices();
        if (active.len == 0) return;
        if (self.scan_connections != active.len) {
            self.scan_connections = active.len;
            self.idle_connections = 0;
        }
        while (turn.canSend() and turn.work < work_stop and self.idle_connections < active.len) {
            assert(turn.takeWork());
            const index = self.cursor.next(active).?;
            const progressed = try self.serviceConnection(io, engine, udp, index, visits.* < active.len, turn, result);
            visits.* += 1;
            self.idle_connections = if (progressed) 0 else self.idle_connections + 1;
        }
        if (self.idle_connections < active.len and (!turn.canSend() or turn.work == work_stop)) self.immediate_work = true;
        if (self.idle_connections == active.len) self.immediate_work = false;
    }

    fn serviceConnection(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        index: u16,
        tick: bool,
        turn: *schedule.Turn,
        result: *StepResult,
    ) StepError!bool {
        const view = engine.driverView();
        if (tick) view.tickOne(index, result.now);
        const owner = view.sendOwner(index) orelse {
            self.pending.remove(index);
            return false;
        };
        if (self.pending.owner(index)) |stored| {
            if (!std.meta.eql(stored, owner)) self.pending.remove(index);
        }
        var generated = false;
        if (self.pending.owner(index) == null) {
            const sent = view.sendOne(index, result.now, &self.output) orelse return false;
            self.pending.put(owner, sent) catch unreachable;
            generated = true;
            result.now = try currentTime(io);
        }
        const ready = self.pending.ready(index, result.now.nanos()) orelse return generated;
        assert(turn.canSend());
        // The socket reports only batch-level failure, so a batch must have one owner.
        if (self.batch_len > 0 and !std.meta.eql(self.batch.owners[0], owner)) {
            _ = self.flush(io, engine, udp, result);
        }
        const at = self.batch_len;
        @memcpy(self.batch.buffers[at][0..ready.bytes.len], ready.bytes);
        self.batch.sent[at] = ready;
        self.batch.sent[at].bytes = self.batch.buffers[at][0..ready.bytes.len];
        self.batch.owners[at] = owner;
        self.batch_len += 1;
        self.pending.remove(index);
        turn.recordSend();
        if (self.batch_len == constants.send_batch_max) _ = self.flush(io, engine, udp, result);
        return true;
    }

    fn flush(self: *Driver, io: std.Io, engine: *Engine, udp: *Udp, result: *StepResult) ?StepError {
        const count = self.batch_len;
        if (count == 0) return null;
        defer self.batch_len = 0;
        const owner = self.batch.owners[0];
        for (self.batch.owners[1..count]) |other| assert(std.meta.eql(owner, other));
        result.send_calls += 1;
        sendMany(io, udp, self.batch.sent[0..count]) catch |err| {
            if (engine.driverView().sendOwner(owner.index)) |current| {
                if (std.meta.eql(current, owner)) {
                    engine.driverView().failSend(owner.index);
                    self.pending.remove(owner.index);
                    result.send_failures += 1;
                }
            }
            return err;
        };
        result.datagrams_sent += count;
        return null;
    }

    fn receiveDatagram(
        self: *Driver,
        io: std.Io,
        engine: *Engine,
        udp: *Udp,
        result: *StepResult,
        wait_ms: ?u32,
    ) StepError!Received {
        const timeout = receiveTimeout(wait_ms, self.nextTimeoutMs(engine, result.now));
        const datagram = udp.receiveTimeout(io, timeout) catch |err| switch (err) {
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

fn sendMany(io: std.Io, udp: *const Udp, batch: []const types.Sent) StepError!void {
    return udp.sendMany(io, batch) catch |err| mapSendError(err);
}

fn send(
    io: std.Io,
    udp: *const Udp,
    destination: *const types.Address,
    bytes: []const u8,
) StepError!void {
    return udp.send(io, destination, bytes) catch |err| mapSendError(err);
}

fn mapSendError(err: udp_mod.SendError) StepError {
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

fn entropy(io: std.Io) std.Io.RandomSecureError![limits.local_cid_length]u8 {
    var bytes: [limits.local_cid_length]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    return bytes;
}

comptime {
    assert(@sizeOf(Driver) <= 32 * 1_024);
}

test "driver zero wait remains an actual nonblocking timeout" {
    const timeout = receiveTimeout(0, null);
    try std.testing.expectEqual(@as(i96, 0), timeout.duration.raw.nanoseconds);
    try std.testing.expectEqual(@as(i96, 0), receiveTimeout(5, 0).duration.raw.nanoseconds);
}
