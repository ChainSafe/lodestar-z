const std = @import("std");
const n = @import("network");
const d = @import("discv5");
const napi = @import("zapi:zapi").napi;
const faults = @import("network_faults.zig");
const Config = @import("network_config.zig").Config;
const Wake = @import("network_wake.zig").Wake;
pub const allocator = std.heap.c_allocator;
pub const State = enum { starting, running, stopping, closed, failed };
pub const Reason = enum { requested, startupCancelled, failed };
pub const Notify = napi.ThreadSafeFunction(Runtime, void);
var instances = std.atomic.Value(u32).init(0);
var sessions: u64 = 0;
var session_mutex: std.Io.Mutex = .init;

pub fn reserve() !u64 {
    const old = instances.fetchAdd(1, .acq_rel);
    if (old >= 4) {
        _ = instances.fetchSub(1, .acq_rel);
        return error.NetworkInstanceLimit;
    }
    errdefer unreserve();
    std.Io.Threaded.mutexLock(&session_mutex);
    defer std.Io.Threaded.mutexUnlock(&session_mutex);
    if (sessions == std.math.maxInt(u64)) return error.ClockRevisionExhausted;
    sessions += 1;
    return sessions;
}
pub fn unreserve() void {
    std.debug.assert(instances.fetchSub(1, .acq_rel) > 0);
}

pub const Observation = union(enum) {
    peerReady: Peer,
    peerUpdated: Peer,
    peerClosed: struct { peer: Peer, reason: n.peers.DisconnectReason },
    operationalError: struct { code: anyerror, count: u64 },
    pub const Peer = struct { index: u16, generation: u64, identity: n.PeerId };
};
comptime {
    std.debug.assert(@sizeOf(Observation) <= 256);
}

pub const Queue = struct {
    entries: [64]Observation = undefined,
    head: u8 = 0,
    len: u8 = 0,
    high_water: u8 = 0,
    dropped: u64 = 0,
    pending_error: ?struct { code: anyerror, count: u64 } = null,
    error_queued: bool = false,

    pub fn push(self: *Queue, event: Observation) bool {
        if (self.len == self.entries.len) {
            self.dropped +|= 1;
            return false;
        }
        self.entries[(@as(usize, self.head) + self.len) % self.entries.len] = event;
        self.len += 1;
        if (event == .operationalError) self.error_queued = true;
        self.high_water = @max(self.high_water, self.len);
        return true;
    }
    pub fn recordFailure(self: *Queue, code: anyerror) void {
        if (self.pending_error) |*pending| pending.count +|= 1 else self.pending_error = .{ .code = code, .count = 1 };
        self.flushError();
    }
    fn flushError(self: *Queue) void {
        if (self.error_queued or self.len == 64) return;
        if (self.pending_error) |pending| {
            _ = self.push(.{ .operationalError = .{ .code = pending.code, .count = pending.count } });
            self.pending_error = null;
        }
    }
    pub fn peek(self: *const Queue, out: []Observation) usize {
        const count = @min(out.len, self.len);
        for (0..count) |i| out[i] = self.entries[(@as(usize, self.head) + i) % self.entries.len];
        return count;
    }
    pub fn commit(self: *Queue, count: usize) void {
        std.debug.assert(count <= self.len);
        for (0..count) |i| {
            if (self.entries[(@as(usize, self.head) + i) % self.entries.len] == .operationalError) self.error_queued = false;
        }
        self.head = @intCast((@as(usize, self.head) + count) % self.entries.len);
        self.len -= @intCast(count);
        self.flushError();
    }
};

pub const Identity = struct {
    peer: n.PeerId,
    endpoint: n.Address,
    multiaddr: [n.wire.multiaddr.binary_length_max]u8,
    multiaddr_len: u8,
    enr: [d.wire.constants.enr_size_max]u8,
    enr_len: u16,
};
pub const Diagnostics = struct {
    state: State = .starting,
    terminal_error: ?anyerror = null,
    session: u64,
    currentSlot: u64,
    clockRevision: u64 = 0,
    ownerTurns: u64 = 0,
    lastMonotonicMs: u64 = 0,
    peerCount: u16 = 0,
    readyPeerCount: u16 = 0,
    queuedEvents: u8 = 0,
    queueCapacity: u8 = 64,
    queueHighWater: u8 = 0,
    observationsDropped: u64 = 0,
    operationalFailures: u64 = 0,
    nativeRequestedBytes: usize = 0,
    bridgeRequestedBytes: usize = @sizeOf(Runtime) - @sizeOf(n.NetworkCore),
};

pub const Runtime = struct {
    test_scenario: if (faults.enabled) faults.Scenario else void = if (faults.enabled) .none else {},
    test_drain_publication: if (faults.enabled) faults.DrainPublication else void = if (faults.enabled) .idle else {},
    refs: std.atomic.Value(u32) = .init(1),
    mutex: std.Io.Mutex = .init,
    config: Config = undefined,
    core: n.NetworkCore = undefined,
    threaded: std.Io.Threaded = undefined,
    key: n.KeyPair = undefined,
    records: [d.Maintenance.bootstrap_max]d.identity.enr.Record = undefined,
    outputs: [32]n.peers.Event = undefined,
    wake: ?Wake = null,
    thread: ?std.Thread = null,
    notify: Notify = undefined,
    notify_live: bool = true,
    notification_pending: bool = false,
    observation_rearm: bool = false,
    env_alive: bool = true,
    disposed: bool = false,
    ready_deferred: ?napi.Deferred = null,
    close_deferred: ?napi.Deferred = null,
    ready_settled: bool = false,
    close_settled: bool = false,
    copy_error: ?napi.Ref = null,
    close_results: [3]?napi.Ref = @splat(null),
    hook_live: bool = false,
    env: napi.Env,
    stop: bool = false,
    reason: Reason = .requested,
    quiescent: bool = false,
    startup: enum { pending, ready, failed } = .pending,
    startup_error: ?anyerror = null,
    identity: Identity = undefined,
    slot: u64 = 0,
    revision: u64 = 0,
    queue: Queue = .{},
    diag: Diagnostics,

    pub fn lock(self: *Runtime) void {
        std.Io.Threaded.mutexLock(&self.mutex);
    }
    pub fn unlock(self: *Runtime) void {
        std.Io.Threaded.mutexUnlock(&self.mutex);
    }
    pub fn retain(self: *Runtime) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Runtime) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) {
            self.config.wipe();
            faults.count(&faults.runtimes, false);
            std.crypto.secureZero(u8, std.mem.asBytes(self));
            allocator.destroy(self);
        }
    }
    pub fn requestStop(self: *Runtime) void {
        self.lock();
        defer self.unlock();
        if (self.stop or self.quiescent) return;
        self.stop = true;
        self.reason = if (self.startup == .pending) .startupCancelled else .requested;
        self.diag.state = .stopping;
        self.signalLocked();
    }
    fn signalLocked(self: *Runtime) void {
        if (self.wake) |*wake| signal(wake) catch {
            self.stop = true;
            self.reason = .failed;
            self.startup_error = error.NetworkWakeFailed;
        };
    }
    fn signal(wake: *const Wake) !void {
        try faults.check(.wake_signal);
        try wake.signal();
    }
    pub fn setSlot(self: *Runtime, slot: u64) !u64 {
        self.lock();
        defer self.unlock();
        if (self.stop or self.quiescent) return error.NetworkClosed;
        if (slot < self.slot) return error.ClockRegression;
        if (self.revision == std.math.maxInt(u64)) return error.ClockRevisionExhausted;
        self.slot = slot;
        self.revision += 1;
        self.signalLocked();
        return self.revision;
    }
    pub fn snapshot(self: *Runtime) Diagnostics {
        self.lock();
        defer self.unlock();
        var result = self.diag;
        result.terminal_error = if (self.reason == .failed) self.startup_error else null;
        result.queuedEvents = self.queue.len;
        result.queueHighWater = self.queue.high_water;
        result.observationsDropped = self.queue.dropped;
        return result;
    }
    pub fn commitDrain(self: *Runtime, count: usize, reported_more: bool) void {
        self.lock();
        defer self.unlock();
        self.queue.commit(count);
        if (!reported_more and self.queue.len > 0 and !self.stop and !self.quiescent and !self.observation_rearm) {
            // The owner holds the only TSFN participant, including this stale-snapshot rearm.
            self.observation_rearm = true;
            self.signalLocked();
        }
    }
    fn pingLocked(self: *Runtime) void {
        if (self.notification_pending or !self.notify_live or !self.env_alive) return;
        self.notification_pending = true;
        self.notify.call(undefined, .non_blocking) catch |err| switch (err) {
            error.QueueFull => {},
            error.Closing => {
                self.notify_live = false;
                self.stop = true;
            },
            else => {
                self.notification_pending = false;
                self.stop = true;
                self.reason = .failed;
                self.startup_error = err;
            },
        };
    }
    pub fn join(self: *Runtime) void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
            unreserve();
        }
    }
    pub fn removeHook(self: *Runtime) void {
        if (!self.hook_live) return;
        self.env.removeEnvCleanupHook(Runtime, self, cleanup) catch unreachable;
        self.hook_live = false;
        self.release();
    }
    pub fn failDelivery(self: *Runtime) void {
        self.lock();
        defer self.unlock();
        self.stop = true;
        self.reason = .failed;
        self.startup_error = error.NetworkResultAllocationFailed;
        if (self.quiescent) self.diag.state = .failed;
        self.signalLocked();
    }
    pub fn forceStop(self: *Runtime, env_dying: bool) void {
        self.lock();
        self.disposed = true;
        if (env_dying) self.env_alive = false;
        self.unlock();
        self.requestStop();
        self.join();
    }
    pub fn disposeJsReferences(self: *Runtime) void {
        if (self.copy_error) |ref| ref.delete() catch unreachable;
        self.copy_error = null;
        for (&self.close_results) |*entry| {
            if (entry.*) |ref| ref.delete() catch unreachable;
            entry.* = null;
        }
    }
    pub fn cleanup(self: *Runtime) void {
        self.hook_live = false;
        self.forceStop(true);
        self.disposeJsReferences();
        self.release();
    }
    pub fn finalize(_: napi.Env, self: *Runtime) void {
        self.disposeJsReferences();
        faults.count(&faults.notifications, false);
        self.release();
    }

    fn now(io: std.Io) n.Now {
        const mono = std.Io.Timestamp.now(io, .awake);
        return .{ .mono_ms = @intCast(@max(0, mono.toMilliseconds())), .unix_s = std.Io.Timestamp.now(io, .real).toSeconds() };
    }
    fn cancelled(self: *Runtime) bool {
        self.lock();
        defer self.unlock();
        return self.stop;
    }
    pub fn run(self: *Runtime) void {
        self.serve() catch |err| {
            self.lock();
            if (self.reason != .failed) {
                self.startup_error = err;
                self.reason = if (err == error.AbortError) .startupCancelled else .failed;
            }
            self.unlock();
        };
        self.lock();
        if (self.startup == .pending) {
            self.startup = .failed;
            self.startup_error = self.startup_error orelse error.AbortError;
        }
        if (self.wake) |*wake| wake.deinit();
        self.wake = null;
        self.quiescent = true;
        self.diag.state = if (self.reason == .failed) .failed else .closed;
        self.pingLocked();
        const release_notify = self.notify_live;
        self.notify_live = false;
        self.unlock();
        if (release_notify) self.notify.release(.release) catch unreachable;
        faults.count(&faults.owners, false);
        self.release();
    }
    fn serve(self: *Runtime) !void {
        defer self.config.wipe();
        try self.startupBarrier(.entry);
        if (self.cancelled()) return error.AbortError;
        self.threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing, .concurrent_limit = .nothing });
        defer self.threaded.deinit();
        const io = self.threaded.io();
        var seed: u64 = undefined;
        try faults.check(.entropy);
        try io.randomSecure(std.mem.asBytes(&seed));
        try faults.check(.key);
        self.key = try n.KeyPair.fromSecretKey(&self.config.secret);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&self.key));
        self.config.wipe();
        try self.startupBarrier(.key_ready);
        if (self.cancelled()) return error.AbortError;
        for (0..self.config.bootstrap_count) |i| {
            try faults.check(.enr);
            self.records[i] = try d.identity.enr.Record.init(self.config.bootstrap[i].bytes[0..self.config.bootstrap[i].len]);
            if (self.cancelled()) return error.AbortError;
        }
        var gossip = self.config.gossip;
        gossip.random_seed = seed;
        gossip.ip_allowlist = self.config.allowlist[0..self.config.allowlist_count];
        gossip.topic_policy = if (self.config.topic_boundary_count == 0) null else self.config.topic_boundaries[0..self.config.topic_boundary_count];
        try faults.check(.core);
        try self.core.initManaged(allocator, io, .{
            .wait_mode = .native_poll,
            .host = &self.key,
            .bind = self.config.bind,
            .configuration = .{ .profile = self.config.profile, .seed = seed, .forks = self.config.forks[0..self.config.fork_count], .gossip = gossip },
            .local = self.config.local,
            .schedule = self.config.schedule,
            .discovery = if (self.config.discovery_bind) |bind| .{ .bind = bind, .sequence = self.config.discovery_sequence, .advertisement = self.config.advertisement, .bootstrap = self.records[0..self.config.bootstrap_count] } else null,
        });
        defer {
            self.core.shutdown(now(io));
            self.core.deinit(io);
            std.crypto.secureZero(u8, std.mem.asBytes(&self.core));
        }
        try faults.check(.wake_attach);
        try self.core.setHostWake(self.wake.?.read_fd);
        defer self.core.setHostWake(null) catch {};
        if (comptime faults.enabled) {
            if (self.test_scenario == .gossip) faults.captureGossip(&self.core.core.service.gossipsub.inner);
        }
        var identity: Identity = undefined;
        identity.peer = self.core.peerId();
        identity.endpoint = self.core.localAddress();
        const multiaddr = self.core.localMultiaddr();
        identity.multiaddr_len = @intCast((try multiaddr.encode(&identity.multiaddr)).len);
        identity.enr_len = 0;
        if (self.core.localRecord()) |record| {
            identity.enr_len = @intCast(record.slice().len);
            @memcpy(identity.enr[0..identity.enr_len], record.slice());
        }
        try self.startupBarrier(.before_ready);
        self.lock();
        if (self.stop) {
            self.unlock();
            return error.AbortError;
        }
        self.identity = identity;
        if (comptime faults.enabled) {
            if (self.test_scenario == .observations) {
                for (0..67) |i| _ = self.queue.push(.{ .peerReady = .{ .index = @intCast(i), .generation = std.math.maxInt(u64) - i, .identity = identity.peer } });
                self.queue.recordFailure(error.InjectedNetworkFailure);
                self.queue.recordFailure(error.InjectedNetworkFailure);
            } else if (self.test_scenario == .drain_publish) {
                _ = self.queue.push(.{ .peerReady = .{ .index = 0, .generation = 1, .identity = identity.peer } });
            }
        }
        self.startup = .ready;
        self.diag.state = .running;
        const plan = self.core.memoryPlan();
        self.diag.nativeRequestedBytes = plan.inline_bytes + plan.allocated_bytes;
        self.pingLocked();
        self.unlock();
        while (true) {
            self.lock();
            if (self.stop) {
                self.unlock();
                break;
            }
            self.wake.?.drain() catch {
                self.stop = true;
                self.reason = .failed;
                self.startup_error = error.NetworkWakeFailed;
            };
            if (self.observation_rearm) {
                self.observation_rearm = false;
                if (!self.stop and self.queue.len > 0) self.pingLocked();
            }
            const slot = self.slot;
            self.diag.currentSlot = slot;
            self.diag.clockRevision = self.revision;
            const stopped = self.stop;
            self.unlock();
            if (stopped) break;
            const timestamp = now(io);
            const result = self.core.step(io, timestamp, slot, .{ .peers = &self.outputs }, 100);
            const diagnostics = self.core.diagnostics();
            self.lock();
            const was_empty = self.queue.len == 0;
            if (comptime faults.enabled) {
                if (self.test_drain_publication == .requested) {
                    _ = self.queue.push(.{ .peerUpdated = .{ .index = 0, .generation = 1, .identity = self.identity.peer } });
                    self.test_drain_publication = .published;
                }
            }
            for (self.outputs[0..result.counts.peers]) |event| {
                const observation: Observation = switch (event) {
                    .ready => |p| .{ .peerReady = .{ .index = p.peer.index, .generation = p.peer.generation, .identity = p.identity } },
                    .updated => |p| .{ .peerUpdated = .{ .index = p.peer.index, .generation = p.peer.generation, .identity = p.identity } },
                    .closed => |p| .{ .peerClosed = .{ .peer = .{ .index = p.peer.index, .generation = p.peer.generation, .identity = p.identity }, .reason = p.reason } },
                };
                _ = self.queue.push(observation);
            }
            if (result.failure) |err| {
                self.diag.operationalFailures +|= 1;
                self.queue.recordFailure(err);
                if (result.readiness.failure != null) {
                    self.stop = true;
                    self.reason = .failed;
                    self.startup_error = err;
                }
            }
            self.diag.ownerTurns +|= 1;
            self.diag.lastMonotonicMs = timestamp.mono_ms;
            self.diag.peerCount = diagnostics.core.connected;
            self.diag.readyPeerCount = diagnostics.core.relevant;
            if (was_empty and self.queue.len > 0) self.pingLocked();
            self.unlock();
        }
    }
    fn startupBarrier(self: *Runtime, stage: faults.Scenario) !void {
        if (comptime !faults.enabled) return;
        if (self.test_scenario != stage) return;
        faults.reached.store(stage, .release);
        for (0..500) |_| {
            if (self.cancelled()) return error.AbortError;
            var fd = std.c.pollfd{ .fd = self.wake.?.read_fd, .events = std.c.POLL.IN, .revents = 0 };
            const result = std.c.poll(@ptrCast(&fd), 1, 10);
            if (result < 0 and std.c.errno(result) != .INTR) return error.NetworkWakeFailed;
            if (result > 0) try self.wake.?.drain();
        }
        return error.NetworkTestBarrierTimeout;
    }
};

test "observation queue remains bounded and copies exact generations" {
    var queue: Queue = .{};
    for (0..65) |i| _ = queue.push(.{ .operationalError = .{ .code = error.TestError, .count = std.math.maxInt(u64) - i } });
    try std.testing.expectEqual(@as(u8, 64), queue.len);
    try std.testing.expectEqual(@as(u64, 1), queue.dropped);
    var batch: [32]Observation = undefined;
    try std.testing.expectEqual(@as(usize, 32), queue.peek(&batch));
    try std.testing.expectEqual(std.math.maxInt(u64), batch[0].operationalError.count);
    try std.testing.expectEqual(@as(u8, 64), queue.len);
    queue.commit(32);
    try std.testing.expectEqual(@as(u8, 32), queue.len);
}

test "slot mailbox coalesces and preserves rejected revision boundaries" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .session = 1, .currentSlot = 100 }, .slot = 100, .notify_live = false, .env_alive = false };
    runtime.wake = try Wake.init();
    defer runtime.wake.?.deinit();
    for (0..10_000) |i| try std.testing.expectEqual(i + 1, try runtime.setSlot(100 + i));
    try std.testing.expectEqual(@as(u64, 10_099), runtime.slot);
    try std.testing.expectError(error.ClockRegression, runtime.setSlot(100));
    try std.testing.expectEqual(@as(u64, 10_000), runtime.revision);
    runtime.revision = std.math.maxInt(u64);
    try std.testing.expectError(error.ClockRevisionExhausted, runtime.setSlot(10_100));
    try std.testing.expectEqual(@as(u64, 10_099), runtime.slot);
    runtime.requestStop();
    try std.testing.expectError(error.NetworkClosed, runtime.setSlot(10_100));
}

test "operational errors coalesce until prior delivery commits" {
    var queue: Queue = .{};
    for (0..10_000) |_| queue.recordFailure(error.TestFailure);
    try std.testing.expectEqual(@as(u8, 1), queue.len);
    var batch: [32]Observation = undefined;
    try std.testing.expectEqual(@as(usize, 1), queue.peek(&batch));
    try std.testing.expectEqual(@as(u64, 1), batch[0].operationalError.count);
    queue.commit(1);
    try std.testing.expectEqual(@as(usize, 1), queue.peek(&batch));
    try std.testing.expectEqual(@as(u64, 9999), batch[0].operationalError.count);
}

test "committed mailbox wakes fail closed without rolling back revision" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .session = 1, .currentSlot = 100 }, .slot = 100, .notify_live = false, .env_alive = false };
    var wake = try Wake.init();
    defer wake.deinit();
    runtime.wake = wake;
    runtime.wake.?.write_fd = -1;
    try std.testing.expectEqual(@as(u64, 1), try runtime.setSlot(101));
    try std.testing.expectEqual(@as(u64, 101), runtime.slot);
    try std.testing.expect(runtime.stop);
    try std.testing.expectEqual(Reason.failed, runtime.reason);
    try std.testing.expectEqual(error.NetworkWakeFailed, runtime.snapshot().terminal_error.?);
    try std.testing.expectError(error.NetworkClosed, runtime.setSlot(102));
}
