const std = @import("std");
const n = @import("network");
const d = @import("discv5");
const napi = @import("zapi:zapi").napi;
const faults = @import("network_faults.zig");
pub const gossip_mod = @import("network_gossip.zig");
pub const incoming_mod = @import("network_incoming.zig");
pub const requests_mod = @import("network_requests.zig");
pub const commands = @import("network_commands.zig");
pub const application_config = @import("network_application_config.zig");
pub const projection = @import("network_peer_projection.zig");
const Config = @import("network_config.zig").Config;
const Wake = @import("network_wake.zig").Wake;
pub const allocator = std.heap.c_allocator;
pub const State = enum { starting, prepared, running, stopping, closed, failed };
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
pub const ResolvedCapacities = struct {
    peerCapacity: u16 = 0,
    targetPeers: u16 = 0,
    maxPeers: u16 = 0,
    minOutbound: u16 = 0,
    outboundReserve: u16 = 0,
    connectionCapacity: u16 = 0,
    handshakingCapacity: u16 = 0,
    dialingCapacity: u16 = 0,
    requestPeerCapacity: u16 = 0,
    admissionIdentityCapacity: u16 = 0,
    gossipConnectedCapacity: u16 = 0,
    gossipRetainedCapacity: u16 = 0,
    dialEngineCapacity: u16 = 0,
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
    operationCapacity: u8 = 32,
    operationOccupied: u8 = 0,
    operationHighWater: u8 = 0,
    operationRefusals: u64 = 0,
    connectCapacity: u8 = 16,
    connectOccupied: u8 = 0,
    connectHighWater: u8 = 0,
    connectRefusals: u64 = 0,
    intentCapacity: u8 = 2,
    intentOccupied: u8 = 0,
    intentHighWater: u8 = 0,
    intentRefusals: u64 = 0,
    snapshotCapacity: u8 = 2,
    snapshotOccupied: u8 = 0,
    snapshotHighWater: u8 = 0,
    snapshotRefusals: u64 = 0,
    targetListCapacity: u8 = 2,
    targetListOccupied: u8 = 0,
    targetListHighWater: u8 = 0,
    targetListRefusals: u64 = 0,
    preparingPins: u8 = 0,
    copyingPins: u8 = 0,
    peerLaneCapacity: u8 = 64,
    peerLaneOccupied: u8 = 0,
    peerLaneHighWater: u8 = 0,
    ownerSequence: u64 = 0,
    liveNativeRequestedBytes: usize = 0,
    liveBridgeRequestedBytes: usize = 0,
    operationBytes: usize = @sizeOf(commands.Table) + 32 * @sizeOf(Operation),
    typedStoreBytes: usize = 0,
    peerLaneBytes: usize = 0,
    ownerShellBytes: usize = @sizeOf(Runtime),
    ownerAllocationBytes: usize = @sizeOf(Owner),
    nativeRequestedBytes: usize = 0,
    nativeAllocationCount: usize = 0,
    resolvedCapacities: ResolvedCapacities = .{},
    requests: requests_mod.Diagnostics = .{},
    incoming: incoming_mod.Diagnostics = .{},
    gossip: gossip_mod.Diagnostics = .{},
    bridgeRequestedBytes: usize = @sizeOf(Runtime) + @sizeOf(Owner) - @sizeOf(n.NetworkCore),
};

pub const Owner = struct {
    threaded_live: bool = false,
    core_live: bool = false,
    config: Config = undefined,
    core: n.NetworkCore = undefined,
    threaded: std.Io.Threaded = undefined,
    key: n.KeyPair = undefined,
    records: [d.Maintenance.bootstrap_max]d.identity.enr.Record = undefined,
    outputs: [32]n.peers.Event = undefined,
    application_outputs: [32]n.reqresp.Event = undefined,
    gossip_outputs: [32]n.gossipsub.Event = undefined,
    application: ?@import("network_application_config.zig").Config = null,
};

pub const Operation = struct {
    input: commands.Input = undefined,
    deferred: ?napi.Deferred = null,
    failure: ?anyerror = null,
    sequence: u64 = 0,
    boolean: bool = false,
    deadline: u64 = 0,
    identity: Identity = undefined,
    count: usize = 0,
    counts: n.Core.PeerCounts = undefined,
    publication: n.gossipsub.Gossipsub.PublishOutcome = .{},
};
pub const Stores = struct {
    backing: std.mem.Allocator,
    intents: [2]application_config.Intent = undefined,
    snapshots: [2][]n.peers.types.Snapshot,
    direct: [2][256]n.PeerId = undefined,
    targets: [2][256]n.PeerId = undefined,
    pub fn create(backing: std.mem.Allocator, capacity: usize) !*Stores {
        try faults.check(.application_stores);
        const self = try backing.create(Stores);
        errdefer backing.destroy(self);
        self.* = .{ .backing = backing, .snapshots = undefined };
        try faults.check(.application_snapshot_0);
        self.snapshots[0] = try backing.alloc(n.peers.types.Snapshot, capacity);
        errdefer backing.free(self.snapshots[0]);
        try faults.check(.application_snapshot_1);
        self.snapshots[1] = try backing.alloc(n.peers.types.Snapshot, capacity);
        return self;
    }
    pub fn destroy(self: *Stores) void {
        for (self.snapshots) |snapshots| self.backing.free(snapshots);
        self.backing.destroy(self);
    }
    pub fn bytes(capacity: usize) usize {
        return @sizeOf(Stores) + 2 * capacity * @sizeOf(n.peers.types.Snapshot);
    }
};

pub const Runtime = struct {
    test_scenario: if (faults.enabled) faults.Scenario else void = if (faults.enabled) .none else {},
    test_drain_publication: if (faults.enabled) faults.DrainPublication else void = if (faults.enabled) .idle else {},
    refs: std.atomic.Value(u32) = .init(1),
    mutex: std.Io.Mutex = .init,
    heavy: ?*Owner = null,
    application: bool = false,
    active: bool = false,
    graceful: bool = false,
    closing_deadline: ?u64 = null,
    stores: ?*Stores = null,
    lane: ?*projection.Lane = null,
    table: commands.Table = .{},
    requests: ?requests_mod.Table = null,
    incoming: ?incoming_mod.Table = null,
    gossip: ?gossip_mod.Table = null,
    payload_budget: incoming_mod.Budget = .{},
    test_incoming_deadline: u64 = 0,
    test_gossip_held: if (faults.enabled) bool else void = if (faults.enabled) false else {},
    test_gossip_expiry: if (faults.enabled) ?gossip_mod.Token else void = if (faults.enabled) null else {},
    operations: [32]Operation = @splat(.{}),
    peer_capacity: u16 = 0,
    max_peers: u16 = 0,

    wake: ?Wake = null,
    thread: ?std.Thread = null,
    notify: Notify = undefined,
    notify_live: bool = true,
    notify_finalized: bool = false,
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

    pub fn requestObligations(self: *const Runtime) bool {
        return (if (self.requests) |*requests| requests.obligated() else false) or (if (self.incoming) |*incoming| incoming.obligated() else false);
    }
    pub fn retireRequest(self: *Runtime, token: requests_mod.Token) void {
        self.lock();
        self.requests.?.retire(token);
        self.unlock();
        self.release();
    }
    pub fn retireRequestStorageLocked(self: *Runtime) void {
        if (!self.quiescent) return;
        if (self.gossip) |*table| table.trim();
        if (self.incoming) |*table| {
            if (table.diag.occupied == 0) {
                table.backing.free(table.cells);
                table.cells = &.{};
            }
        }
        if (self.requests) |*table| {
            if (table.diag.occupied != 0) return;
            table.backing.free(table.cells);
            table.cells = &.{};
        }
    }
    pub fn retireStoresLocked(self: *Runtime) void {
        if (!self.quiescent or self.table.occupied != 0) return;
        if (self.stores) |stores| {
            stores.destroy();
            self.stores = null;
        }
    }
    pub fn destroyOwner(self: *Runtime) void {
        if (self.heavy) |heavy| {
            if (heavy.core_live) {
                heavy.core.shutdown(now(heavy.threaded.io()));
                incoming_mod.closeLocked(self);
                gossip_mod.closeLocked(self);
                heavy.core.deinit(heavy.threaded.io());
            }
            if (heavy.threaded_live) heavy.threaded.deinit();
            heavy.config.wipe();
            std.crypto.secureZero(u8, std.mem.asBytes(heavy));
            allocator.destroy(heavy);
            self.heavy = null;
        }
    }
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
            self.destroyOwner();
            if (self.stores) |stores| stores.destroy();
            if (self.lane) |lane| allocator.destroy(lane);
            if (self.requests) |*requests| requests.deinit();
            if (self.incoming) |*incoming| incoming.deinit();
            if (self.gossip) |*gossip| gossip.deinit();
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
    pub fn signalLocked(self: *Runtime) void {
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
        if (self.application) return error.NetworkApplicationClock;
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
        result.operationOccupied = self.table.occupied;
        result.operationHighWater = self.table.high_water;
        result.operationRefusals = self.table.refusals;
        result.connectHighWater = self.table.kind_high_water[@intFromEnum(commands.Kind.connect)];
        result.connectRefusals = self.table.kind_refusals[@intFromEnum(commands.Kind.connect)];
        result.intentHighWater = self.table.kind_high_water[@intFromEnum(commands.Kind.intent)];
        result.intentRefusals = self.table.kind_refusals[@intFromEnum(commands.Kind.intent)];
        result.snapshotHighWater = self.table.kind_high_water[@intFromEnum(commands.Kind.snapshot)];
        result.snapshotRefusals = self.table.kind_refusals[@intFromEnum(commands.Kind.snapshot)];
        result.targetListHighWater = self.table.kind_high_water[@intFromEnum(commands.Kind.targets)];
        result.targetListRefusals = self.table.kind_refusals[@intFromEnum(commands.Kind.targets)];
        result.connectOccupied = self.table.connects;
        result.ownerSequence = self.table.sequence;
        for (self.table.cells) |cell| {
            result.preparingPins += @intFromBool(cell.state == .preparing);
            result.copyingPins += @intFromBool(cell.state == .copying);
            if (cell.state == .free) continue;
            switch (cell.kind) {
                .intent => result.intentOccupied += 1,
                .snapshot => result.snapshotOccupied += 1,
                .targets => result.targetListOccupied += 1,
                else => {},
            }
        }
        if (self.lane) |lane| {
            result.peerLaneOccupied = lane.len;
            result.peerLaneHighWater = lane.high_water;
            result.peerLaneBytes = @sizeOf(projection.Lane);
        }
        if (self.stores != null) result.typedStoreBytes = Stores.bytes(self.peer_capacity);
        if (self.requests) |*requests| {
            result.requests = requests.snapshot();
            for (requests.cells) |cell| result.copyingPins += @intFromBool(cell.copying);
        }
        result.liveNativeRequestedBytes = if (self.heavy != null) self.diag.nativeRequestedBytes else 0;
        result.liveBridgeRequestedBytes = @sizeOf(Runtime) + result.peerLaneBytes + result.typedStoreBytes + if (self.heavy != null) @sizeOf(Owner) - @sizeOf(n.NetworkCore) else @as(usize, 0);

        if (self.requests) |*requests| result.liveBridgeRequestedBytes += requests.cells.len * @sizeOf(requests_mod.Cell) + result.requests.inputBytes + result.requests.sinkBytes;
        if (self.incoming) |*incoming| {
            result.incoming = incoming.snapshot();
            for (incoming.cells) |cell| {
                result.copyingPins += @intFromBool(cell.copying);
                result.preparingPins += @intFromBool(cell.state == .response_preparing);
            }
            result.liveBridgeRequestedBytes += incoming.cells.len * @sizeOf(incoming_mod.Cell) + result.incoming.requestBytes + result.incoming.responseBytes;
        }
        if (self.gossip) |*gossip| {
            result.gossip = gossip.snapshot();
            for (gossip.cells) |cell| result.copyingPins += @intFromBool(cell.state == .copying);
            result.liveBridgeRequestedBytes += gossip.cells.len * @sizeOf(gossip_mod.Cell) + result.gossip.payloadBytes + result.gossip.publicationBytes;
        }
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
    pub fn pingLocked(self: *Runtime) void {
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
        self.graceful = false;
        if (env_dying) self.env_alive = false;
        self.unlock();
        self.requestStop();
        self.join();
    }
    pub fn retireClosedRequests(self: *Runtime) void {
        std.debug.assert(self.quiescent and self.notify_finalized and self.disposed);
        if (self.requests) |*table| for (table.cells, 0..) |cell, i| {
            if (cell.state == .free) continue;
            std.debug.assert(cell.state == .terminal and cell.native == null and !cell.copying);
            std.debug.assert(cell.pull == null and cell.retirement == null);
            self.retireRequest(.{ .index = @intCast(i), .generation = cell.generation });
        };
        if (self.incoming) |*table| for (table.cells, 0..) |cell, i| {
            if (cell.state == .free) continue;
            std.debug.assert(!cell.native and !cell.copying and cell.closed == null and cell.pending == null);
            @import("network_incoming_js.zig").retireReferences(&table.cells[i]);
            table.retire(.{ .index = @intCast(i), .generation = cell.generation });
        };
        self.retireRequestStorageLocked();
        self.disposeJsReferences();
    }
    pub fn disposeTerminalReferences(self: *Runtime) void {
        if (self.notify_finalized and (self.requests == null or self.requests.?.diag.occupied == 0) and (self.incoming == null or self.incoming.?.diag.occupied == 0)) self.disposeJsReferences();
    }
    pub fn disposeJsReferences(self: *Runtime) void {
        if (self.copy_error) |ref| ref.delete() catch unreachable;
        self.copy_error = null;
        self.disposeCloseReferences();
    }
    fn disposeCloseReferences(self: *Runtime) void {
        for (&self.close_results) |*entry| {
            if (entry.*) |ref| ref.delete() catch unreachable;
            entry.* = null;
        }
    }
    pub fn cleanup(self: *Runtime) void {
        self.hook_live = false;
        self.forceStop(true);
        for (0..32) |i| {
            self.lock();
            const cell = &self.table.cells[i];
            const token: ?commands.Token = if (cell.state == .free) null else .{ .index = @intCast(i), .generation = cell.generation };
            std.debug.assert(cell.state != .preparing and cell.state != .copying);
            self.unlock();
            if (token) |live| self.abortCommand(live);
        }
        if (self.requests) |*requests| for (requests.cells, 0..) |cell, i| {
            if (cell.state != .free) self.retireRequest(.{ .index = @intCast(i), .generation = cell.generation });
        };
        if (self.incoming) |*incoming| for (incoming.cells, 0..) |cell, i| {
            if (cell.state != .free) {
                @import("network_incoming_js.zig").retireReferences(&incoming.cells[i]);
                incoming.retire(.{ .index = @intCast(i), .generation = cell.generation });
            }
        };
        self.disposeJsReferences();
        self.release();
    }
    pub fn finalize(_: napi.Env, self: *Runtime) void {
        self.notify_finalized = true;
        self.disposeCloseReferences();
        if (self.disposed) self.retireClosedRequests() else self.disposeTerminalReferences();
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
    fn cancelCommandsLocked(self: *Runtime) void {
        for (&self.table.cells, 0..) |*cell, i| {
            switch (cell.state) {
                .queued, .executing, .waiting => {
                    gossip_mod.releasePublicationLocked(self, &self.operations[i].input);
                    self.operations[i].failure = self.startup_error orelse error.NetworkClosed;
                    cell.state = .terminal;
                },
                else => {},
            }
        }
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
        self.destroyOwner();
        requests_mod.closeLocked(self);
        incoming_mod.closeLocked(self);
        gossip_mod.closeLocked(self);
        self.cancelCommandsLocked();
        if (self.startup == .pending) {
            self.startup = .failed;
            self.startup_error = self.startup_error orelse error.AbortError;
        }
        if (self.wake) |*wake| wake.deinit();
        self.wake = null;
        self.quiescent = true;
        self.retireStoresLocked();
        self.retireRequestStorageLocked();
        self.diag.state = if (self.reason == .failed) .failed else .closed;
        self.pingLocked();
        const release_notify = self.notify_live;
        self.notify_live = false;
        self.unlock();
        if (release_notify) self.notify.release(.release) catch unreachable;
        faults.count(&faults.owners, false);
        self.release();
    }
    pub fn initializeOwner(self: *Runtime) !void {
        if (!self.application) try self.startupBarrier(.entry);
        if (self.cancelled()) return error.AbortError;
        self.heavy.?.threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing, .concurrent_limit = .nothing });
        self.heavy.?.threaded_live = true;
        const io = self.heavy.?.threaded.io();
        var seed: u64 = undefined;
        try faults.check(.entropy);
        try io.randomSecure(std.mem.asBytes(&seed));
        try faults.check(.key);
        self.heavy.?.key = try n.KeyPair.fromSecretKey(&self.heavy.?.config.secret);

        self.heavy.?.config.wipe();
        if (!self.application) try self.startupBarrier(.key_ready);
        if (self.cancelled()) return error.AbortError;
        for (0..self.heavy.?.config.bootstrap_count) |i| {
            try faults.check(.enr);
            self.heavy.?.records[i] = try d.identity.enr.Record.init(self.heavy.?.config.bootstrap[i].bytes[0..self.heavy.?.config.bootstrap[i].len]);
            if (self.cancelled()) return error.AbortError;
        }
        var gossip = self.heavy.?.config.gossip;
        gossip.random_seed = seed;
        gossip.ip_allowlist = self.heavy.?.config.allowlist[0..self.heavy.?.config.allowlist_count];
        gossip.topic_policy = if (self.heavy.?.config.topic_boundary_count == 0) null else self.heavy.?.config.topic_boundaries[0..self.heavy.?.config.topic_boundary_count];
        try faults.check(.core);
        try self.heavy.?.core.initManaged(allocator, io, .{
            .wait_mode = .native_poll,
            .host = &self.heavy.?.key,
            .bind = self.heavy.?.config.bind,
            .configuration = if (self.heavy.?.application) |*application| try application.resolve(&self.heavy.?.config, seed) else .{ .profile = self.heavy.?.config.profile, .seed = seed, .forks = self.heavy.?.config.forks[0..self.heavy.?.config.fork_count], .gossip = gossip },
            .local = self.heavy.?.config.local,
            .schedule = self.heavy.?.config.schedule,
            .discovery = if (self.heavy.?.config.discovery_bind) |bind| .{ .bind = bind, .sequence = self.heavy.?.config.discovery_sequence, .advertisement = self.heavy.?.config.advertisement, .bootstrap = self.heavy.?.records[0..self.heavy.?.config.bootstrap_count] } else null,
        });
        self.heavy.?.core_live = true;
        try faults.check(.wake_attach);
        try self.heavy.?.core.setHostWake(self.wake.?.read_fd);

        self.lock();
        defer self.unlock();
        const plan = self.heavy.?.core.memoryPlan();
        self.diag.nativeRequestedBytes = plan.inline_bytes + plan.allocated_bytes;
        self.diag.nativeAllocationCount = self.heavy.?.core.reservations.allocation_calls;
        const core = &self.heavy.?.core.core;
        const limits = self.heavy.?.core.transport.engine.limits;
        self.diag.resolvedCapacities = .{
            .peerCapacity = core.catalog.options.capacity,
            .targetPeers = core.catalog.options.target_peers,
            .maxPeers = core.catalog.options.max_peers,
            .minOutbound = core.catalog.options.min_outbound,
            .outboundReserve = core.catalog.options.outbound_reserve,
            .connectionCapacity = limits.connections_max,
            .handshakingCapacity = limits.handshaking_max,
            .dialingCapacity = limits.dialing_max,
            .requestPeerCapacity = core.service.reqresp.inner.options.peers,
            .admissionIdentityCapacity = if (core.service.reqresp.inner.admission) |*admission| admission.options.identities else 0,
            .gossipConnectedCapacity = core.service.gossipsub.inner.options.connected_capacity,
            .gossipRetainedCapacity = core.service.gossipsub.inner.options.retained_capacity,
            .dialEngineCapacity = core.dial_queue.options.engine_dialing_max,
        };
    }
    fn serve(self: *Runtime) !void {
        if (!self.heavy.?.core_live) try self.initializeOwner();
        const io = self.heavy.?.threaded.io();
        try self.publishReady();
        while (true) {
            self.lock();
            const stop = self.stop;
            const graceful = self.graceful and self.active and self.reason == .requested;
            self.unlock();
            if (stop and !graceful) break;
            const timestamp = now(io);
            if (stop) {
                if (self.closing_deadline == null) {
                    self.lock();
                    self.cancelCommandsLocked();
                    self.pingLocked();
                    self.unlock();
                    self.closing_deadline = timestamp.mono_ms +| 2000;
                    self.heavy.?.core.beginGracefulClose(timestamp);
                }
                if (timestamp.mono_ms >= self.closing_deadline.? or self.heavy.?.core.peerCounts().connected == 0) break;
            } else try commands.executeCommands(self, timestamp);
            self.lock();
            self.wake.?.drain() catch {
                self.stop = true;
                self.reason = .failed;
                self.startup_error = error.NetworkWakeFailed;
            };
            if (self.observation_rearm) {
                self.observation_rearm = false;
                if (!self.stop and (self.queue.len > 0 or (self.lane != null and self.lane.?.len > 0) or (self.incoming != null and self.incoming.?.oldest() != null) or (self.gossip != null and self.gossip.?.oldest() != null))) self.pingLocked();
            }
            const slot = self.slot;
            self.diag.currentSlot = slot;
            self.diag.clockRevision = self.revision;
            const stopped = self.stop and !(self.graceful and self.active and self.reason == .requested);
            const active = self.active;
            const peer_room: usize = if (self.lane) |lane| 64 - @as(usize, lane.len) else self.heavy.?.outputs.len;
            self.unlock();
            if (stopped) break;
            if (!active) {
                var fd = std.c.pollfd{ .fd = self.wake.?.read_fd, .events = std.c.POLL.IN, .revents = 0 };
                if (commands.waitLimit(self, timestamp) == 0) continue;
                const rc = std.c.poll(@ptrCast(&fd), 1, -1);
                if (rc < 0 and std.c.errno(rc) != .INTR) return error.NetworkWakeFailed;
                continue;
            }
            try gossip_mod.flags(self, io);
            requests_mod.flags(self, timestamp);
            _ = try @import("network_incoming_phase_faults.zig").terminalBarrier(self, false);
            try incoming_mod.flags(self, timestamp);
            const terminal_accepted = try @import("network_incoming_phase_faults.zig").terminalBarrier(self, true);
            const sequence = try self.advanceSequence();
            const result = self.heavy.?.core.step(io, timestamp, slot, .{ .peers = self.heavy.?.outputs[0..@min(peer_room, self.heavy.?.outputs.len)], .application = &self.heavy.?.application_outputs, .gossipsub = &self.heavy.?.gossip_outputs }, commands.waitLimit(self, timestamp));
            @import("network_gossip_faults.zig").afterStep(self);
            if (terminal_accepted) |proof| @import("network_incoming_phase_faults.zig").afterStep(self, &proof, self.heavy.?.application_outputs[0..result.counts.application]);
            try requests_mod.capture(self, self.heavy.?.application_outputs[0..result.counts.application], timestamp);
            try gossip_mod.capture(self, self.heavy.?.gossip_outputs[0..result.counts.gossipsub], try gossip_mod.sample(io));
            commands.completeConnects(self, timestamp);

            self.publishTurn(&result, timestamp, sequence);
        }
    }
    fn publishReady(self: *Runtime) !void {
        if (comptime faults.enabled) {
            if (self.test_scenario == .gossip) faults.captureGossip(&self.heavy.?.core.core.service.gossipsub.inner, &self.heavy.?.core.core.local.fork);
        }
        const identity = try self.readIdentity();
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
            } else if (self.test_scenario == .application_peer_lane) {
                if (self.lane) |lane| for (0..64) |i| {
                    const event: n.peers.Event = .{ .closed = .{
                        .peer = .{ .index = @intCast(i), .generation = std.math.maxInt(u64) - i },
                        .connection = .{ .index = @intCast(i % 16), .generation = std.math.maxInt(u32) - @as(u32, @intCast(i)) },
                        .identity = identity.peer,
                        .reason = .host,
                    } };
                    lane.publish(&.{event}, 0);
                };
            } else if (self.test_scenario == .drain_publish) {
                _ = self.queue.push(.{ .peerReady = .{ .index = 0, .generation = 1, .identity = identity.peer } });
            }
        }
        self.startup = .ready;
        self.diag.state = if (self.application) .prepared else .running;
        self.active = !self.application;
        const plan = self.heavy.?.core.memoryPlan();
        self.diag.nativeRequestedBytes = plan.inline_bytes + plan.allocated_bytes;
        self.pingLocked();
        self.unlock();
    }
    fn publishTurn(self: *Runtime, result: *const n.network_core.Result, timestamp: n.Now, sequence: u64) void {
        const diagnostics = self.heavy.?.core.diagnostics();
        self.lock();
        const was_empty = self.queue.len == 0;
        if (self.lane) |lane| {
            const empty = lane.len == 0;
            lane.publish(self.heavy.?.outputs[0..result.counts.peers], sequence);
            if (empty and lane.len > 0) self.pingLocked();
        }
        if (comptime faults.enabled) {
            if (self.test_drain_publication == .requested) {
                _ = self.queue.push(.{ .peerUpdated = .{ .index = 0, .generation = 1, .identity = self.identity.peer } });
                self.test_drain_publication = .published;
            }
        }
        for (self.heavy.?.outputs[0..result.counts.peers]) |event| {
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
    pub fn readIdentity(self: *Runtime) !Identity {
        var identity: Identity = undefined;
        identity.peer = self.heavy.?.core.peerId();
        identity.endpoint = self.heavy.?.core.localAddress();
        const multiaddr = self.heavy.?.core.localMultiaddr();
        identity.multiaddr_len = @intCast((try multiaddr.encode(&identity.multiaddr)).len);
        identity.enr_len = 0;
        if (self.heavy.?.core.localRecord()) |record| {
            identity.enr_len = @intCast(record.slice().len);
            @memcpy(identity.enr[0..identity.enr_len], record.slice());
        }
        return identity;
    }
    pub fn advanceSequence(self: *Runtime) !u64 {
        self.lock();
        defer self.unlock();
        return self.table.advance();
    }
    pub fn reserveCommand(self: *Runtime, command: commands.Command) !commands.Token {
        self.lock();
        defer self.unlock();
        if (!self.application or self.stop or self.quiescent) return error.NetworkClosed;
        if (!self.active and command != .applyIntent and command != .getIdentity) return error.NetworkNotActive;
        const token = self.table.reserve(commands.storageKind(command)) catch |err| {
            if (err == error.NetworkSequenceExhausted) {
                self.stop = true;
                self.reason = .failed;
                self.startup_error = err;
                self.signalLocked();
            }
            return err;
        };
        self.operations[token.index] = .{ .input = .{ .command = command } };
        self.retain();
        return token;
    }
    pub fn abortCommand(self: *Runtime, token: commands.Token) void {
        self.lock();
        gossip_mod.releasePublicationLocked(self, &self.operations[token.index].input);
        self.table.retire(token);
        self.retireStoresLocked();
        self.unlock();
        self.release();
    }
    pub fn queueCommand(self: *Runtime, token: commands.Token) !void {
        self.lock();
        defer self.unlock();
        if (self.stop or self.quiescent) return error.NetworkClosed;
        self.table.get(token).state = .queued;
        self.signalLocked();
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

test {
    _ = commands;
    _ = projection;
}

test "application typed store allocation prefixes release all requested bytes" {
    for ([_]usize{ 64, 512 }) |capacity| {
        for (0..3) |prefix| {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = prefix });
            try std.testing.expectError(error.OutOfMemory, Stores.create(failing.allocator(), capacity));
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
        var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const stores = try Stores.create(measured.allocator(), capacity);
        try std.testing.expectEqual(Stores.bytes(capacity), measured.allocated_bytes);
        stores.destroy();
        try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
        std.debug.print("application bridge capacity={} stores={} shell={} owner={} lane={} store_prefixes={}\n", .{ capacity, Stores.bytes(capacity), @sizeOf(Runtime), @sizeOf(Owner), @sizeOf(projection.Lane), measured.alloc_index });
    }
}

test "authenticated connect completion latches before a later close in the borrowed batch" {
    const key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{2}));
    const peer = n.PeerId.fromPublicKey(&key.publicKey());
    const handle: n.Handle = .{ .index = 3, .generation = 7 };
    const events = [_]n.Event{
        .{ .connected = .{ .conn = handle, .peer_id = peer, .direction = .outbound } },
        .{ .closed = .{ .conn = handle, .peer_id = peer, .direction = .outbound, .reason = .host } },
    };
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .session = 1, .currentSlot = 100 }, .notify_live = false, .env_alive = false };
    const token = try runtime.table.reserve(.connect);
    runtime.table.get(token).state = .waiting;
    runtime.operations[token.index] = .{ .input = .{ .command = .connect, .peer = peer }, .deadline = 2 };
    try std.testing.expect(commands.latchConnects(&runtime.table, &runtime.operations, &events, .{ .mono_ms = 3, .unix_s = 0 }));
    try std.testing.expectEqual(commands.State.terminal, runtime.table.get(token).state);
    try std.testing.expect(runtime.operations[token.index].failure == null);
    try std.testing.expect(!commands.latchConnects(&runtime.table, &runtime.operations, &events, .{ .mono_ms = 4, .unix_s = 0 }));
    try std.testing.expect(runtime.operations[token.index].failure == null);
    runtime.table.retire(token);
}

test "stop preserves latched success and cancels accepted nonterminal commands" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .session = 1, .currentSlot = 100 }, .notify_live = false, .env_alive = false };
    const success = try runtime.table.reserve(.small);
    const waiting = try runtime.table.reserve(.connect);
    const queued = try runtime.table.reserve(.small);
    const preparing = try runtime.table.reserve(.intent);
    runtime.table.get(success).state = .terminal;
    runtime.table.get(waiting).state = .waiting;
    runtime.table.get(queued).state = .queued;
    runtime.cancelCommandsLocked();
    try std.testing.expect(runtime.operations[success.index].failure == null);
    try std.testing.expectEqual(error.NetworkClosed, runtime.operations[waiting.index].failure.?);
    try std.testing.expectEqual(error.NetworkClosed, runtime.operations[queued.index].failure.?);
    try std.testing.expectEqual(commands.State.preparing, runtime.table.get(preparing).state);
    for ([_]commands.Token{ success, waiting, queued, preparing }) |token| runtime.table.retire(token);
    try std.testing.expectEqual(@as(u8, 0), runtime.table.occupied);
}

test {
    _ = requests_mod;
    _ = @import("network_incoming.zig");
}

test "request table storage retires only after physical quiescence and final pins" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .session = 1, .currentSlot = 0 } };
    runtime.requests = try requests_mod.Table.init(std.testing.allocator, 1, 32 + 2 * n.reqresp.Protocol.blocks_by_root_v2.info().response_max);
    defer runtime.requests.?.deinit();
    runtime.retireRequestStorageLocked();
    try std.testing.expectEqual(@as(usize, 1), runtime.requests.?.cells.len);
    const token = try runtime.requests.?.reserve(.blocks_by_root_v2, 32);
    try runtime.requests.?.allocate(token, 32);
    const cell = runtime.requests.?.get(token).?;
    cell.state = .native;
    cell.copying = true;
    cell.chunk = .{ .len = 4, .fork = null };
    runtime.quiescent = true;
    requests_mod.closeLocked(&runtime);
    runtime.retireRequestStorageLocked();
    try std.testing.expectEqual(@as(usize, 1), runtime.requests.?.cells.len);
    try std.testing.expect(cell.sink.len > 0);
    cell.copying = false;
    runtime.requests.?.retire(token);
    runtime.retireRequestStorageLocked();
    try std.testing.expectEqual(@as(usize, 0), runtime.requests.?.cells.len);
    try std.testing.expectEqual(@as(usize, 1), runtime.requests.?.diag.capacity);
    try std.testing.expect(runtime.requests.?.get(token) == null);
}

test {
    _ = @import("network_gossip.zig");
}
