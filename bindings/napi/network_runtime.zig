const std = @import("std");
const n = @import("network");
const d = @import("discv5");
const napi = @import("zapi:zapi").napi;
const faults = @import("network_faults.zig");
pub const gossip_mod = @import("network_gossip.zig");
pub const incoming_mod = @import("network_incoming.zig");
pub const requests_mod = @import("network_requests.zig");
pub const publications_mod = @import("network_publications.zig");
pub const commands = @import("network_commands.zig");
pub const application_config = @import("network_application_config.zig");
pub const projection = @import("network_peer_projection.zig");
const Wake = @import("network_wake.zig").Wake;
pub const Owner = @import("network_owner.zig").Owner;
pub const allocator = std.heap.c_allocator;
pub const State = enum { running, stopping, closed, failed };
pub const Reason = enum { requested, failed };
pub const Notify = napi.ThreadSafeFunction(Runtime, void);
var initialized = std.atomic.Value(bool).init(false);

/// The beacon node initializes once, from its owning Node environment. Teardown never resets this guard.
pub fn beginInitialization() !void {
    if (initialized.swap(true, .acq_rel)) return error.NetworkAlreadyInitialized;
}

pub const Identity = struct {
    peer: n.PeerId,
    metadata: n.peers.types.Metadata,
    endpoints: [2]?n.Address,
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
    state: State = .running,
    terminal_error: ?anyerror = null,
    currentSlot: u64,
    ownerTurns: u64 = 0,
    lastMonotonicMs: u64 = 0,
    peerCount: u16 = 0,
    readyPeerCount: u16 = 0,
    operationalFailures: u64 = 0,
    operationCapacity: u8 = 32,
    operationOccupied: u8 = 0,
    operationHighWater: u8 = 0,
    operationRefusals: u64 = 0,
    peerReportsIgnored: u64 = 0,
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
    preparingPins: u16 = 0,
    copyingPins: u16 = 0,
    peerLaneCapacity: u8 = 64,
    peerLaneOccupied: u8 = 0,
    peerLaneHighWater: u8 = 0,
    ownerSequence: u64 = 0,
    liveNativeRequestedBytes: usize = 0,
    liveBridgeRequestedBytes: usize = 0,
    operationBytes: usize = @sizeOf(commands.Table),
    typedStoreBytes: usize = 0,
    metricsExportBytes: usize = 0,
    peerLaneBytes: usize = 0,
    ownerShellBytes: usize = @sizeOf(Runtime),
    ownerAllocationBytes: usize = @sizeOf(Owner),
    nativeRequestedBytes: usize = 0,
    nativeAllocationCount: usize = 0,
    quicReceiveWindowBytes: u64 = 0,
    quicConnectionWindowBytes: u64 = 0,
    quicStreamWindowBytes: u64 = 0,
    resolvedCapacities: ResolvedCapacities = .{},
    publications: publications_mod.Diagnostics = .{},
    requests: requests_mod.Diagnostics = .{},
    incoming: incoming_mod.Diagnostics = .{},
    gossip: gossip_mod.Diagnostics = .{},
    bridgeRequestedBytes: usize = @sizeOf(Runtime) + @sizeOf(Owner) - @sizeOf(n.NetworkCore),
};

pub const Stores = struct {
    backing: std.mem.Allocator,
    intents: [2]application_config.Intent = undefined,
    snapshots: [2][]n.peers.types.Snapshot,
    gossip_diagnostics: [2]n.gossipsub.diagnostics.Page = undefined,
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
    logs: n.logging.Sink = .{},
    metrics: @import("network_metrics.zig").Export = .{},
    metrics_due_ms: u64 = 0,
    health_log_due_ms: u64 = 0,
    test_scenario: if (faults.enabled) faults.Scenario else void = if (faults.enabled) .none else {},
    refs: std.atomic.Value(u32) = .init(1),
    mutex: std.Io.Mutex = .init,
    heavy: ?*Owner = null,
    graceful: bool = false,
    closing_deadline: ?u64 = null,
    stores: ?*Stores = null,
    lane: ?*projection.Lane = null,
    table: commands.Table = .{},
    reports: @import("network_peer_reports.zig").Table = .{},
    publications: ?publications_mod.Table = null,
    requests: ?requests_mod.Table = null,
    incoming: ?incoming_mod.Table = null,
    gossip: ?gossip_mod.Table = null,
    payload_budget: @import("network_budget.zig").Budget = .{},
    test_incoming_deadline: if (faults.enabled) u64 else void = if (faults.enabled) 0 else {},
    test_gossip_held: if (faults.enabled) bool else void = if (faults.enabled) false else {},
    test_gossip_expiry: if (faults.enabled) ?gossip_mod.Token else void = if (faults.enabled) null else {},
    peer_capacity: u16 = 0,
    max_peers: u16 = 0,

    wake: ?Wake = null,
    thread: ?std.Thread = null,
    notify: Notify = undefined,
    notify_live: bool = true,
    notify_finalized: bool = false,
    notification_pending: bool = false,
    work_rearm: bool = false,
    env_alive: bool = true,
    disposed: bool = false,
    close_deferred: ?napi.Deferred = null,
    close_settled: bool = false,
    copy_error: ?napi.Ref = null,
    close_results: [2]?napi.Ref = @splat(null),
    hook_live: bool = false,
    env: napi.Env,
    stop: bool = false,
    reason: Reason = .requested,
    quiescent: bool = false,
    terminal_error: ?anyerror = null,
    identity: Identity = undefined,
    slot: u64 = 0,
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
        if (self.publications) |*table| table.trim();
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
    fn retireStoresLocked(self: *Runtime) void {
        if (!self.quiescent or self.table.occupied != 0) return;
        if (self.stores) |stores| {
            stores.destroy();
            self.stores = null;
        }
    }
    fn destroyOwner(self: *Runtime) void {
        if (self.heavy) |heavy| {
            if (heavy.core_live) {
                heavy.core.shutdown(@import("network_owner.zig").now(heavy.threaded.io()));
                if (self.metrics.allocatedBytes() > 0) {
                    const context = n.metrics.Context.init(&heavy.core, @import("network_owner.zig").now(heavy.threaded.io()), false);
                    if (self.metrics.render(&context)) |index| {
                        self.metrics.published = index;
                        self.metrics.failure = null;
                    } else |err| self.metrics.failure = err;
                    self.metrics.finish();
                }
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
            self.metrics.deinit();
            if (self.stores) |stores| stores.destroy();
            if (self.lane) |lane| allocator.destroy(lane);
            if (self.publications) |*table| table.deinit();
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
        self.reason = .requested;
        self.diag.state = .stopping;
        self.signalLocked();
    }
    pub fn signalLocked(self: *Runtime) void {
        if (self.wake) |*wake| signal(wake) catch {
            self.stop = true;
            self.reason = .failed;
            self.terminal_error = error.NetworkWakeFailed;
        };
    }
    fn signal(wake: *const Wake) !void {
        try faults.check(.wake_signal);
        try wake.signal();
    }
    pub fn snapshot(self: *Runtime) !Diagnostics {
        self.lock();
        defer self.unlock();
        var result = self.diag;
        result.terminal_error = if (self.reason == .failed) self.terminal_error else null;
        result.operationOccupied = self.table.occupied;
        result.operationHighWater = self.table.high_water;
        result.operationRefusals = self.table.refusals;
        result.peerReportsIgnored = self.reports.ignored;
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
        for (&self.table.cells) |*cell| {
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
        result.metricsExportBytes = self.metrics.allocatedBytes();
        result.liveBridgeRequestedBytes = result.metricsExportBytes + @sizeOf(Runtime) + result.peerLaneBytes + result.typedStoreBytes + if (self.heavy != null) @sizeOf(Owner) - @sizeOf(n.NetworkCore) else @as(usize, 0);

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
            result.gossip = gossip.snapshot(try gossip_mod.monotonic());
            result.copyingPins += @intCast(gossip.diag.copying);
            result.liveBridgeRequestedBytes += gossip_mod.Table.backingBytes(gossip.cells.len, gossip.store.bytes.len);
        }
        if (self.publications) |*table| {
            result.publications = table.snapshot();
            result.liveBridgeRequestedBytes += table.cells.len * @sizeOf(publications_mod.Cell) + result.publications.payloadBytes;
            for (table.cells) |cell| {
                result.preparingPins += @intFromBool(cell.state == .preparing);
                result.copyingPins += @intFromBool(cell.state == .copying);
            }
            result.gossip.publicationBytes = result.publications.reservedBytes;
            result.gossip.publicationBytesHighWater = result.publications.reservedBytesHighWater;
            result.gossip.publicationCopies = result.publications.copies;
            result.gossip.publicationBytesCopied = result.publications.bytesCopied;
            result.gossip.publicationQueued = result.publications.queued;
            result.gossip.publicationPressured = result.publications.pressured;
            result.gossip.publicationSelected = result.publications.selected;
            result.gossip.publicationUnavailable = result.publications.unavailable;
            result.gossip.publicationDuplicates = result.publications.duplicates;
        }
        return result;
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
                self.terminal_error = err;
            },
        };
    }
    pub fn join(self: *Runtime) void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
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
        self.terminal_error = error.NetworkResultAllocationFailed;
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
            std.debug.assert(!cell.native and !cell.copying and cell.closed == null and cell.pending == null and cell.permission == null);
            table.retire(.{ .index = @intCast(i), .generation = cell.generation });
        };
        self.retireClosedPublications();
        self.retireRequestStorageLocked();
        self.disposeJsReferences();
    }
    pub fn disposeTerminalReferences(self: *Runtime) void {
        if (self.notify_finalized and (self.publications == null or self.publications.?.diag.occupied == 0) and (self.requests == null or self.requests.?.diag.occupied == 0) and (self.incoming == null or self.incoming.?.diag.occupied == 0)) self.disposeJsReferences();
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
        self.retireClosedPublications();
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

    pub fn cancelCommandsLocked(self: *Runtime) void {
        for (&self.table.cells, 0..) |*cell, i| {
            switch (cell.state) {
                .queued, .executing, .waiting => {
                    self.table.cells[i].failure = self.terminal_error orelse error.NetworkClosed;
                    cell.state = .terminal;
                },
                else => {},
            }
        }
    }
    pub fn finishOwner(self: *Runtime, failure: ?anyerror) void {
        if (failure) |err| {
            if (err != error.AbortError) std.log.scoped(.network_runtime).err("owner_failed reason={s}", .{@errorName(err)});
            self.lock();
            if (self.reason != .failed) {
                self.terminal_error = err;
                self.reason = .failed;
            }
            self.unlock();
        }
        self.lock();
        self.destroyOwner();
        requests_mod.closeLocked(self);
        incoming_mod.closeLocked(self);
        gossip_mod.closeLocked(self);
        self.cancelCommandsLocked();
        if (self.publications) |*table| table.close(self.terminal_error orelse error.NetworkClosed);
        if (self.wake) |*wake| wake.deinit();
        self.wake = null;
        self.quiescent = true;
        self.retireStoresLocked();
        self.retireRequestStorageLocked();
        self.diag.state = if (self.reason == .failed) .failed else .closed;
        std.log.scoped(.network_runtime).info("owner_stopped reason={s} turns={d} operational_failures={d}", .{ @tagName(self.reason), self.diag.ownerTurns, self.diag.operationalFailures });
        self.pingLocked();
        const release_notify = self.notify_live;
        self.notify_live = false;
        self.unlock();
        if (release_notify) self.notify.release(.release) catch unreachable;
        faults.count(&faults.owners, false);
    }
    pub fn advanceSequence(self: *Runtime) !u64 {
        self.lock();
        defer self.unlock();
        return self.table.advance();
    }
    pub fn reservePublication(self: *Runtime, kind: n.gossipsub.topic.Kind, bytes: usize) !publications_mod.Token {
        self.lock();
        defer self.unlock();
        if (self.stop or self.quiescent) return error.NetworkClosed;
        const token = try self.publications.?.reserve(kind, bytes);
        self.retain();
        return token;
    }
    pub fn retirePublication(self: *Runtime, token: publications_mod.Token) void {
        self.lock();
        self.publications.?.retire(token);
        self.retireRequestStorageLocked();
        self.unlock();
        self.release();
    }
    fn retireClosedPublications(self: *Runtime) void {
        for (0..publications_mod.capacity_max) |i| {
            if (self.publications == null or i >= self.publications.?.cells.len) break;
            const cell = &self.publications.?.cells[i];
            if (cell.state == .free) continue;
            std.debug.assert(cell.state == .terminal);
            self.retirePublication(.{ .index = @intCast(i), .generation = cell.generation });
        }
    }
    pub fn reserveCommand(self: *Runtime, command: commands.Command) !commands.Token {
        self.lock();
        defer self.unlock();
        if (self.stop or self.quiescent) return error.NetworkClosed;
        const token = self.table.reserve(command) catch |err| {
            if (err == error.NetworkSequenceExhausted) {
                self.stop = true;
                self.reason = .failed;
                self.terminal_error = err;
                self.signalLocked();
            }
            return err;
        };
        self.retain();
        return token;
    }
    pub fn abortCommand(self: *Runtime, token: commands.Token) void {
        self.lock();
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
};

test {
    _ = commands;
    _ = publications_mod;
    _ = projection;
    _ = @import("network_peer_reports.zig");
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
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 100 }, .notify_live = false, .env_alive = false };
    const token = try runtime.table.reserve(.connect);
    runtime.table.get(token).state = .waiting;
    runtime.table.cells[token.index].input.peer = peer;
    runtime.table.cells[token.index].deadline = 2;
    try std.testing.expect(commands.latchConnects(&runtime.table, &events, .{ .mono_ms = 3, .unix_s = 0 }));
    try std.testing.expectEqual(commands.State.terminal, runtime.table.get(token).state);
    try std.testing.expect(runtime.table.cells[token.index].failure == null);
    try std.testing.expect(!commands.latchConnects(&runtime.table, &events, .{ .mono_ms = 4, .unix_s = 0 }));
    try std.testing.expect(runtime.table.cells[token.index].failure == null);
    runtime.table.retire(token);
}

test "stop preserves latched success and cancels accepted nonterminal commands" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 100 }, .notify_live = false, .env_alive = false };
    const success = try runtime.table.reserve(.getIdentity);
    const waiting = try runtime.table.reserve(.connect);
    const queued = try runtime.table.reserve(.getIdentity);
    const preparing = try runtime.table.reserve(.applyIntent);
    runtime.table.get(success).state = .terminal;
    runtime.table.get(waiting).state = .waiting;
    runtime.table.get(queued).state = .queued;
    runtime.cancelCommandsLocked();
    try std.testing.expect(runtime.table.cells[success.index].failure == null);
    try std.testing.expectEqual(error.NetworkClosed, runtime.table.cells[waiting.index].failure.?);
    try std.testing.expectEqual(error.NetworkClosed, runtime.table.cells[queued.index].failure.?);
    try std.testing.expectEqual(commands.State.preparing, runtime.table.get(preparing).state);
    for ([_]commands.Token{ success, waiting, queued, preparing }) |token| runtime.table.retire(token);
    try std.testing.expectEqual(@as(u8, 0), runtime.table.occupied);
}

test {
    _ = requests_mod;
    _ = @import("network_incoming.zig");
}

test "request table storage retires only after physical quiescence and final pins" {
    var runtime: Runtime = .{ .env = undefined, .diag = .{ .currentSlot = 0 } };
    runtime.payload_budget.limit = 32 + 2 * n.reqresp.Protocol.blocks_by_root_v2.info().response_max;
    runtime.requests = try requests_mod.Table.init(std.testing.allocator, 1, &runtime.payload_budget);
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
