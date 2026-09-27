const std = @import("std");
const n = @import("network");
const d = @import("discv5");
const napi = @import("zapi:zapi").napi;
pub const gossip_mod = @import("network_gossip.zig");
pub const incoming_mod = @import("network_incoming.zig");
pub const requests_mod = @import("network_requests.zig");
pub const publications_mod = @import("network_publications.zig");
pub const commands = @import("network_commands.zig");
pub const application_config = @import("network_application_config.zig");
pub const projection = @import("network_peer_projection.zig");
const Wake = @import("network_wake.zig").Wake;
const readiness_mod = @import("network_readiness.zig");
pub const Row = readiness_mod.Row;
pub const Place = readiness_mod.Place;
pub const Owner = @import("network_owner.zig").Owner;
pub const allocator = std.heap.c_allocator;
pub const State = enum { running, stopping, closed, failed };
pub const Reason = enum { requested, failed };
pub const Notify = napi.ThreadSafeFunction(Runtime, void);
pub const bridge = n.metrics.bridge;
var runtime_live = std.atomic.Value(bool).init(false);

/// A JS-thread native call, timed from `call` to `end`.
pub const Call = struct {
    runtime: ?*Runtime,
    entry: bridge.Entry,
    started_ns: u64,

    pub fn end(self: Call) void {
        if (self.runtime) |runtime| runtime.bridge.calls[@intFromEnum(self.entry)].observe(bridge.now() -| self.started_ns);
    }
};

pub fn call(runtime: ?*Runtime, entry: bridge.Entry) Call {
    return .{ .runtime = runtime, .entry = entry, .started_ns = bridge.now() };
}

/// Claims the one live runtime per process. The last `Runtime.release` returns the claim, also after a failed initialization.
pub fn create(env: napi.Env) !*Runtime {
    if (runtime_live.swap(true, .acq_rel)) return error.NetworkAlreadyInitialized;
    errdefer runtime_live.store(false, .release);
    const runtime = try allocator.create(Runtime);
    runtime.* = .{ .env = env, .diag = .{ .currentSlot = 0 } };
    return runtime;
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
    operationalFailures: u64 = 0,
    operationOccupied: u8 = 0,
    peerReportsIgnored: u64 = 0,
    connectOccupied: u8 = 0,
    preparingPins: u16 = 0,
    copyingPins: u16 = 0,
    peerLaneOccupied: u8 = 0,
    ownerSequence: u64 = 0,
    liveNativeRequestedBytes: usize = 0,
    liveBridgeRequestedBytes: usize = 0,
    typedStoreBytes: usize = 0,
    metricsExportBytes: usize = 0,
    peerLaneBytes: usize = 0,
    ownerShellBytes: usize = @sizeOf(Runtime),
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
    payloadBudget: @import("network_budget.zig").Diagnostics = .{},
    bridgeRequestedBytes: usize = @sizeOf(Runtime) + @sizeOf(Owner) - @sizeOf(n.NetworkCore),
};

/// A remembered peers snapshot and the network it belongs to.
pub const RememberedPage = struct {
    genesis_root: [32]u8,
    records: [n.peers.remembered.capacity]n.peers.remembered.Record,
};

/// The host's standing capacities: serving starts it can take now, and whether it executes ordinary gossip.
pub const Capacity = struct { serving: u32 = 0, ordinary: bool = false };

pub const Stores = struct {
    backing: std.mem.Allocator,
    intents: [2]application_config.Intent = undefined,
    snapshots: [2][]n.peers.types.Snapshot,
    gossip_diagnostics: [2]n.gossipsub.diagnostics.Page = undefined,
    direct: [2][256]n.PeerId = undefined,
    targets: [2][256]n.PeerId = undefined,
    remembered: [2]RememberedPage = undefined,
    pub fn create(backing: std.mem.Allocator, capacity: usize) !*Stores {
        const self = try backing.create(Stores);
        errdefer backing.destroy(self);
        self.* = .{ .backing = backing, .snapshots = undefined };
        self.snapshots[0] = try backing.alloc(n.peers.types.Snapshot, capacity);
        errdefer backing.free(self.snapshots[0]);
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
    bridge: bridge.Recorder = .{},
    metrics_due_ms: u64 = 0,
    health_log_due_ms: u64 = 0,
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
    peer_capacity: u16 = 0,
    max_peers: u16 = 0,

    wake: ?Wake = null,
    thread: ?std.Thread = null,
    notify: Notify = undefined,
    notify_live: bool = true,
    notify_finalized: bool = false,
    readiness: readiness_mod.Readiness = .{},
    capacity: Capacity = .{},
    /// JS thread: an exchange is running, so a nested one is refused.
    in_exchange: bool = false,
    /// The exchange results created at initialize, which idle exchanges and rollbacks return.
    results: @import("network_exchange.zig").Results = .{},
    /// Owner thread: an event capture left host work for the next apply, so the next turn is due now.
    host_due: bool = false,
    /// The owner leaves reported verdicts unapplied while an ownership test holds them.
    verdicts_held: bool = false,
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
                    self.captureBridgeLocked(&heavy.bridge);
                    var context = n.metrics.Context.init(&heavy.core, @import("network_owner.zig").now(heavy.threaded.io()), false);
                    context.bridge = &heavy.bridge;
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
    /// Copies the bridge measurements and the tables' exported state for one render.
    pub fn captureBridgeLocked(self: *const Runtime, into: *bridge.Snapshot) void {
        self.bridge.snapshot(into);
        if (self.gossip) |*table| into.captureProcessor(table);
    }
    pub fn lock(self: *Runtime) void {
        std.Io.Threaded.mutexLock(&self.mutex);
    }
    pub fn unlock(self: *Runtime) void {
        // A payload release while the owner waits for budget wakes it to retry.
        if (self.payload_budget.released) {
            self.payload_budget.released = false;
            self.signalLocked();
        }
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
            std.crypto.secureZero(u8, std.mem.asBytes(self));
            allocator.destroy(self);
            const claimed = runtime_live.swap(false, .release);
            std.debug.assert(claimed);
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
        self.refreshLocked();
    }
    pub fn signalLocked(self: *Runtime) void {
        if (self.wake) |*wake| wake.signal() catch self.failLocked(error.NetworkWakeFailed);
    }
    /// Stops the owner for a terminal failure. The first one is the close result's error, also after a requested
    /// stop began.
    pub fn failLocked(self: *Runtime, err: anyerror) void {
        self.stop = true;
        if (self.reason == .failed) return;
        self.reason = .failed;
        self.terminal_error = err;
        self.diag.state = .failed;
    }
    pub fn snapshot(self: *Runtime) !Diagnostics {
        self.lock();
        defer self.unlock();
        var result = self.diag;
        result.terminal_error = if (self.reason == .failed) self.terminal_error else null;
        result.operationOccupied = self.table.occupied;
        result.peerReportsIgnored = self.reports.ignored;
        result.connectOccupied = self.table.connects;
        result.ownerSequence = self.table.sequence;
        for (&self.table.cells) |*cell| {
            result.preparingPins += @intFromBool(cell.state == .preparing);
            result.copyingPins += @intFromBool(cell.state == .copying);
        }
        if (self.lane) |lane| {
            result.peerLaneOccupied = lane.len;
            result.peerLaneBytes = @sizeOf(projection.Lane);
        }
        if (self.stores != null) result.typedStoreBytes = Stores.bytes(self.peer_capacity);
        result.payloadBudget = self.payload_budget.snapshot();
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
            result.gossip.publicationCopies = result.publications.copies;
            result.gossip.publicationQueued = result.publications.queued;
            result.gossip.publicationSelected = result.publications.selected;
            result.gossip.publicationDuplicates = result.publications.duplicates;
        }
        return result;
    }
    /// Where `row` belongs now. Neither checks nor serving starts are served after a stop, no claim after
    /// quiescence, and nothing once the close result settled, so a host may stop exchanging.
    pub fn wantLocked(self: *Runtime, row: Row) Place {
        switch (row) {
            .legacy => return if (self.settleableLocked() or self.acknowledgingLocked() or (self.quiescent and !self.close_settled)) .control else .none,
            .peers => return if (!self.close_settled and self.lane != null and self.lane.?.len > 0) .payload else .none,
            .checks => {
                const table = if (self.gossip) |*table| table else return .none;
                return if (!self.stop and !self.quiescent and table.readiness().checks) .payload else .none;
            },
            .serving => {
                const table = if (self.incoming) |*table| table else return .none;
                if (self.stop or self.quiescent or table.oldest() == null) return .none;
                return if (self.capacity.serving > 0) .payload else .parked;
            },
            .gossip => {
                const table = if (self.gossip) |*table| table else return .none;
                if (self.quiescent) return .none;
                const work = table.readiness();
                if (work.urgent or (work.ordinary and self.capacity.ordinary)) return .payload;
                return if (work.ordinary) .parked else .none;
            },
        }
    }
    /// Moves `row` to where it belongs, notifying the host when the move disarms.
    pub fn recomputeLocked(self: *Runtime, row: Row) void {
        if (self.readiness.recompute(row, self.wantLocked(row))) self.notifyLocked();
    }
    pub fn refreshLocked(self: *Runtime) void {
        inline for (@typeInfo(Row).@"enum".fields) |field| self.recomputeLocked(@enumFromInt(field.value));
    }
    pub fn notifyLocked(self: *Runtime) void {
        if (!self.notify_live or !self.env_alive) return;
        self.notify.call(undefined, .non_blocking) catch |err| switch (err) {
            // An undequeued notification remains, and its exchange sees this work.
            error.QueueFull => {},
            error.Closing => {
                self.notify_live = false;
                self.stop = true;
            },
            else => self.failLocked(err),
        };
    }
    /// An owner disposition of a delivered message that an exchange would acknowledge now. O(1).
    pub fn acknowledgingLocked(self: *const Runtime) bool {
        return if (self.gossip) |*table| table.diag.acknowledging > 0 else false;
    }
    /// A command, request or incoming result an exchange would settle, or a publication completion it would deliver,
    /// now. O(1).
    pub fn settleableLocked(self: *const Runtime) bool {
        return self.table.anyTerminal() or
            (if (self.publications) |*table| table.anyTerminal() else false) or
            (if (self.requests) |*table| table.anyDue(self.stop, self.disposed) else false) or
            (if (self.incoming) |*table| table.anyDue() else false);
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
    /// Stops the owner at once and joins it, without disposing of what JavaScript can still settle.
    pub fn abandon(self: *Runtime) void {
        self.lock();
        self.graceful = false;
        self.unlock();
        self.requestStop();
        self.join();
    }
    pub fn forceStop(self: *Runtime, env_dying: bool) void {
        self.lock();
        self.disposed = true;
        if (env_dying) self.env_alive = false;
        self.unlock();
        self.abandon();
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
    /// The host's drain can settle the close result after the notifier finalizes, so its
    /// references outlive the notifier until close settles or the runtime is disposed.
    pub fn disposeTerminalReferences(self: *Runtime) void {
        if (!self.notify_finalized or self.table.occupied != 0 or (self.publications != null and self.publications.?.diag.occupied != 0) or (self.requests != null and self.requests.?.diag.occupied != 0) or (self.incoming != null and self.incoming.?.diag.occupied != 0)) return;
        if (self.copy_error) |ref| ref.delete() catch unreachable;
        self.copy_error = null;
        if (self.close_settled) self.disposeCloseReferences();
    }
    pub fn disposeJsReferences(self: *Runtime) void {
        if (self.copy_error) |ref| ref.delete() catch unreachable;
        self.copy_error = null;
        self.disposeCloseReferences();
        self.results.dispose();
    }
    pub fn disposeCloseReferences(self: *Runtime) void {
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
        if (self.disposed) self.retireClosedRequests() else self.disposeTerminalReferences();
        self.release();
    }

    pub fn cancelCommandsLocked(self: *Runtime) void {
        for (&self.table.cells, 0..) |*cell, i| {
            switch (cell.state) {
                .queued, .executing, .waiting => {
                    self.table.cells[i].failure = self.terminal_error orelse error.NetworkClosed;
                    self.table.transition(cell, .terminal);
                },
                else => {},
            }
        }
    }
    pub fn finishOwner(self: *Runtime, failure: ?anyerror) void {
        if (failure) |err| {
            if (err != error.AbortError) std.log.scoped(.network_runtime).err("owner_failed reason={s}", .{@errorName(err)});
            self.lock();
            self.failLocked(err);
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
        // Every host sees quiescence, also one whose waiting payload left it disarmed or one already collected.
        self.readiness.armed = false;
        self.refreshLocked();
        self.notifyLocked();
        const release_notify = self.notify_live;
        self.notify_live = false;
        self.unlock();
        if (release_notify) self.notify.release(.release) catch unreachable;
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
                self.failLocked(err);
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
        self.table.transition(self.table.get(token), .queued);
        self.signalLocked();
    }
};

test {
    _ = @import("network_runtime_test.zig");
}
