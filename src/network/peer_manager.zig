const std = @import("std");
const service_mod = @import("service.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const control_mod = @import("peers/control.zig");
const dial_mod = @import("peers/dialing.zig");
const policy = peers.policy;
const engine_mod = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;
const coverage = @import("peers/coverage.zig");

pub const coverage_reconcile_interval_ms = 1_000;
pub const replacement_interval_ms = 5_000;

pub const Options = struct {
    peers: t.Options = .{},
    control: control_mod.Options = .{},
    dial: dial_mod.Options,
    metadata_freshness_ms: u64 = 60_000,
};
pub const DialIntent = dial_mod.DialIntent;
pub const MemoryPlan = struct {
    inline_bytes: usize,
    allocated_bytes: usize,
    catalog_bytes: usize,
    control_bytes: usize,
    dial_bytes: usize,
    scratch_bytes: usize,
    policy_bytes: usize,
};
pub const DiscoveryNeed = struct {
    general: bool = false,
    attnets: [8]u8 = @splat(0),
    syncnets: u8 = 0,
    custody: bool = false,

    /// Query lifetime bounds discovery work independently of the desired peer coverage.
    pub fn query(self: DiscoveryNeed, expires_ms: u64) peers.discovery.Demand {
        return .{ .general = self.general, .attnets = self.attnets, .syncnets = self.syncnets, .custody = self.custody, .expires_ms = expires_ms };
    }
};
const SelectionRevision = struct {
    catalog: u64,
    delivery: u64,
    gossip: [4]u64,

    fn cacheable(self: *const SelectionRevision) bool {
        for (self.gossip) |revision| if (revision == std.math.maxInt(u64)) return false;
        return self.catalog != std.math.maxInt(u64) and self.delivery != std.math.maxInt(u64);
    }
};

pub const PeerManager = struct {
    allocator: std.mem.Allocator,
    catalog: peers.Catalog,
    control: control_mod.Control,
    dialing: dial_mod.Dialing,
    local_identity: t.PeerId,
    local: t.LocalState,
    snapshot_scratch: []t.Snapshot,
    policy_scratch: []policy.Input,
    selection: policy.Result = .{},
    discovery_need: DiscoveryNeed = .{},
    demand: t.Demand = .{},
    selection_revision: ?SelectionRevision = null,
    reconciliation_deadline: ?u64 = null,
    custody_pending: bool = false,
    selection_deadline: ?u64 = null,
    coverage_reconcile_after_ms: u64 = 0,
    replacement_after_ms: u64 = 0,
    native_dial_room: u16 = 0,
    metadata_freshness_ms: u64,
    policy_seed: u64,
    stopped: bool = false,
    quiescing: bool = false,
    counters: Counters = .{},
    metrics_io: std.Io = std.Io.Threaded.global_single_threaded.io(),
    selection_duration: @import("metrics/timing.zig").Duration = .{},
    requested_connect: u64 = 0,
    requested_disconnect: [std.meta.fields(t.DisconnectReason).len]u64 = @splat(0),

    pub const Counters = struct {
        rejected: u64 = 0,
        gossip_refused: u64 = 0,
        displaced: u64 = 0,
        policy_disconnects: u64 = 0,
        custody_hashes: u64 = 0,
        selections: u64 = 0,
        selection_rows: u64 = 0,
        catalog_deadline_rows: u64 = 0,
        candidate_selections: u64 = 0,
    };
    pub const PeerCounts = struct { connected: u16, relevant: u16, outbound_relevant: u16 };

    pub const Diagnostics = struct {
        policy: Counters,
        connected: u16,
        relevant: u16,
        control: control_mod.Control.Counters,
        control_resources: control_mod.Control.Resources,
        dialing: dial_mod.Dialing.Resources,
        reqresp: rr.Counters,
        reqresp_resources: rr.ReqResp.Resources,
        gossip: gossip.Gossipsub.Counters,
        gossip_resources: gossip.ResourceSnapshot,
        score_calculations: u64,
        score_topic_visits: u64,
    };

    /// Returns copied observations without reconciliation, score refresh or event publication.
    pub fn diagnostics(self: *const PeerManager, service: *const service_mod.Service) Diagnostics {
        const g = service.gossipsub;
        return .{
            .policy = self.counters,
            .connected = self.catalog.connectedCount(),
            .relevant = self.catalog.relevantCount(),
            .control = self.control.counters,
            .control_resources = self.control.resourceSnapshot(),
            .dialing = self.dialing.resourceSnapshot(&self.catalog),
            .reqresp = service.reqresp.counters,
            .reqresp_resources = service.reqresp.resourceSnapshot(),
            .gossip = g.counters,
            .gossip_resources = g.resourceSnapshot(),
            .score_calculations = g.peers.scores.calculations,
            .score_topic_visits = g.peers.scores.topic_visits,
        };
    }

    pub fn validateOptions(options: Options) !void {
        try options.peers.validate();
        if (options.peers.target_peers >= options.peers.max_peers or
            options.dial.outbound_reserved > options.peers.max_peers - options.peers.target_peers) return error.InvalidOptions;
        if (options.metadata_freshness_ms == 0 or options.metadata_freshness_ms > 86_400_000) return error.InvalidOptions;
        try control_mod.Control.validateOptions(options.control);
        try dial_mod.Dialing.validateOptions(options.dial);
    }

    pub fn init(
        a: std.mem.Allocator,
        identity: *const t.PeerId,
        local: *const t.LocalState,
        options: Options,
        service: *const service_mod.Service,
        connections_max: u16,
    ) !PeerManager {
        var copied: t.LocalState = undefined;
        try peers.control_wire.copyServingLocal(&copied, local, service.router.capabilities().receive);
        try validateOptions(options);
        if (service.reqresp.options.outbound_control_reserved < options.peers.max_peers or
            service.router.negotiator.outbound_control_reserved < options.peers.max_peers)
            return error.InvalidOptions;
        var catalog = try peers.Catalog.initWithIntents(a, options.peers, options.dial.capacity, connections_max, options.dial.seed);
        errdefer catalog.deinit(a);
        var control = try control_mod.Control.init(
            a,
            options.control,
            @intCast(catalog.rows.len),
            options.peers.max_peers,
            service.reqresp.serving.control_reserved,
        );
        errdefer control.deinit(a);
        const dialing = try dial_mod.Dialing.init(options.dial);
        const scratch = try a.alloc(t.Snapshot, options.peers.capacity);
        errdefer a.free(scratch);
        const policy_scratch = try a.alloc(policy.Input, options.peers.max_peers);
        errdefer a.free(policy_scratch);
        return .{
            .allocator = a,
            .catalog = catalog,
            .control = control,
            .dialing = dialing,
            .local_identity = identity.*,
            .local = copied,
            .snapshot_scratch = scratch,
            .policy_scratch = policy_scratch,
            .metadata_freshness_ms = options.metadata_freshness_ms,
            .policy_seed = options.dial.seed,
        };
    }
    /// Call managed.shutdown with Service and Engine before releasing an active PeerManager.
    pub fn deinit(self: *PeerManager) void {
        self.allocator.free(self.policy_scratch);
        self.allocator.free(self.snapshot_scratch);
        self.control.deinit(self.allocator);
        self.catalog.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn memoryPlan(self: *const PeerManager) MemoryPlan {
        const catalog = self.catalog.memoryPlan().allocated_bytes;
        const control = self.control.memoryPlan().allocated_bytes;
        const dial = 0;
        const scratch = self.snapshot_scratch.len * @sizeOf(t.Snapshot);
        const policy_bytes = self.policy_scratch.len * @sizeOf(policy.Input);
        return .{
            .inline_bytes = @sizeOf(PeerManager),
            .allocated_bytes = catalog + control + dial + scratch + policy_bytes,
            .catalog_bytes = catalog,
            .control_bytes = control,
            .dial_bytes = dial,
            .scratch_bytes = scratch,
            .policy_bytes = policy_bytes,
        };
    }
    pub fn transportEvent(
        self: *PeerManager,
        service: *service_mod.Service,
        engine: *engine_mod.Engine,
        event: engine_mod.Event,
        now: Now,
    ) void {
        switch (event) {
            .connected => |connected| {
                if (self.quiescing) {
                    _ = engine.close(connected.conn, 0);
                    return;
                }
                const identity = connected.peer_id;
                const endpoint = engine.peerAddress(connected.conn) orelse return;
                const direction = connected.direction;
                self.dialing.syncAnswered(engine);
                const decision = self.catalog.admit(
                    &identity,
                    &self.local_identity,
                    connected.conn,
                    &.{
                        .direction = direction,
                        .endpoint = endpoint,
                        .now_ms = now.mono_ms,
                        .outbound_reserved = self.dialing.options.outbound_reserved,
                        .pending_dials = self.dialing.answeredPeers(&self.catalog, &identity),
                        .selected_dial = self.dialing.selectedPeer(&self.catalog, &identity, now.mono_ms),
                    },
                );
                switch (decision) {
                    .admitted => |admission| {
                        if (admission.displaced) |old| {
                            self.counters.displaced +|= 1;
                            self.control.cancelConnection(
                                service,
                                engine,
                                admission.peer,
                                old,
                            );
                            service.gossipsub.retireConnection(&service.router, engine, old, now);
                            _ = engine.close(old, 0);
                        }
                        self.control.connected(admission.peer, connected.conn, direction, now);
                        const direct = self.catalog.rowFor(admission.peer).?.direct;
                        const admission_result = service.gossipsub.peerConnected(engine, connected.conn, direct, now);
                        if (admission_result != .admitted) self.counters.gossip_refused +|= 1;
                        self.dialing.accepted(&self.catalog, admission.peer, connected.conn, now.mono_ms);
                    },
                    else => {
                        std.log.scoped(.network_peers).debug("peer_admission_refused peer={f} connection={d}:{d} reason={s}", .{ @import("logging.zig").peer(&identity), connected.conn.index, connected.conn.generation, @tagName(decision) });
                        self.counters.rejected +|= 1;
                        _ = self.dialing.deferConnection(&self.catalog, connected.conn, now.mono_ms);
                        _ = engine.close(connected.conn, 0);
                    },
                }
            },
            .closed => |closed| {
                _ = self.dialing.dialClosed(&self.catalog, closed.conn, closed.reason, now.mono_ms);
                if (self.catalog.findConnection(closed.conn)) |peer| {
                    const goodbye = service.reqresp.closingGoodbye(engine, closed.conn, now);
                    if (goodbye) |code| self.control.receivedGoodbye(&self.catalog, peer, closed.conn, code, now, true);
                    const snapshot = self.catalog.get(peer).?;
                    const reason = snapshot.disconnect_reason orelse if (goodbye != null) t.DisconnectReason.remote_goodbye else .transport_closed;
                    self.control.close(
                        service,
                        &self.catalog,
                        engine,
                        peer,
                        closed.conn,
                        reason,
                        now,
                    );
                }
            },
            .path_changed => |changed| {
                if (self.catalog.findConnection(changed.conn)) |peer| {
                    _ = self.catalog.updateEndpoint(peer, changed.conn, &changed.peer);
                }
            },
            else => {},
        }
    }
    fn catalogDeadline(self: *PeerManager, now_ms: u64) ?u64 {
        self.counters.catalog_deadline_rows +|= self.catalog.rows.len;
        return self.catalog.nextDeadline(now_ms);
    }
    /// Reconciles at the supplied clock without pumping protocols or borrowing an Engine.
    pub fn reconcile(self: *PeerManager, service: *service_mod.Service, now: Now) void {
        if (self.stopped or self.quiescing) return;
        self.catalog.refresh(now.mono_ms);
        const expired = if (self.reconciliation_deadline) |due| now.mono_ms >= due else false;
        if ((if (self.policyWakeup(service, now)) |due| now.mono_ms >= due else false) or expired) {
            self.refreshSelection(service, now);
            self.coverage_reconcile_after_ms = now.mono_ms +| coverage_reconcile_interval_ms;
            self.refreshDiscoveryNeed();
            const revision = self.currentSelectionRevision(service);
            self.selection_revision = if (revision.cacheable()) revision else null;
            const catalog_deadline = self.catalogDeadline(now.mono_ms);
            self.reconciliation_deadline = catalog_deadline;
            if (self.selection_deadline) |due| self.reconciliation_deadline = @min(self.reconciliation_deadline orelse due, due);
            self.dialing.selection_dirty = true;
        }
        if (self.dialing.selectionNeeded(&self.catalog) or (if (self.dialing.selection_deadline) |due| now.mono_ms >= due else false)) {
            self.counters.candidate_selections +|= 1;
            self.dialing.configureSelection(&self.catalog, &self.selection.deficits.missing, self.selection.retained_count < self.catalog.options.target_peers or self.selection.deficits.outbound > 0, &self.local.fork, now.mono_ms);
        }
    }
    fn currentSelectionRevision(self: *const PeerManager, service: *const service_mod.Service) SelectionRevision {
        return .{ .catalog = self.catalog.revision, .delivery = service.gossipsub.deliveryRevision(), .gossip = service.gossipsub.coverageRevision() };
    }
    pub fn policyWakeup(self: *const PeerManager, service: *const service_mod.Service, now: Now) ?u64 {
        const before = self.selection_revision orelse return now.mono_ms;
        const after = self.currentSelectionRevision(service);
        if (before.catalog != after.catalog or before.delivery != after.delivery) return now.mono_ms;
        if (!after.cacheable() or !std.meta.eql(before.gossip, after.gossip))
            return @max(now.mono_ms, self.coverage_reconcile_after_ms);
        return null;
    }
    pub fn updateNativeRoom(self: *PeerManager, engine: *const engine_mod.Engine) void {
        self.native_dial_room = engine.limits.connections_max -| engine.registry.active_len;
    }

    pub fn peerWakeup(self: *const PeerManager, now: Now, capacity: usize) ?u64 {
        if (capacity == 0) return null;
        if (self.catalog.eventsPending()) return now.mono_ms;
        return null;
    }
    pub fn setDemand(self: *PeerManager, demand: *const t.Demand) !void {
        if (self.stopped) return error.Stopped;
        try demand.validate(&self.local.fork, self.catalog.options.max_peers);
        if (std.meta.eql(self.demand, demand.*)) return;
        self.commitDemand(demand);
    }
    /// Requires demand validated against the local fork before publication.
    pub fn commitDemand(self: *PeerManager, demand: *const t.Demand) void {
        self.demand = demand.*;
        self.selection_revision = null;
    }
    /// Returns the last completed policy evaluation, shared with discoveryNeed.
    /// Call reconcile with an explicit clock to include pending input changes.
    pub fn coverageDeficits(self: *const PeerManager) policy.Deficits {
        return self.selection.deficits;
    }
    pub fn candidateHints(self: *const PeerManager, identity: *const t.PeerId, now: Now) ?peers.enr.Hints {
        return self.catalog.candidateHints(identity, now.mono_ms);
    }
    /// Returns the same completed evaluation as coverageDeficits without advancing policy.
    pub fn discoveryNeed(self: *const PeerManager) DiscoveryNeed {
        return self.discovery_need;
    }
    pub const DiscoveryIntake = struct { accepted: u16 = 0, refused: u16 = 0 };
    /// Requires Discovery.step output or equivalent authenticated-source scope authorization.
    pub fn discoveredBatch(self: *PeerManager, service: *service_mod.Service, candidates: []const peers.enr.Candidate, now: Now) DiscoveryIntake {
        std.debug.assert(candidates.len <= 16);
        self.reconcile(service, now);
        var result: DiscoveryIntake = .{};
        for (candidates) |*candidate| {
            self.enqueueDiscovered(candidate, now) catch {
                result.refused += 1;
                continue;
            };
            result.accepted += 1;
        }
        return result;
    }
    fn enqueueDiscovered(self: *PeerManager, candidate: *const peers.enr.Candidate, now: Now) !void {
        if (self.stopped) return error.Stopped;
        if (candidate.peer.eql(&self.local_identity)) return error.SelfDial;
        try self.dialing.enqueueDiscovered(&self.catalog, candidate, &self.local.fork, &self.selection.deficits.missing, now.mono_ms);
    }
    fn refreshSelection(self: *PeerManager, service: *service_mod.Service, now: Now) void {
        const timing = @import("metrics/timing.zig");
        const start = timing.now(self.metrics_io);
        defer self.selection_duration.observe(timing.now(self.metrics_io) -| start);
        self.counters.selections +|= 1;
        self.counters.selection_rows +|= self.catalog.rows.len;
        self.selection_deadline = null;
        const count = self.catalog.snapshots(self.snapshot_scratch);
        const local_subscriptions = service.gossipsub.overlay.subnetSubscriptions(null, self.local.fork.digest);
        var input_count: usize = 0;
        for (self.snapshot_scratch[0..count]) |*snapshot| {
            const conn = snapshot.connection orelse continue;
            if (snapshot.disconnect_reason != null) continue;
            std.debug.assert(input_count < self.policy_scratch.len);
            const input = &self.policy_scratch[input_count];
            input_count += 1;
            input.* = self.selectionInput(service, snapshot, conn, &local_subscriptions, now);
            const grace = snapshot.connected_at_ms +| self.control.options.inbound_status_grace_ms;
            if (input.reject == null and now.mono_ms < grace) {
                input.evaluating = true;
                self.selection_deadline = @min(self.selection_deadline orelse grace, grace);
            }
        }
        self.selection = policy.selectWithPacing(self.policy_scratch[0..input_count], &self.demand, self.catalog.options, self.policy_seed, now.mono_ms >= self.replacement_after_ms);
        self.requested_connect +|= self.selection.dial_budget;
        for (self.policy_scratch[0..input_count], 0..) |input, i| if (self.selection.reasons[i]) |reason| {
            self.requested_disconnect[@intFromEnum(reason)] +|= 1;
            if (self.disconnect(input.peer, reason, now)) self.counters.policy_disconnects +|= 1;
            if (reason == .count_pruning) self.replacement_after_ms = now.mono_ms +| replacement_interval_ms;
        };
        if (now.mono_ms < self.replacement_after_ms)
            self.selection_deadline = @min(self.selection_deadline orelse self.replacement_after_ms, self.replacement_after_ms);
    }

    fn selectionInput(
        self: *PeerManager,
        service: *service_mod.Service,
        snapshot: *const t.Snapshot,
        conn: t.Handle,
        local_subscriptions: *const gossip.topic_policy.Subnets,
        now: Now,
    ) policy.Input {
        var input: policy.Input = .{
            .peer = snapshot.peer,
            .direct = snapshot.direct,
            .outbound = snapshot.direction == .outbound,
            .relevant = snapshot.relevant,
            .revalidating = self.control.revalidationDeadline(snapshot.peer, conn, now) != null,
            .ready = false,
            .score = peers.reputation.selectionScore(
                snapshot.score,
                self.gossipScore(service, snapshot.peer, now) orelse 0,
                service.gossipsub.options.score_params.graylist_threshold,
            ),
        };
        if (snapshot.ban_until_ms > now.mono_ms or snapshot.score <= peers.reputation.ban_score)
            input.reject = .banned;
        if (snapshot.status) |status| {
            if (!std.mem.eql(u8, &status.fork_digest, &self.local.fork.digest))
                input.reject = .incompatible_fork;
            if (self.local.fork.fork.gte(.fulu) and status.earliest_available_slot == null)
                input.reject = .missing_availability;
        }
        const delivery = service.gossipsub.deliveryStatus(conn);
        if (delivery == .unavailable) {
            if (!input.revalidating) input.outbound = false;
            if (snapshot.relevant and !snapshot.direct and input.reject == null)
                input.reject = .gossip_unavailable;
        }
        if (self.control.revalidationDeadline(snapshot.peer, conn, now)) |deadline|
            self.selection_deadline = @min(self.selection_deadline orelse deadline, deadline);
        if ((!snapshot.relevant and !input.revalidating) or input.reject != null) return input;
        const subscriptions = service.gossipsub.coverageSubscriptions(conn, self.local.fork.digest, local_subscriptions, now);
        input.coverage = coverage.gossip(&subscriptions, &self.local.fork);
        const metadata = snapshot.metadata orelse return input;
        peers.control_wire.validateMetadata(&metadata, self.local.fork) catch return input;
        const deadline = snapshot.metadata_at_ms +| self.metadata_freshness_ms;
        if (now.mono_ms >= deadline) return input;
        self.selection_deadline = @min(self.selection_deadline orelse deadline, deadline);
        if (delivery == .available) {
            input.ready = !self.local.fork.fork.gte(.fulu) or snapshot.sampling_groups != null;
            input.stable = coverage.stable(&input.coverage, &metadata, snapshot.sampling_groups);
        }
        if (self.local.fork.fork.gte(.fulu) and snapshot.score >= peers.reputation.prune_score and
            (service.gossipsub.scoreSnapshot(conn, now) orelse 0) >= 0)
            input.coverage.custody_groups = snapshot.custody_groups orelse .initEmpty();
        return input;
    }
    fn refreshDiscoveryNeed(self: *PeerManager) void {
        self.discovery_need = .{};
        self.discovery_need.general = self.selection.retained_count < self.catalog.options.target_peers or
            self.selection.deficits.outbound > 0;
        std.mem.writeInt(u64, &self.discovery_need.attnets, self.selection.deficits.missing.attnets, .little);
        self.discovery_need.syncnets = self.selection.deficits.missing.syncnets;
        self.discovery_need.custody = self.selection.deficits.groups > 0 or self.selection.deficits.custody_groups > 0;
    }
    pub fn dialRoom(self: *const PeerManager) u16 {
        const attempts = self.dialing.attempts();
        const pending = self.dialing.pendingPeers(&self.catalog, null);
        const capacity = self.catalog.options.max_peers -| self.catalog.connectedCount() -| pending;
        const wanted = @max(self.selection.dial_budget, self.dialing.hostDemand(&self.catalog)) -| pending;
        return @min(self.native_dial_room -| attempts.unstarted, capacity, wanted);
    }
    pub fn updateStatus(self: *PeerManager, service: *const service_mod.Service, status: *const t.Status) !void {
        var local = self.local;
        local.status = status.*;
        try peers.control_wire.copyServingLocal(&self.local, &local, service.router.capabilities().receive);
        self.selection_revision = null;
    }

    /// The caller must validate the complete local state before committing it.
    pub fn commitLocal(self: *PeerManager, service: *service_mod.Service, local: *const t.LocalState, now: Now) void {
        if (!std.meta.eql(self.local.fork, local.fork)) {
            self.control.forkUpdated(service, &self.catalog, self.local.fork, now);
        }
        self.local = local.*;
        service.reqresp.setRequestFork(local.fork.fork);
        for (self.local.fork.custody_groups..128) |index| {
            self.demand.group_targets[index] = 0;
            self.demand.custody_group_targets[index] = 0;
        }
        var budget: u16 = 0;
        _ = self.catalog.advanceCustody(&self.local.fork, now.mono_ms, self.metadata_freshness_ms, &budget);
        self.selection_revision = null;
    }
    pub fn reStatusPeer(self: *PeerManager, peer: t.PeerRef, connection: t.Handle, now: Now) bool {
        if (self.stopped) return false;
        return self.control.reStatusPeer(peer, connection, now);
    }
    pub fn reStatusPeers(self: *PeerManager, now: Now) void {
        self.control.reStatusPeers(now);
    }
    pub fn reportPeer(
        self: *PeerManager,
        peer: t.PeerRef,
        action: t.PeerAction,
        now: Now,
    ) ?t.ReputationDecision {
        const decision = self.catalog.report(peer, action, now.mono_ms) orelse return null;
        self.selection_revision = null;
        if (decision != .none) _ = self.disconnect(
            peer,
            if (decision == .ban) .banned else .reputation,
            now,
        );
        return decision;
    }
    pub fn connect(
        self: *PeerManager,
        identity: *const t.PeerId,
        addresses: []const t.Address,
        now: Now,
    ) !void {
        return self.connectUntil(identity, addresses, now, now.mono_ms +| dial_mod.connect_timeout_ms);
    }
    pub fn connectUntil(self: *PeerManager, identity: *const t.PeerId, addresses: []const t.Address, now: Now, deadline_ms: u64) !void {
        if (self.stopped) return error.Stopped;
        if (identity.eql(&self.local_identity)) return error.SelfDial;
        try self.dialing.enqueueUntil(&self.catalog, identity, addresses, false, now.mono_ms, deadline_ms);
        self.selection_revision = null;
    }
    pub fn cancelConnect(self: *PeerManager, engine: *engine_mod.Engine, identity: *const t.PeerId, now: Now) void {
        self.dialing.cancelConnect(&self.catalog, engine, identity, now.mono_ms);
        self.selection_revision = null;
    }
    pub fn addDirectPeer(
        self: *PeerManager,
        service: *service_mod.Service,
        identity: *const t.PeerId,
        addresses: []const t.Address,
        now: Now,
    ) !void {
        if (self.stopped) return error.Stopped;
        if (identity.eql(&self.local_identity)) return error.SelfDial;
        const already_direct = if (self.catalog.find(identity)) |peer| self.catalog.rowFor(peer).?.direct else false;
        if (!already_direct and self.catalog.direct_count >= self.catalog.options.target_peers - self.catalog.options.min_outbound)
            return error.DirectPeerCapacity;
        try self.dialing.enqueue(&self.catalog, identity, addresses, true, now.mono_ms);
        self.selection_revision = null;
        if (self.catalog.find(identity)) |peer| {
            _ = self.catalog.setDirect(peer, true);
            if (self.catalog.rowFor(peer).?.connection) |conn| service.gossipsub.markDirect(conn);
        }
    }
    pub fn directPeers(self: *const PeerManager, out: []t.PeerId) error{OutputTooSmall}!usize {
        return self.catalog.directPeers(out);
    }
    pub fn removeDirectPeer(self: *PeerManager, service: *service_mod.Service, identity: *const t.PeerId) bool {
        const peer = self.catalog.find(identity) orelse return false;
        if (!self.catalog.rowFor(peer).?.direct) return false;
        _ = self.catalog.setDirect(peer, false);
        self.selection_revision = null;
        service.gossipsub.unmarkDirect(identity);
        return true;
    }
    pub fn closePeer(self: *PeerManager, service: *service_mod.Service, engine: *engine_mod.Engine, peer: t.PeerRef, connection: t.Handle, now: Now) bool {
        if (self.stopped) return false;
        const snapshot = self.catalog.get(peer) orelse return false;
        if (!std.meta.eql(snapshot.connection, connection)) return false;
        self.control.close(service, &self.catalog, engine, peer, connection, .host, now);
        self.dialing.cancelConnect(&self.catalog, engine, &snapshot.identity, now.mono_ms);
        self.selection_revision = null;
        return true;
    }
    pub fn disconnect(self: *PeerManager, peer: t.PeerRef, reason: t.DisconnectReason, now: Now) bool {
        const snapshot = self.catalog.get(peer) orelse return false;
        return self.control.disconnect(
            &self.catalog,
            peer,
            snapshot.connection orelse return false,
            reason,
            now,
        );
    }
    pub fn dialIntents(
        self: *PeerManager,
        service: *service_mod.Service,
        engine: *engine_mod.Engine,
        now: Now,
        out: []dial_mod.DialIntent,
    ) usize {
        if (self.stopped) return 0;
        self.dialing.expire(&self.catalog, engine, now.mono_ms);
        self.reconcile(service, now);
        self.updateNativeRoom(engine);
        const count = self.dialing.poll(&self.catalog, now.mono_ms, out[0..@min(out.len, self.dialRoom())]);
        if (count > 0 and self.selection.retained_count >= self.catalog.options.target_peers and self.selection.deficits.outbound == 0) {
            self.replacement_after_ms = now.mono_ms +| replacement_interval_ms;
            self.selection_revision = null;
        }
        return count;
    }
    pub fn dialStarted(self: *PeerManager, token: dial_mod.Token, conn: t.Handle) bool {
        return self.dialing.dialStarted(token, conn);
    }
    pub fn dialDeferred(self: *PeerManager, token: dial_mod.Token, now: Now) bool {
        return self.dialing.dialDeferred(&self.catalog, token, now.mono_ms);
    }
    pub fn dialFailed(self: *PeerManager, token: dial_mod.Token, now: Now) bool {
        return self.dialing.dialFailed(&self.catalog, token, now.mono_ms);
    }
    pub fn snapshots(self: *const PeerManager, out: []t.Snapshot) usize {
        return self.catalog.snapshots(out);
    }
    pub fn peerCounts(self: *const PeerManager) PeerCounts {
        var result: PeerCounts = .{ .connected = 0, .relevant = 0, .outbound_relevant = 0 };
        for (self.catalog.rows) |row| {
            if (!row.occupied or row.connection == null) continue;
            result.connected += 1;
            if (row.status == null) continue;
            result.relevant += 1;
            if (row.direction == .outbound) result.outbound_relevant += 1;
        }
        return result;
    }
    pub fn gossipScore(self: *PeerManager, service: *service_mod.Service, peer: t.PeerRef, now: Now) ?f64 {
        const snapshot = self.catalog.get(peer) orelse return null;
        return service.gossipsub.scoreSnapshot(
            snapshot.connection orelse return null,
            now,
        );
    }
};
