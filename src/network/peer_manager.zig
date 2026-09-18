const std = @import("std");
const service_mod = @import("service.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const control_mod = @import("peers/control.zig");
const dial_mod = @import("peers/dial_queue.zig");
const policy = peers.policy;
const engine_mod = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;

pub const Options = struct {
    peers: t.Options = .{},
    control: control_mod.Options = .{},
    dial: dial_mod.Options,
    metadata_freshness_ms: u64 = 60_000,
};
pub const DialIntent = dial_mod.DialIntent;
pub const DialToken = dial_mod.Token;
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

    /// Query lifetime is a host/runtime monotonic scheduling decision, independent of slot expiry.
    pub fn query(self: DiscoveryNeed, expires_ms: u64) peers.discovery.Demand {
        return .{ .general = self.general, .attnets = self.attnets, .syncnets = self.syncnets, .custody = self.custody, .expires_ms = expires_ms };
    }
};
const SelectionRevision = struct {
    catalog: u64,
    delivery: u64,

    fn cacheable(self: *const SelectionRevision) bool {
        return self.catalog != std.math.maxInt(u64) and self.delivery != std.math.maxInt(u64);
    }
};

pub const PeerManager = struct {
    allocator: std.mem.Allocator,
    catalog: peers.Catalog,
    control: control_mod.Control,
    dial_queue: dial_mod.DialQueue,
    local_identity: t.PeerId,
    local: t.LocalState,
    snapshot_scratch: []t.Snapshot,
    policy_scratch: []policy.Input,
    selection: policy.Result = .{},
    discovery_need: DiscoveryNeed = .{},
    demand: t.Demand = .{},
    current_slot: u64 = 0,
    selection_revision: ?SelectionRevision = null,
    candidates_revision: ?u64 = null,
    reconciliation_deadline: ?u64 = null,
    custody_pending: bool = false,
    selection_deadline: ?u64 = null,
    native_dial_room: u16 = 0,
    metadata_freshness_ms: u64,
    policy_seed: u64,
    stopped: bool = false,
    quiescing: bool = false,
    counters: Counters = .{},

    pub const Counters = struct {
        rejected: u64 = 0,
        gossip_refused: u64 = 0,
        displaced: u64 = 0,
        policy_disconnects: u64 = 0,
        custody_hashes: u64 = 0,
        selections: u64 = 0,
        selection_rows: u64 = 0,
        candidate_syncs: u64 = 0,
        candidate_rows: u64 = 0,
        candidate_lookup_rows: u64 = 0,
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
        dialing: dial_mod.DialQueue.Resources,
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
            .dialing = self.dial_queue.resourceSnapshot(),
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
        if (options.metadata_freshness_ms == 0 or options.metadata_freshness_ms > 86_400_000) return error.InvalidOptions;
        try control_mod.Control.validateOptions(options.control);
        try dial_mod.DialQueue.validateOptions(options.dial);
    }

    pub fn init(
        a: std.mem.Allocator,
        identity: *const t.PeerId,
        local: *const t.LocalState,
        options: Options,
        service: *const service_mod.Service,
    ) !PeerManager {
        var copied: t.LocalState = undefined;
        try peers.control_wire.copyLocal(&copied, local);
        try validateOptions(options);
        if (service.reqresp.options.outbound_control_reserved < options.peers.max_peers or
            service.router.negotiator.outbound_control_reserved < options.peers.max_peers)
            return error.InvalidOptions;
        var catalog = try peers.Catalog.init(a, options.peers);
        errdefer catalog.deinit(a);
        var control = try control_mod.Control.init(
            a,
            options.control,
            options.peers.capacity,
            options.peers.max_peers,
            @intCast(service.reqresp.inbound.len),
        );
        errdefer control.deinit(a);
        var dial_queue = try dial_mod.DialQueue.init(a, options.dial);
        errdefer dial_queue.deinit(a);
        const scratch = try a.alloc(t.Snapshot, options.peers.capacity);
        errdefer a.free(scratch);
        const policy_scratch = try a.alloc(policy.Input, options.peers.max_peers);
        errdefer a.free(policy_scratch);
        return .{
            .allocator = a,
            .catalog = catalog,
            .control = control,
            .dial_queue = dial_queue,
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
        self.dial_queue.deinit(self.allocator);
        self.control.deinit(self.allocator);
        self.catalog.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn memoryPlan(self: *const PeerManager) MemoryPlan {
        const catalog = self.catalog.memoryPlan().allocated_bytes;
        const control = self.control.memoryPlan().allocated_bytes;
        const dial = self.dial_queue.memoryPlan().allocated_bytes;
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
                const decision = self.catalog.admit(
                    &identity,
                    &self.local_identity,
                    connected.conn,
                    &.{ .direction = direction, .endpoint = endpoint, .now_ms = now.mono_ms },
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
                        _ = self.catalog.setDirect(
                            admission.peer,
                            self.dial_queue.isDirect(&identity),
                        );
                        const admission_result = service.gossipsub.peerConnected(engine, connected.conn, now);
                        if (admission_result != .admitted) self.counters.gossip_refused +|= 1;
                        if (self.dial_queue.isDirect(&identity)) service.gossipsub.markDirect(connected.conn);
                        self.dial_queue.accepted(&identity, connected.conn, now.mono_ms);
                    },
                    else => {
                        std.log.scoped(.network_peers).debug("peer_admission_refused peer={f} connection={d}:{d} reason={s}", .{ @import("logging.zig").peer(&identity), connected.conn.index, connected.conn.generation, @tagName(decision) });
                        self.counters.rejected +|= 1;
                        _ = engine.close(connected.conn, 0);
                    },
                }
            },
            .closed => |closed| {
                _ = self.dial_queue.dialClosed(closed.conn, now.mono_ms);
                if (self.control.peerFor(closed.conn)) |peer| {
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
                    self.dial_queue.disconnected(&snapshot.identity, snapshot.connected_at_ms, reason, now.mono_ms);
                }
            },
            .path_changed => |changed| {
                if (self.control.peerFor(changed.conn)) |peer| {
                    _ = self.catalog.updateEndpoint(peer, changed.conn, &changed.peer);
                }
            },
            else => {},
        }
    }
    fn refreshCandidates(self: *PeerManager, now: Now, catalog_deadline: ?u64) void {
        if (self.candidates_revision == self.catalog.revision and self.catalog.revision != std.math.maxInt(u64)) return;
        self.counters.candidate_syncs +|= 1;
        self.counters.candidate_rows +|= self.catalog.rows.len;
        const count = self.catalog.snapshots(self.snapshot_scratch);
        for (self.snapshot_scratch[0..count]) |*snapshot| self.syncCandidate(snapshot, now, catalog_deadline);
        self.candidates_revision = self.catalog.revision;
    }
    fn candidateBlocked(snapshot: *const t.Snapshot, now_ms: u64) bool {
        return snapshot.ban_until_ms > now_ms or snapshot.score <= -50 or snapshot.goodbye_until_ms > now_ms;
    }
    fn syncCandidate(self: *PeerManager, snapshot: *const t.Snapshot, now: Now, catalog_deadline: ?u64) void {
        const eligible_at_ms: ?u64 = if (candidateBlocked(snapshot, now.mono_ms))
            @max(catalog_deadline orelse now.mono_ms +| 1_000, snapshot.goodbye_until_ms)
        else
            null;
        self.dial_queue.synchronize(snapshot, now.mono_ms, eligible_at_ms);
    }
    fn catalogDeadline(self: *PeerManager, now_ms: u64) ?u64 {
        self.counters.catalog_deadline_rows +|= self.catalog.rows.len;
        return self.catalog.nextDeadline(now_ms);
    }
    fn syncIdentity(self: *PeerManager, identity: *const t.PeerId, now: Now) void {
        for (self.catalog.rows, 0..) |*row, index| {
            if (!row.occupied or !row.identity.eql(identity)) continue;
            self.counters.candidate_lookup_rows +|= index + 1;
            const snapshot = self.catalog.get(.{ .index = @intCast(index), .generation = row.generation }).?;
            const deadline = if (candidateBlocked(&snapshot, now.mono_ms)) self.catalogDeadline(now.mono_ms) else null;
            self.syncCandidate(&snapshot, now, deadline);
            return;
        }
        self.counters.candidate_lookup_rows +|= self.catalog.rows.len;
    }
    /// Reconciles at the supplied clock without pumping protocols or borrowing an Engine.
    /// Health only ranks removals. Once pruned, changing health alone cannot remove
    /// a retained peer while count, coverage and protection remain unchanged.
    pub fn reconcile(self: *PeerManager, service: *service_mod.Service, now: Now) void {
        if (self.stopped or self.quiescing) return;
        self.catalog.refresh(now.mono_ms);
        const expired = if (self.reconciliation_deadline) |due| now.mono_ms >= due else false;
        if (expired) self.candidates_revision = null;
        if (self.policyChanged(service) or expired) {
            self.refreshSelection(service, now);
            self.refreshDiscoveryNeed();
            const revision = self.currentSelectionRevision(service);
            self.selection_revision = if (revision.cacheable()) revision else null;
            const catalog_deadline = self.catalogDeadline(now.mono_ms);
            self.reconciliation_deadline = catalog_deadline;
            if (self.selection_deadline) |due| self.reconciliation_deadline = @min(self.reconciliation_deadline orelse due, due);
            self.dial_queue.selection_dirty = true;
            self.refreshCandidates(now, catalog_deadline);
        }
        if (self.dial_queue.selection_dirty or (if (self.dial_queue.selection_deadline) |due| now.mono_ms >= due else false)) {
            self.counters.candidate_selections +|= 1;
            self.dial_queue.configureSelection(&self.selection.deficits.missing, self.selection.retained_count < self.catalog.options.target_peers or self.selection.deficits.outbound > 0, &self.local.fork, now.mono_ms);
        }
    }
    fn currentSelectionRevision(self: *const PeerManager, service: *const service_mod.Service) SelectionRevision {
        return .{ .catalog = self.catalog.revision, .delivery = service.gossipsub.deliveryRevision() };
    }
    pub fn policyChanged(self: *const PeerManager, service: *const service_mod.Service) bool {
        return !std.meta.eql(self.selection_revision, self.currentSelectionRevision(service));
    }
    pub fn updateNativeRoom(self: *PeerManager, engine: *const engine_mod.Engine) void {
        const ceiling = @min(self.catalog.options.max_peers, engine.limits.connections_max);
        self.native_dial_room = ceiling -| engine.registry.active_len;
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
    pub fn candidateHints(self: *const PeerManager, identity: *const t.PeerId, now: Now) ?dial_mod.Hints {
        return self.dial_queue.candidateHints(identity, now.mono_ms);
    }
    /// Returns the same completed evaluation as coverageDeficits without advancing policy.
    /// The host must schedule the next process slot turn for demand expiry.
    pub fn discoveryNeed(self: *const PeerManager) DiscoveryNeed {
        return self.discovery_need;
    }
    /// Requires Discovery.step output or equivalent authenticated-source scope authorization.
    pub fn discovered(self: *PeerManager, service: *service_mod.Service, candidate: *const peers.enr.Candidate, now: Now) !void {
        if (self.stopped) return error.Stopped;
        self.reconcile(service, now);
        try self.enqueueDiscovered(candidate, now);
    }
    pub const DiscoveryIntake = struct { accepted: u16 = 0, refused: u16 = 0 };
    /// Each candidate has the same authenticated-source precondition as discovered.
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
        try self.dial_queue.enqueueDiscovered(candidate, &self.local.fork, &self.selection.deficits.missing, now.mono_ms);
        self.syncIdentity(&candidate.peer, now);
    }
    fn refreshSelection(self: *PeerManager, service: *service_mod.Service, now: Now) void {
        self.counters.selections +|= 1;
        self.counters.selection_rows +|= self.catalog.rows.len;
        self.selection_deadline = null;
        const count = self.catalog.snapshots(self.snapshot_scratch);
        var input_count: usize = 0;
        for (self.snapshot_scratch[0..count]) |*snapshot| {
            const conn = snapshot.connection orelse continue;
            if (snapshot.disconnect_reason != null) continue;
            std.debug.assert(input_count < self.policy_scratch.len);
            const input = &self.policy_scratch[input_count];
            input_count += 1;
            input.* = self.selectionInput(service, snapshot, conn, now);
            const grace = snapshot.connected_at_ms +| self.control.options.inbound_status_grace_ms;
            if (!input.ready and input.reject == null and now.mono_ms < grace) {
                input.evaluating = true;
                self.selection_deadline = @min(self.selection_deadline orelse grace, grace);
            }
        }
        self.selection = policy.select(self.policy_scratch[0..input_count], &self.demand, self.catalog.options, self.policy_seed);
        for (self.policy_scratch[0..input_count], 0..) |input, i| if (self.selection.reasons[i]) |reason| {
            if (self.disconnect(input.peer, reason, now)) self.counters.policy_disconnects +|= 1;
        };
    }

    fn selectionInput(
        self: *PeerManager,
        service: *service_mod.Service,
        snapshot: *const t.Snapshot,
        conn: t.Handle,
        now: Now,
    ) policy.Input {
        var input: policy.Input = .{
            .peer = snapshot.peer,
            .direct = snapshot.direct,
            .outbound = snapshot.direction == .outbound,
            .relevant = snapshot.relevant,
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
            input.outbound = false;
            if (snapshot.relevant and !snapshot.direct and input.reject == null)
                input.reject = .gossip_unavailable;
        }
        if (!snapshot.relevant or input.reject != null) return input;
        const metadata = snapshot.metadata orelse return input;
        peers.control_wire.validateMetadata(&metadata, self.local.fork) catch return input;
        const deadline = snapshot.metadata_at_ms +| self.metadata_freshness_ms;
        if (now.mono_ms >= deadline) return input;
        self.selection_deadline = @min(self.selection_deadline orelse deadline, deadline);
        if (delivery == .available) {
            input.ready = !self.local.fork.fork.gte(.fulu) or snapshot.sampling_groups != null;
            input.coverage.attnets = std.mem.readInt(u64, &metadata.attnets, .little);
            input.coverage.syncnets = @intCast(metadata.syncnets);
            input.coverage.groups = snapshot.sampling_groups orelse .initEmpty();
        }
        return input;
    }
    fn refreshDiscoveryNeed(self: *PeerManager) void {
        self.discovery_need = .{};
        if (self.selection.dial_budget == 0) return;
        self.discovery_need.general = self.catalog.relevantCount() < self.catalog.options.target_peers or
            self.selection.deficits.outbound > 0;
        if (self.current_slot >= self.demand.expires_at_slot) return;
        std.mem.writeInt(u64, &self.discovery_need.attnets, self.selection.deficits.missing.attnets, .little);
        self.discovery_need.syncnets = self.selection.deficits.missing.syncnets;
        self.discovery_need.custody = self.selection.deficits.groups > 0;
    }
    pub fn dialRoom(self: *const PeerManager) u16 {
        const attempts = self.dial_queue.attempts();
        const budget = @min(self.catalog.options.max_peers -| self.selection.retained_count, @max(self.selection.dial_budget, self.dial_queue.hostDemand()));
        return @min(self.native_dial_room -| attempts.unstarted, budget -| attempts.total);
    }
    pub fn updateStatus(self: *PeerManager, status: *const t.Status) !void {
        var local = self.local;
        local.status = status.*;
        try peers.control_wire.copyLocal(&self.local, &local);
        self.selection_revision = null;
    }
    pub fn updateMetadata(self: *PeerManager, metadata: *const t.Metadata) !void {
        var local = self.local;
        local.metadata = metadata.*;
        try peers.control_wire.copyLocal(&self.local, &local);
        self.selection_revision = null;
    }
    pub fn updateFork(self: *PeerManager, service: *service_mod.Service, local: *const t.LocalState, now: Now) !void {
        var copied: t.LocalState = undefined;
        try peers.control_wire.copyLocal(&copied, local);
        self.commitLocal(service, &copied, now);
    }

    /// The caller must validate the complete local state before committing it.
    pub fn commitLocal(self: *PeerManager, service: *service_mod.Service, local: *const t.LocalState, now: Now) void {
        if (!std.meta.eql(self.local.fork, local.fork)) {
            self.control.forkUpdated(service, &self.catalog, self.local.fork, now);
        }
        self.local = local.*;
        service.reqresp.setRequestFork(local.fork.fork);
        for (self.local.fork.custody_groups..128) |index| self.demand.group_targets[index] = 0;
        var budget: u16 = 0;
        _ = self.catalog.advanceCustody(&self.local.fork, now.mono_ms, self.metadata_freshness_ms, &budget);
        _ = self.dial_queue.advanceCustody(&self.local.fork, now.mono_ms, &budget);
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
        try self.dial_queue.enqueueUntil(identity, addresses, false, now.mono_ms, deadline_ms);
        self.syncIdentity(identity, now);
        self.selection_revision = null;
    }
    pub fn cancelConnect(self: *PeerManager, engine: *engine_mod.Engine, identity: *const t.PeerId, now: Now) void {
        self.dial_queue.cancelConnect(engine, identity, now.mono_ms);
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
        try self.dial_queue.enqueue(identity, addresses, true, now.mono_ms);
        self.syncIdentity(identity, now);
        self.selection_revision = null;
        if (self.catalog.find(identity)) |peer| {
            _ = self.catalog.setDirect(peer, true);
            if (self.catalog.get(peer).?.connection) |conn| service.gossipsub.markDirect(conn);
        }
    }
    pub fn directPeers(self: *const PeerManager, out: []t.PeerId) error{OutputTooSmall}!usize {
        return self.dial_queue.directPeers(out);
    }
    pub fn removeDirectPeer(self: *PeerManager, service: *service_mod.Service, identity: *const t.PeerId) bool {
        if (!self.dial_queue.removeDirect(identity)) return false;
        self.selection_revision = null;
        service.gossipsub.unmarkDirect(identity);
        if (self.catalog.find(identity)) |peer| _ = self.catalog.setDirect(peer, false);
        return true;
    }
    pub fn closePeer(self: *PeerManager, service: *service_mod.Service, engine: *engine_mod.Engine, peer: t.PeerRef, connection: t.Handle, now: Now) bool {
        if (self.stopped) return false;
        const snapshot = self.catalog.get(peer) orelse return false;
        if (!std.meta.eql(snapshot.connection, connection)) return false;
        self.control.close(service, &self.catalog, engine, peer, connection, .host, now);
        self.dial_queue.cancelConnect(engine, &snapshot.identity, now.mono_ms);
        self.dial_queue.disconnected(&snapshot.identity, snapshot.connected_at_ms, .host, now.mono_ms);
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
        self.dial_queue.expire(engine, now.mono_ms);
        self.reconcile(service, now);
        self.updateNativeRoom(engine);
        return self.dial_queue.poll(now.mono_ms, out[0..@min(out.len, self.dialRoom())]);
    }
    pub fn dialStarted(self: *PeerManager, token: dial_mod.Token, conn: t.Handle) bool {
        return self.dial_queue.dialStarted(token, conn);
    }
    pub fn dialDeferred(self: *PeerManager, token: dial_mod.Token, now: Now) bool {
        return self.dial_queue.dialDeferred(token, now.mono_ms);
    }
    pub fn dialFailed(self: *PeerManager, token: dial_mod.Token, now: Now) bool {
        return self.dial_queue.dialFailed(token, now.mono_ms);
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
