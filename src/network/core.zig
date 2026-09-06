const std = @import("std");
const service_mod = @import("service.zig");
const t = @import("peers/types.zig");
const peers = @import("peers/root.zig");
const control_mod = @import("peers/control.zig");
const dial_mod = @import("peers/dial_queue.zig");
const policy = peers.policy;
const custody = peers.custody;
const engine_mod = @import("quic/engine.zig");
const rr = @import("reqresp/root.zig");
const gossip = @import("gossipsub/root.zig");
const Now = @import("types.zig").Now;
pub const Options = struct {
    peers: t.Options = .{},
    service: service_mod.Options = .{
        .router = .{ .outbound_control_reserved = 8 },
        .reqresp = .{
            .forks = &.{},
            .outbound_control_reserved = 8,
            .inbound_control_reserved = 8,
            .outbound_per_peer_max = 8,
            .inbound_per_peer_max = 16,
            .inbound_application_per_peer_max = 8,
        },
    },
    control: control_mod.Options = .{},
    dial: dial_mod.Options,
    metadata_freshness_ms: u64 = 60_000,
};
pub const DialIntent = dial_mod.DialIntent;
pub const DialToken = dial_mod.Token;
pub const Counts = struct { peers: usize, application: usize, gossipsub: usize };
pub const MemoryPlan = struct {
    inline_bytes: usize,
    allocated_bytes: usize,
    catalog_bytes: usize,
    control_bytes: usize,
    dial_bytes: usize,
    service_bytes: usize,
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
pub const Core = struct {
    allocator: std.mem.Allocator,
    service: service_mod.Service,
    catalog: peers.Catalog,
    control: control_mod.Control,
    dial_queue: dial_mod.DialQueue,
    local_identity: t.PeerId,
    local: t.LocalState,
    snapshot_scratch: []t.Snapshot,
    policy_scratch: []policy.Input,
    selection: policy.Result = .{},
    demand: t.Demand = .{},
    current_slot: u64 = 0,
    policy_dirty: bool = true,
    catalog_revision: ?u64 = null,
    candidates_revision: ?u64 = null,
    score_revision: u64 = 0,
    delivery_ready: std.StaticBitSet(4096) = .initEmpty(),
    reconciliation_deadline: ?u64 = null,
    reconciliation_now: Now = .{ .mono_ms = 0, .unix_s = 0 },
    custody_pending: bool = false,
    metadata_deadline: ?u64 = null,
    native_dial_room: u16 = 0,
    metadata_freshness_ms: u64,
    policy_seed: u64,
    stopped: bool = false,
    counters: Counters = .{},

    pub const Counters = struct {
        rejected: u64 = 0,
        displaced: u64 = 0,
        policy_disconnects: u64 = 0,
        custody_hashes: u64 = 0,
        selections: u64 = 0,
        selection_rows: u64 = 0,
        candidate_syncs: u64 = 0,
        candidate_rows: u64 = 0,
        candidate_lookup_rows: u64 = 0,
        availability_rows: u64 = 0,
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
    pub fn diagnostics(self: *const Core) Diagnostics {
        const g = &self.service.gossipsub.inner;
        return .{
            .policy = self.counters,
            .connected = self.catalog.connectedCount(),
            .relevant = self.catalog.relevantCount(),
            .control = self.control.counters,
            .control_resources = self.control.resourceSnapshot(),
            .dialing = self.dial_queue.resourceSnapshot(),
            .reqresp = self.service.reqresp.inner.counters,
            .reqresp_resources = self.service.reqresp.inner.resourceSnapshot(),
            .gossip = g.counters,
            .gossip_resources = g.resourceSnapshot(),
            .score_calculations = g.scores.calculations,
            .score_topic_visits = g.scores.topic_visits,
        };
    }

    pub fn validateOptions(options: Options) !void {
        try options.peers.validate();
        if (options.metadata_freshness_ms == 0 or options.metadata_freshness_ms > 86_400_000) return error.InvalidOptions;
        if (options.service.reqresp.peers < options.peers.engine_capacity)
            return error.InvalidOptions;
        try control_mod.Control.validateOptions(options.control);
        try dial_mod.DialQueue.validateOptions(options.dial);
        try service_mod.Service.validateOptions(options.service);
    }

    pub fn init(
        a: std.mem.Allocator,
        identity: *const t.PeerId,
        local: *const t.LocalState,
        options: Options,
    ) !Core {
        var copied: t.LocalState = undefined;
        try peers.control_wire.copyLocal(&copied, local);
        try validateOptions(options);
        var catalog = try peers.Catalog.init(a, options.peers);
        errdefer catalog.deinit(a);
        var control = try control_mod.Control.init(
            a,
            options.control,
            options.peers.capacity,
            options.service.reqresp.inbound_max,
        );
        errdefer control.deinit(a);
        var dial_queue = try dial_mod.DialQueue.init(a, options.dial);
        errdefer dial_queue.deinit(a);
        const scratch = try a.alloc(t.Snapshot, options.peers.capacity);
        errdefer a.free(scratch);
        const policy_scratch = try a.alloc(policy.Input, options.peers.max_peers);
        errdefer a.free(policy_scratch);
        var service_options = options.service;
        service_options.automatic_gossip_admission = false;
        const service = try service_mod.Service.init(a, service_options);
        return .{
            .allocator = a,
            .service = service,
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
    /// Call shutdown with the borrowed Engine before releasing an active Core.
    pub fn deinit(self: *Core) void {
        self.service.deinit();
        self.allocator.free(self.policy_scratch);
        self.allocator.free(self.snapshot_scratch);
        self.dial_queue.deinit(self.allocator);
        self.control.deinit(self.allocator);
        self.catalog.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn memoryPlan(self: *const Core) MemoryPlan {
        const catalog = self.catalog.memoryPlan().allocated_bytes;
        const control = self.control.memoryPlan().allocated_bytes;
        const dial = self.dial_queue.memoryPlan().allocated_bytes;
        const request = self.service.reqresp.memoryPlan();
        const gossip_plan = self.service.gossipsub.inner.memoryPlan();
        const gossip_stream = @TypeOf(self.service.gossipsub.streams[0]);
        const negotiation = @TypeOf(self.service.router.negotiator.entries[0]);
        const service_bytes = request.total_bytes - request.facade_bytes +
            gossip_plan.total_bytes - @sizeOf(gossip.Gossipsub) +
            self.service.gossipsub.streams.len * @sizeOf(gossip_stream) +
            self.service.router.supported.len * @sizeOf([]const u8) +
            self.service.router.negotiator.entries.len * @sizeOf(negotiation);
        const scratch = self.snapshot_scratch.len * @sizeOf(t.Snapshot);
        const policy_bytes = self.policy_scratch.len * @sizeOf(policy.Input);
        return .{
            .inline_bytes = @sizeOf(Core),
            .allocated_bytes = catalog + control + dial + service_bytes + scratch + policy_bytes,
            .catalog_bytes = catalog,
            .control_bytes = control,
            .dial_bytes = dial,
            .service_bytes = service_bytes,
            .scratch_bytes = scratch,
            .policy_bytes = policy_bytes,
        };
    }
    /// Public protocol borrows retain their Service lifetime until the next process call.
    /// Internal closes after publication perform cleanup without a second owner recycling pass.
    pub fn process(
        self: *Core,
        engine: *engine_mod.Engine,
        events: []const engine_mod.Event,
        activity: []const engine_mod.Handle,
        now: Now,
        slot: u64,
        peer_events: []t.Event,
        application: []rr.Event,
        gossip_events: []gossip.Event,
    ) Counts {
        const per_connection = 2 * @import("quic/limits.zig").streams_per_connection + 3;
        std.debug.assert(events.len <= @as(usize, engine.limits.connections_max) * per_connection);
        if (self.stopped) return .{
            .peers = self.catalog.pollEvents(peer_events),
            .application = 0,
            .gossipsub = 0,
        };
        self.current_slot = slot;
        if (slot >= self.demand.expires_at_slot and !std.meta.eql(self.demand, t.Demand{})) {
            self.demand = .{};
            self.policy_dirty = true;
        }
        self.catalog.refresh(now.mono_ms);
        self.dial_queue.expire(engine, now.mono_ms);
        for (events) |event| self.transportEvent(engine, event, now);
        var controls: [32]rr.Event = undefined;
        const counts = self.service.processPartitioned(
            engine,
            events,
            activity,
            now,
            application,
            &controls,
            gossip_events,
        );
        self.control.events(
            &self.service,
            &self.catalog,
            engine,
            &self.local,
            now,
            slot,
            controls[0..counts.control],
        );
        self.control.maintain(&self.service, &self.catalog, engine, &self.local, now);
        var connected_budget: u16 = custody.hashes_per_turn / 2;
        var candidate_budget: u16 = custody.hashes_per_turn / 2;
        const connected_pending = self.catalog.advanceCustody(&self.local.fork, now.mono_ms, self.metadata_freshness_ms, &connected_budget);
        const candidate_pending = self.dial_queue.advanceCustody(&self.local.fork, now.mono_ms, &candidate_budget);
        self.custody_pending = connected_pending or candidate_pending;
        self.counters.custody_hashes +|= custody.hashes_per_turn - connected_budget - candidate_budget;
        self.reconcile(now);
        self.updateNativeRoom(engine);
        return .{
            .peers = self.catalog.pollEvents(peer_events),
            .application = counts.application,
            .gossipsub = counts.gossipsub,
        };
    }
    fn transportEvent(
        self: *Core,
        engine: *engine_mod.Engine,
        event: engine_mod.Event,
        now: Now,
    ) void {
        switch (event) {
            .connected => |connected| {
                const identity = engine.peerId(connected.conn) orelse return;
                const endpoint = engine.peerAddress(connected.conn) orelse return;
                const direction = engine.direction(connected.conn) orelse return;
                switch (self.catalog.admit(
                    &identity,
                    &self.local_identity,
                    connected.conn,
                    &.{ .direction = direction, .endpoint = endpoint, .now_ms = now.mono_ms },
                )) {
                    .admitted => |admission| {
                        if (admission.displaced) |old| {
                            self.counters.displaced +|= 1;
                            self.control.cancelConnection(
                                &self.service,
                                engine,
                                admission.peer,
                                old,
                            );
                            self.service.gossipsub.transportEvents(
                                engine,
                                &.{.{ .closed = .{
                                    .conn = old,
                                    .peer_id = identity,
                                    .direction = direction,
                                    .reason = .host,
                                } }},
                                now,
                            );
                            _ = engine.close(old, 0);
                        }
                        self.control.connected(admission.peer, connected.conn, direction, now);
                        _ = self.catalog.setDirect(
                            admission.peer,
                            self.dial_queue.isDirect(&identity),
                        );
                        self.dial_queue.accepted(&identity, connected.conn, now.mono_ms);
                    },
                    else => {
                        self.counters.rejected +|= 1;
                        _ = engine.close(connected.conn, 0);
                    },
                }
            },
            .closed => |closed| {
                _ = self.dial_queue.dialClosed(closed.conn, now.mono_ms);
                if (self.control.peerFor(closed.conn)) |peer| {
                    const snapshot = self.catalog.get(peer).?;
                    self.control.close(
                        &self.service,
                        &self.catalog,
                        engine,
                        peer,
                        closed.conn,
                        snapshot.disconnect_reason orelse .transport_closed,
                        now,
                    );
                    self.dial_queue.connection(&snapshot.identity, false, now.mono_ms);
                }
            },
            else => {},
        }
    }
    fn refreshCandidates(self: *Core, now: Now) void {
        if (self.candidates_revision == self.catalog.revision and self.catalog.revision != std.math.maxInt(u64)) return;
        self.counters.candidate_syncs +|= 1;
        self.counters.candidate_rows +|= self.catalog.rows.len;
        const count = self.catalog.snapshots(self.snapshot_scratch);
        for (self.snapshot_scratch[0..count]) |*snapshot| self.syncCandidate(snapshot, now);
        self.candidates_revision = self.catalog.revision;
    }
    fn syncCandidate(self: *Core, snapshot: *const t.Snapshot, now: Now) void {
        self.dial_queue.syncConnection(&snapshot.identity, snapshot.connection != null, now.mono_ms);
        if (snapshot.relevant) self.dial_queue.relevant(&snapshot.identity, snapshot.status_at_ms);
        if (snapshot.ban_until_ms > now.mono_ms or snapshot.score <= -50 or snapshot.goodbye_until_ms > now.mono_ms) {
            const due = @max(self.catalog.nextDeadline(now.mono_ms) orelse now.mono_ms +| 1_000, snapshot.goodbye_until_ms);
            self.dial_queue.deferPeer(&snapshot.identity, due);
        }
    }
    fn syncIdentity(self: *Core, identity: *const t.PeerId, now: Now) void {
        for (self.catalog.rows, 0..) |*row, index| {
            self.counters.candidate_lookup_rows +|= 1;
            if (!row.occupied or !row.identity.eql(identity)) continue;
            self.syncCandidate(&self.catalog.get(.{ .index = @intCast(index), .generation = row.generation }).?, now);
            return;
        }
    }
    fn observeDelivery(self: *Core) void {
        var ready: @TypeOf(self.delivery_ready) = .initEmpty();
        if (self.demand.coverage.attnets != 0 or self.demand.coverage.syncnets != 0) {
            for (self.catalog.rows, 0..) |row, index| {
                self.counters.availability_rows +|= 1;
                const conn = row.connection orelse continue;
                if (row.closing_reason == null and self.service.gossipsub.deliveryAvailable(conn)) ready.set(index);
            }
        }
        if (!ready.eql(self.delivery_ready)) self.policy_dirty = true;
        self.delivery_ready = ready;
    }
    /// Reconciles at the supplied clock without pumping protocols or borrowing an Engine.
    /// Health only ranks removals. Once pruned, changing health alone cannot remove
    /// a retained peer while count, coverage and protection remain unchanged.
    pub fn reconcile(self: *Core, now: Now) void {
        if (self.stopped) return;
        self.reconciliation_now = now;
        self.catalog.refresh(now.mono_ms);
        const expired = if (self.reconciliation_deadline) |due| now.mono_ms >= due else false;
        if (expired) self.candidates_revision = null;
        self.observeDelivery();
        if (self.policyChanged() or expired) {
            self.refreshSelection(now);
            self.catalog_revision = self.catalog.revision;
            self.score_revision = self.service.gossipsub.inner.scores.revision;
            self.reconciliation_deadline = self.catalog.nextDeadline(now.mono_ms);
            if (self.metadata_deadline) |due| self.reconciliation_deadline = @min(self.reconciliation_deadline orelse due, due);
            self.dial_queue.selection_dirty = true;
        }
        self.refreshCandidates(now);
        if (self.dial_queue.selection_dirty or (if (self.dial_queue.selection_deadline) |due| now.mono_ms >= due else false)) {
            self.counters.candidate_selections +|= 1;
            self.dial_queue.configureSelection(&self.selection.deficits.missing, self.selection.retained_count < self.catalog.options.target_peers or self.selection.deficits.outbound > 0, &self.local.fork, now.mono_ms);
        }
    }
    fn policyChanged(self: *const Core) bool {
        const score_revision = self.service.gossipsub.inner.scores.revision;
        return self.policy_dirty or self.catalog_revision != self.catalog.revision or
            self.score_revision != score_revision or self.catalog.revision == std.math.maxInt(u64) or
            score_revision == std.math.maxInt(u64);
    }
    fn updateNativeRoom(self: *Core, engine: *const engine_mod.Engine) void {
        const ceiling = @min(self.catalog.options.max_peers, engine.limits.connections_max);
        self.native_dial_room = ceiling -| engine.registry.active_len;
    }
    pub fn nextWakeup(
        self: *Core,
        now: Now,
        peer_capacity: usize,
        application_capacity: usize,
        gossip_capacity: usize,
        dial_capacity: usize,
    ) ?u64 {
        if (self.stopped) return self.peerWakeup(now, peer_capacity);
        self.observeDelivery();
        var due = self.service.nextWakeupPartitioned(
            now,
            application_capacity,
            32,
            gossip_capacity,
        );
        for ([_]?u64{
            self.control.nextWakeup(&self.catalog, now),
            self.dial_queue.nextWakeup(now.mono_ms, @min(dial_capacity, self.dialRoom())),
            if (self.policyChanged() or self.dial_queue.selection_dirty) now.mono_ms else null,
            self.reconciliation_deadline,
            self.dial_queue.selection_deadline,
            if (self.custody_pending) now.mono_ms +| 1 else null,
            self.peerWakeup(now, peer_capacity),
        }) |next| {
            if (next) |value| due = @min(due orelse value, value);
        }
        return due;
    }
    fn peerWakeup(self: *const Core, now: Now, capacity: usize) ?u64 {
        if (capacity == 0) return null;
        if (self.catalog.eventsPending()) return now.mono_ms;
        return null;
    }
    pub fn setDemand(self: *Core, demand: *const t.Demand) !void {
        if (self.stopped) return error.Stopped;
        try demand.validate(&self.local.fork, self.catalog.options.max_peers);
        if (std.meta.eql(self.demand, demand.*)) return;
        self.demand = demand.*;
        self.policy_dirty = true;
    }
    /// Reconciles mutations at the last explicit reconcile/process/dial clock.
    pub fn coverageDeficits(self: *Core) policy.Deficits {
        self.reconcile(self.reconciliation_now);
        return self.selection.deficits;
    }
    pub fn candidateHints(self: *const Core, identity: *const t.PeerId, now: Now) ?dial_mod.Hints {
        return self.dial_queue.candidateHints(identity, now.mono_ms);
    }
    /// Current need after process. The host must schedule the next slot turn for demand expiry.
    pub fn discoveryNeed(self: *Core) DiscoveryNeed {
        self.reconcile(self.reconciliation_now);
        if (self.stopped) return .{};
        var result: DiscoveryNeed = .{ .general = self.selection.dial_budget > 0 and (self.catalog.relevantCount() < self.catalog.options.target_peers or self.selection.deficits.outbound > 0) };
        if (self.current_slot < self.demand.expires_at_slot and self.selection.dial_budget > 0) {
            std.mem.writeInt(u64, &result.attnets, self.selection.deficits.missing.attnets, .little);
            result.syncnets = self.selection.deficits.missing.syncnets;
            result.custody = self.selection.deficits.custody > 0;
        }
        return result;
    }
    /// Requires Discovery.step output or equivalent authenticated-source scope authorization.
    pub fn discovered(self: *Core, candidate: *const peers.enr.Candidate, now: Now) !void {
        if (self.stopped) return error.Stopped;
        self.reconcile(now);
        try self.enqueueDiscovered(candidate, now);
    }
    pub const DiscoveryIntake = struct { accepted: u16 = 0, refused: u16 = 0 };
    /// Each candidate has the same authenticated-source precondition as discovered.
    pub fn discoveredBatch(self: *Core, candidates: []const peers.enr.Candidate, now: Now) DiscoveryIntake {
        std.debug.assert(candidates.len <= 16);
        self.reconcile(now);
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
    fn enqueueDiscovered(self: *Core, candidate: *const peers.enr.Candidate, now: Now) !void {
        if (self.stopped) return error.Stopped;
        if (candidate.peer.eql(&self.local_identity)) return error.SelfDial;
        try self.dial_queue.enqueueDiscovered(candidate, &self.local.fork, &self.selection.deficits.missing, now.mono_ms);
        self.syncIdentity(&candidate.peer, now);
    }
    fn refreshSelection(self: *Core, now: Now) void {
        self.counters.selections +|= 1;
        self.counters.selection_rows +|= self.catalog.rows.len;
        self.metadata_deadline = null;
        const count = self.catalog.snapshots(self.snapshot_scratch);
        var input_count: usize = 0;
        for (self.snapshot_scratch[0..count]) |*snapshot| {
            const conn = snapshot.connection orelse continue;
            if (snapshot.disconnect_reason != null) continue;
            std.debug.assert(input_count < self.policy_scratch.len);
            const input = &self.policy_scratch[input_count];
            input_count += 1;
            input.* = .{ .peer = snapshot.peer, .direct = snapshot.direct, .outbound = snapshot.direction == .outbound, .relevant = snapshot.relevant, .score = snapshot.score + (self.gossipScore(snapshot.peer, now) orelse 0) };
            if (snapshot.ban_until_ms > now.mono_ms or snapshot.score <= -50) input.reject = .banned;
            if (snapshot.status) |status| {
                if (!std.mem.eql(u8, &status.fork_digest, &self.local.fork.digest)) input.reject = .incompatible_fork;
                if (self.local.fork.fork.gte(.fulu) and status.earliest_available_slot == null) input.reject = .missing_availability;
            }
            if (!snapshot.relevant or input.reject != null) continue;
            const metadata = snapshot.metadata orelse continue;
            peers.control_wire.validateMetadata(&metadata, self.local.fork) catch continue;
            const deadline = snapshot.metadata_at_ms +| self.metadata_freshness_ms;
            if (now.mono_ms >= deadline) continue;
            self.metadata_deadline = @min(self.metadata_deadline orelse deadline, deadline);
            if (self.service.gossipsub.deliveryAvailable(conn)) {
                input.coverage.attnets = std.mem.readInt(u64, &metadata.attnets, .little);
                input.coverage.syncnets = @intCast(metadata.syncnets);
            }
            input.coverage.custody = snapshot.custody_groups orelse .initEmpty();
        }
        self.selection = policy.select(self.policy_scratch[0..input_count], &self.demand, self.catalog.options, self.policy_seed);
        for (self.policy_scratch[0..input_count], 0..) |input, i| if (self.selection.reasons[i]) |reason| {
            if (self.disconnect(input.peer, reason, now)) self.counters.policy_disconnects +|= 1;
        };
        self.policy_dirty = false;
    }
    fn dialRoom(self: *const Core) u16 {
        const attempts = self.dial_queue.attempts();
        const budget = @min(self.catalog.options.max_peers -| self.selection.retained_count, @max(self.selection.dial_budget, self.dial_queue.hostDemand()));
        return @min(self.native_dial_room -| attempts.unstarted, budget -| attempts.total);
    }
    pub fn updateStatus(self: *Core, status: *const t.Status) !void {
        var local = self.local;
        local.status = status.*;
        try peers.control_wire.copyLocal(&self.local, &local);
        self.policy_dirty = true;
    }
    pub fn updateMetadata(self: *Core, metadata: *const t.Metadata) !void {
        var local = self.local;
        local.metadata = metadata.*;
        try peers.control_wire.copyLocal(&self.local, &local);
        self.policy_dirty = true;
    }
    pub fn updateFork(self: *Core, local: *const t.LocalState, now: Now) !void {
        self.reconciliation_now = now;
        var copied: t.LocalState = undefined;
        try peers.control_wire.copyLocal(&copied, local);
        if (!std.meta.eql(self.local.fork, copied.fork)) {
            self.control.forkUpdated(&self.service, &self.catalog, self.local.fork, now);
        }
        self.local = copied;
        for (self.local.fork.custody_groups..128) |index| self.demand.coverage.custody.unset(index);
        var budget: u16 = 0;
        _ = self.catalog.advanceCustody(&self.local.fork, now.mono_ms, self.metadata_freshness_ms, &budget);
        _ = self.dial_queue.advanceCustody(&self.local.fork, now.mono_ms, &budget);
        self.policy_dirty = true;
        self.reStatusPeers(now);
    }
    pub fn reStatusPeers(self: *Core, now: Now) void {
        self.control.reStatusPeers(now);
    }
    pub fn reportPeer(
        self: *Core,
        peer: t.PeerRef,
        action: t.PeerAction,
        now: Now,
    ) ?t.ReputationDecision {
        self.reconciliation_now = now;
        const decision = self.catalog.report(peer, action, now.mono_ms) orelse return null;
        self.policy_dirty = true;
        if (decision != .none) _ = self.disconnect(
            peer,
            if (decision == .ban) .banned else .reputation,
            now,
        );
        return decision;
    }
    pub fn connect(
        self: *Core,
        identity: *const t.PeerId,
        addresses: []const t.Address,
        now: Now,
    ) !void {
        self.reconciliation_now = now;
        if (self.stopped) return error.Stopped;
        if (identity.eql(&self.local_identity)) return error.SelfDial;
        try self.dial_queue.enqueue(identity, addresses, false, now.mono_ms);
        self.syncIdentity(identity, now);
        self.policy_dirty = true;
    }
    pub fn addDirectPeer(
        self: *Core,
        identity: *const t.PeerId,
        addresses: []const t.Address,
        now: Now,
    ) !void {
        self.reconciliation_now = now;
        if (self.stopped) return error.Stopped;
        if (identity.eql(&self.local_identity)) return error.SelfDial;
        try self.dial_queue.enqueue(identity, addresses, true, now.mono_ms);
        self.syncIdentity(identity, now);
        self.policy_dirty = true;
        if (self.catalog.find(identity)) |peer| _ = self.catalog.setDirect(peer, true);
    }
    pub fn removeDirectPeer(self: *Core, identity: *const t.PeerId) void {
        self.dial_queue.removeDirect(identity);
        self.policy_dirty = true;
        self.service.gossipsub.inner.unmarkDirect(identity);
        if (self.catalog.find(identity)) |peer| _ = self.catalog.setDirect(peer, false);
    }
    pub fn disconnect(self: *Core, peer: t.PeerRef, reason: t.DisconnectReason, now: Now) bool {
        self.reconciliation_now = now;
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
        self: *Core,
        engine: *engine_mod.Engine,
        now: Now,
        out: []dial_mod.DialIntent,
    ) usize {
        if (self.stopped) return 0;
        self.dial_queue.expire(engine, now.mono_ms);
        self.catalog.refresh(now.mono_ms);
        self.reconcile(now);
        self.updateNativeRoom(engine);
        return self.dial_queue.poll(now.mono_ms, out[0..@min(out.len, self.dialRoom())]);
    }
    pub fn dialStarted(self: *Core, token: dial_mod.Token, conn: t.Handle) bool {
        return self.dial_queue.dialStarted(token, conn);
    }
    pub fn dialDeferred(self: *Core, token: dial_mod.Token, now: Now) bool {
        return self.dial_queue.dialDeferred(token, now.mono_ms);
    }
    pub fn dialFailed(self: *Core, token: dial_mod.Token, now: Now) bool {
        return self.dial_queue.dialFailed(token, now.mono_ms);
    }
    pub fn snapshots(self: *const Core, out: []t.Snapshot) usize {
        return self.catalog.snapshots(out);
    }
    pub fn peerCounts(self: *Core) PeerCounts {
        const count = self.catalog.snapshots(self.snapshot_scratch);
        var result: PeerCounts = .{ .connected = 0, .relevant = 0, .outbound_relevant = 0 };
        for (self.snapshot_scratch[0..count]) |snapshot| {
            if (snapshot.connection != null) result.connected += 1;
            if (!snapshot.relevant) continue;
            result.relevant += 1;
            if (snapshot.direction == .outbound) result.outbound_relevant += 1;
        }
        return result;
    }
    pub fn connectedPeerCount(self: *const Core) u16 {
        return self.catalog.relevantCount();
    }
    pub fn gossipScore(self: *Core, peer: t.PeerRef, now: Now) ?f64 {
        const snapshot = self.catalog.get(peer) orelse return null;
        return self.service.gossipsub.inner.scoreSnapshot(
            snapshot.connection orelse return null,
            now,
        );
    }
    pub fn sendReqRespRequest(
        self: *Core,
        engine: *engine_mod.Engine,
        conn: t.Handle,
        protocol: rr.Protocol,
        bytes: []const u8,
        sink: []u8,
        options: rr.reqresp.RequestOptions,
        now: Now,
    ) !rr.RequestHandle {
        if (self.stopped) return error.Stopped;
        if (protocol.isControl()) return error.ControlProtocol;
        return self.service.request(engine, conn, protocol, bytes, sink, options, now);
    }
    pub fn consume(self: *Core, request: rr.RequestHandle, now: Now) bool {
        return self.service.reqresp.consume(request, now);
    }
    pub fn respond(
        self: *Core,
        request: rr.RequestHandle,
        bytes: []const u8,
        fork: ?@import("config").ForkSeq,
        now: Now,
    ) !void {
        try self.service.reqresp.respond(request, bytes, fork, now);
    }
    pub fn respondError(
        self: *Core,
        request: rr.RequestHandle,
        code: u8,
        message: []const u8,
        now: Now,
    ) !void {
        try self.service.reqresp.respondError(request, code, message, now);
    }
    pub fn finish(self: *Core, request: rr.RequestHandle, now: Now) bool {
        return self.service.reqresp.finish(request, now);
    }
    pub fn cancel(self: *Core, request: rr.RequestHandle) bool {
        return self.service.reqresp.cancel(request);
    }
    pub fn errorMessage(self: *const Core, request: rr.RequestHandle) []const u8 {
        return self.service.reqresp.errorMessage(request);
    }
    /// Copies host-calculated parameters. Preserves outstanding Service event borrows.
    pub fn configureTopic(self: *Core, topic: []const u8, params: *const gossip.score.TopicParams) (gossip.Gossipsub.ConfigureTopicError || error{Stopped})!void {
        if (self.stopped) return error.Stopped;
        try self.service.gossipsub.configureTopic(topic, params);
    }

    pub fn publishGossip(
        self: *Core,
        topic: []const u8,
        bytes: []const u8,
        now: Now,
    ) !gossip.Gossipsub.PublishOutcome {
        if (self.stopped) return error.Stopped;
        return self.service.gossipsub.publish(topic, bytes, now);
    }
    pub fn subscribe(self: *Core, topic: []const u8) bool {
        if (self.stopped) return false;
        return self.service.gossipsub.subscribe(topic);
    }
    pub fn unsubscribe(self: *Core, topic: []const u8) bool {
        return self.service.gossipsub.unsubscribe(topic);
    }
    pub fn reportValidation(
        self: *Core,
        handle: gossip.ValidationHandle,
        verdict: gossip.Verdict,
        now: Now,
    ) gossip.ReportOutcome {
        return self.service.gossipsub.report(handle, verdict, now);
    }
    pub fn shutdown(self: *Core, engine: *engine_mod.Engine, now: Now) void {
        if (self.stopped) return;
        self.stopped = true;
        self.service.reqresp.shutdown(&self.service.router, engine);
        self.service.router.negotiator.shutdown(engine);
        const count = self.catalog.snapshots(self.snapshot_scratch);
        for (self.snapshot_scratch[0..count]) |snapshot| if (snapshot.connection) |conn| {
            self.control.close(
                &self.service,
                &self.catalog,
                engine,
                snapshot.peer,
                conn,
                .shutdown,
                now,
            );
        };
        self.dial_queue.shutdown(engine);
    }
};
