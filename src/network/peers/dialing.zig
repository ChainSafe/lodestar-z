const std = @import("std");
const catalog_mod = @import("catalog.zig");
const Catalog = catalog_mod.Catalog;
const Row = catalog_mod.Row;
const policy = @import("policy.zig");
const enr = @import("enr.zig");
const t = @import("types.zig");
const Engine = @import("../quic/engine.zig").Engine;
const DeadlineHeap = @import("../deadline_heap.zig").DeadlineHeap;
const assert = std.debug.assert;
pub const Token = struct { index: u16, generation: u64 };
pub const DialIntent = struct { token: Token, peer: t.PeerId, address: t.Address };
/// `outbound_reserved` peer slots stay closed to unselected inbound admission so dials can land.
pub const Options = struct { capacity: u16 = 256, concurrent_max: u16 = 4, outbound_reserved: u16 = 0, seed: u64 };
/// Unanswered QUIC dials cost one handshake slot each, so the table is sized for dead endpoints,
/// not for peer headroom.
pub const attempts_max = 64;
pub const history_retention_ms = catalog_mod.history_retention_ms;
pub const hint_freshness_ms = catalog_mod.hint_freshness_ms;
pub const connect_timeout_ms: u64 = 30_000;
pub const DialTime = @import("../metrics/histogram.zig").Duration(&.{ 100, 500, 1000, 5000, 10000, 60000 });
pub const Source = enum { discovery, manual, direct };
const Attempt = struct {
    generation: u64 = 0,
    peer: ?t.PeerRef = null,
    connection: ?t.Handle = null,
    answered: bool = false,
    started_ms: u64 = 0,
    lease_until_ms: u64 = 0,
    /// The dialed endpoint, which a discovery refresh may drop from the row's addresses mid-flight.
    address: t.Address = .unspecified,
};

pub const Dialing = struct {
    options: Options,
    active: [attempts_max]Attempt = @splat(.{}),
    selection_dirty: bool = true,
    selection_revision: ?u64 = null,
    selection_deadline: ?u64 = null,
    cursor: usize = 0,
    preferred_starts: u16 = 0,
    random: std.Random.DefaultPrng,
    counters: Counters = .{},
    selected_attempts: [std.meta.fields(Source).len]u64 = @splat(0),
    durations: [2]DialTime = @splat(.{}),
    outcomes: [std.meta.fields(t.DialOutcome).len]u64 = @splat(0),
    /// Redials of an endpoint by its previous failure, each counted when the redial is selected.
    retries: [std.meta.fields(t.DialFailure).len]u64 = @splat(0),
    /// Attempts held, and those not yet started on a connection.
    held: Attempts = .{},
    /// Moves on every change to the attempt table or to a manual intent.
    version: u64 = 0,
    /// Pending peers and host demand, recomputed only when a revision or `version` moved.
    demand: ?Demand = null,
    /// Intent rows rekeyed or taken from the deadline heaps. An idle catalog visits none.
    visits: u64 = 0,

    const Demand = struct { revision: u64, intent_revision: u64, version: u64, pending: u16, host: u16 };

    pub const Counters = struct {
        manual_completed: u64 = 0,
        manual_expired: u64 = 0,
        manual_cancelled: u64 = 0,
        failed_intents_released: u64 = 0,
        recent_failures_refused: u64 = 0,
    };
    pub const Resources = struct {
        capacity: usize = 0,
        occupied: usize = 0,
        attempts: usize = 0,
        connected: usize = 0,
        automatic: usize = 0,
        custody_incomplete: usize = 0,
    };
    pub fn resourceSnapshot(self: *const Dialing, catalog: *const Catalog) Resources {
        var result: Resources = .{ .capacity = catalog.intent_capacity, .occupied = catalog.intent_count, .attempts = self.attempts().total };
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            if (row.connection != null) result.connected += 1;
            if (row.intent.automatic) result.automatic += 1;
            if (row.custody_work) |*work| {
                if (!work.exhausted() and work.complete() == null) result.custody_incomplete += 1;
            }
        }
        return result;
    }
    pub fn validateOptions(options: Options) error{InvalidOptions}!void {
        if (options.capacity == 0 or options.capacity > 4096 or options.concurrent_max == 0 or
            options.concurrent_max > attempts_max or options.concurrent_max > options.capacity or
            options.outbound_reserved > options.concurrent_max) return error.InvalidOptions;
    }
    pub fn init(options: Options) !Dialing {
        try validateOptions(options);
        return .{ .options = options, .random = .init(options.seed) };
    }
    pub fn enqueue(self: *Dialing, catalog: *Catalog, peer: *const t.PeerId, addresses: []const t.Address, direct: bool, now_ms: u64) !void {
        return self.enqueueUntil(catalog, peer, addresses, direct, now_ms, now_ms +| connect_timeout_ms);
    }
    pub fn enqueueUntil(self: *Dialing, catalog: *Catalog, peer: *const t.PeerId, addresses: []const t.Address, direct: bool, now_ms: u64, deadline_ms: u64) !void {
        if (deadline_ms <= now_ms or deadline_ms - now_ms > 86_400_000) return error.InvalidDeadline;
        if (addresses.len == 0 or addresses.len > 2) return error.InvalidAddress;
        for (addresses) |address| if (address.port() == 0) return error.InvalidAddress;
        const existing = if (catalog.find(peer)) |ref| catalog.rowFor(ref) else null;
        var prepared: [2]t.Address = undefined;
        var count: u8 = 0;
        if (existing) |row| if (!row.intent.automatic) {
            prepared = row.intent.addresses;
            count = row.intent.address_count;
        };
        for (addresses) |address| {
            var found = false;
            for (prepared[0..count]) |known| found = found or known.eql(address);
            if (found) continue;
            if (count == prepared.len) return error.AddressCapacity;
            prepared[count] = address;
            count += 1;
        }
        const ref = try catalog.retainIntent(peer);
        const row = catalog.rowFor(ref).?;
        row.intent.addresses = prepared;
        row.intent.address_count = count;
        if (row.intent.automatic) row.intent.address_index = 0;
        row.intent.automatic = false;
        if (direct) _ = catalog.setDirect(ref, true);
        if (!direct) row.intent.manual_until_ms = @max(row.intent.manual_until_ms, deadline_ms);
        self.selection_dirty = true;
        self.version +|= 1;
        catalog.markDial(ref.index);
        if (row.connection) |conn| self.accepted(catalog, ref, conn, now_ms);
    }

    /// Requires Discovery.step output with authenticated source scope and a verified ENR.
    pub fn enqueueDiscovered(self: *Dialing, catalog: *Catalog, candidate: *const enr.Candidate, context: *const t.ForkContext, wanted: *const t.Coverage, now_ms: u64) !void {
        try context.validate();
        if (candidate.address_count == 0 or candidate.address_count > 2) return error.InvalidCandidate;
        const hints: enr.Hints = .{ .sequence = candidate.sequence, .record_hash = candidate.record_hash, .fork = candidate.fork, .next_fork_digest = candidate.next_fork_digest, .attnets = candidate.attnets, .syncnets = candidate.syncnets, .custody_group_count = candidate.custody_group_count };
        if (!hints.validFor(context)) return error.InvalidCandidate;
        for (candidate.addresses[0..candidate.address_count]) |address| if (address.port() == 0) return error.InvalidCandidate;
        if (catalog.find(&candidate.peer)) |ref| {
            const row = catalog.rowFor(ref).?;
            if (row.node_id) |id| if (!std.mem.eql(u8, &id, &candidate.node_id)) return error.InvalidCandidate;
            if (row.intent.hints) |previous| {
                if (candidate.sequence < previous.sequence) return error.StaleRecord;
                if (candidate.sequence == previous.sequence) {
                    if (!std.meta.eql(previous, hints)) return error.StaleRecord;
                    if (row.intent.automatic) try mergeAddresses(&row.intent, candidate);
                    row.intent.hints_at_ms = now_ms;
                    self.selection_dirty = true;
                    catalog.markDial(ref.index);
                    return;
                }
            }
            const retained = catalog.intents.isSet(ref.index);
            const admitted = admittedAddresses(catalog, candidate, now_ms);
            if ((!retained or row.intent.automatic) and admitted.count == 0) {
                self.counters.recent_failures_refused +|= 1;
                return error.RecentlyFailed;
            }
            _ = try catalog.retainIntent(&candidate.peer);
            if (!retained) row.intent.automatic = true;
            row.node_id = candidate.node_id;
            row.intent.hints = hints;
            row.intent.hints_at_ms = now_ms;
            if (row.intent.automatic) applyAddresses(&row.intent, &admitted);
            Catalog.prepareCandidateCustody(row, context);
            self.selection_dirty = true;
            catalog.markDial(ref.index);
            return;
        }
        const admitted = admittedAddresses(catalog, candidate, now_ms);
        if (admitted.count == 0) {
            self.counters.recent_failures_refused +|= 1;
            return error.RecentlyFailed;
        }
        var incoming: Row = .{ .identity = candidate.peer, .node_id = candidate.node_id, .intent = .{ .automatic = true, .eligible_at_ms = now_ms, .history_until_ms = now_ms +| history_retention_ms, .hints = hints, .hints_at_ms = now_ms } };
        applyAddresses(&incoming.intent, &admitted);
        Catalog.prepareCandidateCustody(&incoming, context);
        if (catalog.intent_count == catalog.intent_capacity) {
            const index = replacement(catalog, &incoming, context, wanted, now_ms) orelse return error.Capacity;
            // Candidate replacement may retire discovery intent, never established reputation.
            catalog.rows[index].intent.automatic = false;
            catalog.releaseIntent(catalog.reference(index));
        }
        const ref = try catalog.retainIntent(&candidate.peer);
        const row = catalog.rowFor(ref).?;
        row.node_id = incoming.node_id;
        row.intent = incoming.intent;
        row.custody_work = incoming.custody_work;
        row.custody_context = incoming.custody_context;
        self.selection_dirty = true;
        catalog.markDial(ref.index);
    }
    fn replacement(catalog: *const Catalog, incoming: *const Row, context: *const t.ForkContext, wanted: *const t.Coverage, now_ms: u64) ?usize {
        const incoming_utility = matchesDemand(incoming, context, wanted, now_ms);
        var victim: ?usize = null;
        var victim_utility: u2 = 2;
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            if (row.connection != null or row.pending_close != null or row.pending_update or !row.intent.automatic or row.direct or row.attempt != null or
                row.intent.manual_until_ms != 0 or (row.intent.failures == 0 and now_ms < row.intent.eligible_at_ms) or
                row.generation == std.math.maxInt(u64)) continue;
            std.debug.assert(row.connection == null and row.pending_close == null and !row.pending_update);
            const usefulness: u2 = if (row.intent.failures != 0) 0 else matchesDemand(row, context, wanted, now_ms);
            if (incoming_utility < usefulness or (row.intent.failures == 0 and incoming_utility == usefulness and now_ms < row.intent.history_until_ms)) continue;
            if (victim == null or usefulness < victim_utility or (usefulness == victim_utility and row.intent.history_until_ms < catalog.rows[victim.?].intent.history_until_ms)) {
                victim = index;
                victim_utility = usefulness;
            }
        }
        return victim;
    }
    fn mergeAddresses(intent: *catalog_mod.Intent, candidate: *const enr.Candidate) error{StaleRecord}!void {
        var addresses = intent.addresses;
        var count = intent.address_count;
        for (candidate.addresses[0..candidate.address_count]) |address| {
            var found = false;
            for (addresses[0..count]) |known| {
                if (std.meta.activeTag(known) != std.meta.activeTag(address)) continue;
                if (!known.eql(address)) return error.StaleRecord;
                found = true;
            }
            if (found) continue;
            if (count == addresses.len) return error.StaleRecord;
            addresses[count] = address;
            count += 1;
        }
        intent.addresses = addresses;
        intent.address_count = count;
    }
    fn matchesDemand(row: *const Row, context: *const t.ForkContext, wanted: *const t.Coverage, now_ms: u64) u2 {
        const available = Catalog.candidateCoverage(row, context, now_ms);
        if (available.attnets & wanted.attnets != 0 or available.syncnets & wanted.syncnets != 0 or
            available.custody_groups.intersectWith(wanted.custody_groups).count() > 0) return 2;
        return @intFromBool(policy.utility(&available, wanted) > 0);
    }
    pub fn selectionNeeded(self: *const Dialing, catalog: *const Catalog) bool {
        return self.selection_dirty or self.selection_revision != catalog.intent_revision or catalog.intent_revision == std.math.maxInt(u64);
    }
    pub fn configureSelection(self: *Dialing, catalog: *Catalog, wanted: *const t.Coverage, general: bool, context: *const t.ForkContext, now_ms: u64) void {
        self.selection_deadline = null;
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            const deadline = row.intent.hints_at_ms +| hint_freshness_ms;
            if (row.intent.hints != null and now_ms < deadline) self.selection_deadline = @min(self.selection_deadline orelse deadline, deadline);
            row.intent.priority = matchesDemand(row, context, wanted, now_ms);
            const compatible = if (row.intent.hints) |hints| hints.validFor(context) else false;
            row.intent.selected = compatible and (general or row.intent.priority > 0);
            catalog.markDial(index);
        }
        self.selection_dirty = false;
        self.selection_revision = catalog.intent_revision;
    }
    pub fn hostDemand(_: *const Dialing, catalog: *const Catalog) u16 {
        var count: u16 = 0;
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            if ((row.direct or row.intent.manual_until_ms != 0) and row.connection == null) count += 1;
        }
        return count;
    }
    pub const Attempts = struct { total: u16 = 0, unstarted: u16 = 0 };
    pub fn attempts(self: *const Dialing) Attempts {
        return self.held;
    }
    pub const DemandCounts = struct { pending: u16, host: u16 };
    /// Pending peers and host demand, rescanned only when the catalog or the attempt table changed.
    pub fn demandCounts(self: *Dialing, catalog: *const Catalog) DemandCounts {
        const saturated = std.math.maxInt(u64);
        const cacheable = catalog.revision != saturated and catalog.intent_revision != saturated and self.version != saturated;
        if (self.demand) |cached| if (cacheable and cached.revision == catalog.revision and
            cached.intent_revision == catalog.intent_revision and cached.version == self.version)
            return .{ .pending = cached.pending, .host = cached.host };
        const result: DemandCounts = .{ .pending = self.pendingPeers(catalog, null), .host = self.hostDemand(catalog) };
        self.demand = .{ .revision = catalog.revision, .intent_revision = catalog.intent_revision, .version = self.version, .pending = result.pending, .host = result.host };
        return result;
    }
    pub fn pendingPeers(self: *const Dialing, catalog: *const Catalog, except: ?*const t.PeerId) u16 {
        return self.countPeers(catalog, except, false);
    }
    pub fn syncAnswered(self: *Dialing, engine: *const Engine) void {
        for (&self.active) |*attempt| {
            if (attempt.peer == null or attempt.answered) continue;
            const conn = attempt.connection orelse continue;
            attempt.answered = engine.dialAnswered(conn);
        }
    }

    /// Dials the server answered are likely to land, so only they hold peer slots.
    pub fn answeredPeers(self: *const Dialing, catalog: *const Catalog, except: ?*const t.PeerId) u16 {
        return self.countPeers(catalog, except, true);
    }
    fn countPeers(self: *const Dialing, catalog: *const Catalog, except: ?*const t.PeerId, answered_only: bool) u16 {
        var count: u16 = 0;
        for (self.active) |attempt| if (attempt.peer) |peer| {
            if (answered_only and !attempt.answered) continue;
            const row = catalog.rowFor(peer).?;
            if (row.connection != null) continue;
            if (except) |identity| if (row.identity.eql(identity)) continue;
            count += 1;
        };
        return count;
    }
    pub fn selectedPeer(self: *const Dialing, catalog: *const Catalog, identity: *const t.PeerId, now_ms: u64) bool {
        const peer = catalog.find(identity) orelse return false;
        const index = catalog.rowFor(peer).?.attempt orelse return false;
        const attempt = &self.active[index];
        return std.meta.eql(attempt.peer, peer) and now_ms < attempt.lease_until_ms;
    }
    pub fn deferConnection(self: *Dialing, catalog: *Catalog, conn: t.Handle, now_ms: u64) bool {
        for (self.active, 0..) |attempt, index| {
            const peer = attempt.peer orelse continue;
            if (!std.meta.eql(attempt.connection, conn)) continue;
            const row = catalog.rowFor(peer).?;
            self.retire(catalog, @intCast(index), .admission_refused);
            catalog.history.clear(dialedKey(catalog, row, &attempt));
            row.intent.eligible_at_ms = @max(row.intent.eligible_at_ms, now_ms +| 1_000);
            catalog.markDial(peer.index);
            releaseUnused(catalog, peer);
            return true;
        }
        return false;
    }
    pub fn accepted(self: *Dialing, catalog: *Catalog, peer: t.PeerRef, conn: t.Handle, now_ms: u64) void {
        const row = catalog.rowFor(peer).?;
        std.debug.assert(std.meta.eql(row.connection, conn));
        catalog.markDial(peer.index);
        if (row.intent.manual_until_ms != 0) {
            row.intent.manual_until_ms = 0;
            self.version +|= 1;
            self.counters.manual_completed +|= 1;
        }
        if (row.attempt) |index| {
            const attempt = &self.active[index];
            if (attempt.connection) |current| {
                if (!std.meta.eql(current, conn)) return;
                self.durations[0].observe(now_ms -| attempt.started_ms);
                catalog.history.clear(dialedKey(catalog, row, attempt));
            }
            self.retire(catalog, index, .connected);
        }
        row.intent.eligible_at_ms = @max(row.intent.eligible_at_ms, now_ms +| 1_000);
        releaseUnused(catalog, peer);
    }
    pub fn cancelConnect(self: *Dialing, catalog: *Catalog, engine: *Engine, peer: *const t.PeerId, now_ms: u64) void {
        const ref = catalog.find(peer) orelse return;
        const row = catalog.rowFor(ref).?;
        if (row.intent.manual_until_ms != 0) self.counters.manual_cancelled +|= 1;
        row.intent.manual_until_ms = 0;
        self.version +|= 1;
        catalog.markDial(ref.index);
        if (row.attempt) |index| {
            if (self.active[index].connection) |conn| closeAttempt(engine, conn);
            self.retire(catalog, index, .cancelled);
        }
        row.intent.eligible_at_ms = @max(row.intent.eligible_at_ms, now_ms +| 60_000);
        releaseUnused(catalog, ref);
    }
    pub fn dialClosed(self: *Dialing, catalog: *Catalog, conn: t.Handle, reason: t.CloseReason, now_ms: u64) bool {
        for (self.active, 0..) |attempt, index| {
            if (attempt.peer == null or !std.meta.eql(attempt.connection, conn)) continue;
            self.failed(catalog, @intCast(index), now_ms, closeFailure(reason), endpointEvidence(reason));
            return true;
        }
        return false;
    }
    fn closeAttempt(engine: *Engine, conn: t.Handle) void {
        if (engine.peerId(conn) != null) _ = engine.close(conn, 0) else _ = engine.abandon(conn);
    }
    fn attemptFor(self: *Dialing, token: Token) ?*Attempt {
        if (token.index >= self.active.len) return null;
        const attempt = &self.active[token.index];
        return if (attempt.peer != null and attempt.generation == token.generation) attempt else null;
    }
    pub fn dialStarted(self: *Dialing, token: Token, conn: t.Handle) bool {
        const attempt = self.attemptFor(token) orelse return false;
        if (attempt.connection != null) return false;
        attempt.connection = conn;
        self.held.unstarted -= 1;
        self.version +|= 1;
        return true;
    }
    pub fn dialFailed(self: *Dialing, catalog: *Catalog, token: Token, now_ms: u64) bool {
        const attempt = self.attemptFor(token) orelse return false;
        if (attempt.connection != null) return false;
        self.failed(catalog, @intCast(token.index), now_ms, .destination_unreachable, true);
        return true;
    }
    pub fn dialDeferred(self: *Dialing, catalog: *Catalog, token: Token, now_ms: u64) bool {
        const attempt = self.attemptFor(token) orelse return false;
        if (attempt.connection != null) return false;
        const peer = attempt.peer.?;
        const row = catalog.rowFor(peer).?;
        self.retire(catalog, @intCast(token.index), .deferred);
        row.intent.eligible_at_ms = @max(row.intent.eligible_at_ms, now_ms +| 1_000);
        releaseUnused(catalog, peer);
        return true;
    }
    fn retire(self: *Dialing, catalog: *Catalog, index: u8, outcome: t.DialOutcome) void {
        const attempt = &self.active[index];
        const peer = attempt.peer.?;
        const row = catalog.rowFor(peer).?;
        std.debug.assert(row.attempt == index);
        row.attempt = null;
        self.held.total -= 1;
        if (attempt.connection == null) self.held.unstarted -= 1;
        self.version +|= 1;
        catalog.markDial(peer.index);
        attempt.* = .{ .generation = attempt.generation };
        self.outcomes[@intFromEnum(outcome)] +|= 1;
    }
    fn failed(self: *Dialing, catalog: *Catalog, index: u8, now_ms: u64, failure: t.DialFailure, evidence: bool) void {
        const attempt = self.active[index];
        const peer = attempt.peer.?;
        const row = catalog.rowFor(peer).?;
        // Another connection to the peer already won, so this attempt is redundant, not failed.
        const redundant = row.connection != null;
        self.retire(catalog, index, if (redundant) .cancelled else failureOutcome(failure));
        if (!redundant) {
            self.durations[1].observe(now_ms -| attempt.started_ms);
            row.intent.failures = @min(row.intent.failures +| 1, 7);
            catalog.history.markRetry(dialedKey(catalog, row, &attempt), failure, now_ms);
            const base: u64 = @min(@as(u64, 1_000) << @intCast(row.intent.failures - 1), 60_000);
            const jitter = self.random.random().int(u16) % 1_001;
            row.intent.eligible_at_ms = @max(row.intent.eligible_at_ms, now_ms +| @min(base + jitter, 60_000));
        }
        // A redundant attempt leaves the backoff alone but still records its endpoint evidence.
        const learned = evidence and discoveryOnly(row);
        if (learned and remember(catalog, row, &attempt, failure, now_ms)) {
            self.counters.failed_intents_released +|= 1;
            row.intent.automatic = false;
        } else if (learned or !redundant) {
            rotate(catalog, row, &attempt, now_ms);
        }
        releaseUnused(catalog, peer);
    }
    /// Records the dialed endpoint's evidence and reports whether every endpoint of the intent is blocked.
    fn remember(catalog: *Catalog, row: *const Row, attempt: *const Attempt, failure: t.DialFailure, now_ms: u64) bool {
        std.debug.assert(discoveryOnly(row));
        const sequence = if (row.intent.hints) |hints| hints.sequence else 0;
        catalog.history.recordEndpoint(dialedKey(catalog, row, attempt), failure, sequence, now_ms);
        for (row.intent.addresses[0..row.intent.address_count]) |endpoint| {
            if (!catalog.history.blocked(catalog.history.endpointKey(&row.identity, endpoint), sequence, now_ms)) return false;
        }
        return true;
    }
    /// Moves past the dialed endpoint, or stays on the current one when a refresh replaced the dialed
    /// one. A discovery intent skips endpoints its history blocks, so it never returns to a
    /// peer-id-mismatched endpoint while another remains.
    fn rotate(catalog: *const Catalog, row: *Row, attempt: *const Attempt, now_ms: u64) void {
        const intent = &row.intent;
        std.debug.assert(intent.address_index < intent.address_count);
        var start = intent.address_index;
        for (intent.addresses[0..intent.address_count], 0..) |address, position| {
            if (address.eql(attempt.address)) start = @intCast((position + 1) % intent.address_count);
        }
        intent.address_index = start;
        if (!discoveryOnly(row)) return;
        const sequence = if (intent.hints) |hints| hints.sequence else 0;
        for (0..intent.address_count) |offset| {
            const position: u8 = @intCast((start + offset) % intent.address_count);
            if (!catalog.history.blocked(catalog.history.endpointKey(&row.identity, intent.addresses[position]), sequence, now_ms)) {
                intent.address_index = position;
                return;
            }
        }
    }
    fn releaseUnused(catalog: *Catalog, peer: t.PeerRef) void {
        const row = catalog.rowFor(peer).?;
        if (!row.direct and !row.intent.automatic and row.intent.manual_until_ms == 0 and row.attempt == null) catalog.releaseIntent(peer);
    }
    /// Releases an intent that no longer holds a direct, discovery, manual or attempt claim.
    pub fn releaseIfUnused(catalog: *Catalog, peer: t.PeerRef) void {
        if (!catalog.intents.isSet(peer.index)) return;
        releaseUnused(catalog, peer);
    }
    /// Expires the manual intents and attempt leases whose deadline passed. It takes only the due
    /// rows from the heap, and acts on them in the order a scan of every intent and attempt would.
    pub fn expire(self: *Dialing, catalog: *Catalog, engine: ?*Engine, now_ms: u64) void {
        self.sync(catalog, now_ms);
        const due = self.takeDue(catalog, &catalog.dial.expiries, now_ms);
        if (due.len == 0) return;
        std.sort.pdq(u32, due, {}, std.sort.asc(u32));
        for (due) |index| {
            const row = &catalog.rows[index];
            if (!catalog.intents.isSet(index)) continue;
            if (row.intent.manual_until_ms == 0 or now_ms < row.intent.manual_until_ms) continue;
            const peer = catalog.reference(index);
            if (!row.intent.automatic and !row.direct) if (row.attempt) |slot| {
                if (self.active[slot].connection) |conn| {
                    closeAttempt(engine orelse continue, conn);
                }
                self.retire(catalog, slot, .cancelled);
            };
            row.intent.manual_until_ms = 0;
            self.version +|= 1;
            self.counters.manual_expired +|= 1;
            releaseUnused(catalog, peer);
        }
        var leases: u64 = 0;
        for (due) |index| {
            const slot = catalog.rows[index].attempt orelse continue;
            if (now_ms >= self.active[slot].lease_until_ms) leases |= @as(u64, 1) << @intCast(slot);
        }
        // Attempts expire in slot order; each iteration clears the lowest set bit.
        while (leases != 0) : (leases &= leases - 1) {
            const index: u8 = @intCast(@ctz(leases));
            const attempt = self.active[index];
            if (attempt.peer == null or now_ms < attempt.lease_until_ms) continue;
            if (attempt.connection) |conn| closeAttempt(engine orelse continue, conn);
            self.failed(catalog, index, now_ms, .expired, false);
        }
        self.sync(catalog, now_ms);
    }
    /// Takes every row whose key in `heap` is due and marks it for rekeying.
    fn takeDue(self: *Dialing, catalog: *Catalog, heap: *DeadlineHeap, now_ms: u64) []u32 {
        var count: usize = 0;
        // Each row holds at most one key, so the heap empties within rows.len pops.
        while (heap.popDue(now_ms)) |index| {
            catalog.dial.scratch[count] = index;
            count += 1;
            catalog.markDial(index);
        }
        self.visits +|= count;
        return catalog.dial.scratch[0..count];
    }
    /// Rekeys the rows marked since the last read of the heaps.
    fn sync(self: *Dialing, catalog: *Catalog, now_ms: u64) void {
        if (catalog.dial.dirty_count == 0) return;
        var it = catalog.dial.dirty.iterator(.{});
        while (it.next()) |index| self.rekey(catalog, index, now_ms);
        self.visits +|= catalog.dial.dirty_count;
        @memset(catalog.dial.dirty_masks, 0);
        catalog.dial.dirty_count = 0;
    }
    fn rekey(self: *const Dialing, catalog: *Catalog, index: usize, now_ms: u64) void {
        const row = &catalog.rows[index];
        const key: u32 = @intCast(index);
        if (self.expiryOf(catalog, index)) |at| catalog.dial.expiries.set(key, at) else catalog.dial.expiries.clear(key);
        if (catalog.intents.isSet(index) and dialable(row, now_ms))
            catalog.dial.eligible.set(key, eligibleAt(row, now_ms))
        else
            catalog.dial.eligible.clear(key);
    }
    /// The earlier of a manual intent's expiry and its attempt's lease.
    fn expiryOf(self: *const Dialing, catalog: *const Catalog, index: usize) ?u64 {
        const row = &catalog.rows[index];
        var expiry: ?u64 = if (catalog.intents.isSet(index) and row.intent.manual_until_ms != 0) row.intent.manual_until_ms else null;
        if (row.attempt) |slot| {
            const lease = self.active[slot].lease_until_ms;
            expiry = @min(expiry orelse lease, lease);
        }
        return expiry;
    }
    fn freeAttempt(self: *const Dialing) ?u8 {
        for (self.active[0..self.options.concurrent_max], 0..) |attempt, index| {
            if (attempt.peer == null and attempt.generation != std.math.maxInt(u64)) return @intCast(index);
        }
        return null;
    }
    /// Starts attempts for the preferred eligible intents. The candidates are the rows whose
    /// eligibility key is due, the same set a scan of every intent would accept.
    pub fn poll(self: *Dialing, catalog: *Catalog, now_ms: u64, out: []DialIntent) usize {
        self.expire(catalog, null, now_ms);
        if (out.len == 0 or self.freeAttempt() == null) return 0;
        const due = self.takeDue(catalog, &catalog.dial.eligible, now_ms);
        var candidates: usize = 0;
        for (due) |index| {
            const row = &catalog.rows[index];
            if (!catalog.intents.isSet(index) or !dialable(row, now_ms) or now_ms < eligibleAt(row, now_ms)) continue;
            due[candidates] = index;
            candidates += 1;
        }
        const pool = due[0..candidates];
        var count: usize = 0;
        for (0..self.options.concurrent_max) |_| {
            if (count == out.len) break;
            const slot = self.freeAttempt() orelse break;
            var best: ?usize = null;
            var automatic: ?usize = null;
            for (pool) |index| {
                const row = &catalog.rows[index];
                if (row.attempt != null) continue;
                if (self.preferred(catalog, index, best, now_ms)) best = index;
                if (dialTier(row, now_ms) == 0 and self.preferred(catalog, index, automatic, now_ms)) automatic = index;
            }
            const index = (if (self.preferred_starts >= self.options.concurrent_max) automatic orelse best else best) orelse break;
            self.cursor = (index + 1) % catalog.rows.len;
            const row = &catalog.rows[index];
            const attempt = &self.active[slot];
            attempt.* = .{ .generation = attempt.generation + 1, .peer = catalog.reference(index), .started_ms = now_ms, .lease_until_ms = if (row.direct or row.intent.automatic) now_ms +| 10_000 else @min(row.intent.manual_until_ms, now_ms +| 10_000), .address = row.intent.addresses[row.intent.address_index] };
            row.attempt = slot;
            self.held.total += 1;
            self.held.unstarted += 1;
            self.version +|= 1;
            const tier = dialTier(row, now_ms);
            self.preferred_starts = if (tier == 0) 0 else @min(self.preferred_starts + 1, self.options.concurrent_max);
            self.selected_attempts[tier] +|= 1;
            if (catalog.history.takeRetry(dialedKey(catalog, row, attempt), now_ms)) |failure| self.retries[@intFromEnum(failure)] +|= 1;
            out[count] = .{ .token = .{ .index = slot, .generation = attempt.generation }, .peer = row.identity, .address = attempt.address };
            count += 1;
        }
        self.sync(catalog, now_ms);
        return count;
    }
    fn preferred(self: *const Dialing, catalog: *const Catalog, index: usize, current: ?usize, now_ms: u64) bool {
        const best = current orelse return true;
        const row = &catalog.rows[index];
        const other = &catalog.rows[best];
        if (dialTier(row, now_ms) != dialTier(other, now_ms)) return dialTier(row, now_ms) > dialTier(other, now_ms);
        if (row.intent.priority != other.intent.priority) return row.intent.priority > other.intent.priority;
        if (row.intent.failures != other.intent.failures) return row.intent.failures < other.intent.failures;
        return (index + catalog.rows.len - self.cursor) % catalog.rows.len < (best + catalog.rows.len - self.cursor) % catalog.rows.len;
    }
    pub fn eligibleAt(row: *const Row, now_ms: u64) u64 {
        var rep = row.reputation;
        rep.decay(now_ms);
        var due = @max(row.intent.eligible_at_ms, rep.goodbye_until_ms);
        if (rep.banned(now_ms)) due = @max(due, rep.nextDeadline(now_ms) orelse std.math.maxInt(u64));
        if (dialTier(row, now_ms) == 0) due = @max(due, rep.redial_until_ms);
        return due;
    }
    /// The earliest manual expiry or lease, and with dial room the earliest eligible intent,
    /// bounded below by now. It reads the heap tops after rekeying marked rows.
    pub fn nextWakeup(self: *Dialing, catalog: *Catalog, now_ms: u64, output_capacity: usize) ?u64 {
        self.sync(catalog, now_ms);
        if (@import("builtin").is_test) self.checkIntents(catalog, now_ms);
        var due: ?u64 = if (catalog.dial.expiries.peek()) |top| @max(now_ms, top.deadline) else null;
        if (output_capacity != 0 and self.freeAttempt() != null) if (catalog.dial.eligible.peek()) |top| {
            const eligible = @max(now_ms, top.deadline);
            due = @min(due orelse eligible, eligible);
        };
        return due;
    }
    /// Test builds check that the heaps hold every key a scan of every intent and attempt would
    /// compute, that a dialable row due now is due on the heap, and that the counts match the table.
    fn checkIntents(self: *const Dialing, catalog: *const Catalog, now_ms: u64) void {
        assert(catalog.dial.dirty_count == 0);
        var held: Attempts = .{};
        for (self.active, 0..) |attempt, slot| if (attempt.peer) |peer| {
            held.total += 1;
            held.unstarted += @intFromBool(attempt.connection == null);
            assert(catalog.rowFor(peer).?.attempt.? == slot);
            assert(catalog.intents.isSet(peer.index));
        };
        assert(std.meta.eql(held, self.held));
        for (catalog.rows, 0..) |*row, index| {
            const retained = catalog.intents.isSet(index);
            assert(catalog.dial.expiries.get(@intCast(index)) == self.expiryOf(catalog, index));
            const key = catalog.dial.eligible.get(@intCast(index));
            if (retained and dialable(row, now_ms)) {
                // A key computed earlier may stand before a fresh one; it never stands after a due one.
                assert(key != null and key.? <= @max(now_ms, eligibleAt(row, now_ms)) +| 1);
            } else {
                // A lapsed manual intent keeps its key until expire clears it.
                assert(key == null or (row.intent.manual_until_ms != 0 and now_ms >= row.intent.manual_until_ms));
            }
        }
        if (self.demand) |cached| if (cached.revision == catalog.revision and cached.intent_revision == catalog.intent_revision and cached.version == self.version) {
            assert(cached.pending == self.pendingPeers(catalog, null));
            assert(cached.host == self.hostDemand(catalog));
        };
    }
    pub fn shutdown(self: *Dialing, catalog: *Catalog, engine: *Engine) void {
        for (self.active, 0..) |attempt, index| {
            if (attempt.peer == null) continue;
            if (attempt.connection) |conn| closeAttempt(engine, conn);
            self.retire(catalog, @intCast(index), .cancelled);
        }
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const peer = catalog.reference(index);
            _ = catalog.setDirect(peer, false);
            catalog.releaseIntent(peer);
        }
    }
};
fn closeFailure(reason: t.CloseReason) t.DialFailure {
    return switch (reason) {
        .dial_unanswered => .unanswered,
        .handshake_timeout => .handshake_timeout,
        .peer_id_mismatch => .peer_id_mismatch,
        else => .refused,
    };
}
fn failureOutcome(failure: t.DialFailure) t.DialOutcome {
    return switch (failure) {
        inline else => |tag| @field(t.DialOutcome, @tagName(tag)),
    };
}
fn dialTier(row: *const Row, now_ms: u64) u8 {
    return if (row.direct) 2 else if (now_ms < row.intent.manual_until_ms) 1 else 0;
}
fn hasDialIntent(row: *const Row, now_ms: u64) bool {
    return row.direct or now_ms < row.intent.manual_until_ms or (row.intent.automatic and row.intent.selected);
}
/// An intent row the dialer may start an attempt for once it is eligible.
fn dialable(row: *const Row, now_ms: u64) bool {
    return row.connection == null and row.attempt == null and hasDialIntent(row, now_ms);
}
/// Only discovery-only intents record and consult endpoint history.
fn discoveryOnly(row: *const Row) bool {
    return row.intent.automatic and !row.direct and row.intent.manual_until_ms == 0;
}
fn dialedKey(catalog: *const Catalog, row: *const Row, attempt: *const Attempt) u64 {
    return catalog.history.endpointKey(&row.identity, attempt.address);
}

const Admitted = struct { addresses: [2]t.Address = undefined, count: u8 = 0, strikes: u8 = 0 };

fn admittedAddresses(catalog: *const Catalog, candidate: *const enr.Candidate, now_ms: u64) Admitted {
    var result: Admitted = .{};
    for (candidate.addresses[0..candidate.address_count]) |address| {
        if (result.count != 0 and result.addresses[0].eql(address)) continue;
        const key = catalog.history.endpointKey(&candidate.peer, address);
        if (catalog.history.blocked(key, candidate.sequence, now_ms)) continue;
        result.strikes = @max(result.strikes, catalog.history.strikesFor(key, candidate.sequence, now_ms));
        result.addresses[result.count] = address;
        result.count += 1;
    }
    return result;
}

fn applyAddresses(intent: *catalog_mod.Intent, admitted: *const Admitted) void {
    intent.addresses = admitted.addresses;
    intent.address_count = admitted.count;
    intent.address_index = 0;
    intent.failures = @max(intent.failures, admitted.strikes);
}

/// Local closes say nothing about the dialed endpoint; their attempts still count once by outcome.
fn endpointEvidence(reason: t.CloseReason) bool {
    return switch (reason) {
        .host, .send_failed => false,
        .idle_timeout, .handshake_timeout, .dial_unanswered, .peer_id_mismatch, .tls_failed, .peer_closed, .transport_error => true,
    };
}

comptime {
    std.debug.assert(attempts_max <= std.math.maxInt(u8));
}

test {
    _ = @import("dialing_test.zig");
    _ = @import("dialing_catalog_test.zig");
}
