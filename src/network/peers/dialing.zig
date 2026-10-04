const std = @import("std");
const time = @import("../time.zig");
const Catalog = @import("catalog.zig").Catalog;
const Row = Catalog.Row;
const policy = @import("policy.zig");
const enr = @import("enr.zig");
const t = @import("types.zig");
const dial_history = @import("dial_history.zig");
const remembered = @import("remembered.zig");
const Engine = @import("../quic/Engine.zig");
const Now = @import("../types.zig").Now;
const Schedule = @import("../types.zig").Schedule;
const DeadlineHeap = @import("../deadline_heap.zig").DeadlineHeap;
const assert = std.debug.assert;

const history_retention_ms = Catalog.history_retention_ms;
const hint_freshness_ms = Catalog.hint_freshness_ms;

const Attempt = struct {
    generation: u64 = 0,
    selected_ms: u64 = 0,
    peer: ?t.PeerRef = null,
    connection: ?t.Handle = null,
    answered: bool = false,
    lease_until_ms: u64 = 0,
    /// The dialed endpoint, which a discovery refresh may drop from the row's addresses mid-flight.
    address: t.Address = .unspecified,
};

pub const Dialing = struct {
    pub const Token = struct { index: u16, generation: u64 };
    pub const SelectedDial = struct { token: Token, peer: t.PeerId, address: t.Address };
    /// `outbound_reserved` peer slots stay closed to unselected inbound admission so dials can land.
    pub const Options = struct { capacity: u16 = 256, concurrent_max: u16 = 4, outbound_reserved: u16 = 0, seed: u64 };
    /// Unanswered QUIC dials cost one handshake slot each, so the table is sized for dead endpoints,
    /// not for peer headroom.
    pub const attempts_max = 64;
    pub const connect_timeout_ms: u64 = 30_000;
    pub const Source = enum { discovery, manual, direct };
    pub const DialTime = @import("../metrics/histogram.zig").Duration(&.{ 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000 });

    options: Options,
    active: [attempts_max]Attempt = @splat(.{}),
    selection_dirty: bool = true,
    selection_revision: ?u64 = null,
    selection_deadline: ?u64 = null,
    cursor: usize = 0,
    preferred_starts: u16 = 0,
    /// The last automatic start was a remembered candidate's first attempt, so the next one
    /// prefers another candidate: replay interleaves with fresh discovery.
    after_replay: bool = false,
    /// Rows replay queued whose first attempt has not started. Replay keeps at most a burst of
    /// them waiting, and the replay pacer sets when each starts.
    replay_waiting: [remembered.replay_burst]?t.PeerRef = @splat(null),
    random: std.Random.DefaultPrng,
    selected_attempts: [std.meta.fields(Source).len]u64 = @splat(0),
    outcomes: [std.meta.fields(t.DialOutcome).len]u64 = @splat(0),
    /// Time from selection to retirement by outcome; each count equals its outcome counter.
    durations: [std.meta.fields(t.DialOutcome).len]DialTime = @splat(.{}),
    /// Redials of an endpoint by its previous failure, each counted when the redial is selected.
    retries: [std.meta.fields(t.DialFailure).len]u64 = @splat(0),
    /// Discovered candidates refused because every endpoint recently failed, or because the
    /// identity recently rejected us, by that rejection.
    refused: struct { endpoint: u64 = 0, identity: [std.meta.fields(t.Rejection).len]u64 = @splat(0) } = .{},
    /// Attempts held, and those not yet started on a connection.
    held: Attempts = .{},
    /// Moves on every change to the attempt table or to a manual intent.
    version: u64 = 0,
    /// Pending peers and host demand, recomputed only when a revision or `version` moved.
    demand: ?Demand = null,
    /// Intent rows rekeyed or taken from the deadline heaps. An idle catalog visits none.
    visits: u64 = 0,

    const Demand = struct { revision: u64, intent_revision: u64, version: u64, pending: u16, host: u16 };

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
        if (existing) |row| if (!row.dial.automatic) {
            prepared = row.dial.addresses;
            count = row.dial.address_count;
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
        row.dial.addresses = prepared;
        row.dial.address_count = count;
        if (row.dial.automatic) row.dial.address_index = 0;
        row.dial.automatic = false;
        row.dial.replay = .none;
        if (direct) _ = catalog.setDirect(ref, true);
        if (!direct) row.dial.manual_until_ms = @max(row.dial.manual_until_ms, deadline_ms);
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
        var incoming: Row = .{ .identity = candidate.peer, .node_id = candidate.node_id, .dial = .{ .automatic = true, .eligible_at_ms = now_ms, .history_until_ms = now_ms +| history_retention_ms, .hints = hints, .hints_at_ms = now_ms } };
        if (catalog.find(&candidate.peer)) |ref| {
            const row = catalog.rowFor(ref).?;
            if (row.node_id) |id| if (!std.mem.eql(u8, &id, &candidate.node_id)) return error.InvalidCandidate;
            if (row.dial.hints) |previous| {
                if (candidate.sequence < previous.sequence) return error.StaleRecord;
                if (candidate.sequence == previous.sequence) {
                    if (!std.meta.eql(previous, hints)) return error.StaleRecord;
                    if (row.dial.automatic) try mergeAddresses(&row.dial, candidate);
                    row.dial.hints_at_ms = now_ms;
                    self.selection_dirty = true;
                    catalog.markDial(ref.index);
                    return;
                }
            }
            const retained = catalog.intents.isSet(ref.index);
            const admitted = admittedAddresses(catalog, &candidate.peer, candidate.addresses[0..candidate.address_count], candidate.sequence, now_ms);
            if ((!retained or row.dial.automatic) and admitted.count == 0) return self.refuse(&admitted);
            if (!retained) {
                applyAddresses(&incoming.dial, &admitted);
                Catalog.prepareCandidateCustody(&incoming, context);
                _ = try retainCandidate(catalog, &incoming, context, wanted, now_ms);
                row.dial.automatic = true;
            }
            row.node_id = candidate.node_id;
            row.dial.hints = hints;
            row.dial.hints_at_ms = now_ms;
            if (row.dial.automatic) applyAddresses(&row.dial, &admitted);
            Catalog.prepareCandidateCustody(row, context);
            self.selection_dirty = true;
            catalog.markDial(ref.index);
            return;
        }
        const admitted = admittedAddresses(catalog, &candidate.peer, candidate.addresses[0..candidate.address_count], candidate.sequence, now_ms);
        if (admitted.count == 0) return self.refuse(&admitted);
        applyAddresses(&incoming.dial, &admitted);
        Catalog.prepareCandidateCustody(&incoming, context);
        const ref = try retainCandidate(catalog, &incoming, context, wanted, now_ms);
        const row = catalog.rowFor(ref).?;
        row.node_id = incoming.node_id;
        row.dial = incoming.dial;
        row.custody_work = incoming.custody_work;
        row.custody_context = incoming.custody_context;
        self.selection_dirty = true;
        catalog.markDial(ref.index);
    }
    fn refuse(self: *Dialing, admitted: *const Admitted) error{ RecentlyFailed, RecentlyRejected } {
        const kind = admitted.rejection orelse {
            self.refused.endpoint +|= 1;
            return error.RecentlyFailed;
        };
        self.refused.identity[@intFromEnum(kind)] +|= 1;
        return error.RecentlyRejected;
    }
    /// Queues loaded remembered records as automatic candidates until a burst of them waits for a
    /// first attempt, and returns how many it queued. Poll starts those attempts as the replay
    /// pacer allows, and the eligibility heap wakes it for them.
    pub fn replayRemembered(self: *Dialing, catalog: *Catalog, context: *const t.ForkContext, wanted: *const t.Coverage, now: Now) usize {
        const memory = &catalog.remembered;
        var queued: usize = 0;
        for (&self.replay_waiting) |*waiting| {
            if (waiting.*) |peer| if (catalog.rowFor(peer)) |row| if (row.dial.replay == .untried) continue;
            waiting.* = null;
            // Each pass takes one loaded record, so a call visits every record at most once.
            for (0..remembered.capacity) |_| {
                const record = memory.nextReplay(remembered.seconds(now)) orelse return queued;
                const outcome = self.queueRemembered(catalog, &record, context, wanted, now.millis());
                memory.counters.replays[@intFromEnum(outcome)] +|= 1;
                if (outcome != .queued) continue;
                waiting.* = catalog.find(&record.peer).?;
                queued += 1;
                break;
            }
        }
        return queued;
    }
    /// A remembered candidate keeps its proven endpoint and has no ENR hints, so selection admits
    /// it only under general demand. It meets the identity's rejection memory, the endpoint's
    /// history, the peer's own dial deadlines and candidate replacement.
    fn queueRemembered(self: *Dialing, catalog: *Catalog, record: *const remembered.Record, context: *const t.ForkContext, wanted: *const t.Coverage, now_ms: u64) remembered.Replay {
        if (catalog.find(&record.peer)) |ref| {
            const row = catalog.rowFor(ref).?;
            if (row.connection != null or catalog.intents.isSet(ref.index)) return .known;
            if (eligibleAt(catalog, row, now_ms) > now_ms) return .failed;
        }
        const admitted = admittedAddresses(catalog, &record.peer, &.{record.address}, 0, now_ms);
        if (admitted.rejection != null) return .rejected;
        if (admitted.count == 0) return .failed;
        const incoming: Row = .{ .identity = record.peer, .dial = .{ .automatic = true, .replay = .untried } };
        const ref = retainCandidate(catalog, &incoming, context, wanted, now_ms) catch return .capacity;
        const row = catalog.rowFor(ref).?;
        row.dial.automatic = true;
        row.dial.replay = .untried;
        row.dial.eligible_at_ms = @max(row.dial.eligible_at_ms, now_ms);
        row.dial.history_until_ms = @max(row.dial.history_until_ms, now_ms +| history_retention_ms);
        applyAddresses(&row.dial, &admitted);
        self.selection_dirty = true;
        catalog.markDial(ref.index);
        return .queued;
    }
    fn retainCandidate(catalog: *Catalog, incoming: *const Row, context: *const t.ForkContext, wanted: *const t.Coverage, now_ms: u64) error{Capacity}!t.PeerRef {
        if (catalog.intent_count == catalog.intent_capacity) {
            const index = replacement(catalog, incoming, context, wanted, now_ms) orelse return error.Capacity;
            // Candidate replacement may retire discovery intent, never established reputation.
            catalog.rows[index].dial.automatic = false;
            catalog.releaseIntent(catalog.reference(index));
        }
        return catalog.retainIntent(&incoming.identity);
    }
    fn replacement(catalog: *const Catalog, incoming: *const Row, context: *const t.ForkContext, wanted: *const t.Coverage, now_ms: u64) ?usize {
        const incoming_utility = matchesDemand(incoming, context, wanted, now_ms);
        var victim: ?usize = null;
        var victim_utility: u2 = 2;
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            if (row.connection != null or row.pending_close != null or row.pending_update or !row.dial.automatic or row.direct or row.attempt != null or
                row.dial.manual_until_ms != 0 or (row.dial.failures == 0 and now_ms < row.dial.eligible_at_ms) or
                row.generation == std.math.maxInt(u64)) continue;
            std.debug.assert(row.connection == null and row.pending_close == null and !row.pending_update);
            const usefulness: u2 = if (row.dial.failures != 0) 0 else matchesDemand(row, context, wanted, now_ms);
            if (incoming_utility < usefulness or (row.dial.failures == 0 and incoming_utility == usefulness and now_ms < row.dial.history_until_ms)) continue;
            if (victim == null or usefulness < victim_utility or (usefulness == victim_utility and row.dial.history_until_ms < catalog.rows[victim.?].dial.history_until_ms)) {
                victim = index;
                victim_utility = usefulness;
            }
        }
        return victim;
    }
    fn mergeAddresses(state: *Catalog.DialState, candidate: *const enr.Candidate) error{StaleRecord}!void {
        var addresses = state.addresses;
        var count = state.address_count;
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
        state.addresses = addresses;
        state.address_count = count;
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
            const deadline = row.dial.hints_at_ms +| hint_freshness_ms;
            if (row.dial.hints != null and now_ms < deadline) self.selection_deadline = @min(self.selection_deadline orelse deadline, deadline);
            row.dial.priority = matchesDemand(row, context, wanted, now_ms);
            row.dial.selected = if (row.dial.hints) |hints|
                hints.validFor(context) and (general or row.dial.priority > 0)
            else
                general and row.dial.replay != .none;
            catalog.markDial(index);
        }
        self.selection_dirty = false;
        self.selection_revision = catalog.intent_revision;
    }
    fn hostDemand(_: *const Dialing, catalog: *const Catalog) u16 {
        var count: u16 = 0;
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            if ((row.direct or row.dial.manual_until_ms != 0) and row.connection == null) count += 1;
        }
        return count;
    }
    pub const Attempts = struct { total: u16 = 0, unstarted: u16 = 0 };
    pub fn attempts(self: *const Dialing) Attempts {
        return self.held;
    }
    pub const DemandCounts = struct { pending: u16, host: u16 };
    /// Pending peers and host demand, rescanned only when the catalog or the attempt table changed.
    pub fn demandCounts(self: *const Dialing, catalog: *const Catalog) DemandCounts {
        const saturated = std.math.maxInt(u64);
        const cacheable = catalog.revision != saturated and catalog.intent_revision != saturated and self.version != saturated;
        if (self.demand) |cached| if (cacheable and cached.revision == catalog.revision and
            cached.intent_revision == catalog.intent_revision and cached.version == self.version)
            return .{ .pending = cached.pending, .host = cached.host };
        const result: DemandCounts = .{ .pending = self.pendingPeers(catalog, null), .host = self.hostDemand(catalog) };
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
            self.retire(catalog, @intCast(index), .admission_refused, now_ms);
            row.dial.eligible_at_ms = @max(row.dial.eligible_at_ms, now_ms +| 1_000);
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
        // Any connection to a remembered candidate ends its turn for a paced first attempt.
        if (row.dial.replay == .untried) row.dial.replay = .tried;
        if (row.dial.manual_until_ms != 0) {
            row.dial.manual_until_ms = 0;
            self.version +|= 1;
        }
        if (row.attempt) |index| {
            const attempt = &self.active[index];
            if (attempt.connection) |current| {
                if (!std.meta.eql(current, conn)) return;
                row.dialed = attempt.address;
                if (discoveryOnly(row)) {
                    row.origin = origin(row);
                    catalog.remembered.note(row.origin.?, .connected);
                }
            }
            self.retire(catalog, index, .connected, now_ms);
        }
        row.dial.eligible_at_ms = @max(row.dial.eligible_at_ms, now_ms +| 1_000);
        releaseUnused(catalog, peer);
    }
    pub fn cancelConnect(self: *Dialing, catalog: *Catalog, peer: *const t.PeerId, now_ms: u64) ?t.Handle {
        const ref = catalog.find(peer) orelse return null;
        const row = catalog.rowFor(ref).?;
        var close: ?t.Handle = null;
        row.dial.manual_until_ms = 0;
        self.version +|= 1;
        catalog.markDial(ref.index);
        if (row.attempt) |index| {
            close = self.active[index].connection;
            self.retire(catalog, index, .cancelled, now_ms);
        }
        row.dial.eligible_at_ms = @max(row.dial.eligible_at_ms, now_ms +| 60_000);
        releaseUnused(catalog, ref);
        return close;
    }
    pub fn dialClosed(self: *Dialing, catalog: *Catalog, conn: t.Handle, reason: t.CloseReason, now_ms: u64) bool {
        for (self.active, 0..) |attempt, index| {
            if (attempt.peer == null or !std.meta.eql(attempt.connection, conn)) continue;
            self.failed(catalog, @intCast(index), now_ms, closeFailure(reason), endpointEvidence(reason));
            return true;
        }
        return false;
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
        self.retire(catalog, @intCast(token.index), .deferred, now_ms);
        row.dial.eligible_at_ms = @max(row.dial.eligible_at_ms, now_ms +| 1_000);
        releaseUnused(catalog, peer);
        return true;
    }
    fn retire(self: *Dialing, catalog: *Catalog, index: u8, outcome: t.DialOutcome, now_ms: u64) void {
        const attempt = &self.active[index];
        const peer = attempt.peer.?;
        const row = catalog.rowFor(peer).?;
        std.debug.assert(row.attempt == index);
        row.attempt = null;
        self.held.total -= 1;
        if (attempt.connection == null) self.held.unstarted -= 1;
        self.version +|= 1;
        catalog.markDial(peer.index);
        self.durations[@intFromEnum(outcome)].observe(now_ms -| attempt.selected_ms);
        attempt.* = .{ .generation = attempt.generation };
        self.outcomes[@intFromEnum(outcome)] +|= 1;
    }
    fn failed(self: *Dialing, catalog: *Catalog, index: u8, now_ms: u64, failure: t.DialFailure, evidence: bool) void {
        const attempt = self.active[index];
        const peer = attempt.peer.?;
        const row = catalog.rowFor(peer).?;
        // Another connection to the peer already won, so this attempt is redundant, not failed.
        const redundant = row.connection != null;
        self.retire(catalog, index, if (redundant) .cancelled else failureOutcome(failure), now_ms);
        if (!redundant) {
            row.dial.failures = @min(row.dial.failures +| 1, 7);
            catalog.history.markRetry(dialedKey(catalog, row, &attempt), failure, now_ms);
            const base: u64 = @min(@as(u64, 1_000) << @intCast(row.dial.failures - 1), 60_000);
            const jitter = self.random.random().int(u16) % 1_001;
            row.dial.eligible_at_ms = @max(row.dial.eligible_at_ms, now_ms +| @min(base + jitter, 60_000));
        }
        if (failure == .peer_id_mismatch) catalog.remembered.forgetEndpoint(&row.identity, attempt.address);
        // A redundant attempt leaves the backoff alone but still records its endpoint evidence.
        const learned = evidence and discoveryOnly(row);
        if (learned and remember(catalog, row, &attempt, failure, now_ms)) {
            row.dial.automatic = false;
        } else if (learned or !redundant) {
            rotate(catalog, row, &attempt, now_ms);
        }
        releaseUnused(catalog, peer);
    }
    /// Records the dialed endpoint's evidence and reports whether every endpoint of the intent is blocked.
    fn remember(catalog: *Catalog, row: *const Row, attempt: *const Attempt, failure: t.DialFailure, now_ms: u64) bool {
        std.debug.assert(discoveryOnly(row));
        const sequence = if (row.dial.hints) |hints| hints.sequence else 0;
        catalog.history.recordEndpoint(dialedKey(catalog, row, attempt), failure, sequence, now_ms);
        for (row.dial.addresses[0..row.dial.address_count]) |endpoint| {
            if (!catalog.history.blocked(catalog.history.endpointKey(&row.identity, endpoint), sequence, now_ms)) return false;
        }
        return true;
    }
    /// Moves past the dialed endpoint, or stays on the current one when a refresh replaced the dialed
    /// one. A discovery intent skips endpoints its history blocks, so it never returns to a
    /// peer-id-mismatched endpoint while another remains.
    fn rotate(catalog: *const Catalog, row: *Row, attempt: *const Attempt, now_ms: u64) void {
        const intent = &row.dial;
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
        if (!row.direct and !row.dial.automatic and row.dial.manual_until_ms == 0 and row.attempt == null) catalog.releaseIntent(peer);
    }
    /// Releases an intent that no longer holds a direct, discovery, manual or attempt claim.
    pub fn releaseIfUnused(catalog: *Catalog, peer: t.PeerRef) void {
        if (!catalog.intents.isSet(peer.index)) return;
        releaseUnused(catalog, peer);
    }
    /// Expires the manual intents and attempt leases whose deadline passed. It takes only the due
    /// rows from the heap, and acts on them in the order a scan of every intent and attempt would.
    /// Close the returned connections before delivering transport events or selecting more dials.
    pub fn expire(self: *Dialing, catalog: *Catalog, now_ms: u64, close: *[attempts_max]t.Handle) usize {
        var count: usize = 0;
        self.refresh(catalog, now_ms);
        const due = self.takeDue(catalog, &catalog.dial.expiries, now_ms);
        if (due.len == 0) return 0;
        std.sort.pdq(u32, due, {}, std.sort.asc(u32));
        for (due) |index| {
            const row = &catalog.rows[index];
            if (!catalog.intents.isSet(index)) continue;
            if (row.dial.manual_until_ms == 0 or now_ms < row.dial.manual_until_ms) continue;
            const peer = catalog.reference(index);
            if (!row.dial.automatic and !row.direct) if (row.attempt) |slot| {
                if (self.active[slot].connection) |conn| {
                    close[count] = conn;
                    count += 1;
                }
                self.retire(catalog, slot, .cancelled, now_ms);
            };
            row.dial.manual_until_ms = 0;
            self.version +|= 1;
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
            if (attempt.connection) |conn| {
                close[count] = conn;
                count += 1;
            }
            self.failed(catalog, index, now_ms, .expired, false);
        }
        self.refresh(catalog, now_ms);
        return count;
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
    /// Applies pending intent changes to the deadline heaps before the next selection.
    pub fn refresh(self: *Dialing, catalog: *Catalog, now_ms: u64) void {
        const result = self.demandCounts(catalog);
        self.demand = .{ .revision = catalog.revision, .intent_revision = catalog.intent_revision, .version = self.version, .pending = result.pending, .host = result.host };
        if (catalog.dial.dirty_count == 0) return;
        var it = catalog.dial.dirty.iterator(.{});
        while (it.next()) |index| self.rekey(catalog, index, now_ms);
        self.visits +|= catalog.dial.dirty_count;
        @memset(catalog.dial.dirty_masks, 0);
        catalog.dial.dirty_count = 0;
        if (@import("builtin").is_test) self.checkIntents(catalog, now_ms);
    }
    fn rekey(self: *const Dialing, catalog: *Catalog, index: usize, now_ms: u64) void {
        const row = &catalog.rows[index];
        const key: u32 = @intCast(index);
        if (self.expiryOf(catalog, index)) |at| catalog.dial.expiries.set(key, at) else catalog.dial.expiries.clear(key);
        if (catalog.intents.isSet(index) and dialable(row, now_ms))
            catalog.dial.eligible.set(key, eligibleAt(catalog, row, now_ms))
        else
            catalog.dial.eligible.clear(key);
    }
    /// The earlier of a manual intent's expiry and its attempt's lease.
    fn expiryOf(self: *const Dialing, catalog: *const Catalog, index: usize) ?u64 {
        const row = &catalog.rows[index];
        var expiry: ?u64 = if (catalog.intents.isSet(index) and row.dial.manual_until_ms != 0) row.dial.manual_until_ms else null;
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
    /// Call `expire` and close its returned connections before selecting attempts at this time.
    pub fn poll(self: *Dialing, catalog: *Catalog, now_ms: u64, out: []SelectedDial) usize {
        self.refresh(catalog, now_ms);
        if (out.len == 0 or self.freeAttempt() == null) return 0;
        const due = self.takeDue(catalog, &catalog.dial.eligible, now_ms);
        var candidates: usize = 0;
        for (due) |index| {
            const row = &catalog.rows[index];
            if (!catalog.intents.isSet(index) or !dialable(row, now_ms) or now_ms < eligibleAt(catalog, row, now_ms)) continue;
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
            const favor_replay = !self.after_replay;
            // A remembered first attempt starts only as the replay pacer allows, and spends it.
            const replay_ready = now_ms >= catalog.remembered.replayDue();
            for (pool) |index| {
                const row = &catalog.rows[index];
                if (row.attempt != null or (row.dial.replay == .untried and !replay_ready)) continue;
                if (self.preferred(catalog, index, best, now_ms, favor_replay)) best = index;
                if (dialTier(row, now_ms) == 0 and self.preferred(catalog, index, automatic, now_ms, favor_replay)) automatic = index;
            }
            const index = (if (self.preferred_starts >= self.options.concurrent_max) automatic orelse best else best) orelse break;
            self.cursor = (index + 1) % catalog.rows.len;
            const row = &catalog.rows[index];
            const attempt = &self.active[slot];
            attempt.* = .{ .generation = attempt.generation + 1, .selected_ms = now_ms, .peer = catalog.reference(index), .lease_until_ms = if (row.direct or row.dial.automatic) now_ms +| 10_000 else @min(row.dial.manual_until_ms, now_ms +| 10_000), .address = row.dial.addresses[row.dial.address_index] };
            row.attempt = slot;
            self.held.total += 1;
            self.held.unstarted += 1;
            self.version +|= 1;
            const tier = dialTier(row, now_ms);
            self.preferred_starts = if (tier == 0) 0 else @min(self.preferred_starts + 1, self.options.concurrent_max);
            self.selected_attempts[tier] +|= 1;
            if (tier == 0) self.after_replay = row.dial.replay == .untried;
            if (row.dial.replay == .untried) {
                catalog.remembered.takeReplay(now_ms);
                row.dial.replay = .tried;
            }
            if (discoveryOnly(row)) catalog.remembered.note(origin(row), .dialed);
            if (catalog.history.takeRetry(dialedKey(catalog, row, attempt), now_ms)) |failure| self.retries[@intFromEnum(failure)] +|= 1;
            out[count] = .{ .token = .{ .index = slot, .generation = attempt.generation }, .peer = row.identity, .address = attempt.address };
            count += 1;
        }
        self.refresh(catalog, now_ms);
        return count;
    }
    /// Orders by dial tier, then remembered first attempts ahead of other candidates when
    /// `favor_replay` and behind them otherwise, then demand priority, fewer failures and the
    /// rotating cursor. A remembered peer served us before but has no ENR to rank its coverage by,
    /// so its first attempt goes ahead of coverage priority on its turn.
    fn preferred(self: *const Dialing, catalog: *const Catalog, index: usize, current: ?usize, now_ms: u64, favor_replay: bool) bool {
        const best = current orelse return true;
        const row = &catalog.rows[index];
        const other = &catalog.rows[best];
        if (dialTier(row, now_ms) != dialTier(other, now_ms)) return dialTier(row, now_ms) > dialTier(other, now_ms);
        const untried = row.dial.replay == .untried;
        if (untried != (other.dial.replay == .untried)) return untried == favor_replay;
        if (row.dial.priority != other.dial.priority) return row.dial.priority > other.dial.priority;
        if (row.dial.failures != other.dial.failures) return row.dial.failures < other.dial.failures;
        return (index + catalog.rows.len - self.cursor) % catalog.rows.len < (best + catalog.rows.len - self.cursor) % catalog.rows.len;
    }
    /// Only a live manual intent dials through the identity's rejection block; discovery and direct
    /// retries wait for it. A key computed from a block the history later forgets keeps the row
    /// waiting until that block's end. A remembered first attempt also waits for the replay pacer,
    /// whose due time only moves later.
    fn eligibleAt(catalog: *const Catalog, row: *const Row, now_ms: u64) u64 {
        var rep = row.reputation;
        rep.decay(now_ms);
        var due = @max(row.dial.eligible_at_ms, rep.goodbye_until_ms);
        if (rep.banned(now_ms)) due = @max(due, rep.nextDeadline(now_ms) orelse std.math.maxInt(u64));
        if (dialTier(row, now_ms) == 0) due = @max(due, rep.redial_until_ms);
        if (now_ms >= row.dial.manual_until_ms) due = @max(due, catalog.history.rejectedUntil(catalog.history.identityKey(&row.identity), now_ms));
        if (row.dial.replay == .untried) due = @max(due, catalog.remembered.replayDue());
        return due;
    }
    /// Dirty intents need one refresh even when output capacity prevents starting a dial.
    pub fn schedule(self: *const Dialing, catalog: *const Catalog, output_capacity: usize) Schedule {
        var result: Schedule = .{
            .runnable = catalog.dial.dirty_count != 0,
            .deadline = time.optionalMilliseconds(if (catalog.dial.expiries.peek()) |top| top.deadline else null),
        };
        if (output_capacity != 0 and self.freeAttempt() != null) if (catalog.dial.eligible.peek()) |top| {
            result = result.merge(.{ .deadline = time.optionalMilliseconds(top.deadline) });
        };
        return result;
    }
    /// Test builds check that the heaps hold every key a scan of every intent and attempt would
    /// compute, that a dialable row due now is due on the heap unless it waits out a forgotten
    /// rejection block, that the counts match the table, and that each outcome's dial times count
    /// every attempt it retired.
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
        for (self.outcomes, self.durations) |count, duration| assert(duration.count == count);
        for (catalog.rows, 0..) |*row, index| {
            const retained = catalog.intents.isSet(index);
            assert(catalog.dial.expiries.get(@intCast(index)) == self.expiryOf(catalog, index));
            const key = catalog.dial.eligible.get(@intCast(index));
            if (retained and dialable(row, now_ms)) {
                // A key computed earlier may stand before a fresh one, which costs a wake. It stands
                // after a due one only when the history forgot the rejection block it waits for, an
                // eviction or a colliding clear, and then no longer than that block could run.
                const due = @max(now_ms, eligibleAt(catalog, row, now_ms)) +| 1;
                const forgotten = catalog.history.rejectedUntil(catalog.history.identityKey(&row.identity), now_ms) == 0;
                assert(key != null and (key.? <= due or (forgotten and key.? <= now_ms +| dial_history.rejection_block_max_ms)));
            } else {
                // A lapsed manual intent keeps its key until expire clears it.
                assert(key == null or (row.dial.manual_until_ms != 0 and now_ms >= row.dial.manual_until_ms));
            }
        }
        if (self.demand) |cached| if (cached.revision == catalog.revision and cached.intent_revision == catalog.intent_revision and cached.version == self.version) {
            assert(cached.pending == self.pendingPeers(catalog, null));
            assert(cached.host == self.hostDemand(catalog));
        };
    }
    pub fn shutdown(self: *Dialing, catalog: *Catalog, now_ms: u64, close: *[attempts_max]t.Handle) usize {
        var count: usize = 0;
        for (self.active, 0..) |attempt, index| {
            if (attempt.peer == null) continue;
            if (attempt.connection) |conn| {
                close[count] = conn;
                count += 1;
            }
            self.retire(catalog, @intCast(index), .cancelled, now_ms);
        }
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const peer = catalog.reference(index);
            _ = catalog.setDirect(peer, false);
            catalog.releaseIntent(peer);
        }
        return count;
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
        // A health close follows an admitted connection, whose attempt already retired as connected.
        .health => unreachable,
        inline else => |tag| @field(t.DialOutcome, @tagName(tag)),
    };
}
fn dialTier(row: *const Row, now_ms: u64) u8 {
    return if (row.direct) 2 else if (now_ms < row.dial.manual_until_ms) 1 else 0;
}
fn hasDialIntent(row: *const Row, now_ms: u64) bool {
    return row.direct or now_ms < row.dial.manual_until_ms or (row.dial.automatic and row.dial.selected);
}
/// An intent row the dialer may start an attempt for once it is eligible.
fn dialable(row: *const Row, now_ms: u64) bool {
    return row.connection == null and row.attempt == null and hasDialIntent(row, now_ms);
}
/// Only discovery-only intents record and consult endpoint history.
fn discoveryOnly(row: *const Row) bool {
    return row.dial.automatic and !row.direct and row.dial.manual_until_ms == 0;
}
fn origin(row: *const Row) remembered.Origin {
    return if (row.dial.replay == .none) .fresh else .remembered;
}
fn dialedKey(catalog: *const Catalog, row: *const Row, attempt: *const Attempt) u64 {
    return catalog.history.endpointKey(&row.identity, attempt.address);
}

const Admitted = struct { addresses: [2]t.Address = undefined, count: u8 = 0, strikes: u8 = 0, rejection: ?t.Rejection = null };

/// The candidate's endpoints its dial history admits: none while the identity's rejection blocks
/// it, else those without a blocking failure. A remembered candidate has no ENR sequence, 0, so no
/// newer record lifts a block.
fn admittedAddresses(catalog: *const Catalog, peer: *const t.PeerId, addresses: []const t.Address, sequence: u64, now_ms: u64) Admitted {
    std.debug.assert(addresses.len <= 2);
    var result: Admitted = .{ .rejection = catalog.history.rejection(catalog.history.identityKey(peer), now_ms) };
    if (result.rejection != null) return result;
    for (addresses) |address| {
        if (result.count != 0 and result.addresses[0].eql(address)) continue;
        const key = catalog.history.endpointKey(peer, address);
        if (catalog.history.blocked(key, sequence, now_ms)) continue;
        result.strikes = @max(result.strikes, catalog.history.strikesFor(key, sequence, now_ms));
        result.addresses[result.count] = address;
        result.count += 1;
    }
    return result;
}

fn applyAddresses(state: *Catalog.DialState, admitted: *const Admitted) void {
    state.addresses = admitted.addresses;
    state.address_count = admitted.count;
    state.address_index = 0;
    state.failures = @max(state.failures, admitted.strikes);
}

/// Local closes say nothing about the dialed endpoint; their attempts still count once by outcome.
fn endpointEvidence(reason: t.CloseReason) bool {
    return switch (reason) {
        .host, .send_failed => false,
        .idle_timeout, .handshake_timeout, .dial_unanswered, .peer_id_mismatch, .tls_failed, .peer_closed, .transport_error => true,
    };
}

comptime {
    std.debug.assert(Dialing.attempts_max <= std.math.maxInt(u8));
}

test {
    _ = @import("dialing_test.zig");
    _ = @import("dialing_catalog_test.zig");
    _ = @import("dialing_candidates_test.zig");
    _ = @import("dialing_custody_test.zig");
    _ = @import("dialing_history_test.zig");
    _ = @import("dialing_metrics_test.zig");
    _ = @import("dialing_replay_test.zig");
    _ = @import("dialing_enr_test.zig");
}
