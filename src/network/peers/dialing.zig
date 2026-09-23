const std = @import("std");
const catalog_mod = @import("catalog.zig");
const Catalog = catalog_mod.Catalog;
const Row = catalog_mod.Row;
const policy = @import("policy.zig");
const enr = @import("enr.zig");
const t = @import("types.zig");
const Engine = @import("../quic/engine.zig").Engine;
pub const Token = struct { index: u16, generation: u64 };
pub const DialIntent = struct { token: Token, peer: t.PeerId, address: t.Address };
pub const Options = struct { capacity: u16 = 256, concurrent_max: u16 = 4, seed: u64 };
pub const history_retention_ms = catalog_mod.history_retention_ms;
pub const hint_freshness_ms = catalog_mod.hint_freshness_ms;
pub const connect_timeout_ms: u64 = 30_000;
pub const DialTime = @import("../metrics/histogram.zig").Duration(&.{ 100, 500, 1000, 5000, 10000, 60000 });
pub const Source = enum { discovery, manual, direct };
const Attempt = struct {
    generation: u64 = 0,
    peer: ?t.PeerRef = null,
    connection: ?t.Handle = null,
    started_ms: u64 = 0,
    lease_until_ms: u64 = 0,
};

pub const Dialing = struct {
    options: Options,
    active: [4]Attempt = @splat(.{}),
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
    retries: [std.meta.fields(t.DialFailure).len]u64 = @splat(0),

    pub const Counters = struct {
        manual_completed: u64 = 0,
        manual_expired: u64 = 0,
        manual_cancelled: u64 = 0,
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
            options.concurrent_max > 4 or options.concurrent_max > options.capacity) return error.InvalidOptions;
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
                    return;
                }
            }
            const retained = catalog.intents.isSet(ref.index);
            _ = try catalog.retainIntent(&candidate.peer);
            if (!retained) row.intent.automatic = true;
            row.node_id = candidate.node_id;
            row.intent.hints = hints;
            row.intent.hints_at_ms = now_ms;
            if (row.intent.automatic) copyAddresses(&row.intent, candidate);
            Catalog.prepareCandidateCustody(row, context);
            self.selection_dirty = true;
            return;
        }
        var incoming: Row = .{ .identity = candidate.peer, .node_id = candidate.node_id, .intent = .{ .automatic = true, .eligible_at_ms = now_ms, .history_until_ms = now_ms +| history_retention_ms, .hints = hints, .hints_at_ms = now_ms } };
        copyAddresses(&incoming.intent, candidate);
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
    }
    fn replacement(catalog: *const Catalog, incoming: *const Row, context: *const t.ForkContext, wanted: *const t.Coverage, now_ms: u64) ?usize {
        const incoming_utility = matchesDemand(incoming, context, wanted, now_ms);
        var victim: ?usize = null;
        var victim_utility: u2 = 2;
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            if (row.connection != null or row.pending_close != null or row.pending_update or !row.intent.automatic or row.direct or row.attempt != null or
                row.intent.manual_until_ms != 0 or now_ms < row.intent.eligible_at_ms or row.generation == std.math.maxInt(u64)) continue;
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
    fn copyAddresses(intent: *catalog_mod.Intent, candidate: *const enr.Candidate) void {
        intent.address_count = 0;
        intent.address_index = 0;
        for (candidate.addresses[0..candidate.address_count]) |address| {
            if (intent.address_count != 0 and intent.addresses[0].eql(address)) continue;
            intent.addresses[intent.address_count] = address;
            intent.address_count += 1;
        }
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
        var result: Attempts = .{};
        for (self.active) |attempt| if (attempt.peer != null) {
            result.total += 1;
            if (attempt.connection == null) result.unstarted += 1;
        };
        return result;
    }
    pub fn pendingPeers(self: *const Dialing, catalog: *const Catalog, except: ?*const t.PeerId) u16 {
        var count: u16 = 0;
        for (self.active) |attempt| if (attempt.peer) |peer| {
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
            row.intent.eligible_at_ms = @max(row.intent.eligible_at_ms, now_ms +| 1_000);
            releaseUnused(catalog, peer);
            return true;
        }
        return false;
    }
    pub fn accepted(self: *Dialing, catalog: *Catalog, peer: t.PeerRef, conn: t.Handle, now_ms: u64) void {
        const row = catalog.rowFor(peer).?;
        std.debug.assert(std.meta.eql(row.connection, conn));
        row.intent.last_failure = null;
        if (row.intent.manual_until_ms != 0) {
            row.intent.manual_until_ms = 0;
            self.counters.manual_completed +|= 1;
        }
        if (row.attempt) |index| {
            const attempt = &self.active[index];
            if (attempt.connection) |current| {
                if (!std.meta.eql(current, conn)) return;
                self.durations[0].observe(now_ms -| attempt.started_ms);
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
            self.failed(catalog, @intCast(index), now_ms, closeFailure(reason));
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
        return true;
    }
    pub fn dialFailed(self: *Dialing, catalog: *Catalog, token: Token, now_ms: u64) bool {
        const attempt = self.attemptFor(token) orelse return false;
        if (attempt.connection != null) return false;
        self.failed(catalog, @intCast(token.index), now_ms, .destination_unreachable);
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
        const row = catalog.rowFor(attempt.peer.?).?;
        std.debug.assert(row.attempt == index);
        row.attempt = null;
        attempt.* = .{ .generation = attempt.generation };
        self.outcomes[@intFromEnum(outcome)] +|= 1;
    }
    fn failed(self: *Dialing, catalog: *Catalog, index: u8, now_ms: u64, failure: t.DialFailure) void {
        const attempt = self.active[index];
        const peer = attempt.peer.?;
        const row = catalog.rowFor(peer).?;
        self.retire(catalog, index, failureOutcome(failure));
        if (row.connection == null) {
            self.durations[1].observe(now_ms -| attempt.started_ms);
            row.intent.failures = @min(row.intent.failures +| 1, 7);
            row.intent.last_failure = failure;
            const base: u64 = @min(@as(u64, 1_000) << @intCast(row.intent.failures - 1), 60_000);
            const jitter = self.random.random().int(u16) % 1_001;
            row.intent.eligible_at_ms = @max(row.intent.eligible_at_ms, now_ms +| @min(base + jitter, 60_000));
            row.intent.address_index = (row.intent.address_index + 1) % row.intent.address_count;
        }
        releaseUnused(catalog, peer);
    }
    fn releaseUnused(catalog: *Catalog, peer: t.PeerRef) void {
        const row = catalog.rowFor(peer).?;
        if (!row.direct and !row.intent.automatic and row.intent.manual_until_ms == 0 and row.attempt == null) catalog.releaseIntent(peer);
    }
    pub fn expire(self: *Dialing, catalog: *Catalog, engine: ?*Engine, now_ms: u64) void {
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            const peer = catalog.reference(index);
            if (row.intent.manual_until_ms == 0) {
                releaseUnused(catalog, peer);
                continue;
            }
            if (now_ms < row.intent.manual_until_ms) continue;
            if (!row.intent.automatic and !row.direct) if (row.attempt) |slot| {
                if (self.active[slot].connection) |conn| {
                    closeAttempt(engine orelse continue, conn);
                }
                self.retire(catalog, slot, .cancelled);
            };
            row.intent.manual_until_ms = 0;
            self.counters.manual_expired +|= 1;
            releaseUnused(catalog, peer);
        }
        for (self.active, 0..) |attempt, index| {
            if (attempt.peer == null or now_ms < attempt.lease_until_ms) continue;
            if (attempt.connection) |conn| closeAttempt(engine orelse continue, conn);
            self.failed(catalog, @intCast(index), now_ms, .expired);
        }
    }
    fn freeAttempt(self: *const Dialing) ?u8 {
        for (self.active[0..self.options.concurrent_max], 0..) |attempt, index| {
            if (attempt.peer == null and attempt.generation != std.math.maxInt(u64)) return @intCast(index);
        }
        return null;
    }
    pub fn poll(self: *Dialing, catalog: *Catalog, now_ms: u64, out: []DialIntent) usize {
        self.expire(catalog, null, now_ms);
        var count: usize = 0;
        for (0..self.options.concurrent_max) |_| {
            if (count == out.len) break;
            const slot = self.freeAttempt() orelse break;
            var best: ?usize = null;
            var automatic: ?usize = null;
            var it = catalog.intents.iterator(.{});
            while (it.next()) |index| {
                const row = &catalog.rows[index];
                if (!hasDialIntent(row, now_ms) or row.connection != null or row.attempt != null or now_ms < eligibleAt(row, now_ms)) continue;
                if (self.preferred(catalog, index, best, now_ms)) best = index;
                if (dialTier(row, now_ms) == 0 and self.preferred(catalog, index, automatic, now_ms)) automatic = index;
            }
            const index = (if (self.preferred_starts >= self.options.concurrent_max) automatic orelse best else best) orelse break;
            self.cursor = (index + 1) % catalog.rows.len;
            const row = &catalog.rows[index];
            const attempt = &self.active[slot];
            attempt.* = .{ .generation = attempt.generation + 1, .peer = catalog.reference(index), .started_ms = now_ms, .lease_until_ms = if (row.direct or row.intent.automatic) now_ms +| 10_000 else @min(row.intent.manual_until_ms, now_ms +| 10_000) };
            row.attempt = slot;
            const tier = dialTier(row, now_ms);
            self.preferred_starts = if (tier == 0) 0 else @min(self.preferred_starts + 1, self.options.concurrent_max);
            self.selected_attempts[tier] +|= 1;
            if (row.intent.last_failure) |failure| self.retries[@intFromEnum(failure)] +|= 1;
            out[count] = .{ .token = .{ .index = slot, .generation = attempt.generation }, .peer = row.identity, .address = row.intent.addresses[row.intent.address_index] };
            count += 1;
        }
        return count;
    }
    fn preferred(self: *const Dialing, catalog: *const Catalog, index: usize, current: ?usize, now_ms: u64) bool {
        const best = current orelse return true;
        const row = &catalog.rows[index];
        const other = &catalog.rows[best];
        if (dialTier(row, now_ms) != dialTier(other, now_ms)) return dialTier(row, now_ms) > dialTier(other, now_ms);
        if (row.intent.priority != other.intent.priority) return row.intent.priority > other.intent.priority;
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
    pub fn nextWakeup(self: *const Dialing, catalog: *const Catalog, now_ms: u64, output_capacity: usize) ?u64 {
        var due: ?u64 = null;
        for (self.active) |attempt| if (attempt.peer != null) {
            due = @min(due orelse std.math.maxInt(u64), @max(now_ms, attempt.lease_until_ms));
        };
        const room = output_capacity != 0 and self.freeAttempt() != null;
        var it = catalog.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &catalog.rows[index];
            if (row.intent.manual_until_ms != 0) due = @min(due orelse std.math.maxInt(u64), @max(now_ms, row.intent.manual_until_ms));
            if (!room or row.connection != null or row.attempt != null or !hasDialIntent(row, now_ms)) continue;
            due = @min(due orelse std.math.maxInt(u64), @max(now_ms, eligibleAt(row, now_ms)));
        }
        return due;
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

test {
    _ = @import("dialing_test.zig");
    _ = @import("dialing_catalog_test.zig");
}
