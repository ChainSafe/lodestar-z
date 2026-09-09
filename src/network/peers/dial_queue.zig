const std = @import("std");
const custody = @import("custody.zig");
const policy = @import("policy.zig");
const enr = @import("enr.zig");
const t = @import("types.zig");
pub const Token = struct { index: u16, generation: u64 };
pub const DialIntent = struct { token: Token, peer: t.PeerId, address: t.Address };
pub const Options = struct {
    capacity: u16 = 256,
    concurrent_max: u16 = 4,
    engine_dialing_max: u16 = 16,
    seed: u64,
};
pub const history_retention_ms: u64 = 600_000;
pub const hint_freshness_ms: u64 = 300_000;
pub const connect_timeout_ms: u64 = 30_000;
const stable_connection_ms: u64 = 300_000;
pub const Hints = struct {
    node_id: [32]u8,
    sequence: u64,
    fork: enr.ForkId,
    next_fork_digest: ?[4]u8,
    attnets: ?[8]u8,
    syncnets: ?u8,
    custody_group_count: ?u64,

    fn validFor(self: *const Hints, context: *const t.ForkContext) bool {
        context.validate() catch return false;
        if (!std.mem.eql(u8, &self.fork.digest, &context.digest)) return false;
        if (self.syncnets) |bits| if (bits & 0xf0 != 0) return false;
        if (self.custody_group_count) |count| if (count == 0 or count > context.custody_groups) return false;
        return true;
    }
};
const Row = struct {
    automatic: bool = false,
    selected: bool = true,
    priority: u16 = 0,
    hints: ?Hints = null,
    hints_at_ms: u64 = 0,
    history_until_ms: u64 = 0,
    custody_work: ?custody.Derivation = null,
    custody_context: ?t.ForkContext = null,
    occupied: bool = false,
    generation: u64 = 0,
    peer: t.PeerId = undefined,
    addresses: [2]t.Address = undefined,
    address_count: u8 = 0,
    address_index: u8 = 0,
    direct: bool = false,
    connected: bool = false,
    attempt: bool = false,
    conn: ?t.Handle = null,
    eligible_at_ms: u64 = 0,
    lease_expires_at_ms: u64 = 0,
    failures: u8 = 0,
    manual_until_ms: u64 = 0,
};
pub const DialQueue = struct {
    rows: []Row,
    options: Options,
    selection_dirty: bool = true,
    selection_deadline: ?u64 = null,
    cursor: usize = 0,
    custody_cursor: usize = 0,
    random: std.Random.DefaultPrng,
    counters: Counters = .{},

    pub const Counters = struct {
        manual_completed: u64 = 0,
        manual_expired: u64 = 0,
        manual_cancelled: u64 = 0,
        connection_backoffs: u64 = 0,
    };

    pub const Resources = struct {
        capacity: usize = 0,
        occupied: usize = 0,
        attempts: usize = 0,
        connected: usize = 0,
        automatic: usize = 0,
        /// Retained unfinished derivations, including expired hints; excludes exhausted work.
        custody_incomplete: usize = 0,
    };

    pub fn resourceSnapshot(self: *const DialQueue) Resources {
        var result: Resources = .{ .capacity = self.rows.len };
        for (self.rows) |*row| {
            if (!row.occupied) continue;
            result.occupied += 1;
            if (row.attempt) result.attempts += 1;
            if (row.connected) result.connected += 1;
            if (row.automatic) result.automatic += 1;
            if (row.custody_work) |*work| {
                if (!work.exhausted and work.groups.count() < work.requested) result.custody_incomplete += 1;
            }
        }
        return result;
    }

    pub fn validateOptions(options: Options) error{InvalidOptions}!void {
        if (options.capacity == 0 or options.capacity > 4096 or options.concurrent_max == 0 or
            options.concurrent_max > 4 or options.concurrent_max > options.engine_dialing_max or
            options.concurrent_max > options.capacity) return error.InvalidOptions;
    }

    pub fn init(a: std.mem.Allocator, options: Options) !DialQueue {
        try validateOptions(options);
        const rows = try a.alloc(Row, options.capacity);
        @memset(rows, .{});
        return .{ .rows = rows, .options = options, .random = .init(options.seed) };
    }
    pub fn deinit(self: *DialQueue, a: std.mem.Allocator) void {
        a.free(self.rows);
        self.* = undefined;
    }
    pub fn memoryPlan(self: *const DialQueue) struct {
        inline_bytes: usize,
        allocated_bytes: usize,
    } {
        return .{
            .inline_bytes = @sizeOf(DialQueue),
            .allocated_bytes = self.rows.len * @sizeOf(Row),
        };
    }
    pub fn enqueue(
        self: *DialQueue,
        peer: *const t.PeerId,
        addresses: []const t.Address,
        direct: bool,
        now_ms: u64,
    ) !void {
        return self.enqueueUntil(peer, addresses, direct, now_ms, now_ms +| connect_timeout_ms);
    }

    pub fn enqueueUntil(self: *DialQueue, peer: *const t.PeerId, addresses: []const t.Address, direct: bool, now_ms: u64, deadline_ms: u64) !void {
        if (deadline_ms <= now_ms or deadline_ms - now_ms > 86_400_000) return error.InvalidDeadline;
        if (addresses.len == 0 or addresses.len > 2) return error.InvalidAddress;
        for (addresses) |address| if (address.port() == 0) return error.InvalidAddress;
        var free: ?*Row = null;
        for (self.rows) |*row| {
            if (row.occupied and row.peer.eql(peer)) {
                var prepared = row.addresses;
                var count: u8 = if (row.automatic) 0 else row.address_count;
                for (addresses) |address| {
                    var found = false;
                    for (prepared[0..count]) |known| found = found or known.eql(address);
                    if (found) continue;
                    if (count == prepared.len) return error.AddressCapacity;
                    prepared[count] = address;
                    count += 1;
                }
                row.addresses = prepared;
                row.address_count = count;
                if (row.automatic) row.address_index = 0;
                row.automatic = false;
                row.direct = row.direct or direct;
                if (!direct) row.manual_until_ms = @max(row.manual_until_ms, deadline_ms);
                self.selection_dirty = true;
                return;
            }
            if (!row.occupied and row.generation < std.math.maxInt(u64) and free == null) {
                free = row;
            }
        }
        const row = free orelse return error.Capacity;
        row.* = .{
            .occupied = true,
            .generation = row.generation,
            .peer = peer.*,
            .direct = direct,
            .eligible_at_ms = now_ms,
            .manual_until_ms = if (direct) 0 else deadline_ms,
        };
        for (addresses) |address| {
            if (row.address_count != 0 and row.addresses[0].eql(address)) continue;
            row.addresses[row.address_count] = address;
            row.address_count += 1;
        }
        self.selection_dirty = true;
    }
    /// Consumes copied Discovery.step output, whose QUIC scope was checked against the
    /// authenticated discovery source. Bare enr.decode output does not satisfy this precondition.
    pub fn enqueueDiscovered(self: *DialQueue, candidate: *const enr.Candidate, context: *const t.ForkContext, wanted: *const t.Coverage, now_ms: u64) !void {
        try context.validate();
        if (candidate.address_count == 0 or candidate.address_count > 2) return error.InvalidCandidate;
        const hints: Hints = .{ .node_id = candidate.node_id, .sequence = candidate.sequence, .fork = candidate.fork, .next_fork_digest = candidate.next_fork_digest, .attnets = candidate.attnets, .syncnets = candidate.syncnets, .custody_group_count = candidate.custody_group_count };
        if (!hints.validFor(context)) return error.InvalidCandidate;
        for (candidate.addresses[0..candidate.address_count]) |address| if (address.port() == 0) return error.InvalidCandidate;
        const node_id = custody.nodeId(&candidate.peer) catch return error.InvalidCandidate;
        if (!std.mem.eql(u8, &node_id, &candidate.node_id)) return error.InvalidCandidate;
        var incoming: Row = .{ .occupied = true, .automatic = true, .peer = candidate.peer, .eligible_at_ms = now_ms, .history_until_ms = now_ms +| history_retention_ms, .hints = hints, .hints_at_ms = now_ms };
        copyAddresses(&incoming, candidate);
        resetCustody(&incoming, context);
        const incoming_utility = policy.utility(&coverage(&incoming, context, now_ms), wanted);
        self.selection_dirty = true;
        var free: ?*Row = null;
        var victim: ?*Row = null;
        var victim_utility: u16 = std.math.maxInt(u16);
        for (self.rows) |*row| {
            if (row.occupied and row.peer.eql(&candidate.peer)) {
                if (row.hints) |previous| {
                    if (candidate.sequence < previous.sequence) return error.StaleRecord;
                    if (candidate.sequence == previous.sequence) {
                        if (!std.meta.eql(previous, hints)) return error.StaleRecord;
                        if (row.automatic) {
                            if (row.address_count != incoming.address_count) return error.StaleRecord;
                            for (row.addresses[0..row.address_count], incoming.addresses[0..incoming.address_count]) |known, address| if (!known.eql(address)) return error.StaleRecord;
                        }
                        row.hints_at_ms = now_ms;
                        return;
                    }
                }
                row.hints = hints;
                row.hints_at_ms = now_ms;
                if (row.automatic) copyAddresses(row, candidate);
                resetCustody(row, context);
                return;
            }
            if (row.generation == std.math.maxInt(u64)) continue;
            if (!row.occupied) {
                if (free == null) free = row;
                continue;
            }
            if (!row.automatic or row.direct or row.connected or row.attempt or row.conn != null or now_ms < row.eligible_at_ms) continue;
            if (row.failures != 0 and now_ms < row.history_until_ms) continue;
            const usefulness = policy.utility(&coverage(row, context, now_ms), wanted);
            if (incoming_utility < usefulness or (incoming_utility == usefulness and now_ms < row.history_until_ms)) continue;
            if (victim == null or usefulness < victim_utility or (usefulness == victim_utility and row.history_until_ms < victim.?.history_until_ms)) {
                victim = row;
                victim_utility = usefulness;
            }
        }
        const row = free orelse victim orelse return error.Capacity;
        incoming.generation = row.generation;
        row.* = incoming;
    }
    fn copyAddresses(row: *Row, candidate: *const enr.Candidate) void {
        row.address_count = 0;
        row.address_index = 0;
        for (candidate.addresses[0..candidate.address_count]) |address| {
            if (row.address_count != 0 and row.addresses[0].eql(address)) continue;
            row.addresses[row.address_count] = address;
            row.address_count += 1;
        }
    }
    fn resetCustody(row: *Row, context: *const t.ForkContext) void {
        const hints = row.hints orelse return;
        if (!hints.validFor(context)) {
            row.custody_work = null;
            return;
        }
        const count = hints.custody_group_count orelse {
            row.custody_work = null;
            return;
        };
        if (std.meta.eql(row.custody_context, context.*)) if (row.custody_work) |work| if (work.requested == count) return;
        row.custody_context = context.*;
        row.custody_work = custody.Derivation.init(&hints.node_id, .{ .groups = context.custody_groups, .columns = @import("preset").NUMBER_OF_COLUMNS }, count) catch null;
    }
    fn coverage(row: *const Row, context: *const t.ForkContext, now_ms: u64) t.Coverage {
        const hints = row.hints orelse return .{};
        if (now_ms >= row.hints_at_ms +| hint_freshness_ms or !hints.validFor(context)) return .{};
        var result: t.Coverage = .{ .attnets = if (hints.attnets) |bits| std.mem.readInt(u64, &bits, .little) else 0, .syncnets = @intCast(hints.syncnets orelse 0) };
        if (std.meta.eql(row.custody_context, context.*)) if (row.custody_work) |work| {
            if (!work.exhausted and work.groups.count() == work.requested) result.groups = work.groups;
        };
        return result;
    }
    pub fn advanceCustody(self: *DialQueue, context: *const t.ForkContext, now_ms: u64, budget: *u16) bool {
        var pending = false;
        for (0..self.rows.len) |_| {
            const row = &self.rows[self.custody_cursor];
            self.custody_cursor = (self.custody_cursor + 1) % self.rows.len;
            if (!row.occupied) continue;
            resetCustody(row, context);
            if (now_ms >= row.hints_at_ms +| hint_freshness_ms) continue;
            const work = if (row.custody_work) |*value| value else continue;
            const before = work.hashes;
            const result = work.step(@min(custody.hashes_per_row, budget.*)) catch {
                budget.* -= work.hashes - before;
                continue;
            };
            budget.* -= work.hashes - before;
            if (work.hashes != before and result != null) self.selection_dirty = true;
            pending = pending or result == null;
        }
        self.custody_cursor = (self.custody_cursor + 1) % self.rows.len;
        return pending;
    }
    pub fn configureSelection(self: *DialQueue, wanted: *const t.Coverage, general: bool, context: *const t.ForkContext, now_ms: u64) void {
        self.selection_deadline = null;
        for (self.rows) |*row| {
            if (!row.occupied) continue;
            const deadline = row.hints_at_ms +| hint_freshness_ms;
            if (row.hints != null and now_ms < deadline) self.selection_deadline = @min(self.selection_deadline orelse deadline, deadline);
            row.priority = policy.utility(&coverage(row, context, now_ms), wanted);
            const compatible = if (row.hints) |hints| hints.validFor(context) else false;
            row.selected = compatible and (general or row.priority > 0);
        }
        self.selection_dirty = false;
    }
    pub fn candidateHints(self: *const DialQueue, peer: *const t.PeerId, now_ms: u64) ?Hints {
        for (self.rows) |row| {
            if (!row.occupied or !row.peer.eql(peer) or now_ms >= row.hints_at_ms +| hint_freshness_ms) continue;
            return row.hints;
        }
        return null;
    }
    /// Only selected relevant authenticated success renews automatic history retention.
    pub fn relevant(self: *DialQueue, peer: *const t.PeerId, now_ms: u64) void {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            row.history_until_ms = @max(row.history_until_ms, now_ms +| history_retention_ms);
        };
    }
    pub fn hostDemand(self: *const DialQueue) u16 {
        var count: u16 = 0;
        for (self.rows) |row| if (row.occupied and (row.direct or row.manual_until_ms != 0) and !row.connected) {
            count += 1;
        };
        return count;
    }
    pub const Attempts = struct { total: u16 = 0, unstarted: u16 = 0 };
    pub fn attempts(self: *const DialQueue) Attempts {
        var result: Attempts = .{};
        for (self.rows) |row| if (row.occupied and row.attempt) {
            result.total += 1;
            if (row.conn == null) result.unstarted += 1;
        };
        return result;
    }
    pub fn isDirect(self: *const DialQueue, peer: *const t.PeerId) bool {
        for (self.rows) |row| if (row.occupied and row.peer.eql(peer)) return row.direct;
        return false;
    }
    pub fn directPeers(self: *const DialQueue, out: []t.PeerId) error{OutputTooSmall}!usize {
        var count: usize = 0;
        for (self.rows) |row| if (row.occupied and row.direct) {
            count += 1;
        };
        if (out.len < count) return error.OutputTooSmall;
        var written: usize = 0;
        for (self.rows) |row| if (row.occupied and row.direct) {
            out[written] = row.peer;
            written += 1;
        };
        std.debug.assert(written == count);
        return written;
    }
    pub fn removeDirect(self: *DialQueue, peer: *const t.PeerId) bool {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            const removed = row.direct;
            row.direct = false;
            return removed;
        };
        return false;
    }
    pub fn remove(self: *DialQueue, peer: *const t.PeerId) bool {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            if (row.attempt) return false;
            row.occupied = false;
            return true;
        };
        return false;
    }
    pub fn connection(self: *DialQueue, peer: *const t.PeerId, connected: bool, now_ms: u64) void {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            row.connected = connected;
            if (row.conn != null) return;
            row.attempt = false;
            row.conn = null;
            row.eligible_at_ms = @max(row.eligible_at_ms, now_ms +| 1_000);
        };
    }
    pub fn accepted(
        self: *DialQueue,
        peer: *const t.PeerId,
        conn: t.Handle,
        now_ms: u64,
    ) void {
        for (self.rows) |*row| {
            if (!row.occupied or !row.peer.eql(peer)) continue;
            if (row.manual_until_ms != 0) {
                row.manual_until_ms = 0;
                self.counters.manual_completed +|= 1;
                std.log.scoped(.network_peers).debug("dial_intent_completed peer={f} persistent={any}", .{ @import("../logging.zig").peer(peer), row.direct or row.automatic });
            }
            if (row.conn) |attempt| {
                if (!std.meta.eql(attempt, conn)) {
                    row.connected = true;
                    return;
                }
            }
            row.conn = null;
            self.connection(peer, true, now_ms);
            if (!row.automatic and !row.direct) row.occupied = false;
            return;
        }
    }

    pub fn disconnected(self: *DialQueue, peer: *const t.PeerId, connected_at_ms: u64, reason: t.DisconnectReason, now_ms: u64) void {
        for (self.rows) |*row| {
            if (!row.occupied or !row.connected or !row.peer.eql(peer)) continue;
            self.connection(peer, false, now_ms);
            const lifetime = now_ms -| connected_at_ms;
            const unhealthy = reason == .health_timeout or reason == .health_error;
            if (lifetime >= stable_connection_ms and !unhealthy) row.failures = 0;
            row.failures = @min(row.failures +| 1, 7);
            const delay = @min(@as(u64, 5_000) << @intCast(row.failures - 1), 300_000);
            row.eligible_at_ms = @max(row.eligible_at_ms, now_ms +| delay +| (self.random.random().int(u16) % 1_001));
            row.history_until_ms = @max(row.history_until_ms, now_ms +| history_retention_ms);
            self.counters.connection_backoffs +|= 1;
            std.log.scoped(.network_peers).debug("dial_backoff peer={f} reason={s} failures={d} connected_ms={d} retry_ms={d}", .{ @import("../logging.zig").peer(peer), @tagName(reason), row.failures, lifetime, row.eligible_at_ms -| now_ms });
            return;
        }
    }

    pub fn cancelConnect(self: *DialQueue, engine: *@import("../quic/engine.zig").Engine, peer: *const t.PeerId, now_ms: u64) void {
        for (self.rows) |*row| {
            if (!row.occupied or !row.peer.eql(peer)) continue;
            if (row.manual_until_ms != 0) self.counters.manual_cancelled +|= 1;
            row.manual_until_ms = 0;
            if (row.attempt) {
                if (row.conn) |conn| closeAttempt(engine, conn);
                row.conn = null;
                row.attempt = false;
            }
            row.eligible_at_ms = @max(row.eligible_at_ms, now_ms +| 60_000);
            if (!row.automatic and !row.direct) row.occupied = false;
            self.selection_dirty = true;
            return;
        }
    }

    /// The caller supplies an observed canonical transport close, including its full generation.
    pub fn dialClosed(self: *DialQueue, conn: t.Handle, now_ms: u64) bool {
        for (self.rows) |*row| {
            if (!row.occupied or !row.attempt or !std.meta.eql(row.conn, conn)) continue;
            self.failed(row, now_ms);
            return true;
        }
        return false;
    }

    fn closeAttempt(engine: *@import("../quic/engine.zig").Engine, conn: t.Handle) void {
        if (engine.peerId(conn) != null) {
            _ = engine.close(conn, 0);
        } else {
            _ = engine.abandon(conn);
        }
    }

    pub fn syncConnection(
        self: *DialQueue,
        peer: *const t.PeerId,
        connected: bool,
        now_ms: u64,
    ) void {
        for (self.rows) |row| {
            if (!row.occupied or !row.peer.eql(peer)) continue;
            if (row.connected != connected) self.connection(peer, connected, now_ms);
            return;
        }
    }
    pub fn deferPeer(self: *DialQueue, peer: *const t.PeerId, eligible_at_ms: u64) void {
        for (self.rows) |*row| if (row.occupied and row.peer.eql(peer)) {
            row.eligible_at_ms = @max(row.eligible_at_ms, eligible_at_ms);
        };
    }
    fn rowFor(self: *DialQueue, token: Token) ?*Row {
        if (token.index >= self.rows.len) return null;
        const row = &self.rows[token.index];
        if (!row.occupied or !row.attempt or row.generation != token.generation) return null;
        return row;
    }
    pub fn dialStarted(self: *DialQueue, token: Token, conn: t.Handle) bool {
        const row = self.rowFor(token) orelse return false;
        if (row.conn != null) return false;
        row.conn = conn;
        return true;
    }
    /// Reports failure before dialStarted. Started owners retire through dialClosed or expire.
    pub fn dialFailed(self: *DialQueue, token: Token, now_ms: u64) bool {
        const row = self.rowFor(token) orelse return false;
        if (row.conn != null) return false;
        self.failed(row, now_ms);
        return true;
    }
    pub fn dialDeferred(self: *DialQueue, token: Token, now_ms: u64) bool {
        const row = self.rowFor(token) orelse return false;
        if (row.conn != null) return false;
        row.attempt = false;
        row.eligible_at_ms = @max(row.eligible_at_ms, now_ms +| 1000);
        return true;
    }
    fn failed(self: *DialQueue, row: *Row, now_ms: u64) void {
        row.attempt = false;
        row.conn = null;
        row.failures = @min(row.failures +| 1, 7);
        const base: u64 = @min(@as(u64, 1_000) << @intCast(row.failures - 1), 60_000);
        const jitter = self.random.random().int(u16) % 1_001;
        row.eligible_at_ms = @max(row.eligible_at_ms, now_ms +| @min(base + jitter, 60_000));
        row.address_index = (row.address_index + 1) % row.address_count;
    }
    pub fn expire(
        self: *DialQueue,
        engine: ?*@import("../quic/engine.zig").Engine,
        now_ms: u64,
    ) void {
        for (self.rows) |*row| {
            if (!row.occupied) continue;
            if (row.manual_until_ms == 0) {
                if (!row.automatic and !row.direct and !row.attempt) row.occupied = false;
                continue;
            }
            if (now_ms < row.manual_until_ms) continue;
            if (!row.automatic and !row.direct and row.conn != null and engine == null) continue;
            row.manual_until_ms = 0;
            self.counters.manual_expired +|= 1;
            std.log.scoped(.network_peers).debug("dial_intent_expired peer={f} persistent={any}", .{ @import("../logging.zig").peer(&row.peer), row.direct or row.automatic });
            if (!row.automatic and !row.direct) {
                if (row.conn) |conn| {
                    closeAttempt(engine.?, conn);
                }
                row.attempt = false;
                row.conn = null;
                row.occupied = false;
            }
        }
        for (self.rows) |*row| if (row.occupied and row.attempt and
            now_ms >= row.lease_expires_at_ms)
        {
            if (row.conn) |conn| {
                const owner = engine orelse continue;
                closeAttempt(owner, conn);
            }
            self.failed(row, now_ms);
        };
    }
    /// Started expiry requires expire(engine, now); polling alone preserves the native owner.
    pub fn poll(self: *DialQueue, now_ms: u64, out: []DialIntent) usize {
        self.expire(null, now_ms);
        var active: usize = 0;
        for (self.rows) |row| if (row.occupied and row.attempt) {
            active += 1;
        };
        var count: usize = 0;
        for (0..self.options.concurrent_max) |_| {
            if (count == out.len or active >= self.options.concurrent_max) break;
            var best: ?usize = null;
            for (0..self.rows.len) |offset| {
                const index = (self.cursor + offset) % self.rows.len;
                const row = &self.rows[index];
                if (!row.occupied or !hasDialIntent(row, now_ms) or row.connected or row.attempt or now_ms < row.eligible_at_ms or row.generation == std.math.maxInt(u64)) continue;
                if (best == null or row.direct and !self.rows[best.?].direct or (row.direct == self.rows[best.?].direct and row.priority > self.rows[best.?].priority)) best = index;
            }
            const index = best orelse break;
            self.cursor = (index + 1) % self.rows.len;
            const row = &self.rows[index];
            row.generation += 1;
            row.attempt = true;
            row.lease_expires_at_ms = if (row.direct or row.automatic) now_ms +| 10_000 else @min(row.manual_until_ms, now_ms +| 10_000);
            out[count] = .{
                .token = .{ .index = @intCast(index), .generation = row.generation },
                .peer = row.peer,
                .address = row.addresses[row.address_index],
            };
            count += 1;
            active += 1;
        }
        return count;
    }
    pub fn nextWakeup(self: *const DialQueue, now_ms: u64, output_capacity: usize) ?u64 {
        var active: usize = 0;
        for (self.rows) |row| if (row.occupied and row.attempt) {
            active += 1;
        };
        var due: ?u64 = null;
        for (self.rows) |row| {
            if (!row.occupied or (row.connected and !row.attempt)) continue;
            if (row.manual_until_ms > now_ms) due = @min(due orelse row.manual_until_ms, row.manual_until_ms);
            if (!row.attempt and (!hasDialIntent(&row, now_ms) or output_capacity == 0 or active >= self.options.concurrent_max or
                row.generation == std.math.maxInt(u64))) continue;
            const deadline = if (row.attempt) row.lease_expires_at_ms else row.eligible_at_ms;
            const next = @max(now_ms, deadline);
            due = @min(due orelse next, next);
        }
        return due;
    }
    pub fn shutdown(self: *DialQueue, engine: *@import("../quic/engine.zig").Engine) void {
        for (self.rows) |*row| {
            if (row.attempt) if (row.conn) |conn| {
                closeAttempt(engine, conn);
            };
            row.occupied = false;
            row.attempt = false;
        }
    }
};

fn hasDialIntent(row: *const Row, now_ms: u64) bool {
    return row.direct or now_ms < row.manual_until_ms or (row.automatic and row.selected);
}
