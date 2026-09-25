const std = @import("std");
const t = @import("types.zig");
const custody = @import("custody.zig");
const reputation = @import("reputation.zig");
const lists = @import("../index_list.zig");
const enr = @import("enr.zig");
const identity_index = @import("identity_index.zig");
const dial_history = @import("dial_history.zig");
const DeadlineHeap = @import("../deadline_heap.zig").DeadlineHeap;
const assert = std.debug.assert;

pub const history_retention_ms: u64 = 600_000;
pub const hint_freshness_ms: u64 = 300_000;

pub const Intent = struct {
    automatic: bool = false,
    selected: bool = true,
    priority: u2 = 0,
    hints: ?enr.Hints = null,
    hints_at_ms: u64 = 0,
    addresses: [2]t.Address = undefined,
    address_count: u8 = 0,
    address_index: u8 = 0,
    manual_until_ms: u64 = 0,
    eligible_at_ms: u64 = 0,
    history_until_ms: u64 = 0,
    failures: u8 = 0,
};
pub const Row = struct {
    free_link: lists.Link = .{},
    established_slot: ?u16 = null,
    intent: Intent = .{},
    attempt: ?u8 = null,
    identify: ?@import("../identify/root.zig").Metadata = null,
    custody_work: ?custody.SamplingDerivation = null,
    custody_context: ?t.ForkContext = null,
    generation: u64 = 0,
    occupied: bool = false,
    identity: t.PeerId = undefined,
    node_id: ?[32]u8 = null,
    connection: ?t.Handle = null,
    closing_reason: ?t.DisconnectReason = null,
    direction: t.Direction = .inbound,
    endpoint: t.Address = .unspecified,
    /// The endpoint the connection was dialed to, kept after its attempt retires; null for an
    /// inbound connection.
    dialed: ?t.Address = null,
    status: ?t.Status = null,
    metadata: ?t.Metadata = null,
    status_at_ms: u64 = 0,
    metadata_at_ms: u64 = 0,
    connected_at_ms: u64 = 0,
    direct: bool = false,
    reputation: reputation.State = .{},
    published: bool = false,
    pending_update: bool = false,
    pending_close: ?struct { connection: t.Handle, reason: t.DisconnectReason } = null,
};

pub const Catalog = struct {
    rows: []Row,
    by_identity: identity_index.Index,
    by_connection: []?u16,
    options: t.Options,
    intent_capacity: u16,
    intent_count: u16 = 0,
    intents: std.DynamicBitSetUnmanaged,
    intent_masks: []usize,
    history: dial_history.History,
    established: []?u16,
    free: lists.List = .{},
    connected_count: u16 = 0,
    relevant_count: u16 = 0,
    direct_count: u16 = 0,
    intent_revision: u64 = 0,
    connection_backoffs: u64 = 0,
    random: std.Random.DefaultPrng,
    candidate_custody_cursor: usize = 0,
    revision: u64 = 0,
    event_cursor: usize = 0,
    custody_cursor: usize = 0,
    /// Rows with a pending close or update; pollEvents visits only these.
    events: std.DynamicBitSetUnmanaged,
    event_masks: []usize,
    event_count: u16 = 0,
    /// The owner clock at the last refresh. Snapshots report reputation decayed to it.
    clock_ms: u64 = 0,
    /// No stored reputation crosses the ban or prune score, and no other reputation deadline
    /// passes, before this time, so refresh decays the rows only once it has passed.
    refresh_due_ms: u64 = 0,
    /// Rows visited by refresh passes.
    refresh_visits: u64 = 0,
    dial: DialIndex,

    /// Intent deadlines, in ms. Dialing owns the keys; the catalog marks a row in `dirty` when an
    /// input of its keys changes, and Dialing rekeys marked rows before reading the heaps.
    pub const DialIndex = struct {
        /// Manual intent expiry and attempt lease, per row.
        expiries: DeadlineHeap,
        /// When a dialable row may next be dialed: its backoff, cooldowns and ban.
        eligible: DeadlineHeap,
        dirty: std.DynamicBitSetUnmanaged,
        dirty_masks: []usize,
        dirty_count: u32 = 0,
        /// Rows one expire or poll takes from a heap.
        scratch: []u32,
    };

    pub fn init(a: std.mem.Allocator, options: t.Options, connections_max: u16, seed: u64) !Catalog {
        return initWithIntents(a, options, 0, connections_max, seed);
    }

    pub fn initWithIntents(a: std.mem.Allocator, options: t.Options, intent_capacity: u16, connections_max: u16, seed: u64) !Catalog {
        try options.validate();
        if (intent_capacity > 4096) return error.InvalidOptions;
        if (connections_max == 0 or connections_max > @import("../quic/limits.zig").connections_max_ceiling) return error.InvalidOptions;
        const rows = try a.alloc(Row, @as(usize, options.capacity) + intent_capacity);
        errdefer a.free(rows);

        const slots = try a.alloc(u16, identity_index.capacity(rows.len));
        errdefer a.free(slots);

        const connections = try a.alloc(?u16, connections_max);
        errdefer a.free(connections);

        const established = try a.alloc(?u16, options.capacity);
        errdefer a.free(established);
        const intent_masks = try a.alloc(usize, try std.math.divCeil(usize, rows.len, @bitSizeOf(usize)));
        errdefer a.free(intent_masks);
        const history = try a.alloc(dial_history.Entry, dial_history.History.capacityFor(intent_capacity));
        errdefer a.free(history);
        const event_masks = try a.alloc(usize, intent_masks.len);
        errdefer a.free(event_masks);
        const dirty_masks = try a.alloc(usize, intent_masks.len);
        errdefer a.free(dirty_masks);
        var expiries = try DeadlineHeap.init(a, @intCast(rows.len));
        errdefer expiries.deinit(a);
        var eligible = try DeadlineHeap.init(a, @intCast(rows.len));
        errdefer eligible.deinit(a);
        const scratch = try a.alloc(u32, rows.len);
        errdefer a.free(scratch);

        @memset(history, .{});
        @memset(intent_masks, 0);
        @memset(event_masks, 0);
        @memset(dirty_masks, 0);
        @memset(established, null);
        @memset(rows, .{});
        @memset(slots, identity_index.empty);
        @memset(connections, null);
        var result: Catalog = .{
            .rows = rows,
            .options = options,
            .intent_capacity = intent_capacity,
            .intents = .{ .bit_length = rows.len, .masks = intent_masks.ptr },
            .intent_masks = intent_masks,
            .history = .{ .entries = history, .seed = seed },
            .established = established,
            .random = .init(seed),
            .by_identity = .{ .slots = slots, .seed = seed },
            .by_connection = connections,
            .events = .{ .bit_length = rows.len, .masks = event_masks.ptr },
            .event_masks = event_masks,
            .dial = .{
                .expiries = expiries,
                .eligible = eligible,
                .dirty = .{ .bit_length = rows.len, .masks = dirty_masks.ptr },
                .dirty_masks = dirty_masks,
                .scratch = scratch,
            },
        };
        for (0..rows.len) |index| result.free.append(rows, "free_link", @intCast(index));
        return result;
    }

    pub fn deinit(self: *Catalog, a: std.mem.Allocator) void {
        a.free(self.dial.scratch);
        self.dial.eligible.deinit(a);
        self.dial.expiries.deinit(a);
        a.free(self.dial.dirty_masks);
        a.free(self.event_masks);
        a.free(self.history.entries);
        a.free(self.intent_masks);
        a.free(self.established);
        a.free(self.by_connection);
        a.free(self.by_identity.slots);
        a.free(self.rows);
        self.* = undefined;
    }

    pub fn candidateHints(self: *const Catalog, identity: *const t.PeerId, now_ms: u64) ?enr.Hints {
        const row = self.rowFor(self.find(identity) orelse return null).?;
        return if (now_ms < row.intent.hints_at_ms +| hint_freshness_ms) row.intent.hints else null;
    }

    pub fn isDirect(self: *const Catalog, identity: *const t.PeerId) bool {
        const peer = self.find(identity) orelse return false;
        return self.rowFor(peer).?.direct;
    }

    pub fn removeDirect(self: *Catalog, identity: *const t.PeerId) bool {
        const peer = self.find(identity) orelse return false;
        if (!self.rowFor(peer).?.direct) return false;
        return self.setDirect(peer, false);
    }

    pub fn directPeers(self: *const Catalog, out: []t.PeerId) error{OutputTooSmall}!usize {
        if (out.len < self.direct_count) return error.OutputTooSmall;
        var count: usize = 0;
        var it = self.intents.iterator(.{});
        while (it.next()) |index| {
            const row = &self.rows[index];
            if (!row.direct) continue;
            out[count] = row.identity;
            count += 1;
        }
        std.debug.assert(count == self.direct_count);
        return count;
    }

    pub fn prepareCandidateCustody(row: *Row, context: *const t.ForkContext) void {
        if (row.connection != null) return;
        const hints = row.intent.hints orelse return;
        const count = hints.custody_group_count orelse context.custody_requirement;
        if (!hints.validFor(context) or count == 0) {
            row.custody_work = null;
            return;
        }
        if (std.meta.eql(row.custody_context, context.*)) if (row.custody_work) |work| if (work.custody_count == count and work.sampling_count == count) return;
        row.custody_context = context.*;
        row.custody_work = custody.SamplingDerivation.init(&row.node_id.?, .{ .groups = context.custody_groups, .columns = @import("preset").NUMBER_OF_COLUMNS }, count, 0) catch null;
    }

    pub fn candidateCoverage(row: *const Row, context: *const t.ForkContext, now_ms: u64) t.Coverage {
        const hints = row.intent.hints orelse return .{};
        if (now_ms >= row.intent.hints_at_ms +| hint_freshness_ms or !hints.validFor(context)) return .{};
        var result: t.Coverage = .{ .attnets = if (hints.attnets) |bits| std.mem.readInt(u64, &bits, .little) else 0, .syncnets = @intCast(hints.syncnets orelse 0) };
        const count = hints.custody_group_count orelse context.custody_requirement;
        if (std.meta.eql(row.custody_context, context.*)) if (row.custody_work) |*work| {
            if (work.custody_count == count) if (work.complete()) |derived| {
                result.groups = derived.custody;
                result.custody_groups = derived.custody;
            };
        };
        return result;
    }

    pub fn advanceCustody(self: *Catalog, context: *const t.ForkContext, now_ms: u64, freshness_ms: u64, budget: *u16) bool {
        var connected_budget: u16 = @min(budget.*, custody.hashes_per_turn / 2);
        const reserved = connected_budget;
        const connected_pending = self.advanceConnectedCustody(context, now_ms, freshness_ms, &connected_budget);
        budget.* -= reserved - connected_budget;
        var pending = connected_pending;
        // Scan both halves of the intent index from a rotating start, including unselected hints.
        for (0..2) |half| {
            var it = self.intents.iterator(.{});
            while (it.next()) |index| {
                if ((index < self.candidate_custody_cursor) != (half == 1)) continue;
                const row = &self.rows[index];
                if (row.connection != null) continue;
                const before_context = row.custody_context;
                const had_work = row.custody_work != null;
                prepareCandidateCustody(row, context);
                if (!std.meta.eql(before_context, row.custody_context) or had_work != (row.custody_work != null)) self.intent_revision +|= 1;
                if (now_ms >= row.intent.hints_at_ms +| hint_freshness_ms) continue;
                const work = if (row.custody_work) |*value| value else continue;
                const before = work.totalHashes();
                const result = work.step(@min(custody.hashes_per_row, budget.*)) catch {
                    budget.* -= work.totalHashes() - before;
                    continue;
                };
                budget.* -= work.totalHashes() - before;
                if (work.totalHashes() != before and result != null) self.intent_revision +|= 1;
                pending = pending or result == null;
            }
        }
        self.candidate_custody_cursor = (self.candidate_custody_cursor + 1) % self.rows.len;
        return pending;
    }

    fn advanceConnectedCustody(self: *Catalog, context: *const t.ForkContext, now_ms: u64, freshness_ms: u64, budget: *u16) bool {
        var pending = false;
        for (0..self.rows.len) |_| {
            const index = self.custody_cursor;
            const row = &self.rows[index];
            self.custody_cursor = (self.custody_cursor + 1) % self.rows.len;
            if (!row.occupied or row.connection == null or row.closing_reason != null) continue;
            const metadata = row.metadata orelse continue;
            const count = metadata.custody_group_count orelse {
                if (row.custody_work != null) self.revision +|= 1;
                row.custody_work = null;
                continue;
            };
            const compatible = if (row.status) |status| std.mem.eql(u8, &status.fork_digest, &context.digest) else false;
            if (count == 0 or count > context.custody_groups or !compatible) {
                if (row.custody_work != null) self.revision +|= 1;
                row.custody_work = null;
                continue;
            }
            var completed = if (row.custody_work) |*work| work.complete() != null else false;
            if (!std.meta.eql(row.custody_context, context.*) or (if (row.custody_work) |work| work.custody_count != count else true)) {
                self.revision +|= 1;
                row.custody_work = null;
                row.custody_context = context.*;
                if (row.node_id == null) row.node_id = custody.nodeId(&row.identity) catch continue;
                row.custody_work = custody.SamplingDerivation.init(&row.node_id.?, .{ .groups = context.custody_groups, .columns = @import("preset").NUMBER_OF_COLUMNS }, count, context.minimum_sampling_groups) catch continue;
                completed = false;
            }
            if (now_ms >= row.metadata_at_ms +| freshness_ms) continue;
            const work = &row.custody_work.?;
            const before = work.totalHashes();
            const result = work.step(@min(custody.hashes_per_row, budget.*)) catch {
                budget.* -= work.totalHashes() - before;
                continue;
            };
            budget.* -= work.totalHashes() - before;
            if (!completed and result != null) {
                self.revision +|= 1;
                row.pending_update = true;
                self.syncEvent(index);
            }
            pending = pending or result == null;
        }
        // A rotating work start prevents a large configured catalog from monopolizing the budget.
        self.custody_cursor = (self.custody_cursor + 1) % self.rows.len;
        return pending;
    }
    pub fn find(self: *const Catalog, identity: *const t.PeerId) ?t.PeerRef {
        const index = self.by_identity.find(self.rows, identity) orelse return null;
        return .{ .index = index, .generation = self.rows[index].generation };
    }

    pub fn findConnection(self: *const Catalog, conn: t.Handle) ?t.PeerRef {
        if (conn.index >= self.by_connection.len) return null;
        const index = self.by_connection[conn.index] orelse return null;
        const row = &self.rows[index];
        return if (row.occupied and std.meta.eql(row.connection, conn)) .{ .index = index, .generation = row.generation } else null;
    }

    pub fn rowFor(self: *const Catalog, ref: t.PeerRef) ?*Row {
        if (ref.index >= self.rows.len) return null;
        const row = &self.rows[ref.index];
        return if (row.occupied and row.generation == ref.generation) row else null;
    }

    fn connectedRow(self: *Catalog, ref: t.PeerRef, conn: t.Handle) ?*Row {
        const row = self.rowFor(ref) orelse return null;
        const current = row.connection orelse return null;
        return if (std.meta.eql(current, conn)) row else null;
    }

    pub fn get(self: *const Catalog, ref: t.PeerRef) ?t.Snapshot {
        const row = self.rowFor(ref) orelse return null;
        if (row.established_slot == null) return null;
        const derived = if (row.connection != null and row.custody_work != null) row.custody_work.?.complete() else null;
        var current = row.reputation;
        current.decay(self.clock_ms);
        return .{
            .peer = ref,
            .identity = row.identity,
            .connection = row.connection,
            .direction = row.direction,
            .endpoint = row.endpoint,
            .relevant = row.connection != null and row.status != null,
            .disconnect_reason = row.closing_reason,
            .status = row.status,
            .metadata = row.metadata,
            .identify = row.identify,
            .status_at_ms = row.status_at_ms,
            .metadata_at_ms = row.metadata_at_ms,
            .custody_groups = if (derived) |value| value.custody else null,
            .sampling_groups = if (derived) |value| value.sampling else null,
            .connected_at_ms = row.connected_at_ms,
            .direct = row.direct,
            .score = current.score,
            .score_at_ms = current.decay_at_ms,
            .ban_until_ms = row.reputation.ban_until_ms,
            .goodbye_until_ms = row.reputation.goodbye_until_ms,
            .redial_until_ms = row.reputation.redial_until_ms,
        };
    }

    pub fn snapshots(self: *const Catalog, out: []t.Snapshot) usize {
        var count: usize = 0;
        for (self.rows, 0..) |row, index| {
            if (count == out.len) break;
            if (row.established_slot == null) continue;
            out[count] = self.get(.{ .index = @intCast(index), .generation = row.generation }).?;
            count += 1;
        }
        return count;
    }

    /// Identity and connection metadata must come from authenticated transport state.
    pub fn admit(
        self: *Catalog,
        identity: *const t.PeerId,
        local: *const t.PeerId,
        conn: t.Handle,
        options: *const t.AdmissionOptions,
    ) t.Admission {
        std.debug.assert(conn.index < self.by_connection.len);
        if (identity.eql(local)) return .duplicate;
        if (self.find(identity)) |ref| {
            const row = self.rowFor(ref).?;
            var current_reputation = row.reputation;
            current_reputation.decay(options.now_ms);
            if (current_reputation.banned(options.now_ms)) return .banned;
            if (options.now_ms < current_reputation.goodbye_until_ms or
                (options.direction == .inbound and !row.direct and options.now_ms < current_reputation.redial_until_ms)) return .cooldown;
            if (row.pending_close != null) return .pending;
            var displaced: ?t.Handle = null;
            if (row.connection) |current| {
                const local_smaller = std.mem.order(u8, &local.bytes, &identity.bytes) == .lt;
                const preferred: t.Direction = if (local_smaller)
                    .outbound
                else
                    .inbound;
                if (std.meta.eql(current, conn) or row.direction == options.direction or
                    options.direction != preferred) return .duplicate;
                displaced = current;
            } else if (!self.admissionRoom(row.direct, options)) return .capacity;
            const fresh = row.established_slot == null;
            if (fresh and !self.promote(ref, options.direction, options.now_ms)) return .capacity;
            if (row.connection == null) self.connected_count += 1;
            if (row.status != null) self.relevant_count -= 1;
            row.reputation = current_reputation;
            if (displaced) |old| self.by_connection[old.index] = null;
            connect(row, conn, options);
            self.by_connection[conn.index] = ref.index;
            self.revision +|= 1;
            self.syncEvent(ref.index);
            self.markDial(ref.index);
            self.noteReputation(row, options.now_ms);
            return .{ .admitted = .{ .peer = ref, .displaced = displaced, .fresh = fresh } };
        }
        if (!self.admissionRoom(false, options)) return .capacity;
        const slot = self.reclaimable(options.direction, options.now_ms) orelse return .capacity;
        if (self.established[slot]) |victim| self.forget(self.reference(victim));
        const ref = self.allocate(identity) orelse return .capacity;
        self.established[slot] = ref.index;
        const row = self.rowFor(ref).?;
        row.established_slot = @intCast(slot);
        connect(row, conn, options);
        self.connected_count += 1;
        self.by_connection[conn.index] = ref.index;
        self.revision +|= 1;
        self.syncEvent(ref.index);
        self.markDial(ref.index);
        return .{ .admitted = .{ .peer = ref, .fresh = true } };
    }

    fn admissionRoom(self: *const Catalog, direct: bool, options: *const t.AdmissionOptions) bool {
        const remaining = self.options.max_peers -| self.connectedCount();
        if (remaining <= options.pending_dials) return false;
        return options.direction == .outbound or direct or options.selected_dial or remaining > options.outbound_reserved;
    }

    pub fn reference(self: *const Catalog, index: usize) t.PeerRef {
        std.debug.assert(self.rows[index].occupied);
        return .{ .index = @intCast(index), .generation = self.rows[index].generation };
    }

    fn allocate(self: *Catalog, identity: *const t.PeerId) ?t.PeerRef {
        for (0..self.rows.len) |_| {
            const index = self.free.pop(self.rows, "free_link") orelse return null;
            const row = &self.rows[index];
            if (row.generation == std.math.maxInt(u64)) continue;
            row.* = .{ .occupied = true, .generation = row.generation + 1, .identity = identity.* };
            self.by_identity.insert(self.rows, @intCast(index));
            return self.reference(index);
        }
        return null;
    }

    pub fn retainIntent(self: *Catalog, identity: *const t.PeerId) error{Capacity}!t.PeerRef {
        const existing = self.find(identity);
        if (existing) |peer| if (self.intents.isSet(peer.index)) return peer;
        if (self.intent_count == self.intent_capacity) return error.Capacity;
        const peer = existing orelse self.allocate(identity) orelse return error.Capacity;
        self.intents.set(peer.index);
        self.intent_count += 1;
        self.intent_revision +|= 1;
        self.markDial(peer.index);
        return peer;
    }

    pub fn releaseIntent(self: *Catalog, peer: t.PeerRef) void {
        const row = self.rowFor(peer) orelse return;
        std.debug.assert(!row.direct and row.attempt == null);
        if (self.intents.isSet(peer.index)) {
            self.intents.unset(peer.index);
            self.intent_count -= 1;
            self.intent_revision +|= 1;
        }
        self.markDial(peer.index);
        if (row.established_slot == null) {
            self.forget(peer);
        } else {
            row.intent = .{ .failures = row.intent.failures, .eligible_at_ms = row.intent.eligible_at_ms, .history_until_ms = row.intent.history_until_ms };
            if (row.connection == null) {
                row.custody_work = null;
                row.custody_context = null;
            }
        }
    }

    fn forget(self: *Catalog, peer: t.PeerRef) void {
        const row = self.rowFor(peer).?;
        std.debug.assert(row.connection == null and row.attempt == null and !row.direct and row.pending_close == null and !row.pending_update);
        self.by_identity.remove(self.rows, &row.identity);
        if (row.established_slot) |slot| {
            self.established[slot] = null;
        }
        if (self.intents.isSet(peer.index)) {
            self.intents.unset(peer.index);
            self.intent_count -= 1;
            self.intent_revision +|= 1;
        }
        assert(!self.events.isSet(peer.index));
        self.markDial(peer.index);
        row.* = .{ .generation = row.generation };
        self.free.prepend(self.rows, "free_link", peer.index);
    }

    fn promote(self: *Catalog, peer: t.PeerRef, direction: t.Direction, now_ms: u64) bool {
        const slot = self.reclaimable(direction, now_ms) orelse return false;
        if (self.established[slot]) |victim| self.forget(self.reference(victim));
        self.established[slot] = peer.index;
        self.rows[peer.index].established_slot = @intCast(slot);
        return true;
    }

    fn reclaimable(self: *const Catalog, direction: t.Direction, now_ms: u64) ?usize {
        const limit = self.established.len - if (direction == .inbound)
            @as(usize, self.options.outbound_reserve)
        else
            0;
        var victim: ?usize = null;
        var victim_banned = false;
        var victim_deadline: u64 = 0;
        for (self.established[0..limit], 0..) |entry, slot| {
            const index = entry orelse return slot;
            const row = &self.rows[index];
            if (row.connection != null or row.direct or row.attempt != null or row.intent.manual_until_ms > now_ms or row.pending_close != null or
                row.pending_update or row.generation == std.math.maxInt(u64)) continue;
            var current_reputation = row.reputation;
            current_reputation.decay(now_ms);
            if (!current_reputation.retained(now_ms)) return slot;
            const banned = current_reputation.banned(now_ms);
            const deadline = current_reputation.nextDeadline(now_ms) orelse now_ms;
            if (victim == null or (victim_banned and !banned) or
                (victim_banned == banned and deadline < victim_deadline))
            {
                victim = slot;
                victim_banned = banned;
                victim_deadline = deadline;
            }
        }
        return victim;
    }

    fn connect(row: *Row, conn: t.Handle, options: *const t.AdmissionOptions) void {
        std.log.scoped(.network_peers).debug("peer_admitted peer={f} connection={d}:{d} direction={s}", .{ @import("../logging.zig").peer(&row.identity), conn.index, conn.generation, @tagName(options.direction) });
        row.identify = null;
        row.custody_work = null;
        row.custody_context = null;
        if (row.node_id == null) row.node_id = options.node_id;
        row.connection = conn;
        row.closing_reason = null;
        row.direction = options.direction;
        row.endpoint = options.endpoint;
        row.dialed = null;
        row.connected_at_ms = options.now_ms;
        row.status = null;
        row.metadata = null;
        row.status_at_ms = 0;
        row.metadata_at_ms = 0;
        row.pending_update = row.published;
    }

    pub fn relevantCount(self: *const Catalog) u16 {
        return self.relevant_count;
    }

    pub fn eventsPending(self: *const Catalog) bool {
        if (@import("builtin").is_test) self.checkEvents();
        return self.event_count != 0;
    }

    /// Keeps `events` equal to the rows holding a pending close or update.
    fn syncEvent(self: *Catalog, index: usize) void {
        const row = &self.rows[index];
        const pending = row.pending_close != null or row.pending_update;
        if (pending == self.events.isSet(index)) return;
        if (pending) {
            self.events.set(index);
            self.event_count += 1;
        } else {
            self.events.unset(index);
            self.event_count -= 1;
        }
    }

    /// Test builds check that `events` holds exactly the rows with a pending close or update.
    fn checkEvents(self: *const Catalog) void {
        var count: usize = 0;
        for (self.rows, 0..) |*row, index| {
            const pending = row.pending_close != null or row.pending_update;
            assert(pending == self.events.isSet(index));
            count += @intFromBool(pending);
        }
        assert(count == self.event_count);
    }

    /// Marks the row for Dialing to rekey its intent deadlines.
    pub fn markDial(self: *Catalog, index: usize) void {
        if (self.dial.dirty.isSet(index)) return;
        self.dial.dirty.set(index);
        self.dial.dirty_count += 1;
    }

    /// Pulls the refresh deadline forward to the row's next reputation deadline.
    fn noteReputation(self: *Catalog, row: *const Row, now_ms: u64) void {
        const next = row.reputation.nextDeadline(now_ms) orelse return;
        self.refresh_due_ms = @min(self.refresh_due_ms, next);
    }

    pub fn connectedCount(self: *const Catalog) u16 {
        return self.connected_count;
    }

    pub fn disconnect(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        reason: t.DisconnectReason,
        now_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        std.log.scoped(.network_peers).debug("peer_disconnected peer={f} connection={d}:{d} reason={s} connected_ms={d} relevant={any} agent={f}", .{ @import("../logging.zig").peer(&row.identity), conn.index, conn.generation, @tagName(reason), now_ms -| row.connected_at_ms, row.status != null, std.json.fmt(@import("client.zig").agent(&row.identify), .{}) });
        self.revision +|= 1;
        self.by_connection[conn.index] = null;
        self.connected_count -= 1;
        if (row.status != null) self.relevant_count -= 1;
        row.connection = null;
        row.custody_work = null;
        row.custody_context = null;
        row.status = null;
        row.metadata = null;
        row.pending_update = false;
        row.pending_close = .{ .connection = conn, .reason = reason };
        row.reputation.decay(now_ms);
        self.connectionClosed(ref.index, reason, now_ms);
        self.syncEvent(ref.index);
        self.markDial(ref.index);
        self.noteReputation(row, now_ms);
        return true;
    }

    fn connectionClosed(self: *Catalog, index: usize, reason: t.DisconnectReason, now_ms: u64) void {
        const row = &self.rows[index];
        row.intent.history_until_ms = @max(row.intent.history_until_ms, now_ms +| history_retention_ms);
        if (reason == .capacity or reason == .count_pruning) {
            if (row.reputation.redial_until_ms <= now_ms)
                row.reputation.deferRedial(now_ms, @import("goodbye.zig").cooldownMs(129));
            return;
        }
        const lifetime = now_ms -| row.connected_at_ms;
        if (lifetime >= 300_000) row.intent.failures = 0;
        row.intent.failures = @min(row.intent.failures +| 1, 7);
        const delay = @min(@as(u64, 5_000) << @intCast(row.intent.failures - 1), 300_000);
        row.intent.eligible_at_ms = @max(row.intent.eligible_at_ms, now_ms +| delay +| (self.random.random().int(u16) % 1_001));
        self.connection_backoffs +|= 1;
        if (reason == .health_timeout or reason == .health_error) self.recordHealth(index, now_ms);
    }

    /// Charges a health close to the endpoint the connection was dialed to; an inbound connection
    /// says nothing about the intent's endpoints. The row's own backoff is lost when a later
    /// admission reclaims the row, so only this history entry carries the escalation to a
    /// rediscovered intent. A discovery-only intent then moves off the endpoints its history blocks,
    /// and drops once every one is blocked, as after a failed dial.
    fn recordHealth(self: *Catalog, index: usize, now_ms: u64) void {
        const row = &self.rows[index];
        const key = self.history.endpointKey(&row.identity, row.dialed orelse return);
        const intent = &row.intent;
        const sequence = if (intent.hints) |hints| hints.sequence else 0;
        self.history.recordEndpoint(key, .health, sequence, now_ms);
        self.history.markRetry(key, .health, now_ms);
        if (!intent.automatic or row.direct or intent.manual_until_ms != 0) return;
        for (0..intent.address_count) |offset| {
            const position: u8 = @intCast((intent.address_index + offset) % intent.address_count);
            if (!self.history.blocked(self.history.endpointKey(&row.identity, intent.addresses[position]), sequence, now_ms)) {
                intent.address_index = position;
                return;
            }
        }
        intent.automatic = false;
        if (row.attempt == null) self.releaseIntent(self.reference(index));
    }

    /// Clears the connection-failure evidence of the endpoint the connection was dialed to. Control
    /// calls it once the connection completed a valid relevant Status and a valid Metadata exchange:
    /// a QUIC handshake alone does not show the endpoint serves the peer.
    pub fn clearDialFailures(self: *Catalog, ref: t.PeerRef, conn: t.Handle) void {
        const row = self.connectedRow(ref, conn) orelse return;
        const endpoint = row.dialed orelse return;
        self.history.clearFailures(self.history.endpointKey(&row.identity, endpoint));
    }

    /// Clears the health evidence of the endpoint the connection was dialed to. Control calls it once
    /// a probe started after the Status and Metadata exchange succeeded, so a peer that answers that
    /// exchange and then stops answering keeps its strikes across reconnects.
    pub fn clearHealthStrikes(self: *Catalog, ref: t.PeerRef, conn: t.Handle) void {
        const row = self.connectedRow(ref, conn) orelse return;
        self.history.clearHealth(self.history.endpointKey(&row.identity, row.dialed orelse return));
    }

    pub fn markUnavailable(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        reason: t.DisconnectReason,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return true;
        self.revision +|= 1;
        row.closing_reason = reason;
        if (row.status != null) self.relevant_count -= 1;
        row.status = null;
        row.pending_update = row.published;
        self.syncEvent(ref.index);
        return true;
    }

    pub fn invalidateStatus(self: *Catalog, ref: t.PeerRef, conn: t.Handle) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return false;
        if (row.status == null and row.custody_work == null) return true;
        self.revision +|= 1;
        if (row.status != null) self.relevant_count -= 1;
        row.status = null;
        row.custody_work = null;
        row.pending_update = row.published;
        self.syncEvent(ref.index);
        return true;
    }

    /// Only a decoded Status accepted by the relevance check may establish relevance.
    pub fn updateStatus(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        status: *const t.Status,
        now_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return false;
        self.revision +|= 1;
        if (row.status == null) self.relevant_count += 1;
        row.status = status.*;
        row.intent.history_until_ms = @max(row.intent.history_until_ms, now_ms +| history_retention_ms);
        row.status_at_ms = now_ms;
        row.pending_update = true;
        self.syncEvent(ref.index);
        return true;
    }

    pub fn updateIdentify(self: *Catalog, ref: t.PeerRef, conn: t.Handle, metadata: *const @import("../identify/root.zig").Metadata) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return false;
        row.identify = metadata.*;
        self.revision +|= 1;
        if (row.published or row.status != null) row.pending_update = true;
        self.syncEvent(ref.index);
        return true;
    }

    pub fn updateEndpoint(self: *Catalog, ref: t.PeerRef, conn: t.Handle, endpoint: *const t.Address) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return false;
        if (row.endpoint.eql(endpoint.*)) return true;
        row.endpoint = endpoint.*;
        self.revision +|= 1;
        if (row.published) row.pending_update = true;
        self.syncEvent(ref.index);
        return true;
    }

    pub fn updateMetadata(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        metadata: *const t.Metadata,
        now_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return false;
        if (row.metadata) |current| {
            if (metadata.seq_number < current.seq_number) return false;
            if (std.meta.eql(current, metadata.*)) {
                row.metadata_at_ms = now_ms;
                return true;
            }
        }
        if (row.metadata == null or row.metadata.?.custody_group_count != metadata.custody_group_count) row.custody_work = null;
        self.revision +|= 1;
        row.metadata = metadata.*;
        row.metadata_at_ms = now_ms;
        if (row.published or row.status != null) row.pending_update = true;
        self.syncEvent(ref.index);
        return true;
    }

    pub fn setDirect(self: *Catalog, ref: t.PeerRef, direct: bool) bool {
        const row = self.rowFor(ref) orelse return false;
        if (row.direct != direct) {
            self.revision +|= 1;
            if (direct) self.direct_count += 1 else self.direct_count -= 1;
        }
        row.direct = direct;
        self.markDial(ref.index);
        return true;
    }

    pub fn report(
        self: *Catalog,
        ref: t.PeerRef,
        action: t.PeerAction,
        now_ms: u64,
    ) ?t.ReputationDecision {
        const row = self.rowFor(ref) orelse return null;
        if (row.established_slot == null) return null;
        self.revision +|= 1;
        defer {
            self.noteReputation(row, now_ms);
            self.markDial(ref.index);
        }
        return row.reputation.apply(action, now_ms);
    }

    pub fn nonCompletion(self: *Catalog, ref: t.PeerRef, now_ms: u64) bool {
        const row = self.rowFor(ref) orelse return false;
        if (row.established_slot == null) return false;
        const before = row.reputation.score;
        row.reputation.nonCompletion(now_ms);
        if (before != row.reputation.score) self.revision +|= 1;
        self.noteReputation(row, now_ms);
        self.markDial(ref.index);
        return true;
    }

    pub fn cooldown(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        now_ms: u64,
        duration_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        self.revision +|= 1;
        row.reputation.cooldown(now_ms, duration_ms);
        self.noteReputation(row, now_ms);
        self.markDial(ref.index);
        return true;
    }

    /// Advances the snapshot clock, and decays every row once a stored score may have crossed the
    /// ban or prune score, so the revision moves on the crossing. It visits no row before then.
    pub fn refresh(self: *Catalog, now_ms: u64) void {
        self.clock_ms = @max(self.clock_ms, now_ms);
        if (now_ms < self.refresh_due_ms) {
            if (@import("builtin").is_test) self.checkReputation(now_ms);
            return;
        }
        var due: u64 = std.math.maxInt(u64);
        for (self.rows) |*row| {
            if (!row.occupied) continue;
            const banned = row.reputation.score <= reputation.ban_score;
            const useful = row.reputation.score >= reputation.prune_score;
            row.reputation.decay(now_ms);
            if (banned != (row.reputation.score <= reputation.ban_score) or
                useful != (row.reputation.score >= reputation.prune_score)) self.revision +|= 1;
            if (row.reputation.nextDeadline(now_ms)) |next| due = @min(due, next);
        }
        self.refresh_visits +|= self.rows.len;
        self.refresh_due_ms = due;
    }

    /// Test builds check that no stored score crossed the ban or prune score since the last pass.
    fn checkReputation(self: *const Catalog, now_ms: u64) void {
        for (self.rows) |*row| {
            if (!row.occupied) continue;
            var current = row.reputation;
            current.decay(now_ms);
            assert((row.reputation.score <= reputation.ban_score) == (current.score <= reputation.ban_score));
            assert((row.reputation.score >= reputation.prune_score) == (current.score >= reputation.prune_score));
        }
    }

    pub fn deferRedial(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        now_ms: u64,
        duration_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        self.revision +|= 1;
        row.reputation.deferRedial(now_ms, duration_ms);
        self.noteReputation(row, now_ms);
        self.markDial(ref.index);
        return true;
    }

    pub fn nextDeadline(self: *const Catalog, now_ms: u64) ?u64 {
        var deadline: ?u64 = null;
        for (self.rows) |*row| {
            if (!row.occupied) continue;
            if (row.reputation.nextDeadline(now_ms)) |next| {
                deadline = @min(deadline orelse next, next);
            }
        }
        return deadline;
    }

    /// Emits pending closes and updates in row order from the cursor, visiting only rows with one.
    pub fn pollEvents(self: *Catalog, out: []t.Event) usize {
        if (@import("builtin").is_test) self.checkEvents();
        if (out.len == 0 or self.event_count == 0) return 0;
        const start = self.event_cursor;
        var count: usize = 0;
        // The first half visits rows from the cursor to the end, the second the rows before it.
        outer: for (0..2) |half| {
            var it = self.events.iterator(.{});
            while (it.next()) |index| {
                if ((index < start) != (half == 1)) continue;
                if (count == out.len) break :outer;
                self.emitEvent(index, &out[count]);
                self.syncEvent(index);
                count += 1;
                self.event_cursor = (index + 1) % self.rows.len;
            }
        }
        // A pass that does not fill the output visits every row and ends where it started.
        if (count < out.len) self.event_cursor = start;
        return count;
    }

    fn emitEvent(self: *Catalog, index: usize, out: *t.Event) void {
        const row = &self.rows[index];
        assert(row.occupied);
        const ref: t.PeerRef = .{ .index = @intCast(index), .generation = row.generation };
        if (row.pending_close) |closed| {
            out.* = .{ .closed = .{
                .peer = ref,
                .identity = row.identity,
                .connection = closed.connection,
                .reason = closed.reason,
            } };
            row.pending_close = null;
            row.published = false;
            return;
        }
        assert(row.pending_update);
        const snapshot = self.get(ref).?;
        out.* = if (row.published)
            .{ .updated = snapshot }
        else
            .{ .ready = snapshot };
        row.pending_update = false;
        row.published = true;
    }
};

test {
    _ = @import("catalog_test.zig");
}
