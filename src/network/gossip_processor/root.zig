const std = @import("std");
const n = @import("../root.zig");
const native = n.gossipsub;
const storage = @import("../gossipsub/message_store.zig");
pub const Plan = @import("plan.zig").Plan;
pub const Source = @import("../gossipsub/peer_book.zig").Ref;
pub const limits_mod = @import("../gossip_limits.zig");
const lists = @import("../index_list.zig");
const Groups = @import("groups.zig").Groups;
const Dependencies = @import("dependencies.zig").Dependencies;
const none = lists.none;
const state_count = @typeInfo(State).@"enum".fields.len;
pub const metadata_mod = @import("metadata.zig");
const Kind = limits_mod.Kind;
const assert = std.debug.assert;
pub const batch_max = 64;
pub const batch_bytes = 16 * 1024 * 1024;
pub const payload_max = 10 * 1024 * 1024;
comptime {
    assert(payload_max <= batch_bytes);
}
pub const topic_max = native.topic.topic_max_len;
pub const Token = struct { index: u16, generation: u64 };
pub const State = enum { free, capturing, needs_check, checking, waiting, queued, copying, delivered, verdict_pending };
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    order: u64 = 0,
    handle: native.ValidationHandle = undefined,
    identity: n.PeerId = undefined,
    source: ?Source = null,
    connection: n.quic.engine.Handle = undefined,
    id: native.MessageId = undefined,
    topic: [topic_max]u8 = undefined,
    topic_len: u16 = 0,
    deadline: u64 = 0,
    received_at: u64 = 0,
    admitted_ms: u64 = 0,
    input: struct { len: usize = 0, handle: ?storage.Handle = null } = .{},
    kind: Kind = .beacon_block,
    metadata: metadata_mod.Metadata = .{},
    check_notification: u64 = 0,
    state_link: lists.Link = .{},
    ready_link: lists.Link = .{},
    expiry_link: lists.Link = .{},
    group_link: lists.Link = .{},
    root_link: lists.Link = .{},
    group_index: u32 = none,
    root_index: u32 = none,
    deneb: bool = false,
    executing: bool = false,
    execution_bytes: usize = 0,
    source_charge: usize = 0,
    retired: bool = false,
    verdict: native.Verdict = .ignore,
};
pub const Diagnostics = struct {
    capacity: usize = 0,
    occupied: usize = 0,
    highWater: usize = 0,
    queued: usize = 0,
    pendingVerdicts: usize = 0,
    reservedBytes: usize = 0,
    reservedBytesHighWater: usize = 0,
    payloadBytes: usize = 0,
    copyingBytes: usize = 0,
    copying: usize = 0,
    publicationBytes: usize = 0,
    messagesCopied: u64 = 0,
    bytesCopied: u64 = 0,
    capacityRefusals: u64 = 0,
    byteRefusals: u64 = 0,
    queuedExpired: u64 = 0,
    deliveredExpired: u64 = 0,
    reportsAccepted: u64 = 0,
    reportsAppliedAccept: u64 = 0,
    reportsAppliedReject: u64 = 0,
    reportsAppliedIgnore: u64 = 0,
    waiting: usize = 0,
    checking: usize = 0,
    executing: usize = 0,
    executingBytes: usize = 0,
    expiredExecuting: usize = 0,
    oldestExpiredExecutionAgeMs: u64 = 0,
    slotRefusals: u64 = 0,
    publicationCopies: u64 = 0,
    publicationQueued: u64 = 0,
    publicationSelected: u64 = 0,
    publicationDuplicates: u64 = 0,
};
/// Host-visible states exported per kind: queued for the host, waiting for a dependency,
/// awaiting a host dependency check, and executing on the host.
pub const Occupancy = enum { queued, waiting, checking, executing };
pub const occupancy_count = @typeInfo(Occupancy).@"enum".fields.len;
/// Why the processor refused a message: its kind's items, bytes or cells, the shared payload
/// store, its source's share, slot or fork eligibility, or dependency waiting room.
pub const Refusal = enum { kind_full, store_full, source_full, ineligible, dependency_full };
pub const refusal_count = @typeInfo(Refusal).@"enum".fields.len;
pub const Job = struct { kind: Kind, start: usize, len: usize, grouped: bool };
pub const Batch = struct {
    tokens: [batch_max]Token = undefined,
    len: usize = 0,
    jobs: [batch_max]Job = undefined,
    job_count: usize = 0,
};
const Search = struct {
    until: u64 = 0,
    root: [32]u8 = undefined,
    peers: [8]n.PeerId = undefined,
    count: u8 = 0,
    anonymous: bool = false,
};
pub const GossipProcessor = struct {
    cells: []Cell,
    backing: std.mem.Allocator,
    diag: Diagnostics = .{},
    order: u64 = 0,
    queues: [limits_mod.kind_count][state_count]lists.List = @splat(@splat(.{})),
    ready: [limits_mod.kind_count]lists.List = @splat(.{}),
    expiry: lists.List = .{},
    groups: Groups,
    dependencies: Dependencies,
    store: storage.Store,
    staging_pages: usize = 0,
    staging_items: usize = 0,
    limits: limits_mod.Limits,
    execution: ?limits_mod.Limits = null,
    ordinary_enabled: bool = true,
    slot: u64 = 0,
    last_now: u64 = 0,
    prune_cursor: usize = 0,
    prune_remaining: usize = 0,
    drop_before: u64 = 0,
    closed: bool = false,
    searches: [96]Search = @splat(.{}),
    refusals: [limits_mod.kind_count][refusal_count]u64 = @splat(@splat(0)),
    used_items: [limits_mod.kind_count]usize = @splat(0),
    used_bytes: [limits_mod.kind_count]usize = @splat(0),
    waiting_per_peer: [@import("../gossipsub/peer_book.zig").capacity][limits_mod.kind_count]u16 = @splat(@splat(0)),
    waiting_items: [limits_mod.kind_count]usize = @splat(0),
    executing_items: [limits_mod.kind_count]usize = @splat(0),
    executing_bytes: [limits_mod.kind_count]usize = @splat(0),
    forks: [@import("../chain.zig").boundary_max]n.reqresp.ForkEntry = undefined,
    fork_count: usize = 0,
    source_maximum: [limits_mod.kind_count]usize = @splat(payload_max),
    sources: [@import("../gossipsub/peer_book.zig").capacity]struct {
        generation: u64 = 0,
        items: [limits_mod.kind_count]usize = @splat(0),
        bytes: [limits_mod.kind_count]usize = @splat(0),
    } = @splat(.{}),

    pub const admit = @import("admission.zig").admit;

    pub fn fork(self: *const GossipProcessor, digest: [4]u8) ?@import("config").ForkSeq {
        for (self.forks[0..self.fork_count]) |entry| if (std.mem.eql(u8, &entry.digest, &digest)) return entry.fork;
        return null;
    }

    pub fn init(backing: std.mem.Allocator, plan: Plan) !GossipProcessor {
        const capacity = plan.capacity;
        const bytes = plan.bytes;
        const limits = plan.limits;
        if (plan.forks.len > @import("../chain.zig").boundary_max) return error.InvalidGossipProcessorLimits;
        if (capacity == 0 or capacity > limits_mod.capacity_max) return error.InvalidGossipProcessorLimits;
        try limits_mod.validate(&limits);
        if (capacity != limits_mod.items(&limits) or bytes != limits_mod.bytes(&limits)) return error.InvalidGossipProcessorLimits;
        const cells = try backing.alloc(Cell, capacity);
        errdefer backing.free(cells);
        @memset(cells, .{});
        var groups = try Groups.init(backing, capacity);
        errdefer groups.deinit(backing);
        var dependencies = try Dependencies.init(backing, capacity);
        errdefer dependencies.deinit(backing);
        const store = try storage.Store.init(backing, capacity, bytes);
        var self: GossipProcessor = .{ .cells = cells, .backing = backing, .store = store, .groups = groups, .dependencies = dependencies, .limits = limits, .execution = plan.execution, .source_maximum = plan.source_maximum, .fork_count = plan.forks.len, .diag = .{ .capacity = capacity } };
        @memcpy(self.forks[0..plan.forks.len], plan.forks);
        self.groups.index.seed = plan.random_seed ^ 3;
        self.dependencies.index.seed = plan.random_seed ^ 4;
        if (self.execution == null) {
            self.execution = limits;
            for (&self.execution.?) |*limit| limit.items = @max(1, limit.items / 2);
        }
        var k: usize = 0;
        var end: usize = limits[0].items;
        for (cells, 0..) |*cell, i| {
            if (i == end) {
                k += 1;
                end += limits[k].items;
            }
            cell.kind = @enumFromInt(k);
            self.queues[k][@intFromEnum(State.free)].append(cells, "state_link", @intCast(i));
        }
        return self;
    }
    pub fn backingBytes(capacity: usize, bytes: usize) usize {
        if (capacity == 0) return 0;
        return capacity * @sizeOf(Cell) + Groups.backingBytes(capacity) + Dependencies.backingBytes(capacity) + storage.Store.metadataBytes(capacity, bytes) + bytes / storage.page_bytes * storage.page_bytes;
    }
    pub fn deinit(self: *GossipProcessor) void {
        assert(self.diag.occupied == 0 and self.diag.reservedBytes == 0);
        if (self.cells.len == 0) return;
        self.backing.free(self.cells);
        self.groups.deinit(self.backing);
        self.dependencies.deinit(self.backing);
        self.store.deinit(self.backing);
    }
    pub fn trim(self: *GossipProcessor) void {
        if (self.diag.occupied != 0 or self.cells.len == 0) return;
        self.deinit();
        self.cells = &.{};
    }
    fn queue(self: *GossipProcessor, kind: Kind, state: State) *lists.List {
        return &self.queues[@intFromEnum(kind)][@intFromEnum(state)];
    }
    fn queueValue(self: *const GossipProcessor, kind: Kind, state: State) lists.List {
        return self.queues[@intFromEnum(kind)][@intFromEnum(state)];
    }
    fn token(self: *const GossipProcessor, index: u32) Token {
        return .{ .index = @intCast(index), .generation = self.cells[index].generation };
    }
    pub fn get(self: *GossipProcessor, handle: Token) ?*Cell {
        if (handle.index >= self.cells.len) return null;
        const cell = &self.cells[handle.index];
        return if (cell.state != .free and cell.generation == handle.generation) cell else null;
    }
    fn indexOf(self: *const GossipProcessor, cell: *const Cell) u32 {
        return @intCast((@intFromPtr(cell) - @intFromPtr(self.cells.ptr)) / @sizeOf(Cell));
    }
    pub fn reserve(self: *GossipProcessor, len: usize) !Token {
        return self.reserveKind(.beacon_block, len);
    }
    pub fn hasCapacity(self: *const GossipProcessor, kind: Kind, len: usize) bool {
        assert(len <= payload_max);
        if (self.closed or self.order == std.math.maxInt(u64)) return false;
        const k = @intFromEnum(kind);
        const pages = storage.Store.pagesFor(len);
        if (self.used_items[k] >= self.limits[k].items or pages * storage.page_bytes > self.limits[k].bytes - self.used_bytes[k]) return false;
        return self.queueValue(kind, .free).len > 0 and pages <= self.store.free_pages - self.staging_pages and self.store.used_entries + self.store.retired_entries + self.staging_items < self.store.entries.len;
    }
    pub fn refuse(self: *GossipProcessor, kind: Kind, reason: Refusal) void {
        self.refusals[@intFromEnum(kind)][@intFromEnum(reason)] +|= 1;
    }
    /// Counts a capacity refusal against the kind's own limits, or the shared store when the kind has room.
    pub fn refuseCapacity(self: *GossipProcessor, kind: Kind, len: usize) void {
        const k = @intFromEnum(kind);
        const pages = storage.Store.pagesFor(len);
        const room = self.used_items[k] < self.limits[k].items and pages * storage.page_bytes <= self.limits[k].bytes - self.used_bytes[k] and self.queueValue(kind, .free).len > 0;
        self.refuse(kind, if (room) .store_full else .kind_full);
    }
    pub fn occupancy(self: *const GossipProcessor, kind: Kind) [occupancy_count]u64 {
        return .{
            self.queueValue(kind, .queued).len,
            self.queueValue(kind, .waiting).len,
            self.queueValue(kind, .needs_check).len + self.queueValue(kind, .checking).len,
            self.executing_items[@intFromEnum(kind)],
        };
    }
    pub fn freshnessVictim(self: *const GossipProcessor, kind: Kind) ?Token {
        if (!limits_mod.newestFirst(kind)) return null;
        var selected: u32 = none;
        for ([_]State{ .queued, .needs_check, .checking, .waiting }) |state| {
            const index = self.queueValue(kind, state).head;
            if (index != none and (selected == none or self.cells[index].order < self.cells[selected].order)) selected = index;
        }
        return if (selected == none) null else self.token(selected);
    }
    pub fn capture(self: *GossipProcessor, message: *const native.MessageEvent, metadata: *const metadata_mod.Metadata, deneb: bool, received_at: u64) !void {
        const kind = native.topic.parseCanonical(message.topic).?.name.kind;
        if (!self.sourceRoom(message.source, kind, message.bytes.len)) return error.NetworkGossipFull;
        const handle = try self.reserveKind(kind, message.bytes.len);
        const cell = self.get(handle).?;
        cell.metadata = metadata.*;
        cell.deneb = deneb;
        cell.handle = message.handle;
        cell.identity = message.identity;
        cell.source = message.source;
        if (message.source) |source| {
            const usage = &self.sources[source.index];
            if (usage.generation != source.generation) usage.* = .{ .generation = source.generation };
            cell.source_charge = chargedBytes(message.bytes.len);
            usage.items[@intFromEnum(kind)] += 1;
            usage.bytes[@intFromEnum(kind)] += cell.source_charge;
        }
        cell.connection = message.peer;
        cell.id = message.id;
        assert(message.topic.len <= topic_max);
        @memcpy(cell.topic[0..message.topic.len], message.topic);
        cell.topic_len = @intCast(message.topic.len);
        cell.deadline = message.deadline;
        cell.received_at = received_at;
        cell.admitted_ms = message.admitted_ms;
        self.install(handle, message.bytes);
    }
    fn chargedBytes(len: usize) usize {
        return @max(storage.inline_bytes, storage.Store.pagesFor(len) * storage.page_bytes);
    }
    pub fn sourceRoom(self: *const GossipProcessor, source: ?Source, kind: Kind, len: usize) bool {
        const limits = self.limits;
        const peer = source orelse return true;
        const usage = &self.sources[peer.index];
        const k = @intFromEnum(kind);
        const items = if (usage.generation == peer.generation) usage.items[k] else 0;
        const bytes = if (usage.generation == peer.generation) usage.bytes[k] else 0;
        const maximum = chargedBytes(@min(self.source_maximum[k], limits[k].bytes));
        return items < limits_mod.sourceItems(limits[k]) and chargedBytes(len) <= limits_mod.sourceBytes(limits[k], maximum, storage.inline_bytes) -| bytes;
    }
    pub fn reserveKind(self: *GossipProcessor, kind: Kind, len: usize) !Token {
        assert(len <= payload_max);
        if (self.closed) return error.NetworkGossipFull;
        const k = @intFromEnum(kind);
        const pages = storage.Store.pagesFor(len);
        if (self.used_items[k] >= self.limits[k].items or pages * storage.page_bytes > self.limits[k].bytes - self.used_bytes[k]) return error.NetworkGossipFull;
        const index = self.queueValue(kind, .free).head;
        if (index == none) {
            self.diag.capacityRefusals +|= 1;
            return error.NetworkGossipFull;
        }
        if (pages > self.store.free_pages - self.staging_pages or self.store.used_entries + self.store.retired_entries + self.staging_items >= self.store.entries.len) {
            self.diag.byteRefusals +|= 1;
            return error.NetworkBridgeFull;
        }
        const order = try std.math.add(u64, self.order, 1);
        self.queue(kind, .free).remove(self.cells, "state_link", index);
        const generation = self.cells[index].generation;
        assert(generation < std.math.maxInt(u64));
        self.cells[index] = .{ .state = .capturing, .generation = generation + 1, .order = order, .kind = kind, .input = .{ .len = len } };
        self.queue(kind, .capturing).append(self.cells, "state_link", index);
        self.order = order;
        self.staging_pages += pages;
        self.staging_items += 1;
        self.used_items[k] += 1;
        self.used_bytes[k] += pages * storage.page_bytes;
        self.diag.payloadBytes += len;
        self.diag.occupied += 1;
        self.diag.highWater = @max(self.diag.highWater, self.diag.occupied);
        return self.token(index);
    }
    pub fn install(self: *GossipProcessor, handle: Token, copy: []const u8) void {
        const cell = self.get(handle).?;
        assert(cell.state == .capturing and cell.input.len == copy.len);
        const payload = self.store.put(cell.id, cell.topic[0..cell.topic_len], copy).?;
        self.store.retainValidation(payload);
        self.store.seal(payload);
        self.staging_pages -= storage.Store.pagesFor(copy.len);
        self.staging_items -= 1;
        cell.input.handle = payload;
        self.last_now = @max(self.last_now, cell.admitted_ms);
        // All deadlines use the startup timeout and serialized admission clock.
        if (self.expiry.tail != none) assert(self.cells[self.expiry.tail].deadline <= cell.deadline);
        self.expiry.append(self.cells, "expiry_link", handle.index);
        self.transition(handle.index, if (cell.metadata.root != null) .needs_check else .queued);
    }
    fn transition(self: *GossipProcessor, index: u32, state: State) void {
        const cell = &self.cells[index];
        const previous = cell.state;
        const k = @intFromEnum(cell.kind);
        if (previous == .queued) {
            if (cell.group_index != none) self.groups.leave(self.cells, index, self.last_now) else self.ready[k].remove(self.cells, "ready_link", index);
        }
        if (previous == .waiting) {
            self.dependencies.leave(self.cells, index);
            self.waiting_items[k] -= 1;
            if (cell.source) |source| self.waiting_per_peer[source.index][k] -= 1;
        }
        self.countState(previous, false, cell.input.len);
        self.queue(cell.kind, previous).remove(self.cells, "state_link", index);
        cell.state = state;
        self.queue(cell.kind, state).append(self.cells, "state_link", index);
        self.countState(state, true, cell.input.len);
        if (state == .queued) {
            if (cell.kind == .beacon_attestation and cell.metadata.group != null) self.groups.join(self.cells, index, self.last_now) else self.ready[k].append(self.cells, "ready_link", index);
        }
        if (state == .waiting) {
            self.dependencies.join(self.cells, index);
            self.waiting_items[k] += 1;
            if (cell.source) |source| self.waiting_per_peer[source.index][k] += 1;
        }
    }
    fn countState(self: *GossipProcessor, state: State, add: bool, bytes: usize) void {
        const count: ?*usize = switch (state) {
            .queued => &self.diag.queued,
            .waiting => &self.diag.waiting,
            .copying => &self.diag.copying,
            .needs_check, .checking => &self.diag.checking,
            .verdict_pending => &self.diag.pendingVerdicts,
            else => null,
        };
        if (count) |value| {
            if (add) value.* += 1 else value.* -= 1;
        }
        if (state == .copying) {
            if (add) self.diag.copyingBytes += bytes else self.diag.copyingBytes -= bytes;
        }
    }
    pub fn copyPayload(self: *const GossipProcessor, cell: *const Cell, destination: []u8) void {
        assert(destination.len == cell.input.len);
        const handle = cell.input.handle.?;
        var cursor = self.store.cursor(handle);
        var offset: usize = 0;
        for (0..@max(@intFromBool(destination.len > 0), storage.Store.pagesFor(destination.len))) |_| {
            const segment = self.store.segment(handle, cursor);
            @memcpy(destination[offset..][0..segment.len], segment);
            offset += segment.len;
            self.store.advance(&cursor, segment.len);
        }
        assert(offset == destination.len);
    }

    fn releasePayload(self: *GossipProcessor, cell: *Cell) void {
        if (cell.input.handle) |handle| self.store.releaseValidation(handle) else if (cell.state == .capturing) {
            self.staging_pages -= storage.Store.pagesFor(cell.input.len);
            self.staging_items -= 1;
        }
        self.used_bytes[@intFromEnum(cell.kind)] -= storage.Store.pagesFor(cell.input.len) * storage.page_bytes;
        self.diag.payloadBytes -= cell.input.len;
        cell.input = .{};
    }
    fn releaseExecution(self: *GossipProcessor, cell: *Cell) void {
        if (!cell.executing) return;
        const k = @intFromEnum(cell.kind);
        self.executing_items[k] -= 1;
        self.executing_bytes[k] -= cell.execution_bytes;
        self.diag.executing -= 1;
        self.diag.executingBytes -= cell.execution_bytes;
        cell.executing = false;
    }
    pub fn retire(self: *GossipProcessor, handle: Token) void {
        const cell = self.get(handle).?;
        assert(cell.state != .copying);
        if (cell.expiry_link.linked) self.expiry.remove(self.cells, "expiry_link", handle.index);
        self.releasePayload(cell);
        self.releaseExecution(cell);
        self.transition(handle.index, .free);
        self.used_items[@intFromEnum(cell.kind)] -= 1;
        if (cell.source_charge > 0) {
            const source = cell.source.?;
            const usage = &self.sources[source.index];
            if (usage.generation == source.generation) {
                usage.items[@intFromEnum(cell.kind)] -= 1;
                usage.bytes[@intFromEnum(cell.kind)] -= cell.source_charge;
            }
        }
        const generation = cell.generation;
        const kind = cell.kind;
        const link = cell.state_link;
        cell.* = .{ .generation = generation, .kind = kind, .state_link = link };
        if (generation == std.math.maxInt(u64)) self.queue(kind, .free).remove(self.cells, "state_link", handle.index);
        self.diag.occupied -= 1;
    }
    pub fn oldest(self: *const GossipProcessor) ?Token {
        var selected: u32 = none;
        for (limits_mod.priority) |kind| {
            const index = self.nextKind(kind);
            if (index != none and (selected == none or self.cells[index].order < self.cells[selected].order)) selected = index;
        }
        return if (selected == none) null else self.token(selected);
    }
    pub fn hasWork(self: *const GossipProcessor) bool {
        if (self.closed) return false;
        for (limits_mod.priority) |kind| {
            if (self.queueValue(kind, .needs_check).len > 0) return true;
            const index = self.nextKind(kind);
            if (index != none and self.dispatchable(&self.cells[index])) return true;
        }
        return false;
    }
    /// Work a host drain can take now: dependency checks, and claimable urgent and ordinary jobs.
    pub const HostWork = struct { checks: bool = false, urgent: bool = false, ordinary: bool = false };
    /// Ordinary work counts also while the host's last claim disabled it, so a host able to
    /// execute again knows to claim it. O(kinds).
    pub fn hostWork(self: *const GossipProcessor) HostWork {
        var result: HostWork = .{};
        if (self.closed) return result;
        for (limits_mod.priority) |kind| {
            if (self.queueValue(kind, .needs_check).len > 0) result.checks = true;
            const index = self.nextKind(kind);
            if (index == none or !self.executable(&self.cells[index])) continue;
            if (limits_mod.urgent(kind)) result.urgent = true else result.ordinary = true;
        }
        return result;
    }
    pub fn expire(self: *GossipProcessor, now: u64) void {
        self.last_now = @max(self.last_now, now);
        var bytes: usize = 0;
        for (0..batch_max) |_| {
            const index = self.expiry.head;
            if (index == none or self.cells[index].deadline > now) break;
            const cell = &self.cells[index];
            const cost = if (cell.state == .copying or cell.state == .delivered) 0 else cell.input.len;
            if (bytes > 0 and cost > batch_bytes -| bytes) break;
            bytes += cost;
            self.expiry.remove(self.cells, "expiry_link", index);
            if (cell.state != .delivered and cell.state != .verdict_pending) self.diag.queuedExpired +|= 1 else self.diag.deliveredExpired +|= 1;
            cell.retired = true;
            if (cell.state != .copying and cell.state != .delivered) self.retire(self.token(index));
        }
    }
    pub fn maintain(self: *GossipProcessor, now: u64, slot: u64) void {
        if (self.closed) return;
        self.expire(now);
        self.groups.advance(now, batch_max);
        if (self.slot != slot) {
            self.slot = slot;
            self.prune_cursor = 0;
            self.prune_remaining = self.cells.len;
        }
        for (0..batch_max) |_| {
            const index = self.dependencies.next() orelse break;
            self.transition(index, .needs_check);
        }
        for (0..@min(batch_max, self.prune_remaining)) |_| {
            const index = self.prune_cursor;
            self.prune_cursor += 1;
            self.prune_remaining -= 1;
            const cell = &self.cells[index];
            switch (cell.state) {
                .needs_check, .checking, .waiting, .queued => if (!self.eligible(cell)) self.ignore(cell),
                else => {},
            }
        }
    }
    fn eligible(self: *const GossipProcessor, cell: *const Cell) bool {
        return cell.order > self.drop_before and metadata_mod.eligible(&cell.metadata, cell.kind, cell.deneb, self.slot);
    }
    pub fn close(self: *GossipProcessor) void {
        self.closed = true;
        for (self.cells, 0..) |*cell, i| {
            if (cell.state == .free) continue;
            cell.retired = true;
            if (cell.state != .copying and cell.state != .capturing) self.retire(self.token(@intCast(i)));
        }
    }
    pub const Demand = struct { items: usize = batch_max, bytes: usize = batch_bytes, ordinary: bool = true };
    fn dispatchable(self: *const GossipProcessor, cell: *const Cell) bool {
        if (self.execution != null and !self.ordinary_enabled and !limits_mod.urgent(cell.kind)) return false;
        return self.executable(cell);
    }
    /// Whether the kind's execution limits admit `cell`, whatever the host's ordinary gate.
    fn executable(self: *const GossipProcessor, cell: *const Cell) bool {
        const execution = self.execution orelse return true;
        const k = @intFromEnum(cell.kind);
        return self.executing_items[k] < execution[k].items and cell.input.len <= execution[k].bytes - self.executing_bytes[k];
    }
    fn nextKind(self: *const GossipProcessor, kind: Kind) u32 {
        const ready = self.ready[@intFromEnum(kind)];
        const index = if (limits_mod.newestFirst(kind)) ready.tail else ready.head;
        if (kind != .beacon_attestation or self.groups.ready.tail == none) return index;
        const group = self.groups.rows[self.groups.ready.tail].members.tail;
        return if (index == none or self.cells[group].order > self.cells[index].order) group else index;
    }
    pub fn claim(self: *GossipProcessor, now: u64) Batch {
        return self.claimDemand(now, .{});
    }
    pub fn claimDemand(self: *GossipProcessor, now: u64, demand: Demand) Batch {
        self.maintain(now, self.slot);
        self.ordinary_enabled = demand.ordinary;
        var batch: Batch = .{};
        if (self.closed) return batch;
        var size: usize = 0;
        var work: usize = 0;
        for (limits_mod.priority) |kind| {
            for (0..batch_max) |_| {
                if (batch.len >= @min(batch_max, demand.items) or work == batch_max) return batch;
                const index = self.nextKind(kind);
                if (index == none) break;
                const cell = &self.cells[index];
                if (now >= cell.deadline or !self.eligible(cell)) {
                    work += 1;
                    self.ignore(cell);
                    continue;
                }
                if (!self.dispatchable(cell)) break;
                const group = cell.group_index;
                const start = batch.len;
                const group_count = if (group == none) 1 else self.groups.rows[group].members.len;
                for (0..@min(batch_max - work, group_count)) |_| {
                    if (batch.len >= @min(batch_max, demand.items)) break;
                    const member = if (group == none) index else self.groups.rows[group].members.tail;
                    if (now >= self.cells[member].deadline or !self.eligible(&self.cells[member])) {
                        self.ignore(&self.cells[member]);
                        work += 1;
                        continue;
                    }
                    if (!self.dispatchable(&self.cells[member])) break;
                    if (!self.append(&batch, member, &size, demand.bytes)) break;
                    work += 1;
                }
                if (batch.len == start) break;
                batch.jobs[batch.job_count] = .{ .kind = kind, .start = start, .len = batch.len - start, .grouped = group != none };
                batch.job_count += 1;
            }
        }
        return batch;
    }
    fn append(self: *GossipProcessor, batch: *Batch, index: u32, size: *usize, limit: usize) bool {
        const cell = &self.cells[index];
        assert(cell.input.len <= batch_bytes);
        // An empty batch takes its first item whatever the host's byte cap, so no item blocks its lane.
        if (batch.len > 0 and cell.input.len > @min(batch_bytes, limit) -| size.*) return false;
        size.* += cell.input.len;
        self.transition(index, .copying);
        cell.executing = true;
        cell.execution_bytes = cell.input.len;
        self.executing_items[@intFromEnum(cell.kind)] += 1;
        self.executing_bytes[@intFromEnum(cell.kind)] += cell.input.len;
        self.diag.executing += 1;
        self.diag.executingBytes += cell.input.len;
        batch.tokens[batch.len] = self.token(index);
        batch.len += 1;
        return true;
    }
    pub fn claimChecks(self: *GossipProcessor, now: u64) Batch {
        self.maintain(now, self.slot);
        var batch: Batch = .{};
        if (self.closed) return batch;
        var work: usize = 0;
        for (limits_mod.priority) |kind| {
            for (0..batch_max) |_| {
                if (work == batch_max) return batch;
                const index = self.queueValue(kind, .needs_check).head;
                if (index == none) break;
                work += 1;
                const cell = &self.cells[index];
                if (now >= cell.deadline or !self.eligible(cell)) {
                    self.ignore(cell);
                    continue;
                }
                self.transition(index, .checking);
                cell.check_notification = self.dependencies.notification;
                batch.tokens[batch.len] = self.token(index);
                batch.len += 1;
            }
        }
        return batch;
    }
    pub fn retryChecks(self: *GossipProcessor, batch: *const Batch) void {
        for (batch.tokens[0..batch.len]) |handle| if (self.get(handle)) |cell| {
            if (cell.state == .checking) self.transition(handle.index, .needs_check);
        };
    }
    pub fn classify(self: *GossipProcessor, handle: Token, available: bool) bool {
        const cell = self.get(handle) orelse return false;
        if (cell.state != .checking or cell.retired) return false;
        if (self.last_now >= cell.deadline or !self.eligible(cell)) {
            self.ignore(cell);
        } else if (available or !cell.metadata.await_block) {
            self.transition(handle.index, .queued);
        } else if (cell.check_notification != self.dependencies.notification or self.dependencies.notification == std.math.maxInt(u64)) {
            self.transition(handle.index, .needs_check);
        } else {
            const k = @intFromEnum(cell.kind);
            const peer_full = if (cell.source) |source| self.waiting_per_peer[source.index][k] >= @max(1, self.limits[k].items / 4) else false;
            if (peer_full or self.waiting_items[k] >= self.limits[k].items / 2) {
                self.ignore(cell);
                self.refuse(cell.kind, .dependency_full);
            } else self.transition(handle.index, .waiting);
        }
        return true;
    }
    pub fn trackSearch(self: *GossipProcessor, root: [32]u8, peer: ?n.PeerId, now: u64) bool {
        var free: ?*Search = null;
        var found: ?*Search = null;
        for (&self.searches) |*search| {
            if (now >= search.until) {
                if (free == null) free = search;
                continue;
            }
            if (std.mem.eql(u8, &search.root, &root)) {
                found = search;
                break;
            }
        }
        const search = found orelse free orelse return false;
        if (found == null) search.* = .{ .root = root, .until = now +| 30000 };
        if (peer) |identity| {
            for (search.peers[0..search.count]) |prior| if (identity.eql(&prior)) return false;
            if (search.count == search.peers.len) return false;
            search.peers[search.count] = identity;
            search.count += 1;
        } else {
            if (search.anonymous) return false;
            search.anonymous = true;
        }
        return true;
    }

    pub fn notifyBlock(self: *GossipProcessor, root: [32]u8) void {
        self.dependencies.notify(&root);
    }
    pub fn ignore(self: *GossipProcessor, cell: *Cell) void {
        assert(!cell.executing);
        if (!self.eligible(cell)) self.diag.slotRefusals +|= 1;
        self.transition(self.indexOf(cell), .verdict_pending);
        cell.verdict = .ignore;
    }
    pub fn dropQueued(self: *GossipProcessor) void {
        self.drop_before = self.order;
        self.prune_cursor = 0;
        self.prune_remaining = self.cells.len;
    }
    pub fn nextVerdict(self: *const GossipProcessor) ?Token {
        for (limits_mod.priority) |kind| {
            const index = self.queueValue(kind, .verdict_pending).head;
            if (index != none) return self.token(index);
        }
        return null;
    }
    pub fn finish(self: *GossipProcessor, batch: *const Batch, success: bool) void {
        for (batch.tokens[0..batch.len]) |handle| {
            const cell = self.get(handle).?;
            assert(cell.state == .copying);
            self.transition(handle.index, if (success) .delivered else .queued);
            if (!success) self.releaseExecution(cell);
            if (success) {
                self.diag.messagesCopied +|= 1;
                self.diag.bytesCopied +|= cell.input.len;
                self.releasePayload(cell);
            }
            if (cell.retired and (!success or self.closed)) self.retire(handle);
        }
    }
    pub fn report(self: *GossipProcessor, handle: Token, verdict: native.Verdict, now: u64) bool {
        self.expire(now);
        if (self.get(handle)) |cell| if (cell.state == .delivered) {
            self.releaseExecution(cell);
            if (cell.retired or now >= cell.deadline) {
                self.retire(handle);
                return false;
            }
            cell.verdict = verdict;
            self.transition(handle.index, .verdict_pending);
            self.diag.reportsAccepted +|= 1;
            return true;
        };
        return false;
    }
    pub fn outcome(self: *GossipProcessor, result: native.ReportOutcome) void {
        switch (result) {
            .applied => |verdict| switch (verdict) {
                .accept => self.diag.reportsAppliedAccept +|= 1,
                .reject => self.diag.reportsAppliedReject +|= 1,
                .ignore => self.diag.reportsAppliedIgnore +|= 1,
            },
            .already_resolved, .expired, .stale_handle => {},
        }
    }

    /// Work the owner carries over turns in bounded batches: a slot prune, dependency promotion
    /// or queued verdicts.
    pub fn pending(self: *const GossipProcessor) bool {
        if (self.closed) return false;
        return self.prune_remaining > 0 or self.dependencies.promoting.len > 0 or self.diag.pendingVerdicts > 0;
    }
    /// Earliest attestation group or expiry deadline. O(1).
    pub fn deadline(self: *const GossipProcessor) ?u64 {
        var result = self.groups.deadline();
        if (self.expiry.head != none) {
            const expiry = self.cells[self.expiry.head].deadline;
            result = @min(result orelse expiry, expiry);
        }
        return result;
    }
    pub fn snapshot(self: *const GossipProcessor, now: u64) Diagnostics {
        var result = self.diag;
        for (limits_mod.priority) |kind| {
            var index = self.queueValue(kind, .delivered).head;
            for (0..self.queueValue(kind, .delivered).len) |_| {
                const cell = &self.cells[index];
                if (now >= cell.deadline) {
                    result.expiredExecuting += 1;
                    result.oldestExpiredExecutionAgeMs = @max(result.oldestExpiredExecutionAgeMs, now - cell.deadline);
                }
                index = cell.state_link.next;
            }
        }
        assert(result.expiredExecuting <= result.executing);
        return result;
    }
};

test {
    _ = metadata_mod;
    _ = @import("root_test.zig");
    _ = @import("root_scheduler_test.zig");
}
