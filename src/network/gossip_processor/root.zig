const std = @import("std");
const n = @import("../root.zig");
const native = n.gossipsub;
const Budget = @import("../byte_budget.zig").Budget;
const storage = @import("../gossipsub/message_store.zig");
pub const limits_mod = @import("limits.zig");
pub const metadata_mod = @import("metadata.zig");
const Kind = limits_mod.Kind;
const assert = std.debug.assert;
pub const batch_max = 64;
pub const batch_bytes = 16 * 1024 * 1024;
pub const payload_max = 10 * 1024 * 1024;
pub const topic_max = native.topic.topic_max_len;
pub const Token = struct { index: u16, generation: u64 };
pub const State = enum { free, capturing, needs_check, checking, waiting, queued, copying, delivered, verdict_pending };
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    order: u64 = 0,
    handle: native.ValidationHandle = undefined,
    identity: n.PeerId = undefined,
    source: ?@import("../gossipsub/peer_book.zig").Ref = null,
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
    check_again: bool = false,
    deneb: bool = false,
    executing: bool = false,
    execution_bytes: usize = 0,
    reservation: usize = 0,
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
    publicationBytes: usize = 0,
    publicationBytesHighWater: usize = 0,
    messagesCopied: u64 = 0,
    bytesCopied: u64 = 0,
    capacityRefusals: u64 = 0,
    byteRefusals: u64 = 0,
    queuedExpired: u64 = 0,
    deliveredExpired: u64 = 0,
    staleReports: u64 = 0,
    reportsAccepted: u64 = 0,
    reportsAppliedAccept: u64 = 0,
    reportsAppliedReject: u64 = 0,
    reportsAppliedIgnore: u64 = 0,
    reportsAlreadyResolved: u64 = 0,
    reportsExpired: u64 = 0,
    reportsStale: u64 = 0,
    waiting: usize = 0,
    checking: usize = 0,
    executing: usize = 0,
    dependencyRefusals: u64 = 0,
    kindRefusals: u64 = 0,
    slotRefusals: u64 = 0,
    fixedPayloadBytes: usize = 0,
    publicationCopies: u64 = 0,
    publicationBytesCopied: u64 = 0,
    publicationQueued: u64 = 0,
    publicationPressured: u64 = 0,
    publicationSelected: u64 = 0,
    publicationUnavailable: u64 = 0,
    publicationDuplicates: u64 = 0,
};
pub const Batch = struct { tokens: [batch_max]Token = undefined, len: usize = 0, grouped: bool = false };
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
    budget: *Budget,
    diag: Diagnostics = .{},
    order: u64 = 0,
    cursor: usize = 0,
    allocation_cursors: [limits_mod.kind_count]usize = @splat(0),
    store: storage.Store,
    staging_pages: usize = 0,
    staging_items: usize = 0,
    limits: ?limits_mod.Limits = null,
    ordinary_enabled: bool = true,
    slot: u64 = 0,
    batch_due: ?u64 = null,
    closed: bool = false,
    searches: [96]Search = @splat(.{}),
    used_items: [limits_mod.kind_count]usize = @splat(0),
    used_bytes: [limits_mod.kind_count]usize = @splat(0),
    waiting_per_peer: [@import("../gossipsub/peer_book.zig").capacity][limits_mod.kind_count]u16 = @splat(@splat(0)),
    waiting_items: [limits_mod.kind_count]usize = @splat(0),
    executing_items: [limits_mod.kind_count]usize = @splat(0),
    executing_bytes: [limits_mod.kind_count]usize = @splat(0),

    pub fn init(backing: std.mem.Allocator, capacity: usize, budget: *Budget) !GossipProcessor {
        return initPlanned(backing, capacity, 64 * 1024 * 1024, budget, null);
    }
    pub fn initPlanned(backing: std.mem.Allocator, capacity: usize, bytes: usize, budget: *Budget, limits: ?limits_mod.Limits) !GossipProcessor {
        if (capacity == 0 or capacity > limits_mod.capacity_max) return error.InvalidGossipProcessorLimits;
        if (limits) |value| {
            try limits_mod.validate(&value);
            if (capacity != limits_mod.items(&value) or bytes != limits_mod.bytes(&value)) return error.InvalidGossipProcessorLimits;
        }
        const cells = try backing.alloc(Cell, capacity);
        errdefer backing.free(cells);
        @memset(cells, .{});
        const store = try storage.Store.init(backing, capacity, bytes);
        return .{ .cells = cells, .backing = backing, .budget = budget, .store = store, .limits = limits, .diag = .{ .capacity = capacity, .fixedPayloadBytes = store.bytes.len + capacity * storage.inline_bytes } };
    }
    pub fn backingBytes(capacity: usize, bytes: usize) usize {
        return capacity * @sizeOf(Cell) + storage.Store.metadataBytes(capacity, bytes) + bytes;
    }
    pub fn deinit(self: *GossipProcessor) void {
        assert(self.diag.occupied == 0 and self.diag.reservedBytes == 0);
        self.backing.free(self.cells);
        self.store.deinit(self.backing);
    }
    pub fn trim(self: *GossipProcessor) void {
        if (self.diag.occupied != 0 or self.cells.len == 0) return;
        self.backing.free(self.cells);
        self.cells = &.{};
        self.backing.free(self.store.entries);
        self.backing.free(self.store.next);
        self.backing.free(self.store.bytes);
        self.store.entries = &.{};
        self.store.next = &.{};
        self.store.bytes = &.{};
        self.diag.fixedPayloadBytes = 0;
    }
    pub fn get(self: *GossipProcessor, token: Token) ?*Cell {
        if (token.index >= self.cells.len) return null;
        const cell = &self.cells[token.index];
        return if (cell.state != .free and cell.generation == token.generation) cell else null;
    }
    pub fn reserve(self: *GossipProcessor, len: usize) !Token {
        return self.reserveKind(.beacon_block, len);
    }
    pub fn reserveKind(self: *GossipProcessor, kind: Kind, len: usize) !Token {
        assert(len <= payload_max);
        const k = @intFromEnum(kind);
        const pages = storage.Store.pagesFor(len);
        if (self.limits) |limits| {
            if (self.used_items[k] >= limits[k].items or pages * storage.page_bytes > limits[k].bytes - self.used_bytes[k]) {
                self.diag.kindRefusals +|= 1;
                return error.NetworkGossipFull;
            }
        }
        const amount = try std.math.mul(usize, len, 2);
        var selected: ?Token = null;
        var start: usize = 0;
        if (self.limits) |limits| for (limits[0..k]) |limit| {
            start += limit.items;
        };
        const end = if (self.limits) |limits| start + limits[k].items else self.cells.len;
        const count = end - start;
        for (0..count) |offset| {
            const i = start + (self.allocation_cursors[k] + offset) % count;
            const cell = &self.cells[i];
            if (cell.state != .free or cell.generation == std.math.maxInt(u64)) continue;
            selected = .{ .index = @intCast(i), .generation = cell.generation + 1 };
            break;
        }
        const token = selected orelse {
            self.diag.capacityRefusals +|= 1;
            return error.NetworkGossipFull;
        };
        if (pages > self.store.free_pages - self.staging_pages or self.store.used_entries + self.store.retired_entries + self.staging_items >= self.store.entries.len) {
            self.diag.byteRefusals +|= 1;
            return error.NetworkBridgeFull;
        }
        const order = try std.math.add(u64, self.order, 1);
        if (self.limits == null) self.reserveBytes(amount) catch |err| {
            self.diag.byteRefusals +|= 1;
            return err;
        };
        self.allocation_cursors[k] = (token.index - start + 1) % count;
        self.order = order;
        self.cells[token.index] = .{ .state = .capturing, .generation = token.generation, .order = order, .reservation = if (self.limits == null) amount else 0, .kind = kind, .input = .{ .len = len } };
        self.staging_pages += pages;
        self.staging_items += 1;
        self.used_items[k] += 1;
        self.used_bytes[k] += pages * storage.page_bytes;
        self.diag.occupied += 1;
        self.diag.highWater = @max(self.diag.highWater, self.diag.occupied);
        return token;
    }
    fn reserveBytes(self: *GossipProcessor, amount: usize) !void {
        try self.budget.reserve(amount);
        self.diag.reservedBytes += amount;
        self.diag.reservedBytesHighWater = @max(self.diag.reservedBytesHighWater, self.diag.reservedBytes);
    }
    fn releaseBytes(self: *GossipProcessor, amount: usize) void {
        self.budget.release(amount);
        self.diag.reservedBytes -= amount;
    }
    pub fn reservePublication(self: *GossipProcessor, amount: usize) !void {
        try self.reserveBytes(amount);
        self.diag.publicationBytes += amount;
        self.diag.publicationBytesHighWater = @max(self.diag.publicationBytesHighWater, self.diag.publicationBytes);
    }
    pub fn releasePublication(self: *GossipProcessor, amount: usize) void {
        self.releaseBytes(amount);
        self.diag.publicationBytes -= amount;
    }
    pub fn install(self: *GossipProcessor, token: Token, copy: []const u8) void {
        const cell = self.get(token).?;
        assert(cell.state == .capturing and cell.input.len == copy.len);
        const handle = self.store.put(cell.id, cell.topic[0..cell.topic_len], copy).?;
        self.store.retainValidation(handle);
        self.store.seal(handle);
        self.staging_pages -= storage.Store.pagesFor(copy.len);
        self.staging_items -= 1;
        cell.input.handle = handle;
        cell.state = if (self.limits != null and cell.metadata.root != null) .needs_check else .queued;
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
        cell.input = .{};
        self.releaseBytes(cell.reservation);
        cell.reservation = 0;
    }
    fn releaseExecution(self: *GossipProcessor, cell: *Cell) void {
        if (!cell.executing) return;
        const k = @intFromEnum(cell.kind);
        self.executing_items[k] -= 1;
        self.executing_bytes[k] -= cell.execution_bytes;
        cell.executing = false;
    }
    pub fn retire(self: *GossipProcessor, token: Token) void {
        const cell = self.get(token).?;
        assert(cell.state != .copying);
        if (cell.state == .waiting) self.leaveWaiting(cell);
        self.releasePayload(cell);
        self.releaseExecution(cell);
        self.used_items[@intFromEnum(cell.kind)] -= 1;
        cell.* = .{ .generation = cell.generation };
        self.diag.occupied -= 1;
    }
    pub fn oldest(self: *const GossipProcessor) ?Token {
        var selected: ?Token = null;
        var order: u64 = std.math.maxInt(u64);
        for (self.cells, 0..) |*cell, i| {
            if (cell.retired) continue;
            if (cell.state != .needs_check and (cell.state != .queued or !self.dispatchable(cell))) continue;
            if (selected == null or cell.order < order) {
                selected = .{ .index = @intCast(i), .generation = cell.generation };
                order = cell.order;
            }
        }
        return selected;
    }
    pub fn hasWork(self: *const GossipProcessor) bool {
        for (self.cells) |*cell| {
            if (cell.retired) continue;
            if (cell.state == .needs_check or (cell.state == .queued and self.dispatchable(cell))) return true;
        }
        return false;
    }
    pub fn expire(self: *GossipProcessor, now: u64) void {
        for (self.cells, 0..) |*cell, i| {
            if (cell.state == .free or cell.state == .capturing or cell.retired or now < cell.deadline) continue;
            if (cell.state != .delivered and cell.state != .verdict_pending) self.diag.queuedExpired +|= 1 else self.diag.deliveredExpired +|= 1;
            cell.retired = true;
            if (cell.state != .copying and (self.limits == null or cell.state != .delivered)) self.retire(.{ .index = @intCast(i), .generation = cell.generation });
        }
    }
    pub fn close(self: *GossipProcessor) void {
        self.closed = true;
        for (self.cells, 0..) |*cell, i| {
            if (cell.state == .free) continue;
            cell.retired = true;
            if (cell.state != .copying and cell.state != .capturing) self.retire(.{ .index = @intCast(i), .generation = cell.generation });
        }
    }
    pub const Demand = struct { items: usize = batch_max, bytes: usize = batch_bytes, ordinary: bool = true, kind: ?Kind = null };
    fn dispatchable(self: *const GossipProcessor, cell: *const Cell) bool {
        if (self.limits) |limits| {
            const k = @intFromEnum(cell.kind);
            if (!self.ordinary_enabled and !limits_mod.urgent(cell.kind)) return false;
            if (self.executing_items[k] >= limits[k].items / 2) return false;
            if (cell.input.len > limits[k].bytes - self.executing_bytes[k]) return false;
        }
        return true;
    }
    fn next(self: *const GossipProcessor, selected_kind: ?Kind, now: u64) ?Token {
        if (self.limits == null) return self.oldest();
        for (limits_mod.priority) |kind| {
            if (selected_kind != null and selected_kind.? != kind) continue;
            var selected: ?Token = null;
            var order: u64 = 0;
            var selected_mature = false;
            var start: usize = 0;
            for (self.limits.?[0..@intFromEnum(kind)]) |limit| start += limit.items;
            const end = start + self.limits.?[@intFromEnum(kind)].items;
            for (self.cells[start..end], start..) |*cell, i| {
                if (cell.state != .queued or cell.retired or cell.kind != kind or !self.dispatchable(cell)) continue;
                const mature = kind == .beacon_attestation and (cell.metadata.group == null or now >= cell.admitted_ms +| 50);
                if (selected == null or (mature and !selected_mature) or (mature == selected_mature and (if (limits_mod.newestFirst(kind)) cell.order > order else cell.order < order))) {
                    selected = .{ .index = @intCast(i), .generation = cell.generation };
                    order = cell.order;
                    selected_mature = mature;
                }
            }
            if (selected != null) return selected;
        }
        return null;
    }
    pub fn claim(self: *GossipProcessor, now: u64) Batch {
        return self.claimDemand(now, .{});
    }
    pub fn claimDemand(self: *GossipProcessor, now: u64, demand: Demand) Batch {
        self.expire(now);
        self.ordinary_enabled = demand.ordinary;
        var batch: Batch = .{};
        if (demand.items == 0) return batch;
        const selected = self.next(demand.kind, now) orelse return batch;
        const first = self.get(selected).?;
        const grouped = self.limits != null and first.kind == .beacon_attestation and first.metadata.group != null;
        if (grouped) {
            var count: usize = 0;
            var due = first.admitted_ms +| 50;
            for (self.cells) |*cell| {
                if (sameGroup(first, cell)) count += 1;
                if (cell.state == .queued and !cell.retired and cell.kind == .beacon_attestation) due = @min(due, cell.admitted_ms +| 50);
            }
            if (count < 32 and now < first.admitted_ms +| 50) {
                self.batch_due = @min(self.batch_due orelse due, due);
                return batch;
            }
        }
        var size: usize = 0;
        const maximum = @min(batch_max, demand.items);
        if (self.limits == null) {
            for (0..maximum) |_| {
                const token = self.oldest() orelse break;
                if (!self.append(&batch, token, &size, demand.bytes)) break;
            }
        } else if (self.append(&batch, selected, &size, demand.bytes) and grouped) {
            batch.grouped = true;
            for (self.cells, 0..) |*cell, i| {
                if (batch.len == maximum) break;
                if (!sameGroup(first, cell) or !self.dispatchable(cell)) continue;
                _ = self.append(&batch, .{ .index = @intCast(i), .generation = cell.generation }, &size, demand.bytes);
            }
        }
        return batch;
    }
    fn sameGroup(first: *const Cell, cell: *const Cell) bool {
        return cell.state == .queued and !cell.retired and cell.kind == first.kind and cell.metadata.group != null and
            std.mem.eql(u8, &first.metadata.group.?, &cell.metadata.group.?) and std.mem.eql(u8, first.topic[0..14], cell.topic[0..14]);
    }
    fn append(self: *GossipProcessor, batch: *Batch, token: Token, size: *usize, limit: usize) bool {
        const cell = self.get(token).?;
        if (cell.input.len > @min(batch_bytes, limit) - size.*) return false;
        size.* += cell.input.len;
        cell.state = .copying;
        cell.executing = true;
        cell.execution_bytes = cell.input.len;
        self.executing_items[@intFromEnum(cell.kind)] += 1;
        self.executing_bytes[@intFromEnum(cell.kind)] += cell.input.len;
        batch.tokens[batch.len] = token;
        batch.len += 1;
        return true;
    }
    pub fn claimChecks(self: *GossipProcessor, now: u64) Batch {
        self.expire(now);
        var batch: Batch = .{};
        var start: usize = 0;
        for (0..limits_mod.kind_count) |k| {
            const end = if (self.limits) |limits| start + limits[k].items else self.cells.len;
            for (self.cells[start..end], start..) |*cell, i| {
                if (batch.len == batch_max) return batch;
                if (cell.state != .needs_check or cell.retired) continue;
                cell.state = .checking;
                cell.check_again = false;
                batch.tokens[batch.len] = .{ .index = @intCast(i), .generation = cell.generation };
                batch.len += 1;
            }
            if (self.limits == null) break;
            start = end;
        }
        return batch;
    }
    pub fn retryChecks(self: *GossipProcessor, batch: *const Batch) void {
        for (batch.tokens[0..batch.len]) |token| if (self.get(token)) |cell| {
            if (cell.state == .checking) cell.state = .needs_check;
        };
    }
    pub fn classify(self: *GossipProcessor, token: Token, available: bool) bool {
        const cell = self.get(token) orelse return false;
        if (cell.state != .checking or cell.retired) return false;
        if (available or !cell.metadata.await_block) cell.state = .queued else if (cell.check_again) {
            cell.state = .needs_check;
        } else {
            const k = @intFromEnum(cell.kind);
            const peer_full = if (cell.source) |source| self.waiting_per_peer[source.index][k] >= @max(1, @min(64, self.limits.?[k].items / 4)) else false;
            if (peer_full or self.waiting_items[k] >= self.limits.?[k].items / 2) {
                cell.state = .verdict_pending;
                cell.verdict = .ignore;
                self.diag.dependencyRefusals +|= 1;
            } else {
                cell.state = .waiting;
                self.waiting_items[@intFromEnum(cell.kind)] += 1;
                if (cell.source) |source| self.waiting_per_peer[source.index][@intFromEnum(cell.kind)] += 1;
            }
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
        for (self.cells) |*cell| {
            if (cell.metadata.root == null or !std.mem.eql(u8, &cell.metadata.root.?, &root)) continue;
            if (cell.state == .waiting) {
                self.leaveWaiting(cell);
                cell.state = .needs_check;
            }
            if (cell.state == .checking) cell.check_again = true;
        }
    }
    fn leaveWaiting(self: *GossipProcessor, cell: *const Cell) void {
        const k = @intFromEnum(cell.kind);
        self.waiting_items[k] -= 1;
        if (cell.source) |source| self.waiting_per_peer[source.index][k] -= 1;
    }
    pub fn ignore(self: *GossipProcessor, cell: *Cell) void {
        if (cell.state == .waiting) self.leaveWaiting(cell);
        cell.state = .verdict_pending;
        cell.verdict = .ignore;
    }
    pub fn dropQueued(self: *GossipProcessor) void {
        for (self.cells) |*cell| switch (cell.state) {
            .needs_check, .checking, .waiting, .queued => {
                self.ignore(cell);
            },
            else => {},
        };
    }
    pub fn finish(self: *GossipProcessor, batch: *const Batch, success: bool) void {
        for (batch.tokens[0..batch.len]) |token| {
            const cell = self.get(token).?;
            assert(cell.state == .copying);
            cell.state = if (success) .delivered else .queued;
            if (!success) self.releaseExecution(cell);
            if (success) {
                self.diag.messagesCopied +|= 1;
                self.diag.bytesCopied +|= cell.input.len;
                self.releasePayload(cell);
            }
            if (cell.retired and (!success or self.limits == null or self.closed)) self.retire(token);
        }
    }
    pub fn report(self: *GossipProcessor, token: Token, verdict: native.Verdict, now: u64) bool {
        self.expire(now);
        if (self.get(token)) |cell| if (cell.state == .delivered) {
            if (cell.retired) {
                self.retire(token);
                return false;
            }
            cell.verdict = verdict;
            cell.state = .verdict_pending;
            self.diag.reportsAccepted +|= 1;
            return true;
        };
        self.diag.staleReports +|= 1;
        return false;
    }
    pub fn outcome(self: *GossipProcessor, result: native.ReportOutcome) void {
        switch (result) {
            .applied => |verdict| switch (verdict) {
                .accept => self.diag.reportsAppliedAccept +|= 1,
                .reject => self.diag.reportsAppliedReject +|= 1,
                .ignore => self.diag.reportsAppliedIgnore +|= 1,
            },
            .already_resolved => self.diag.reportsAlreadyResolved +|= 1,
            .expired => self.diag.reportsExpired +|= 1,
            .stale_handle => self.diag.reportsStale +|= 1,
        }
    }
    pub fn waitLimit(self: *const GossipProcessor, now: u64, limit: u64) u64 {
        var result = if (self.batch_due) |due| @min(limit, due -| now) else limit;
        for (self.cells) |*cell| {
            if (cell.retired or cell.state == .free or cell.state == .capturing) continue;
            if (cell.state == .verdict_pending) return 0;
            result = @min(result, cell.deadline -| now);
        }
        return result;
    }
    pub fn snapshot(self: *const GossipProcessor) Diagnostics {
        var result = self.diag;
        for (self.cells) |*cell| {
            result.waiting += @intFromBool(cell.state == .waiting);
            result.checking += @intFromBool(cell.state == .checking or cell.state == .needs_check);
            result.executing += @intFromBool(cell.executing);
            result.queued += @intFromBool(cell.state == .queued and !cell.retired);
            result.pendingVerdicts += @intFromBool(cell.state == .verdict_pending);
            result.payloadBytes += cell.input.len;
            if (cell.state == .copying) result.copyingBytes += cell.input.len;
        }
        return result;
    }
};

test {
    _ = metadata_mod;
    _ = @import("root_test.zig");
}
