const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const Runtime = @import("network_runtime.zig").Runtime;
const Budget = @import("network_budget.zig").Budget;
const gossip = n.gossipsub;

pub const capacity_max = 256;
pub const turn_max = 64;
pub const turn_bytes = 2 * 1024 * 1024;
pub const Token = struct { index: u8, generation: u64 };
pub const State = enum { free, preparing, queued, executing, terminal, copying };
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    order: u64 = 0,
    queued_ms: u64 = 0,
    kind: gossip.topic.Kind = .beacon_block,
    topic: [gossip.topic.topic_max_len]u8 = undefined,
    topic_len: u8 = 0,
    options: gossip.Gossipsub.PublishOptions = .{},
    payload: []u8 = &.{},
    reservation: usize = 0,
    deferred: ?napi.Deferred = null,
    outcome: gossip.Gossipsub.PublishOutcome = .{},
    failure: ?anyerror = null,
};
pub const Diagnostics = struct {
    capacity: usize = 0,
    urgentReserved: usize = 0,
    occupied: usize = 0,
    highWater: usize = 0,
    refusals: u64 = 0,
    byteRefusals: u64 = 0,
    reservedBytes: usize = 0,
    reservedBytesHighWater: usize = 0,
    payloadBytes: usize = 0,
    copies: u64 = 0,
    bytesCopied: u64 = 0,
    queued: u64 = 0,
    pressured: u64 = 0,
    selected: u64 = 0,
    unavailable: u64 = 0,
    duplicates: u64 = 0,
    latencyCount: u64 = 0,
    latencyMsP50: u64 = 0,
    latencyMsP99: u64 = 0,
};
pub const Table = struct {
    cells: []Cell,
    backing: std.mem.Allocator,
    budget: *Budget,
    ordinary: usize = 0,
    diag: Diagnostics,
    latency: n.metrics.bridge.PublicationLatency = .{},

    pub fn init(backing: std.mem.Allocator, capacity: usize, budget: *Budget) !Table {
        std.debug.assert(capacity > 0 and capacity <= capacity_max);
        const cells = try backing.alloc(Cell, capacity);
        @memset(cells, .{});
        return .{ .cells = cells, .backing = backing, .budget = budget, .diag = .{
            .capacity = capacity,
            .urgentReserved = @max(1, capacity / 16),
        } };
    }
    pub fn deinit(self: *Table) void {
        std.debug.assert(self.diag.occupied == 0 and self.diag.reservedBytes == 0);
        self.backing.free(self.cells);
    }
    pub fn trim(self: *Table) void {
        if (self.diag.occupied != 0) return;
        self.backing.free(self.cells);
        self.cells = &.{};
    }
    pub fn get(self: *Table, token: Token) ?*Cell {
        if (token.index >= self.cells.len) return null;
        const cell = &self.cells[token.index];
        return if (cell.state != .free and cell.generation == token.generation) cell else null;
    }
    pub fn reserve(self: *Table, kind: gossip.topic.Kind, bytes: usize) !Token {
        if (bytes > self.budget.limit) {
            self.diag.byteRefusals +|= 1;
            return error.ResourceExhausted;
        }
        if (!n.gossip_processor.limits_mod.urgent(kind) and self.ordinary >= self.diag.capacity - self.diag.urgentReserved) {
            self.diag.refusals +|= 1;
            return error.PublicationQueueFull;
        }
        for (self.cells, 0..) |*cell, i| {
            if (cell.state != .free or cell.generation == std.math.maxInt(u64)) continue;
            self.budget.reserve(if (n.gossip_processor.limits_mod.urgent(kind)) .urgent_publication else .publication, bytes) catch |err| {
                self.diag.byteRefusals +|= 1;
                return err;
            };
            cell.* = .{ .state = .preparing, .generation = cell.generation + 1, .kind = kind, .reservation = bytes };
            self.ordinary += @intFromBool(!n.gossip_processor.limits_mod.urgent(kind));
            self.diag.occupied += 1;
            self.diag.highWater = @max(self.diag.highWater, self.diag.occupied);
            self.diag.reservedBytes += bytes;
            self.diag.reservedBytesHighWater = @max(self.diag.reservedBytesHighWater, self.diag.reservedBytes);
            return .{ .index = @intCast(i), .generation = cell.generation };
        }
        self.diag.refusals +|= 1;
        return error.PublicationQueueFull;
    }
    pub fn oldest(self: *Table) ?Token {
        var selected: ?Token = null;
        var order: u64 = std.math.maxInt(u64);
        for (self.cells, 0..) |*cell, i| {
            if (cell.state != .queued or cell.order >= order) continue;
            order = cell.order;
            selected = .{ .index = @intCast(i), .generation = cell.generation };
        }
        return selected;
    }
    pub fn releasePayload(self: *Table, cell: *Cell) void {
        self.backing.free(cell.payload);
        cell.payload = &.{};
        self.budget.release(if (n.gossip_processor.limits_mod.urgent(cell.kind)) .urgent_publication else .publication, cell.reservation);
        self.diag.reservedBytes -= cell.reservation;
        cell.reservation = 0;
    }
    pub fn retire(self: *Table, token: Token) void {
        const cell = self.get(token).?;
        std.debug.assert(cell.state != .executing);
        self.releasePayload(cell);
        self.ordinary -= @intFromBool(!n.gossip_processor.limits_mod.urgent(cell.kind));
        self.diag.occupied -= 1;
        cell.* = .{ .generation = cell.generation };
    }
    pub fn close(self: *Table, failure: anyerror) void {
        for (self.cells) |*cell| {
            std.debug.assert(cell.state != .executing);
            if (cell.state != .queued) continue;
            self.releasePayload(cell);
            cell.failure = failure;
            cell.state = .terminal;
        }
    }
    pub fn obligated(self: *const Table) bool {
        for (self.cells) |*cell| if (cell.deferred != null) return true;
        return false;
    }
    pub fn snapshot(self: *const Table) Diagnostics {
        var result = self.diag;
        for (self.cells) |*cell| {
            if (cell.state != .preparing) result.payloadBytes += cell.payload.len;
        }
        result.latencyCount = self.latency.count;
        result.latencyMsP50 = self.percentile(50);
        result.latencyMsP99 = self.percentile(99);
        return result;
    }
    fn percentile(self: *const Table, percentage: u64) u64 {
        if (self.latency.count == 0) return 0;
        const target = (@as(u128, self.latency.count) * percentage + 99) / 100;
        var count: u64 = 0;
        for (self.latency.buckets, 0..) |value, i| {
            count += value;
            if (count >= target) return @TypeOf(self.latency).bounds[@min(i, @TypeOf(self.latency).bounds.len - 1)];
        }
        unreachable;
    }
};

pub fn execute(runtime: *Runtime, token: Token, now: n.Now) void {
    runtime.lock();
    const table = &runtime.publications.?;
    const cell = table.get(token).?;
    std.debug.assert(cell.state == .queued);
    cell.state = .executing;
    std.debug.assert(now.mono_ms >= cell.queued_ms);
    const latency = now.mono_ms - cell.queued_ms;
    table.latency.observe(latency);
    runtime.unlock();

    const outcome = runtime.heavy.?.core.publishGossipWithOptions(cell.topic[0..cell.topic_len], cell.payload, cell.options, now);
    runtime.lock();
    defer runtime.unlock();
    if (outcome) |result| {
        cell.outcome = result;
        table.diag.queued +|= result.queued;
        table.diag.pressured +|= result.pressured;
        table.diag.selected +|= result.selected;
        table.diag.unavailable +|= result.unavailable;
        table.diag.duplicates +|= @intFromBool(result.duplicate);
    } else |err| cell.failure = err;
    table.releasePayload(cell);
    cell.state = .terminal;
    runtime.pingLocked();
}

test {
    _ = @import("network_publications_test.zig");
}
