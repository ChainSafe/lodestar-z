const std = @import("std");
const n = @import("network");
const native = n.gossipsub;
const Runtime = @import("network_runtime.zig").Runtime;
const Budget = @import("network_incoming.zig").Budget;
const assert = std.debug.assert;
pub const batch_max = 64;
pub const batch_bytes = 16 * 1024 * 1024;
pub const payload_max = 10 * 1024 * 1024;
pub const topic_max = native.topic.topic_max_len;
pub const Token = struct { index: u16, generation: u64 };
pub const State = enum { free, capturing, queued, copying, delivered, verdict_pending };
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    order: u64 = 0,
    handle: native.ValidationHandle = undefined,
    identity: n.PeerId = undefined,
    connection: n.quic.engine.Handle = undefined,
    id: native.MessageId = undefined,
    topic: [topic_max]u8 = undefined,
    topic_len: u16 = 0,
    deadline: u64 = 0,
    received_at: u64 = 0,
    input: []u8 = &.{},
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
    publicationCopies: u64 = 0,
    publicationBytesCopied: u64 = 0,
    publicationQueued: u64 = 0,
    publicationPressured: u64 = 0,
    publicationSelected: u64 = 0,
    publicationUnavailable: u64 = 0,
    publicationDuplicates: u64 = 0,
};
pub const Batch = struct { tokens: [batch_max]Token = undefined, len: usize = 0 };
pub const Table = struct {
    cells: []Cell,
    backing: std.mem.Allocator,
    budget: *Budget,
    diag: Diagnostics = .{},
    order: u64 = 0,
    cursor: usize = 0,

    pub fn init(backing: std.mem.Allocator, capacity: usize, budget: *Budget) !Table {
        assert(capacity > 0 and capacity <= 1024);
        const cells = try backing.alloc(Cell, capacity);
        @memset(cells, .{});
        return .{ .cells = cells, .backing = backing, .budget = budget, .diag = .{ .capacity = capacity } };
    }
    pub fn deinit(self: *Table) void {
        assert(self.diag.occupied == 0 and self.diag.reservedBytes == 0);
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
    pub fn reserve(self: *Table, len: usize) !Token {
        assert(len <= payload_max);
        const amount = try std.math.mul(usize, len, 2);
        var selected: ?Token = null;
        for (self.cells, 0..) |cell, i| {
            if (cell.state != .free or cell.generation == std.math.maxInt(u64)) continue;
            selected = .{ .index = @intCast(i), .generation = cell.generation + 1 };
            break;
        }
        const token = selected orelse {
            self.diag.capacityRefusals +|= 1;
            return error.NetworkGossipFull;
        };
        const order = try std.math.add(u64, self.order, 1);
        self.reserveBytes(amount) catch |err| {
            self.diag.byteRefusals +|= 1;
            return err;
        };
        self.order = order;
        self.cells[token.index] = .{ .state = .capturing, .generation = token.generation, .order = order, .reservation = amount };
        self.diag.occupied += 1;
        self.diag.highWater = @max(self.diag.highWater, self.diag.occupied);
        return token;
    }
    fn reserveBytes(self: *Table, amount: usize) !void {
        try self.budget.reserve(amount);
        self.diag.reservedBytes += amount;
        self.diag.reservedBytesHighWater = @max(self.diag.reservedBytesHighWater, self.diag.reservedBytes);
    }
    fn releaseBytes(self: *Table, amount: usize) void {
        self.budget.release(amount);
        self.diag.reservedBytes -= amount;
    }
    pub fn reservePublication(self: *Table, amount: usize) !void {
        try self.reserveBytes(amount);
        self.diag.publicationBytes += amount;
        self.diag.publicationBytesHighWater = @max(self.diag.publicationBytesHighWater, self.diag.publicationBytes);
    }
    pub fn releasePublication(self: *Table, amount: usize) void {
        self.releaseBytes(amount);
        self.diag.publicationBytes -= amount;
    }
    pub fn allocate(self: *Table, token: Token, input: []const u8) !void {
        self.install(token, try self.backing.dupe(u8, input));
    }
    pub fn install(self: *Table, token: Token, copy: []u8) void {
        const cell = self.get(token).?;
        assert(cell.state == .capturing and cell.reservation == copy.len * 2);
        cell.input = copy;
        cell.state = .queued;
    }
    fn releasePayload(self: *Table, cell: *Cell) void {
        self.backing.free(cell.input);
        cell.input = &.{};
        self.releaseBytes(cell.reservation);
        cell.reservation = 0;
    }
    pub fn retire(self: *Table, token: Token) void {
        const cell = self.get(token).?;
        assert(cell.state != .copying);
        self.releasePayload(cell);
        cell.* = .{ .generation = cell.generation };
        self.diag.occupied -= 1;
    }
    pub fn oldest(self: *const Table) ?Token {
        var selected: ?Token = null;
        var order: u64 = std.math.maxInt(u64);
        for (self.cells, 0..) |cell, i| {
            if (cell.state != .queued or cell.retired) continue;
            if (selected == null or cell.order < order) {
                selected = .{ .index = @intCast(i), .generation = cell.generation };
                order = cell.order;
            }
        }
        return selected;
    }
    pub fn expire(self: *Table, now: u64) void {
        for (self.cells, 0..) |*cell, i| {
            if (cell.state == .free or cell.state == .capturing or cell.retired or now < cell.deadline) continue;
            if (cell.state == .queued or cell.state == .copying) self.diag.queuedExpired +|= 1 else self.diag.deliveredExpired +|= 1;
            cell.retired = true;
            if (cell.state != .copying) self.retire(.{ .index = @intCast(i), .generation = cell.generation });
        }
    }
    pub fn close(self: *Table) void {
        for (self.cells, 0..) |*cell, i| {
            if (cell.state == .free) continue;
            cell.retired = true;
            if (cell.state != .copying and cell.state != .capturing) self.retire(.{ .index = @intCast(i), .generation = cell.generation });
        }
    }
    pub fn claim(self: *Table, now: u64) Batch {
        self.expire(now);
        var batch: Batch = .{};
        var size: usize = 0;
        for (0..batch_max) |_| {
            const token = self.oldest() orelse break;
            const cell = self.get(token).?;
            if (cell.input.len > batch_bytes - size) break;
            size += cell.input.len;
            cell.state = .copying;
            batch.tokens[batch.len] = token;
            batch.len += 1;
        }
        return batch;
    }
    pub fn finish(self: *Table, batch: *const Batch, success: bool) void {
        for (batch.tokens[0..batch.len]) |token| {
            const cell = self.get(token).?;
            assert(cell.state == .copying);
            cell.state = if (success) .delivered else .queued;
            if (success) {
                self.diag.messagesCopied +|= 1;
                self.diag.bytesCopied +|= cell.input.len;
                self.releasePayload(cell);
            }
            if (cell.retired) self.retire(token);
        }
    }
    pub fn report(self: *Table, token: Token, verdict: native.Verdict, now: u64) bool {
        self.expire(now);
        if (self.get(token)) |cell| if (cell.state == .delivered and !cell.retired) {
            cell.verdict = verdict;
            cell.state = .verdict_pending;
            self.diag.reportsAccepted +|= 1;
            return true;
        };
        self.diag.staleReports +|= 1;
        return false;
    }
    pub fn outcome(self: *Table, result: native.ReportOutcome) void {
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
    pub fn waitLimit(self: *const Table, now: u64, limit: u64) u64 {
        var result = limit;
        for (self.cells) |cell| {
            if (cell.retired or cell.state == .free or cell.state == .capturing) continue;
            if (cell.state == .verdict_pending) return 0;
            result = @min(result, cell.deadline -| now);
        }
        return result;
    }
    pub fn snapshot(self: *const Table) Diagnostics {
        var result = self.diag;
        for (self.cells) |cell| {
            result.queued += @intFromBool(cell.state == .queued and !cell.retired);
            result.pendingVerdicts += @intFromBool(cell.state == .verdict_pending);
            result.payloadBytes += cell.input.len;
            if (cell.state == .copying) result.copyingBytes += cell.input.len;
        }
        return result;
    }
};
pub const Clock = struct { mono_ms: u64, unix_ms: u64 };
pub fn sample(io: std.Io) !Clock {
    const mono = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const wall = std.Io.Timestamp.now(io, .real).toMilliseconds();
    if (mono < 0 or mono > std.math.maxInt(u64) or wall < 0 or wall > 9007199254740991) return error.InvalidNetworkClock;
    return .{ .mono_ms = @intCast(mono), .unix_ms = @intCast(wall) };
}
pub fn monotonic() !u64 {
    const value = std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .awake).toMilliseconds();
    if (value < 0 or value > std.math.maxInt(u64)) return error.InvalidNetworkClock;
    return @intCast(value);
}
pub fn projectWall(admitted: u64, clock: Clock) !u64 {
    if (admitted > clock.mono_ms) return error.InvalidNetworkClock;
    const elapsed = clock.mono_ms - admitted;
    if (elapsed > clock.unix_ms or clock.unix_ms > 9007199254740991) return error.InvalidNetworkClock;
    return clock.unix_ms - elapsed;
}
pub fn flags(runtime: *Runtime, io: std.Io) !void {
    runtime.lock();
    defer runtime.unlock();
    const table = if (runtime.gossip) |*table| table else return;
    const clock = try sample(io);
    const now: n.Now = .{ .mono_ms = clock.mono_ms, .unix_s = @intCast(clock.unix_ms / 1000) };
    var applied: usize = 0;
    for (0..table.cells.len) |_| {
        const i = table.cursor;
        table.cursor = (i + 1) % table.cells.len;
        const cell = &table.cells[i];
        if (cell.state != .verdict_pending) continue;
        const result = runtime.heavy.?.core.reportValidation(cell.handle, cell.verdict, now);
        table.outcome(result);
        if (now.mono_ms >= cell.deadline) table.diag.deliveredExpired +|= 1;
        table.retire(.{ .index = @intCast(i), .generation = cell.generation });
        applied += 1;
        if (applied == batch_max) break;
    }
    table.expire(now.mono_ms);
}
pub fn capture(runtime: *Runtime, events: []const native.Event, clock: Clock) !void {
    const table = if (runtime.gossip) |*table| table else return;
    const now: n.Now = .{ .mono_ms = clock.mono_ms, .unix_s = @intCast(clock.unix_ms / 1000) };
    for (events) |event| {
        if (event != .message) continue;
        const message = event.message;
        const received_at = try projectWall(message.admitted_ms, clock);
        runtime.lock();
        const token = table.reserve(message.bytes.len) catch |err| {
            switch (err) {
                error.NetworkGossipFull, error.NetworkBridgeFull => {},
                else => {
                    runtime.unlock();
                    return err;
                },
            }
            table.outcome(runtime.heavy.?.core.reportValidation(message.handle, .ignore, now));
            runtime.unlock();
            continue;
        };
        const cell = table.get(token).?;
        cell.handle = message.handle;
        cell.identity = message.identity;
        cell.connection = message.peer;
        cell.id = message.id;
        assert(message.topic.len <= topic_max);
        @memcpy(cell.topic[0..message.topic.len], message.topic);
        cell.topic_len = @intCast(message.topic.len);
        cell.deadline = message.deadline;
        cell.received_at = received_at;
        runtime.unlock();
        const copy = table.backing.dupe(u8, message.bytes) catch |err| {
            runtime.lock();
            table.retire(token);
            table.outcome(runtime.heavy.?.core.reportValidation(message.handle, .ignore, now));
            runtime.unlock();
            return err;
        };
        runtime.lock();
        const empty = table.oldest() == null;
        table.install(token, copy);
        if (runtime.stop) table.retire(token) else {
            table.expire(clock.mono_ms);
            if (empty and table.oldest() != null) runtime.pingLocked();
        }
        runtime.unlock();
    }
}
pub fn closeLocked(runtime: *Runtime) void {
    if (runtime.gossip) |*table| table.close();
}
pub fn releasePublicationLocked(runtime: *Runtime, input: *@import("network_commands.zig").Input) void {
    if (input.command != .publishGossip) return;
    @import("network_runtime.zig").allocator.free(input.publication);
    input.publication = &.{};
    runtime.gossip.?.releasePublication(input.publication_reservation);
    input.publication_reservation = 0;
}
pub fn published(runtime: *Runtime, result: native.Gossipsub.PublishOutcome) void {
    const diag = &runtime.gossip.?.diag;
    diag.publicationQueued +|= result.queued;
    diag.publicationPressured +|= result.pressured;
    diag.publicationSelected +|= result.selected;
    diag.publicationUnavailable +|= result.unavailable;
    diag.publicationDuplicates +|= @intFromBool(result.duplicate);
}
test {
    _ = @import("network_gossip_test.zig");
}
