const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const rr = n.reqresp;
pub fn forkLabel(fork: ?@FieldType(rr.ForkEntry, "fork")) ?[]const u8 {
    return if (fork) |value| @tagName(value) else null;
}

test "request fork projection retains the context-free nullable representation" {
    try std.testing.expect(forkLabel(null) == null);
    try std.testing.expectEqualStrings("deneb", forkLabel(.deneb).?);
    try std.testing.expectEqualStrings("fulu", forkLabel(.fulu).?);
}

pub const Token = struct { index: u8, generation: u64 };
pub const State = enum { free, preparing, queued, native, terminal };
pub const Terminal = union(enum) {
    done,
    closed,
    rejected: Rejection,
    failed: struct { reason: rr.Failure, phase: ?rr.reqresp.RequestPhase },
};
pub const Rejection = enum { disconnected, protocol_disabled, invalid_request, invalid_request_options, too_many_requests, slots_exhausted, negotiation_table_full, transport };
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    peer: n.PeerId = undefined,
    peer_ref: ?n.peers.types.PeerRef = null,
    connection: ?n.quic.engine.Handle = null,
    protocol: rr.Protocol = .blocks_by_root_v2,
    options: rr.RequestOptions = .{},
    input: []u8 = &.{},
    sink: []u8 = &.{},
    reservation: usize = 0,
    native: ?rr.RequestHandle = null,
    terminal: ?Terminal = null,
    chunk: ?struct { len: usize, fork: ?@FieldType(rr.ForkEntry, "fork") } = null,
    delivered: bool = false,
    copying: bool = false,
    consume: bool = false,
    cancel: bool = false,
    retiring: bool = false,
    abandoned: bool = false,
    peer_message: [rr.codec.error_message_max]u8 = undefined,
    peer_message_len: u16 = 0,
    pull: ?napi.Deferred = null,
    retirement: ?napi.Deferred = null,
};
pub const Diagnostics = struct {
    capacity: usize = 0,
    occupied: usize = 0,
    highWater: usize = 0,
    pendingPulls: usize = 0,
    terminalCells: usize = 0,
    reservedBytes: usize = 0,
    reservedBytesHighWater: usize = 0,
    inputBytes: usize = 0,
    sinkBytes: usize = 0,
    copyingBytes: usize = 0,
    chunksCopied: u64 = 0,
    bytesCopied: u64 = 0,
    requestFull: u64 = 0,
    commandFull: u64 = 0,
    bridgeFull: u64 = 0,
    busyPulls: u64 = 0,
};
pub const Table = struct {
    cells: []Cell = &.{},
    backing: std.mem.Allocator,
    budget: usize,
    diag: Diagnostics = .{},

    pub fn init(backing: std.mem.Allocator, capacity: usize, budget: usize) !Table {
        std.debug.assert(capacity <= 32);
        const cells = try backing.alloc(Cell, capacity);
        @memset(cells, .{});
        return .{ .cells = cells, .backing = backing, .budget = budget, .diag = .{ .capacity = capacity } };
    }
    pub fn deinit(self: *Table) void {
        std.debug.assert(self.diag.occupied == 0);
        self.backing.free(self.cells);
    }
    pub fn get(self: *Table, token: Token) ?*Cell {
        if (token.index >= self.cells.len) return null;
        const cell = &self.cells[token.index];
        return if (cell.state != .free and cell.generation == token.generation) cell else null;
    }
    pub fn reserve(self: *Table, which: rr.Protocol, len: usize) !Token {
        const copies = try std.math.mul(usize, which.info().response_max, 2);
        const amount = try std.math.add(usize, len, copies);
        var selected: ?Token = null;
        for (self.cells, 0..) |*cell, i| {
            if (cell.state != .free or cell.generation == std.math.maxInt(u64)) continue;
            selected = .{ .index = @intCast(i), .generation = cell.generation + 1 };
            break;
        }
        const token = selected orelse {
            self.diag.requestFull +|= 1;
            return error.NetworkRequestFull;
        };
        if (amount > self.budget - self.diag.reservedBytes) {
            self.diag.bridgeFull +|= 1;
            return error.NetworkBridgeFull;
        }
        self.cells[token.index] = .{ .state = .preparing, .generation = token.generation, .protocol = which, .reservation = amount };
        self.diag.occupied += 1;
        self.diag.highWater = @max(self.diag.highWater, self.diag.occupied);
        self.diag.reservedBytes += amount;
        self.diag.reservedBytesHighWater = @max(self.diag.reservedBytesHighWater, self.diag.reservedBytes);
        return token;
    }
    pub fn allocate(self: *Table, token: Token, len: usize) !void {
        const cell = self.get(token).?;
        std.debug.assert(cell.state == .preparing);
        const input = try self.backing.alloc(u8, len);
        errdefer self.backing.free(input);
        const sink = try self.backing.alloc(u8, cell.protocol.info().response_max);
        cell.input = input;
        cell.sink = sink;
    }
    pub fn releasePayload(self: *Table, cell: *Cell) void {
        if (cell.state == .preparing or cell.native != null or cell.copying) return;
        self.backing.free(cell.input);
        cell.input = &.{};
        if (cell.chunk != null) return;
        self.backing.free(cell.sink);
        cell.sink = &.{};
        self.diag.reservedBytes -= cell.reservation;
        cell.reservation = 0;
    }
    pub fn retire(self: *Table, token: Token) void {
        const cell = self.get(token).?;
        std.debug.assert(cell.native == null and !cell.copying);
        cell.state = .terminal;
        cell.chunk = null;
        self.releasePayload(cell);
        cell.state = .free;
        cell.pull = null;
        cell.retirement = null;
        self.diag.occupied -= 1;
    }
    pub fn snapshot(self: *const Table) Diagnostics {
        var result = self.diag;
        for (self.cells) |*cell| {
            if (cell.state == .free) continue;
            result.pendingPulls += @intFromBool(cell.pull != null);
            result.terminalCells += @intFromBool(cell.terminal != null);
            // Preparing storage is private to the JS thread until publication.
            if (cell.state == .preparing) continue;
            result.inputBytes += cell.input.len;
            result.sinkBytes += cell.sink.len;
            if (cell.copying and cell.chunk != null) result.copyingBytes += cell.chunk.?.len;
        }
        return result;
    }
    pub fn obligated(self: *const Table) bool {
        for (self.cells) |*cell| if (cell.pull != null or cell.retirement != null) return true;
        return false;
    }
};

pub fn rejection(err: anyerror) !Rejection {
    return switch (err) {
        error.StalePeer, error.StaleHandle, error.Disconnected => .disconnected,
        error.ProtocolDisabled => .protocol_disabled,
        error.InvalidRequest, error.RequestTooLarge, error.RequestTooSmall => .invalid_request,
        error.InvalidRequestOptions => .invalid_request_options,
        error.TooManyRequests => .too_many_requests,
        error.SlotsExhausted => .slots_exhausted,
        error.NegotiationTableFull => .negotiation_table_full,
        error.Transport, error.Stopped => .transport,
        else => err,
    };
}

const Runtime = @import("network_runtime.zig").Runtime;
pub fn submit(runtime: *Runtime, token: Token, now: n.Now) !void {
    runtime.lock();
    defer runtime.unlock();
    const table = &runtime.requests.?;
    const cell = table.get(token) orelse return error.InvalidRequestHandle;
    if (cell.cancel or runtime.stop) {
        cell.terminal = if (runtime.stop) .closed else .{ .failed = .{ .reason = .cancelled, .phase = null } };
    } else {
        const core = &runtime.heavy.?.core;
        const peer = core.core.catalog.find(&cell.peer);
        if (peer) |ref| {
            cell.peer_ref = ref;
            cell.connection = core.core.catalog.get(ref).?.connection;
            cell.native = core.sendReqRespRequest(ref, cell.protocol, cell.input, cell.sink, cell.options, now) catch |err| blk: {
                cell.terminal = .{ .rejected = try rejection(err) };
                break :blk null;
            };
        } else cell.terminal = .{ .rejected = .disconnected };
    }
    cell.state = if (cell.native != null) .native else .terminal;
    table.releasePayload(cell);
    runtime.pingLocked();
}
pub fn flags(runtime: *Runtime, now: n.Now) void {
    runtime.lock();
    defer runtime.unlock();
    if (runtime.requests) |*table| for (table.cells) |*cell| {
        if (cell.state == .free or cell.state == .preparing or cell.state == .queued or cell.copying) continue;
        if (cell.cancel or runtime.stop) {
            cell.chunk = null;
            if (cell.native) |handle| _ = runtime.heavy.?.core.cancel(handle);
        } else if (cell.consume) {
            cell.consume = false;
            cell.chunk = null;
            cell.delivered = false;
            if (cell.native) |handle| _ = runtime.heavy.?.core.consume(handle, now);
        }
        table.releasePayload(cell);
        if (cell.terminal != null and (cell.pull != null or cell.retiring)) runtime.pingLocked();
    };
}
pub fn capture(runtime: *Runtime, events: []const rr.Event, now: n.Now) !void {
    runtime.lock();
    defer runtime.unlock();
    const core = &runtime.heavy.?.core;
    for (events) |event| {
        switch (event) {
            .request => |incoming| {
                try core.respondError(incoming.request, 2, "application handlers unavailable", now);
                continue;
            },
            .chunk_sent, .served, .over_limit => continue,
            else => {},
        }
        const handle = switch (event) {
            .chunk => |chunk| chunk.request,
            .done => |done| done.request,
            .failed => |failed| failed.request,
            else => unreachable,
        };
        if (handle.direction != .outbound) continue;
        const table = if (runtime.requests) |*table| table else continue;
        for (table.cells) |*cell| {
            if (cell.native == null or !std.meta.eql(cell.native.?, handle)) continue;
            switch (event) {
                .chunk => |chunk| {
                    std.debug.assert(cell.chunk == null and chunk.bytes.ptr == cell.sink.ptr and chunk.bytes.len <= cell.sink.len);
                    if (!cell.cancel and !runtime.stop) cell.chunk = .{ .len = chunk.bytes.len, .fork = chunk.fork };
                },
                .done => {
                    cell.native = null;
                    cell.terminal = .done;
                },
                .failed => |failed| {
                    const message = core.errorMessage(handle);
                    std.debug.assert(message.len <= cell.peer_message.len);
                    @memcpy(cell.peer_message[0..message.len], message);
                    cell.peer_message_len = @intCast(message.len);
                    cell.native = null;
                    cell.terminal = .{ .failed = .{ .reason = failed.reason, .phase = failed.phase } };
                },
                else => unreachable,
            }
            if (runtime.stop) {
                cell.terminal = .closed;
                if (!cell.copying) cell.chunk = null;
            }
            if (cell.native == null) {
                cell.state = .terminal;
                if (cell.delivered and !cell.copying) {
                    cell.chunk = null;
                    cell.delivered = false;
                }
            }
            runtime.requests.?.releasePayload(cell);
            runtime.pingLocked();
            break;
        }
    }
}
pub fn closeLocked(runtime: *Runtime) void {
    if (runtime.requests) |*table| for (table.cells) |*cell| {
        if (cell.state == .free or cell.state == .preparing) continue;
        cell.native = null;
        cell.terminal = .closed;
        cell.state = .terminal;
        if (!cell.copying) cell.chunk = null;
        table.releasePayload(cell);
    };
}

test "request reservations are exact and stale generations cannot release replacements" {
    const protocol = rr.Protocol.blocks_by_root_v2;
    const amount = 32 + 2 * protocol.info().response_max;
    var table = try Table.init(std.testing.allocator, 1, amount);
    defer table.deinit();
    const first = try table.reserve(protocol, 32);
    try table.allocate(first, 32);
    table.get(first).?.state = .queued;
    try std.testing.expectEqual(amount, table.snapshot().reservedBytes);
    try std.testing.expectEqual(@as(usize, 32), table.snapshot().inputBytes);
    try std.testing.expectEqual(protocol.info().response_max, table.snapshot().sinkBytes);
    try std.testing.expectError(error.NetworkRequestFull, table.reserve(protocol, 32));
    table.retire(first);
    const replacement = try table.reserve(protocol, 32);
    try std.testing.expectEqual(first.generation + 1, replacement.generation);
    try std.testing.expect(table.get(first) == null);
    table.retire(replacement);
    table.budget = amount - 1;
    try std.testing.expectError(error.NetworkBridgeFull, table.reserve(protocol, 32));
    try std.testing.expectEqual(@as(usize, 0), table.snapshot().reservedBytes);
    table.cells[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.NetworkRequestFull, table.reserve(protocol, 0));
}

test "request allocation prefixes release through retirement and terminal chunks pin independent sinks" {
    const protocol = rr.Protocol.blocks_by_root_v2;
    const amount = 32 + 2 * protocol.info().response_max;
    for (0..2) |fail_index| {
        var table = try Table.init(std.testing.allocator, 1, amount);
        defer table.deinit();
        const token = try table.reserve(protocol, 32);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        table.backing = failing.allocator();
        try std.testing.expectError(error.OutOfMemory, table.allocate(token, 32));
        table.retire(token);
        table.backing = std.testing.allocator;
        try std.testing.expectEqual(@as(usize, 0), table.snapshot().reservedBytes);
    }
    var table = try Table.init(std.testing.allocator, 1, amount);
    defer table.deinit();
    const token = try table.reserve(protocol, 32);
    try table.allocate(token, 32);
    const cell = table.get(token).?;
    cell.state = .terminal;
    cell.terminal = .done;
    cell.chunk = .{ .len = 4, .fork = null };
    @memcpy(cell.sink[0..4], "held");
    table.releasePayload(cell);
    try std.testing.expectEqual(@as(usize, 0), cell.input.len);
    try std.testing.expectEqualSlices(u8, "held", cell.sink[0..4]);
    cell.copying = true;
    table.releasePayload(cell);
    try std.testing.expectEqual(@as(usize, 4), table.snapshot().copyingBytes);
    cell.copying = false;
    cell.chunk = null;
    table.releasePayload(cell);
    try std.testing.expectEqual(@as(usize, 0), cell.sink.len);
    try std.testing.expectEqual(@as(usize, 0), table.snapshot().reservedBytes);
    try std.testing.expectEqual(@as(usize, 1), table.snapshot().terminalCells);
    table.retire(token);
}
