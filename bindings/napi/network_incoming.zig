const std = @import("std");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const rr = n.reqresp;
const Runtime = @import("network_runtime.zig").Runtime;

pub const Budget = struct {
    limit: usize = 0,
    used: usize = 0,

    pub fn reserve(self: *Budget, amount: usize) !void {
        std.debug.assert(self.used <= self.limit);
        if (amount > self.limit - self.used) return error.NetworkBridgeFull;
        self.used += amount;
    }
    pub fn release(self: *Budget, amount: usize) void {
        std.debug.assert(amount <= self.used);
        self.used -= amount;
    }
};
pub const Token = struct { index: u8, generation: u64 };
pub const State = enum { free, queued, copying, serving, response_preparing, response_queued, response_native, terminal };
pub const Failure = enum { timeout, host_timeout, quota_timeout, cancelled, connection_closed, stream_closed, transport };
pub const Terminal = union(enum) { served, failed: Failure, closed };
pub const Rejection = enum { invalid_context, unknown_fork, chunk_too_large, chunk_too_small, too_many_chunks, invalid_error };
pub const Ack = union(enum) { sent, rejected: Rejection, failed: Failure, closed };
pub const Action = enum { none, finish, fail, cancel, submitted };
pub const ResultRefs = [9]?napi.Ref;
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    sequence: u64 = 0,
    identity: n.PeerId = undefined,
    connection: n.quic.engine.Handle = undefined,
    handle: rr.RequestHandle = undefined,
    native: bool = false,
    protocol: rr.Protocol = .blocks_by_root_v2,
    input: []u8 = &.{},
    response: []u8 = &.{},
    reservation: usize = 0,
    context: ?rr.ForkEntry = null,
    copying: bool = false,
    exposed: bool = false,
    closed: ?napi.Deferred = null,
    results: ResultRefs = @splat(null),
    next_results: ResultRefs = @splat(null),
    pending: ?napi.Deferred = null,
    ack: ?Ack = null,
    terminal: ?Terminal = null,
    chunks: u32 = 0,
    action: Action = .none,
    error_status: u8 = 0,
    error_message: [256]u8 = undefined,
    error_len: u16 = 0,
};
pub const Diagnostics = struct {
    capacity: usize = 0,
    occupied: usize = 0,
    queued: usize = 0,
    highWater: usize = 0,
    pendingResponses: usize = 0,
    closedPromises: usize = 0,
    reservedBytes: usize = 0,
    reservedBytesHighWater: usize = 0,
    requestBytes: usize = 0,
    responseBytes: usize = 0,
    copyingBytes: usize = 0,
    requestsTaken: u64 = 0,
    requestBytesCopied: u64 = 0,
    responseBytesCopied: u64 = 0,
    chunksWritten: u64 = 0,
    bytesWritten: u64 = 0,
    capacityRefusals: u64 = 0,
    byteRefusals: u64 = 0,
    busyResponses: u64 = 0,
};
pub const Table = struct {
    cells: []Cell,
    backing: std.mem.Allocator,
    budget: *Budget,
    diag: Diagnostics = .{},
    sequence: u64 = 0,
    cursor: usize = 0,

    pub fn init(backing: std.mem.Allocator, capacity: usize, budget: *Budget) !Table {
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
    pub fn reserve(self: *Table, protocol: rr.Protocol, len: usize) !Token {
        std.debug.assert(len >= protocol.info().request_min and len <= protocol.info().request_max);
        const amount = try std.math.add(usize, try std.math.mul(usize, len, 2), protocol.info().response_max);
        var selected: ?Token = null;
        for (self.cells, 0..) |cell, i| {
            if (cell.state != .free or cell.generation == std.math.maxInt(u64)) continue;
            selected = .{ .index = @intCast(i), .generation = cell.generation + 1 };
            break;
        }
        const token = selected orelse {
            self.diag.capacityRefusals +|= 1;
            return error.NetworkIncomingFull;
        };
        if (self.sequence == std.math.maxInt(u64)) return error.IncomingSequenceExhausted;
        self.budget.reserve(amount) catch |err| {
            self.diag.byteRefusals +|= 1;
            return err;
        };
        self.sequence += 1;
        self.cells[token.index] = .{ .state = .queued, .generation = token.generation, .sequence = self.sequence, .protocol = protocol, .reservation = amount };
        self.diag.occupied += 1;
        self.diag.highWater = @max(self.diag.highWater, self.diag.occupied);
        self.diag.reservedBytes += amount;
        self.diag.reservedBytesHighWater = @max(self.diag.reservedBytesHighWater, self.diag.reservedBytes);
        return token;
    }
    pub fn allocate(self: *Table, token: Token, input: []const u8) !void {
        const cell = self.get(token).?;
        std.debug.assert(cell.state == .queued and cell.input.len == 0);
        cell.input = try self.backing.dupe(u8, input);
    }
    fn refund(self: *Table, cell: *Cell, amount: usize) void {
        self.budget.release(amount);
        self.diag.reservedBytes -= amount;
        cell.reservation -= amount;
    }
    pub fn releaseInput(self: *Table, cell: *Cell) void {
        const amount = cell.input.len * 2;
        self.backing.free(cell.input);
        cell.input = &.{};
        self.refund(cell, amount);
    }
    pub fn releaseResponse(self: *Table, cell: *Cell) void {
        self.backing.free(cell.response);
        cell.response = &.{};
    }
    pub fn releasePayload(self: *Table, cell: *Cell) void {
        if (cell.native or cell.copying or cell.state == .response_preparing) return;
        self.releaseInput(cell);
        self.releaseResponse(cell);
        self.refund(cell, cell.reservation);
    }
    pub fn retire(self: *Table, token: Token) void {
        const cell = self.get(token).?;
        std.debug.assert(!cell.native and !cell.copying);
        for (cell.results) |ref| std.debug.assert(ref == null);
        for (cell.next_results) |ref| std.debug.assert(ref == null);
        cell.state = .terminal;
        self.releasePayload(cell);
        cell.* = .{ .generation = cell.generation };
        self.diag.occupied -= 1;
    }
    pub fn oldest(self: *Table) ?Token {
        var selected: ?Token = null;
        var sequence: u64 = std.math.maxInt(u64);
        for (self.cells, 0..) |cell, i| {
            if (cell.state != .queued or cell.terminal != null) continue;
            if (selected == null or cell.sequence < sequence) {
                selected = .{ .index = @intCast(i), .generation = cell.generation };
                sequence = cell.sequence;
            }
        }
        return selected;
    }
    pub fn snapshot(self: *const Table) Diagnostics {
        var result = self.diag;
        for (self.cells) |*cell| {
            if (cell.state == .free) continue;
            result.queued += @intFromBool(cell.state == .queued);
            result.closedPromises += @intFromBool(cell.closed != null);
            result.pendingResponses += @intFromBool(cell.pending != null);
            result.requestBytes += cell.input.len;
            if (cell.state != .response_preparing) result.responseBytes += cell.response.len;
            if (cell.copying) result.copyingBytes += cell.input.len;
        }
        return result;
    }
    pub fn obligated(self: *const Table) bool {
        for (self.cells) |cell| if (cell.closed != null or cell.pending != null) return true;
        return false;
    }
};

fn rejection(err: anyerror) !Rejection {
    return switch (err) {
        error.InvalidContext => .invalid_context,
        error.UnknownFork => .unknown_fork,
        error.ChunkTooLarge => .chunk_too_large,
        error.ChunkTooSmall => .chunk_too_small,
        error.TooManyChunks => .too_many_chunks,
        error.InvalidError => .invalid_error,
        else => err,
    };
}
fn failure(reason: rr.Failure) !Failure {
    return switch (reason) {
        .timeout => .timeout,
        .host_timeout => .host_timeout,
        .quota_timeout => .quota_timeout,
        .cancelled => .cancelled,
        .connection_closed => .connection_closed,
        .stream_closed => .stream_closed,
        .transport => .transport,
        else => error.InvalidIncomingFailure,
    };
}
pub fn awaitingTerminal(owner: *rr.ReqResp, handle: rr.RequestHandle, err: anyerror) bool {
    if (err != error.Busy or handle.direction != .inbound) return false;
    const slot = owner.inboundSlot(handle) orelse return false;
    return slot.terminal != null;
}
pub fn flags(runtime: *Runtime, now: n.Now) !void {
    runtime.lock();
    defer runtime.unlock();
    const table = if (runtime.incoming) |*table| table else return;
    if (table.cells.len == 0) return;
    @import("network_incoming_faults.zig").turnLocked(runtime, now);
    var submissions: usize = 0;
    for (0..table.cells.len) |offset| {
        const cell = &table.cells[(table.cursor + offset) % table.cells.len];
        if (!cell.native) continue;
        const core = &runtime.heavy.?.core;
        if (cell.action == .cancel or runtime.stop) {
            _ = core.cancel(cell.handle);
            continue;
        }
        if (cell.state == .response_queued and submissions < 4) {
            submissions += 1;
            core.respond(cell.handle, cell.response, cell.context, now) catch |err| {
                if (awaitingTerminal(&core.core.service.reqresp.inner, cell.handle, err)) continue;
                cell.ack = .{ .rejected = try rejection(err) };
                table.releaseResponse(cell);
                cell.state = .serving;
                runtime.pingLocked();
                continue;
            };
            cell.state = .response_native;
            @import("network_incoming_faults.zig").responseLocked(runtime, cell);
        }
        switch (cell.action) {
            .finish => if (core.finish(cell.handle, now)) {
                cell.action = .submitted;
            },
            .fail => {
                core.respondError(cell.handle, cell.error_status, cell.error_message[0..cell.error_len], now) catch |err| {
                    if (awaitingTerminal(&core.core.service.reqresp.inner, cell.handle, err)) continue;
                    return err;
                };
                cell.action = .submitted;
            },
            else => {},
        }
    }
    table.cursor = (table.cursor + 4) % table.cells.len;
}
pub fn captureLocked(runtime: *Runtime, event: rr.Event, now: n.Now) !void {
    const table = if (runtime.incoming) |*table| table else return;
    if (event == .request) return admitLocked(runtime, event.request, now);
    const handle = switch (event) {
        .chunk_sent => |e| e.request,
        .served => |e| e.request,
        .failed => |e| e.request,
        else => return,
    };
    if (handle.direction != .inbound) return;
    for (table.cells, 0..) |*cell, i| {
        if (cell.state == .free or !cell.native or !std.meta.eql(cell.handle, handle)) continue;
        switch (event) {
            .chunk_sent => |sent| {
                if (cell.state != .response_native) return error.InvalidIncomingAcknowledgement;
                if (sent.chunks != cell.chunks + 1) return error.InvalidIncomingAcknowledgement;
                cell.chunks = sent.chunks;
                cell.ack = .sent;
                @import("network_incoming_faults.zig").ackLocked(runtime, cell);
                table.diag.chunksWritten +|= 1;
                table.diag.bytesWritten +|= cell.response.len;
                table.releaseResponse(cell);
                cell.state = .serving;
            },
            .served => |served| {
                if (served.chunks != cell.chunks) return error.InvalidIncomingAcknowledgement;
                cell.terminal = .served;
                cell.native = false;
            },
            .failed => |failed| {
                cell.terminal = .{ .failed = try failure(failed.reason) };
                cell.native = false;
            },
            else => unreachable,
        }
        if (!cell.native) {
            if (runtime.stop) cell.terminal = .closed;
            if (cell.pending != null and cell.ack == null) cell.ack = if (cell.terminal.? == .closed) .closed else .{ .failed = cell.terminal.?.failed };
            if (cell.state != .response_preparing) cell.state = .terminal;
            table.releasePayload(cell);
            if (!cell.exposed and !cell.copying) table.retire(.{ .index = @intCast(i), .generation = cell.generation });
        }
        runtime.pingLocked();
        break;
    }
}
fn admitLocked(runtime: *Runtime, request: @FieldType(rr.Event, "request"), now: n.Now) !void {
    const table = &runtime.incoming.?;
    const core = &runtime.heavy.?.core;
    const identity = core.transport.engine.peerId(request.peer) orelse {
        _ = core.cancel(request.request);
        return;
    };
    const token = table.reserve(request.protocol, request.bytes.len) catch |err| switch (err) {
        error.NetworkIncomingFull, error.NetworkBridgeFull => {
            core.respondError(request.request, 2, "application capacity exhausted", now) catch {
                _ = core.cancel(request.request);
            };
            return;
        },
        else => return err,
    };
    errdefer table.retire(token);
    try @import("network_faults.zig").check(.incoming_input);
    try table.allocate(token, request.bytes);
    const cell = table.get(token).?;
    cell.identity = identity;
    cell.connection = request.peer;
    cell.handle = request.request;
    cell.native = true;
    runtime.pingLocked();
}
pub fn closeLocked(runtime: *Runtime) void {
    if (runtime.incoming) |*table| for (table.cells, 0..) |*cell, i| {
        if (cell.state == .free) continue;
        cell.native = false;
        if (cell.terminal == null) cell.terminal = .closed;
        if (cell.pending != null and cell.ack == null) cell.ack = .closed;
        if (cell.state != .response_preparing) cell.state = .terminal;
        table.releasePayload(cell);
        if (!cell.exposed and !cell.copying) table.retire(.{ .index = @intCast(i), .generation = cell.generation });
    };
}
test {
    _ = @import("network_incoming_test.zig");
}
