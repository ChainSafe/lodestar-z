const std = @import("std");
const builtin = @import("builtin");
const n = @import("network");
const napi = @import("zapi:zapi").napi;
const rr = n.reqresp;
const Runtime = @import("network_runtime.zig").Runtime;

const Budget = @import("network_budget.zig").Budget;
pub const Token = struct { index: u8, generation: u64 };
pub const State = enum { free, queued, copying, serving, response_preparing, response_queued, response_native, terminal };
pub const Failure = enum { timeout, host_timeout, quota_timeout, cancelled, connection_closed, stream_closed, transport };
pub const Rejection = enum { invalid_context, unknown_fork, chunk_too_large, chunk_too_small, too_many_chunks, invalid_error };
pub const Ack = union(enum) { sent, rejected: Rejection, failed: Failure, closed };
pub const Action = enum { none, finish, fail, cancel, submitted };
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    sequence: u64 = 0,
    identity: n.PeerId = undefined,
    connection: n.quic.engine.Handle = undefined,
    handle: rr.RequestHandle = undefined,
    native: bool = false,
    serving_retained: bool = false,
    release_requested: bool = false,
    protocol: rr.Protocol = .blocks_by_root_v2,
    input: []u8 = &.{},
    response: []u8 = &.{},
    reservation: usize = 0,
    response_reservation: usize = 0,
    context: ?rr.ForkEntry = null,
    copying: bool = false,
    exposed: bool = false,
    /// Deliveries of this start that rolled back.
    rollbacks: u8 = 0,
    closed: ?napi.Deferred = null,
    pending: ?napi.Deferred = null,
    permission: ?napi.Deferred = null,
    permission_ready: bool = false,
    ack: ?Ack = null,
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
    pendingPermissions: usize = 0,
    closedPromises: usize = 0,
    reservedBytes: usize = 0,
    reservedBytesHighWater: usize = 0,
    requestBytes: usize = 0,
    responseBytes: usize = 0,
    copyingBytes: usize = 0,
    requestsTaken: u64 = 0,
    responseBytesCopied: u64 = 0,
    chunksWritten: u64 = 0,
    bytesWritten: u64 = 0,
    retiring: usize = 0,
    capacityRefusals: u64 = 0,
    byteRefusals: u64 = 0,
};
pub const capacity_max = 32;
pub const Table = struct {
    cells: []Cell,
    /// The cells whose settlement is due now. `refresh` keeps it current after each change to a cell.
    due: std.StaticBitSet(capacity_max) = .initEmpty(),
    /// Past the last settled cell, where settlement resumes, so refilled low cells cannot starve higher ones.
    settle_cursor: usize = 0,
    backing: std.mem.Allocator,
    budget: *Budget,
    diag: Diagnostics = .{},
    sequence: u64 = 0,
    cursor: usize = 0,

    pub fn init(backing: std.mem.Allocator, capacity: usize, budget: *Budget) !Table {
        std.debug.assert(capacity <= capacity_max);
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
        const amount = try std.math.mul(usize, len, 2);
        var selected: ?Token = null;
        for (self.cells, 0..) |*cell, i| {
            if (cell.state != .free or cell.generation == std.math.maxInt(u64)) continue;
            selected = .{ .index = @intCast(i), .generation = cell.generation + 1 };
            break;
        }
        const token = selected orelse {
            self.diag.capacityRefusals +|= 1;
            return error.NetworkIncomingFull;
        };
        if (self.sequence == std.math.maxInt(u64)) return error.IncomingSequenceExhausted;
        self.budget.reserve(.incoming, amount) catch |err| {
            self.diag.byteRefusals +|= 1;
            return err;
        };
        self.sequence += 1;
        self.cells[token.index] = .{ .state = .queued, .generation = token.generation, .sequence = self.sequence, .protocol = protocol, .reservation = amount };
        self.refresh(&self.cells[token.index]);
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
        self.budget.release(.incoming, amount);
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
        self.refund(cell, cell.response_reservation);
        cell.response_reservation = 0;
    }
    pub fn reserveResponse(self: *Table, cell: *Cell, len: usize) !void {
        std.debug.assert(len <= cell.protocol.info().response_max);
        if (len <= cell.response_reservation) {
            self.refund(cell, cell.response_reservation - len);
            cell.response_reservation = len;
            return;
        }
        const amount = len - cell.response_reservation;
        try self.budget.reserve(.incoming, amount);
        cell.response_reservation = len;
        cell.reservation += amount;
        self.diag.reservedBytes += amount;
        self.diag.reservedBytesHighWater = @max(self.diag.reservedBytesHighWater, self.diag.reservedBytes);
    }
    pub fn releasePayload(self: *Table, cell: *Cell) void {
        if (cell.native or cell.copying or cell.state == .response_preparing) return;
        self.releaseInput(cell);
        self.releaseResponse(cell);
        self.refund(cell, cell.reservation);
    }
    pub fn retire(self: *Table, token: Token) void {
        const cell = self.get(token).?;
        std.debug.assert(!cell.native and !cell.copying and !cell.serving_retained);
        cell.state = .terminal;
        self.releasePayload(cell);
        cell.* = .{ .generation = cell.generation };
        self.refresh(cell);
        self.diag.occupied -= 1;
    }
    /// Recomputes whether settlement of `cell` is due.
    pub fn refresh(self: *Table, cell: *const Cell) void {
        const index = (@intFromPtr(cell) - @intFromPtr(self.cells.ptr)) / @sizeOf(Cell);
        std.debug.assert(&self.cells[index] == cell);
        self.due.setValue(index, settleable(cell));
    }
    /// The first cell at or after `from` whose settlement is due. O(1).
    pub fn nextDue(self: *const Table, from: usize) ?usize {
        var rest = self.due;
        rest.setRangeValue(.{ .start = 0, .end = @min(from, capacity_max) }, false);
        return rest.findFirstSet();
    }
    /// Whether settlement of any cell is due. O(1); debug builds check it against a scan.
    pub fn anyDue(self: *const Table) bool {
        if (builtin.mode == .Debug) for (0..capacity_max) |i| std.debug.assert(self.due.isSet(i) == (i < self.cells.len and settleable(&self.cells[i])));
        return self.due.findFirstSet() != null;
    }
    pub fn oldest(self: *Table) ?Token {
        var selected: ?Token = null;
        var sequence: u64 = std.math.maxInt(u64);
        for (self.cells, 0..) |*cell, i| {
            if (cell.state != .queued or !cell.native) continue;
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
            result.retiring += @intFromBool(!cell.native and cell.serving_retained);
            result.closedPromises += @intFromBool(cell.closed != null);
            result.pendingResponses += @intFromBool(cell.pending != null);
            result.pendingPermissions += @intFromBool(cell.permission != null);
            result.requestBytes += cell.input.len;
            if (cell.state != .response_preparing) result.responseBytes += cell.response.len;
            if (cell.copying) result.copyingBytes += cell.input.len;
        }
        return result;
    }
    pub fn obligated(self: *const Table) bool {
        for (self.cells) |*cell| if (cell.closed != null or cell.pending != null or cell.permission != null) return true;
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
    return slot.request.terminalEvent() != null;
}
/// A promise the host's settlement resolves now: a write acknowledgement, the close of a finished
/// stream, or a response permission.
pub fn settleable(cell: *const Cell) bool {
    if (cell.state == .free or cell.copying or cell.state == .response_preparing) return false;
    return (cell.ack != null and cell.pending != null) or (!cell.native and cell.closed != null) or ((cell.permission_ready or !cell.native) and cell.permission != null);
}
/// A retained serving slot whose host released it and holds no promise, so the owner returns it.
pub fn releasable(cell: *const Cell) bool {
    return cell.serving_retained and cell.release_requested and !cell.native and !cell.copying and
        cell.closed == null and cell.pending == null and cell.permission == null;
}
/// Work the owner does for a cell at its next host apply: a release or a response permission.
fn ownerWork(cell: *const Cell) bool {
    if (cell.state == .free) return false;
    return releasable(cell) or (cell.native and cell.permission != null and !cell.permission_ready);
}
/// Applies releases, cancels, response permissions, queued responses and terminal actions.
/// Returns whether the per-turn response cap left queued responses for the next turn.
pub fn flags(runtime: *Runtime, now: n.Now) !bool {
    runtime.lock();
    defer runtime.unlock();
    const table = if (runtime.incoming) |*table| table else return false;
    if (table.cells.len == 0) return false;
    var submissions: usize = 0;
    var more = false;
    // Cells refresh their settlement at the end of each iteration, so the legacy row is recomputed after the loop.
    defer runtime.recomputeLocked(.legacy);
    for (0..table.cells.len) |offset| {
        const cell = &table.cells[(table.cursor + offset) % table.cells.len];
        defer table.refresh(cell);
        if (releasable(cell)) {
            const released = runtime.heavy.?.core.service.reqresp.releaseServing(cell.handle);
            std.debug.assert(released);
            cell.serving_retained = false;
            table.retire(.{ .index = @intCast((table.cursor + offset) % table.cells.len), .generation = cell.generation });
            continue;
        }
        if (!cell.native) continue;
        const core = &runtime.heavy.?.core;
        if (cell.action == .cancel or runtime.stop) {
            _ = core.cancel(cell.handle);
            continue;
        }
        if (cell.permission != null and !cell.permission_ready and core.service.reqresp.reserveResponse(cell.handle)) {
            table.reserveResponse(cell, cell.protocol.info().response_max) catch {
                // A payload release wakes the owner to retry.
                table.budget.waiting = true;
                continue;
            };
            cell.permission_ready = true;
        }
        if (cell.state == .response_queued and submissions == 4) more = true;
        if (cell.state == .response_queued and submissions < 4) {
            submissions += 1;
            core.respond(cell.handle, cell.response, cell.context, now) catch |err| {
                if (awaitingTerminal(&core.service.reqresp, cell.handle, err)) continue;
                cell.ack = .{ .rejected = try rejection(err) };
                table.releaseResponse(cell);
                cell.state = .serving;
                continue;
            };
            cell.state = .response_native;
        }
        switch (cell.action) {
            .finish => if (core.finish(cell.handle, now)) {
                cell.action = .submitted;
            },
            .fail => {
                core.respondError(cell.handle, cell.error_status, cell.error_message[0..cell.error_len], now) catch |err| {
                    if (awaitingTerminal(&core.service.reqresp, cell.handle, err)) continue;
                    return err;
                };
                cell.action = .submitted;
            },
            else => {},
        }
    }
    table.cursor = (table.cursor + 4) % table.cells.len;
    return more;
}
pub fn captureLocked(runtime: *Runtime, event: rr.Event, now: n.Now) !void {
    const table = if (runtime.incoming) |*table| table else return;
    if (event == .request) return admitLocked(runtime, event.request, now) catch |err| switch (@as(anyerror, err)) {
        error.OutOfMemory => {
            runtime.diag.operationalFailures +|= 1;
            runtime.heavy.?.core.respondError(event.request.request, 2, "local serving allocation failed", now) catch {
                _ = runtime.heavy.?.core.cancel(event.request.request);
            };
        },
        else => return err,
    };
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
                table.diag.chunksWritten +|= 1;
                table.diag.bytesWritten +|= cell.response.len;
                table.releaseResponse(cell);
                cell.state = .serving;
            },
            .served => |served| {
                if (served.chunks != cell.chunks) return error.InvalidIncomingAcknowledgement;
                cell.native = false;
            },
            .failed => |failed| {
                const reason = try failure(failed.reason);
                if (cell.pending != null and cell.ack == null and !runtime.stop) cell.ack = .{ .failed = reason };
                cell.native = false;
            },
            else => unreachable,
        }
        if (!cell.native) {
            if (cell.pending != null and cell.ack == null) {
                std.debug.assert(runtime.stop);
                cell.ack = .closed;
            }
            if (cell.state != .response_preparing) cell.state = .terminal;
            table.releasePayload(cell);
            if (!cell.exposed and !cell.copying) {
                if (cell.serving_retained) {
                    const released = runtime.heavy.?.core.service.reqresp.releaseServing(cell.handle);
                    std.debug.assert(released);
                    cell.serving_retained = false;
                }
                table.retire(.{ .index = @intCast(i), .generation = cell.generation });
            }
        }
        table.refresh(cell);
        runtime.recomputeLocked(.legacy);
        runtime.recomputeLocked(.serving);
        if (ownerWork(cell)) runtime.host_due = true;
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
    try table.allocate(token, request.bytes);
    const cell = table.get(token).?;
    cell.identity = identity;
    cell.connection = request.peer;
    cell.handle = request.request;
    cell.native = true;
    const retained = core.service.reqresp.retainServing(request.request);
    std.debug.assert(retained);
    cell.serving_retained = true;
    table.refresh(cell);
    runtime.recomputeLocked(.serving);
}
pub fn closeLocked(runtime: *Runtime) void {
    if (runtime.incoming) |*table| for (table.cells, 0..) |*cell, i| {
        if (cell.state == .free) continue;
        cell.native = false;
        cell.serving_retained = false;
        if (cell.pending != null and cell.ack == null) cell.ack = .closed;
        if (cell.state != .response_preparing) cell.state = .terminal;
        table.releasePayload(cell);
        table.refresh(cell);
        if (!cell.exposed and !cell.copying) table.retire(.{ .index = @intCast(i), .generation = cell.generation });
    };
}
test {
    _ = @import("network_incoming_test.zig");
}
