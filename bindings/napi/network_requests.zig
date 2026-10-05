const std = @import("std");
const builtin = @import("builtin");
const n = @import("network");
const rr = n.reqresp;
const Budget = @import("network_budget.zig").Budget;
const network_incoming = @import("network_incoming.zig");
pub fn forkLabel(fork: ?@FieldType(n.types.ForkEntry, "fork")) ?[]const u8 {
    return if (fork) |value| @tagName(value) else null;
}

pub const Token = struct { index: u8, generation: u64 };
pub const State = enum { free, preparing, queued, native, terminal };
pub const Terminal = union(enum) {
    done,
    closed,
    rejected: Rejection,
    failed: struct { reason: rr.ReqResp.Failure, phase: ?rr.ReqResp.RequestPhase },
};
pub const Rejection = enum { disconnected, protocol_disabled, invalid_request, invalid_request_options, too_many_requests, slots_exhausted, negotiation_table_full, transport };
pub const Chunk = struct { len: usize, fork: ?@FieldType(n.types.ForkEntry, "fork") };
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    order: u64 = 0,
    peer: n.PeerId = undefined,
    protocol: rr.Protocol = .blocks_by_root_v2,
    options: rr.ReqResp.RequestOptions = .{},
    input: []u8 = &.{},
    sink: []u8 = &.{},
    reservation: usize = 0,
    native: ?rr.ReqResp.RequestHandle = null,
    terminal: ?Terminal = null,
    chunk: ?Chunk = null,
    delivered: bool = false,
    copying: bool = false,
    consume: bool = false,
    cancel: bool = false,
    retiring: bool = false,
    peer_message: [rr.codec.error_message_max]u8 = undefined,
    peer_message_len: u16 = 0,
    /// A pull awaits the next chunk or the terminal outcome, which an exchange delivers.
    pulling: bool = false,
    /// A return or throw awaits the retirement, which the terminal completion ends.
    retirement_awaited: bool = false,
};
/// What an exchange delivers for one due cell: its chunk, to the pending pull, or its terminal outcome, which answers
/// a pending pull, ends a retirement or, once the owner has quiesced, awaits the iterator's next pull.
pub const Completion = struct {
    token: Token,
    value: union(enum) { chunk: Chunk, terminal: Terminal },
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
};
pub const capacity_max = 32;
pub const Table = struct {
    cells: []Cell = &.{},
    /// The cells whose completion is due now, one set per combination of the runtime's stop and
    /// quiescent flags. `refresh` keeps them current after each change to a cell.
    due: [4]std.StaticBitSet(capacity_max) = @splat(.empty),
    /// Past the last delivered cell, where delivery resumes, so refilled low cells cannot starve higher ones.
    settle_cursor: usize = 0,
    backing: std.mem.Allocator,
    budget: *Budget,
    diag: Diagnostics = .{},

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
        try self.budget.reserve(.outgoing, amount);
        self.cells[token.index] = .{ .state = .preparing, .generation = token.generation, .protocol = which, .reservation = amount };
        self.refresh(&self.cells[token.index]);
        self.diag.occupied += 1;
        self.diag.highWater = @max(self.diag.highWater, self.diag.occupied);
        self.diag.reservedBytes += amount;
        self.diag.reservedBytesHighWater = @max(self.diag.reservedBytesHighWater, self.diag.reservedBytes);
        return token;
    }
    pub fn oldest(self: *Table) ?Token {
        var selected: ?Token = null;
        var order: u64 = std.math.maxInt(u64);
        for (self.cells, 0..) |cell, i| {
            if (cell.state != .queued or cell.order >= order) continue;
            order = cell.order;
            selected = .{ .index = @intCast(i), .generation = cell.generation };
        }
        return selected;
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
        self.budget.release(.outgoing, cell.reservation);
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
        cell.pulling = false;
        cell.retirement_awaited = false;
        self.refresh(cell);
        self.diag.occupied -= 1;
    }
    /// Recomputes whether the completion of `cell` is due, under each stop and quiescent flag.
    pub fn refresh(self: *Table, cell: *const Cell) void {
        const index = (@intFromPtr(cell) - @intFromPtr(self.cells.ptr)) / @sizeOf(Cell);
        std.debug.assert(&self.cells[index] == cell);
        for (&self.due, 0..) |*set, flags_index| set.setValue(index, settleable(cell, flags_index & 1 != 0, flags_index & 2 != 0));
    }
    /// The first cell at or after `from` whose completion is due. O(1).
    pub fn nextDue(self: *const Table, from: usize, stop: bool, quiescent: bool) ?usize {
        var rest = self.due[dueIndex(stop, quiescent)];
        rest.setRangeValue(.{ .start = 0, .end = @min(from, capacity_max) }, false);
        return rest.findFirstSet();
    }
    /// Whether the completion of any cell is due. O(1); debug builds check it against a scan.
    pub fn anyDue(self: *const Table, stop: bool, quiescent: bool) bool {
        if (builtin.mode == .Debug) for (&self.due, 0..) |*set, flags_index| for (0..capacity_max) |i| {
            std.debug.assert(set.isSet(i) == (i < self.cells.len and settleable(&self.cells[i], flags_index & 1 != 0, flags_index & 2 != 0)));
        };
        return self.due[dueIndex(stop, quiescent)].findFirstSet() != null;
    }
    fn dueIndex(stop: bool, quiescent: bool) usize {
        return @as(usize, @intFromBool(stop)) | @as(usize, @intFromBool(quiescent)) << 1;
    }
    /// Pins the due cell at `index` for delivery: its chunk when a pull awaits one, else its terminal outcome.
    pub fn pin(self: *Table, index: usize, stop: bool) Completion {
        const cell = &self.cells[index];
        const token: Token = .{ .index = @intCast(index), .generation = cell.generation };
        defer self.refresh(cell);
        defer cell.copying = true;
        if (deliverable(cell, stop)) return .{ .token = token, .value = .{ .chunk = cell.chunk.? } };
        return .{ .token = token, .value = .{ .terminal = outcome(cell) } };
    }
    /// Commits a delivered completion. Returns whether it retired the cell, whose runtime reference the caller
    /// releases.
    pub fn commit(self: *Table, completion: Completion) bool {
        const cell = self.get(completion.token).?;
        cell.copying = false;
        const chunk = switch (completion.value) {
            .terminal => {
                self.retire(completion.token);
                return true;
            },
            .chunk => |chunk| chunk,
        };
        cell.pulling = false;
        self.diag.chunksCopied +|= 1;
        self.diag.bytesCopied +|= chunk.len;
        cell.delivered = true;
        // The stream ended meanwhile, so no pull consumes the chunk.
        if (cell.native == null) {
            cell.chunk = null;
            cell.delivered = false;
        }
        self.releasePayload(cell);
        self.refresh(cell);
        return false;
    }
    /// Returns a pinned cell, still due, to where it was.
    pub fn restore(self: *Table, completion: Completion) void {
        const cell = self.get(completion.token).?;
        cell.copying = false;
        self.releasePayload(cell);
        self.refresh(cell);
    }
    pub fn snapshot(self: *const Table) Diagnostics {
        var result = self.diag;
        for (self.cells) |*cell| {
            if (cell.state == .free) continue;
            result.pendingPulls += @intFromBool(cell.pulling);
            result.terminalCells += @intFromBool(cell.terminal != null);
            // Preparing storage is private to the JS thread until publication.
            if (cell.state == .preparing) continue;
            result.inputBytes += cell.input.len;
            result.sinkBytes += cell.sink.len;
            if (cell.copying and cell.chunk != null) result.copyingBytes += cell.chunk.?.len;
        }
        return result;
    }
    /// Whether a pull or a return awaits a completion, which keeps the event loop alive.
    pub fn obligated(self: *const Table) bool {
        for (self.cells) |*cell| if (cell.pulling or cell.retirement_awaited) return true;
        return false;
    }
};

/// A received chunk and a pull waiting for it.
pub fn deliverable(cell: *const Cell, stop: bool) bool {
    return cell.pulling and cell.chunk != null and !cell.delivered and !cell.retiring and !stop;
}
/// A completion an exchange delivers now: a chunk to its pending pull, or the terminal outcome to a pending pull or a
/// retirement, or to the iterator once the owner has quiesced, so no request outlives the runtime's close.
pub fn settleable(cell: *const Cell, stop: bool, quiescent: bool) bool {
    if (cell.state == .free or cell.state == .preparing or cell.copying) return false;
    if (deliverable(cell, stop)) return true;
    const terminal = cell.terminal != null and cell.native == null and (cell.chunk == null or cell.retiring or stop);
    return terminal and (cell.pulling or cell.retiring or quiescent);
}
/// The terminal outcome a pending pull takes: a retirement turns any outcome but the runtime's close into a
/// cancellation.
pub fn outcome(cell: *const Cell) Terminal {
    const terminal = cell.terminal.?;
    if (!cell.retiring or terminal == .closed) return terminal;
    return .{ .failed = .{ .reason = .cancelled, .phase = switch (terminal) {
        .failed => |failure| failure.phase,
        .done => .response,
        else => null,
    } } };
}
/// JS thread: arms a pull. The owner consumes a delivered chunk first; an exchange delivers the answer.
pub fn armPull(runtime: *Runtime, cell: *Cell) void {
    cell.pulling = true;
    if (cell.delivered) cell.consume = true;
    runtime.requests.?.refresh(cell);
    runtime.signalLocked();
    runtime.recomputeLocked(.completions);
}
/// JS thread: asks the owner to cancel and retire the request, whose terminal completion ends a retirement that is
/// `awaited`.
pub fn armRetirement(runtime: *Runtime, cell: *Cell, awaited: bool) void {
    cell.retirement_awaited = cell.retirement_awaited or awaited;
    cell.retiring = true;
    cell.cancel = true;
    runtime.requests.?.refresh(cell);
    runtime.signalLocked();
    runtime.recomputeLocked(.completions);
}

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
pub const turn_max = 16;
pub fn submit(runtime: *Runtime, token: Token, now: n.Now) !void {
    runtime.lock();
    defer runtime.unlock();
    const table = &runtime.requests.?;
    const cell = table.get(token) orelse return error.InvalidRequestHandle;
    if (cell.cancel or runtime.stop) {
        cell.terminal = if (runtime.stop) .closed else .{ .failed = .{ .reason = .cancelled, .phase = null } };
    } else {
        const core = &runtime.heavy.?.core;
        cell.native = core.sendReqRespRequest(&cell.peer, cell.protocol, cell.input, cell.sink, cell.options, now) catch |err| blk: {
            cell.terminal = .{ .rejected = try rejection(err) };
            break :blk null;
        };
    }
    cell.state = if (cell.native != null) .native else .terminal;
    if (cell.native) |handle| {
        std.log.scoped(.network_bridge).debug("host_request_submitted host_request={d}:{d} request={d}:{d} method={s} peer={f}", .{ token.index, token.generation, handle.index, handle.generation, @tagName(cell.protocol), n.logging.peer(&cell.peer) });
    } else if (cell.terminal) |terminal| {
        std.log.scoped(.network_bridge).debug("host_request_refused host_request={d}:{d} method={s} peer={f} reason={s}", .{ token.index, token.generation, @tagName(cell.protocol), n.logging.peer(&cell.peer), if (terminal == .rejected) @tagName(terminal.rejected) else @tagName(terminal) });
    }
    table.releasePayload(cell);
    table.refresh(cell);
    runtime.recomputeLocked(.completions);
}
pub fn applyPending(runtime: *Runtime, now: n.Now) void {
    runtime.lock();
    defer runtime.unlock();
    if (runtime.requests) |*table| for (table.cells) |*cell| {
        if (cell.state == .free or cell.state == .preparing or cell.state == .queued or cell.copying) continue;
        if (cell.cancel or runtime.stop) {
            cell.chunk = null;
            if (cell.native) |handle| _ = runtime.heavy.?.core.cancelRequest(handle, now);
        } else if (cell.consume) {
            cell.consume = false;
            cell.chunk = null;
            cell.delivered = false;
            if (cell.native) |handle| _ = runtime.heavy.?.core.consumeResponse(handle, now);
        }
        table.releasePayload(cell);
        table.refresh(cell);
        if (cell.terminal != null and (cell.pulling or cell.retiring)) runtime.recomputeLocked(.completions);
    };
}
pub fn capture(runtime: *Runtime, events: []const rr.ReqResp.Event, now: n.Now) !void {
    runtime.lock();
    defer runtime.unlock();
    const core = &runtime.heavy.?.core;
    for (events) |event| {
        try network_incoming.captureLocked(runtime, event, now);
        switch (event) {
            .request => |incoming| {
                if (runtime.incoming == null) try core.respondError(incoming.request, 2, "application handlers unavailable", now);
                continue;
            },
            .chunk_sent, .served => continue,
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
            table.releasePayload(cell);
            table.refresh(cell);
            runtime.recomputeLocked(.completions);
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
        table.refresh(cell);
    };
}

test {
    _ = @import("network_requests_test.zig");
}
