const std = @import("std");

test "application admission reserves 32 commands and at most 16 connects" {
    var table: Table = .{};
    for (0..16) |_| _ = try table.reserve(.connect);
    try std.testing.expectError(error.NetworkCommandFull, table.reserve(.connect));
    for (0..16) |_| _ = try table.reserve(.getIdentity);
    try std.testing.expectError(error.NetworkCommandFull, table.reserve(.getIdentity));
}

pub const capacity = 32;
pub const connect_max = 16;
pub const turn_max = 4;
pub const Kind = enum { small, connect, intent, snapshot, targets };
pub const State = enum { free, preparing, queued, executing, waiting, terminal, copying };
pub const Token = struct { index: u8, generation: u64 };
pub const Cell = struct {
    state: State = .free,
    generation: u64 = 0,
    kind: Kind = .small,
    store: ?u8 = null,
    order: u64 = 0,
    input: Input = .{ .command = .getIdentity },
    deferred: ?@import("zapi:zapi").napi.Deferred = null,
    failure: ?anyerror = null,
    sequence: u64 = 0,
    boolean: bool = false,
    deadline: u64 = 0,
    identity: @import("network_runtime.zig").Identity = undefined,
    count: usize = 0,
    counts: n.PeerManager.PeerCounts = undefined,
};
pub const Table = struct {
    cells: [capacity]Cell = @splat(.{}),
    stores: [3][2]bool = @splat(@splat(false)),
    connects: u8 = 0,
    occupied: u8 = 0,
    high_water: u8 = 0,
    refusals: u64 = 0,
    sequence: u64 = 0,
    admission_sequence: u64 = 0,
    kind_high_water: [5]u8 = @splat(0),
    kind_refusals: [5]u64 = @splat(0),

    pub fn advance(self: *Table) !u64 {
        self.sequence = std.math.add(u64, self.sequence, 1) catch return error.NetworkSequenceExhausted;
        return self.sequence;
    }
    pub fn nextOrder(self: *Table) !u64 {
        if (self.admission_sequence >= std.math.maxInt(u64) - 1) return error.NetworkSequenceExhausted;
        self.admission_sequence += 1;
        return self.admission_sequence;
    }
    fn storeKind(kind: Kind) ?usize {
        return switch (kind) {
            .intent => 0,
            .snapshot => 1,
            .targets => 2,
            else => null,
        };
    }
    pub fn reserve(self: *Table, command: Command) !Token {
        const kind = storageKind(command);
        return self.reserveInner(command) catch |err| {
            self.refusals +|= 1;
            self.kind_refusals[@intFromEnum(kind)] +|= 1;
            return err;
        };
    }
    fn reserveInner(self: *Table, command: Command) !Token {
        const kind = storageKind(command);
        if (kind == .connect and self.connects == connect_max) return error.NetworkCommandFull;
        var store: ?u8 = null;
        if (storeKind(kind)) |which| {
            for (self.stores[which], 0..) |used, i| if (!used) {
                store = @intCast(i);
                break;
            };
            if (store == null) return error.NetworkCommandFull;
        }
        for (&self.cells, 0..) |*cell, i| {
            if (cell.state != .free) continue;
            const generation = std.math.add(u64, cell.generation, 1) catch return error.NetworkSequenceExhausted;
            const order = try self.nextOrder();
            cell.* = .{ .state = .preparing, .generation = generation, .kind = kind, .store = store, .order = order, .input = .{ .command = command } };
            if (storeKind(kind)) |which| self.stores[which][store.?] = true;
            self.connects += @intFromBool(kind == .connect);
            self.occupied += 1;
            self.high_water = @max(self.high_water, self.occupied);
            var count: u8 = 0;
            for (&self.cells) |*entry| if (entry.state != .free and entry.kind == kind) {
                count += 1;
            };
            self.kind_high_water[@intFromEnum(kind)] = @max(self.kind_high_water[@intFromEnum(kind)], count);
            return .{ .index = @intCast(i), .generation = generation };
        }
        return error.NetworkCommandFull;
    }
    pub fn nextQueued(self: *Table) ?Token {
        var selected: ?Token = null;
        var order: u64 = std.math.maxInt(u64);
        for (&self.cells, 0..) |*cell, i| {
            if (cell.state == .queued and (selected == null or cell.order < order)) {
                selected = .{ .index = @intCast(i), .generation = cell.generation };
                order = cell.order;
            }
        }
        return selected;
    }
    pub fn get(self: *Table, token: Token) *Cell {
        const cell = &self.cells[token.index];
        std.debug.assert(cell.generation == token.generation and cell.state != .free);
        return cell;
    }
    pub fn retire(self: *Table, token: Token) void {
        const cell = self.get(token);
        if (storeKind(cell.kind)) |which| self.stores[which][cell.store.?] = false;
        self.connects -= @intFromBool(cell.kind == .connect);
        self.occupied -= 1;
        cell.state = .free;
    }
};

test "typed reservations unwind and identities never wrap" {
    var table: Table = .{};
    const first = try table.reserve(.applyIntent);
    _ = try table.reserve(.applyIntent);
    try std.testing.expectError(error.NetworkCommandFull, table.reserve(.applyIntent));
    try std.testing.expectEqual(@as(u8, 2), table.occupied);
    table.retire(first);
    const next = try table.reserve(.applyIntent);
    try std.testing.expectEqual(first.generation + 1, next.generation);
    table.retire(next);
    table.cells[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.NetworkSequenceExhausted, table.reserve(.getIdentity));
    table.sequence = std.math.maxInt(u64);
    try std.testing.expectError(error.NetworkSequenceExhausted, table.advance());
    table.admission_sequence = std.math.maxInt(u64) - 2;
    try std.testing.expectEqual(std.math.maxInt(u64) - 1, try table.nextOrder());
    try std.testing.expectError(error.NetworkSequenceExhausted, table.nextOrder());
}

const n = @import("network");
pub const Command = enum { applyIntent, updateStatus, getIdentity, getPeers, getGossipDiagnostics, connect, disconnect, reStatusPeers, addDirectPeer, removeDirectPeer, getDirectPeers };
fn storageKind(command: Command) Kind {
    return switch (command) {
        .applyIntent => .intent,
        .getPeers, .getDirectPeers, .getGossipDiagnostics => .snapshot,
        .connect => .connect,
        .reStatusPeers => .targets,
        else => .small,
    };
}
pub const Input = struct {
    command: Command,
    status: n.peers.types.Status = undefined,
    peer: n.PeerId = undefined,
    addresses: [2]n.Address = undefined,
    address_count: u8 = 0,
    slot: u64 = 0,
    timeout_ms: u64 = 0,
    target_count: u16 = 0,
    diagnostics_cursor: u16 = 0,
};

const Runtime = @import("network_runtime.zig").Runtime;
pub fn execute(self: *Runtime, token: Token, timestamp: n.Now) void {
    const cell = self.table.get(token);
    executeOne(self, token.index, timestamp) catch |err| {
        std.log.scoped(.network_bridge).debug("command_failed command={s} operation={d}:{d} reason={s}", .{ @tagName(cell.input.command), token.index, token.generation, @errorName(err) });
        cell.failure = err;
    };
    self.lock();
    defer self.unlock();
    if (cell.state == .executing) {
        if (self.stop) cell.failure = self.terminal_error orelse error.NetworkClosed;
        cell.state = .terminal;
    }
    if (cell.state == .terminal) self.pingLocked();
}
fn executeOne(self: *Runtime, index: usize, timestamp: n.Now) !void {
    const operation = &self.table.cells[index];
    const input = &operation.input;
    const core = &self.heavy.?.core;
    const store = self.table.cells[index].store;
    switch (input.command) {
        .applyIntent => {
            if (input.slot < self.slot) return error.ClockRegression;
            const intent = &self.stores.?.intents[store.?].value;
            intent.update = try self.heavy.?.config.chain.update(intent.update.local, core.advertisementEndpoints(), input.slot);
            intent.slot = input.slot;
            operation.boolean = try core.applyIntent(intent, timestamp);
            self.lock();
            self.slot = input.slot;
            self.diag.currentSlot = input.slot;
            if (!self.stop) self.diag.state = .running;
            self.unlock();
        },
        .updateStatus => {
            var status = input.status;
            status.fork_digest = core.localState().status.fork_digest;
            try core.updateStatus(&status);
        },
        .getIdentity => operation.identity = try self.heavy.?.readIdentity(),
        .getPeers => {
            operation.count = try core.completeSnapshots(self.stores.?.snapshots[store.?]);
            operation.counts = core.peerCounts();
        },
        .getGossipDiagnostics => try n.gossipsub.diagnostics.capture(core.service.gossipsub, input.diagnostics_cursor, timestamp, &self.stores.?.gossip_diagnostics[store.?]),
        .getDirectPeers => operation.count = try core.directPeers(&self.stores.?.direct[store.?]),
        .removeDirectPeer => operation.boolean = core.removeDirectPeer(&input.peer),
        .addDirectPeer => try core.addDirectPeer(&input.peer, input.addresses[0..input.address_count], timestamp),
        .connect => {
            if (core.isConnected(&input.peer)) return;
            operation.deadline = timestamp.mono_ms +| input.timeout_ms;
            try core.connectUntil(&input.peer, input.addresses[0..input.address_count], timestamp, operation.deadline);
            self.lock();
            self.table.cells[index].state = .waiting;
            self.unlock();
        },
        .disconnect => {
            core.cancelConnect(&input.peer, timestamp);
            self.lock();
            for (&self.table.cells, 0..) |*cell, i| {
                if (cell.state != .waiting or !self.table.cells[i].input.peer.eql(&input.peer)) continue;
                self.table.cells[i].failure = error.NetworkConnectCancelled;
                cell.state = .terminal;
            }
            self.unlock();
            _ = core.closePeer(&input.peer, timestamp);
        },
        .reStatusPeers => for (self.stores.?.targets[store.?][0..input.target_count]) |*identity| {
            _ = core.reStatusPeer(identity, timestamp);
        },
    }
}
pub fn completeConnects(self: *Runtime, timestamp: n.Now) void {
    const events = self.heavy.?.core.transportEvents();
    self.lock();
    defer self.unlock();
    if (self.stop) return;
    if (latchConnects(&self.table, events, timestamp)) self.pingLocked();
}

pub fn latchConnects(table: *Table, events: []const n.Event, timestamp: n.Now) bool {
    var terminal = false;
    for (&table.cells, 0..) |*cell, i| {
        if (cell.state != .waiting) continue;
        const operation = &table.cells[i];
        var connected = false;
        for (events) |event| if (event == .connected and event.connected.peer_id.eql(&operation.input.peer)) {
            connected = true;
            break;
        };
        if (!connected and timestamp.mono_ms < operation.deadline) continue;
        operation.failure = if (connected) null else error.NetworkConnectTimeout;
        cell.state = .terminal;
        terminal = true;
    }
    return terminal;
}
pub fn waitLimit(self: *Runtime, timestamp: n.Now) u32 {
    self.lock();
    defer self.unlock();
    if (self.reports.pending != 0) return 0;
    if (self.publications) |*table| if (table.oldest() != null) return 0;
    if (self.requests) |*table| if (table.oldest() != null) return 0;
    var limit: u64 = 100;
    for (&self.table.cells, 0..) |*cell, i| {
        if (cell.state == .queued) return 0;
        if (cell.state == .waiting) limit = @min(limit, self.table.cells[i].deadline -| timestamp.mono_ms);
    }
    if (self.gossip) |*gossip| limit = gossip.waitLimit(timestamp.mono_ms, limit);
    if (self.closing_deadline) |deadline| limit = @min(limit, deadline -| timestamp.mono_ms);
    return @intCast(limit);
}
