const std = @import("std");
const builtin = @import("builtin");

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
    /// The terminal cells, whose completions an exchange delivers. `transition` keeps it current.
    terminal: std.StaticBitSet(capacity) = .initEmpty(),
    /// Past the last delivered cell, where delivery resumes, so refilled low cells cannot starve higher ones.
    settle_cursor: usize = 0,
    stores: [3][2]bool = @splat(@splat(false)),
    connects: u8 = 0,
    occupied: u8 = 0,
    sequence: u64 = 0,
    admission_sequence: u64 = 0,

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
        self.transition(cell, .free);
    }
    /// Moves `cell` to `state`, keeping the terminal set current.
    pub fn transition(self: *Table, cell: *Cell, state: State) void {
        const index = (@intFromPtr(cell) - @intFromPtr(&self.cells)) / @sizeOf(Cell);
        std.debug.assert(&self.cells[index] == cell);
        cell.state = state;
        self.terminal.setValue(index, state == .terminal);
    }
    /// The first terminal cell at or after `from`. O(1).
    pub fn nextTerminal(self: *const Table, from: usize) ?usize {
        var rest = self.terminal;
        rest.setRangeValue(.{ .start = 0, .end = @min(from, capacity) }, false);
        return rest.findFirstSet();
    }
    /// Whether any completion awaits delivery. O(1); debug builds check it against a scan.
    pub fn anyTerminal(self: *const Table) bool {
        if (builtin.mode == .Debug) for (&self.cells, 0..) |*cell, i| std.debug.assert(self.terminal.isSet(i) == (cell.state == .terminal));
        return self.terminal.findFirstSet() != null;
    }
};

const n = @import("network");
pub const Command = enum { applyIntent, updateStatus, getIdentity, getPeers, getGossipDiagnostics, connect, disconnect, reStatusPeers, addDirectPeer, removeDirectPeer, getDirectPeers, getRememberedPeers };
fn storageKind(command: Command) Kind {
    return switch (command) {
        .applyIntent => .intent,
        .getPeers, .getDirectPeers, .getGossipDiagnostics, .getRememberedPeers => .snapshot,
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
        self.table.transition(cell, .terminal);
    }
    if (cell.state == .terminal) self.recomputeLocked(.completions);
}
fn executeOne(self: *Runtime, index: usize, timestamp: n.Now) !void {
    const operation = &self.table.cells[index];
    const input = &operation.input;
    const core = &self.heavy.?.core;
    const store = self.table.cells[index].store;
    switch (input.command) {
        .applyIntent => {
            if (input.slot < core.current_slot) return error.ClockRegression;
            const intent = &self.stores.?.intents[store.?].value;
            intent.update = try self.heavy.?.config.chain.update(intent.update.local, core.advertisementEndpoints(), input.slot);
            intent.slot = input.slot;
            operation.boolean = try core.applyIntent(intent, timestamp);
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
        .getRememberedPeers => {
            const page = &self.stores.?.remembered[store.?];
            page.genesis_root = self.heavy.?.application.genesis_root;
            operation.count = try core.rememberedPeers(timestamp, &page.records);
        },
        .removeDirectPeer => operation.boolean = core.removeDirectPeer(&input.peer),
        .addDirectPeer => try core.addDirectPeer(&input.peer, input.addresses[0..input.address_count], timestamp),
        .connect => {
            if (core.isConnected(&input.peer)) return;
            operation.deadline = timestamp.mono_ms +| input.timeout_ms;
            try core.connectUntil(&input.peer, input.addresses[0..input.address_count], timestamp, operation.deadline);
            self.lock();
            self.table.transition(operation, .waiting);
            self.unlock();
        },
        .disconnect => {
            core.cancelConnect(&input.peer, timestamp);
            self.lock();
            for (&self.table.cells, 0..) |*cell, i| {
                if (cell.state != .waiting or !self.table.cells[i].input.peer.eql(&input.peer)) continue;
                self.table.cells[i].failure = error.NetworkConnectCancelled;
                self.table.transition(cell, .terminal);
            }
            self.unlock();
            _ = core.closePeer(&input.peer, timestamp);
        },
        .reStatusPeers => for (self.stores.?.targets[store.?][0..input.target_count]) |*identity| {
            _ = core.reStatusPeer(identity, timestamp);
        },
    }
}
pub fn completeConnects(self: *Runtime, events: []const n.Event, timestamp: n.Now) void {
    self.lock();
    defer self.unlock();
    if (self.stop) return;
    if (latchConnects(&self.table, events, timestamp)) self.recomputeLocked(.completions);
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
        table.transition(cell, .terminal);
        terminal = true;
    }
    return terminal;
}
/// The earliest deadline of a connect waiting for its peer. Scans only while a connect is held.
pub fn connectDeadline(table: *const Table) ?u64 {
    if (table.connects == 0) return null;
    var deadline: ?u64 = null;
    for (&table.cells) |*cell| {
        if (cell.state == .waiting) deadline = @min(deadline orelse cell.deadline, cell.deadline);
    }
    return deadline;
}

test {
    _ = @import("network_commands_test.zig");
}
