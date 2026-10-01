//! Owns inbound admission ordering and promotion; Server owns wire progress and ReqResp settles
//! every slot transition. Each Server embeds its one admission record; no slot table is mirrored.
const std = @import("std");
const RequestIO = @import("RequestIO.zig");
const ReqResp = @import("ReqResp.zig");
const Server = @import("Server.zig");
const admission = @import("admission.zig");
const ReceivePlan = @import("ReceivePlan.zig");
const constants = @import("constants.zig");
const index_list = @import("../index_list.zig");
const types = @import("../types.zig");
const Engine = @import("../quic/Engine.zig");
const Handle = types.Handle;
const StreamHandle = types.StreamHandle;
const Now = types.Now;
const protocol = @import("protocol.zig");
const Protocol = protocol.Protocol;
const PeerId = @import("../wire/peer_id.zig").PeerId;
const routing = @import("../router.zig");
const assert = std.debug.assert;

pub const State = struct {
    cost: u128 = 1,
    paid: u128 = 0,
    eligible_ms: u64 = 0,
    /// Accepted without its start charged; promotion charges it once before serving.
    start_pending: bool = false,
    /// The last ready admission attempt; none means an attempt is due.
    wait: enum { none, start, tokens, serving } = .none,

    pub fn decoded(self: *State, cost: u128, now_ms: u64) void {
        self.cost = cost;
        self.eligible_ms = @max(self.eligible_ms, now_ms);
        if (self.eligible_ms > now_ms) {
            assert(self.start_pending);
            self.wait = .start;
        }
    }

    pub fn rejected(self: *State) void {
        self.start_pending = false;
    }

    pub fn deadline(self: *const State, timeout: u64) u64 {
        return if (self.wait == .start or self.wait == .tokens) @min(timeout, self.eligible_ms) else timeout;
    }
};

/// A checked receive slot whose start was charged or deferred. Consume immediately on this owner.
pub const Acceptance = struct {
    index: u16,
    identity: PeerId,
    protocol: Protocol,
    bounds: protocol.Info,
    state: State,
};

pub const Lease = struct { execution: u16, scratch: []u8 };
pub const Progress = enum { waiting, charged, admitted };

const InboundAdmission = @This();

limiter: admission.Limiter,
peer_cursors: []PeerCursor,
ready: [2]index_list.List = .{ .{}, .{} },
pending: bool = false,

pub fn init(allocator: std.mem.Allocator, options: admission.Options, peers: u16) admission.InitError!InboundAdmission {
    var limiter = try admission.Limiter.init(allocator, options);
    errdefer limiter.deinit(allocator);
    const cursors = try allocator.alloc(PeerCursor, peers);
    @memset(cursors, .{});
    return .{ .limiter = limiter, .peer_cursors = cursors };
}

pub fn deinit(self: *InboundAdmission, allocator: std.mem.Allocator) void {
    allocator.free(self.peer_cursors);
    self.limiter.deinit(allocator);
    self.* = undefined;
}

pub fn schedulerBytes(self: *const InboundAdmission) usize {
    return self.peer_cursors.len * @sizeOf(PeerCursor);
}

pub fn due(self: *const InboundAdmission) bool {
    return self.pending and self.ready[0].len + self.ready[1].len > 0;
}

pub fn capacityReleased(self: *InboundAdmission) void {
    self.pending = true;
}

pub fn waitEnded(self: *InboundAdmission, slot: *Server) void {
    assert(slot.request.running() and slot.state == .ready);
    slot.admission.wait = .none;
    self.pending = true;
}

pub fn accept(self: *InboundAdmission, owner: *ReqResp, engine: *Engine, stream: StreamHandle, ready: routing.Selection, now: Now) ReqResp.AcceptError!ReqResp.RequestHandle {
    try owner.attach(engine);
    if (stream.conn.index >= owner.options.peers) return error.InvalidCapacity;
    const identity = engine.peerId(stream.conn) orelse return error.StaleHandle;
    if (ready.leftover.len > RequestIO.read_buffer_length) return error.InvalidHandoff;
    const which = switch (ready.protocol) {
        .reqresp => |which| which,
        else => return error.UnknownProtocol,
    };
    const bounds = owner.requestBounds(which);
    if (owner.inboundCount(stream.conn, which) >= constants.MAX_CONCURRENT_REQUESTS) {
        owner.recordAdmissionRefusal(stream, which, .protocol_concurrency, 0);
        return error.ProtocolConcurrency;
    }
    const limiter = &self.limiter;
    if (!limiter.tracks(&identity, now.mono_ms)) {
        owner.recordAdmissionRefusal(stream, which, .identity_capacity, 1);
        return error.TooManyRequests;
    }
    if (owner.inboundCount(stream.conn, null) >= owner.options.inbound_per_peer_max) {
        owner.recordAdmissionRefusal(stream, which, .peer_capacity, 0);
        return error.PeerSlotsExhausted;
    }
    const available = availableInbound(owner.inbound, stream.conn, which);
    if (!which.isControl() and owner.options.inbound_application_per_peer_max > 0 and
        owner.inboundApplicationCount(stream.conn) >= owner.options.inbound_application_per_peer_max)
    {
        owner.recordAdmissionRefusal(stream, which, .peer_capacity, 0);
        return error.PeerSlotsExhausted;
    }
    const index = available orelse {
        owner.recordAdmissionRefusal(stream, which, .peer_capacity, 0);
        return error.SlotsExhausted;
    };
    const slot = &owner.inbound[index];
    if (ready.leftover.len > slot.receive.read.len) return error.InvalidHandoff;
    const request_sink = owner.inboundSink(index);
    assert(request_sink.len >= bounds.request_max);
    const control = which.isControl();
    // A responder rate-limits by withholding its response, never by closing the stream, so a
    // request past the starts limiter waits in `.ready` for its start. One arriving behind a
    // request still owed its start waits too, uncharged, so it cannot take the refill that one
    // awaits; it still needs a limiter row for its identity.
    const start_due: ?u64 = if (startsPending(owner.inbound, stream.conn, control))
        limiter.startAt(&identity, control, now.mono_ms)
    else switch (limiter.start(&identity, control, now.mono_ms)) {
        .allowed => null,
        .identity_capacity => unreachable,
        else => limiter.startAt(&identity, control, now.mono_ms),
    };
    const accepted: Acceptance = .{
        .index = index,
        .identity = identity,
        .protocol = which,
        .bounds = bounds,
        .state = .{ .eligible_ms = start_due orelse 0, .start_pending = start_due != null },
    };
    return Server.acceptPrepared(owner, engine, stream, ready, &accepted, now);
}

fn availableInbound(slots: []Server, peer: Handle, which: Protocol) ?u16 {
    const first = ReceivePlan.first(peer.index, which);
    for (slots[first..][0..constants.MAX_CONCURRENT_REQUESTS], first..) |*slot, index| {
        if (slot.request.available()) return @intCast(index);
    }
    return null;
}

pub fn settle(self: *InboundAdmission, slots: []Server, index: u16) void {
    const slot = &slots[index];
    const peer = index / ReceivePlan.slots_per_peer;
    const bit = @as(u64, 1) << @intCast(index % ReceivePlan.slots_per_peer);
    const class: u1 = @intFromBool(slot.request.protocol.isControl());
    const cursor = &self.peer_cursors[peer];
    const waiting = slot.request.running() and slot.state == .ready;
    if (waiting and cursor.ready_mask[class] & bit == 0 and slot.admission.wait == .none) self.pending = true;
    if (waiting) cursor.ready_mask[class] |= bit else cursor.ready_mask[class] &= ~bit;
    switch (class) {
        inline else => |which| {
            const field = PeerCursor.link_fields[which];
            const linked = @field(cursor, field).linked;
            if (cursor.ready_mask[which] != 0 and !linked) self.ready[which].append(self.peer_cursors, field, peer);
            if (cursor.ready_mask[which] == 0 and linked) self.ready[which].remove(self.peer_cursors, field, peer);
        },
    }
}

/// One admission attempt per connection per class, control first. A connection that was
/// admitted moves to the tail; one that was not keeps its place ahead of it.
pub fn promoteReady(self: *InboundAdmission, owner: *ReqResp, now: Now) void {
    if (!self.pending) return;
    self.pending = false;
    var promoted: usize = 0;
    inline for (.{ 1, 0 }) |class| {
        const field = PeerCursor.link_fields[class];
        const list = &self.ready[class];
        var next = list.head;
        // Each visited connection is behind every unvisited one once moved, so each
        // connection on the list is visited once.
        for (0..list.len) |_| {
            if (next == index_list.none) break;
            if (promoted == owner.options.work_per_pump_max) {
                self.pending = true;
                return;
            }
            const peer: u16 = @intCast(next);
            const cursor = &self.peer_cursors[peer];
            next = @field(cursor, field).next;
            if (self.promotePeer(owner, peer, class, now)) {
                promoted += 1;
                // The connection's other `.ready` slots wait for the next round.
                if (cursor.ready_mask[class] != 0) {
                    self.pending = true;
                    list.remove(self.peer_cursors, field, peer);
                    list.append(self.peer_cursors, field, peer);
                }
            }
        }
    }
}

/// Tries the connection's `.ready` slots of the class in turn until one is admitted, is
/// charged its start or pays toward its cost.
fn promotePeer(self: *InboundAdmission, owner: *ReqResp, peer: u16, comptime class: u1, now: Now) bool {
    const cursor = &self.peer_cursors[peer];
    const first = @as(usize, peer) * ReceivePlan.slots_per_peer;
    const start = cursor.admission[class];
    for (0..ReceivePlan.slots_per_peer) |offset| {
        const local: u8 = @intCast((start + offset) % ReceivePlan.slots_per_peer);
        if (cursor.ready_mask[class] & (@as(u64, 1) << @intCast(local)) == 0) continue;
        const index: u16 = @intCast(first + local);
        owner.visits +|= 1;
        const result = self.promote(owner, index, now);
        owner.settleSlot(.inbound, index);
        if (result != .waiting) {
            cursor.admission[class] = @intCast((local + 1) % ReceivePlan.slots_per_peer);
            return true;
        }
    }
    return false;
}

/// Reports admission progress explicitly; the caller finishes with ReqResp.settleSlot.
pub fn promote(self: *InboundAdmission, owner: *ReqResp, index: u16, now: Now) Progress {
    const slot = &owner.inbound[index];
    const request = &slot.request;
    const state = &slot.admission;
    if (!request.running() or slot.state != .ready or now.mono_ms < state.eligible_ms) return .waiting;
    var progress: Progress = .waiting;
    if (state.start_pending) {
        if (!self.chargeStart(owner.inbound, index, now)) return .waiting;
        progress = .charged;
    }
    const execution = owner.serving.available(&slot.identity, request.protocol.isControl()) orelse {
        state.wait = .serving;
        return progress;
    };
    const cost = self.limiter.requestCost(request.protocol, state.cost, slot.request_fork);
    if (state.paid < cost) {
        const granted = self.limiter.grant(&slot.identity, request.protocol, cost - state.paid, slot.request_fork, now.mono_ms);
        state.paid += granted;
        if (granted > 0) progress = .charged;
        if (state.paid < cost) {
            state.eligible_ms = self.limiter.eligibleAt(&slot.identity, request.protocol, 1, slot.request_fork, now.mono_ms).?;
            state.wait = .tokens;
            return progress;
        }
    }
    state.wait = .none;
    const lease: Lease = .{ .execution = execution, .scratch = owner.serving.acquire(execution, request.handle(index), &slot.identity, request.protocol.isControl()) };
    slot.admit(index, &lease, now);
    return .admitted;
}

/// Charges the start deferred at accept once one is due and no `.ready` request of its class
/// on the connection has waited longer. Otherwise sets when to recheck; nothing is reserved.
fn chargeStart(self: *InboundAdmission, slots: []Server, index: u16, now: Now) bool {
    const slot = &slots[index];
    const state = &slot.admission;
    const limiter = &self.limiter;
    const control = slot.request.protocol.isControl();
    if (!self.startQueued(slots, index) and limiter.start(&slot.identity, control, now.mono_ms) == .allowed) {
        state.start_pending = false;
        return true;
    }
    state.eligible_ms = limiter.startAt(&slot.identity, control, now.mono_ms);
    // A start due now goes to the longer waiter, so this one stays due an admission attempt.
    state.wait = if (state.eligible_ms > now.mono_ms) .start else .none;
    return false;
}

/// Whether a running request of the class on the connection is still owed its start.
fn startsPending(slots: []const Server, conn: Handle, control: bool) bool {
    for (slots[ReceivePlan.first(conn.index, @enumFromInt(0))..][0..ReceivePlan.slots_per_peer]) |*slot| {
        if (!slot.admission.start_pending or !slot.request.running() or slot.request.protocol.isControl() != control) continue;
        if (std.meta.eql(slot.request.conn, conn)) return true;
    }
    return false;
}

/// Whether another `.ready` request of the slot's class on its connection has waited longer
/// for its start, by accept time and then slot order. Starts go to the longest waiter, so
/// while its identity keeps a limiter row and no other connection spends its starts, a
/// waiter is charged its start within one refill per request ahead of it.
fn startQueued(self: *const InboundAdmission, slots: []const Server, index: u16) bool {
    const slot = &slots[index];
    const peer = index / ReceivePlan.slots_per_peer;
    const first = @as(usize, peer) * ReceivePlan.slots_per_peer;
    var mask = self.peer_cursors[peer].ready_mask[@intFromBool(slot.request.protocol.isControl())];
    for (0..ReceivePlan.slots_per_peer) |_| {
        if (mask == 0) break;
        const other = first + @ctz(mask);
        mask &= mask - 1;
        const waiter = &slots[other];
        if (other == index or !waiter.admission.start_pending) continue;
        if (waiter.request.started_ms < slot.request.started_ms) return true;
        if (waiter.request.started_ms == slot.request.started_ms and other < index) return true;
    }
    return false;
}

pub fn chargeRejected(self: *InboundAdmission, owner: *ReqResp, engine: *Engine, slot: *const Server, now: Now) void {
    const request = &slot.request;
    const identity = engine.peerId(request.conn) orelse return;
    const decision = self.limiter.take(&identity, request.protocol, 1, slot.request_fork, now.mono_ms);
    if (decision == .allowed) return;
    owner.recordAdmissionRefusal(request.stream, request.protocol, switch (decision) {
        .allowed => unreachable,
        .peer_quota => .peer_quota,
        .global_quota => .global_quota,
        .identity_capacity => .identity_capacity,
    }, 1);
}

pub fn checkSlot(self: *const InboundAdmission, slot: *const Server, index: u16) void {
    const bit = @as(u64, 1) << @intCast(index % ReceivePlan.slots_per_peer);
    const class: u1 = @intFromBool(slot.request.protocol.isControl());
    const waiting = slot.request.running() and slot.state == .ready;
    const cursor = &self.peer_cursors[index / ReceivePlan.slots_per_peer];
    assert((cursor.ready_mask[class] & bit != 0) == waiting);
    if (waiting) assert(PeerCursor.linked(self.peer_cursors, class, index / ReceivePlan.slots_per_peer));
    if (waiting and slot.admission.wait == .none) assert(self.pending);
}

/// Per connection index: where the next admission attempt starts, the `.ready` inbound slots and
/// the admission list links, per class (application, control).
const PeerCursor = struct {
    admission: [2]u8 = @splat(0),
    ready_mask: [2]u64 = @splat(0),
    application_link: index_list.Link = .{},
    control_link: index_list.Link = .{},

    const link_fields = [2][]const u8{ "application_link", "control_link" };

    fn linked(rows: []const PeerCursor, class: u1, peer: u32) bool {
        return if (class == 0) rows[peer].application_link.linked else rows[peer].control_link.linked;
    }
};

comptime {
    assert(ReceivePlan.slots_per_peer <= 64);
}

test {
    _ = @import("inbound_admission_test.zig");
}
