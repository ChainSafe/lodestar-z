//! A Lookup is one iterative FINDNODE walk toward a target. It holds only candidates and call
//! handles, while deadlines and response accumulation stay in the call table.

const std = @import("std");
const CallTable = @import("CallTable.zig");
const Engine = @import("Engine.zig");
const enr = @import("identity/enr.zig");
const RoutingTable = @import("RoutingTable.zig");
const types = @import("types.zig");
const message = @import("wire/message.zig");

pub const result_max: usize = RoutingTable.bucket_size;
pub const parallelism: usize = 3;
pub const request_distance_count: usize = 3;
pub const candidate_capacity: usize = RoutingTable.table_capacity;
pub const discovered_port_min: u16 = 1_025;

pub const Error = Engine.Error || error{
    InvalidSeed,
    TooManySeeds,
    UnexpectedResponse,
    UnknownQuery,
};

pub const Started = struct {
    call: Engine.StartResult,
    peer: types.Endpoint,
};

const State = union(enum) {
    unqueried,
    waiting: CallTable.Handle,
    succeeded,
    failed,
};

pub const Candidate = struct {
    peer: types.Endpoint,
    record: enr.Record,
    state: State,
};

pub const Candidates = [candidate_capacity]Candidate;

const Lookup = @This();

local_id: types.NodeId,
target: types.NodeId,
candidates: *Candidates,
candidate_count: u16,
waiting_count: u8,
queries_started: u16,
finished: bool,

/// Borrows `candidates` for the life of the lookup and allocates nothing.
pub fn init(
    self: *Lookup,
    candidates: *Candidates,
    local_id: types.NodeId,
    target: types.NodeId,
    seeds: []const RoutingTable.Entry,
) Error!void {
    if (seeds.len > result_max) return Error.TooManySeeds;
    self.* = .{
        .local_id = local_id,
        .target = target,
        .candidates = candidates,
        .candidate_count = 0,
        .waiting_count = 0,
        .queries_started = 0,
        .finished = false,
    };
    for (seeds) |*seed| try self.addSeed(seed);
}

pub fn candidateCount(self: *const Lookup) usize {
    return self.candidate_count;
}

pub fn waitingCount(self: *const Lookup) usize {
    std.debug.assert(self.waiting_count <= parallelism);
    return self.waiting_count;
}

pub fn isFinished(self: *const Lookup) bool {
    return self.finished;
}

pub fn ownsCall(self: *const Lookup, handle: CallTable.Handle) bool {
    return self.waitingIndex(handle) != null;
}

/// Starts at most one call, to the closest unqueried candidate that could still improve the
/// sixteen best results. Returns null when nothing can start, and the lookup is finished once
/// that happens with no calls waiting.
pub fn startNext(
    self: *Lookup,
    core: *Engine,
    out: []u8,
    request_id: message.RequestId,
    now_ms: u64,
    entropy: *const Engine.StartEntropy,
) Error!?Started {
    if (self.finished or self.waiting_count == parallelism) return null;
    const index = self.nextCandidateIndex() orelse {
        if (self.waiting_count == 0) self.finished = true;
        return null;
    };
    const candidate = &self.candidates[index];
    const distances = requestDistances(&self.target, &candidate.peer.node_id);
    const request = message.Message{ .find_node = .{
        .request_id = request_id,
        .distances = &distances,
    } };
    const started = try core.startCall(
        out,
        candidate.peer,
        &candidate.record,
        &request,
        now_ms,
        entropy,
    );
    candidate.state = .{ .waiting = started.handle };
    self.waiting_count += 1;
    self.queries_started += 1;
    std.debug.assert(self.queries_started <= candidate_capacity);
    return .{ .call = started, .peer = candidate.peer };
}

pub fn knownRecord(
    self: *const Lookup,
    handle: CallTable.Handle,
) ?*const enr.Record {
    const index = self.waitingIndex(handle) orelse return null;
    return &self.candidates[index].record;
}

/// Adds discovered records as candidates and, on the terminal fragment, confirms the responder
/// in routing.
pub fn onResponse(
    self: *Lookup,
    core: *Engine,
    response: *const Engine.AuthenticatedResponse,
    now_ms: u64,
) Error!void {
    if (response.matched.response != .nodes) return Error.UnexpectedResponse;
    const index = self.waitingIndex(response.matched.handle) orelse
        return Error.UnknownQuery;
    if (!std.meta.eql(response.peer, self.candidates[index].peer))
        return Error.UnknownQuery;
    const source = response.peer.address;
    for (response.node_records) |*record| self.addDiscovered(record, source);
    if (!response.matched.terminal) return;

    self.candidates[index].state = .succeeded;
    self.waiting_count -= 1;
    const candidate = &self.candidates[index];
    _ = core.confirmPeer(
        &candidate.peer,
        &candidate.record,
        now_ms,
    ) catch return;
}

pub fn onFailure(
    self: *Lookup,
    core: *Engine,
    handle: CallTable.Handle,
) Error!void {
    const index = self.waitingIndex(handle) orelse return Error.UnknownQuery;
    _ = core.cancelCall(handle);
    self.candidates[index].state = .failed;
    self.waiting_count -= 1;
}

pub fn cancel(self: *Lookup, core: *Engine) void {
    for (self.activeCandidatesMut()) |*candidate| switch (candidate.state) {
        .waiting => |handle| {
            _ = core.cancelCall(handle);
            candidate.state = .failed;
        },
        else => {},
    };
    self.waiting_count = 0;
    self.finished = true;
}

pub fn results(self: *const Lookup, out: []enr.Record) []enr.Record {
    const bounded = out[0..@min(out.len, result_max)];
    var length: usize = 0;
    for (self.activeCandidates()) |*candidate| {
        if (candidate.state != .succeeded) continue;
        length = types.insertClosest(
            enr.Record,
            recordNodeId,
            bounded,
            length,
            candidate.record,
            &self.target,
        );
    }
    return bounded[0..length];
}

fn addSeed(self: *Lookup, seed: *const RoutingTable.Entry) Error!void {
    if (!std.mem.eql(u8, &seed.peer.node_id, &seed.record.node_id))
        return Error.InvalidSeed;
    if (std.mem.eql(u8, &seed.peer.node_id, &self.local_id)) return;
    if (self.findCandidate(&seed.peer.node_id) != null) return;
    self.appendCandidate(seed.peer, &seed.record);
}

fn addDiscovered(
    self: *Lookup,
    record: *const enr.Record,
    source: types.Address,
) void {
    if (std.mem.eql(u8, &record.node_id, &self.local_id)) return;
    const address = record.endpoint() orelse return;
    if (address.port() < discovered_port_min or
        !RoutingTable.relayAllowed(source, address)) return;
    if (self.findCandidate(&record.node_id)) |index| {
        const candidate = &self.candidates[index];
        if (candidate.state == .unqueried and
            record.sequence > candidate.record.sequence)
        {
            candidate.peer.address = address;
            candidate.record = record.*;
        }
        return;
    }
    if (self.candidate_count == candidate_capacity) return;
    self.appendCandidate(.{ .node_id = record.node_id, .address = address }, record);
}

fn appendCandidate(
    self: *Lookup,
    peer: types.Endpoint,
    record: *const enr.Record,
) void {
    std.debug.assert(self.candidate_count < candidate_capacity);
    self.candidates[self.candidate_count] = .{
        .peer = peer,
        .record = record.*,
        .state = .unqueried,
    };
    self.candidate_count += 1;
}

fn nextCandidateIndex(self: *const Lookup) ?usize {
    const boundary = self.successBoundary();
    var selected: ?usize = null;
    for (self.activeCandidates(), 0..) |*candidate, index| {
        if (candidate.state != .unqueried) continue;
        if (boundary) |node_id| {
            if (!types.xorCloser(&candidate.peer.node_id, &node_id, &self.target))
                continue;
        }
        if (selected) |previous| {
            if (!types.xorCloser(
                &candidate.peer.node_id,
                &self.candidates[previous].peer.node_id,
                &self.target,
            )) continue;
        }
        selected = index;
    }
    return selected;
}

// The sixteenth-closest success bounds the result set. A candidate farther away cannot improve
// it.
fn successBoundary(self: *const Lookup) ?types.NodeId {
    var closest: [result_max]*const Candidate = undefined;
    var length: usize = 0;
    for (self.activeCandidates()) |*candidate| {
        if (candidate.state != .succeeded) continue;
        length = types.insertClosest(
            *const Candidate,
            candidateNodeId,
            &closest,
            length,
            candidate,
            &self.target,
        );
    }
    if (length < result_max) return null;
    return closest[result_max - 1].peer.node_id;
}

fn findCandidate(
    self: *const Lookup,
    node_id: *const types.NodeId,
) ?usize {
    for (self.activeCandidates(), 0..) |*candidate, index| {
        if (std.mem.eql(u8, &candidate.peer.node_id, node_id)) return index;
    }
    return null;
}

fn waitingIndex(self: *const Lookup, handle: CallTable.Handle) ?usize {
    for (self.activeCandidates(), 0..) |*candidate, index| switch (candidate.state) {
        .waiting => |stored| if (std.meta.eql(stored, handle)) return index,
        else => {},
    };
    return null;
}

fn activeCandidates(self: *const Lookup) []const Candidate {
    return self.candidates[0..self.candidate_count];
}

fn activeCandidatesMut(self: *Lookup) []Candidate {
    return self.candidates[0..self.candidate_count];
}

/// Returns the target's distance from `destination` together with the nearest distance on
/// either side, so one query covers the bucket and its neighbours.
pub fn requestDistances(
    target: *const types.NodeId,
    destination: *const types.NodeId,
) [request_distance_count]u16 {
    const center: usize = types.logDistance(target, destination);
    var result: [request_distance_count]u16 = undefined;
    result[0] = @intCast(center);
    var count: usize = 1;
    for (1..257) |offset| {
        if (count == result.len) break;
        if (center + offset <= 256) {
            result[count] = @intCast(center + offset);
            count += 1;
        }
        if (count == result.len) break;
        if (center > offset) {
            result[count] = @intCast(center - offset);
            count += 1;
        }
    }
    std.debug.assert(count == result.len);
    return result;
}

fn recordNodeId(record: *const enr.Record) *const types.NodeId {
    return &record.node_id;
}

fn candidateNodeId(candidate: *const *const Candidate) *const types.NodeId {
    return &candidate.*.peer.node_id;
}

comptime {
    std.debug.assert(result_max == 16);
    std.debug.assert(candidate_capacity == 272);
    std.debug.assert(parallelism == request_distance_count);
    std.debug.assert(@sizeOf(Candidate) <= 512);
    std.debug.assert(@sizeOf(Lookup) <= 128);
}
