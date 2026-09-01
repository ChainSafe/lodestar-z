const std = @import("std");
const calls = @import("calls.zig");
const engine_mod = @import("engine.zig");
const enr = @import("identity/enr.zig");
const routing = @import("routing.zig");
const types = @import("types.zig");
const message = @import("wire/message.zig");

pub const result_max: usize = routing.bucket_size;
pub const parallelism: usize = 3;
pub const request_distance_count: usize = 3;
pub const candidate_capacity: usize = routing.table_capacity;
pub const discovered_port_min: u16 = 1_025;

pub const Error = std.mem.Allocator.Error || engine_mod.Error || error{
    InvalidSeed,
    TooManySeeds,
    UnexpectedResponse,
    UnknownQuery,
};

pub const Started = struct {
    call: engine_mod.StartResult,
    peer: types.Endpoint,
};

const State = union(enum) {
    unqueried,
    waiting: calls.Handle,
    succeeded,
    failed,
};

const Candidate = struct {
    peer: types.Endpoint,
    record: enr.Record,
    state: State,
};

pub const Lookup = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    local_id: types.NodeId,
    target: types.NodeId,
    candidates: []Candidate,
    candidate_count: u16,
    waiting_count: u8,
    queries_started: u16,
    finished: bool,

    pub fn init(
        self: *Self,
        allocator: std.mem.Allocator,
        local_id: types.NodeId,
        target: types.NodeId,
        seeds: []const routing.Entry,
    ) Error!void {
        if (seeds.len > result_max) return Error.TooManySeeds;
        const candidates = try allocator.alloc(Candidate, candidate_capacity);
        self.* = .{
            .allocator = allocator,
            .local_id = local_id,
            .target = target,
            .candidates = candidates,
            .candidate_count = 0,
            .waiting_count = 0,
            .queries_started = 0,
            .finished = false,
        };
        errdefer self.deinit();
        for (seeds) |*seed| try self.addSeed(seed);
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.candidates);
        self.* = undefined;
    }

    pub fn candidateCount(self: *const Self) usize {
        return self.candidate_count;
    }

    pub fn waitingCount(self: *const Self) usize {
        std.debug.assert(self.waiting_count <= parallelism);
        return self.waiting_count;
    }

    pub fn isFinished(self: *const Self) bool {
        return self.finished;
    }

    pub fn startNext(
        self: *Self,
        core: *engine_mod.Engine,
        out: []u8,
        request_id: message.RequestId,
        now_ms: u64,
        entropy: engine_mod.StartEntropy,
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
        const started = try core.startCallKnown(
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
        self: *const Self,
        handle: calls.Handle,
    ) ?*const enr.Record {
        const index = self.waitingIndex(handle) orelse return null;
        return &self.candidates[index].record;
    }

    pub fn onResponse(
        self: *Self,
        core: *engine_mod.Engine,
        response: *const engine_mod.AuthenticatedResponse,
        now_ms: u64,
    ) Error!?types.NodeId {
        if (response.matched.response != .nodes) return Error.UnexpectedResponse;
        const index = self.waitingIndex(response.matched.handle) orelse
            return Error.UnknownQuery;
        if (!types.Endpoint.eql(response.peer, self.candidates[index].peer))
            return Error.UnknownQuery;
        const source = response.peer.address;
        for (response.node_records) |*record| self.addDiscovered(record, source);
        if (!response.matched.terminal) return null;

        self.candidates[index].state = .succeeded;
        self.waiting_count -= 1;
        const candidate = &self.candidates[index];
        const update = core.confirmPeer(
            &candidate.peer,
            &candidate.record,
            now_ms,
        ) catch return null;
        return switch (update) {
            .pending => |node_id| node_id,
            else => null,
        };
    }

    pub fn onFailure(
        self: *Self,
        core: *engine_mod.Engine,
        handle: calls.Handle,
    ) Error!void {
        const index = self.waitingIndex(handle) orelse return Error.UnknownQuery;
        _ = core.cancelCall(handle);
        self.candidates[index].state = .failed;
        self.waiting_count -= 1;
    }

    pub fn cancel(self: *Self, core: *engine_mod.Engine) void {
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

    pub fn results(self: *const Self, out: []enr.Record) []enr.Record {
        const limit = @min(out.len, result_max);
        var result_length: usize = 0;
        for (self.activeCandidates()) |*candidate| {
            if (candidate.state != .succeeded) continue;
            var position: usize = 0;
            while (position < result_length and !types.xorCloser(
                &candidate.peer.node_id,
                &out[position].node_id,
                &self.target,
            )) : (position += 1) {}
            if (position == limit) continue;
            if (result_length < limit) result_length += 1;
            std.mem.copyBackwards(
                enr.Record,
                out[position + 1 .. result_length],
                out[position .. result_length - 1],
            );
            out[position] = candidate.record;
        }
        return out[0..result_length];
    }

    fn addSeed(self: *Self, seed: *const routing.Entry) Error!void {
        if (!std.mem.eql(u8, &seed.peer.node_id, &seed.record.node_id))
            return Error.InvalidSeed;
        if (std.mem.eql(u8, &seed.peer.node_id, &self.local_id)) return;
        if (self.findCandidate(&seed.peer.node_id) != null) return;
        self.appendCandidate(seed.peer, &seed.record);
    }

    fn addDiscovered(
        self: *Self,
        record: *const enr.Record,
        source: types.Address,
    ) void {
        if (std.mem.eql(u8, &record.node_id, &self.local_id)) return;
        const address = record.endpoint() orelse return;
        if (addressPort(address) < discovered_port_min or
            !types.relayAllowed(source, address)) return;
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
        self: *Self,
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

    fn nextCandidateIndex(self: *const Self) ?usize {
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

    fn successBoundary(self: *const Self) ?types.NodeId {
        var closest: [result_max]usize = undefined;
        var length: usize = 0;
        for (self.activeCandidates(), 0..) |*candidate, index| {
            if (candidate.state != .succeeded) continue;
            var position: usize = 0;
            while (position < length and !types.xorCloser(
                &candidate.peer.node_id,
                &self.candidates[closest[position]].peer.node_id,
                &self.target,
            )) : (position += 1) {}
            if (position == result_max) continue;
            if (length < result_max) length += 1;
            std.mem.copyBackwards(
                usize,
                closest[position + 1 .. length],
                closest[position .. length - 1],
            );
            closest[position] = index;
        }
        if (length < result_max) return null;
        return self.candidates[closest[result_max - 1]].peer.node_id;
    }

    fn findCandidate(
        self: *const Self,
        node_id: *const types.NodeId,
    ) ?usize {
        for (self.activeCandidates(), 0..) |*candidate, index| {
            if (std.mem.eql(u8, &candidate.peer.node_id, node_id)) return index;
        }
        return null;
    }

    fn waitingIndex(self: *const Self, handle: calls.Handle) ?usize {
        for (self.activeCandidates(), 0..) |*candidate, index| switch (candidate.state) {
            .waiting => |stored| if (handleEqual(stored, handle)) return index,
            else => {},
        };
        return null;
    }

    fn activeCandidates(self: *const Self) []const Candidate {
        return self.candidates[0..self.candidate_count];
    }

    fn activeCandidatesMut(self: *Self) []Candidate {
        return self.candidates[0..self.candidate_count];
    }
};

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

fn addressPort(address: types.Address) u16 {
    return switch (address) {
        inline else => |value| value.port,
    };
}

fn handleEqual(left: calls.Handle, right: calls.Handle) bool {
    return left.index == right.index and left.generation == right.generation;
}

comptime {
    std.debug.assert(result_max == 16);
    std.debug.assert(candidate_capacity == 272);
    std.debug.assert(parallelism == request_distance_count);
    std.debug.assert(@sizeOf(Candidate) <= 512);
    std.debug.assert(@sizeOf(Lookup) <= 128);
}
