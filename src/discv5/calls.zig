const std = @import("std");
const message = @import("wire/message.zig");
const constants = @import("wire/constants.zig");
const types = @import("types.zig");

pub const capacity_max: usize = 256;

pub const Error = std.mem.Allocator.Error || message.Error || error{
    CallExpired,
    GenerationExhausted,
    HandshakeAttempted,
    InvalidCapacity,
    InvalidNodeCount,
    InvalidRequest,
    InvalidResponseCount,
    NonceInUse,
    PeerBusy,
    RequestIdMismatch,
    RequestTooLarge,
    StaleHandle,
    TableFull,
    UnexpectedResponse,
    UnknownCall,
};

pub const Handle = struct {
    index: u16,
    generation: u64,
};

pub const Response = union(enum) {
    pong: message.Pong,
    nodes: message.Nodes,
    talk_response: message.TalkResponse,
};

pub const Owner = enum {
    caller,
    routing_revalidation,
};

pub const Matched = struct {
    handle: Handle,
    response: Response,
    terminal: bool,
};

pub const AcceptedNodes = std.StaticBitSet(types.findnode_result_max);

pub const MatchResult = struct {
    matched: Matched,
    accepted_nodes: AcceptedNodes = AcceptedNodes.initEmpty(),
    owner: Owner,
};

pub const Expired = struct {
    handle: Handle,
    peer: types.Endpoint,
    owner: Owner,
};

const NodesState = struct {
    distances: std.StaticBitSet(types.distance_count),
    seen: [types.findnode_result_max]types.NodeId = undefined,
    accepted: u8 = 0,
    total: u8 = 0,
    received: u8 = 0,
};

const Expected = union(enum) {
    pong,
    nodes: NodesState,
    talk_response,
};

const Entry = struct {
    generation: u64,
    peer: types.Endpoint,
    request_id: message.RequestId,
    expected: Expected,
    owner: Owner,
    request: [constants.ordinary_plaintext_size_max]u8,
    request_length: u16,
    sent_nonce: [constants.nonce_size]u8 = undefined,
    sent: bool = false,
    deadline_ms: u64,
    handshake_attempted: bool = false,
    remote_public_key: [33]u8,
};

pub const Table = struct {
    allocator: std.mem.Allocator,
    entries: []?Entry,
    next_generations: []u64,

    pub fn init(
        self: *Table,
        allocator: std.mem.Allocator,
        capacity: usize,
    ) Error!void {
        if (capacity == 0 or capacity > capacity_max) return Error.InvalidCapacity;

        const entries = try allocator.alloc(?Entry, capacity);
        errdefer allocator.free(entries);
        const next_generations = try allocator.alloc(u64, capacity);

        @memset(entries, null);
        @memset(next_generations, 1);
        self.* = .{
            .allocator = allocator,
            .entries = entries,
            .next_generations = next_generations,
        };
    }

    pub fn deinit(self: *Table) void {
        for (self.entries) |*entry| clearEntry(entry);
        self.allocator.free(self.next_generations);
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn begin(
        self: *Table,
        peer: types.Endpoint,
        remote_public_key: *const [33]u8,
        request: *const message.Message,
        deadline_ms: u64,
        request_capacity: usize,
        owner: Owner,
    ) Error!Handle {
        if (self.findNode(&peer.node_id) != null) return Error.PeerBusy;
        const expected = try expectedResponse(request);
        var encoded: [constants.ordinary_plaintext_size_max]u8 = undefined;
        defer std.crypto.secureZero(u8, &encoded);
        const request_bytes = try request.encode(&encoded);
        if (request_bytes.len > request_capacity) return Error.RequestTooLarge;
        const index = try self.availableIndex();
        const generation = self.next_generations[index];
        const successor = std.math.add(u64, generation, 1) catch
            return Error.GenerationExhausted;
        var entry = Entry{
            .generation = generation,
            .peer = peer,
            .request_id = request.requestId(),
            .expected = expected,
            .owner = owner,
            .request = undefined,
            .request_length = @intCast(request_bytes.len),
            .deadline_ms = deadline_ms,
            .remote_public_key = remote_public_key.*,
        };
        @memcpy(entry.request[0..request_bytes.len], request_bytes);
        self.entries[index] = entry;
        self.next_generations[index] = successor;
        return .{ .index = @intCast(index), .generation = generation };
    }

    pub fn remotePublicKey(self: *const Table, handle: Handle) ?[33]u8 {
        const entry = self.get(handle) orelse return null;
        return entry.remote_public_key;
    }

    pub fn requestBytes(self: *const Table, handle: Handle) ?[]const u8 {
        const entry = self.get(handle) orelse return null;
        return entry.request[0..entry.request_length];
    }

    pub fn endpoint(self: *const Table, handle: Handle) ?types.Endpoint {
        const entry = self.get(handle) orelse return null;
        return entry.peer;
    }

    pub fn markSent(
        self: *Table,
        handle: Handle,
        sent_nonce: *const [constants.nonce_size]u8,
        deadline_ms: u64,
    ) Error!void {
        const entry = self.getMut(handle) orelse return Error.StaleHandle;
        if (self.findNonce(entry.peer.address, sent_nonce, handle) != null)
            return Error.NonceInUse;
        entry.sent_nonce = sent_nonce.*;
        entry.sent = true;
        entry.deadline_ms = deadline_ms;
    }

    pub fn acceptChallenge(
        self: *Table,
        address: types.Address,
        nonce: *const [constants.nonce_size]u8,
        now_ms: u64,
    ) Error!?Handle {
        const index = self.findNonce(address, nonce, null) orelse return null;
        const entry = &self.entries[index].?;
        if (now_ms >= entry.deadline_ms) return null;
        if (entry.handshake_attempted) return Error.HandshakeAttempted;
        entry.handshake_attempted = true;
        return .{ .index = @intCast(index), .generation = entry.generation };
    }

    pub fn match(
        self: *const Table,
        peer: types.Endpoint,
        response: *const message.Message,
        now_ms: u64,
    ) Error!Handle {
        const index = self.findPeer(peer) orelse return Error.UnknownCall;
        const entry = &self.entries[index].?;
        if (now_ms >= entry.deadline_ms) return Error.CallExpired;
        const response_id = response.requestId();
        if (!std.mem.eql(u8, entry.request_id.slice(), response_id.slice()))
            return Error.RequestIdMismatch;
        if (!expectsResponse(entry.expected, response)) return Error.UnexpectedResponse;
        if (response.* == .nodes) {
            try validateNodesHeader(&entry.expected.nodes, response.nodes.total);
        }
        return .{ .index = @intCast(index), .generation = entry.generation };
    }

    pub fn accept(
        self: *Table,
        handle: Handle,
        response: *const message.Message,
        node_ids: []const types.NodeId,
    ) Error!MatchResult {
        const entry = self.getMut(handle) orelse return Error.StaleHandle;
        if (!expectsResponse(entry.expected, response)) return Error.UnexpectedResponse;
        const index: usize = handle.index;
        return switch (response.*) {
            .pong => |pong| self.complete(index, handle, .{ .pong = pong }),
            .talk_response => |talk| self.complete(
                index,
                handle,
                .{ .talk_response = talk },
            ),
            .nodes => |nodes| try self.acceptNodes(index, handle, nodes, node_ids),
            else => unreachable,
        };
    }

    pub fn cancel(self: *Table, handle: Handle) bool {
        const index: usize = handle.index;
        if (index >= self.entries.len) return false;
        const entry = self.entries[index] orelse return false;
        if (entry.generation != handle.generation) return false;
        clearEntry(&self.entries[index]);
        return true;
    }

    pub fn expire(self: *Table, now_ms: u64, out: []Expired) usize {
        var expired_count: usize = 0;
        for (self.entries, 0..) |*slot, index| {
            if (expired_count == out.len) break;
            const entry = slot.* orelse continue;
            if (now_ms < entry.deadline_ms) continue;
            out[expired_count] = .{
                .handle = .{
                    .index = @intCast(index),
                    .generation = entry.generation,
                },
                .peer = entry.peer,
                .owner = entry.owner,
            };
            expired_count += 1;
            clearEntry(slot);
        }
        return expired_count;
    }

    pub fn count(self: *const Table) usize {
        var result: usize = 0;
        for (self.entries) |entry| if (entry != null) {
            result += 1;
        };
        return result;
    }

    fn acceptNodes(
        self: *Table,
        index: usize,
        handle: Handle,
        nodes: message.Nodes,
        node_ids: []const types.NodeId,
    ) Error!MatchResult {
        if (node_ids.len != nodes.enrs.len or node_ids.len > types.findnode_result_max)
            return Error.InvalidNodeCount;
        const state = &self.entries[index].?.expected.nodes;
        try validateNodesHeader(state, nodes.total);
        const total: u8 = @intCast(nodes.total);

        var accepted_nodes = AcceptedNodes.initEmpty();
        for (node_ids, 0..) |*node_id, node_index| {
            if (state.accepted == types.findnode_result_max) break;
            const distance = types.logDistance(&self.entries[index].?.peer.node_id, node_id);
            if (!state.distances.isSet(distance)) continue;
            if (containsNode(state.seen[0..state.accepted], node_id)) continue;
            state.seen[state.accepted] = node_id.*;
            state.accepted += 1;
            accepted_nodes.set(node_index);
        }

        state.total = total;
        state.received += 1;
        const terminal = state.received == total or
            state.accepted == types.findnode_result_max;
        const result = MatchResult{
            .matched = .{
                .handle = handle,
                .response = .{ .nodes = nodes },
                .terminal = terminal,
            },
            .accepted_nodes = accepted_nodes,
            .owner = self.entries[index].?.owner,
        };
        if (terminal) clearEntry(&self.entries[index]);
        return result;
    }

    fn complete(
        self: *Table,
        index: usize,
        handle: Handle,
        response: Response,
    ) MatchResult {
        const owner = self.entries[index].?.owner;
        clearEntry(&self.entries[index]);
        return .{ .matched = .{
            .handle = handle,
            .response = response,
            .terminal = true,
        }, .owner = owner };
    }

    fn availableIndex(self: *const Table) Error!usize {
        var saw_exhausted = false;
        for (self.entries, self.next_generations, 0..) |entry, generation, index| {
            if (entry != null) continue;
            if (generation == std.math.maxInt(u64)) {
                saw_exhausted = true;
                continue;
            }
            return index;
        }
        return if (saw_exhausted) Error.GenerationExhausted else Error.TableFull;
    }

    fn get(self: *const Table, handle: Handle) ?*const Entry {
        const index: usize = handle.index;
        if (index >= self.entries.len) return null;
        const entry = if (self.entries[index]) |*value| value else return null;
        if (entry.generation != handle.generation) return null;
        return entry;
    }

    fn getMut(self: *Table, handle: Handle) ?*Entry {
        const index: usize = handle.index;
        if (index >= self.entries.len) return null;
        const entry = if (self.entries[index]) |*value| value else return null;
        if (entry.generation != handle.generation) return null;
        return entry;
    }

    fn findPeer(self: *const Table, peer: types.Endpoint) ?usize {
        for (self.entries, 0..) |entry, index| {
            const stored = entry orelse continue;
            if (!stored.sent) continue;
            if (std.meta.eql(stored.peer, peer)) return index;
        }
        return null;
    }

    fn findNode(self: *const Table, node_id: *const types.NodeId) ?usize {
        for (self.entries, 0..) |entry, index| {
            const stored = entry orelse continue;
            if (std.mem.eql(u8, &stored.peer.node_id, node_id)) return index;
        }
        return null;
    }

    fn findNonce(
        self: *const Table,
        address: types.Address,
        nonce: *const [constants.nonce_size]u8,
        excluded: ?Handle,
    ) ?usize {
        for (self.entries, 0..) |entry, index| {
            const stored = entry orelse continue;
            if (!stored.sent) continue;
            if (excluded) |handle| {
                if (index == handle.index and stored.generation == handle.generation) continue;
            }
            if (!std.meta.eql(stored.peer.address, address)) continue;
            if (std.mem.eql(u8, &stored.sent_nonce, nonce)) return index;
        }
        return null;
    }
};

fn expectedResponse(request: *const message.Message) Error!Expected {
    return switch (request.*) {
        .ping => .pong,
        .find_node => |find_node| blk: {
            if (find_node.distances.len > types.distance_count)
                return Error.InvalidMessage;
            var distances = std.StaticBitSet(types.distance_count).initEmpty();
            for (find_node.distances) |distance| {
                if (distance > types.distance_max) return Error.InvalidMessage;
                distances.set(distance);
            }
            break :blk .{ .nodes = .{ .distances = distances } };
        },
        .talk_request => .talk_response,
        else => Error.InvalidRequest,
    };
}

fn expectsResponse(expected: Expected, response: *const message.Message) bool {
    return switch (response.*) {
        .pong => expected == .pong,
        .nodes => expected == .nodes,
        .talk_response => expected == .talk_response,
        else => false,
    };
}

fn containsNode(nodes: []const types.NodeId, target: *const types.NodeId) bool {
    for (nodes) |*node| if (std.mem.eql(u8, node, target)) return true;
    return false;
}

fn validateNodesHeader(state: *const NodesState, total_value: u64) Error!void {
    if (total_value == 0 or total_value > types.findnode_response_packets_max)
        return Error.InvalidResponseCount;
    const total: u8 = @intCast(total_value);
    if (state.total != 0 and state.total != total) return Error.InvalidResponseCount;
    if (state.received >= total) return Error.InvalidResponseCount;
}

fn clearEntry(entry: *?Entry) void {
    if (entry.*) |*stored| {
        std.crypto.secureZero(u8, stored.request[0..stored.request_length]);
    }
    entry.* = null;
}

comptime {
    std.debug.assert(@sizeOf(Entry) <= 2_048);
    std.debug.assert(@sizeOf(Table) <= 64);
}
