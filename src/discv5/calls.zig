const std = @import("std");
const message = @import("wire/message.zig");
const constants = @import("wire/constants.zig");
const types = @import("types.zig");

pub const capacity_max: u16 = 64;
pub const nodes_response_packets_max: u8 = 16;

pub const Error = message.Error || error{
    GenerationExhausted,
    HandshakeAttempted,
    InvalidCapacity,
    InvalidResponseCount,
    NonceInUse,
    PeerBusy,
    RequestIdMismatch,
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

pub const Matched = struct {
    handle: Handle,
    response: Response,
    terminal: bool,
};

const Expected = enum {
    pong,
    nodes,
    talk_response,
};

const Entry = struct {
    generation: u64,
    peer: types.Endpoint,
    request_id: message.RequestId,
    expected: Expected,
    request: [constants.message_size_max]u8,
    request_length: u16,
    sent_nonce: [constants.nonce_size]u8 = undefined,
    sent: bool = false,
    deadline_ms: u64,
    nodes_total: u8 = 0,
    nodes_received: u8 = 0,
    handshake_attempted: bool = false,
};

pub const Table = struct {
    entries: [capacity_max]?Entry = [_]?Entry{null} ** capacity_max,
    next_generations: [capacity_max]u64 = [_]u64{1} ** capacity_max,
    capacity: u16,

    pub fn init(self: *Table, capacity: u16) Error!void {
        if (capacity == 0 or capacity > capacity_max) return Error.InvalidCapacity;
        self.* = .{ .capacity = capacity };
    }

    pub fn begin(
        self: *Table,
        peer: types.Endpoint,
        request: *const message.Message,
        deadline_ms: u64,
    ) Error!Handle {
        if (self.findNode(&peer.node_id) != null) return Error.PeerBusy;
        const expected = try expectedResponse(request);
        var encoded: [constants.message_size_max]u8 = undefined;
        const request_bytes = try request.encode(&encoded);
        const index = try self.availableIndex();
        const generation = self.next_generations[index];
        const successor = std.math.add(u64, generation, 1) catch
            return Error.GenerationExhausted;
        var entry = Entry{
            .generation = generation,
            .peer = peer,
            .request_id = request.requestId(),
            .expected = expected,
            .request = undefined,
            .request_length = @intCast(request_bytes.len),
            .deadline_ms = deadline_ms,
        };
        @memcpy(entry.request[0..request_bytes.len], request_bytes);
        self.entries[index] = entry;
        self.next_generations[index] = successor;
        return .{ .index = @intCast(index), .generation = generation };
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
        if (self.findNonceExcept(entry.peer.address, sent_nonce, handle) != null)
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
        const index = self.findNonce(address, nonce) orelse return null;
        const entry = &self.entries[index].?;
        if (now_ms >= entry.deadline_ms) return null;
        if (entry.handshake_attempted) return Error.HandshakeAttempted;
        entry.handshake_attempted = true;
        return .{ .index = @intCast(index), .generation = entry.generation };
    }

    pub fn accept(
        self: *Table,
        peer: types.Endpoint,
        response: *const message.Message,
    ) Error!Matched {
        const index = self.findPeer(peer) orelse return Error.UnknownCall;
        const entry = &self.entries[index].?;
        const response_id = response.requestId();
        if (!std.mem.eql(u8, entry.request_id.slice(), response_id.slice()))
            return Error.RequestIdMismatch;
        const handle = Handle{ .index = @intCast(index), .generation = entry.generation };
        return switch (response.*) {
            .pong => |pong| self.complete(index, handle, .{ .pong = pong }),
            .talk_response => |talk| self.complete(
                index,
                handle,
                .{ .talk_response = talk },
            ),
            .nodes => |nodes| try self.acceptNodes(index, handle, nodes),
            else => Error.UnexpectedResponse,
        };
    }

    pub fn cancel(self: *Table, handle: Handle) bool {
        const index: usize = handle.index;
        if (index >= self.capacity) return false;
        const entry = self.entries[index] orelse return false;
        if (entry.generation != handle.generation) return false;
        self.entries[index] = null;
        return true;
    }

    pub fn expire(self: *Table, now_ms: u64, out: []Handle) usize {
        var expired_count: usize = 0;
        for (self.activeEntries(), 0..) |*slot, index| {
            if (expired_count == out.len) break;
            const entry = slot.* orelse continue;
            if (now_ms < entry.deadline_ms) continue;
            out[expired_count] = .{
                .index = @intCast(index),
                .generation = entry.generation,
            };
            expired_count += 1;
            slot.* = null;
        }
        return expired_count;
    }

    pub fn count(self: *const Table) usize {
        var result: usize = 0;
        for (self.activeEntriesConst()) |entry| if (entry != null) {
            result += 1;
        };
        return result;
    }

    fn acceptNodes(
        self: *Table,
        index: usize,
        handle: Handle,
        nodes: message.Nodes,
    ) Error!Matched {
        if (self.entries[index].?.expected != .nodes)
            return Error.UnexpectedResponse;
        if (nodes.total == 0 or nodes.total > nodes_response_packets_max)
            return Error.InvalidResponseCount;
        const total: u8 = @intCast(nodes.total);
        const entry = &self.entries[index].?;
        if (entry.nodes_total != 0 and entry.nodes_total != total)
            return Error.InvalidResponseCount;
        if (entry.nodes_received >= total) return Error.InvalidResponseCount;
        const received = entry.nodes_received + 1;
        entry.nodes_total = total;
        entry.nodes_received = received;
        const terminal = received == total;
        const matched = Matched{
            .handle = handle,
            .response = .{ .nodes = nodes },
            .terminal = terminal,
        };
        if (terminal) self.entries[index] = null;
        return matched;
    }

    fn complete(
        self: *Table,
        index: usize,
        handle: Handle,
        response: Response,
    ) Error!Matched {
        const expected = self.entries[index].?.expected;
        const actual: Expected = switch (response) {
            .pong => .pong,
            .nodes => .nodes,
            .talk_response => .talk_response,
        };
        if (expected != actual) return Error.UnexpectedResponse;
        self.entries[index] = null;
        return .{ .handle = handle, .response = response, .terminal = true };
    }

    fn availableIndex(self: *const Table) Error!usize {
        var saw_exhausted = false;
        for (
            self.activeEntriesConst(),
            self.next_generations[0..self.capacity],
            0..,
        ) |entry, generation, index| {
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
        if (index >= self.capacity) return null;
        const entry = if (self.entries[index]) |*value| value else return null;
        if (entry.generation != handle.generation) return null;
        return entry;
    }

    fn getMut(self: *Table, handle: Handle) ?*Entry {
        const index: usize = handle.index;
        if (index >= self.capacity) return null;
        const entry = if (self.entries[index]) |*value| value else return null;
        if (entry.generation != handle.generation) return null;
        return entry;
    }

    fn findPeer(self: *const Table, peer: types.Endpoint) ?usize {
        for (self.activeEntriesConst(), 0..) |entry, index| {
            if (entry) |stored| {
                if (!stored.sent) continue;
                if (types.Endpoint.eql(stored.peer, peer)) return index;
            }
        }
        return null;
    }

    fn findNode(self: *const Table, node_id: *const types.NodeId) ?usize {
        for (self.activeEntriesConst(), 0..) |entry, index| {
            const stored = entry orelse continue;
            if (std.mem.eql(u8, &stored.peer.node_id, node_id)) return index;
        }
        return null;
    }

    fn findNonce(
        self: *const Table,
        address: types.Address,
        nonce: *const [constants.nonce_size]u8,
    ) ?usize {
        for (self.activeEntriesConst(), 0..) |entry, index| {
            const stored = entry orelse continue;
            if (!stored.sent) continue;
            if (!types.Address.eql(stored.peer.address, address)) continue;
            if (std.mem.eql(u8, &stored.sent_nonce, nonce)) return index;
        }
        return null;
    }

    fn findNonceExcept(
        self: *const Table,
        address: types.Address,
        nonce: *const [constants.nonce_size]u8,
        excluded: Handle,
    ) ?usize {
        for (self.activeEntriesConst(), 0..) |entry, index| {
            const stored = entry orelse continue;
            if (!stored.sent) continue;
            if (index == excluded.index and stored.generation == excluded.generation)
                continue;
            if (!types.Address.eql(stored.peer.address, address)) continue;
            if (std.mem.eql(u8, &stored.sent_nonce, nonce)) return index;
        }
        return null;
    }

    fn activeEntries(self: *Table) []?Entry {
        return self.entries[0..self.capacity];
    }

    fn activeEntriesConst(self: *const Table) []const ?Entry {
        return self.entries[0..self.capacity];
    }
};

fn expectedResponse(request: *const message.Message) Error!Expected {
    return switch (request.*) {
        .ping => .pong,
        .find_node => .nodes,
        .talk_request => .talk_response,
        else => Error.UnexpectedResponse,
    };
}

comptime {
    std.debug.assert(nodes_response_packets_max <= 16);
    std.debug.assert(@sizeOf(Entry) <= 1_408);
    std.debug.assert(@sizeOf(Table) <= 96 * 1_024);
}
