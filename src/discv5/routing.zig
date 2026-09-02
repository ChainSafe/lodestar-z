const std = @import("std");
const enr = @import("identity/enr.zig");
const types = @import("types.zig");

pub const bucket_size: usize = 16;
pub const bucket_count: usize = 17;
pub const table_capacity: usize = bucket_size * bucket_count;
pub const bucket_subnet_limit: usize = 2;
pub const table_subnet_limit: usize = 10;

pub const InitError = std.mem.Allocator.Error;

pub const Error = error{
    AddressLimit,
    InvalidDistance,
    InvalidRecord,
    InvalidRemoteRecord,
    NoPendingRevalidation,
    SelfEntry,
    TooManyDistances,
};

pub const Entry = struct {
    peer: types.Endpoint,
    record: enr.Record,
    last_verified_ms: u64,
};

pub const PutResult = union(enum) {
    inserted,
    refreshed,
    updated,
    pending: types.NodeId,
    pending_busy,
};

pub const ResolveResult = union(enum) {
    retained,
    replaced: types.NodeId,
};

const Pending = struct {
    entry: Entry,
    replace_id: types.NodeId,
};

pub const Table = struct {
    const Self = @This();

    local_id: types.NodeId,
    entries: []Entry,
    pending: []?Pending,
    counts: [bucket_count]u8,
    total: u16,

    pub fn init(
        self: *Self,
        allocator: std.mem.Allocator,
        local_id: types.NodeId,
    ) InitError!void {
        const entries = try allocator.alloc(Entry, table_capacity);
        errdefer allocator.free(entries);
        const pending = try allocator.alloc(?Pending, bucket_count);
        @memset(pending, null);
        self.* = .{
            .local_id = local_id,
            .entries = entries,
            .pending = pending,
            .counts = [_]u8{0} ** bucket_count,
            .total = 0,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.pending);
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn count(self: *const Self) usize {
        std.debug.assert(self.total <= table_capacity);
        return self.total;
    }

    pub fn pendingCount(self: *const Self) usize {
        var count_value: usize = 0;
        for (self.pending) |candidate| {
            if (candidate != null) count_value += 1;
        }
        return count_value;
    }

    pub fn revalidationTarget(self: *const Self) ?Entry {
        for (self.pending, 0..) |candidate, index| {
            const pending = candidate orelse continue;
            const position = self.findInBucket(index, &pending.replace_id) orelse
                unreachable;
            return self.bucketEntries(index)[position];
        }
        return null;
    }

    pub fn contains(self: *const Self, node_id: *const types.NodeId) bool {
        const index = bucketIndex(types.logDistance(&self.local_id, node_id));
        return self.findInBucket(index, node_id) != null;
    }

    pub fn get(self: *const Self, node_id: *const types.NodeId) ?Entry {
        const index = bucketIndex(types.logDistance(&self.local_id, node_id));
        const position = self.findInBucket(index, node_id) orelse return null;
        return self.bucketEntries(index)[position];
    }

    pub fn upsertVerified(
        self: *Self,
        peer: *const types.Endpoint,
        record: *const enr.Record,
        now_ms: u64,
    ) Error!PutResult {
        try validateEntry(&self.local_id, peer, record);
        const index = bucketIndex(types.logDistance(&self.local_id, &peer.node_id));
        if (self.findInBucket(index, &peer.node_id)) |position| {
            if (self.pending[index]) |candidate| {
                if (std.mem.eql(u8, &candidate.replace_id, &peer.node_id)) {
                    self.pending[index] = null;
                }
            }
            return self.updateExisting(index, position, peer, record, now_ms);
        }
        if (self.pending[index]) |*candidate| {
            if (!std.mem.eql(u8, &candidate.entry.peer.node_id, &peer.node_id)) {
                return .pending_busy;
            }
            if (record.sequence > candidate.entry.record.sequence) {
                try self.requireAddressCapacity(index, peer.address, &peer.node_id);
                candidate.entry.peer = peer.*;
                candidate.entry.record = record.*;
            }
            candidate.entry.last_verified_ms = now_ms;
            return .{ .pending = candidate.replace_id };
        }

        try self.requireAddressCapacity(index, peer.address, &peer.node_id);
        const bucket_length: usize = self.counts[index];
        if (bucket_length < bucket_size) {
            const offset = bucketOffset(index) + bucket_length;
            self.entries[offset] = makeEntry(peer, record, now_ms);
            self.counts[index] += 1;
            self.total += 1;
            std.debug.assert(self.total <= table_capacity);
            return .inserted;
        }

        const oldest = self.entries[bucketOffset(index)].peer.node_id;
        self.pending[index] = .{
            .entry = makeEntry(peer, record, now_ms),
            .replace_id = oldest,
        };
        return .{ .pending = oldest };
    }

    pub fn resolveRevalidation(
        self: *Self,
        node_id: *const types.NodeId,
        alive: bool,
        now_ms: u64,
    ) Error!ResolveResult {
        const index = bucketIndex(types.logDistance(&self.local_id, node_id));
        const candidate = self.pending[index] orelse return Error.NoPendingRevalidation;
        if (!std.mem.eql(u8, &candidate.replace_id, node_id))
            return Error.NoPendingRevalidation;
        const position = self.findInBucket(index, node_id) orelse
            return Error.NoPendingRevalidation;
        self.pending[index] = null;
        if (alive) {
            self.touch(index, position, now_ms);
            return .retained;
        }

        self.removeAt(index, position);
        const bucket_length: usize = self.counts[index];
        std.debug.assert(bucket_length < bucket_size);
        self.entries[bucketOffset(index) + bucket_length] = candidate.entry;
        self.counts[index] += 1;
        self.total += 1;
        std.debug.assert(self.total <= table_capacity);
        return .{ .replaced = candidate.entry.peer.node_id };
    }

    pub fn findNodes(
        self: *const Self,
        local_record: *const enr.Record,
        requester: ?types.Address,
        distances: []const u16,
        out: []enr.Record,
    ) Error![]enr.Record {
        std.debug.assert(std.mem.eql(u8, &local_record.node_id, &self.local_id));
        if (distances.len > types.distance_count) return Error.TooManyDistances;
        var requested = [_]bool{false} ** types.distance_count;
        for (distances) |distance| {
            if (distance > types.distance_max) return Error.InvalidDistance;
            requested[distance] = true;
        }

        const limit = @min(out.len, types.findnode_result_max);
        var result_length: usize = 0;
        if (requested[0] and result_length < limit and
            recordRelayAllowed(local_record, requester))
        {
            out[result_length] = local_record.*;
            result_length += 1;
        }
        for (1..types.distance_count) |distance| {
            if (result_length == limit) break;
            if (!requested[distance]) continue;
            const index = bucketIndex(@intCast(distance));
            const entries = self.bucketEntries(index);
            var position = entries.len;
            while (position > 0 and result_length < limit) {
                position -= 1;
                const entry = &entries[position];
                if (types.logDistance(&self.local_id, &entry.peer.node_id) != distance)
                    continue;
                if (requester) |source| {
                    if (!relayAllowed(source, entry.peer.address)) continue;
                }
                out[result_length] = entry.record;
                result_length += 1;
            }
        }
        return out[0..result_length];
    }

    pub fn closest(
        self: *const Self,
        target: *const types.NodeId,
        out: []Entry,
    ) []Entry {
        const bounded = out[0..@min(out.len, bucket_size)];
        var length: usize = 0;
        for (0..bucket_count) |index| {
            for (self.bucketEntries(index)) |entry| {
                length = types.insertClosest(Entry, entryNodeId, bounded, length, entry, target);
            }
        }
        return bounded[0..length];
    }

    fn updateExisting(
        self: *Self,
        bucket_index: usize,
        position: usize,
        peer: *const types.Endpoint,
        record: *const enr.Record,
        now_ms: u64,
    ) Error!PutResult {
        const offset = bucketOffset(bucket_index) + position;
        const previous_sequence = self.entries[offset].record.sequence;
        if (record.sequence > previous_sequence) {
            try self.requireAddressCapacity(bucket_index, peer.address, &peer.node_id);
            self.entries[offset].peer = peer.*;
            self.entries[offset].record = record.*;
        }
        self.touch(bucket_index, position, now_ms);
        return if (record.sequence > previous_sequence) .updated else .refreshed;
    }

    fn touch(
        self: *Self,
        bucket_index: usize,
        position: usize,
        now_ms: u64,
    ) void {
        const entries = self.bucketEntriesMut(bucket_index);
        std.debug.assert(position < entries.len);
        var entry = entries[position];
        entry.last_verified_ms = now_ms;
        std.mem.copyForwards(Entry, entries[position .. entries.len - 1], entries[position + 1 ..]);
        entries[entries.len - 1] = entry;
    }

    fn removeAt(self: *Self, bucket_index: usize, position: usize) void {
        const entries = self.bucketEntriesMut(bucket_index);
        std.debug.assert(position < entries.len);
        std.mem.copyForwards(Entry, entries[position .. entries.len - 1], entries[position + 1 ..]);
        self.counts[bucket_index] -= 1;
        self.total -= 1;
    }

    fn requireAddressCapacity(
        self: *const Self,
        bucket_index: usize,
        address: types.Address,
        exclude_id: *const types.NodeId,
    ) Error!void {
        var bucket_matches: usize = 0;
        var table_matches: usize = 0;
        for (0..bucket_count) |index| {
            for (self.bucketEntries(index)) |entry| {
                if (std.mem.eql(u8, &entry.peer.node_id, exclude_id)) continue;
                if (!sameSubnet(entry.peer.address, address)) continue;
                table_matches += 1;
                if (index == bucket_index) bucket_matches += 1;
            }
            if (self.pending[index]) |candidate| {
                if (std.mem.eql(u8, &candidate.entry.peer.node_id, exclude_id)) continue;
                if (!sameSubnet(candidate.entry.peer.address, address)) continue;
                table_matches += 1;
                if (index == bucket_index) bucket_matches += 1;
            }
        }
        if (bucket_matches >= bucket_subnet_limit or table_matches >= table_subnet_limit)
            return Error.AddressLimit;
    }

    fn findInBucket(
        self: *const Self,
        bucket_index: usize,
        node_id: *const types.NodeId,
    ) ?usize {
        for (self.bucketEntries(bucket_index), 0..) |entry, position| {
            if (std.mem.eql(u8, &entry.peer.node_id, node_id)) return position;
        }
        return null;
    }

    fn bucketEntries(self: *const Self, bucket_index: usize) []const Entry {
        std.debug.assert(bucket_index < bucket_count);
        const offset = bucketOffset(bucket_index);
        return self.entries[offset .. offset + self.counts[bucket_index]];
    }

    fn bucketEntriesMut(self: *Self, bucket_index: usize) []Entry {
        std.debug.assert(bucket_index < bucket_count);
        const offset = bucketOffset(bucket_index);
        return self.entries[offset .. offset + self.counts[bucket_index]];
    }
};

fn makeEntry(
    peer: *const types.Endpoint,
    record: *const enr.Record,
    now_ms: u64,
) Entry {
    return .{
        .peer = peer.*,
        .record = record.*,
        .last_verified_ms = now_ms,
    };
}

fn validateEntry(
    local_id: *const types.NodeId,
    peer: *const types.Endpoint,
    record: *const enr.Record,
) Error!void {
    if (std.mem.eql(u8, local_id, &peer.node_id)) return Error.SelfEntry;
    if (!std.mem.eql(u8, &peer.node_id, &record.node_id))
        return Error.InvalidRemoteRecord;
    if (record.length > record.bytes.len) return Error.InvalidRecord;
    if (!recordHasAddress(record, peer.address)) return Error.InvalidRemoteRecord;
    if (!peer.address.isUsable()) return Error.InvalidRemoteRecord;
}

fn entryNodeId(entry: *const Entry) *const types.NodeId {
    return &entry.peer.node_id;
}

fn recordHasAddress(record: *const enr.Record, address: types.Address) bool {
    return switch (address) {
        .ip4 => |value| if (record.ip4) |ip|
            record.udp == value.port and std.mem.eql(u8, &ip, &value.octets)
        else
            false,
        .ip6 => |value| if (record.ip6) |ip|
            (record.udp6 orelse record.udp) == value.port and
                std.mem.eql(u8, &ip, &value.octets)
        else
            false,
    };
}

fn sameSubnet(left: types.Address, right: types.Address) bool {
    return switch (left) {
        .ip4 => |value| switch (right) {
            .ip4 => |other| std.mem.eql(u8, value.octets[0..3], other.octets[0..3]),
            .ip6 => false,
        },
        .ip6 => |value| switch (right) {
            .ip4 => false,
            .ip6 => |other| std.mem.eql(u8, value.octets[0..8], other.octets[0..8]),
        },
    };
}

fn recordRelayAllowed(record: *const enr.Record, requester: ?types.Address) bool {
    const source = requester orelse return true;
    const address = record.endpoint() orelse return false;
    return relayAllowed(source, address);
}

/// Public candidates may be relayed by anyone; special scopes only by a source in the same scope.
pub fn relayAllowed(source: types.Address, candidate: types.Address) bool {
    const source_class = addressClass(source);
    const candidate_class = addressClass(candidate);
    if (source_class == .invalid or candidate_class == .invalid) return false;
    return switch (candidate_class) {
        .public => true,
        .private, .loopback, .link_local => source_class == candidate_class and
            std.meta.activeTag(source) == std.meta.activeTag(candidate),
        .invalid => false,
    };
}

const AddressClass = enum {
    invalid,
    public,
    private,
    loopback,
    link_local,
};

fn addressClass(address: types.Address) AddressClass {
    return switch (address) {
        .ip4 => |value| classifyIp4(value.octets),
        .ip6 => |value| classifyIp6(value.octets),
    };
}

fn classifyIp4(ip: [4]u8) AddressClass {
    if (ip[0] == 0 or ip[0] >= 224) return .invalid;
    if (ip[0] == 127) return .loopback;
    if (ip[0] == 169 and ip[1] == 254) return .link_local;
    if (ip[0] == 10 or
        (ip[0] == 100 and ip[1] >= 64 and ip[1] <= 127) or
        (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) or
        (ip[0] == 192 and ip[1] == 168)) return .private;
    return .public;
}

fn classifyIp6(ip: [16]u8) AddressClass {
    if (std.mem.allEqual(u8, &ip, 0) or ip[0] == 0xff) return .invalid;
    if (std.mem.allEqual(u8, ip[0..15], 0) and ip[15] == 1) return .loopback;
    if (std.mem.allEqual(u8, ip[0..10], 0) and ip[10] == 0xff and ip[11] == 0xff) {
        return classifyIp4(ip[12..16].*);
    }
    if (std.mem.allEqual(u8, ip[0..12], 0)) return .invalid;
    if (ip[0] == 0xfe and ip[1] & 0xc0 == 0x80) return .link_local;
    if (ip[0] & 0xfe == 0xfc or
        (ip[0] == 0xfe and ip[1] & 0xc0 == 0xc0)) return .private;
    return .public;
}

fn bucketIndex(distance: u16) usize {
    const bucket_min_distance = types.distance_max - bucket_count;
    if (distance <= bucket_min_distance) return 0;
    return @intCast(distance - bucket_min_distance - 1);
}

fn bucketOffset(index: usize) usize {
    std.debug.assert(index < bucket_count);
    return index * bucket_size;
}

comptime {
    std.debug.assert(bucket_count == types.distance_max / 15);
    std.debug.assert(table_capacity == 272);
    std.debug.assert(bucket_subnet_limit <= bucket_size);
    std.debug.assert(table_subnet_limit <= table_capacity);
}
