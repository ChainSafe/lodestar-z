const std = @import("std");
const binding = @import("binding.zig");
const api = @import("api.zig");
const peer_id = @import("../wire/peer_id.zig");
const connection = @import("connection.zig");
const peer_index = @import("peer_index.zig");
const route_table = @import("route_table.zig");
const tls = @import("../tls/context.zig");
const assert = std.debug.assert;

const RouteKeys = struct {
    cids: [route_table.routes_per_slot]binding.Cid = undefined,
    len: u8 = 0,
};

pub const Registry = struct {
    slots: []connection.Slot,
    routes: route_table.RouteTable,
    route_keys: []RouteKeys,
    active: []u16,
    positions: []u16,
    activity: []bool,
    keylog_arena: []u8,
    peers: peer_index.PeerIndex,
    seed: u64,
    active_len: u16 = 0,
    handshaking: u16 = 0,
    dialing: u16 = 0,
    outbound: u16 = 0,

    pub fn init(allocator: std.mem.Allocator, slots_max: u16, keylog: bool, seed: u64) !Registry {
        const slots = try allocator.alloc(connection.Slot, slots_max);
        errdefer allocator.free(slots);
        @memset(slots, .{});

        var routes = try route_table.RouteTable.init(
            allocator,
            slots_max,
            seed,
        );
        errdefer routes.deinit(allocator);

        const active = try allocator.alloc(u16, slots_max);
        errdefer allocator.free(active);
        for (active, 0..) |*entry, index| entry.* = @intCast(index);

        const activity = try allocator.alloc(bool, slots_max);
        errdefer allocator.free(activity);
        @memset(activity, false);

        const keylog_len: usize = if (keylog)
            tls.keylog_capacity * @as(usize, slots_max)
        else
            0;
        const keylog_arena = try allocator.alloc(u8, keylog_len);
        errdefer allocator.free(keylog_arena);

        var peers = try peer_index.PeerIndex.init(allocator, slots_max);
        errdefer peers.deinit(allocator);

        const positions = try allocator.alloc(u16, slots_max);
        errdefer allocator.free(positions);
        for (positions, 0..) |*entry, index| entry.* = @intCast(index);
        const route_keys = try allocator.alloc(RouteKeys, slots_max);
        errdefer allocator.free(route_keys);
        @memset(route_keys, .{});
        return .{
            .slots = slots,
            .routes = routes,
            .active = active,
            .activity = activity,
            .keylog_arena = keylog_arena,
            .peers = peers,
            .positions = positions,
            .route_keys = route_keys,
            .seed = seed,
        };
    }

    pub fn deinit(self: *Registry, allocator: std.mem.Allocator) void {
        for (self.slots) |*slot| if (slot.state != .free) {
            slot.release();
        };
        self.peers.deinit(allocator);
        allocator.free(self.keylog_arena);
        allocator.free(self.activity);
        allocator.free(self.active);
        allocator.free(self.positions);
        allocator.free(self.route_keys);
        self.routes.deinit(allocator);
        allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn claim(self: *Registry) ?u16 {
        assert(self.active.len == self.slots.len);
        assert(self.active_len <= self.active.len);
        if (self.active_len == self.active.len) return null;
        const index = self.active[self.active_len];
        assert(self.slots[index].state == .free);
        assert(self.route_keys[index].len == 0);
        self.active_len += 1;
        self.activity[index] = false;
        return index;
    }

    pub fn unclaim(self: *Registry, index: u16) void {
        assert(index < self.slots.len);
        assert(self.active_len > 0);
        const cursor = self.positions[index];
        assert(cursor < self.active_len);
        assert(self.active[cursor] == index);
        self.active_len -= 1;
        const moved = self.active[self.active_len];
        self.active[cursor] = moved;
        self.positions[moved] = cursor;
        self.active[self.active_len] = index;
        self.positions[index] = self.active_len;
    }

    pub fn retire(self: *Registry, index: u16) void {
        assert(index < self.slots.len);
        const slot = &self.slots[index];
        assert(slot.state != .free);
        if (slot.peer_id) |id| self.peers.remove(peer_index.keyOf(self.seed, &id), index);
        self.removeRoutesFor(index);
        slot.release();
        self.unclaim(index);
        assert(slot.state == .free);
    }

    pub fn keylogFor(self: *const Registry, index: u16) []u8 {
        assert(index < self.slots.len);
        if (self.keylog_arena.len == 0) return &.{};
        assert(self.keylog_arena.len == tls.keylog_capacity * self.slots.len);
        const start = tls.keylog_capacity * @as(usize, index);
        return self.keylog_arena[start..][0..tls.keylog_capacity];
    }

    pub fn indexPeer(self: *Registry, index: u16, id: peer_id.PeerId) void {
        const slot = &self.slots[index];
        assert(slot.state == .established);
        assert(slot.peer_id == null);
        slot.peer_id = id;
        self.peers.insert(.{
            .key = peer_index.keyOf(self.seed, &id),
            .index = index,
            .generation = slot.generation,
            .used = true,
        });
    }

    pub fn findPeer(self: *const Registry, id: *const peer_id.PeerId) ?api.Handle {
        var candidates = self.peers.candidates(peer_index.keyOf(self.seed, id));
        while (candidates.next()) |entry| {
            assert(entry.index < self.slots.len);
            const slot = &self.slots[entry.index];
            if (slot.generation != entry.generation or slot.state == .free) continue;
            const stored = slot.peer_id orelse continue;
            if (stored.eql(id)) return .{ .index = entry.index, .generation = entry.generation };
        }
        return null;
    }

    pub fn findRoute(self: *const Registry, cid: *const binding.Cid) ?u16 {
        const index = self.routes.find(cid) orelse return null;
        assert(index < self.slots.len);
        assert(self.slots[index].state != .free);
        return index;
    }

    pub fn addRoute(self: *Registry, cid: *const binding.Cid, index: u16) route_table.Error!void {
        assert(index < self.slots.len);
        assert(self.routes.count <= route_table.routes_per_slot * self.slots.len);
        const keys = &self.route_keys[index];
        if (keys.len == route_table.routes_per_slot) return error.Full;
        try self.routes.insert(cid, index);
        keys.cids[keys.len] = cid.*;
        keys.len += 1;
    }

    pub fn removeRoutesFor(self: *Registry, index: u16) void {
        assert(index < self.slots.len);
        const keys = &self.route_keys[index];
        for (keys.cids[0..keys.len]) |*cid| self.routes.remove(cid, index);
        keys.len = 0;
        assert(self.routes.count <= route_table.routes_per_slot * self.slots.len);
    }
};
