const std = @import("std");
const binding = @import("binding.zig");
const connection = @import("connection.zig");
const index_list = @import("../index_list.zig");
const route_table = @import("route_table.zig");
const DeadlineHeap = @import("../deadline_heap.zig").DeadlineHeap;
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
    keylog_arena: []u8,
    /// One key per live connection: its earliest QUIC timer, handshake limit, keep-alive or
    /// deferred close, in monotonic nanoseconds.
    timers: DeadlineHeap,
    /// Rows popped by one expiry pass.
    expired: []u16,
    collect: index_list.List = .{},
    dirty: index_list.List = .{},
    events: index_list.List = .{},
    released: index_list.List = .{},
    deferred: index_list.List = .{},
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

        var timers = try DeadlineHeap.init(allocator, slots_max);
        errdefer timers.deinit(allocator);
        const expired = try allocator.alloc(u16, slots_max);
        errdefer allocator.free(expired);

        const keylog_len: usize = if (keylog)
            tls.keylog_capacity * @as(usize, slots_max)
        else
            0;
        const keylog_arena = try allocator.alloc(u8, keylog_len);
        errdefer allocator.free(keylog_arena);

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
            .timers = timers,
            .expired = expired,
            .keylog_arena = keylog_arena,
            .positions = positions,
            .route_keys = route_keys,
        };
    }

    pub fn deinit(self: *Registry, allocator: std.mem.Allocator) void {
        for (self.slots) |*slot| if (slot.state != .free) {
            slot.release();
        };
        allocator.free(self.keylog_arena);
        allocator.free(self.expired);
        self.timers.deinit(allocator);
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
        var available: ?usize = null;
        for (self.active[self.active_len..], self.active_len..) |candidate, position| {
            if (self.slots[candidate].generation != std.math.maxInt(u32)) {
                available = position;
                break;
            }
        }
        const position = available orelse return null;
        const index = self.active[position];
        const displaced = self.active[self.active_len];
        self.active[position] = displaced;
        self.positions[displaced] = @intCast(position);
        self.active[self.active_len] = index;
        self.positions[index] = self.active_len;
        assert(self.slots[index].state == .free);
        assert(self.route_keys[index].len == 0);
        self.active_len += 1;
        assert(self.timers.get(index) == null);
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
        self.removeRoutesFor(index);
        self.unlink(index);
        slot.release();
        self.unclaim(index);
        assert(slot.state == .free);
    }

    /// Removes the slot from every per-turn list and the timer heap.
    pub fn unlink(self: *Registry, index: u16) void {
        assert(index < self.slots.len);
        const slot = &self.slots[index];
        if (slot.collect_link.linked) self.collect.remove(self.slots, "collect_link", index);
        if (slot.dirty_link.linked) self.dirty.remove(self.slots, "dirty_link", index);
        if (slot.event_link.linked) self.events.remove(self.slots, "event_link", index);
        if (slot.release_link.linked) self.released.remove(self.slots, "release_link", index);
        if (slot.deferred_link.linked) self.deferred.remove(self.slots, "deferred_link", index);
        self.timers.clear(index);
    }

    pub fn keylogFor(self: *const Registry, index: u16) []u8 {
        assert(index < self.slots.len);
        if (self.keylog_arena.len == 0) return &.{};
        assert(self.keylog_arena.len == tls.keylog_capacity * self.slots.len);
        const start = tls.keylog_capacity * @as(usize, index);
        return self.keylog_arena[start..][0..tls.keylog_capacity];
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
