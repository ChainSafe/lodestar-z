//! Pending unknown-block gossip queue.
//!
//! Holds gossip attestations and aggregates whose `beacon_block_root` is not
//! yet known locally. Unlike orphan blocks, we only have the gossip object and
//! must fetch the voted block by root before replaying the object through the
//! normal processor/import path.

const std = @import("std");
const Allocator = std.mem.Allocator;

const work_item_mod = @import("work_item.zig");
const AttestationWork = work_item_mod.AttestationWork;
const AggregateWork = work_item_mod.AggregateWork;
const MessageId = work_item_mod.MessageId;
const Root = @import("consensus_types").primitive.Root.Type;
const Slot = @import("consensus_types").primitive.Slot.Type;

pub const MAX_PENDING_UNKNOWN_BLOCK_GOSSIP_OBJECTS: usize = 16_384;
pub const MAX_UNKNOWN_BLOCK_GOSSIP_FETCH_ATTEMPTS: u8 = 5;

const StoredPeerId = struct {
    buf: [128]u8 = undefined,
    len: u8 = 0,

    fn init(peer_id: []const u8) StoredPeerId {
        var stored: StoredPeerId = .{};
        stored.len = @intCast(@min(peer_id.len, stored.buf.len));
        @memcpy(stored.buf[0..stored.len], peer_id[0..stored.len]);
        return stored;
    }

    fn bytes(self: *const StoredPeerId) []const u8 {
        return self.buf[0..self.len];
    }
};

const ExcludedPeerSet = struct {
    peers: std.ArrayListUnmanaged(StoredPeerId) = .empty,

    fn deinit(self: *ExcludedPeerSet, allocator: Allocator) void {
        self.peers.deinit(allocator);
        self.* = .{};
    }

    fn clear(self: *ExcludedPeerSet, allocator: Allocator) void {
        self.deinit(allocator);
    }

    fn isEmpty(self: *const ExcludedPeerSet) bool {
        return self.peers.items.len == 0;
    }

    fn contains(self: *const ExcludedPeerSet, peer_id: []const u8) bool {
        for (self.peers.items) |*entry| {
            if (std.mem.eql(u8, entry.bytes(), peer_id)) return true;
        }
        return false;
    }

    fn add(self: *ExcludedPeerSet, allocator: Allocator, peer_id: []const u8) !void {
        if (self.contains(peer_id)) return;
        try self.peers.append(allocator, StoredPeerId.init(peer_id));
    }
};

pub const PendingKind = enum {
    attestation,
    aggregate,
};

pub const PendingItem = union(PendingKind) {
    attestation: AttestationWork,
    aggregate: AggregateWork,

    pub fn slot(self: PendingItem) Slot {
        return switch (self) {
            .attestation => |work| work.attestation.slot(),
            .aggregate => |work| work.aggregate.attestation().slot(),
        };
    }

    pub fn messageId(self: PendingItem) MessageId {
        return switch (self) {
            .attestation => |work| work.message_id,
            .aggregate => |work| work.message_id,
        };
    }

    pub fn deinit(self: *PendingItem, allocator: Allocator) void {
        switch (self.*) {
            .attestation => |*work| work.attestation.deinit(allocator),
            .aggregate => |*work| {
                work.resolved.deinit(allocator);
                work.aggregate.deinit(allocator);
            },
        }
        self.* = undefined;
    }
};

pub const ReleasedItems = std.ArrayListUnmanaged(PendingItem);

const FetchStatus = enum {
    pending,
    fetching,
    waiting_import,
};

const PendingRoot = struct {
    items: std.ArrayListUnmanaged(PendingItem) = .empty,
    preferred_peer_id_buf: [128]u8 = undefined,
    preferred_peer_id_len: u8 = 0,
    excluded_peers: ExcludedPeerSet = .{},
    attempts: u8 = 0,
    status: FetchStatus = .pending,

    fn deinit(self: *PendingRoot, allocator: Allocator) void {
        for (self.items.items) |*item| item.deinit(allocator);
        self.items.deinit(allocator);
        self.excluded_peers.deinit(allocator);
        self.* = .{};
    }

    fn preferredPeerId(self: *const PendingRoot) ?[]const u8 {
        if (self.preferred_peer_id_len == 0) return null;
        return self.preferred_peer_id_buf[0..self.preferred_peer_id_len];
    }

    fn setPreferredPeer(self: *PendingRoot, peer_id: ?[]const u8) void {
        const peer = peer_id orelse return;
        self.preferred_peer_id_len = @intCast(@min(peer.len, self.preferred_peer_id_buf.len));
        @memcpy(self.preferred_peer_id_buf[0..self.preferred_peer_id_len], peer[0..self.preferred_peer_id_len]);
    }

    fn clearExcludedPeers(self: *PendingRoot, allocator: Allocator) void {
        self.excluded_peers.clear(allocator);
    }

    fn containsMessageId(self: *const PendingRoot, message_id: MessageId) bool {
        for (self.items.items) |item| {
            const item_message_id = item.messageId();
            if (std.mem.eql(u8, item_message_id[0..], message_id[0..])) return true;
        }
        return false;
    }
};

pub const Callbacks = struct {
    ptr: *anyopaque,
    /// Returns true only if the by-root request was accepted into the bridge / request queue.
    requestBlockByRootFn: *const fn (ptr: *anyopaque, root: Root, peer_id: []const u8) bool,
    getConnectedPeersFn: *const fn (ptr: *anyopaque) []const []const u8,

    pub fn requestBlockByRoot(self: Callbacks, root: Root, peer_id: []const u8) bool {
        return self.requestBlockByRootFn(self.ptr, root, peer_id);
    }

    pub fn getConnectedPeers(self: Callbacks) []const []const u8 {
        return self.getConnectedPeersFn(self.ptr);
    }
};

pub const Queue = struct {
    allocator: Allocator,
    pending_by_root: std.array_hash_map.Auto(Root, PendingRoot),
    dropped_items: ReleasedItems = .empty,
    total_count: usize = 0,
    peer_index: usize = 0,

    pub fn init(allocator: Allocator) Queue {
        return .{
            .allocator = allocator,
            .pending_by_root = .empty,
        };
    }

    pub fn deinit(self: *Queue) void {
        var it = self.pending_by_root.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.pending_by_root.deinit(self.allocator);
        for (self.dropped_items.items) |*item| item.deinit(self.allocator);
        self.dropped_items.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn addAttestation(
        self: *Queue,
        block_root: Root,
        peer_id: ?[]const u8,
        work: AttestationWork,
    ) !bool {
        return self.addItem(block_root, peer_id, .{ .attestation = work });
    }

    pub fn addAggregate(
        self: *Queue,
        block_root: Root,
        peer_id: ?[]const u8,
        work: AggregateWork,
    ) !bool {
        return self.addItem(block_root, peer_id, .{ .aggregate = work });
    }

    pub fn onSlot(self: *Queue, current_slot: Slot) void {
        var roots_to_remove = std.ArrayListUnmanaged(Root).empty;
        defer roots_to_remove.deinit(self.allocator);

        var it = self.pending_by_root.iterator();
        while (it.next()) |entry| {
            var i: usize = 0;
            while (i < entry.value_ptr.items.items.len) {
                if (entry.value_ptr.items.items[i].slot() < current_slot) {
                    const removed = entry.value_ptr.items.swapRemove(i);
                    self.queueDroppedItem(removed);
                    self.total_count -|= 1;
                } else {
                    i += 1;
                }
            }

            if (entry.value_ptr.items.items.len == 0) {
                roots_to_remove.append(self.allocator, entry.key_ptr.*) catch {};
            }
        }

        for (roots_to_remove.items) |root| {
            self.removeRoot(root);
        }
    }

    pub fn tick(self: *Queue, callbacks: Callbacks) void {
        const peers = callbacks.getConnectedPeers();
        if (peers.len == 0) return;

        var it = self.pending_by_root.iterator();
        while (it.next()) |entry| {
            const root = entry.key_ptr.*;
            const pending = entry.value_ptr;
            if (pending.items.items.len == 0) continue;
            if (pending.status != .pending) continue;
            if (pending.attempts >= MAX_UNKNOWN_BLOCK_GOSSIP_FETCH_ATTEMPTS) {
                self.removeRoot(root);
                continue;
            }

            const peer = self.selectPeer(pending, peers) orelse continue;
            if (!callbacks.requestBlockByRoot(root, peer)) {
                // The shared by-root bridge queue is full. Stop scheduling more
                // roots this tick and retry on a later pass after the bridge
                // drains.
                break;
            }
            pending.status = .fetching;
            pending.attempts += 1;
        }
    }

    pub fn onFetchAccepted(self: *Queue, block_root: Root) void {
        if (self.pending_by_root.getPtr(block_root)) |pending| {
            pending.status = .waiting_import;
        }
    }

    pub fn onFetchFailed(self: *Queue, block_root: Root, failed_peer_id: ?[]const u8) void {
        const pending = self.pending_by_root.getPtr(block_root) orelse return;
        if (failed_peer_id) |peer_id| {
            _ = pending.excluded_peers.add(self.allocator, peer_id) catch {};
        }
        if (pending.attempts >= MAX_UNKNOWN_BLOCK_GOSSIP_FETCH_ATTEMPTS) {
            self.removeRoot(block_root);
            return;
        }
        pending.status = .pending;
    }

    pub fn dropRoot(self: *Queue, block_root: Root) void {
        self.removeRoot(block_root);
    }

    pub fn releaseImported(self: *Queue, block_root: Root, out: *ReleasedItems) !void {
        const pending_len = blk: {
            const pending = self.pending_by_root.getPtr(block_root) orelse return;
            break :blk pending.items.items.len;
        };
        try out.ensureUnusedCapacity(self.allocator, pending_len);

        const removed = self.pending_by_root.fetchSwapRemove(block_root) orelse return;
        var pending = removed.value;
        defer {
            pending.items.deinit(self.allocator);
            pending.excluded_peers.deinit(self.allocator);
        }

        for (pending.items.items) |item| {
            out.appendAssumeCapacity(item);
        }
        self.total_count -|= pending.items.items.len;
        pending.items.items.len = 0;
    }

    pub fn takeDropped(self: *Queue, out: *ReleasedItems) !void {
        try out.ensureUnusedCapacity(self.allocator, self.dropped_items.items.len);
        for (self.dropped_items.items) |item| {
            out.appendAssumeCapacity(item);
        }
        self.dropped_items.items.len = 0;
    }

    pub fn pendingCount(self: *const Queue) usize {
        return self.total_count;
    }

    fn addItem(self: *Queue, block_root: Root, peer_id: ?[]const u8, item: PendingItem) !bool {
        var owned = item;
        errdefer owned.deinit(self.allocator);

        if (self.total_count >= MAX_PENDING_UNKNOWN_BLOCK_GOSSIP_OBJECTS) {
            self.dropOldest();
        }

        const gop = try self.pending_by_root.getOrPut(self.allocator, block_root);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        gop.value_ptr.setPreferredPeer(peer_id);
        if (gop.value_ptr.containsMessageId(owned.messageId())) {
            return false;
        }
        try gop.value_ptr.items.append(self.allocator, owned);
        self.total_count += 1;
        owned = undefined;
        return true;
    }

    fn removeRoot(self: *Queue, block_root: Root) void {
        if (self.pending_by_root.fetchSwapRemove(block_root)) |kv| {
            var pending = kv.value;
            self.total_count -|= pending.items.items.len;
            for (pending.items.items) |item| {
                self.queueDroppedItem(item);
            }
            pending.items.deinit(self.allocator);
            pending.excluded_peers.deinit(self.allocator);
        }
    }

    fn dropOldest(self: *Queue) void {
        var oldest_root: ?Root = null;
        var oldest_slot: Slot = std.math.maxInt(Slot);
        var oldest_idx: usize = 0;

        var it = self.pending_by_root.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items, 0..) |item, idx| {
                const slot = item.slot();
                if (slot < oldest_slot) {
                    oldest_slot = slot;
                    oldest_root = entry.key_ptr.*;
                    oldest_idx = idx;
                }
            }
        }

        if (oldest_root) |root| {
            if (self.pending_by_root.getPtr(root)) |pending| {
                const removed = pending.items.swapRemove(oldest_idx);
                self.queueDroppedItem(removed);
                self.total_count -|= 1;
                if (pending.items.items.len == 0) {
                    self.removeRoot(root);
                }
            }
        }
    }

    fn queueDroppedItem(self: *Queue, item: PendingItem) void {
        var owned = item;
        self.dropped_items.append(self.allocator, owned) catch {
            owned.deinit(self.allocator);
        };
    }

    fn selectPeer(self: *Queue, pending: *PendingRoot, peers: []const []const u8) ?[]const u8 {
        if (pending.preferredPeerId()) |preferred| {
            if (!isPeerExcluded(pending, preferred)) {
                for (peers) |peer| {
                    if (std.mem.eql(u8, peer, preferred)) return peer;
                }
            }
        }

        if (self.nextEligiblePeer(pending, peers)) |peer| return peer;
        if (pending.excluded_peers.isEmpty()) return null;

        pending.clearExcludedPeers(self.allocator);
        if (pending.preferredPeerId()) |preferred| {
            for (peers) |peer| {
                if (std.mem.eql(u8, peer, preferred)) return peer;
            }
        }
        return self.nextEligiblePeer(pending, peers);
    }

    fn nextEligiblePeer(self: *Queue, pending: *const PendingRoot, peers: []const []const u8) ?[]const u8 {
        if (peers.len == 0) return null;

        for (0..peers.len) |offset| {
            const idx = (self.peer_index + offset) % peers.len;
            const peer = peers[idx];
            if (isPeerExcluded(pending, peer)) continue;
            self.peer_index = (idx + 1) % peers.len;
            return peer;
        }
        return null;
    }
};

fn isPeerExcluded(pending: *const PendingRoot, peer_id: []const u8) bool {
    return pending.excluded_peers.contains(peer_id);
}

const TestCallbacksCtx = struct {
    connected: []const []const u8,
    requested_root: ?Root = null,
    requested_peer: ?[]const u8 = null,
};

fn testRequestBlockByRoot(ptr: *anyopaque, root: Root, peer_id: []const u8) bool {
    const ctx: *TestCallbacksCtx = @ptrCast(@alignCast(ptr));
    ctx.requested_root = root;
    ctx.requested_peer = peer_id;
    return true;
}

fn testGetConnectedPeers(ptr: *anyopaque) []const []const u8 {
    const ctx: *TestCallbacksCtx = @ptrCast(@alignCast(ptr));
    return ctx.connected;
}

test "Queue releases imported root items" {
    var queue = Queue.init(std.testing.allocator);
    defer queue.deinit();

    var att = AttestationWork{
        .source = .{},
        .message_id = [_]u8{0xA1} ** 20,
        .attestation = undefined,
        .attestation_data_root = [_]u8{0} ** 32,
        .resolved = .{
            .validator_index = 1,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{0} ** 32,
            .expected_subnet = 0,
        },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    };
    att.attestation = .{ .phase0 = .{
        .aggregation_bits = .{ .bit_len = 1, .data = .empty },
        .data = .{
            .slot = 12,
            .index = 0,
            .beacon_block_root = [_]u8{0x11} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    } };

    try std.testing.expect(try queue.addAttestation([_]u8{0x11} ** 32, "peer-a", att));

    var released: ReleasedItems = .empty;
    defer {
        for (released.items) |*item| item.deinit(std.testing.allocator);
        released.deinit(std.testing.allocator);
    }
    try queue.releaseImported([_]u8{0x11} ** 32, &released);

    try std.testing.expectEqual(@as(usize, 1), released.items.len);
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
}

test "Queue enqueue failure leaves root pending for retry" {
    var queue = Queue.init(std.testing.allocator);
    defer queue.deinit();

    var att = AttestationWork{
        .source = .{},
        .message_id = [_]u8{0xD4} ** 20,
        .attestation = undefined,
        .attestation_data_root = [_]u8{0} ** 32,
        .resolved = .{
            .validator_index = 1,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{0} ** 32,
            .expected_subnet = 0,
        },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    };
    att.attestation = .{ .phase0 = .{
        .aggregation_bits = .{ .bit_len = 1, .data = .empty },
        .data = .{
            .slot = 12,
            .index = 0,
            .beacon_block_root = [_]u8{0x44} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    } };

    const root = [_]u8{0x44} ** 32;
    try std.testing.expect(try queue.addAttestation(root, "peer-a", att));

    const TestCallbacks = struct {
        request_calls: usize = 0,
        allow_enqueue: bool = false,

        fn requestBlockByRoot(ptr: *anyopaque, _: Root, _: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.request_calls += 1;
            return self.allow_enqueue;
        }

        fn getConnectedPeers(_: *anyopaque) []const []const u8 {
            return &.{"peer-a"};
        }
    };

    var ctx = TestCallbacks{};
    const callbacks = Callbacks{
        .ptr = @ptrCast(&ctx),
        .requestBlockByRootFn = &TestCallbacks.requestBlockByRoot,
        .getConnectedPeersFn = &TestCallbacks.getConnectedPeers,
    };

    queue.tick(callbacks);

    try std.testing.expectEqual(@as(usize, 1), ctx.request_calls);
    const pending = queue.pending_by_root.getPtr(root).?;
    try std.testing.expectEqual(FetchStatus.pending, pending.status);
    try std.testing.expectEqual(@as(u8, 0), pending.attempts);

    ctx.allow_enqueue = true;
    queue.tick(callbacks);

    try std.testing.expectEqual(@as(usize, 2), ctx.request_calls);
    try std.testing.expectEqual(FetchStatus.fetching, pending.status);
    try std.testing.expectEqual(@as(u8, 1), pending.attempts);
}

test "Queue by-root queue backpressure stops further scheduling this tick" {
    var queue = Queue.init(std.testing.allocator);
    defer queue.deinit();

    var att_a = AttestationWork{
        .source = .{},
        .message_id = [_]u8{0xE1} ** 20,
        .attestation = undefined,
        .attestation_data_root = [_]u8{0} ** 32,
        .resolved = .{
            .validator_index = 1,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{0} ** 32,
            .expected_subnet = 0,
        },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    };
    att_a.attestation = .{ .phase0 = .{
        .aggregation_bits = .{ .bit_len = 1, .data = .empty },
        .data = .{
            .slot = 12,
            .index = 0,
            .beacon_block_root = [_]u8{0x51} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    } };

    var att_b = AttestationWork{
        .source = .{},
        .message_id = [_]u8{0xE2} ** 20,
        .attestation = undefined,
        .attestation_data_root = [_]u8{0} ** 32,
        .resolved = .{
            .validator_index = 2,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{0} ** 32,
            .expected_subnet = 0,
        },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    };
    att_b.attestation = .{ .phase0 = .{
        .aggregation_bits = .{ .bit_len = 1, .data = .empty },
        .data = .{
            .slot = 12,
            .index = 0,
            .beacon_block_root = [_]u8{0x52} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    } };

    try std.testing.expect(try queue.addAttestation([_]u8{0x51} ** 32, "peer-a", att_a));
    try std.testing.expect(try queue.addAttestation([_]u8{0x52} ** 32, "peer-b", att_b));

    const TestCallbacks = struct {
        request_calls: usize = 0,

        fn requestBlockByRoot(ptr: *anyopaque, _: Root, _: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.request_calls += 1;
            return false;
        }

        fn getConnectedPeers(_: *anyopaque) []const []const u8 {
            return &.{ "peer-a", "peer-b" };
        }
    };

    var ctx = TestCallbacks{};
    const callbacks = Callbacks{
        .ptr = @ptrCast(&ctx),
        .requestBlockByRootFn = &TestCallbacks.requestBlockByRoot,
        .getConnectedPeersFn = &TestCallbacks.getConnectedPeers,
    };

    queue.tick(callbacks);

    try std.testing.expectEqual(@as(usize, 1), ctx.request_calls);
}

test "Queue retries a different peer after failure" {
    var queue = Queue.init(std.testing.allocator);
    defer queue.deinit();

    var att = AttestationWork{
        .source = .{},
        .message_id = [_]u8{0xB2} ** 20,
        .attestation = undefined,
        .attestation_data_root = [_]u8{0} ** 32,
        .resolved = .{
            .validator_index = 1,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{0} ** 32,
            .expected_subnet = 0,
        },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    };
    att.attestation = .{ .phase0 = .{
        .aggregation_bits = .{ .bit_len = 1, .data = .empty },
        .data = .{
            .slot = 12,
            .index = 0,
            .beacon_block_root = [_]u8{0x22} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    } };

    const root = [_]u8{0x22} ** 32;
    try std.testing.expect(try queue.addAttestation(root, "peer-a", att));

    const connected = [_][]const u8{ "peer-a", "peer-b" };
    var ctx = TestCallbacksCtx{ .connected = connected[0..] };
    const callbacks = Callbacks{
        .ptr = @ptrCast(&ctx),
        .requestBlockByRootFn = &testRequestBlockByRoot,
        .getConnectedPeersFn = &testGetConnectedPeers,
    };

    queue.tick(callbacks);
    try std.testing.expectEqual(root, ctx.requested_root.?);
    try std.testing.expectEqualStrings("peer-a", ctx.requested_peer.?);

    queue.onFetchFailed(root, "peer-a");
    ctx.requested_root = null;
    ctx.requested_peer = null;

    queue.tick(callbacks);
    try std.testing.expectEqual(root, ctx.requested_root.?);
    try std.testing.expectEqualStrings("peer-b", ctx.requested_peer.?);
}

test "Queue exposes expired items through takeDropped" {
    var queue = Queue.init(std.testing.allocator);
    defer queue.deinit();

    var att = AttestationWork{
        .source = .{},
        .message_id = [_]u8{0xC3} ** 20,
        .attestation = undefined,
        .attestation_data_root = [_]u8{0} ** 32,
        .resolved = .{
            .validator_index = 1,
            .validator_committee_index = 0,
            .committee_size = 1,
            .signing_root = [_]u8{0} ** 32,
            .expected_subnet = 0,
        },
        .subnet_id = 0,
        .seen_timestamp_ns = 0,
    };
    att.attestation = .{ .phase0 = .{
        .aggregation_bits = .{ .bit_len = 1, .data = .empty },
        .data = .{
            .slot = 12,
            .index = 0,
            .beacon_block_root = [_]u8{0x33} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    } };

    try std.testing.expect(try queue.addAttestation([_]u8{0x33} ** 32, "peer-a", att));

    queue.onSlot(13);

    var dropped: ReleasedItems = .empty;
    defer {
        for (dropped.items) |*item| item.deinit(std.testing.allocator);
        dropped.deinit(std.testing.allocator);
    }
    try queue.takeDropped(&dropped);

    try std.testing.expectEqual(@as(usize, 1), dropped.items.len);
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
}
