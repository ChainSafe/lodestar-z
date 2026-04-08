const std = @import("std");
const Allocator = std.mem.Allocator;

const unknown_chain_sync_mod = @import("unknown_chain_sync.zig");
const backwards_chain = @import("backwards_chain.zig");

const UnknownChainSync = unknown_chain_sync_mod.UnknownChainSync;
const Callbacks = unknown_chain_sync_mod.Callbacks;
const ForkChoiceQuery = unknown_chain_sync_mod.ForkChoiceQuery;
const MinimalHeader = backwards_chain.MinimalHeader;
const PeerSet = backwards_chain.PeerSet;
const MAX_CHAINS: usize = 64;

/// Test stub for fork choice.
const TestForkChoice = struct {
    known_roots: std.AutoArrayHashMap([32]u8, void),

    fn init(alloc: Allocator) TestForkChoice {
        return .{ .known_roots = std.AutoArrayHashMap([32]u8, void).init(alloc) };
    }
    fn deinit(self: *TestForkChoice) void {
        self.known_roots.deinit();
    }
    fn addRoot(self: *TestForkChoice, root: [32]u8) !void {
        try self.known_roots.put(root, {});
    }
    fn hasBlock(ptr: *anyopaque, root: [32]u8) bool {
        const self: *TestForkChoice = @ptrCast(@alignCast(ptr));
        return self.known_roots.contains(root);
    }
    fn query(self: *TestForkChoice) ForkChoiceQuery {
        return .{ .ptr = @ptrCast(self), .hasBlockFn = &hasBlock };
    }
};

/// Test stub for callbacks.
const TestCallbacks = struct {
    fetch_requests: std.ArrayListUnmanaged(FetchReq),
    linked_chains: std.ArrayListUnmanaged(LinkedChainInfo),
    allocator: Allocator,

    const FetchReq = struct { root: [32]u8 };
    const LinkedChainInfo = struct {
        linking_root: [32]u8,
        header_count: usize,
    };

    fn init(alloc: Allocator) TestCallbacks {
        return .{
            .fetch_requests = .empty,
            .linked_chains = .empty,
            .allocator = alloc,
        };
    }
    fn deinit(self: *TestCallbacks) void {
        self.fetch_requests.deinit(self.allocator);
        self.linked_chains.deinit(self.allocator);
    }
    fn fetchBlockByRoot(ptr: *anyopaque, root: [32]u8, _: []const u8) void {
        const self: *TestCallbacks = @ptrCast(@alignCast(ptr));
        self.fetch_requests.append(self.allocator, .{ .root = root }) catch {};
    }
    fn processLinkedChain(ptr: *anyopaque, linking_root: [32]u8, headers: []const MinimalHeader, peers: *const PeerSet) void {
        const self: *TestCallbacks = @ptrCast(@alignCast(ptr));
        _ = peers;
        self.linked_chains.append(self.allocator, .{
            .linking_root = linking_root,
            .header_count = headers.len,
        }) catch {};
    }
    fn callbacks(self: *TestCallbacks) Callbacks {
        return .{
            .ptr = @ptrCast(self),
            .fetchBlockByRootFn = &fetchBlockByRoot,
            .processLinkedChainFn = &processLinkedChain,
        };
    }
};

test "UnknownChainSync: onUnknownBlockRoot creates chain" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    const root = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(root, "peer-1");

    try std.testing.expectEqual(@as(usize, 1), sync.chainCount());
    try std.testing.expect(sync.isTracking(root));
    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.unknown_head));
}

test "UnknownChainSync: duplicate root doesn't create new chain" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    const root = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(root, "peer-1");
    try sync.onUnknownBlockRoot(root, "peer-2");

    try std.testing.expectEqual(@as(usize, 1), sync.chainCount());
    // Both peers should be tracked.
    try std.testing.expectEqual(@as(usize, 2), sync.chains.items[0].peers.count());
}

test "UnknownChainSync: root in fork choice is ignored" {
    const alloc = std.testing.allocator;
    var fc = TestForkChoice.init(alloc);
    defer fc.deinit();

    const known_root = [_]u8{0x01} ** 32;
    try fc.addRoot(known_root);

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setForkChoice(fc.query());

    try sync.onUnknownBlockRoot(known_root, "peer-1");
    try std.testing.expectEqual(@as(usize, 0), sync.chainCount());
}

test "UnknownChainSync: advance and link via block input" {
    const alloc = std.testing.allocator;
    var fc = TestForkChoice.init(alloc);
    defer fc.deinit();

    const known_root = [_]u8{0xAA} ** 32; // in fork choice
    try fc.addRoot(known_root);

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setForkChoice(fc.query());

    // Unknown root appears.
    const head_root = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(head_root, "peer-1");

    // Header arrives: head_root → parent_root.
    const parent_root = [_]u8{0x02} ** 32;
    try sync.onUnknownBlockInput(100, head_root, parent_root, "peer-1");
    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.unknown_ancestor));

    // Next header: parent_root → known_root (in fork choice).
    try sync.onUnknownBlockInput(99, parent_root, known_root, "peer-1");

    // Chain should now be linked.
    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.linked));
}

test "UnknownChainSync: onBlockImported links chain" {
    const alloc = std.testing.allocator;
    var fc = TestForkChoice.init(alloc);
    defer fc.deinit();

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setForkChoice(fc.query());

    const head_root = [_]u8{0x01} ** 32;
    const parent_root = [_]u8{0x02} ** 32;
    try sync.onUnknownBlockRoot(head_root, "peer-1");
    try sync.onUnknownBlockInput(100, head_root, parent_root, "peer-1");

    // Now parent_root gets imported (and added to fork choice).
    try fc.addRoot(parent_root);
    sync.onBlockImported(parent_root);

    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.linked));
}

test "UnknownChainSync: onFinalized prunes old chains" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    const root = [_]u8{0x01} ** 32;
    const parent = [_]u8{0x02} ** 32;
    try sync.onUnknownBlockRoot(root, "peer-1");
    try sync.onUnknownBlockInput(50, root, parent, "peer-1");

    // Finalize at slot 100 — chain's oldest header (slot 50) is behind.
    sync.onFinalized(100);
    try std.testing.expectEqual(@as(usize, 0), sync.chainCount());
    try std.testing.expectEqual(@as(u64, 1), sync.chains_pruned);
}

test "UnknownChainSync: tick fetches and processes linked chains" {
    const alloc = std.testing.allocator;
    var fc = TestForkChoice.init(alloc);
    defer fc.deinit();
    var cbs = TestCallbacks.init(alloc);
    defer cbs.deinit();

    const known_root = [_]u8{0xAA} ** 32;
    try fc.addRoot(known_root);

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setForkChoice(fc.query());
    sync.setCallbacks(cbs.callbacks());

    // Create a chain and advance it to linked state.
    const head = [_]u8{0x01} ** 32;
    const mid = [_]u8{0x02} ** 32;
    try sync.onUnknownBlockRoot(head, "peer-1");
    try sync.onUnknownBlockInput(102, head, mid, "peer-1");
    try sync.onUnknownBlockInput(101, mid, known_root, "peer-1");

    // Chain should be linked.
    try std.testing.expectEqual(@as(usize, 1), sync.chainCountByState(.linked));

    // Tick should process the linked chain and remove it.
    sync.tick();

    try std.testing.expectEqual(@as(usize, 0), sync.chainCount());
    try std.testing.expectEqual(@as(usize, 1), cbs.linked_chains.items.len);
    try std.testing.expectEqual(@as(usize, 2), cbs.linked_chains.items[0].header_count);
    try std.testing.expectEqual(@as(u64, 1), sync.linked_chains_processed);
}

test "UnknownChainSync: tick requests fetch for unlinked chains" {
    const alloc = std.testing.allocator;
    var cbs = TestCallbacks.init(alloc);
    defer cbs.deinit();

    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();
    sync.setCallbacks(cbs.callbacks());

    const head = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(head, "peer-1");

    // Tick should request the head root.
    sync.tick();

    try std.testing.expectEqual(@as(usize, 1), cbs.fetch_requests.items.len);
    try std.testing.expectEqualSlices(u8, &head, &cbs.fetch_requests.items[0].root);
}

test "UnknownChainSync: peer connect/disconnect" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    const root = [_]u8{0x01} ** 32;
    try sync.onUnknownBlockRoot(root, "peer-1");

    // Connect a peer with matching head root.
    try sync.onPeerConnected("peer-2", root);
    try std.testing.expectEqual(@as(usize, 2), sync.chains.items[0].peers.count());

    // Disconnect peer-1.
    sync.onPeerDisconnected("peer-1");
    try std.testing.expectEqual(@as(usize, 1), sync.chains.items[0].peers.count());
}

test "UnknownChainSync: evicts oldest at capacity" {
    const alloc = std.testing.allocator;
    var sync = UnknownChainSync.init(alloc);
    defer sync.deinit();

    // Fill to capacity.
    for (0..MAX_CHAINS) |i| {
        var root: [32]u8 = [_]u8{0} ** 32;
        root[0] = @intCast(i);
        try sync.onUnknownBlockRoot(root, "peer-1");
    }
    try std.testing.expectEqual(MAX_CHAINS, sync.chainCount());

    // One more should evict oldest.
    const new_root: [32]u8 = [_]u8{0xFF} ** 32;
    try sync.onUnknownBlockRoot(new_root, "peer-1");
    try std.testing.expectEqual(MAX_CHAINS, sync.chainCount());
}
