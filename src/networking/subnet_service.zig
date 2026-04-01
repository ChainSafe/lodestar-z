//! Subnet subscription management for attestation and sync committee subnets.
//!
//! Tracks which subnets this node should subscribe to based on validator duties.
//! Subscriptions expire after a configurable number of slots (typically 2 epochs).
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#attestation-subnet-bitfield

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const log = std.log.scoped(.subnet_service);

// ── Constants ────────────────────────────────────────────────────────────────

/// Default number of extra slots to keep a subnet subscription alive after its target slot.
/// Gives time for attestation aggregation.
pub const DEFAULT_SUBSCRIPTION_LOOKAHEAD_SLOTS: u64 = 2;

/// Maximum attestation subnet index (64 on mainnet).
pub const ATTESTATION_SUBNET_COUNT: u64 = 64;

/// Maximum sync committee subnet index (4 on mainnet).
pub const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;

const AttestationSubnetSet = std.StaticBitSet(@as(usize, ATTESTATION_SUBNET_COUNT));

// ── Types ────────────────────────────────────────────────────────────────────

pub const SubnetId = u8;

pub const SubnetKind = enum {
    attestation,
    sync_committee,
};

/// A single subnet subscription record.
pub const SubnetSubscription = struct {
    subnet_id: SubnetId,
    kind: SubnetKind,
    /// Slot at which this subscription expires (subscription is active while current_slot <= expiry_slot).
    expiry_slot: u64,
    /// Whether this node is an aggregator on this subnet for the target slot.
    is_aggregator: bool,
};

// ── SubnetService ─────────────────────────────────────────────────────────────

/// Manages subnet subscriptions for validator duties.
///
/// Subscriptions are keyed by (kind, subnet_id) and expire after their target slot.
/// The `onSlot` method should be called on each new slot to prune expired subscriptions.
pub const SubnetService = struct {
    allocator: Allocator,
    /// Attestation subnet subscriptions: subnet_id → SubnetSubscription
    attnets: std.AutoHashMap(SubnetId, SubnetSubscription),
    /// Sync committee subnet subscriptions: subnet_id → SubnetSubscription
    syncnets: std.AutoHashMap(SubnetId, SubnetSubscription),
    /// Aggregator duties keyed by target slot. Used to activate gossip
    /// subscriptions only near the attestation duty rather than for the full
    /// prefetch horizon.
    aggregator_slots: std.AutoHashMap(u64, AttestationSubnetSet),
    /// Current slot, updated via onSlot.
    current_slot: u64,
    /// Extra slots to keep a subscription alive after target slot.
    lookahead_slots: u64,

    pub fn init(allocator: Allocator) SubnetService {
        return .{
            .allocator = allocator,
            .attnets = std.AutoHashMap(SubnetId, SubnetSubscription).init(allocator),
            .syncnets = std.AutoHashMap(SubnetId, SubnetSubscription).init(allocator),
            .aggregator_slots = std.AutoHashMap(u64, AttestationSubnetSet).init(allocator),
            .current_slot = 0,
            .lookahead_slots = DEFAULT_SUBSCRIPTION_LOOKAHEAD_SLOTS,
        };
    }

    pub fn deinit(self: *SubnetService) void {
        self.attnets.deinit();
        self.syncnets.deinit();
        self.aggregator_slots.deinit();
    }

    /// Subscribe to an attestation subnet for the given slot.
    ///
    /// The subscription expires at `slot + lookahead_slots`.
    /// If already subscribed, updates the expiry if the new one is later.
    pub fn subscribeToAttestationSubnet(
        self: *SubnetService,
        subnet_id: SubnetId,
        slot: u64,
        is_aggregator: bool,
    ) !void {
        const expiry_slot = slot + self.lookahead_slots;
        const sub = SubnetSubscription{
            .subnet_id = subnet_id,
            .kind = .attestation,
            .expiry_slot = expiry_slot,
            .is_aggregator = is_aggregator,
        };

        const entry = try self.attnets.getOrPut(subnet_id);
        if (!entry.found_existing or entry.value_ptr.expiry_slot < expiry_slot) {
            entry.value_ptr.* = sub;
            log.debug("subscribed to attestation subnet {} until slot {}", .{ subnet_id, expiry_slot });
        }

        if (is_aggregator) {
            const slot_entry = try self.aggregator_slots.getOrPut(slot);
            if (!slot_entry.found_existing) {
                slot_entry.value_ptr.* = AttestationSubnetSet.initEmpty();
            }
            slot_entry.value_ptr.set(subnet_id);
        }
    }

    /// Subscribe to a sync committee subnet for the given slot.
    pub fn subscribeToSyncSubnet(
        self: *SubnetService,
        subnet_id: SubnetId,
        slot: u64,
        is_aggregator: bool,
    ) !void {
        const expiry_slot = slot + self.lookahead_slots;
        const sub = SubnetSubscription{
            .subnet_id = subnet_id,
            .kind = .sync_committee,
            .expiry_slot = expiry_slot,
            .is_aggregator = is_aggregator,
        };

        const entry = try self.syncnets.getOrPut(subnet_id);
        if (!entry.found_existing or entry.value_ptr.expiry_slot < expiry_slot) {
            entry.value_ptr.* = sub;
            log.debug("subscribed to sync subnet {} until slot {}", .{ subnet_id, expiry_slot });
        }
    }

    /// Unsubscribe from an attestation subnet immediately.
    pub fn unsubscribeFromAttestationSubnet(self: *SubnetService, subnet_id: SubnetId) void {
        if (self.attnets.remove(subnet_id)) {
            log.debug("unsubscribed from attestation subnet {}", .{subnet_id});
        }

        var slots_iter = self.aggregator_slots.iterator();
        while (slots_iter.next()) |entry| {
            entry.value_ptr.unset(subnet_id);
        }
    }

    /// Unsubscribe from a sync committee subnet immediately.
    pub fn unsubscribeFromSyncSubnet(self: *SubnetService, subnet_id: SubnetId) void {
        if (self.syncnets.remove(subnet_id)) {
            log.debug("unsubscribed from sync subnet {}", .{subnet_id});
        }
    }

    /// Returns the active attestation subnet IDs. Caller owns the returned slice.
    pub fn getActiveAttestationSubnets(self: *SubnetService) ![]SubnetId {
        var result = std.ArrayListUnmanaged(SubnetId).empty;
        errdefer result.deinit(self.allocator);

        var it = self.attnets.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expiry_slot >= self.current_slot) {
                try result.append(self.allocator, entry.key_ptr.*);
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Returns the active sync committee subnet IDs. Caller owns the returned slice.
    pub fn getActiveSyncSubnets(self: *SubnetService) ![]SubnetId {
        var result = std.ArrayListUnmanaged(SubnetId).empty;
        errdefer result.deinit(self.allocator);

        var it = self.syncnets.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expiry_slot >= self.current_slot) {
                try result.append(self.allocator, entry.key_ptr.*);
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Called on each new slot. Updates current_slot and prunes expired subscriptions.
    pub fn onSlot(self: *SubnetService, slot: u64) void {
        self.current_slot = slot;
        self.pruneExpired(&self.attnets, "attestation");
        self.pruneExpired(&self.syncnets, "sync_committee");
        self.pruneExpiredAggregators();
    }

    /// Remove expired subscriptions from a map.
    fn pruneExpired(
        self: *SubnetService,
        map: *std.AutoHashMap(SubnetId, SubnetSubscription),
        kind_name: []const u8,
    ) void {
        var to_remove: [64]SubnetId = undefined;
        var count: usize = 0;

        var it = map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expiry_slot < self.current_slot) {
                to_remove[count] = entry.key_ptr.*;
                count += 1;
            }
        }

        for (to_remove[0..count]) |subnet_id| {
            _ = map.remove(subnet_id);
            log.debug("pruned expired {s} subnet {}", .{ kind_name, subnet_id });
        }
    }

    /// Returns whether this node is subscribed to the given attestation subnet.
    pub fn isSubscribedToAttestationSubnet(self: *SubnetService, subnet_id: SubnetId) bool {
        const sub = self.attnets.get(subnet_id) orelse return false;
        return sub.expiry_slot >= self.current_slot;
    }

    /// Returns whether this node is subscribed to the given sync subnet.
    pub fn isSubscribedToSyncSubnet(self: *SubnetService, subnet_id: SubnetId) bool {
        const sub = self.syncnets.get(subnet_id) orelse return false;
        return sub.expiry_slot >= self.current_slot;
    }

    /// Returns whether this node is acting as aggregator on the given attestation subnet.
    pub fn isAggregatorOnAttestationSubnet(self: *SubnetService, subnet_id: SubnetId) bool {
        var slots_iter = self.aggregator_slots.iterator();
        while (slots_iter.next()) |entry| {
            const target_slot = entry.key_ptr.*;
            if (target_slot < self.current_slot) continue;
            if (target_slot > self.current_slot + self.lookahead_slots) continue;
            if (entry.value_ptr.isSet(subnet_id)) return true;
        }
        return false;
    }

    /// Returns attestation subnets whose aggregator duties are close enough that
    /// the node should maintain a local gossip subscription now.
    pub fn getGossipAttestationSubnets(self: *SubnetService) ![]SubnetId {
        var active = AttestationSubnetSet.initEmpty();
        var slots_iter = self.aggregator_slots.iterator();
        while (slots_iter.next()) |entry| {
            const target_slot = entry.key_ptr.*;
            if (target_slot < self.current_slot) continue;
            if (target_slot > self.current_slot + self.lookahead_slots) continue;
            active.setUnion(entry.value_ptr.*);
        }

        var result = std.ArrayListUnmanaged(SubnetId).empty;
        errdefer result.deinit(self.allocator);

        var subnet: usize = 0;
        while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
            if (!active.isSet(subnet)) continue;
            try result.append(self.allocator, @intCast(subnet));
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Total number of active subscriptions (attestation + sync).
    pub fn activeCount(self: *SubnetService) usize {
        var count: usize = 0;
        {
            var it = self.attnets.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.expiry_slot >= self.current_slot) count += 1;
            }
        }
        {
            var it = self.syncnets.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.expiry_slot >= self.current_slot) count += 1;
            }
        }
        return count;
    }

    fn pruneExpiredAggregators(self: *SubnetService) void {
        var to_remove: [64]u64 = undefined;
        var count: usize = 0;

        var iter = self.aggregator_slots.iterator();
        while (iter.next()) |entry| {
            if (entry.key_ptr.* < self.current_slot or entry.value_ptr.count() == 0) {
                to_remove[count] = entry.key_ptr.*;
                count += 1;
            }
        }

        for (to_remove[0..count]) |slot| {
            _ = self.aggregator_slots.remove(slot);
        }
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

test "SubnetService: subscribe and query attestation subnet" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    svc.onSlot(100);
    try svc.subscribeToAttestationSubnet(5, 101, false);

    try testing.expect(svc.isSubscribedToAttestationSubnet(5));
    try testing.expect(!svc.isAggregatorOnAttestationSubnet(5));
    try testing.expect(!svc.isSubscribedToAttestationSubnet(6));
}

test "SubnetService: aggregator flag" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    svc.onSlot(100);
    try svc.subscribeToAttestationSubnet(3, 102, true);

    try testing.expect(svc.isAggregatorOnAttestationSubnet(3));
}

test "SubnetService: aggregator gossip subscription activates near duty slot" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    svc.onSlot(10);
    try svc.subscribeToAttestationSubnet(3, 20, true);
    try testing.expect(!svc.isAggregatorOnAttestationSubnet(3));

    svc.onSlot(18);
    try testing.expect(svc.isAggregatorOnAttestationSubnet(3));

    const gossip_subnets = try svc.getGossipAttestationSubnets();
    defer testing.allocator.free(gossip_subnets);
    try testing.expectEqual(@as(usize, 1), gossip_subnets.len);
    try testing.expectEqual(@as(SubnetId, 3), gossip_subnets[0]);
}

test "SubnetService: later non-aggregator duty does not clear pending aggregator duty" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    svc.onSlot(30);
    try svc.subscribeToAttestationSubnet(5, 32, true);
    try svc.subscribeToAttestationSubnet(5, 40, false);

    try testing.expect(svc.isAggregatorOnAttestationSubnet(5));
}

test "SubnetService: subscription expiry via onSlot" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    // Subscribe at slot 100, expiry = 102 (100 + 2 lookahead).
    svc.onSlot(100);
    try svc.subscribeToAttestationSubnet(7, 100, false);
    try testing.expect(svc.isSubscribedToAttestationSubnet(7));

    // Advance past expiry.
    svc.onSlot(103);
    try testing.expect(!svc.isSubscribedToAttestationSubnet(7));
}

test "SubnetService: prune removes expired entries" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    svc.onSlot(10);
    try svc.subscribeToAttestationSubnet(1, 10, false); // expiry = 12
    try svc.subscribeToAttestationSubnet(2, 20, false); // expiry = 22
    try testing.expectEqual(@as(usize, 2), svc.attnets.count());

    svc.onSlot(15); // expires subnet 1
    try testing.expectEqual(@as(usize, 1), svc.attnets.count());
    try testing.expect(!svc.isSubscribedToAttestationSubnet(1));
    try testing.expect(svc.isSubscribedToAttestationSubnet(2));
}

test "SubnetService: unsubscribe" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    svc.onSlot(50);
    try svc.subscribeToAttestationSubnet(9, 60, true);
    try testing.expect(svc.isSubscribedToAttestationSubnet(9));

    svc.unsubscribeFromAttestationSubnet(9);
    try testing.expect(!svc.isSubscribedToAttestationSubnet(9));
}

test "SubnetService: getActiveAttestationSubnets" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    svc.onSlot(100);
    try svc.subscribeToAttestationSubnet(1, 105, false);
    try svc.subscribeToAttestationSubnet(2, 110, false);

    const active = try svc.getActiveAttestationSubnets();
    defer testing.allocator.free(active);

    try testing.expectEqual(@as(usize, 2), active.len);
}

test "SubnetService: sync committee subnets" {
    var svc = SubnetService.init(testing.allocator);
    defer svc.deinit();

    svc.onSlot(200);
    try svc.subscribeToSyncSubnet(0, 205, true);
    try svc.subscribeToSyncSubnet(2, 205, false);

    try testing.expect(svc.isSubscribedToSyncSubnet(0));
    try testing.expect(svc.isSubscribedToSyncSubnet(2));
    try testing.expect(!svc.isSubscribedToSyncSubnet(1));

    const active = try svc.getActiveSyncSubnets();
    defer testing.allocator.free(active);
    try testing.expectEqual(@as(usize, 2), active.len);
}
