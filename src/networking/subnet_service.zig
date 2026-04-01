//! Subnet subscription management for attestation and sync committee subnets.
//!
//! Tracks which subnets this node should subscribe to based on validator duties.
//! Separates:
//! - peer-demand retention for committee duties
//! - pre-duty mesh participation for attestation aggregators
//! - deterministic long-lived attestation subnets for ENR/metadata
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#attestation-subnet-bitfield

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Sha256 = std.crypto.hash.sha2.Sha256;
const constants = @import("constants");
const preset = @import("preset").preset;

const log = std.log.scoped(.subnet_service);

// ── Constants ────────────────────────────────────────────────────────────────

/// Subscribe to attestation subnet meshes this many slots before an
/// aggregator duty so there is time to form a healthy mesh.
pub const DEFAULT_AGGREGATOR_SUBSCRIPTION_LEAD_SLOTS: u64 = 2;

/// Committee subnet demand remains relevant through the dutied slot and the
/// immediately following slot so submitted attestations can still be spread.
pub const ATTESTATION_COMMITTEE_RETENTION_SLOTS: u64 = 1;

/// Maximum attestation subnet index (64 on mainnet).
pub const ATTESTATION_SUBNET_COUNT: u64 = constants.ATTESTATION_SUBNET_COUNT;

/// Maximum sync committee subnet index (4 on mainnet).
pub const SYNC_COMMITTEE_SUBNET_COUNT: u64 = constants.SYNC_COMMITTEE_SUBNET_COUNT;

const AttestationSubnetSet = std.StaticBitSet(@as(usize, ATTESTATION_SUBNET_COUNT));
const LongLivedSubscriptionPeriod = u64;

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

/// Manages subnet subscriptions for validator duties and long-lived attnets.
///
/// The `onSlot` method should be called on each new slot to prune expired
/// subscriptions and rotate long-lived attestation subnets when necessary.
pub const SubnetService = struct {
    allocator: Allocator,
    /// Validator-duty attestation subnets: subnet_id → SubnetSubscription.
    /// These drive peer discovery / prioritization but not long-lived ENR
    /// advertisement.
    attnets: std.AutoHashMap(SubnetId, SubnetSubscription),
    /// Sync committee subnet subscriptions: subnet_id → SubnetSubscription
    syncnets: std.AutoHashMap(SubnetId, SubnetSubscription),
    /// Aggregator duties keyed by target slot. Used to activate gossip
    /// subscriptions only near the attestation duty rather than for the full
    /// prefetch horizon.
    aggregator_slots: std.AutoHashMap(u64, AttestationSubnetSet),
    /// Deterministic long-lived attestation subnets advertised in metadata/ENR
    /// and maintained in the gossip mesh regardless of near-term duties.
    long_lived_attnets: AttestationSubnetSet,
    /// Local discv5 node ID used to deterministically derive long-lived
    /// attestation subnets. Null disables the long-lived subscription model.
    node_id: ?[32]u8,
    long_lived_subscription_period: ?LongLivedSubscriptionPeriod,
    /// Current slot, updated via onSlot.
    current_slot: u64,
    /// Number of slots before an aggregator duty at which the node should
    /// actively join the attestation subnet gossip mesh.
    aggregator_subscription_lead_slots: u64,

    pub fn init(allocator: Allocator, node_id: ?[32]u8) SubnetService {
        var self: SubnetService = .{
            .allocator = allocator,
            .attnets = std.AutoHashMap(SubnetId, SubnetSubscription).init(allocator),
            .syncnets = std.AutoHashMap(SubnetId, SubnetSubscription).init(allocator),
            .aggregator_slots = std.AutoHashMap(u64, AttestationSubnetSet).init(allocator),
            .long_lived_attnets = AttestationSubnetSet.initEmpty(),
            .node_id = node_id,
            .long_lived_subscription_period = null,
            .current_slot = 0,
            .aggregator_subscription_lead_slots = DEFAULT_AGGREGATOR_SUBSCRIPTION_LEAD_SLOTS,
        };
        self.recomputeLongLivedAttestationSubnets(0);
        return self;
    }

    pub fn deinit(self: *SubnetService) void {
        self.attnets.deinit();
        self.syncnets.deinit();
        self.aggregator_slots.deinit();
    }

    /// Subscribe to an attestation subnet for the given slot.
    ///
    /// Committee demand expires at `slot + 1`, matching Lodestar's
    /// committeeSubnets behavior: keep peers long enough to spread the
    /// submitted attestation, but do not conflate that with aggregator mesh
    /// pre-subscription timing.
    ///
    /// If already subscribed, updates the expiry if the new one is later.
    pub fn subscribeToAttestationSubnet(
        self: *SubnetService,
        subnet_id: SubnetId,
        slot: u64,
        is_aggregator: bool,
    ) !void {
        const expiry_slot = slot + ATTESTATION_COMMITTEE_RETENTION_SLOTS;
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
        const expiry_slot = slot;
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
        var active = self.long_lived_attnets;
        var it = self.attnets.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expiry_slot >= self.current_slot) {
                active.set(entry.key_ptr.*);
            }
        }
        return bitsetToOwnedSlice(self.allocator, active);
    }

    /// Returns the attestation subnets to advertise in metadata / ENR.
    ///
    /// This intentionally excludes short-lived validator duties. Per Lodestar
    /// and the spec, metadata attnets should represent the node's deterministic
    /// long-lived mesh participation rather than transient aggregation duties.
    pub fn getMetadataAttestationSubnets(self: *SubnetService) ![]SubnetId {
        return bitsetToOwnedSlice(self.allocator, self.long_lived_attnets);
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
        self.recomputeLongLivedAttestationSubnets(@divFloor(slot, preset.SLOTS_PER_EPOCH));
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
        if (self.long_lived_attnets.isSet(subnet_id)) return true;
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
            if (target_slot > self.current_slot + self.aggregator_subscription_lead_slots) continue;
            if (entry.value_ptr.isSet(subnet_id)) return true;
        }
        return false;
    }

    /// Returns attestation subnets whose aggregator duties are close enough that
    /// the node should maintain a local gossip subscription now.
    pub fn getGossipAttestationSubnets(self: *SubnetService) ![]SubnetId {
        var active = self.long_lived_attnets;
        var slots_iter = self.aggregator_slots.iterator();
        while (slots_iter.next()) |entry| {
            const target_slot = entry.key_ptr.*;
            if (target_slot < self.current_slot) continue;
            if (target_slot > self.current_slot + self.aggregator_subscription_lead_slots) continue;
            active.setUnion(entry.value_ptr.*);
        }
        return bitsetToOwnedSlice(self.allocator, active);
    }

    /// Total number of active subscriptions (attestation + sync).
    pub fn activeCount(self: *SubnetService) usize {
        var count: usize = self.long_lived_attnets.count();
        var active_short_lived = self.attnets.iterator();
        while (active_short_lived.next()) |entry| {
            if (entry.value_ptr.expiry_slot >= self.current_slot and !self.long_lived_attnets.isSet(entry.key_ptr.*)) {
                count += 1;
            }
        }

        var active_sync = self.syncnets.iterator();
        while (active_sync.next()) |entry| {
            if (entry.value_ptr.expiry_slot >= self.current_slot) count += 1;
        }
        return count;
    }

    fn recomputeLongLivedAttestationSubnets(self: *SubnetService, epoch: u64) void {
        const node_id = self.node_id orelse {
            self.long_lived_attnets = AttestationSubnetSet.initEmpty();
            self.long_lived_subscription_period = null;
            return;
        };

        const subscription_period = @divFloor(epoch, constants.EPOCHS_PER_SUBNET_SUBSCRIPTION);
        if (self.long_lived_subscription_period) |current_period| {
            if (current_period == subscription_period) return;
        }

        var updated = AttestationSubnetSet.initEmpty();
        var index: u64 = 0;
        while (index < constants.SUBNETS_PER_NODE) : (index += 1) {
            updated.set(computeSubscribedSubnetByIndex(node_id, epoch, index));
        }

        self.long_lived_attnets = updated;
        self.long_lived_subscription_period = subscription_period;
    }

    fn computeSubscribedSubnetByIndex(node_id: [32]u8, epoch: u64, index: u64) SubnetId {
        const node_id_prefix = getNodeIdPrefix(node_id);
        const node_offset = getNodeOffset(node_id);
        const permutation_epoch = @divFloor(epoch + node_offset, constants.EPOCHS_PER_SUBNET_SUBSCRIPTION);

        var seed_input = [_]u8{0} ** 8;
        std.mem.writeInt(u64, seed_input[0..], permutation_epoch, .little);

        var permutation_seed: [32]u8 = undefined;
        Sha256.hash(seed_input[0..], &permutation_seed, .{});

        const permutated_prefix = computeShuffledIndex(
            node_id_prefix,
            1 << constants.ATTESTATION_SUBNET_PREFIX_BITS,
            &permutation_seed,
        );
        return @intCast((permutated_prefix + index) % constants.ATTESTATION_SUBNET_COUNT);
    }

    fn getNodeIdPrefix(node_id: [32]u8) u64 {
        const total_shifted_bits: usize = @as(usize, constants.NODE_ID_BITS) - @as(usize, constants.ATTESTATION_SUBNET_PREFIX_BITS);
        const shifted_bits = total_shifted_bits % 8;
        return node_id[0] >> shifted_bits;
    }

    fn getNodeOffset(node_id: [32]u8) u64 {
        return node_id[node_id.len - 1];
    }

    fn computeShuffledIndex(index: u64, index_count: u64, seed: *const [32]u8) u64 {
        var permuted = index;
        var pivot_input = [_]u8{0} ** 33;
        var source_input = [_]u8{0} ** 37;
        @memcpy(pivot_input[0..32], seed);
        @memcpy(source_input[0..32], seed);

        var round: usize = 0;
        while (round < preset.SHUFFLE_ROUND_COUNT) : (round += 1) {
            pivot_input[32] = @intCast(round);

            var pivot_digest: [32]u8 = undefined;
            Sha256.hash(pivot_input[0..], &pivot_digest, .{});
            const pivot = std.mem.readInt(u64, pivot_digest[0..8], .little) % index_count;

            const flip = (pivot + index_count - permuted) % index_count;
            const position = @max(permuted, flip);
            const position_div: u32 = @intCast(position / 256);

            source_input[32] = @intCast(round);
            std.mem.writeInt(u32, source_input[33..37], position_div, .little);

            var source_digest: [32]u8 = undefined;
            Sha256.hash(source_input[0..], &source_digest, .{});
            const byte = source_digest[@intCast((position % 256) / 8)];
            const bit = (byte >> @intCast(position % 8)) & 1;
            if (bit == 1) permuted = flip;
        }

        return permuted;
    }

    fn bitsetToOwnedSlice(allocator: Allocator, bitset: AttestationSubnetSet) ![]SubnetId {
        var result = std.ArrayListUnmanaged(SubnetId).empty;
        errdefer result.deinit(allocator);

        var subnet: usize = 0;
        while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
            if (!bitset.isSet(subnet)) continue;
            try result.append(allocator, @intCast(subnet));
        }
        return result.toOwnedSlice(allocator);
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

fn containsSubnet(subnets: []const SubnetId, subnet_id: SubnetId) bool {
    for (subnets) |subnet| {
        if (subnet == subnet_id) return true;
    }
    return false;
}

test "SubnetService: subscribe and query attestation subnet" {
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    svc.onSlot(100);
    try svc.subscribeToAttestationSubnet(5, 101, false);

    try testing.expect(svc.isSubscribedToAttestationSubnet(5));
    try testing.expect(!svc.isAggregatorOnAttestationSubnet(5));
    try testing.expect(!svc.isSubscribedToAttestationSubnet(6));
}

test "SubnetService: aggregator flag" {
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    svc.onSlot(100);
    try svc.subscribeToAttestationSubnet(3, 102, true);

    try testing.expect(svc.isAggregatorOnAttestationSubnet(3));
}

test "SubnetService: aggregator gossip subscription activates near duty slot" {
    var svc = SubnetService.init(testing.allocator, null);
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
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    svc.onSlot(30);
    try svc.subscribeToAttestationSubnet(5, 32, true);
    try svc.subscribeToAttestationSubnet(5, 40, false);

    try testing.expect(svc.isAggregatorOnAttestationSubnet(5));
}

test "SubnetService: subscription expiry via onSlot" {
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    // Committee demand persists through slot + 1.
    svc.onSlot(100);
    try svc.subscribeToAttestationSubnet(7, 100, false);
    try testing.expect(svc.isSubscribedToAttestationSubnet(7));

    svc.onSlot(101);
    try testing.expect(svc.isSubscribedToAttestationSubnet(7));

    // Advance past expiry.
    svc.onSlot(102);
    try testing.expect(!svc.isSubscribedToAttestationSubnet(7));
}

test "SubnetService: prune removes expired entries" {
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    svc.onSlot(10);
    try svc.subscribeToAttestationSubnet(1, 10, false); // expiry = 11
    try svc.subscribeToAttestationSubnet(2, 20, false); // expiry = 21
    try testing.expectEqual(@as(usize, 2), svc.attnets.count());

    svc.onSlot(12); // expires subnet 1
    try testing.expectEqual(@as(usize, 1), svc.attnets.count());
    try testing.expect(!svc.isSubscribedToAttestationSubnet(1));
    try testing.expect(svc.isSubscribedToAttestationSubnet(2));
}

test "SubnetService: unsubscribe" {
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    svc.onSlot(50);
    try svc.subscribeToAttestationSubnet(9, 60, true);
    try testing.expect(svc.isSubscribedToAttestationSubnet(9));

    svc.unsubscribeFromAttestationSubnet(9);
    try testing.expect(!svc.isSubscribedToAttestationSubnet(9));
}

test "SubnetService: getActiveAttestationSubnets" {
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    svc.onSlot(100);
    try svc.subscribeToAttestationSubnet(1, 105, false);
    try svc.subscribeToAttestationSubnet(2, 110, false);

    const active = try svc.getActiveAttestationSubnets();
    defer testing.allocator.free(active);

    try testing.expectEqual(@as(usize, 2), active.len);
}

test "SubnetService: sync committee subnets" {
    var svc = SubnetService.init(testing.allocator, null);
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

test "SubnetService: long-lived attnets feed metadata and baseline gossip" {
    var node_id = [_]u8{0} ** 32;
    node_id[0] = 0xa4;
    node_id[31] = 0x1d;

    var svc = SubnetService.init(testing.allocator, node_id);
    defer svc.deinit();

    svc.onSlot(0);

    const metadata = try svc.getMetadataAttestationSubnets();
    defer testing.allocator.free(metadata);
    try testing.expectEqual(@as(usize, constants.SUBNETS_PER_NODE), metadata.len);

    const gossip = try svc.getGossipAttestationSubnets();
    defer testing.allocator.free(gossip);
    try testing.expectEqualSlices(SubnetId, metadata, gossip);

    const active = try svc.getActiveAttestationSubnets();
    defer testing.allocator.free(active);
    try testing.expectEqualSlices(SubnetId, metadata, active);
}

test "SubnetService: short-lived duties do not leak into metadata attnets" {
    var node_id = [_]u8{0} ** 32;
    node_id[0] = 0x5c;
    node_id[31] = 0xe7;

    var svc = SubnetService.init(testing.allocator, node_id);
    defer svc.deinit();

    svc.onSlot(32);

    const metadata_before = try svc.getMetadataAttestationSubnets();
    defer testing.allocator.free(metadata_before);

    var duty_subnet: ?SubnetId = null;
    var subnet: usize = 0;
    while (subnet < ATTESTATION_SUBNET_COUNT) : (subnet += 1) {
        const candidate: SubnetId = @intCast(subnet);
        if (!containsSubnet(metadata_before, candidate)) {
            duty_subnet = candidate;
            break;
        }
    }
    try testing.expect(duty_subnet != null);

    try svc.subscribeToAttestationSubnet(duty_subnet.?, 40, true);

    const metadata_after = try svc.getMetadataAttestationSubnets();
    defer testing.allocator.free(metadata_after);
    try testing.expectEqualSlices(SubnetId, metadata_before, metadata_after);

    const active = try svc.getActiveAttestationSubnets();
    defer testing.allocator.free(active);
    try testing.expectEqual(metadata_before.len + 1, active.len);
    try testing.expect(containsSubnet(active, duty_subnet.?));

    svc.onSlot(38);
    const gossip = try svc.getGossipAttestationSubnets();
    defer testing.allocator.free(gossip);
    try testing.expectEqual(metadata_before.len + 1, gossip.len);
    try testing.expect(containsSubnet(gossip, duty_subnet.?));
}

test "SubnetService: attestation committee demand outlives gossip mesh by one slot" {
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    svc.onSlot(30);
    try svc.subscribeToAttestationSubnet(6, 32, true);

    svc.onSlot(32);
    try testing.expect(svc.isSubscribedToAttestationSubnet(6));
    try testing.expect(svc.isAggregatorOnAttestationSubnet(6));

    svc.onSlot(33);
    try testing.expect(svc.isSubscribedToAttestationSubnet(6));
    try testing.expect(!svc.isAggregatorOnAttestationSubnet(6));

    const gossip = try svc.getGossipAttestationSubnets();
    defer testing.allocator.free(gossip);
    try testing.expect(!containsSubnet(gossip, 6));
}

test "SubnetService: sync committee expiry is exact" {
    var svc = SubnetService.init(testing.allocator, null);
    defer svc.deinit();

    svc.onSlot(50);
    try svc.subscribeToSyncSubnet(1, 55, false);
    svc.onSlot(55);
    try testing.expect(svc.isSubscribedToSyncSubnet(1));
    svc.onSlot(56);
    try testing.expect(!svc.isSubscribedToSyncSubnet(1));
}
