const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const networking = @import("networking");
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const AnyGossipAttestation = fork_types.AnyGossipAttestation;
const AnySignedAggregateAndProof = fork_types.AnySignedAggregateAndProof;
const processor_mod = @import("processor");
const ResolvedAggregate = processor_mod.work_item.ResolvedAggregate;
const ResolvedAttestation = processor_mod.work_item.ResolvedAttestation;
const gossip_handler_mod = @import("gossip_handler.zig");
const GossipHandler = gossip_handler_mod.GossipHandler;
const GossipHandlerError = gossip_handler_mod.GossipHandlerError;

// ============================================================
// Tests
// ============================================================

const consensus_types = @import("consensus_types");
const phase0 = consensus_types.phase0;

// --- Test stubs ---

var g_imported_count: u32 = 0;

fn stubImportBlock(_: *anyopaque, _: []const u8) anyerror!void {
    g_imported_count += 1;
}

fn stubGetProposerIndex(_: *anyopaque, slot: u64) ?u32 {
    return @intCast(slot % 100);
}

fn stubGetForkSeqForSlot(_: *anyopaque, _: u64) ForkSeq {
    return .phase0;
}

fn stubIsKnownBlockRoot(_: *anyopaque, _: [32]u8) bool {
    return true; // all parents known
}

fn stubGetValidatorCount(_: *anyopaque) u32 {
    return 1000;
}

fn stubResolveAttestation(
    _: *anyopaque,
    attestation: *const AnyGossipAttestation,
    _: *const [32]u8,
) anyerror!ResolvedAttestation {
    const committee_index = attestation.committeeIndex();
    const slots_since_epoch_start = attestation.slot() % preset.SLOTS_PER_EPOCH;
    return .{
        .validator_index = switch (attestation.*) {
            .phase0 => 0,
            .electra_single => |single| single.attester_index,
        },
        .validator_committee_index = 0,
        .committee_size = 1,
        .signing_root = [_]u8{0} ** 32,
        .expected_subnet = @intCast((slots_since_epoch_start + committee_index) % networking.peer_info.ATTESTATION_SUBNET_COUNT),
    };
}

fn stubResolveAggregate(
    _: *anyopaque,
    _: *const AnySignedAggregateAndProof,
    _: *const [32]u8,
) anyerror!ResolvedAggregate {
    return .{
        .attestation_signing_root = [_]u8{0} ** 32,
        .selection_signing_root = [_]u8{0} ** 32,
        .aggregate_signing_root = [_]u8{0} ** 32,
        .attesting_indices = &.{},
    };
}

fn stubIsValidSyncCommitteeSubnet(_: *anyopaque, _: u64, validator_index: u64, subnet: u64) bool {
    const subcommittee_size = preset.SYNC_COMMITTEE_SIZE / networking.peer_info.SYNC_COMMITTEE_SUBNET_COUNT;
    return @divFloor(validator_index, subcommittee_size) == subnet;
}

fn stubVerifySyncCommitteeSignatureFalse(_: *anyopaque, _: []const u8) bool {
    return false;
}

fn makeTestHandler(allocator: Allocator) !*GossipHandler {
    var dummy_node: u8 = 0;
    return GossipHandler.create(
        allocator,
        @ptrCast(&dummy_node),
        &stubImportBlock,
        &stubGetForkSeqForSlot,
        &stubGetProposerIndex,
        &stubIsKnownBlockRoot,
        &stubGetValidatorCount,
        &stubResolveAttestation,
        &stubResolveAggregate,
        &stubIsValidSyncCommitteeSubnet,
    );
}

fn makeSnappyBlock(allocator: Allocator, slot: u64, proposer: u64) ![]u8 {
    const snappy = @import("snappy").frame;
    var block: phase0.SignedBeaconBlock.Type = phase0.SignedBeaconBlock.default_value;
    block.message.slot = slot;
    block.message.proposer_index = proposer;
    block.message.parent_root = [_]u8{0xAA} ** 32;

    const ssz_size = phase0.SignedBeaconBlock.serializedSize(&block);
    const ssz_buf = try allocator.alloc(u8, ssz_size);
    defer allocator.free(ssz_buf);
    _ = phase0.SignedBeaconBlock.serializeIntoBytes(&block, ssz_buf);

    return snappy.compress(allocator, ssz_buf);
}

test "GossipHandler: onBeaconBlock imports valid block" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(10, 0, 0);
    g_imported_count = 0;

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    try handler.onBeaconBlock(compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_count);
}

test "GossipHandler: onBeaconBlock ignores duplicate block" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(10, 0, 0);
    g_imported_count = 0;

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    try handler.onBeaconBlock(compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_count);

    const result = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
    try testing.expectEqual(@as(u32, 1), g_imported_count);
}

test "GossipHandler: onBeaconBlock ignores future slot" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(5, 0, 0);

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    const result = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
}

test "GossipHandler: onBeaconBlock ignores finalized block" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(30, 0, 20);

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    const result = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
}

test "GossipHandler: onAttestation decodes and validates" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra); // SingleAttestation format requires Electra+

    // Create a valid SingleAttestation, serialize, compress.
    var att: consensus_types.electra.SingleAttestation.Type = consensus_types.electra.SingleAttestation.default_value;
    att.committee_index = 0;
    att.attester_index = 5;
    att.data.slot = 96;
    att.data.target.epoch = 3;
    att.data.target.root = [_]u8{0xAA} ** 32; // known root (mock returns true)
    att.data.beacon_block_root = [_]u8{0xBB} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try snappy.compress(alloc, &ssz_buf);
    defer alloc.free(compressed);

    // Should pass validation (epoch 3 is current).
    try handler.onAttestation(0, compressed);
}

test "GossipHandler: onAttestation rejects stale epoch" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra); // SingleAttestation format requires Electra+

    // Attestation from epoch 0 — outside current/previous window.
    var att: consensus_types.electra.SingleAttestation.Type = consensus_types.electra.SingleAttestation.default_value;
    att.data.slot = 5;
    att.data.target.epoch = 0;
    att.data.target.root = [_]u8{0xAA} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try snappy.compress(alloc, &ssz_buf);
    defer alloc.free(compressed);

    const result = handler.onAttestation(5, compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
}

test "GossipHandler: onAttestation rejects pre-electra aggregated attestations" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.phase0);

    var att: consensus_types.phase0.Attestation.Type = consensus_types.phase0.Attestation.default_value;
    try att.aggregation_bits.data.append(alloc, 0x03);
    att.aggregation_bits.bit_len = 2;
    defer att.aggregation_bits.data.deinit(alloc);
    att.data.slot = 96;
    att.data.index = 0;
    att.data.target.epoch = 3;
    att.data.target.root = [_]u8{0xAA} ** 32;
    att.data.beacon_block_root = [_]u8{0xBB} ** 32;

    const ssz_size = consensus_types.phase0.Attestation.serializedSize(&att);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = consensus_types.phase0.Attestation.serializeIntoBytes(&att, ssz_buf);

    const compressed = try snappy.compress(alloc, ssz_buf);
    defer alloc.free(compressed);

    try testing.expectError(GossipHandlerError.ValidationRejected, handler.onAttestation(0, compressed));
}

test "GossipHandler: process result classifies wrong subnet" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra);

    var att: consensus_types.electra.SingleAttestation.Type = consensus_types.electra.SingleAttestation.default_value;
    att.committee_index = 0;
    att.attester_index = 5;
    att.data.slot = 96;
    att.data.target.epoch = 3;
    att.data.target.root = [_]u8{0xAA} ** 32;
    att.data.beacon_block_root = [_]u8{0xBB} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try snappy.compress(alloc, &ssz_buf);
    defer alloc.free(compressed);

    const result = handler.processGossipMessageWithSubnetAndMetadata(.beacon_attestation, 1, compressed, .{});
    switch (result) {
        .rejected => |reason| try testing.expectEqual(networking.peer_scoring.GossipRejectReason.wrong_subnet, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "GossipHandler: onAttestation rejects wrong subnet" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra);

    var att: consensus_types.electra.SingleAttestation.Type = consensus_types.electra.SingleAttestation.default_value;
    att.committee_index = 0;
    att.attester_index = 5;
    att.data.slot = 96;
    att.data.target.epoch = 3;
    att.data.target.root = [_]u8{0xAA} ** 32;
    att.data.beacon_block_root = [_]u8{0xBB} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try snappy.compress(alloc, &ssz_buf);
    defer alloc.free(compressed);

    try testing.expectError(GossipHandlerError.ValidationRejected, handler.onAttestation(1, compressed));
}

test "GossipHandler: onSyncCommitteeMessage rejects wrong subnet" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);

    const msg = consensus_types.altair.SyncCommitteeMessage.Type{
        .slot = 100,
        .beacon_block_root = [_]u8{0xAB} ** 32,
        .validator_index = 7,
        .signature = [_]u8{0xCD} ** 96,
    };

    var ssz_buf: [consensus_types.altair.SyncCommitteeMessage.fixed_size]u8 = undefined;
    _ = consensus_types.altair.SyncCommitteeMessage.serializeIntoBytes(&msg, &ssz_buf);

    const compressed = try snappy.compress(alloc, &ssz_buf);
    defer alloc.free(compressed);

    try testing.expectError(GossipHandlerError.ValidationRejected, handler.onSyncCommitteeMessage(1, compressed));
}

test "GossipHandler: onGossipMessage routes beacon_block" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(42, 1, 0);
    g_imported_count = 0;

    const compressed = try makeSnappyBlock(alloc, 42, 42);
    defer alloc.free(compressed);

    try handler.onGossipMessage(.beacon_block, compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_count);
}

test "GossipHandler: process result classifies invalid sync signature" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.verifySyncCommitteeSignatureFn = &stubVerifySyncCommitteeSignatureFalse;

    const msg = consensus_types.altair.SyncCommitteeMessage.Type{
        .slot = 100,
        .beacon_block_root = [_]u8{0xAB} ** 32,
        .validator_index = 7,
        .signature = [_]u8{0xCD} ** 96,
    };

    var ssz_buf: [consensus_types.altair.SyncCommitteeMessage.fixed_size]u8 = undefined;
    _ = consensus_types.altair.SyncCommitteeMessage.serializeIntoBytes(&msg, &ssz_buf);

    const compressed = try snappy.compress(alloc, &ssz_buf);
    defer alloc.free(compressed);

    const result = handler.processGossipMessageWithSubnetAndMetadata(.sync_committee, 0, compressed, .{});
    switch (result) {
        .rejected => |reason| try testing.expectEqual(networking.peer_scoring.GossipRejectReason.invalid_signature, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "GossipHandler: decode failures are returned as errors" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    // Sending invalid data (not valid snappy) should return DecodeFailed
    // for topics that now have real handlers.
    const dummy = [_]u8{ 0, 1, 2, 3 };
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.voluntary_exit, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.proposer_slashing, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.attester_slashing, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.bls_to_execution_change, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.blob_sidecar, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.data_column_sidecar, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.sync_committee, null, &dummy));
    try testing.expectError(GossipHandlerError.DecodeFailed, handler.onGossipMessageWithSubnet(.sync_committee_contribution_and_proof, null, &dummy));
}

test "GossipHandler: onAggregateAndProof validates and accepts" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);

    // Create a valid SignedAggregateAndProof.
    var signed_agg: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 96;
    signed_agg.message.aggregate.data.target.epoch = 3;
    // Need at least 1 set bit for aggregation_bits.
    // Default aggregation_bits is empty — allocate a single byte with bit 0 set.
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = phase0.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try snappy.compress(alloc, ssz_buf);
    defer alloc.free(compressed);

    try handler.onAggregateAndProof(compressed);
}

test "GossipHandler: onAggregateAndProof validates electra aggregates" {
    const alloc = testing.allocator;
    const snappy = @import("snappy").frame;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra);

    var signed_agg: consensus_types.electra.SignedAggregateAndProof.Type = consensus_types.electra.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 96;
    signed_agg.message.aggregate.data.target.epoch = 3;
    signed_agg.message.aggregate.data.index = 0;
    try signed_agg.message.aggregate.committee_bits.set(0, true);
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = consensus_types.electra.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = consensus_types.electra.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try snappy.compress(alloc, ssz_buf);
    defer alloc.free(compressed);

    try handler.onAggregateAndProof(compressed);
}
