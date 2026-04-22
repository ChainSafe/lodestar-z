const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const networking = @import("networking");
const chain_mod = @import("chain");
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
const UnknownParentBlock = gossip_handler_mod.UnknownParentBlock;
const snappy = @import("snappy").raw;

// ============================================================
// Tests
// ============================================================

const consensus_types = @import("consensus_types");
const phase0 = consensus_types.phase0;

// --- Test stubs ---

var g_imported_count: u32 = 0;
var g_imported_aggregate_count: u32 = 0;
var g_verify_aggregate_failures_remaining: u32 = 0;
var g_queued_unknown_block_count: u32 = 0;
var g_queued_unknown_block_attestation_count: u32 = 0;
var g_queued_unknown_block_aggregate_count: u32 = 0;
var g_last_unknown_slot: ?u64 = null;
var g_last_unknown_peer: ?[]const u8 = null;
var g_last_unknown_root: ?[32]u8 = null;

fn stubImportBlock(_: *anyopaque, prepared: chain_mod.PreparedBlockInput) anyerror!void {
    var owned = prepared;
    defer owned.deinit(testing.allocator);
    g_imported_count += 1;
}

fn stubQueueUnknownBlock(_: *anyopaque, block: UnknownParentBlock) anyerror!void {
    var owned = block;
    g_queued_unknown_block_count += 1;
    g_last_unknown_slot = owned.block.beaconBlock().slot();
    g_last_unknown_peer = owned.peer_id;
    owned.block.deinit(testing.allocator);
}

fn stubQueueUnknownBlockAttestation(
    _: *anyopaque,
    block_root: [32]u8,
    work: processor_mod.work_item.AttestationWork,
    peer_id: ?[]const u8,
) anyerror!bool {
    var owned = work;
    defer owned.attestation.deinit(testing.allocator);
    g_queued_unknown_block_attestation_count += 1;
    g_last_unknown_root = block_root;
    g_last_unknown_peer = peer_id;
    return true;
}

fn stubQueueUnknownBlockAggregate(
    _: *anyopaque,
    block_root: [32]u8,
    work: processor_mod.work_item.AggregateWork,
    peer_id: ?[]const u8,
) anyerror!bool {
    var owned = work;
    defer {
        owned.resolved.deinit(testing.allocator);
        owned.aggregate.deinit(testing.allocator);
    }
    g_queued_unknown_block_aggregate_count += 1;
    g_last_unknown_root = block_root;
    g_last_unknown_peer = peer_id;
    return true;
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

fn stubIsKnownBlockRootFalse(_: *anyopaque, _: [32]u8) bool {
    return false;
}

fn stubGetKnownBlockInfo(_: *anyopaque, root: [32]u8) ?chain_mod.gossip_validation.ChainState.KnownBlockInfo {
    if (std.mem.eql(u8, &root, &([_]u8{0} ** 32))) return null;
    if (root[0] == 0xBC or root[0] == 0xCD) return null;
    return .{
        .slot = 95,
        .target_root = [_]u8{0xAA} ** 32,
    };
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

fn stubVerifyAggregateSignature(
    _: *anyopaque,
    _: *const AnySignedAggregateAndProof,
    _: *const ResolvedAggregate,
) bool {
    if (g_verify_aggregate_failures_remaining > 0) {
        g_verify_aggregate_failures_remaining -= 1;
        return false;
    }
    return true;
}

fn stubImportResolvedAggregate(
    _: *anyopaque,
    _: *const AnySignedAggregateAndProof,
    _: *const [32]u8,
    _: *const ResolvedAggregate,
) anyerror!void {
    g_imported_aggregate_count += 1;
}

fn stubIsValidSyncCommitteeSubnet(_: *anyopaque, _: u64, validator_index: u64, subnet: u64) bool {
    const subcommittee_size = preset.SYNC_COMMITTEE_SIZE / networking.peer_info.SYNC_COMMITTEE_SUBNET_COUNT;
    return @divFloor(validator_index, subcommittee_size) == subnet;
}

fn stubVerifySyncCommitteeSignatureFalse(_: *anyopaque, _: []const u8) bool {
    return false;
}

fn stubImportSyncContribution(_: *anyopaque, _: *const consensus_types.altair.SignedContributionAndProof.Type) anyerror!void {}

fn stubImportBlobSidecar(_: *anyopaque, _: []const u8) anyerror!void {}

fn stubImportDataColumnSidecar(_: *anyopaque, _: []const u8) anyerror!void {}

fn stubVerifySyncContributionSignature(
    _: *anyopaque,
    _: *const consensus_types.altair.SignedContributionAndProof.Type,
) anyerror!u32 {
    return 1;
}

fn stubVerifyBlobSidecar(_: *anyopaque, _: *const consensus_types.deneb.BlobSidecar.Type) anyerror!void {}

fn stubVerifyDataColumnSidecar(_: *anyopaque, _: *const consensus_types.fulu.DataColumnSidecar.Type) anyerror!void {}

fn stubGetBlobSidecarSubnetCountForSlot(_: *anyopaque, slot: u64) u64 {
    return if (slot >= 1_000_000) 9 else 6;
}

fn makeTestHandler(allocator: Allocator) !*GossipHandler {
    var dummy_node: u8 = 0;
    return GossipHandler.create(
        allocator,
        testing.io,
        @ptrCast(&dummy_node),
        &stubImportBlock,
        &stubGetForkSeqForSlot,
        &stubGetProposerIndex,
        &stubIsKnownBlockRoot,
        &stubGetKnownBlockInfo,
        &stubGetValidatorCount,
        &stubResolveAttestation,
        &stubResolveAggregate,
        &stubIsValidSyncCommitteeSubnet,
        .{
            .importSyncContributionFn = &stubImportSyncContribution,
            .importBlobSidecarFn = &stubImportBlobSidecar,
            .importDataColumnSidecarFn = &stubImportDataColumnSidecar,
            .verifySyncContributionSignatureFn = &stubVerifySyncContributionSignature,
            .verifyBlobSidecarFn = &stubVerifyBlobSidecar,
            .verifyDataColumnSidecarFn = &stubVerifyDataColumnSidecar,
            .getBlobSidecarSubnetCountFn = &stubGetBlobSidecarSubnetCountForSlot,
        },
    );
}

fn compressSnappyBlock(allocator: Allocator, payload: []const u8) ![]u8 {
    const max_len = snappy.maxCompressedLength(payload.len);
    const scratch = try allocator.alloc(u8, max_len);
    defer allocator.free(scratch);

    const compressed_len = try snappy.compress(payload, scratch);
    const compressed = try allocator.alloc(u8, compressed_len);
    @memcpy(compressed, scratch[0..compressed_len]);
    return compressed;
}

fn makeSnappyBlock(allocator: Allocator, slot: u64, proposer: u64) ![]u8 {
    var block: phase0.SignedBeaconBlock.Type = phase0.SignedBeaconBlock.default_value;
    block.message.slot = slot;
    block.message.proposer_index = proposer;
    block.message.parent_root = [_]u8{0xAA} ** 32;

    const ssz_size = phase0.SignedBeaconBlock.serializedSize(&block);
    const ssz_buf = try allocator.alloc(u8, ssz_size);
    defer allocator.free(ssz_buf);
    _ = phase0.SignedBeaconBlock.serializeIntoBytes(&block, ssz_buf);

    return compressSnappyBlock(allocator, ssz_buf);
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

test "GossipHandler: onBeaconBlock queues unknown parent and ignores propagation" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(10, 0, 0);
    handler.isKnownBlockRoot = &stubIsKnownBlockRootFalse;
    handler.queueUnknownBlockFn = &stubQueueUnknownBlock;
    g_imported_count = 0;
    g_queued_unknown_block_count = 0;
    g_last_unknown_slot = null;
    g_last_unknown_peer = null;

    const compressed = try makeSnappyBlock(alloc, 10, 10);
    defer alloc.free(compressed);

    const result = handler.processGossipMessageWithSubnetAndMetadata(.beacon_block, null, compressed, .{
        .peer_id = "peer-1",
    });
    switch (result) {
        .ignored => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(u32, 0), g_imported_count);
    try testing.expectEqual(@as(u32, 1), g_queued_unknown_block_count);
    try testing.expectEqual(@as(?u64, 10), g_last_unknown_slot);
    try testing.expectEqualStrings("peer-1", g_last_unknown_peer.?);

    const result2 = handler.onBeaconBlock(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result2);
    try testing.expectEqual(@as(u32, 1), g_queued_unknown_block_count);
}

test "GossipHandler: onAttestation decodes and validates" {
    const alloc = testing.allocator;
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
    att.data.beacon_block_root = [_]u8{0xAA} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try compressSnappyBlock(alloc, &ssz_buf);
    defer alloc.free(compressed);

    // Should pass validation (epoch 3 is current).
    try handler.onAttestation(0, compressed);
}

test "GossipHandler: onAttestation queues unknown beacon_block_root for replay" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra);
    handler.queueUnknownBlockAttestationFn = &stubQueueUnknownBlockAttestation;
    g_queued_unknown_block_attestation_count = 0;
    g_last_unknown_root = null;
    g_last_unknown_peer = null;

    var att: consensus_types.electra.SingleAttestation.Type = consensus_types.electra.SingleAttestation.default_value;
    att.committee_index = 0;
    att.attester_index = 5;
    att.data.slot = 96;
    att.data.target.epoch = 3;
    att.data.target.root = [_]u8{0xAA} ** 32;
    att.data.beacon_block_root = [_]u8{0xBC} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try compressSnappyBlock(alloc, &ssz_buf);
    defer alloc.free(compressed);

    const result = handler.processGossipMessageWithSubnetAndMetadata(.beacon_attestation, 0, compressed, .{
        .peer_id = "peer-att",
    });
    switch (result) {
        .deferred => {},
        else => return error.TestUnexpectedResult,
    }

    try testing.expectEqual(@as(u32, 1), g_queued_unknown_block_attestation_count);
    try testing.expectEqual([_]u8{0xBC} ** 32, g_last_unknown_root.?);
    try testing.expectEqualStrings("peer-att", g_last_unknown_peer.?);
}

test "GossipHandler: onAttestation rejects stale epoch" {
    const alloc = testing.allocator;
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

    const compressed = try compressSnappyBlock(alloc, &ssz_buf);
    defer alloc.free(compressed);

    const result = handler.onAttestation(5, compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, result);
}

test "GossipHandler: onAttestation rejects pre-electra aggregated attestations" {
    const alloc = testing.allocator;
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
    att.data.beacon_block_root = [_]u8{0xAA} ** 32;

    const ssz_size = consensus_types.phase0.Attestation.serializedSize(&att);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = consensus_types.phase0.Attestation.serializeIntoBytes(&att, ssz_buf);

    const compressed = try compressSnappyBlock(alloc, ssz_buf);
    defer alloc.free(compressed);

    try testing.expectError(GossipHandlerError.ValidationRejected, handler.onAttestation(0, compressed));
}

test "GossipHandler: process result classifies wrong subnet" {
    const alloc = testing.allocator;
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
    att.data.beacon_block_root = [_]u8{0xAA} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try compressSnappyBlock(alloc, &ssz_buf);
    defer alloc.free(compressed);

    const result = handler.processGossipMessageWithSubnetAndMetadata(.beacon_attestation, 1, compressed, .{});
    switch (result) {
        .rejected => |reason| try testing.expectEqual(networking.peer_scoring.GossipRejectReason.wrong_subnet, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "GossipHandler: onAttestation rejects wrong subnet" {
    const alloc = testing.allocator;
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
    att.data.beacon_block_root = [_]u8{0xAA} ** 32;

    var ssz_buf: [consensus_types.electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = consensus_types.electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const compressed = try compressSnappyBlock(alloc, &ssz_buf);
    defer alloc.free(compressed);

    try testing.expectError(GossipHandlerError.ValidationRejected, handler.onAttestation(1, compressed));
}

test "GossipHandler: onSyncCommitteeMessage rejects wrong subnet" {
    const alloc = testing.allocator;
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

    const compressed = try compressSnappyBlock(alloc, &ssz_buf);
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

    const compressed = try compressSnappyBlock(alloc, &ssz_buf);
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

test "GossipHandler: sync contribution ignores seen aggregator and participant superset" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);

    var signed_contribution = consensus_types.altair.SignedContributionAndProof.default_value;
    signed_contribution.message.aggregator_index = 5;
    signed_contribution.message.contribution.slot = 100;
    signed_contribution.message.contribution.subcommittee_index = 0;
    signed_contribution.message.contribution.beacon_block_root = [_]u8{0xAA} ** 32;
    signed_contribution.message.contribution.aggregation_bits.data[0] = 0x01;

    var ssz_buf: [consensus_types.altair.SignedContributionAndProof.fixed_size]u8 = undefined;
    _ = consensus_types.altair.SignedContributionAndProof.serializeIntoBytes(&signed_contribution, ssz_buf[0..]);

    const compressed = try compressSnappyBlock(alloc, &ssz_buf);
    defer alloc.free(compressed);

    try handler.onSyncCommitteeContribution(compressed);
    try testing.expectError(GossipHandlerError.ValidationIgnored, handler.onSyncCommitteeContribution(compressed));
}

test "GossipHandler: onAggregateAndProof validates and accepts" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);

    // Create a valid SignedAggregateAndProof.
    var signed_agg: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 96;
    signed_agg.message.aggregate.data.target.epoch = 3;
    signed_agg.message.aggregate.data.target.root = [_]u8{0xAA} ** 32;
    signed_agg.message.aggregate.data.beacon_block_root = [_]u8{0xAA} ** 32;
    // Need at least 1 set bit for aggregation_bits.
    // Default aggregation_bits is empty — allocate a single byte with bit 0 set.
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = phase0.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try compressSnappyBlock(alloc, ssz_buf);
    defer alloc.free(compressed);

    try handler.onAggregateAndProof(compressed);
}

test "GossipHandler: aggregate invalid signature does not poison later valid aggregate and success marks seen" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.verifyAggregateSignatureFn = &stubVerifyAggregateSignature;
    handler.importResolvedAggregateFn = &stubImportResolvedAggregate;
    g_verify_aggregate_failures_remaining = 1;
    g_imported_aggregate_count = 0;

    var signed_agg: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 96;
    signed_agg.message.aggregate.data.target.epoch = 3;
    signed_agg.message.aggregate.data.target.root = [_]u8{0xAA} ** 32;
    signed_agg.message.aggregate.data.beacon_block_root = [_]u8{0xAA} ** 32;
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = phase0.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try compressSnappyBlock(alloc, ssz_buf);
    defer alloc.free(compressed);

    try testing.expectError(GossipHandlerError.ValidationRejected, handler.onAggregateAndProof(compressed));
    try testing.expectEqual(@as(u32, 0), g_imported_aggregate_count);

    try handler.onAggregateAndProof(compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_aggregate_count);

    try testing.expectError(GossipHandlerError.ValidationIgnored, handler.onAggregateAndProof(compressed));
    try testing.expectEqual(@as(u32, 1), g_imported_aggregate_count);
}

test "GossipHandler: aggregate participant subset is ignored after valid superset" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.verifyAggregateSignatureFn = &stubVerifyAggregateSignature;
    handler.importResolvedAggregateFn = &stubImportResolvedAggregate;
    g_verify_aggregate_failures_remaining = 0;
    g_imported_aggregate_count = 0;

    var superset: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    superset.message.aggregator_index = 5;
    superset.message.aggregate.data.slot = 96;
    superset.message.aggregate.data.target.epoch = 3;
    superset.message.aggregate.data.target.root = [_]u8{0xAA} ** 32;
    superset.message.aggregate.data.beacon_block_root = [_]u8{0xAA} ** 32;
    try superset.message.aggregate.aggregation_bits.data.append(alloc, 0x03);
    superset.message.aggregate.aggregation_bits.bit_len = 2;
    defer superset.message.aggregate.aggregation_bits.data.deinit(alloc);

    const superset_size = phase0.SignedAggregateAndProof.serializedSize(&superset);
    const superset_buf = try alloc.alloc(u8, superset_size);
    defer alloc.free(superset_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&superset, superset_buf);
    const superset_compressed = try compressSnappyBlock(alloc, superset_buf);
    defer alloc.free(superset_compressed);

    try handler.onAggregateAndProof(superset_compressed);
    try testing.expectEqual(@as(u32, 1), g_imported_aggregate_count);

    var subset: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    subset.message.aggregator_index = 6;
    subset.message.aggregate.data.slot = 96;
    subset.message.aggregate.data.target.epoch = 3;
    subset.message.aggregate.data.target.root = [_]u8{0xAA} ** 32;
    subset.message.aggregate.data.beacon_block_root = [_]u8{0xAA} ** 32;
    try subset.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    subset.message.aggregate.aggregation_bits.bit_len = 2;
    defer subset.message.aggregate.aggregation_bits.data.deinit(alloc);

    const subset_size = phase0.SignedAggregateAndProof.serializedSize(&subset);
    const subset_buf = try alloc.alloc(u8, subset_size);
    defer alloc.free(subset_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&subset, subset_buf);
    const subset_compressed = try compressSnappyBlock(alloc, subset_buf);
    defer alloc.free(subset_compressed);

    try testing.expectError(GossipHandlerError.ValidationIgnored, handler.onAggregateAndProof(subset_compressed));
    try testing.expectEqual(@as(u32, 1), g_imported_aggregate_count);
}

test "GossipHandler: onAggregateAndProof ignores stale pre-electra aggregate" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);

    var signed_agg: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 32;
    signed_agg.message.aggregate.data.target.epoch = 1;
    signed_agg.message.aggregate.data.target.root = [_]u8{0xAA} ** 32;
    signed_agg.message.aggregate.data.beacon_block_root = [_]u8{0xAA} ** 32;
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = phase0.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try compressSnappyBlock(alloc, ssz_buf);
    defer alloc.free(compressed);

    try testing.expectError(GossipHandlerError.ValidationIgnored, handler.onAggregateAndProof(compressed));
}

test "GossipHandler: onAggregateAndProof queues unknown beacon_block_root for replay" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.queueUnknownBlockAggregateFn = &stubQueueUnknownBlockAggregate;
    g_queued_unknown_block_aggregate_count = 0;
    g_last_unknown_root = null;
    g_last_unknown_peer = null;

    var signed_agg: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 96;
    signed_agg.message.aggregate.data.target.epoch = 3;
    signed_agg.message.aggregate.data.target.root = [_]u8{0xAA} ** 32;
    signed_agg.message.aggregate.data.beacon_block_root = [_]u8{0xCD} ** 32;
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = phase0.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try compressSnappyBlock(alloc, ssz_buf);
    defer alloc.free(compressed);

    const result = handler.processGossipMessageWithSubnetAndMetadata(.beacon_aggregate_and_proof, null, compressed, .{
        .peer_id = "peer-agg",
    });
    switch (result) {
        .deferred => {},
        else => return error.TestUnexpectedResult,
    }

    try testing.expectEqual(@as(u32, 1), g_queued_unknown_block_aggregate_count);
    try testing.expectEqual([_]u8{0xCD} ** 32, g_last_unknown_root.?);
    try testing.expectEqualStrings("peer-agg", g_last_unknown_peer.?);
}

test "GossipHandler: onAggregateAndProof validates electra aggregates" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra);

    var signed_agg: consensus_types.electra.SignedAggregateAndProof.Type = consensus_types.electra.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 96;
    signed_agg.message.aggregate.data.target.epoch = 3;
    signed_agg.message.aggregate.data.target.root = [_]u8{0xAA} ** 32;
    signed_agg.message.aggregate.data.beacon_block_root = [_]u8{0xAA} ** 32;
    signed_agg.message.aggregate.data.index = 0;
    try signed_agg.message.aggregate.committee_bits.set(0, true);
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = consensus_types.electra.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = consensus_types.electra.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try compressSnappyBlock(alloc, ssz_buf);
    defer alloc.free(compressed);

    try handler.onAggregateAndProof(compressed);
}

test "GossipHandler: onAggregateAndProof ignores stale electra aggregate" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.electra);

    var signed_agg: consensus_types.electra.SignedAggregateAndProof.Type = consensus_types.electra.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 5;
    signed_agg.message.aggregate.data.slot = 32;
    signed_agg.message.aggregate.data.target.epoch = 1;
    signed_agg.message.aggregate.data.target.root = [_]u8{0xAA} ** 32;
    signed_agg.message.aggregate.data.beacon_block_root = [_]u8{0xAA} ** 32;
    signed_agg.message.aggregate.data.index = 0;
    try signed_agg.message.aggregate.committee_bits.set(0, true);
    try signed_agg.message.aggregate.aggregation_bits.data.append(alloc, 0x01);
    signed_agg.message.aggregate.aggregation_bits.bit_len = 1;
    defer signed_agg.message.aggregate.aggregation_bits.data.deinit(alloc);

    const ssz_size = consensus_types.electra.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = consensus_types.electra.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const compressed = try compressSnappyBlock(alloc, ssz_buf);
    defer alloc.free(compressed);

    try testing.expectError(GossipHandlerError.ValidationIgnored, handler.onAggregateAndProof(compressed));
}

test "GossipHandler: data column sidecar rejects wrong subnet" {
    const alloc = testing.allocator;
    const handler = try makeTestHandler(alloc);
    defer handler.deinit();

    handler.updateClock(100, 3, 64);
    handler.updateForkSeq(.fulu);

    var sidecar = consensus_types.fulu.DataColumnSidecar.default_value;
    defer consensus_types.fulu.DataColumnSidecar.deinit(alloc, &sidecar);
    sidecar.index = 0;
    sidecar.signed_block_header.message.slot = 100;
    sidecar.signed_block_header.message.proposer_index = 5;
    sidecar.signed_block_header.message.parent_root = [_]u8{0xAA} ** 32;

    const ssz_size = consensus_types.fulu.DataColumnSidecar.serializedSize(&sidecar);
    const ssz_buf = try alloc.alloc(u8, ssz_size);
    defer alloc.free(ssz_buf);
    _ = consensus_types.fulu.DataColumnSidecar.serializeIntoBytes(&sidecar, ssz_buf);

    const compressed = try compressSnappyBlock(alloc, ssz_buf);
    defer alloc.free(compressed);

    const result = handler.processGossipMessageWithSubnetAndMetadata(.data_column_sidecar, 1, compressed, .{});
    switch (result) {
        .rejected => |reason| try testing.expectEqual(networking.peer_scoring.GossipRejectReason.wrong_subnet, reason),
        else => return error.TestUnexpectedResult,
    }
}
