//! Gossip message decoding for the Ethereum consensus P2P protocol.
//!
//! Gossip messages are SSZ-Snappy encoded (Snappy frame compression over SSZ-serialized data).
//! This module bridges the wire encoding to the validation layer by:
//! 1. Snappy-decompressing the raw gossip data
//! 2. Determining the SSZ type based on the topic
//! 3. Deserializing the message
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#encodings

const std = @import("std");
const testing = std.testing;
const snappy = @import("snappy").frame;
const consensus_types = @import("consensus_types");
const phase0 = consensus_types.phase0;
const electra = consensus_types.electra;
const gossip_topics = @import("gossip_topics.zig");

const GossipTopicType = gossip_topics.GossipTopicType;
const Allocator = std.mem.Allocator;
const capella = consensus_types.capella;
const altair = consensus_types.altair;


/// Errors that can occur during gossip message decoding.
pub const DecodeError = snappy.UncompressError || error{
    /// Snappy decompression produced no output.
    EmptyPayload,
    /// SSZ deserialization failed.
    SszDeserializationFailed,
    /// The topic type is not supported for decoding.
    UnsupportedTopicType,
};

/// Result of decoding a beacon_block gossip message.
/// Contains the extracted fields needed for validation without
/// retaining the full deserialized block.
pub const DecodedBeaconBlock = struct {
    slot: u64,
    proposer_index: u64,
    parent_root: [32]u8,
};

/// Result of decoding a beacon_aggregate_and_proof gossip message.
pub const DecodedAggregateAndProof = struct {
    aggregator_index: u64,
    attestation_slot: u64,
    attestation_target_epoch: u64,
    aggregation_bits_count: u64,
};

/// Result of decoding a voluntary_exit gossip message.
pub const DecodedVoluntaryExit = struct {
    validator_index: u64,
    exit_epoch: u64,
};

/// Result of decoding a proposer_slashing gossip message.
pub const DecodedProposerSlashing = struct {
    proposer_index: u64,
    header_1_slot: u64,
    header_2_slot: u64,
    header_1_body_root: [32]u8,
    header_2_body_root: [32]u8,
};

/// Result of decoding an attester_slashing gossip message.
pub const DecodedAttesterSlashing = struct {
    /// Whether attestation_1.data and attestation_2.data are slashable
    /// (double vote or surround vote).  Computed at decode time so the
    /// caller doesn't need to re-parse the variable-length container.
    is_slashable: bool,
};

/// Result of decoding a bls_to_execution_change gossip message.
pub const DecodedBlsChange = struct {
    validator_index: u64,
};

/// Result of decoding a sync_committee_contribution_and_proof gossip message.
pub const DecodedSyncContributionAndProof = struct {
    aggregator_index: u64,
    contribution_slot: u64,
    subcommittee_index: u64,
    beacon_block_root: [32]u8,
};

/// Result of decoding a sync_committee (SyncCommitteeMessage) gossip message.
pub const DecodedSyncCommitteeMessage = struct {
    slot: u64,
    validator_index: u64,
    beacon_block_root: [32]u8,
};

/// Result of decoding a blob_sidecar gossip message.
/// Extracts header fields for validation without full sidecar deserialization.
pub const DecodedBlobSidecar = struct {
    index: u64,
    slot: u64,
    proposer_index: u64,
    block_parent_root: [32]u8,
};

/// Result of decoding a beacon_attestation (SingleAttestation) gossip message.
/// In Electra, individual gossip attestations use SingleAttestation format
/// (one validator per message, no aggregation bits).
pub const DecodedAttestation = struct {
    committee_index: u64,
    attester_index: u64,
    slot: u64,
    target_epoch: u64,
    target_root: [32]u8,
    beacon_block_root: [32]u8,
    source_epoch: u64,
    source_root: [32]u8,
};

/// Count the number of set bits in a BitList's underlying data.
///
/// The BitList stores bits packed in bytes. This counts the total number
/// of 1-bits (popcount) across all bytes, considering only bit_len bits.
fn countSetBits(bl: anytype) u64 {
    var count: u64 = 0;
    const full_bytes = bl.bit_len / 8;
    const remainder = bl.bit_len % 8;
    for (bl.data.items[0..full_bytes]) |byte| {
        count += @popCount(byte);
    }
    if (remainder > 0 and bl.data.items.len > full_bytes) {
        const mask: u8 = (@as(u8, 1) << @intCast(remainder)) - 1;
        count += @popCount(bl.data.items[full_bytes] & mask);
    }
    return count;
}


/// Union of all decoded gossip message types.
pub const DecodedGossipMessage = union(GossipTopicType) {
    // Fields match GossipTopicType enum declaration order.
    beacon_block: DecodedBeaconBlock,
    beacon_aggregate_and_proof: DecodedAggregateAndProof,
    beacon_attestation: DecodedAttestation,
    voluntary_exit: DecodedVoluntaryExit,
    proposer_slashing: DecodedProposerSlashing,
    attester_slashing: DecodedAttesterSlashing,
    bls_to_execution_change: DecodedBlsChange,
    blob_sidecar: DecodedBlobSidecar,
    sync_committee_contribution_and_proof: DecodedSyncContributionAndProof,
    sync_committee: DecodedSyncCommitteeMessage,
    data_column_sidecar: void,
};

/// Decompress a Snappy-framed gossip payload.
///
/// Returns the decompressed SSZ bytes. Caller owns the returned memory.
pub fn decompressGossipPayload(allocator: Allocator, compressed_data: []const u8) DecodeError![]const u8 {
    const decompressed = snappy.uncompress(allocator, compressed_data) catch |err| return err;
    if (decompressed == null) return error.EmptyPayload;
    return decompressed.?;
}

/// Decode a raw gossip message (Snappy-compressed SSZ) into its typed representation.
///
/// This performs:
/// 1. Snappy decompression
/// 2. SSZ deserialization based on the topic type
/// 3. Extraction of validation-relevant fields
///
/// The `raw_data` is the Snappy-framed payload received from gossipsub.
pub fn decodeGossipMessage(
    allocator: Allocator,
    topic_type: GossipTopicType,
    raw_data: []const u8,
) DecodeError!DecodedGossipMessage {
    // Step 1: Snappy decompress.
    const ssz_bytes = try decompressGossipPayload(allocator, raw_data);
    defer allocator.free(ssz_bytes);

    // Step 2: Deserialize based on topic type.
    return decodeFromSszBytes(allocator, topic_type, ssz_bytes);
}

/// Decode SSZ bytes (already decompressed) into a typed gossip message.
pub fn decodeFromSszBytes(
    allocator: Allocator,
    topic_type: GossipTopicType,
    ssz_bytes: []const u8,
) DecodeError!DecodedGossipMessage {
    switch (topic_type) {
        .beacon_block => {
            var block: phase0.SignedBeaconBlock.Type = undefined;
            phase0.SignedBeaconBlock.deserializeFromBytes(allocator, ssz_bytes, &block) catch
                return error.SszDeserializationFailed;
            return .{ .beacon_block = .{
                .slot = block.message.slot,
                .proposer_index = block.message.proposer_index,
                .parent_root = block.message.parent_root,
            } };
        },
        .beacon_aggregate_and_proof => {
            var signed_agg: phase0.SignedAggregateAndProof.Type = undefined;
            phase0.SignedAggregateAndProof.deserializeFromBytes(allocator, ssz_bytes, &signed_agg) catch
                return error.SszDeserializationFailed;
            const agg = signed_agg.message;
            const att = agg.aggregate;
            return .{ .beacon_aggregate_and_proof = .{
                .aggregator_index = agg.aggregator_index,
                .attestation_slot = att.data.slot,
                .attestation_target_epoch = att.data.target.epoch,
                .aggregation_bits_count = countSetBits(&att.aggregation_bits),
            } };
        },
        .voluntary_exit => {
            var signed_exit: phase0.SignedVoluntaryExit.Type = undefined;
            phase0.SignedVoluntaryExit.deserializeFromBytes(ssz_bytes, &signed_exit) catch
                return error.SszDeserializationFailed;
            return .{ .voluntary_exit = .{
                .validator_index = signed_exit.message.validator_index,
                .exit_epoch = signed_exit.message.epoch,
            } };
        },
        .proposer_slashing => {
            var slashing: phase0.ProposerSlashing.Type = undefined;
            phase0.ProposerSlashing.deserializeFromBytes(ssz_bytes, &slashing) catch
                return error.SszDeserializationFailed;
            return .{ .proposer_slashing = .{
                .proposer_index = slashing.signed_header_1.message.proposer_index,
                .header_1_slot = slashing.signed_header_1.message.slot,
                .header_2_slot = slashing.signed_header_2.message.slot,
                .header_1_body_root = slashing.signed_header_1.message.body_root,
                .header_2_body_root = slashing.signed_header_2.message.body_root,
            } };
        },
        .beacon_attestation => {
            var att: electra.SingleAttestation.Type = undefined;
            electra.SingleAttestation.deserializeFromBytes(ssz_bytes, &att) catch
                return error.SszDeserializationFailed;
            return .{ .beacon_attestation = .{
                .committee_index = att.committee_index,
                .attester_index = att.attester_index,
                .slot = att.data.slot,
                .target_epoch = att.data.target.epoch,
                .target_root = att.data.target.root,
                .beacon_block_root = att.data.beacon_block_root,
                .source_epoch = att.data.source.epoch,
                .source_root = att.data.source.root,
            } };
        },
        .attester_slashing => {
            var slashing: phase0.AttesterSlashing.Type = undefined;
            phase0.AttesterSlashing.deserializeFromBytes(allocator, ssz_bytes, &slashing) catch
                return error.SszDeserializationFailed;
            // Inline slashable check (double vote or surround vote).
            const d1 = &slashing.attestation_1.data;
            const d2 = &slashing.attestation_2.data;
            const is_double_vote = !phase0.AttestationData.equals(d1, d2) and d1.target.epoch == d2.target.epoch;
            const is_surround_vote = d1.source.epoch < d2.source.epoch and d2.target.epoch < d1.target.epoch;
            const is_slashable = is_double_vote or is_surround_vote;
            return .{ .attester_slashing = .{
                .is_slashable = is_slashable,
            } };
        },
        .bls_to_execution_change => {
            var signed_change: capella.SignedBLSToExecutionChange.Type = undefined;
            capella.SignedBLSToExecutionChange.deserializeFromBytes(ssz_bytes, &signed_change) catch
                return error.SszDeserializationFailed;
            return .{ .bls_to_execution_change = .{
                .validator_index = signed_change.message.validator_index,
            } };
        },
        .sync_committee_contribution_and_proof => {
            var signed_cap: altair.SignedContributionAndProof.Type = undefined;
            altair.SignedContributionAndProof.deserializeFromBytes(ssz_bytes, &signed_cap) catch
                return error.SszDeserializationFailed;
            const contrib = signed_cap.message.contribution;
            return .{ .sync_committee_contribution_and_proof = .{
                .aggregator_index = signed_cap.message.aggregator_index,
                .contribution_slot = contrib.slot,
                .subcommittee_index = contrib.subcommittee_index,
                .beacon_block_root = contrib.beacon_block_root,
            } };
        },
        .sync_committee => {
            var msg: altair.SyncCommitteeMessage.Type = undefined;
            altair.SyncCommitteeMessage.deserializeFromBytes(ssz_bytes, &msg) catch
                return error.SszDeserializationFailed;
            return .{ .sync_committee = .{
                .slot = msg.slot,
                .validator_index = msg.validator_index,
                .beacon_block_root = msg.beacon_block_root,
            } };
        },
        .blob_sidecar => {
            // BlobSidecar is a large container (>128 KB due to the blob field).
            // Extract only the fixed-offset header fields we need for validation.
            //
            // BlobSidecar SSZ layout (Deneb, FIELD_ELEMENTS_PER_BLOB=4096):
            //   index:              8 bytes  @ offset 0
            //   blob:          131072 bytes  @ offset 8    (4096 * 32 bytes per field element)
            //   kzg_commitment:    48 bytes  @ offset 131080
            //   kzg_proof:         48 bytes  @ offset 131128
            //   signed_block_header:         @ offset 131176
            //     BLSSignature:    96 bytes  @ offset 131176 (signature)
            //     BeaconBlockHeader:          @ offset 131272
            //       slot:           8 bytes  @ offset 131272
            //       proposer_index: 8 bytes  @ offset 131280
            //       parent_root:   32 bytes  @ offset 131288
            //       state_root:    32 bytes  @ offset 131320
            //       body_root:     32 bytes  @ offset 131352
            //
            // These offsets are derived from SSZ fixed-size field layout.
            // IMPORTANT: If FIELD_ELEMENTS_PER_BLOB changes (e.g. in future forks),
            // these offsets must be updated. A compile-time assert guards this.
            const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
            const BYTES_PER_FIELD_ELEMENT: usize = 32;
            const blob_size = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT; // 131072
            const kzg_commitment_size: usize = 48;
            const kzg_proof_size: usize = 48;
            const bls_signature_size: usize = 96;

            const signed_block_header_offset = 8 + blob_size + kzg_commitment_size + kzg_proof_size;
            const beacon_block_header_offset = signed_block_header_offset + bls_signature_size;
            const slot_offset = beacon_block_header_offset; // slot is first field
            const proposer_index_offset = slot_offset + 8;
            const parent_root_offset = proposer_index_offset + 8;

            // Compile-time assertion: verify our computed offsets match what we hardcoded.
            comptime {
                std.debug.assert(signed_block_header_offset == 131176);
                std.debug.assert(beacon_block_header_offset == 131272);
                std.debug.assert(slot_offset == 131272);
                std.debug.assert(proposer_index_offset == 131280);
                std.debug.assert(parent_root_offset == 131288);
            }

            const min_size = parent_root_offset + 32; // need through parent_root
            if (ssz_bytes.len < min_size) return error.SszDeserializationFailed;
            const index = std.mem.readInt(u64, ssz_bytes[0..8], .little);
            const slot = std.mem.readInt(u64, ssz_bytes[slot_offset..][0..8], .little);
            const proposer_index = std.mem.readInt(u64, ssz_bytes[proposer_index_offset..][0..8], .little);
            var parent_root: [32]u8 = undefined;
            @memcpy(&parent_root, ssz_bytes[parent_root_offset..][0..32]);
            return .{ .blob_sidecar = .{
                .index = index,
                .slot = slot,
                .proposer_index = proposer_index,
                .block_parent_root = parent_root,
            } };
        },
        .data_column_sidecar => return error.UnsupportedTopicType,
    }
}

// === Tests ===

test "decompressGossipPayload roundtrip" {
    const original = "hello gossip world";
    const compressed = try snappy.compress(testing.allocator, original);
    defer testing.allocator.free(compressed);

    const decompressed = try decompressGossipPayload(testing.allocator, compressed);
    defer testing.allocator.free(decompressed);

    try testing.expectEqualStrings(original, decompressed);
}

test "decode beacon_block from SSZ bytes" {
    // Create a SignedBeaconBlock with known values, serialize it, then decode.
    var block: phase0.SignedBeaconBlock.Type = phase0.SignedBeaconBlock.default_value;
    block.message.slot = 42;
    block.message.proposer_index = 7;
    block.message.parent_root = [_]u8{0xAA} ** 32;

    // Serialize to SSZ.
    const ssz_size = phase0.SignedBeaconBlock.serializedSize(&block);
    const ssz_buf = try testing.allocator.alloc(u8, ssz_size);
    defer testing.allocator.free(ssz_buf);
    _ = phase0.SignedBeaconBlock.serializeIntoBytes(&block, ssz_buf);

    // Decode.
    const decoded = try decodeFromSszBytes(testing.allocator, .beacon_block, ssz_buf);
    try testing.expectEqual(@as(u64, 42), decoded.beacon_block.slot);
    try testing.expectEqual(@as(u64, 7), decoded.beacon_block.proposer_index);
    try testing.expectEqualSlices(u8, &([_]u8{0xAA} ** 32), &decoded.beacon_block.parent_root);
}

test "decode voluntary_exit from SSZ bytes" {
    var exit: phase0.SignedVoluntaryExit.Type = phase0.SignedVoluntaryExit.default_value;
    exit.message.validator_index = 123;
    exit.message.epoch = 10;

    var ssz_buf: [phase0.SignedVoluntaryExit.fixed_size]u8 = undefined;
    _ = phase0.SignedVoluntaryExit.serializeIntoBytes(&exit, &ssz_buf);

    const decoded = try decodeFromSszBytes(testing.allocator, .voluntary_exit, &ssz_buf);
    try testing.expectEqual(@as(u64, 123), decoded.voluntary_exit.validator_index);
    try testing.expectEqual(@as(u64, 10), decoded.voluntary_exit.exit_epoch);
}

test "decode proposer_slashing from SSZ bytes" {
    var slashing: phase0.ProposerSlashing.Type = phase0.ProposerSlashing.default_value;
    slashing.signed_header_1.message.proposer_index = 5;
    slashing.signed_header_1.message.slot = 100;
    slashing.signed_header_2.message.slot = 100;
    slashing.signed_header_1.message.body_root = [_]u8{0xAA} ** 32;
    slashing.signed_header_2.message.body_root = [_]u8{0xBB} ** 32;

    var ssz_buf: [phase0.ProposerSlashing.fixed_size]u8 = undefined;
    _ = phase0.ProposerSlashing.serializeIntoBytes(&slashing, &ssz_buf);

    const decoded = try decodeFromSszBytes(testing.allocator, .proposer_slashing, &ssz_buf);
    try testing.expectEqual(@as(u64, 5), decoded.proposer_slashing.proposer_index);
    try testing.expectEqual(@as(u64, 100), decoded.proposer_slashing.header_1_slot);
    try testing.expectEqual(@as(u64, 100), decoded.proposer_slashing.header_2_slot);
}

test "decode unsupported topic type" {
    const dummy = [_]u8{ 0, 1, 2, 3 };
    const result = decodeFromSszBytes(testing.allocator, .data_column_sidecar, &dummy);
    try testing.expectError(error.UnsupportedTopicType, result);
}

test "decode attester_slashing bad SSZ" {
    const dummy = [_]u8{ 0, 1, 2, 3 };
    const result = decodeFromSszBytes(testing.allocator, .attester_slashing, &dummy);
    try testing.expectError(error.SszDeserializationFailed, result);
}

test "decode bls_to_execution_change from SSZ bytes" {
    var change: capella.SignedBLSToExecutionChange.Type = capella.SignedBLSToExecutionChange.default_value;
    change.message.validator_index = 42;

    var ssz_buf: [capella.SignedBLSToExecutionChange.fixed_size]u8 = undefined;
    _ = capella.SignedBLSToExecutionChange.serializeIntoBytes(&change, &ssz_buf);

    const decoded = try decodeFromSszBytes(testing.allocator, .bls_to_execution_change, &ssz_buf);
    try testing.expectEqual(@as(u64, 42), decoded.bls_to_execution_change.validator_index);
}

test "decode beacon_attestation (SingleAttestation) from SSZ bytes" {
    var att: electra.SingleAttestation.Type = electra.SingleAttestation.default_value;
    att.committee_index = 3;
    att.attester_index = 42;
    att.data.slot = 100;
    att.data.target.epoch = 3;
    att.data.target.root = [_]u8{0xBB} ** 32;
    att.data.beacon_block_root = [_]u8{0xCC} ** 32;

    var ssz_buf: [electra.SingleAttestation.fixed_size]u8 = undefined;
    _ = electra.SingleAttestation.serializeIntoBytes(&att, &ssz_buf);

    const decoded = try decodeFromSszBytes(testing.allocator, .beacon_attestation, &ssz_buf);
    try testing.expectEqual(@as(u64, 3), decoded.beacon_attestation.committee_index);
    try testing.expectEqual(@as(u64, 42), decoded.beacon_attestation.attester_index);
    try testing.expectEqual(@as(u64, 100), decoded.beacon_attestation.slot);
    try testing.expectEqual(@as(u64, 3), decoded.beacon_attestation.target_epoch);
    try testing.expectEqualSlices(u8, &([_]u8{0xBB} ** 32), &decoded.beacon_attestation.target_root);
    try testing.expectEqualSlices(u8, &([_]u8{0xCC} ** 32), &decoded.beacon_attestation.beacon_block_root);
}

test "decode beacon_aggregate_and_proof from SSZ bytes" {
    var signed_agg: phase0.SignedAggregateAndProof.Type = phase0.SignedAggregateAndProof.default_value;
    signed_agg.message.aggregator_index = 7;
    signed_agg.message.aggregate.data.slot = 96;
    signed_agg.message.aggregate.data.target.epoch = 3;

    const ssz_size = phase0.SignedAggregateAndProof.serializedSize(&signed_agg);
    const ssz_buf = try testing.allocator.alloc(u8, ssz_size);
    defer testing.allocator.free(ssz_buf);
    _ = phase0.SignedAggregateAndProof.serializeIntoBytes(&signed_agg, ssz_buf);

    const decoded = try decodeFromSszBytes(testing.allocator, .beacon_aggregate_and_proof, ssz_buf);
    try testing.expectEqual(@as(u64, 7), decoded.beacon_aggregate_and_proof.aggregator_index);
    try testing.expectEqual(@as(u64, 96), decoded.beacon_aggregate_and_proof.attestation_slot);
    try testing.expectEqual(@as(u64, 3), decoded.beacon_aggregate_and_proof.attestation_target_epoch);
}

test "decode invalid SSZ data returns error" {
    // Too-short data should fail deserialization.
    const bad_data = [_]u8{ 0, 0, 0 };
    const result = decodeFromSszBytes(testing.allocator, .beacon_block, &bad_data);
    try testing.expectError(error.SszDeserializationFailed, result);
}

test "end-to-end: snappy compress then decode beacon_block" {
    var block: phase0.SignedBeaconBlock.Type = phase0.SignedBeaconBlock.default_value;
    block.message.slot = 99;
    block.message.proposer_index = 3;
    block.message.parent_root = [_]u8{0xCC} ** 32;

    const ssz_size = phase0.SignedBeaconBlock.serializedSize(&block);
    const ssz_buf = try testing.allocator.alloc(u8, ssz_size);
    defer testing.allocator.free(ssz_buf);
    _ = phase0.SignedBeaconBlock.serializeIntoBytes(&block, ssz_buf);

    // Compress with Snappy (simulates what a peer would send).
    const compressed = try snappy.compress(testing.allocator, ssz_buf);
    defer testing.allocator.free(compressed);

    // Full decode pipeline.
    const decoded = try decodeGossipMessage(testing.allocator, .beacon_block, compressed);
    try testing.expectEqual(@as(u64, 99), decoded.beacon_block.slot);
    try testing.expectEqual(@as(u64, 3), decoded.beacon_block.proposer_index);
}
