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
    attester_slashing: void,
    bls_to_execution_change: void,
    blob_sidecar: void,
    sync_committee_contribution_and_proof: void,
    sync_committee: void,
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
            } };
        },
        // Stub types — these will be fleshed out in future spikes.
        .attester_slashing,
        .bls_to_execution_change,
        .blob_sidecar,
        .sync_committee_contribution_and_proof,
        .sync_committee,
        => return error.UnsupportedTopicType,
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
    const result = decodeFromSszBytes(testing.allocator, .beacon_attestation, &dummy);
    try testing.expectError(error.UnsupportedTopicType, result);
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
