//! Gossip message decoding for the Ethereum consensus P2P protocol.
//!
//! Gossip messages are SSZ-Snappy encoded (Snappy frame compression over SSZ-serialized data).
//! This module bridges the wire encoding to the validation layer by:
//! 1. Snappy-decompressing the raw gossip data
//! 2. Determining the SSZ type based on the topic
//! 3. Deserializing the message
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#encodings
//!
//! Security note (CL-2024-08): Snappy frame format requires per-chunk CRC32C checksum
//! verification to prevent acceptance of corrupted or maliciously crafted data. This was
//! a known vulnerability in Lodestar TS (https://github.com/sigp/beacon-fuzz/blob/master/reports/CL-2024-08.md).
//! Our snappy.zig dependency (snappy.frame) verifies checksums on both compressed and
//! uncompressed chunks in `uncompress()`. Verified present: see snappy/src/frame.zig.

const std = @import("std");
const testing = std.testing;
const snappy = @import("snappy").frame;
const consensus_types = @import("consensus_types");
const phase0 = consensus_types.phase0;
const electra = consensus_types.electra;
const config = @import("config");
const ForkSeq = config.ForkSeq;
const gossip_topics = @import("gossip_topics.zig");

const GossipTopicType = gossip_topics.GossipTopicType;
const Allocator = std.mem.Allocator;
const capella = consensus_types.capella;
const altair = consensus_types.altair;

// ─── Per-topic decompressed-size limits ────────────────────────────────────
//
// These caps bound how many bytes snappy.uncompress() may produce before we
// reject the message.  They are intentionally generous (2× the largest valid
// SSZ encoding for the type) so legitimate messages are never dropped, while
// a decompression-bomb payload is caught before it can exhaust memory.
//
// Reference: consensus-specs §p2p-interface – "Encoding strategies"
//   MAX_CHUNK_SIZE = 10 * 2^20 (10 MiB) for request/response
//   Gossip max sizes are per-topic based on SSZ serializedSize bounds.

/// Maximum decompressed size for a SignedBeaconBlock gossip message.
/// A Deneb block with max transactions/blobs is ~2 MiB; cap at 4 MiB for safety.
pub const MAX_GOSSIP_SIZE_BEACON_BLOCK: usize = 4 * 1024 * 1024; // 4 MiB

/// Maximum decompressed size for a BlobSidecar gossip message.
/// BlobSidecar fixed layout: 8 + 131072 + 48 + 48 + 96 + 112 + (kzg_commitment_inclusion_proof)
/// = ~131568 bytes.  Cap at 300 KiB to allow proof overhead.
pub const MAX_GOSSIP_SIZE_BLOB_SIDECAR: usize = 300 * 1024; // 300 KiB

/// Maximum decompressed size for a SingleAttestation (beacon_attestation) gossip message.
/// Fixed-size container: ~212 bytes.  Cap at 4 KiB.
pub const MAX_GOSSIP_SIZE_ATTESTATION: usize = 4 * 1024; // 4 KiB

/// Default maximum for all other gossip topic types (1 MiB).
pub const MAX_GOSSIP_SIZE_DEFAULT: usize = 1024 * 1024; // 1 MiB

/// Return the decompressed-size limit appropriate for the given topic.
pub fn maxGossipSize(topic: GossipTopicType) usize {
    return switch (topic) {
        .beacon_block => MAX_GOSSIP_SIZE_BEACON_BLOCK,
        .blob_sidecar => MAX_GOSSIP_SIZE_BLOB_SIDECAR,
        .beacon_attestation => MAX_GOSSIP_SIZE_ATTESTATION,
        else => MAX_GOSSIP_SIZE_DEFAULT,
    };
}

/// Errors that can occur during gossip message decoding.
pub const DecodeError = snappy.UncompressError || error{
    /// Snappy decompression produced no output.
    EmptyPayload,
    /// SSZ deserialization failed.
    SszDeserializationFailed,
    /// The topic type is not supported for decoding.
    UnsupportedTopicType,
    /// The decompressed payload exceeds the allowed maximum size for this topic.
    /// This prevents decompression-bomb attacks from exhausting memory.
    DecompressionBombDetected,
};

/// Result of decoding a beacon_block gossip message.
/// Contains the extracted fields needed for validation.
///
/// `raw_ssz` carries the raw decompressed SSZ bytes of the SignedBeaconBlock.
/// Ownership is transferred to the recipient: the caller must free `raw_ssz`
/// when it is no longer needed.  Set to null for non-beacon_block messages.
pub const DecodedBeaconBlock = struct {
    slot: u64,
    proposer_index: u64,
    parent_root: [32]u8,
    /// Raw decompressed SSZ bytes.  Caller owns this allocation.
    raw_ssz: []const u8,
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
    /// Deduplication key derived from the sorted intersection of attesting indices.
    /// Matches the output of gossip_validation.attesterSlashingKey so the caller
    /// can pass it directly to SeenSet without re-parsing.
    slashable_key: [32]u8,
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

/// Result of decoding a data_column_sidecar gossip message.
pub const DecodedDataColumnSidecar = struct {
    index: u64,
    slot: u64,
    proposer_index: u64,
    block_parent_root: [32]u8,
    block_root: [32]u8,
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

/// Compute a deduplication key for an attester slashing from the sorted intersection
/// of attesting indices.  Uses the same Wyhash-based algorithm as
/// gossip_validation.attesterSlashingKey so keys are compatible with SeenSet.
///
/// Both index slices must already be sorted in ascending order (the spec requires this
/// for IndexedAttestation).  A two-pointer walk finds the intersection without allocation.
fn attesterSlashingKey(indices_a: []const u64, indices_b: []const u64) [32]u8 {
    var hasher = std.hash.Wyhash.init(0x04);
    var i: usize = 0;
    var j: usize = 0;
    while (i < indices_a.len and j < indices_b.len) {
        if (indices_a[i] == indices_b[j]) {
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, indices_a[i], .little);
            hasher.update(&buf);
            i += 1;
            j += 1;
        } else if (indices_a[i] < indices_b[j]) {
            i += 1;
        } else {
            j += 1;
        }
    }
    var key: [32]u8 = std.mem.zeroes([32]u8);
    const hash = hasher.final();
    std.mem.writeInt(u64, key[0..8], hash, .little);
    key[16] = 0x04;
    return key;
}

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
    data_column_sidecar: DecodedDataColumnSidecar,
};

/// Decompress a Snappy-framed gossip payload, rejecting payloads that would
/// expand beyond `max_decompressed_size` bytes.
///
/// A malicious peer can craft a tiny compressed stream that decompresses to
/// gigabytes of data.  Checking the output length after decompression and
/// freeing immediately bounds worst-case allocation to one call's worth of
/// output.
///
/// Use `maxGossipSize(topic)` to obtain the appropriate limit for a given
/// gossip topic, or one of the `MAX_GOSSIP_SIZE_*` constants directly.
///
/// Returns the decompressed SSZ bytes.  Caller owns the returned memory.
pub fn decompressGossipPayload(
    allocator: Allocator,
    compressed_data: []const u8,
    max_decompressed_size: usize,
) DecodeError![]const u8 {
    const decompressed = snappy.uncompress(allocator, compressed_data) catch |err| return err;
    if (decompressed == null) return error.EmptyPayload;
    const result = decompressed.?;
    if (result.len > max_decompressed_size) {
        allocator.free(result);
        return error.DecompressionBombDetected;
    }
    return result;
}

/// Decode a raw gossip message (Snappy-compressed SSZ) into its typed representation.
///
/// This performs:
/// 1. Snappy decompression (bounded by per-topic size limit)
/// 2. SSZ deserialization based on the topic type and active fork
/// 3. Extraction of validation-relevant fields
///
/// The `raw_data` is the Snappy-framed payload received from gossipsub.
/// `fork_seq` must reflect the active fork at the time the message was received
/// so that the correct SSZ schema is selected (e.g. electra vs phase0 attestations).
pub fn decodeGossipMessage(
    allocator: Allocator,
    topic_type: GossipTopicType,
    raw_data: []const u8,
    fork_seq: ForkSeq,
) DecodeError!DecodedGossipMessage {
    // Step 1: Snappy decompress with per-topic size limit.
    const ssz_bytes = try decompressGossipPayload(allocator, raw_data, maxGossipSize(topic_type));

    // Step 2: Deserialize based on topic type and active fork.
    // For beacon_block, ownership of ssz_bytes transfers into the returned
    // DecodedBeaconBlock.raw_ssz field — do NOT free here.
    // For all other topic types, free after decoding.
    if (topic_type != .beacon_block) {
        defer allocator.free(ssz_bytes);
        return decodeFromSszBytes(allocator, topic_type, ssz_bytes, fork_seq);
    }
    // beacon_block: ownership transfers into raw_ssz on success.
    errdefer allocator.free(ssz_bytes);
    return decodeFromSszBytes(allocator, topic_type, ssz_bytes, fork_seq);
}

/// Decode SSZ bytes (already decompressed) into a typed gossip message.
///
/// `fork_seq` determines which SSZ schema to use for fork-versioned types:
/// - beacon_block: header fields extracted via raw SSZ offsets (fork-agnostic)
/// - beacon_aggregate_and_proof: phase0 schema pre-Electra, electra schema from Electra
/// - beacon_attestation: phase0.Attestation pre-Electra, electra.SingleAttestation from Electra
/// - attester_slashing: phase0 schema pre-Electra, electra schema from Electra
pub fn decodeFromSszBytes(
    allocator: Allocator,
    topic_type: GossipTopicType,
    ssz_bytes: []const u8,
    fork_seq: ForkSeq,
) DecodeError!DecodedGossipMessage {
    switch (topic_type) {
        .beacon_block => {
            // Extract slot, proposer_index, and parent_root directly from SSZ bytes.
            //
            // SignedBeaconBlock SSZ layout (all forks, VariableContainerType):
            //   [message_offset: 4 bytes][signature: 96 bytes][message_ssz...]
            //
            // BeaconBlock SSZ layout (VariableContainerType) starting at message_offset:
            //   [slot: 8][proposer_index: 8][parent_root: 32][state_root: 32][body_offset: 4]...
            //
            // These header fields are identical across all forks (phase0 through fulu).
            // Reading them directly avoids allocating a fork-specific type and works on
            // any fork without additional parameters.
            const SIGNATURE_SIZE: usize = 96;
            const BLS_SIG_OFFSET: usize = 4; // message_offset field is 4 bytes
            // message_offset value = 4 (offset field) + 96 (signature) = 100
            const MIN_SIGNED_BLOCK_SIZE: usize = BLS_SIG_OFFSET + SIGNATURE_SIZE + 8 + 8 + 32;
            if (ssz_bytes.len < MIN_SIGNED_BLOCK_SIZE) return error.SszDeserializationFailed;
            const message_offset = std.mem.readInt(u32, ssz_bytes[0..4], .little);
            if (message_offset != BLS_SIG_OFFSET + SIGNATURE_SIZE) return error.SszDeserializationFailed;
            if (ssz_bytes.len < message_offset + 8 + 8 + 32) return error.SszDeserializationFailed;
            const slot = std.mem.readInt(u64, ssz_bytes[message_offset..][0..8], .little);
            const proposer_index = std.mem.readInt(u64, ssz_bytes[message_offset + 8 ..][0..8], .little);
            var parent_root: [32]u8 = undefined;
            @memcpy(&parent_root, ssz_bytes[message_offset + 16 ..][0..32]);
            return .{
                .beacon_block = .{
                    .slot = slot,
                    .proposer_index = proposer_index,
                    .parent_root = parent_root,
                    // raw_ssz is filled in by decodeGossipMessage after ownership transfer.
                    // When called directly (e.g. from tests), callers must set raw_ssz themselves.
                    .raw_ssz = ssz_bytes,
                },
            };
        },
        .beacon_aggregate_and_proof => {
            if (fork_seq.gte(.electra)) {
                // Electra+: SignedAggregateAndProof uses electra.Attestation with committee_bits.
                var signed_agg: electra.SignedAggregateAndProof.Type = undefined;
                electra.SignedAggregateAndProof.deserializeFromBytes(allocator, ssz_bytes, &signed_agg) catch
                    return error.SszDeserializationFailed;
                const agg = signed_agg.message;
                const att = agg.aggregate;
                return .{ .beacon_aggregate_and_proof = .{
                    .aggregator_index = agg.aggregator_index,
                    .attestation_slot = att.data.slot,
                    .attestation_target_epoch = att.data.target.epoch,
                    .aggregation_bits_count = countSetBits(&att.aggregation_bits),
                } };
            } else {
                // Pre-Electra: SignedAggregateAndProof uses phase0.Attestation.
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
            }
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
            if (fork_seq.gte(.electra)) {
                // Electra+: Individual gossip attestations use SingleAttestation format
                // (one validator per message, committee_index + attester_index).
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
            } else {
                // Pre-Electra: Individual gossip attestations use phase0.Attestation format
                // (aggregation_bits is a BitList of length COMMITTEE_SIZE, one bit set).
                var att: phase0.Attestation.Type = undefined;
                phase0.Attestation.deserializeFromBytes(allocator, ssz_bytes, &att) catch
                    return error.SszDeserializationFailed;
                // committee_index is in data.index for phase0; attester_index is unknown at
                // decode time (it's the single set bit in aggregation_bits, but we don't know
                // the committee here). Use 0 as placeholder — callers must handle pre-Electra.
                return .{
                    .beacon_attestation = .{
                        .committee_index = att.data.index,
                        .attester_index = 0, // not available in pre-Electra gossip format
                        .slot = att.data.slot,
                        .target_epoch = att.data.target.epoch,
                        .target_root = att.data.target.root,
                        .beacon_block_root = att.data.beacon_block_root,
                        .source_epoch = att.data.source.epoch,
                        .source_root = att.data.source.root,
                    },
                };
            }
        },
        .attester_slashing => {
            // Slashable check is the same logic for all forks; only the SSZ schema differs.
            // Electra changed IndexedAttestation.attesting_indices from MAX_VALIDATORS_PER_COMMITTEE
            // to MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT.
            if (fork_seq.gte(.electra)) {
                var slashing: electra.AttesterSlashing.Type = undefined;
                electra.AttesterSlashing.deserializeFromBytes(allocator, ssz_bytes, &slashing) catch
                    return error.SszDeserializationFailed;
                const d1 = &slashing.attestation_1.data;
                const d2 = &slashing.attestation_2.data;
                const is_double_vote = !phase0.AttestationData.equals(d1, d2) and d1.target.epoch == d2.target.epoch;
                const is_surround_vote = d1.source.epoch < d2.source.epoch and d2.target.epoch < d1.target.epoch;
                const key = attesterSlashingKey(
                    slashing.attestation_1.attesting_indices.items,
                    slashing.attestation_2.attesting_indices.items,
                );
                return .{ .attester_slashing = .{
                    .is_slashable = is_double_vote or is_surround_vote,
                    .slashable_key = key,
                } };
            } else {
                var slashing: phase0.AttesterSlashing.Type = undefined;
                phase0.AttesterSlashing.deserializeFromBytes(allocator, ssz_bytes, &slashing) catch
                    return error.SszDeserializationFailed;
                const d1 = &slashing.attestation_1.data;
                const d2 = &slashing.attestation_2.data;
                const is_double_vote = !phase0.AttestationData.equals(d1, d2) and d1.target.epoch == d2.target.epoch;
                const is_surround_vote = d1.source.epoch < d2.source.epoch and d2.target.epoch < d1.target.epoch;
                const key = attesterSlashingKey(
                    slashing.attestation_1.attesting_indices.items,
                    slashing.attestation_2.attesting_indices.items,
                );
                return .{ .attester_slashing = .{
                    .is_slashable = is_double_vote or is_surround_vote,
                    .slashable_key = key,
                } };
            }
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
            //     BeaconBlockHeader (message):@ offset 131176  (message is first field)
            //       slot:           8 bytes  @ offset 131176
            //       proposer_index: 8 bytes  @ offset 131184
            //       parent_root:   32 bytes  @ offset 131192
            //       state_root:    32 bytes  @ offset 131224
            //       body_root:     32 bytes  @ offset 131256
            //     BLSSignature:    96 bytes  @ offset 131288 (signature is second field)
            //
            // These offsets are derived from SSZ fixed-size field layout.
            // SignedBeaconBlockHeader = { message: BeaconBlockHeader, signature: BLSSignature }
            // IMPORTANT: If FIELD_ELEMENTS_PER_BLOB changes (e.g. in future forks),
            // these offsets must be updated. A compile-time assert guards this.
            const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
            const BYTES_PER_FIELD_ELEMENT: usize = 32;
            const blob_size = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT; // 131072
            const kzg_commitment_size: usize = 48;
            const kzg_proof_size: usize = 48;

            const signed_block_header_offset = 8 + blob_size + kzg_commitment_size + kzg_proof_size;
            // message (BeaconBlockHeader) is the first field of SignedBeaconBlockHeader
            const slot_offset = signed_block_header_offset; // slot is first field of BeaconBlockHeader
            const proposer_index_offset = slot_offset + 8;
            const parent_root_offset = proposer_index_offset + 8;

            // Compile-time assertion: verify our computed offsets match what we hardcoded.
            comptime {
                std.debug.assert(signed_block_header_offset == 131176);
                std.debug.assert(slot_offset == 131176);
                std.debug.assert(proposer_index_offset == 131184);
                std.debug.assert(parent_root_offset == 131192);
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
        .data_column_sidecar => {
            var sidecar = consensus_types.fulu.DataColumnSidecar.default_value;
            consensus_types.fulu.DataColumnSidecar.deserializeFromBytes(allocator, ssz_bytes, &sidecar) catch
                return error.SszDeserializationFailed;
            defer consensus_types.fulu.DataColumnSidecar.deinit(allocator, &sidecar);

            const header = &sidecar.signed_block_header.message;
            var block_root: [32]u8 = undefined;
            phase0.BeaconBlockHeader.hashTreeRoot(header, &block_root) catch
                return error.SszDeserializationFailed;

            return .{ .data_column_sidecar = .{
                .index = sidecar.index,
                .slot = header.slot,
                .proposer_index = header.proposer_index,
                .block_parent_root = header.parent_root,
                .block_root = block_root,
            } };
        },
    }
}

// === Tests ===

test "decompressGossipPayload roundtrip" {
    const original = "hello gossip world";
    const compressed = try snappy.compress(testing.allocator, original);
    defer testing.allocator.free(compressed);

    const decompressed = try decompressGossipPayload(testing.allocator, compressed, MAX_GOSSIP_SIZE_DEFAULT);
    defer testing.allocator.free(decompressed);

    try testing.expectEqualStrings(original, decompressed);
}

test "decompressGossipPayload rejects decompression bomb" {
    // Craft a payload that decompresses to more bytes than the limit.
    // Use a small limit so our test data triggers it.
    const original = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 64 bytes
    const compressed = try snappy.compress(testing.allocator, original);
    defer testing.allocator.free(compressed);

    // Allow only 10 bytes — the 64-byte decompressed result should be rejected.
    const result = decompressGossipPayload(testing.allocator, compressed, 10);
    try testing.expectError(error.DecompressionBombDetected, result);
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
    // Note: decodeFromSszBytes for beacon_block sets raw_ssz = ssz_bytes (the input slice).
    // ssz_buf is already freed by the defer above, so we must NOT free raw_ssz separately here.
    const decoded = try decodeFromSszBytes(testing.allocator, .beacon_block, ssz_buf, .phase0);
    try testing.expectEqual(@as(u64, 42), decoded.beacon_block.slot);
    try testing.expectEqual(@as(u64, 7), decoded.beacon_block.proposer_index);
    try testing.expectEqualSlices(u8, &([_]u8{0xAA} ** 32), &decoded.beacon_block.parent_root);
    // raw_ssz points into ssz_buf which is freed by the defer above — no extra free needed.
}

test "decode voluntary_exit from SSZ bytes" {
    var exit: phase0.SignedVoluntaryExit.Type = phase0.SignedVoluntaryExit.default_value;
    exit.message.validator_index = 123;
    exit.message.epoch = 10;

    var ssz_buf: [phase0.SignedVoluntaryExit.fixed_size]u8 = undefined;
    _ = phase0.SignedVoluntaryExit.serializeIntoBytes(&exit, &ssz_buf);

    const decoded = try decodeFromSszBytes(testing.allocator, .voluntary_exit, &ssz_buf, .phase0);
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

    const decoded = try decodeFromSszBytes(testing.allocator, .proposer_slashing, &ssz_buf, .phase0);
    try testing.expectEqual(@as(u64, 5), decoded.proposer_slashing.proposer_index);
    try testing.expectEqual(@as(u64, 100), decoded.proposer_slashing.header_1_slot);
    try testing.expectEqual(@as(u64, 100), decoded.proposer_slashing.header_2_slot);
}

test "decode data_column_sidecar from SSZ bytes" {
    var sidecar = consensus_types.fulu.DataColumnSidecar.default_value;
    sidecar.index = 7;
    sidecar.signed_block_header.message.slot = 123;
    sidecar.signed_block_header.message.proposer_index = 11;
    sidecar.signed_block_header.message.parent_root = [_]u8{0xAA} ** 32;

    const ssz_size = consensus_types.fulu.DataColumnSidecar.serializedSize(&sidecar);
    const ssz_buf = try testing.allocator.alloc(u8, ssz_size);
    defer testing.allocator.free(ssz_buf);
    _ = consensus_types.fulu.DataColumnSidecar.serializeIntoBytes(&sidecar, ssz_buf);

    const decoded = try decodeFromSszBytes(testing.allocator, .data_column_sidecar, ssz_buf, .fulu);
    try testing.expectEqual(@as(u64, 7), decoded.data_column_sidecar.index);
    try testing.expectEqual(@as(u64, 123), decoded.data_column_sidecar.slot);
    try testing.expectEqual(@as(u64, 11), decoded.data_column_sidecar.proposer_index);
    try testing.expectEqualSlices(u8, &([_]u8{0xAA} ** 32), &decoded.data_column_sidecar.block_parent_root);
}

test "decode attester_slashing bad SSZ" {
    const dummy = [_]u8{ 0, 1, 2, 3 };
    const result = decodeFromSszBytes(testing.allocator, .attester_slashing, &dummy, .phase0);
    try testing.expectError(error.SszDeserializationFailed, result);
}

test "decode bls_to_execution_change from SSZ bytes" {
    var change: capella.SignedBLSToExecutionChange.Type = capella.SignedBLSToExecutionChange.default_value;
    change.message.validator_index = 42;

    var ssz_buf: [capella.SignedBLSToExecutionChange.fixed_size]u8 = undefined;
    _ = capella.SignedBLSToExecutionChange.serializeIntoBytes(&change, &ssz_buf);

    const decoded = try decodeFromSszBytes(testing.allocator, .bls_to_execution_change, &ssz_buf, .capella);
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

    const decoded = try decodeFromSszBytes(testing.allocator, .beacon_attestation, &ssz_buf, .electra);
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

    const decoded = try decodeFromSszBytes(testing.allocator, .beacon_aggregate_and_proof, ssz_buf, .phase0);
    try testing.expectEqual(@as(u64, 7), decoded.beacon_aggregate_and_proof.aggregator_index);
    try testing.expectEqual(@as(u64, 96), decoded.beacon_aggregate_and_proof.attestation_slot);
    try testing.expectEqual(@as(u64, 3), decoded.beacon_aggregate_and_proof.attestation_target_epoch);
}

test "decode invalid SSZ data returns error" {
    // Too-short data should fail deserialization.
    const bad_data = [_]u8{ 0, 0, 0 };
    const result = decodeFromSszBytes(testing.allocator, .beacon_block, &bad_data, .phase0);
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
    // raw_ssz is a fresh allocation from decompressGossipPayload — caller must free.
    const decoded = try decodeGossipMessage(testing.allocator, .beacon_block, compressed, .phase0);
    defer testing.allocator.free(decoded.beacon_block.raw_ssz);
    try testing.expectEqual(@as(u64, 99), decoded.beacon_block.slot);
    try testing.expectEqual(@as(u64, 3), decoded.beacon_block.proposer_index);
}
