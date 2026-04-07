//! SSZ types for req/resp protocol messages.
//!
//! These types define the request and response payloads for each protocol method.
//! They use the SSZ framework from `src/ssz/` for serialization.
//!
//! Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md#messages

const std = @import("std");
const testing = std.testing;
const ssz = @import("ssz");
const consensus_types = @import("consensus_types");
const p = consensus_types.primitive;
const deneb = consensus_types.deneb;
const preset = @import("preset").preset;
const constants = @import("constants");

// === Phase0 messages ===

/// StatusMessage is exchanged during the Status handshake.
///
/// Contains the node's view of the chain head and finalized checkpoint.
pub const StatusMessage = ssz.FixedContainerType(struct {
    fork_digest: p.ForkDigest,
    finalized_root: p.Root,
    finalized_epoch: p.Epoch,
    head_root: p.Root,
    head_slot: p.Slot,
});

/// Fulu Status adds the earliest slot this node can serve.
pub const StatusMessageV2 = ssz.FixedContainerType(struct {
    fork_digest: p.ForkDigest,
    finalized_root: p.Root,
    finalized_epoch: p.Epoch,
    head_root: p.Root,
    head_slot: p.Slot,
    earliest_available_slot: p.Slot,
});

/// Ping message carries a metadata sequence number.
pub const Ping = p.Uint64;

/// GoodbyeReason is a single uint64 indicating why the peer is disconnecting.
///
/// Known reasons:
/// - 1: Client shut down
/// - 2: Irrelevant network
/// - 3: Fault/error
pub const GoodbyeReason = p.Uint64;

/// BeaconBlocksByRangeRequest requests a contiguous range of blocks.
///
/// The `step` field is deprecated (always 1) but remains in the SSZ
/// container for backwards compatibility — all implementations still
/// encode/decode 24 bytes.
pub const BeaconBlocksByRangeRequest = ssz.FixedContainerType(struct {
    start_slot: p.Slot,
    count: p.Uint64,
    step: p.Uint64,
});

/// BeaconBlocksByRootRequest is a list of block roots to request.
pub const BeaconBlocksByRootRequest = ssz.FixedListType(p.Root, preset.MAX_REQUEST_BLOCKS);

// === Altair messages ===

/// Metadata contains information about the node's subscriptions.
///
/// Phase0 Metadata has seq_number and attnets only.
/// Altair adds syncnets. The version returned depends on the fork.
pub const MetadataV1 = ssz.FixedContainerType(struct {
    seq_number: p.Uint64,
    attnets: ssz.BitVectorType(constants.ATTESTATION_SUBNET_COUNT),
});

pub const MetadataV2 = ssz.FixedContainerType(struct {
    seq_number: p.Uint64,
    attnets: ssz.BitVectorType(constants.ATTESTATION_SUBNET_COUNT),
    syncnets: ssz.BitVectorType(constants.SYNC_COMMITTEE_SUBNET_COUNT),
});

/// Fulu Metadata adds custody_group_count for PeerDAS.
pub const MetadataV3 = ssz.FixedContainerType(struct {
    seq_number: p.Uint64,
    attnets: ssz.BitVectorType(constants.ATTESTATION_SUBNET_COUNT),
    syncnets: ssz.BitVectorType(constants.SYNC_COMMITTEE_SUBNET_COUNT),
    custody_group_count: p.Uint64,
});

// === Deneb messages ===

/// BlobSidecarsByRangeRequest requests blob sidecars for a slot range.
pub const BlobSidecarsByRangeRequest = ssz.FixedContainerType(struct {
    start_slot: p.Slot,
    count: p.Uint64,
});

/// BlobSidecarsByRootRequest is a list of blob identifiers.
pub const BlobSidecarsByRootRequest = ssz.FixedListType(
    deneb.BlobIdentifier,
    constants.MAX_REQUEST_BLOCKS_DENEB * preset.MAX_BLOBS_PER_BLOCK,
);

// === Fulu / PeerDAS messages ===

/// DataColumnSidecarsByRangeRequest requests data column sidecars for a slot range.
pub const DataColumnSidecarsByRangeRequest = ssz.VariableContainerType(struct {
    start_slot: p.Slot,
    count: p.Uint64,
    columns: ssz.FixedListType(p.Uint64, 128),
});

/// DataColumnIdentifier identifies a specific data column sidecar by block root + column index.
pub const DataColumnIdentifier = ssz.FixedContainerType(struct {
    block_root: p.Root,
    index: p.Uint64,
});

// === Tests ===

test "StatusMessage fixed size" {
    // fork_digest(4) + finalized_root(32) + finalized_epoch(8) + head_root(32) + head_slot(8) = 84.
    try testing.expectEqual(@as(usize, 84), StatusMessage.fixed_size);
}

test "StatusMessageV2 fixed size" {
    // StatusMessage(84) + earliest_available_slot(8) = 92.
    try testing.expectEqual(@as(usize, 92), StatusMessageV2.fixed_size);
}

test "StatusMessage serialize and deserialize roundtrip" {
    const msg: StatusMessage.Type = .{
        .fork_digest = .{ 0x01, 0x02, 0x03, 0x04 },
        .finalized_root = [_]u8{0xAA} ** 32,
        .finalized_epoch = 100,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 200,
    };

    var buf: [StatusMessage.fixed_size]u8 = undefined;
    const written = StatusMessage.serializeIntoBytes(&msg, &buf);
    try testing.expectEqual(StatusMessage.fixed_size, written);

    var decoded: StatusMessage.Type = undefined;
    try StatusMessage.deserializeFromBytes(&buf, &decoded);
    try testing.expectEqual(msg.finalized_epoch, decoded.finalized_epoch);
    try testing.expectEqual(msg.head_slot, decoded.head_slot);
    try testing.expectEqualSlices(u8, &msg.fork_digest, &decoded.fork_digest);
    try testing.expectEqualSlices(u8, &msg.finalized_root, &decoded.finalized_root);
    try testing.expectEqualSlices(u8, &msg.head_root, &decoded.head_root);
}

test "StatusMessageV2 serialize and deserialize roundtrip" {
    const msg: StatusMessageV2.Type = .{
        .fork_digest = .{ 0x01, 0x02, 0x03, 0x04 },
        .finalized_root = [_]u8{0xAA} ** 32,
        .finalized_epoch = 100,
        .head_root = [_]u8{0xBB} ** 32,
        .head_slot = 200,
        .earliest_available_slot = 64,
    };

    var buf: [StatusMessageV2.fixed_size]u8 = undefined;
    const written = StatusMessageV2.serializeIntoBytes(&msg, &buf);
    try testing.expectEqual(StatusMessageV2.fixed_size, written);

    var decoded: StatusMessageV2.Type = undefined;
    try StatusMessageV2.deserializeFromBytes(&buf, &decoded);
    try testing.expectEqual(msg.finalized_epoch, decoded.finalized_epoch);
    try testing.expectEqual(msg.head_slot, decoded.head_slot);
    try testing.expectEqual(msg.earliest_available_slot, decoded.earliest_available_slot);
    try testing.expectEqualSlices(u8, &msg.fork_digest, &decoded.fork_digest);
    try testing.expectEqualSlices(u8, &msg.finalized_root, &decoded.finalized_root);
    try testing.expectEqualSlices(u8, &msg.head_root, &decoded.head_root);
}

test "Ping serialize roundtrip" {
    const ping: Ping.Type = 42;
    var buf: [Ping.fixed_size]u8 = undefined;
    _ = Ping.serializeIntoBytes(&ping, &buf);

    var decoded: Ping.Type = undefined;
    try Ping.deserializeFromBytes(&buf, &decoded);
    try testing.expectEqual(ping, decoded);
}

test "BeaconBlocksByRangeRequest fixed size" {
    // start_slot(8) + count(8) + step(8) = 24.
    try testing.expectEqual(@as(usize, 24), BeaconBlocksByRangeRequest.fixed_size);
}

test "BlobSidecarsByRangeRequest fixed size" {
    // start_slot(8) + count(8) = 16.
    try testing.expectEqual(@as(usize, 16), BlobSidecarsByRangeRequest.fixed_size);
}

test "MetadataV2 fixed size" {
    // seq_number(8) + attnets(64 bits = 8 bytes) + syncnets(4 bits = 1 byte) = 17.
    try testing.expectEqual(@as(usize, 17), MetadataV2.fixed_size);
}

test "MetadataV3 fixed size" {
    // MetadataV2(17) + custody_group_count(8) = 25.
    try testing.expectEqual(@as(usize, 25), MetadataV3.fixed_size);
}
