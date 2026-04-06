//! Shared peer scoring policy for networking events.
//!
//! This module intentionally stays small. It provides the shared policy
//! mapping from live networking events into `PeerAction` decisions without
//! reviving the old unused scoring service/state layer.

const std = @import("std");
const testing = std.testing;

const protocol = @import("protocol.zig");
const gossip_topics = @import("gossip_topics.zig");
const peer_info = @import("peer_info.zig");

const Method = protocol.Method;
const GossipTopicType = gossip_topics.GossipTopicType;
const PeerAction = peer_info.PeerAction;
const GoodbyeReason = peer_info.GoodbyeReason;

/// Ignore a bounded set of mildly negative gossipsub scores so recoverable
/// peers can heal their router score without immediate disconnection pressure.
pub const NEGATIVE_GOSSIPSUB_IGNORE_THRESHOLD: f64 = -1000.0;
pub const ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR: f64 = 0.1;

/// Req/resp protocol context for penalty decisions.
pub const ReqRespProtocol = enum {
    status,
    goodbye,
    ping,
    metadata,
    beacon_blocks_by_range,
    beacon_blocks_by_root,
    blob_sidecars_by_range,
    blob_sidecars_by_root,
    data_column_sidecars_by_range,
    data_column_sidecars_by_root,

    pub fn fromMethod(method: Method) ?ReqRespProtocol {
        return switch (method) {
            .status => .status,
            .goodbye => .goodbye,
            .ping => .ping,
            .metadata => .metadata,
            .beacon_blocks_by_range => .beacon_blocks_by_range,
            .beacon_blocks_by_root => .beacon_blocks_by_root,
            .blob_sidecars_by_range => .blob_sidecars_by_range,
            .blob_sidecars_by_root => .blob_sidecars_by_root,
            .data_column_sidecars_by_range => .data_column_sidecars_by_range,
            .data_column_sidecars_by_root => .data_column_sidecars_by_root,
            .light_client_bootstrap,
            .light_client_updates_by_range,
            .light_client_finality_update,
            .light_client_optimistic_update,
            => null,
        };
    }

    pub fn timeoutSeverity(self: ReqRespProtocol) PeerAction {
        return switch (self) {
            .ping, .status, .metadata => .low_tolerance,
            .beacon_blocks_by_range,
            .beacon_blocks_by_root,
            .blob_sidecars_by_range,
            .blob_sidecars_by_root,
            .data_column_sidecars_by_range,
            .data_column_sidecars_by_root,
            => .mid_tolerance,
            .goodbye => .high_tolerance,
        };
    }

    pub fn unsupportedSeverity(self: ReqRespProtocol) PeerAction {
        return switch (self) {
            .ping => .fatal,
            .status, .metadata => .low_tolerance,
            .goodbye,
            .beacon_blocks_by_range,
            .beacon_blocks_by_root,
            .blob_sidecars_by_range,
            .blob_sidecars_by_root,
            .data_column_sidecars_by_range,
            .data_column_sidecars_by_root,
            => .high_tolerance,
        };
    }
};

pub const GossipRejectReason = enum {
    decode_failed,
    invalid_signature,
    wrong_subnet,
    invalid_block,
    invalid_attestation,
    invalid_aggregate,
    invalid_voluntary_exit,
    invalid_proposer_slashing,
    invalid_attester_slashing,
    invalid_bls_to_execution_change,
    invalid_sync_contribution,
    invalid_sync_committee_message,
    invalid_blob_sidecar,
    invalid_data_column_sidecar,
};

pub fn defaultGossipRejectReason(topic: GossipTopicType) GossipRejectReason {
    return switch (topic) {
        .beacon_block => .invalid_block,
        .beacon_attestation => .invalid_attestation,
        .beacon_aggregate_and_proof => .invalid_aggregate,
        .voluntary_exit => .invalid_voluntary_exit,
        .proposer_slashing => .invalid_proposer_slashing,
        .attester_slashing => .invalid_attester_slashing,
        .bls_to_execution_change => .invalid_bls_to_execution_change,
        .sync_committee_contribution_and_proof => .invalid_sync_contribution,
        .sync_committee => .invalid_sync_committee_message,
        .blob_sidecar => .invalid_blob_sidecar,
        .data_column_sidecar => .invalid_data_column_sidecar,
    };
}

pub fn gossipFailureAction(reason: GossipRejectReason) PeerAction {
    return switch (reason) {
        .invalid_block => .fatal,
        .wrong_subnet => .mid_tolerance,
        .decode_failed,
        .invalid_signature,
        .invalid_attestation,
        .invalid_aggregate,
        .invalid_voluntary_exit,
        .invalid_proposer_slashing,
        .invalid_attester_slashing,
        .invalid_bls_to_execution_change,
        .invalid_sync_contribution,
        .invalid_sync_committee_message,
        .invalid_blob_sidecar,
        .invalid_data_column_sidecar,
        => .low_tolerance,
    };
}

/// Map a req/resp maintenance failure into an optional penalty.
///
/// `PeerNotConnected` means transport state is already gone and does not
/// warrant a further score penalty. Unsupported protocol negotiation should
/// be treated differently from generic I/O failure.
pub fn reqRespFailureAction(protocol_ctx: ReqRespProtocol, err: anyerror) ?PeerAction {
    return switch (err) {
        error.PeerNotConnected,
        error.RequestSelfRateLimited,
        => null,
        error.NoSupportedProtocols => protocol_ctx.unsupportedSeverity(),

        error.InvalidRequestResponse,
        error.MalformedBlockBytes,
        error.MalformedBlobSidecar,
        error.MalformedDataColumnSidecar,
        error.MissingContextBytes,
        error.ForkDigestMismatch,
        error.BlockOutsideRequestedRange,
        error.UnsortedBlockRangeResponse,
        error.UnexpectedBlobSidecar,
        error.UnexpectedBlobSlot,
        error.InvalidBlobIndex,
        error.KzgCommitmentMismatch,
        error.UnexpectedDataColumnSidecar,
        error.UnexpectedColumnSlot,
        error.InvalidColumnIndex,
        error.KzgCommitmentLengthMismatch,
        error.ColumnLengthMismatch,
        error.ColumnProofLengthMismatch,
        => .low_tolerance,

        error.ServerErrorResponse => .mid_tolerance,

        error.ResourceUnavailableResponse,
        error.EmptyResponse,
        error.NoBlockReturned,
        error.MissingBlobSidecar,
        error.MissingDataColumnSidecar,
        => .high_tolerance,

        else => protocol_ctx.timeoutSeverity(),
    };
}

/// Reconnection cool-down derived from a remote Goodbye reason.
pub fn reconnectionCoolDownMs(reason: GoodbyeReason) ?u64 {
    return switch (reason) {
        .banned, .score_too_low => null,
        .too_many_peers => 5 * 60 * 1000,
        .client_shutdown, .fault_error => 60 * 60 * 1000,
        .irrelevant_network, .unable_to_verify => 240 * 60 * 1000,
        _ => 30 * 60 * 1000,
    };
}

/// Reconnection cool-down for peers that silently close an inbound connection
/// without first sending Goodbye.
pub fn inboundDisconnectCoolDownMs() u64 {
    return 5 * 60 * 1000;
}

/// Number of connected peers whose mildly negative gossipsub score we ignore
/// so they can recover. Matches Lodestar's bounded 10% allowance.
pub fn negativeGossipsubIgnoreCount(target_peers: u32) u32 {
    const raw = @as(f64, @floatFromInt(target_peers)) * ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR;
    const count: u32 = @intFromFloat(@ceil(raw));
    return count;
}

test "ReqRespProtocol timeoutSeverity follows maintenance severity policy" {
    try testing.expectEqual(PeerAction.low_tolerance, ReqRespProtocol.ping.timeoutSeverity());
    try testing.expectEqual(PeerAction.low_tolerance, ReqRespProtocol.status.timeoutSeverity());
    try testing.expectEqual(PeerAction.mid_tolerance, ReqRespProtocol.beacon_blocks_by_range.timeoutSeverity());
    try testing.expectEqual(PeerAction.high_tolerance, ReqRespProtocol.goodbye.timeoutSeverity());
}

test "reqRespFailureAction distinguishes unsupported protocol and disconnected peer" {
    try testing.expectEqual(@as(?PeerAction, .fatal), reqRespFailureAction(.ping, error.NoSupportedProtocols));
    try testing.expectEqual(@as(?PeerAction, null), reqRespFailureAction(.ping, error.PeerNotConnected));
    try testing.expectEqual(@as(?PeerAction, null), reqRespFailureAction(.ping, error.RequestSelfRateLimited));
    try testing.expectEqual(@as(?PeerAction, .mid_tolerance), reqRespFailureAction(.beacon_blocks_by_root, error.ConnectionResetByPeer));
}

test "reqRespFailureAction maps explicit response codes and malformed data" {
    try testing.expectEqual(@as(?PeerAction, .low_tolerance), reqRespFailureAction(.status, error.InvalidRequestResponse));
    try testing.expectEqual(@as(?PeerAction, .mid_tolerance), reqRespFailureAction(.metadata, error.ServerErrorResponse));
    try testing.expectEqual(@as(?PeerAction, .high_tolerance), reqRespFailureAction(.beacon_blocks_by_root, error.ResourceUnavailableResponse));
    try testing.expectEqual(@as(?PeerAction, .low_tolerance), reqRespFailureAction(.beacon_blocks_by_range, error.MalformedBlockBytes));
}

test "reconnectionCoolDownMs matches goodbye severity" {
    try testing.expectEqual(@as(?u64, 5 * 60 * 1000), reconnectionCoolDownMs(.too_many_peers));
    try testing.expectEqual(@as(?u64, 60 * 60 * 1000), reconnectionCoolDownMs(.fault_error));
    try testing.expectEqual(@as(?u64, null), reconnectionCoolDownMs(.score_too_low));
}

test "negativeGossipsubIgnoreCount matches Lodestar allowance" {
    try testing.expectEqual(@as(u32, 0), negativeGossipsubIgnoreCount(0));
    try testing.expectEqual(@as(u32, 1), negativeGossipsubIgnoreCount(1));
    try testing.expectEqual(@as(u32, 1), negativeGossipsubIgnoreCount(10));
    try testing.expectEqual(@as(u32, 6), negativeGossipsubIgnoreCount(55));
}

test "gossipFailureAction maps production gossip penalties" {
    try testing.expectEqual(PeerAction.fatal, gossipFailureAction(.invalid_block));
    try testing.expectEqual(PeerAction.mid_tolerance, gossipFailureAction(.wrong_subnet));
    try testing.expectEqual(PeerAction.low_tolerance, gossipFailureAction(.invalid_signature));
    try testing.expectEqual(PeerAction.low_tolerance, gossipFailureAction(.decode_failed));
}

test "defaultGossipRejectReason follows topic families" {
    try testing.expectEqual(GossipRejectReason.invalid_block, defaultGossipRejectReason(.beacon_block));
    try testing.expectEqual(GossipRejectReason.invalid_sync_committee_message, defaultGossipRejectReason(.sync_committee));
    try testing.expectEqual(GossipRejectReason.invalid_data_column_sidecar, defaultGossipRejectReason(.data_column_sidecar));
}
