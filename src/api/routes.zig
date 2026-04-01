//! Beacon API route definitions.
//!
//! Maps HTTP method + path to handler functions. This is the routing table
//! that an HTTP server implementation would use to dispatch incoming requests.
//!
//! Each route definition includes:
//! - HTTP method (GET, POST)
//! - URL path pattern (with parameter placeholders)
//! - Handler function reference
//! - Expected response content types
//!
//! The actual HTTP server integration is deferred; this module provides the
//! route table as data that any server library can consume.

const std = @import("std");
const types = @import("types.zig");
const handlers = @import("handlers/root.zig");
const context = @import("context.zig");
const ApiContext = context.ApiContext;

pub const HttpMethod = enum {
    GET,
    POST,
    DELETE,
};

/// A route definition: method, path pattern, and metadata.
pub const Route = struct {
    method: HttpMethod,
    path: []const u8,
    /// Human-readable operation ID (matches OpenAPI operationId).
    operation_id: []const u8,
    /// Whether this endpoint supports SSZ responses.
    supports_ssz: bool = false,
};

/// Complete Beacon API route table.
///
/// Order matters for prefix matching — more specific routes come first.
pub const routes = [_]Route{
    // -- Node --
    .{
        .method = .GET,
        .path = "/eth/v1/node/identity",
        .operation_id = "getNodeIdentity",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/node/version",
        .operation_id = "getNodeVersion",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/node/syncing",
        .operation_id = "getSyncing",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/node/health",
        .operation_id = "getHealth",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/node/peers",
        .operation_id = "getPeers",
    },

    // -- Beacon --
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/genesis",
        .operation_id = "getGenesis",
    },
    .{
        .method = .GET,
        .path = "/eth/v2/beacon/blocks/{block_id}",
        .operation_id = "getBlockV2",
        .supports_ssz = true,
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/headers/{block_id}",
        .operation_id = "getBlockHeader",
    },
    .{
        .method = .GET,
        .path = "/eth/v2/beacon/states/{state_id}/validators/{validator_id}",
        .operation_id = "getStateValidatorV2",
    },
    .{
        .method = .GET,
        .path = "/eth/v2/beacon/states/{state_id}/validators",
        .operation_id = "getStateValidatorsV2",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/states/{state_id}/root",
        .operation_id = "getStateRoot",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/states/{state_id}/fork",
        .operation_id = "getStateFork",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
        .operation_id = "getFinalityCheckpoints",
    },
    .{
        .method = .POST,
        .path = "/eth/v2/beacon/blocks",
        .operation_id = "publishBlockV2",
        .supports_ssz = true,
    },
    .{
        .method = .POST,
        .path = "/eth/v1/beacon/pool/attestations",
        .operation_id = "submitPoolAttestations",
    },
    .{
        .method = .POST,
        .path = "/eth/v2/beacon/pool/attestations",
        .operation_id = "submitPoolAttestationsV2",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/beacon/pool/voluntary_exits",
        .operation_id = "submitPoolVoluntaryExits",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/beacon/pool/proposer_slashings",
        .operation_id = "submitPoolProposerSlashings",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/beacon/pool/attester_slashings",
        .operation_id = "submitPoolAttesterSlashings",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/beacon/pool/bls_to_execution_changes",
        .operation_id = "submitPoolBlsToExecutionChanges",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/beacon/pool/sync_committees",
        .operation_id = "submitPoolSyncCommittees",
    },

    // -- Pool --
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/pool/attestations",
        .operation_id = "getPoolAttestations",
    },
    .{
        .method = .GET,
        .path = "/eth/v2/beacon/pool/attestations",
        .operation_id = "getPoolAttestationsV2",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/pool/voluntary_exits",
        .operation_id = "getPoolVoluntaryExits",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/pool/proposer_slashings",
        .operation_id = "getPoolProposerSlashings",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/pool/attester_slashings",
        .operation_id = "getPoolAttesterSlashings",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/pool/bls_to_execution_changes",
        .operation_id = "getPoolBlsToExecutionChanges",
    },

    // -- Validator --
    .{
        .method = .GET,
        .path = "/eth/v1/validator/duties/proposer/{epoch}",
        .operation_id = "getProposerDuties",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/validator/duties/attester/{epoch}",
        .operation_id = "getAttesterDuties",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/validator/duties/sync/{epoch}",
        .operation_id = "getSyncDuties",
    },

    .{
        .method = .GET,
        .path = "/eth/v1/validator/blocks/{slot}",
        .operation_id = "produceBlock",
        .supports_ssz = true,
    },
    .{
        .method = .GET,
        .path = "/eth/v3/validator/blocks/{slot}",
        .operation_id = "produceBlockV3",
        .supports_ssz = true,
    },
    .{
        .method = .GET,
        .path = "/eth/v1/validator/attestation_data",
        .operation_id = "getAttestationData",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/validator/aggregate_attestation",
        .operation_id = "getAggregateAttestation",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/validator/aggregate_and_proofs",
        .operation_id = "publishAggregateAndProofs",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/validator/sync_committee_contribution",
        .operation_id = "getSyncCommitteeContribution",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/validator/contribution_and_proofs",
        .operation_id = "publishContributionAndProofs",
    },

    // -- Debug --
    .{
        .method = .GET,
        .path = "/eth/v2/debug/beacon/states/{state_id}",
        .operation_id = "getDebugState",
        .supports_ssz = true,
    },
    .{
        .method = .GET,
        .path = "/eth/v2/debug/beacon/heads",
        .operation_id = "getDebugHeads",
    },

    // -- Events --
    .{
        .method = .GET,
        .path = "/eth/v1/events",
        .operation_id = "getEvents",
    },

    // -- Node (additional) --
    .{
        .method = .GET,
        .path = "/eth/v1/node/peer_count",
        .operation_id = "getPeerCount",
    },
    // -- Config --
    // -- Beacon state (additional) --
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/states/{state_id}/committees",
        .operation_id = "getStateCommittees",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/states/{state_id}/sync_committees",
        .operation_id = "getStateSyncCommittees",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/states/{state_id}/randao",
        .operation_id = "getStateRandao",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/headers",
        .operation_id = "getBlockHeaders",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/blob_sidecars/{block_id}",
        .operation_id = "getBlobSidecars",
        .supports_ssz = true,
    },
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/blinded_blocks/{block_id}",
        .operation_id = "getBlindedBlock",
        .supports_ssz = true,
    },

    // -- Rewards --
    .{
        .method = .GET,
        .path = "/eth/v1/beacon/rewards/blocks/{block_id}",
        .operation_id = "getBlockRewards",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/beacon/rewards/attestations/{epoch}",
        .operation_id = "getAttestationRewards",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/beacon/rewards/sync_committee/{block_id}",
        .operation_id = "getSyncCommitteeRewards",
    },

    // -- Validator (additional) --
    .{
        .method = .POST,
        .path = "/eth/v1/validator/prepare_beacon_proposer",
        .operation_id = "prepareBeaconProposer",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/validator/register_validator",
        .operation_id = "registerValidator",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/validator/liveness/{epoch}",
        .operation_id = "getValidatorLiveness",
    },

    // -- Node (peer by id) --
    .{
        .method = .GET,
        .path = "/eth/v1/node/peers/{peer_id}",
        .operation_id = "getPeer",
    },

    // -- Debug (fork choice) --
    .{
        .method = .GET,
        .path = "/eth/v1/debug/fork_choice",
        .operation_id = "getForkChoice",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/config/spec",
        .operation_id = "getSpec",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/config/fork_schedule",
        .operation_id = "getForkSchedule",
    },
    // -- Lodestar custom --
    .{
        .method = .GET,
        .path = "/eth/v1/lodestar/validator_monitor",
        .operation_id = "getValidatorMonitor",
    },
    // -- Keymanager API (EIP-3042) --
    .{
        .method = .GET,
        .path = "/eth/v1/keystores",
        .operation_id = "listKeystores",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/keystores",
        .operation_id = "importKeystores",
    },
    .{
        .method = .DELETE,
        .path = "/eth/v1/keystores",
        .operation_id = "deleteKeystores",
    },
    .{
        .method = .GET,
        .path = "/eth/v1/remotekeys",
        .operation_id = "listRemoteKeys",
    },
    .{
        .method = .POST,
        .path = "/eth/v1/remotekeys",
        .operation_id = "importRemoteKeys",
    },
    .{
        .method = .DELETE,
        .path = "/eth/v1/remotekeys",
        .operation_id = "deleteRemoteKeys",
    },
};

/// Path segment — either a literal string or a named parameter.
pub const PathSegment = union(enum) {
    literal: []const u8,
    param: []const u8,
};

/// Parse a route path pattern into segments.
///
/// "/eth/v1/beacon/blocks/{block_id}" -> [literal("eth"), literal("v1"), ...]
pub fn parsePathPattern(path: []const u8) [16]?PathSegment {
    var segments: [16]?PathSegment = .{null} ** 16;
    var seg_count: usize = 0;

    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |segment| {
        if (segment.len == 0) continue;
        if (seg_count >= 16) break;

        if (segment.len > 2 and segment[0] == '{' and segment[segment.len - 1] == '}') {
            segments[seg_count] = .{ .param = segment[1 .. segment.len - 1] };
        } else {
            segments[seg_count] = .{ .literal = segment };
        }
        seg_count += 1;
    }
    return segments;
}

/// Match a request path against a route pattern, extracting parameters.
///
/// Returns a map of parameter names to their values, or null on mismatch.
pub fn matchRoute(pattern: []const u8, request_path: []const u8) ?[4]?PathParam {
    const pattern_segments = parsePathPattern(pattern);
    var request_iter = std.mem.splitScalar(u8, request_path, '/');

    var params: [4]?PathParam = .{null} ** 4;
    var param_count: usize = 0;
    var seg_idx: usize = 0;

    while (request_iter.next()) |req_seg| {
        if (req_seg.len == 0) continue;

        const pat = pattern_segments[seg_idx] orelse return null; // request longer than pattern
        seg_idx += 1;

        switch (pat) {
            .literal => |lit| {
                if (!std.mem.eql(u8, lit, req_seg)) return null;
            },
            .param => |name| {
                if (param_count >= 4) return null;
                params[param_count] = .{ .name = name, .value = req_seg };
                param_count += 1;
            },
        }
    }

    // Verify pattern is also exhausted
    if (pattern_segments[seg_idx] != null) return null;

    return params;
}

pub const PathParam = struct {
    name: []const u8,
    value: []const u8,
};

/// Find the matching route for a request and extract path parameters.
pub fn findRoute(method: HttpMethod, path: []const u8) ?RouteMatch {
    for (routes) |route| {
        if (route.method != method) continue;
        if (matchRoute(route.path, path)) |params| {
            return .{
                .route = route,
                .params = params,
            };
        }
    }
    return null;
}

pub const RouteMatch = struct {
    route: Route,
    params: [4]?PathParam,

    /// Get a path parameter by name.
    pub fn getParam(self: *const RouteMatch, name: []const u8) ?[]const u8 {
        for (self.params) |maybe_param| {
            const param = maybe_param orelse continue;
            if (std.mem.eql(u8, param.name, name)) return param.value;
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parsePathPattern literals only" {
    const segments = parsePathPattern("/eth/v1/node/identity");
    try std.testing.expectEqualStrings("eth", segments[0].?.literal);
    try std.testing.expectEqualStrings("v1", segments[1].?.literal);
    try std.testing.expectEqualStrings("node", segments[2].?.literal);
    try std.testing.expectEqualStrings("identity", segments[3].?.literal);
    try std.testing.expect(segments[4] == null);
}

test "parsePathPattern with params" {
    const segments = parsePathPattern("/eth/v2/beacon/blocks/{block_id}");
    try std.testing.expectEqualStrings("eth", segments[0].?.literal);
    try std.testing.expectEqualStrings("v2", segments[1].?.literal);
    try std.testing.expectEqualStrings("beacon", segments[2].?.literal);
    try std.testing.expectEqualStrings("blocks", segments[3].?.literal);
    try std.testing.expectEqualStrings("block_id", segments[4].?.param);
    try std.testing.expect(segments[5] == null);
}

test "matchRoute exact" {
    const result = matchRoute("/eth/v1/node/identity", "/eth/v1/node/identity");
    try std.testing.expect(result != null);
}

test "matchRoute with param extraction" {
    const result = matchRoute("/eth/v2/beacon/blocks/{block_id}", "/eth/v2/beacon/blocks/head");
    try std.testing.expect(result != null);
    const params = result.?;
    try std.testing.expectEqualStrings("block_id", params[0].?.name);
    try std.testing.expectEqualStrings("head", params[0].?.value);
}

test "matchRoute no match" {
    const result = matchRoute("/eth/v1/node/identity", "/eth/v1/node/version");
    try std.testing.expect(result == null);
}

test "matchRoute path too short" {
    const result = matchRoute("/eth/v1/node/identity", "/eth/v1/node");
    try std.testing.expect(result == null);
}

test "matchRoute path too long" {
    const result = matchRoute("/eth/v1/node/identity", "/eth/v1/node/identity/extra");
    try std.testing.expect(result == null);
}

test "matchRoute multi-param" {
    const result = matchRoute(
        "/eth/v2/beacon/states/{state_id}/validators/{validator_id}",
        "/eth/v2/beacon/states/head/validators/42",
    );
    try std.testing.expect(result != null);
    const params = result.?;
    try std.testing.expectEqualStrings("state_id", params[0].?.name);
    try std.testing.expectEqualStrings("head", params[0].?.value);
    try std.testing.expectEqualStrings("validator_id", params[1].?.name);
    try std.testing.expectEqualStrings("42", params[1].?.value);
}

test "findRoute GET node identity" {
    const match = findRoute(.GET, "/eth/v1/node/identity");
    try std.testing.expect(match != null);
    try std.testing.expectEqualStrings("getNodeIdentity", match.?.route.operation_id);
}

test "findRoute GET block with param" {
    const match = findRoute(.GET, "/eth/v2/beacon/blocks/finalized");
    try std.testing.expect(match != null);
    try std.testing.expectEqualStrings("getBlockV2", match.?.route.operation_id);
    try std.testing.expectEqualStrings("finalized", match.?.getParam("block_id").?);
}

test "findRoute POST block" {
    const match = findRoute(.POST, "/eth/v2/beacon/blocks");
    try std.testing.expect(match != null);
    try std.testing.expectEqualStrings("publishBlockV2", match.?.route.operation_id);
}

test "findRoute no match" {
    const match = findRoute(.GET, "/eth/v1/not/a/real/route");
    try std.testing.expect(match == null);
}

test "findRoute wrong method" {
    const match = findRoute(.POST, "/eth/v1/node/identity");
    try std.testing.expect(match == null);
}

test "route count" {
    // Verify we defined all expected routes.
    try std.testing.expectEqual(@as(usize, 64), routes.len);
}
