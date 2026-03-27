//! Beacon API HTTP client for the Validator Client.
//!
//! Wraps HTTP calls to the Beacon Node REST API endpoints consumed by
//! validator clients (duties, block production, attestation, sync committee).
//!
//! TS equivalent: @lodestar/api ApiClient (packages/api/src/client/)
//!
//! Design (Zig 0.16):
//!   - Uses std.http.Client with std.Io for HTTP/1.1 requests.
//!   - All methods are stubs returning error.NotImplemented until wired up.
//!   - SSE stream for events uses a chunked reader over a persistent TCP connection.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const types = @import("types.zig");
const ProposerDuty = types.ProposerDuty;
const AttesterDuty = types.AttesterDuty;
const SyncCommitteeDuty = types.SyncCommitteeDuty;

const log = std.log.scoped(.vc_api);

// ---------------------------------------------------------------------------
// SSE event (raw)
// ---------------------------------------------------------------------------

/// A single Server-Sent Event received from the BN.
pub const SseEvent = struct {
    /// Event type string (e.g., "head", "block", "finalized_checkpoint").
    event_type: []const u8,
    /// Raw JSON data payload.
    data: []const u8,
};

/// Callback type for SSE events.
pub const SseCallback = struct {
    ctx: *anyopaque,
    fn_ptr: *const fn (ctx: *anyopaque, event: SseEvent) void,

    pub fn call(self: SseCallback, event: SseEvent) void {
        self.fn_ptr(self.ctx, event);
    }
};

// ---------------------------------------------------------------------------
// BeaconApiClient
// ---------------------------------------------------------------------------

/// HTTP client for the Beacon Node REST API (validator-facing endpoints).
pub const BeaconApiClient = struct {
    allocator: Allocator,
    /// Base URL of the beacon node (e.g. "http://127.0.0.1:5052").
    base_url: []const u8,

    pub fn init(allocator: Allocator, base_url: []const u8) BeaconApiClient {
        return .{
            .allocator = allocator,
            .base_url = base_url,
        };
    }

    pub fn deinit(self: *BeaconApiClient) void {
        _ = self;
    }

    // -----------------------------------------------------------------------
    // Genesis
    // -----------------------------------------------------------------------

    /// GET /eth/v1/beacon/genesis
    ///
    /// Returns genesis time and validators root.
    /// TS: api.beacon.getGenesis()
    pub fn getGenesis(self: *BeaconApiClient, io: Io) !GenesisResponse {
        _ = self;
        _ = io;
        return error.NotImplemented;
    }

    // -----------------------------------------------------------------------
    // Duties
    // -----------------------------------------------------------------------

    /// GET /eth/v1/validator/duties/proposer/{epoch}
    ///
    /// Returns proposer duties for every slot in the epoch.
    /// TS: api.validator.getProposerDuties({epoch})
    pub fn getProposerDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
    ) ![]ProposerDuty {
        _ = self;
        _ = io;
        _ = epoch;
        return error.NotImplemented;
    }

    /// POST /eth/v1/validator/duties/attester/{epoch}
    ///
    /// Returns attester duties for the given validator indices.
    /// TS: api.validator.getAttesterDuties({epoch, indices})
    pub fn getAttesterDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]AttesterDuty {
        _ = self;
        _ = io;
        _ = epoch;
        _ = indices;
        return error.NotImplemented;
    }

    /// POST /eth/v1/validator/duties/sync/{epoch}
    ///
    /// Returns sync committee duties for the given validator indices.
    /// TS: api.validator.getSyncCommitteeDuties({epoch, indices})
    pub fn getSyncCommitteeDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]SyncCommitteeDuty {
        _ = self;
        _ = io;
        _ = epoch;
        _ = indices;
        return error.NotImplemented;
    }

    // -----------------------------------------------------------------------
    // Validator indices
    // -----------------------------------------------------------------------

    /// POST /eth/v1/beacon/states/head/validators
    ///
    /// Returns validator index + status for a list of pubkeys.
    /// TS: IndicesService uses api.beacon.postStateValidators()
    pub fn getValidatorIndices(
        self: *BeaconApiClient,
        io: Io,
        pubkeys: []const [48]u8,
    ) ![]ValidatorIndexAndStatus {
        _ = self;
        _ = io;
        _ = pubkeys;
        return error.NotImplemented;
    }

    // -----------------------------------------------------------------------
    // Block production
    // -----------------------------------------------------------------------

    /// GET /eth/v3/validator/blocks/{slot}?randao_reveal=...&graffiti=...
    ///
    /// Returns a block to be signed by the proposer.
    /// TS: api.validator.produceBlockV3({slot, randaoReveal, graffiti})
    pub fn produceBlock(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        randao_reveal: [96]u8,
        graffiti: [32]u8,
    ) !ProduceBlockResponse {
        _ = self;
        _ = io;
        _ = slot;
        _ = randao_reveal;
        _ = graffiti;
        return error.NotImplemented;
    }

    /// POST /eth/v1/beacon/blocks (or v2/v3 depending on fork)
    ///
    /// Publishes a signed beacon block.
    /// TS: api.beacon.publishBlockV3({signedBlockOrContents, broadcastValidation})
    pub fn publishBlock(
        self: *BeaconApiClient,
        io: Io,
        /// Raw SSZ-encoded signed block bytes.
        signed_block_ssz: []const u8,
    ) !void {
        _ = self;
        _ = io;
        _ = signed_block_ssz;
        return error.NotImplemented;
    }

    // -----------------------------------------------------------------------
    // Attestation
    // -----------------------------------------------------------------------

    /// GET /eth/v1/validator/attestation_data?slot=...&committee_index=...
    ///
    /// Returns attestation data for signing.
    /// TS: api.validator.produceAttestationData({slot, committeeIndex})
    pub fn produceAttestationData(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        committee_index: u64,
    ) !AttestationDataResponse {
        _ = self;
        _ = io;
        _ = slot;
        _ = committee_index;
        return error.NotImplemented;
    }

    /// POST /eth/v1/beacon/pool/attestations
    ///
    /// Publishes signed attestations.
    /// TS: api.beacon.submitPoolAttestationsV2({signedAttestations})
    pub fn publishAttestations(
        self: *BeaconApiClient,
        io: Io,
        /// Raw JSON or SSZ attestations.
        attestations_ssz: []const u8,
    ) !void {
        _ = self;
        _ = io;
        _ = attestations_ssz;
        return error.NotImplemented;
    }

    /// GET /eth/v1/validator/aggregate_attestation?slot=...&attestation_data_root=...
    ///
    /// Returns an aggregate attestation to be signed and broadcast.
    /// TS: api.validator.getAggregatedAttestation()
    pub fn getAggregatedAttestation(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        attestation_data_root: [32]u8,
    ) !AggregatedAttestationResponse {
        _ = self;
        _ = io;
        _ = slot;
        _ = attestation_data_root;
        return error.NotImplemented;
    }

    /// POST /eth/v1/validator/aggregate_and_proofs
    ///
    /// Publishes signed aggregate and proofs.
    /// TS: api.validator.publishAggregateAndProofsV2()
    pub fn publishAggregateAndProofs(
        self: *BeaconApiClient,
        io: Io,
        proofs_ssz: []const u8,
    ) !void {
        _ = self;
        _ = io;
        _ = proofs_ssz;
        return error.NotImplemented;
    }

    // -----------------------------------------------------------------------
    // Sync committee
    // -----------------------------------------------------------------------

    /// POST /eth/v1/beacon/pool/sync_committees
    ///
    /// Publishes sync committee messages.
    /// TS: api.beacon.submitPoolSyncCommitteeSignatures()
    pub fn publishSyncCommitteeMessages(
        self: *BeaconApiClient,
        io: Io,
        messages_json: []const u8,
    ) !void {
        _ = self;
        _ = io;
        _ = messages_json;
        return error.NotImplemented;
    }

    /// POST /eth/v1/validator/contribution_and_proofs
    ///
    /// Publishes signed sync committee contributions and proofs.
    /// TS: api.validator.publishContributionAndProofs()
    pub fn publishContributionAndProofs(
        self: *BeaconApiClient,
        io: Io,
        contributions_json: []const u8,
    ) !void {
        _ = self;
        _ = io;
        _ = contributions_json;
        return error.NotImplemented;
    }

    /// GET /eth/v1/validator/sync_committee_contribution?slot=...&subcommittee_index=...&beacon_block_root=...
    ///
    /// Returns a sync committee contribution to be signed.
    /// TS: api.validator.produceSyncCommitteeContribution()
    pub fn produceSyncCommitteeContribution(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: [32]u8,
    ) !SyncCommitteeContributionResponse {
        _ = self;
        _ = io;
        _ = slot;
        _ = subcommittee_index;
        _ = beacon_block_root;
        return error.NotImplemented;
    }

    // -----------------------------------------------------------------------
    // Proposer preparation
    // -----------------------------------------------------------------------

    /// POST /eth/v1/validator/prepare_beacon_proposer
    ///
    /// Registers fee recipients with the beacon node.
    /// TS: pollPrepareBeaconProposer()
    pub fn prepareBeaconProposer(
        self: *BeaconApiClient,
        io: Io,
        registrations_json: []const u8,
    ) !void {
        _ = self;
        _ = io;
        _ = registrations_json;
        return error.NotImplemented;
    }

    // -----------------------------------------------------------------------
    // SSE event stream
    // -----------------------------------------------------------------------

    /// GET /eth/v1/events?topics=head,block,...
    ///
    /// Subscribes to beacon node SSE events and calls `callback` for each.
    /// Runs until error or cancellation.
    ///
    /// TS: api.events.eventstream({topics, onEvent, onError, onClose})
    pub fn subscribeToEvents(
        self: *BeaconApiClient,
        io: Io,
        topics: []const []const u8,
        callback: SseCallback,
    ) !void {
        _ = self;
        _ = io;
        _ = topics;
        _ = callback;
        return error.NotImplemented;
    }

    // -----------------------------------------------------------------------
    // Liveness (doppelganger)
    // -----------------------------------------------------------------------

    /// POST /eth/v1/validator/liveness/{epoch}
    ///
    /// Returns liveness data for the given validator indices.
    /// TS: api.validator.getLiveness()
    pub fn getLiveness(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]ValidatorLiveness {
        _ = self;
        _ = io;
        _ = epoch;
        _ = indices;
        return error.NotImplemented;
    }
};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

pub const GenesisResponse = struct {
    genesis_time: u64,
    genesis_validators_root: [32]u8,
    genesis_fork_version: [4]u8,
};

pub const ValidatorIndexAndStatus = struct {
    pubkey: [48]u8,
    index: u64,
    status: []const u8,
};

pub const ProduceBlockResponse = struct {
    /// Raw SSZ bytes of the unsigned block (caller must free).
    block_ssz: []const u8,
    /// Whether the block is blinded (MEV relay path).
    blinded: bool,
};

pub const AttestationDataResponse = struct {
    slot: u64,
    index: u64,
    beacon_block_root: [32]u8,
    source_epoch: u64,
    source_root: [32]u8,
    target_epoch: u64,
    target_root: [32]u8,
};

pub const AggregatedAttestationResponse = struct {
    /// Raw SSZ bytes of the aggregate attestation.
    attestation_ssz: []const u8,
};

pub const SyncCommitteeContributionResponse = struct {
    slot: u64,
    beacon_block_root: [32]u8,
    subcommittee_index: u64,
    /// Aggregation bits (bitmask of sync committee members included).
    aggregation_bits: []const u8,
    /// Aggregate BLS signature.
    signature: [96]u8,
};

pub const ValidatorLiveness = struct {
    index: u64,
    /// True if the validator was seen active in the epoch.
    is_live: bool,
};
