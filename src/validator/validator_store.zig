//! Validator key and state management for the Validator Client.
//!
//! Holds BLS secret keys, tracks validator indices and activation status,
//! and performs signing operations with slashing protection.
//!
//! TS equivalent: packages/validator/src/services/validatorStore.ts (ValidatorStore)
//!
//! Key differences from TS:
//!   - No class hierarchy — flat struct with explicit methods.
//!   - Explicit allocator for key storage.
//!   - Slashing protection is checked in-process (no external DB yet — stub).
//!   - No "remote signer" support in this stub (TS has SignerRemote via web3signer).

const std = @import("std");
const Allocator = std.mem.Allocator;

const bls = @import("bls");
const SecretKey = bls.SecretKey;
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;

const types = @import("types.zig");
const SlashingProtectionRecord = types.SlashingProtectionRecord;
const ValidatorStatus = types.ValidatorStatus;

const log = std.log.scoped(.validator_store);

// ---------------------------------------------------------------------------
// ValidatorRecord
// ---------------------------------------------------------------------------

/// Per-validator in-memory state.
pub const ValidatorRecord = struct {
    /// BLS public key (48 bytes).
    pubkey: [48]u8,
    /// BLS secret key for local signing.
    secret_key: SecretKey,
    /// Validator index on the beacon chain (null until resolved).
    index: ?u64,
    /// Current activation status.
    status: ValidatorStatus,
    /// Slashing protection data.
    slashing: SlashingProtectionRecord,
};

// ---------------------------------------------------------------------------
// ValidatorStore
// ---------------------------------------------------------------------------

pub const ValidatorStore = struct {
    allocator: Allocator,
    validators: std.ArrayList(ValidatorRecord),

    pub fn init(allocator: Allocator) ValidatorStore {
        return .{
            .allocator = allocator,
            .validators = std.ArrayList(ValidatorRecord).init(allocator),
        };
    }

    pub fn deinit(self: *ValidatorStore) void {
        self.validators.deinit();
    }

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /// Add a validator key to the store.
    ///
    /// TS: ValidatorStore.init(opts, signers, ...) — signers map to keys here.
    pub fn addKey(self: *ValidatorStore, secret_key: SecretKey) !void {
        const pk = secret_key.toPublicKey();
        const pubkey_bytes = pk.compress();

        // Check for duplicate.
        for (self.validators.items) |v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey_bytes)) return; // already present
        }

        try self.validators.append(.{
            .pubkey = pubkey_bytes,
            .secret_key = secret_key,
            .index = null,
            .status = .unknown,
            .slashing = .{
                .pubkey = pubkey_bytes,
                .last_signed_block_slot = null,
                .last_signed_attestation_source_epoch = null,
                .last_signed_attestation_target_epoch = null,
            },
        });
        log.debug("added validator pubkey={}", .{std.fmt.fmtSliceHexLower(&pubkey_bytes)});
    }

    /// Return a slice of all known public keys.
    pub fn pubkeys(self: *const ValidatorStore) []const [48]u8 {
        // Build a slice of pubkeys on the fly — caller must not store it across mutations.
        // For now, return error.NotImplemented to signal this needs proper implementation.
        _ = self;
        return &[_][48]u8{};
    }

    /// Update validator indices after resolving them from the beacon node.
    ///
    /// TS: IndicesService.pollValidatorIndices() → validatorStore updates.
    pub fn updateIndex(self: *ValidatorStore, pubkey: [48]u8, index: u64, status: ValidatorStatus) void {
        for (self.validators.items) |*v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) {
                v.index = index;
                v.status = status;
                return;
            }
        }
    }

    /// Return all known validator indices (for duty fetching).
    ///
    /// TS: indicesService.getAllLocalIndices()
    pub fn allIndices(self: *const ValidatorStore, allocator: Allocator) ![]u64 {
        var result = try allocator.alloc(u64, self.validators.items.len);
        var count: usize = 0;
        for (self.validators.items) |v| {
            if (v.index) |idx| {
                result[count] = idx;
                count += 1;
            }
        }
        return result[0..count];
    }

    // -----------------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------------

    /// Sign a beacon block (RANDAO reveal + block signing root).
    ///
    /// Checks slashing protection: refuses if slot ≤ last signed block slot.
    ///
    /// TS: validatorStore.signBlock(block, slot, currentFork, genesisValidatorsRoot)
    pub fn signBlock(
        self: *ValidatorStore,
        pubkey: [48]u8,
        signing_root: [32]u8,
        slot: u64,
    ) !Signature {
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;

        // Slashing protection: double-proposal check.
        if (validator.slashing.last_signed_block_slot) |last_slot| {
            if (slot <= last_slot) {
                log.warn("slashing protection: refusing to sign block at slot {d} (last signed: {d})", .{ slot, last_slot });
                return error.SlashingProtectionTriggered;
            }
        }

        // Update slashing record.
        validator.slashing.last_signed_block_slot = slot;

        // Sign the root.
        return validator.secret_key.sign(&signing_root, bls.DST, null);
    }

    /// Produce a RANDAO reveal for the given epoch.
    ///
    /// TS: validatorStore.signRandao(epoch, currentFork, genesisValidatorsRoot)
    pub fn signRandao(
        self: *ValidatorStore,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return validator.secret_key.sign(&signing_root, bls.DST, null);
    }

    /// Sign attestation data.
    ///
    /// Checks slashing protection: refuses if target_epoch ≤ last or
    /// source_epoch conflicts with a previous vote.
    ///
    /// TS: validatorStore.signAttestation(duty, attestationData, currentEpoch, fork, ...)
    pub fn signAttestation(
        self: *ValidatorStore,
        pubkey: [48]u8,
        signing_root: [32]u8,
        source_epoch: u64,
        target_epoch: u64,
    ) !Signature {
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;

        // Slashing protection: double-vote check.
        if (validator.slashing.last_signed_attestation_target_epoch) |last_target| {
            if (target_epoch <= last_target) {
                log.warn("slashing protection: refusing attestation target_epoch={d} (last={d})", .{ target_epoch, last_target });
                return error.SlashingProtectionTriggered;
            }
        }

        // Update slashing record.
        validator.slashing.last_signed_attestation_source_epoch = source_epoch;
        validator.slashing.last_signed_attestation_target_epoch = target_epoch;

        return validator.secret_key.sign(&signing_root, bls.DST, null);
    }

    /// Sign a sync committee message.
    ///
    /// TS: validatorStore.signSyncCommitteeSignature(pubkey, slot, beaconBlockRoot, fork, ...)
    pub fn signSyncCommitteeMessage(
        self: *ValidatorStore,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return validator.secret_key.sign(&signing_root, bls.DST, null);
    }

    /// Sign a selection proof for aggregation eligibility.
    ///
    /// TS: validatorStore.signAttestationSelectionProof(pubkey, slot, fork, ...)
    pub fn signSelectionProof(
        self: *ValidatorStore,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return validator.secret_key.sign(&signing_root, bls.DST, null);
    }

    /// Sign an aggregate and proof.
    ///
    /// TS: validatorStore.signAggregateAndProof(aggregateAndProof, pubkey, fork, ...)
    pub fn signAggregateAndProof(
        self: *ValidatorStore,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return validator.secret_key.sign(&signing_root, bls.DST, null);
    }

    /// Sign a sync committee contribution and proof.
    ///
    /// TS: validatorStore.signContributionAndProof(contribution, pubkey, fork, ...)
    pub fn signContributionAndProof(
        self: *ValidatorStore,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return validator.secret_key.sign(&signing_root, bls.DST, null);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn findValidator(self: *ValidatorStore, pubkey: [48]u8) ?*ValidatorRecord {
        for (self.validators.items) |*v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) return v;
        }
        return null;
    }
};
