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
//!   - Slashing protection is checked in-process via SQLite-backed SlashingProtectionDb.
//!   - Remote signer support is provided via Web3Signer HTTP client (remote_signer.zig).
//!     Signing root computation stays in the VC; only the BLS sign call goes to the signer.

const std = @import("std");
const Allocator = std.mem.Allocator;

const bls = @import("bls");
const SecretKey = bls.SecretKey;
const PublicKey = bls.PublicKey;
const Signature = bls.Signature;

const types = @import("types.zig");
const EffectiveProposerConfig = types.EffectiveProposerConfig;
const ProposerConfig = types.ProposerConfig;
const ProposerConfigEntry = types.ProposerConfigEntry;
const SlashingProtectionRecord = types.SlashingProtectionRecord;
const ValidatorStatus = types.ValidatorStatus;

const SlashingProtectionDb = @import("slashing_protection_db.zig").SlashingProtectionDb;

const remote_signer_mod = @import("remote_signer.zig");
const RemoteSigner = remote_signer_mod.RemoteSigner;
const SigningType = remote_signer_mod.SigningType;

const Io = std.Io;
const mutex_mod = @import("mutex.zig");

const log = std.log.scoped(.validator_store);

// ---------------------------------------------------------------------------
// ValidatorRecord
// ---------------------------------------------------------------------------

pub const ValidatorSigner = union(enum) {
    local: SecretKey,
    remote: *RemoteSigner,
};

pub const SignerKind = enum {
    local,
    remote,
};

/// Per-validator in-memory state.
pub const ValidatorRecord = struct {
    /// BLS public key (48 bytes).
    pubkey: [48]u8,
    /// Signing source for this validator.
    signer: ValidatorSigner,
    /// Validator index on the beacon chain (null until resolved).
    index: ?u64,
    /// Current activation status.
    status: ValidatorStatus,
    /// Slashing protection data.
    slashing: SlashingProtectionRecord,

    pub fn isRemote(self: *const ValidatorRecord) bool {
        return switch (self.signer) {
            .remote => true,
            .local => false,
        };
    }
};

// ---------------------------------------------------------------------------
// ValidatorStore
// ---------------------------------------------------------------------------

pub const ValidatorStore = struct {
    pub const ValidatorCounts = struct {
        total: usize,
        local: usize,
        remote: usize,
    };

    allocator: Allocator,
    validators: std.array_list.Managed(ValidatorRecord),
    /// Cached pubkey slice kept in sync with validators for non-allocating pubkeys() access.
    pubkeys_cache: std.array_list.Managed([48]u8),
    /// Persistent slashing protection database.
    slashing_db: SlashingProtectionDb,
    /// Default proposer settings applied to every validator unless overridden.
    default_proposer_config: EffectiveProposerConfig,
    /// Per-validator proposer config overrides keyed by pubkey.
    proposer_overrides: std.AutoHashMapUnmanaged([48]u8, ProposerConfig),
    /// Mutex protecting validators list for concurrent add/remove.
    mutex: mutex_mod.Mutex,
    /// Initialize the ValidatorStore with an optional persistent slashing protection DB.
    ///
    /// Pass db_path = null for in-memory-only mode (tests, no persistence).
    pub fn init(
        io: Io,
        allocator: Allocator,
        db_path: ?[]const u8,
        default_proposer_config: EffectiveProposerConfig,
        proposer_configs: []const ProposerConfigEntry,
    ) !ValidatorStore {
        const slashing_db = try SlashingProtectionDb.init(io, allocator, db_path);
        var store = ValidatorStore{
            .allocator = allocator,
            .validators = std.array_list.Managed(ValidatorRecord).init(allocator),
            .pubkeys_cache = std.array_list.Managed([48]u8).init(allocator),
            .slashing_db = slashing_db,
            .default_proposer_config = default_proposer_config,
            .proposer_overrides = .empty,
            .mutex = .{},
        };
        errdefer store.proposer_overrides.deinit(allocator);

        for (proposer_configs) |entry| {
            try store.proposer_overrides.put(allocator, entry.pubkey, entry.config);
        }

        return store;
    }

    pub fn deinit(self: *ValidatorStore) void {
        // Zero all BLS secret keys before freeing the list.
        for (self.validators.items) |*v| {
            self.clearSigner(v);
        }
        self.validators.deinit();
        self.pubkeys_cache.deinit();
        self.proposer_overrides.deinit(self.allocator);
        self.slashing_db.close();
    }

    pub fn counts(self: *ValidatorStore) ValidatorCounts {
        self.mutex.lock();
        defer self.mutex.unlock();

        var remote: usize = 0;
        for (self.validators.items) |v| {
            if (v.isRemote()) remote += 1;
        }

        return .{
            .total = self.validators.items.len,
            .local = self.validators.items.len - remote,
            .remote = remote,
        };
    }

    pub fn getFeeRecipient(self: *ValidatorStore, pubkey: [48]u8) [20]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.effectiveProposerConfigLocked(pubkey).fee_recipient;
    }

    pub fn getFeeRecipientByIndex(self: *ValidatorStore, index: u64) [20]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.validators.items) |validator| {
            if (validator.index != index) continue;
            return self.effectiveProposerConfigLocked(validator.pubkey).fee_recipient;
        }
        return self.default_proposer_config.fee_recipient;
    }

    pub fn getGraffiti(self: *ValidatorStore, pubkey: [48]u8) [32]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.effectiveProposerConfigLocked(pubkey).graffiti;
    }

    pub fn getGasLimit(self: *ValidatorStore, pubkey: [48]u8) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.effectiveProposerConfigLocked(pubkey).gas_limit;
    }

    pub fn getBuilderBoostFactor(self: *ValidatorStore, pubkey: [48]u8) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.effectiveProposerConfigLocked(pubkey).builder_boost_factor;
    }

    pub fn strictFeeRecipientCheck(self: *ValidatorStore, pubkey: [48]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.effectiveProposerConfigLocked(pubkey).strict_fee_recipient_check;
    }

    pub fn getProposerConfig(self: *ValidatorStore, pubkey: [48]u8) ?ProposerConfig {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.proposer_overrides.get(pubkey);
    }

    pub fn setProposerConfigOverride(
        self: *ValidatorStore,
        pubkey: [48]u8,
        config: ?ProposerConfig,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.putProposerConfigLocked(pubkey, config orelse ProposerConfig{});
    }

    pub fn setFeeRecipient(self: *ValidatorStore, pubkey: [48]u8, fee_recipient: [20]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var config = self.proposer_overrides.get(pubkey) orelse ProposerConfig{};
        config.fee_recipient = fee_recipient;
        try self.putProposerConfigLocked(pubkey, config);
    }

    pub fn deleteFeeRecipient(self: *ValidatorStore, pubkey: [48]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var config = self.proposer_overrides.get(pubkey) orelse return;
        config.fee_recipient = null;
        try self.putProposerConfigLocked(pubkey, config);
    }

    pub fn setGraffiti(self: *ValidatorStore, pubkey: [48]u8, graffiti: [32]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var config = self.proposer_overrides.get(pubkey) orelse ProposerConfig{};
        config.graffiti = graffiti;
        try self.putProposerConfigLocked(pubkey, config);
    }

    pub fn deleteGraffiti(self: *ValidatorStore, pubkey: [48]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var config = self.proposer_overrides.get(pubkey) orelse return;
        config.graffiti = null;
        try self.putProposerConfigLocked(pubkey, config);
    }

    pub fn setGasLimit(self: *ValidatorStore, pubkey: [48]u8, gas_limit: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var config = self.proposer_overrides.get(pubkey) orelse ProposerConfig{};
        config.gas_limit = gas_limit;
        try self.putProposerConfigLocked(pubkey, config);
    }

    pub fn deleteGasLimit(self: *ValidatorStore, pubkey: [48]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var config = self.proposer_overrides.get(pubkey) orelse return;
        config.gas_limit = null;
        try self.putProposerConfigLocked(pubkey, config);
    }

    pub fn setBuilderBoostFactor(self: *ValidatorStore, pubkey: [48]u8, builder_boost_factor: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var config = self.proposer_overrides.get(pubkey) orelse ProposerConfig{};
        config.builder_boost_factor = builder_boost_factor;
        try self.putProposerConfigLocked(pubkey, config);
    }

    pub fn deleteBuilderBoostFactor(self: *ValidatorStore, pubkey: [48]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var config = self.proposer_overrides.get(pubkey) orelse return;
        config.builder_boost_factor = null;
        try self.putProposerConfigLocked(pubkey, config);
    }

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /// Add a validator key to the store (thread-safe).
    ///
    /// No-op if the key is already present.
    /// TS: ValidatorStore.init(opts, signers, ...) — signers map to keys here.
    pub fn addKey(self: *ValidatorStore, secret_key: SecretKey) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.addKeyLocked(secret_key);
    }

    /// Add a validator key (caller must hold mutex).
    fn addKeyLocked(self: *ValidatorStore, secret_key: SecretKey) !void {
        const pk = secret_key.toPublicKey();
        const pubkey_bytes = pk.compress();

        // Check for duplicate.
        for (self.validators.items) |v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey_bytes)) return; // already present
        }

        try self.validators.append(.{
            .pubkey = pubkey_bytes,
            .signer = .{ .local = secret_key },
            .index = null,
            .status = .unknown,
            .slashing = .{
                .pubkey = pubkey_bytes,
                .last_signed_block_slot = null,
                .last_signed_attestation_source_epoch = null,
                .last_signed_attestation_target_epoch = null,
            },
        });
        // Keep pubkeys_cache in sync for non-allocating pubkeys() access.
        try self.pubkeys_cache.append(pubkey_bytes);
        log.debug("added validator pubkey={x}", .{pubkey_bytes});
    }

    /// Add a validator at runtime (alias for addKey; thread-safe).
    ///
    /// Used by the Keymanager API POST /eth/v1/keystores.
    pub fn addValidator(self: *ValidatorStore, secret_key: SecretKey) !void {
        return self.addKey(secret_key);
    }

    /// Register a remote signer pubkey without a local secret key (thread-safe).
    ///
    /// The validator will be tracked for duties but signing is delegated to RemoteSigner.
    /// Calling signXxx() for a remote key will return error.RemoteSignerRequired.
    ///
    /// TS: ValidatorStore init with `ExternalSignerSigner` entries — pubkey tracked but
    ///     signing goes through the external signer HTTP client.
    pub fn addRemotePubkey(self: *ValidatorStore, pubkey: [48]u8, signer: *RemoteSigner) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check for duplicate (remote or local).
        for (self.validators.items) |v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) return; // already present
        }

        try self.validators.append(.{
            .pubkey = pubkey,
            .signer = .{ .remote = signer },
            .index = null,
            .status = .unknown,
            .slashing = .{
                .pubkey = pubkey,
                .last_signed_block_slot = null,
                .last_signed_attestation_source_epoch = null,
                .last_signed_attestation_target_epoch = null,
            },
        });
        try self.pubkeys_cache.append(pubkey);
        log.info("registered remote validator pubkey={x}", .{pubkey});
    }

    /// Return true if the given pubkey belongs to a remote signer.
    pub fn isRemote(self: *ValidatorStore, pubkey: [48]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.validators.items) |v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) return v.isRemote();
        }
        return false;
    }

    pub fn signerKind(self: *ValidatorStore, pubkey: [48]u8) ?SignerKind {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.validators.items) |v| {
            if (!std.mem.eql(u8, &v.pubkey, &pubkey)) continue;
            return switch (v.signer) {
                .local => .local,
                .remote => .remote,
            };
        }
        return null;
    }

    /// Remove a validator key at runtime (thread-safe).
    ///
    /// Returns true if the key was found and removed; false if not found.
    /// Used by the Keymanager API DELETE /eth/v1/keystores.
    ///
    /// TS: ValidatorStore.deleteKeystore(pubkey)
    pub fn removeValidator(self: *ValidatorStore, pubkey: [48]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.validators.items, 0..) |v, i| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) {
                // Zero secret key memory before removing the entry.
                self.clearSigner(&self.validators.items[i]);
                _ = self.validators.swapRemove(i);
                // Keep pubkeys_cache in sync.
                _ = self.pubkeys_cache.swapRemove(i);
                log.info("removed validator pubkey={x}", .{pubkey});
                return true;
            }
        }
        return false;
    }

    /// Validator metadata for listing.
    pub const ValidatorInfo = struct {
        /// Compressed BLS public key.
        pubkey: [48]u8,
        /// HD derivation path (empty for imported keystores).
        derivation_path: []const u8,
        /// Whether the key is read-only (remote signer or imported without secret).
        readonly: bool,
    };

    /// List local validators with metadata (thread-safe).
    ///
    /// Returns a caller-owned slice. Caller must free.
    /// Used by the Keymanager API GET /eth/v1/keystores.
    ///
    /// TS: ValidatorStore.getLocalKeystoreInfo()
    pub fn listLocalValidators(self: *ValidatorStore, allocator: Allocator) ![]ValidatorInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.validators.items) |v| {
            if (!v.isRemote()) count += 1;
        }

        const result = try allocator.alloc(ValidatorInfo, count);
        var out_idx: usize = 0;
        for (self.validators.items) |v| {
            if (v.isRemote()) continue;
            const out = &result[out_idx];
            out.* = .{
                .pubkey = v.pubkey,
                .derivation_path = "",
                .readonly = false,
            };
            out_idx += 1;
        }
        return result;
    }

    pub const RemoteValidatorInfo = struct {
        pubkey: [48]u8,
        url: []const u8,
        readonly: bool,
    };

    pub fn listRemoteValidators(self: *ValidatorStore, allocator: Allocator) ![]RemoteValidatorInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.validators.items) |v| {
            if (v.isRemote()) count += 1;
        }

        const result = try allocator.alloc(RemoteValidatorInfo, count);
        var out_idx: usize = 0;
        for (self.validators.items) |v| {
            const remote_signer = switch (v.signer) {
                .remote => |signer| signer,
                .local => continue,
            };
            result[out_idx] = .{
                .pubkey = v.pubkey,
                .url = remote_signer.base_url,
                .readonly = false,
            };
            out_idx += 1;
        }
        return result;
    }

    /// Return all remote validator pubkeys for one signer as an owned slice.
    pub fn allRemotePubkeysForSigner(
        self: *const ValidatorStore,
        allocator: Allocator,
        signer: *const RemoteSigner,
    ) ![][48]u8 {
        const mutex_ptr: *mutex_mod.Mutex = @constCast(&self.mutex);
        mutex_ptr.lock();
        defer mutex_ptr.unlock();

        var count: usize = 0;
        for (self.validators.items) |v| {
            switch (v.signer) {
                .remote => |candidate| {
                    if (candidate == signer) count += 1;
                },
                .local => {},
            }
        }

        const result = try allocator.alloc([48]u8, count);
        var out_idx: usize = 0;
        for (self.validators.items) |v| {
            switch (v.signer) {
                .remote => |candidate| {
                    if (candidate != signer) continue;
                    result[out_idx] = v.pubkey;
                    out_idx += 1;
                },
                .local => {},
            }
        }
        return result;
    }

    /// Return a non-owning slice of all validator public keys.
    ///
    /// STUB Fix: Returns the actual loaded pubkeys from pubkeys_cache, which is kept
    /// in sync with the validators list by addKeyLocked() and removeValidator().
    ///
    /// Safety: The returned slice is valid only while no concurrent writes occur.
    /// For multi-threaded access, use allPubkeys() which returns an owned copy.
    ///
    /// TS: ValidatorStore.hasVote() / all pubkey iteration patterns.
    pub fn pubkeys(self: *const ValidatorStore) []const [48]u8 {
        return self.pubkeys_cache.items;
    }

    /// Return all known public keys as an owned slice (caller must free).
    pub fn allPubkeys(self: *const ValidatorStore, allocator: Allocator) ![][48]u8 {
        const mutex_ptr: *mutex_mod.Mutex = @constCast(&self.mutex);
        mutex_ptr.lock();
        defer mutex_ptr.unlock();

        const result = try allocator.alloc([48]u8, self.validators.items.len);
        for (self.validators.items, result) |v, *out| {
            out.* = v.pubkey;
        }
        return result;
    }

    /// Return all remote-only validator pubkeys as an owned slice (caller must free).
    pub fn allRemotePubkeys(self: *const ValidatorStore, allocator: Allocator) ![][48]u8 {
        const mutex_ptr: *mutex_mod.Mutex = @constCast(&self.mutex);
        mutex_ptr.lock();
        defer mutex_ptr.unlock();

        var count: usize = 0;
        for (self.validators.items) |v| {
            if (v.isRemote()) count += 1;
        }

        const result = try allocator.alloc([48]u8, count);
        var out_idx: usize = 0;
        for (self.validators.items) |v| {
            if (v.isRemote()) {
                result[out_idx] = v.pubkey;
                out_idx += 1;
            }
        }
        return result;
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
        // Lock mutex for thread-safe access. Cast away const — mutex is logically
        // interior-mutable and doesn't change observable ValidatorStore state.
        const mutex_ptr: *mutex_mod.Mutex = @constCast(&self.mutex);
        mutex_ptr.lock();
        defer mutex_ptr.unlock();

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
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
        slot: u64,
    ) !Signature {
        // Hold mutex for the entire check-and-sign sequence to prevent TOCTOU races
        // between the slashing protection check and the actual signing operation.
        self.mutex.lock();
        defer self.mutex.unlock();

        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;

        // Slashing protection FIRST: applies to both local and remote validators.
        // Remote signers must not be allowed to bypass the slashing DB.
        const block_allowed = try self.slashing_db.checkAndInsertBlock(pubkey, slot);
        if (!block_allowed) {
            log.warn("slashing protection: refusing to sign block at slot {d}", .{slot});
            return error.SlashingProtectionTriggered;
        }

        // Also update the in-memory SlashingProtectionRecord for quick reference.
        validator.slashing.last_signed_block_slot = slot;

        return self.signWithValidator(io, validator, pubkey, signing_root, .BLOCK_V2);
    }

    /// Produce a RANDAO reveal for the given epoch.
    ///
    /// TS: validatorStore.signRandao(epoch, currentFork, genesisValidatorsRoot)
    pub fn signRandao(
        self: *ValidatorStore,
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        self.mutex.lock();
        defer self.mutex.unlock();
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return self.signWithValidator(io, validator, pubkey, signing_root, .RANDAO_REVEAL);
    }

    /// Sign attestation data.
    ///
    /// Checks slashing protection:
    ///   - Double vote: refuses if target_epoch <= last_signed_target_epoch.
    ///   - Surround vote: refuses if source_epoch < last_signed_source_epoch
    ///     (new attestation's source would go backwards, allowing a surround).
    ///
    /// Using (monotonically increasing source, strictly increasing target) is the
    /// conservative protection mandated by EIP-3076 and sufficient to prevent all
    /// slashable attestation pairs.
    ///
    /// TS: validatorStore.signAttestation(duty, attestationData, currentEpoch, fork, ...)
    pub fn signAttestation(
        self: *ValidatorStore,
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
        source_epoch: u64,
        target_epoch: u64,
    ) !Signature {
        // Hold mutex for the entire check-and-sign sequence to prevent TOCTOU races
        // between the slashing protection check and the actual signing operation.
        self.mutex.lock();
        defer self.mutex.unlock();

        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;

        // Slashing protection FIRST: applies to both local and remote validators.
        // Remote signers must not be allowed to bypass the slashing DB.
        const attest_allowed = try self.slashing_db.checkAndInsertAttestation(pubkey, source_epoch, target_epoch);
        if (!attest_allowed) {
            log.warn("slashing protection: refusing attestation source={d} target={d}", .{ source_epoch, target_epoch });
            return error.SlashingProtectionTriggered;
        }

        // Also update the in-memory SlashingProtectionRecord for quick reference.
        validator.slashing.last_signed_attestation_source_epoch = source_epoch;
        validator.slashing.last_signed_attestation_target_epoch = target_epoch;

        return self.signWithValidator(io, validator, pubkey, signing_root, .ATTESTATION);
    }

    /// Sign a sync committee message.
    ///
    /// TS: validatorStore.signSyncCommitteeSignature(pubkey, slot, beaconBlockRoot, fork, ...)
    pub fn signSyncCommitteeMessage(
        self: *ValidatorStore,
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        self.mutex.lock();
        defer self.mutex.unlock();
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return self.signWithValidator(io, validator, pubkey, signing_root, .SYNC_COMMITTEE_MESSAGE);
    }

    /// Sign a selection proof for aggregation eligibility.
    ///
    /// `signing_type` distinguishes attestation aggregation (`.AGGREGATION_SLOT`)
    /// from sync committee aggregation (`.SYNC_COMMITTEE_SELECTION_PROOF`) so the
    /// remote signer receives the correct Web3Signer type.
    ///
    /// TS: validatorStore.signAttestationSelectionProof / signSyncCommitteeSelectionProof
    pub fn signSelectionProof(
        self: *ValidatorStore,
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
        signing_type: SigningType,
    ) !Signature {
        self.mutex.lock();
        defer self.mutex.unlock();
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return self.signWithValidator(io, validator, pubkey, signing_root, signing_type);
    }

    /// Sign an aggregate and proof.
    ///
    /// TS: validatorStore.signAggregateAndProof(aggregateAndProof, pubkey, fork, ...)
    pub fn signAggregateAndProof(
        self: *ValidatorStore,
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        self.mutex.lock();
        defer self.mutex.unlock();
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return self.signWithValidator(io, validator, pubkey, signing_root, .AGGREGATE_AND_PROOF);
    }

    /// Sign a sync committee contribution and proof.
    ///
    /// TS: validatorStore.signContributionAndProof(contribution, pubkey, fork, ...)
    pub fn signContributionAndProof(
        self: *ValidatorStore,
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        self.mutex.lock();
        defer self.mutex.unlock();
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return self.signWithValidator(io, validator, pubkey, signing_root, .SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF);
    }

    /// Get the on-chain validator index for a given pubkey, or null if not yet resolved.
    pub fn getValidatorIndex(self: *ValidatorStore, pubkey: [48]u8) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const validator = self.findValidator(pubkey) orelse return null;
        return validator.index;
    }

    /// Sign a voluntary exit message.
    ///
    /// The signing root must be pre-computed by the caller using
    /// `signing.voluntaryExitSigningRoot()`. This method only performs
    /// the BLS signing with slashing protection not applicable (exits
    /// are not slashable, only the epoch is checked for domain correctness).
    ///
    /// TS: validatorStore.signVoluntaryExit(pubkey, signingRoot)
    pub fn signVoluntaryExit(
        self: *ValidatorStore,
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        self.mutex.lock();
        defer self.mutex.unlock();
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return self.signWithValidator(io, validator, pubkey, signing_root, .VOLUNTARY_EXIT);
    }

    pub fn signBuilderRegistration(
        self: *ValidatorStore,
        io: Io,
        pubkey: [48]u8,
        signing_root: [32]u8,
    ) !Signature {
        self.mutex.lock();
        defer self.mutex.unlock();
        const validator = self.findValidator(pubkey) orelse return error.ValidatorNotFound;
        return self.signWithValidator(io, validator, pubkey, signing_root, .VALIDATOR_REGISTRATION);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn effectiveProposerConfigLocked(
        self: *const ValidatorStore,
        pubkey: [48]u8,
    ) EffectiveProposerConfig {
        const override = self.proposer_overrides.get(pubkey);
        return .{
            .fee_recipient = if (override) |config|
                config.fee_recipient orelse self.default_proposer_config.fee_recipient
            else
                self.default_proposer_config.fee_recipient,
            .graffiti = if (override) |config|
                config.graffiti orelse self.default_proposer_config.graffiti
            else
                self.default_proposer_config.graffiti,
            .gas_limit = if (override) |config|
                config.gas_limit orelse self.default_proposer_config.gas_limit
            else
                self.default_proposer_config.gas_limit,
            .builder_boost_factor = if (override) |config|
                config.builder_boost_factor orelse self.default_proposer_config.builder_boost_factor
            else
                self.default_proposer_config.builder_boost_factor,
            .strict_fee_recipient_check = if (override) |config|
                config.strict_fee_recipient_check orelse self.default_proposer_config.strict_fee_recipient_check
            else
                self.default_proposer_config.strict_fee_recipient_check,
        };
    }

    fn putProposerConfigLocked(
        self: *ValidatorStore,
        pubkey: [48]u8,
        config: ProposerConfig,
    ) !void {
        if (configIsEmpty(config)) {
            _ = self.proposer_overrides.remove(pubkey);
            return;
        }
        try self.proposer_overrides.put(self.allocator, pubkey, config);
    }

    fn configIsEmpty(config: ProposerConfig) bool {
        return config.fee_recipient == null and
            config.graffiti == null and
            config.gas_limit == null and
            config.builder_boost_factor == null and
            config.strict_fee_recipient_check == null;
    }

    fn findValidator(self: *ValidatorStore, pubkey: [48]u8) ?*ValidatorRecord {
        for (self.validators.items) |*v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) return v;
        }
        return null;
    }

    fn clearSigner(self: *ValidatorStore, validator: *ValidatorRecord) void {
        _ = self;
        switch (validator.signer) {
            .local => |*secret_key| std.crypto.secureZero(u8, &secret_key.value.b),
            .remote => {},
        }
    }

    fn signWithValidator(
        self: *ValidatorStore,
        io: Io,
        validator: *const ValidatorRecord,
        pubkey: [48]u8,
        signing_root: [32]u8,
        signing_type: SigningType,
    ) !Signature {
        _ = self;
        return switch (validator.signer) {
            .local => |secret_key| secret_key.sign(&signing_root, bls.DST, null),
            .remote => |remote_signer| blk: {
                break :blk remote_signer.sign(io, pubkey, signing_root, signing_type) catch |err| {
                    log.warn(
                        "remote signer url={s} type={s} error={s}",
                        .{ remote_signer.base_url, signing_type.asStr(), @errorName(err) },
                    );
                    return err;
                };
            },
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn makeDummyKey() SecretKey {
    // Generate a deterministic test key from a fixed scalar.
    var scalar: [32]u8 = [_]u8{0} ** 32;
    scalar[31] = 1; // minimal non-zero scalar
    return SecretKey.deserialize(&scalar) catch unreachable;
}

fn initTestStore() !ValidatorStore {
    return ValidatorStore.init(testing.io, testing.allocator, null, .{
        .fee_recipient = [_]u8{0} ** 20,
        .graffiti = [_]u8{0} ** 32,
        .gas_limit = 60_000_000,
        .builder_boost_factor = 100,
        .strict_fee_recipient_check = false,
    }, &.{});
}

test "ValidatorStore: addKey and allIndices" {
    var store = try initTestStore();
    defer store.deinit();

    const sk = makeDummyKey();
    try store.addKey(sk);
    try testing.expectEqual(@as(usize, 1), store.validators.items.len);

    // No index assigned yet.
    const indices = try store.allIndices(testing.allocator);
    defer testing.allocator.free(indices);
    try testing.expectEqual(@as(usize, 0), indices.len);

    // Assign an index.
    const pk = sk.toPublicKey();
    store.updateIndex(pk.compress(), 42, .active_ongoing);

    const indices2 = try store.allIndices(testing.allocator);
    defer testing.allocator.free(indices2);
    try testing.expectEqual(@as(usize, 1), indices2.len);
    try testing.expectEqual(@as(u64, 42), indices2[0]);
}

test "ValidatorStore: slashing protection — block double proposal" {
    var store = try initTestStore();
    defer store.deinit();

    const sk = makeDummyKey();
    try store.addKey(sk);
    const pubkey = sk.toPublicKey().compress();

    const root = [_]u8{0} ** 32;

    // First signature at slot 10 — should succeed.
    _ = try store.signBlock(undefined, pubkey, root, 10);

    // Second signature at slot 10 — should be rejected (same slot).
    try testing.expectError(error.SlashingProtectionTriggered, store.signBlock(undefined, pubkey, root, 10));

    // Signature at slot 9 — should be rejected (earlier slot).
    try testing.expectError(error.SlashingProtectionTriggered, store.signBlock(undefined, pubkey, root, 9));

    // Signature at slot 11 — should succeed (new slot).
    _ = try store.signBlock(undefined, pubkey, root, 11);
}

test "ValidatorStore: slashing protection — attestation double vote" {
    var store = try initTestStore();
    defer store.deinit();

    const sk = makeDummyKey();
    try store.addKey(sk);
    const pubkey = sk.toPublicKey().compress();

    const root = [_]u8{0} ** 32;

    // First attestation source=1, target=5 — should succeed.
    _ = try store.signAttestation(undefined, pubkey, root, 1, 5);

    // Same target epoch — double vote — should be rejected.
    try testing.expectError(error.SlashingProtectionTriggered, store.signAttestation(undefined, pubkey, root, 2, 5));

    // Earlier target — should be rejected.
    try testing.expectError(error.SlashingProtectionTriggered, store.signAttestation(undefined, pubkey, root, 2, 4));

    // New target but source goes backward — surround vote risk — should be rejected.
    try testing.expectError(error.SlashingProtectionTriggered, store.signAttestation(undefined, pubkey, root, 0, 6));

    // Valid next attestation source=1, target=6.
    _ = try store.signAttestation(undefined, pubkey, root, 1, 6);
}

test "ValidatorStore: allPubkeys" {
    var store = try initTestStore();
    defer store.deinit();

    const sk = makeDummyKey();
    try store.addKey(sk);

    const pks = try store.allPubkeys(testing.allocator);
    defer testing.allocator.free(pks);
    try testing.expectEqual(@as(usize, 1), pks.len);
    try testing.expectEqualSlices(u8, &sk.toPublicKey().compress(), &pks[0]);
}

test "ValidatorStore: addValidator, listLocalValidators, removeValidator" {
    var store = try initTestStore();
    defer store.deinit();

    const sk = makeDummyKey();
    try store.addValidator(sk);

    const infos = try store.listLocalValidators(testing.allocator);
    defer testing.allocator.free(infos);

    try testing.expectEqual(@as(usize, 1), infos.len);
    try testing.expectEqualSlices(u8, &sk.toPublicKey().compress(), &infos[0].pubkey);
    try testing.expect(!infos[0].readonly);

    // Remove.
    const removed = store.removeValidator(sk.toPublicKey().compress());
    try testing.expect(removed);

    const infos2 = try store.listLocalValidators(testing.allocator);
    defer testing.allocator.free(infos2);
    try testing.expectEqual(@as(usize, 0), infos2.len);

    // Remove again — not found.
    try testing.expect(!store.removeValidator(sk.toPublicKey().compress()));
}

test "ValidatorStore: allRemotePubkeysForSigner groups remote validators by signer pointer" {
    var store = try initTestStore();
    defer store.deinit();

    var signer0 = RemoteSigner.init(testing.allocator, "http://127.0.0.1:9000");
    var signer1 = RemoteSigner.init(testing.allocator, "http://127.0.0.1:9001");

    var pk0: [48]u8 = [_]u8{0} ** 48;
    var pk1: [48]u8 = [_]u8{1} ** 48;
    var pk2: [48]u8 = [_]u8{2} ** 48;

    try store.addRemotePubkey(pk0, &signer0);
    try store.addRemotePubkey(pk1, &signer1);
    try store.addRemotePubkey(pk2, &signer0);

    const signer0_pubkeys = try store.allRemotePubkeysForSigner(testing.allocator, &signer0);
    defer testing.allocator.free(signer0_pubkeys);
    try testing.expectEqual(@as(usize, 2), signer0_pubkeys.len);
    try testing.expectEqualSlices(u8, &pk0, &signer0_pubkeys[0]);
    try testing.expectEqualSlices(u8, &pk2, &signer0_pubkeys[1]);

    const signer1_pubkeys = try store.allRemotePubkeysForSigner(testing.allocator, &signer1);
    defer testing.allocator.free(signer1_pubkeys);
    try testing.expectEqual(@as(usize, 1), signer1_pubkeys.len);
    try testing.expectEqualSlices(u8, &pk1, &signer1_pubkeys[0]);
}

test "ValidatorStore: proposer config overrides apply after validator is added" {
    const sk = makeDummyKey();
    const pubkey = sk.toPublicKey().compress();

    var default_graffiti: [32]u8 = [_]u8{0} ** 32;
    @memcpy(default_graffiti[0..7], "default");

    const override_fee_recipient: [20]u8 = [_]u8{0x22} ** 20;
    const override_graffiti = textToGraffiti("override");
    const default_fee_recipient: [20]u8 = [_]u8{0x11} ** 20;

    var store = try ValidatorStore.init(testing.io, testing.allocator, null, .{
        .fee_recipient = default_fee_recipient,
        .graffiti = default_graffiti,
        .gas_limit = 60_000_000,
        .builder_boost_factor = 100,
        .strict_fee_recipient_check = false,
    }, &.{
        .{
            .pubkey = pubkey,
            .config = .{
                .fee_recipient = override_fee_recipient,
                .graffiti = override_graffiti,
                .gas_limit = 70_000_000,
                .builder_boost_factor = 200,
            },
        },
    });
    defer store.deinit();

    try store.addKey(sk);

    try testing.expectEqualSlices(u8, &override_fee_recipient, &store.getFeeRecipient(pubkey));
    try testing.expectEqualSlices(u8, &override_graffiti, &store.getGraffiti(pubkey));
    try testing.expectEqual(@as(u64, 70_000_000), store.getGasLimit(pubkey));
    try testing.expectEqual(@as(?u64, 200), store.getBuilderBoostFactor(pubkey));

    try store.deleteFeeRecipient(pubkey);
    try store.deleteGraffiti(pubkey);
    try store.deleteGasLimit(pubkey);
    try store.deleteBuilderBoostFactor(pubkey);

    try testing.expectEqualSlices(u8, &default_fee_recipient, &store.getFeeRecipient(pubkey));
    try testing.expectEqualSlices(u8, &default_graffiti, &store.getGraffiti(pubkey));
    try testing.expectEqual(@as(u64, 60_000_000), store.getGasLimit(pubkey));
    try testing.expectEqual(@as(?u64, 100), store.getBuilderBoostFactor(pubkey));
    try testing.expect(store.getProposerConfig(pubkey) == null);
}

fn textToGraffiti(text: []const u8) [32]u8 {
    var graffiti: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(text.len, graffiti.len);
    @memcpy(graffiti[0..copy_len], text[0..copy_len]);
    return graffiti;
}
