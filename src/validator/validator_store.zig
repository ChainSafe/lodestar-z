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
const SlashingProtectionRecord = types.SlashingProtectionRecord;
const ValidatorStatus = types.ValidatorStatus;

const SlashingProtectionDb = @import("slashing_protection_db.zig").SlashingProtectionDb;

const remote_signer_mod = @import("remote_signer.zig");
const RemoteSigner = remote_signer_mod.RemoteSigner;
const SigningType = remote_signer_mod.SigningType;

const Io = std.Io;

const log = std.log.scoped(.validator_store);

// ---------------------------------------------------------------------------
// ValidatorRecord
// ---------------------------------------------------------------------------

/// Per-validator in-memory state.
pub const ValidatorRecord = struct {
    /// BLS public key (48 bytes).
    pubkey: [48]u8,
    /// BLS secret key for local signing.
    /// For remote-only validators (is_remote = true), this field is zeroed and
    /// must NOT be used for signing. Signing is delegated to RemoteSigner.
    secret_key: SecretKey,
    /// Validator index on the beacon chain (null until resolved).
    index: ?u64,
    /// Current activation status.
    status: ValidatorStatus,
    /// Slashing protection data.
    slashing: SlashingProtectionRecord,
    /// True if this validator's signing is delegated to a remote signer (Web3Signer).
    /// Secret key is zeroed; calls to signXxx will fail with error.RemoteSignerRequired.
    is_remote: bool = false,
};

// ---------------------------------------------------------------------------
// ValidatorStore
// ---------------------------------------------------------------------------

pub const ValidatorStore = struct {
    allocator: Allocator,
    validators: std.ArrayList(ValidatorRecord),
    /// Cached pubkey slice kept in sync with validators for non-allocating pubkeys() access.
    pubkeys_cache: std.ArrayList([48]u8),
    /// Persistent slashing protection database.
    slashing_db: SlashingProtectionDb,
    /// Mutex protecting validators list for concurrent add/remove.
    mutex: std.Thread.Mutex,
    /// Remote signer client (Web3Signer). Non-null when web3signer_url is configured.
    /// Used by signing methods when `validator.is_remote == true`.
    remote_signer: ?*RemoteSigner = null,

    /// Initialize the ValidatorStore with an optional persistent slashing protection DB.
    ///
    /// Pass db_path = null for in-memory-only mode (tests, no persistence).
    pub fn init(allocator: Allocator, db_path: ?[]const u8) !ValidatorStore {
        const slashing_db = try SlashingProtectionDb.init(allocator, db_path);
        return .{
            .allocator = allocator,
            .validators = std.ArrayList(ValidatorRecord).init(allocator),
            .pubkeys_cache = std.ArrayList([48]u8).init(allocator),
            .slashing_db = slashing_db,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ValidatorStore) void {
        // Zero all BLS secret keys before freeing the list.
        for (self.validators.items) |*v| {
            std.crypto.utils.secureZero(u8, &v.secret_key.value.b);
        }
        self.validators.deinit();
        self.pubkeys_cache.deinit();
        self.slashing_db.close();
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
        // Keep pubkeys_cache in sync for non-allocating pubkeys() access.
        try self.pubkeys_cache.append(pubkey_bytes);
        log.debug("added validator pubkey={}", .{std.fmt.fmtSliceHexLower(&pubkey_bytes)});
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
    pub fn addRemotePubkey(self: *ValidatorStore, pubkey: [48]u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check for duplicate (remote or local).
        for (self.validators.items) |v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) return; // already present
        }

        // Build a zeroed SecretKey placeholder — never used for signing.
        var zeroed_sk_bytes = [_]u8{0} ** 32;
        // BLS scalar must be non-zero; use 1 as a safe placeholder.
        zeroed_sk_bytes[31] = 1;
        const placeholder_sk = SecretKey.deserialize(&zeroed_sk_bytes) catch return error.InvalidPubkey;

        try self.validators.append(.{
            .pubkey = pubkey,
            .secret_key = placeholder_sk,
            .index = null,
            .status = .unknown,
            .is_remote = true,
            .slashing = .{
                .pubkey = pubkey,
                .last_signed_block_slot = null,
                .last_signed_attestation_source_epoch = null,
                .last_signed_attestation_target_epoch = null,
            },
        });
        try self.pubkeys_cache.append(pubkey);
        log.info("registered remote validator pubkey={}", .{std.fmt.fmtSliceHexLower(&pubkey)});
    }

    /// Return true if the given pubkey belongs to a remote signer.
    pub fn isRemote(self: *ValidatorStore, pubkey: [48]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.validators.items) |v| {
            if (std.mem.eql(u8, &v.pubkey, &pubkey)) return v.is_remote;
        }
        return false;
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
                std.crypto.utils.secureZero(u8, &self.validators.items[i].secret_key.value.b);
                _ = self.validators.swapRemove(i);
                // Keep pubkeys_cache in sync.
                _ = self.pubkeys_cache.swapRemove(i);
                log.info("removed validator pubkey={}", .{std.fmt.fmtSliceHexLower(&pubkey)});
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

    /// List all validators with metadata (thread-safe).
    ///
    /// Returns a caller-owned slice. Caller must free.
    /// Used by the Keymanager API GET /eth/v1/keystores.
    ///
    /// TS: ValidatorStore.getLocalKeystoreInfo()
    pub fn listValidators(self: *ValidatorStore, allocator: Allocator) ![]ValidatorInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        const result = try allocator.alloc(ValidatorInfo, self.validators.items.len);
        for (self.validators.items, result) |v, *out| {
            out.* = .{
                .pubkey = v.pubkey,
                .derivation_path = "",
                .readonly = false,
            };
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
        const mutex_ptr: *std.Thread.Mutex = @constCast(&self.mutex);
        mutex_ptr.lock();
        defer mutex_ptr.unlock();

        const result = try allocator.alloc([48]u8, self.validators.items.len);
        for (self.validators.items, result) |v, *out| {
            out.* = v.pubkey;
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
        const mutex_ptr: *std.Thread.Mutex = @constCast(&self.mutex);
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

        if (validator.is_remote) {
            const rs = self.remote_signer orelse return error.RemoteSignerRequired;
            return rs.sign(io, pubkey, signing_root, .BLOCK_V2) catch |err| {
                log.warn("remote signer signBlock error={s}", .{@errorName(err)});
                return err;
            };
        }

        // Sign the root locally.
        return validator.secret_key.sign(&signing_root, bls.DST, null);
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
        if (validator.is_remote) {
            const rs = self.remote_signer orelse return error.RemoteSignerRequired;
            return rs.sign(io, pubkey, signing_root, .RANDAO_REVEAL) catch |err| {
                log.warn("remote signer signRandao error={s}", .{@errorName(err)});
                return err;
            };
        }
        return validator.secret_key.sign(&signing_root, bls.DST, null);
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

        if (validator.is_remote) {
            const rs = self.remote_signer orelse return error.RemoteSignerRequired;
            return rs.sign(io, pubkey, signing_root, .ATTESTATION) catch |err| {
                log.warn("remote signer signAttestation error={s}", .{@errorName(err)});
                return err;
            };
        }

        return validator.secret_key.sign(&signing_root, bls.DST, null);
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
        if (validator.is_remote) {
            const rs = self.remote_signer orelse return error.RemoteSignerRequired;
            return rs.sign(io, pubkey, signing_root, .SYNC_COMMITTEE_MESSAGE) catch |err| {
                log.warn("remote signer signSyncCommitteeMessage error={s}", .{@errorName(err)});
                return err;
            };
        }
        return validator.secret_key.sign(&signing_root, bls.DST, null);
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
        if (validator.is_remote) {
            const rs = self.remote_signer orelse return error.RemoteSignerRequired;
            return rs.sign(io, pubkey, signing_root, signing_type) catch |err| {
                log.warn("remote signer signSelectionProof error={s}", .{@errorName(err)});
                return err;
            };
        }
        return validator.secret_key.sign(&signing_root, bls.DST, null);
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
        if (validator.is_remote) {
            const rs = self.remote_signer orelse return error.RemoteSignerRequired;
            return rs.sign(io, pubkey, signing_root, .AGGREGATE_AND_PROOF) catch |err| {
                log.warn("remote signer signAggregateAndProof error={s}", .{@errorName(err)});
                return err;
            };
        }
        return validator.secret_key.sign(&signing_root, bls.DST, null);
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
        if (validator.is_remote) {
            const rs = self.remote_signer orelse return error.RemoteSignerRequired;
            return rs.sign(io, pubkey, signing_root, .SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF) catch |err| {
                log.warn("remote signer signContributionAndProof error={s}", .{@errorName(err)});
                return err;
            };
        }
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

test "ValidatorStore: addKey and allIndices" {
    var store = try ValidatorStore.init(testing.allocator, null);
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
    var store = try ValidatorStore.init(testing.allocator, null);
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
    var store = try ValidatorStore.init(testing.allocator, null);
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
    var store = try ValidatorStore.init(testing.allocator, null);
    defer store.deinit();

    const sk = makeDummyKey();
    try store.addKey(sk);

    const pks = try store.allPubkeys(testing.allocator);
    defer testing.allocator.free(pks);
    try testing.expectEqual(@as(usize, 1), pks.len);
    try testing.expectEqualSlices(u8, &sk.toPublicKey().compress(), &pks[0]);
}

test "ValidatorStore: addValidator, listValidators, removeValidator" {
    var store = try ValidatorStore.init(testing.allocator, null);
    defer store.deinit();

    const sk = makeDummyKey();
    try store.addValidator(sk);

    const infos = try store.listValidators(testing.allocator);
    defer testing.allocator.free(infos);

    try testing.expectEqual(@as(usize, 1), infos.len);
    try testing.expectEqualSlices(u8, &sk.toPublicKey().compress(), &infos[0].pubkey);
    try testing.expect(!infos[0].readonly);

    // Remove.
    const removed = store.removeValidator(sk.toPublicKey().compress());
    try testing.expect(removed);

    const infos2 = try store.listValidators(testing.allocator);
    defer testing.allocator.free(infos2);
    try testing.expectEqual(@as(usize, 0), infos2.len);

    // Remove again — not found.
    try testing.expect(!store.removeValidator(sk.toPublicKey().compress()));
}
