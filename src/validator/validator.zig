//! Main Validator Client entry point.
//!
//! Coordinates the slot clock, service instances, and API client lifecycle.
//! Mirrors the TypeScript Validator class in packages/validator/src/validator.ts.
//!
//! Architecture:
//!
//!   ValidatorClient
//!     ├── SlotClock               — computes slots, fires callbacks
//!     ├── BeaconApiClient         — HTTP calls + SSE stream to BN
//!     ├── ValidatorStore          — BLS keys + slashing protection
//!     ├── ChainHeaderTracker      — SSE head event cache
//!     ├── BlockService            — block proposal duties
//!     ├── AttestationService      — attester duties + aggregation
//!     ├── SyncCommitteeService    — sync committee duties + contributions
//!     ├── PrepareBeaconProposer   — fee recipient registration
//!     └── DoppelgangerService     — duplicate validator detection
//!
//! I/O model (Zig 0.16):
//!   All blocking I/O uses std.Io (evented I/O via io_uring on Linux).
//!   The `run` method takes an `Io` instance and drives the event loop.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const types = @import("types.zig");
const ValidatorConfig = types.ValidatorConfig;

const clock_mod = @import("clock.zig");
const ValidatorSlotTicker = clock_mod.ValidatorSlotTicker;

const api_mod = @import("api_client.zig");
const BeaconApiClient = api_mod.BeaconApiClient;

const store_mod = @import("validator_store.zig");
const ValidatorStore = store_mod.ValidatorStore;

const block_mod = @import("block_service.zig");
const BlockService = block_mod.BlockService;

const attest_mod = @import("attestation_service.zig");
const AttestationService = attest_mod.AttestationService;

const sync_mod = @import("sync_committee_service.zig");
const SyncCommitteeService = sync_mod.SyncCommitteeService;

const dopple_mod = @import("doppelganger.zig");
const DoppelgangerService = dopple_mod.DoppelgangerService;

const chain_header_mod = @import("chain_header_tracker.zig");
const ChainHeaderTracker = chain_header_mod.ChainHeaderTracker;

const prepare_mod = @import("prepare_beacon_proposer.zig");
const PrepareBeaconProposerService = prepare_mod.PrepareBeaconProposerService;

const builder_reg_mod = @import("builder_registration.zig");
const BuilderRegistrationService = builder_reg_mod.BuilderRegistrationService;

const signing_mod = @import("signing.zig");
const SigningContext = signing_mod.SigningContext;

const bls = @import("bls");

const remote_signer_mod = @import("remote_signer.zig");
const RemoteSigner = remote_signer_mod.RemoteSigner;
const startup_signers_mod = @import("startup_signers.zig");
const RemoteSignerKeys = startup_signers_mod.RemoteSignerKeys;
const StartupSigners = startup_signers_mod.StartupSigners;
const KeystoreLock = @import("keystore_lock.zig").KeystoreLock;

const syncing_tracker_mod = @import("syncing_tracker.zig");
const SyncingTracker = syncing_tracker_mod.SyncingTracker;

const index_tracker_mod = @import("index_tracker.zig");
const IndexTracker = index_tracker_mod.IndexTracker;

const liveness_mod = @import("liveness.zig");
const LivenessTracker = liveness_mod.LivenessTracker;
const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;

const fs = @import("fs.zig");
const interchange_mod = @import("interchange.zig");
const time = @import("time.zig");
const state_transition = @import("state_transition");

const log = std.log.scoped(.validator_client);

// ---------------------------------------------------------------------------
// ValidatorClient
// ---------------------------------------------------------------------------

pub const ValidatorClient = struct {
    pub const ValidatorCounts = store_mod.ValidatorStore.ValidatorCounts;
    const BackgroundTaskFuture = std.Io.Future(anyerror!void);
    pub const InitParams = struct {
        config: ValidatorConfig,
        signing_context: SigningContext,
        startup_signers: StartupSigners,
        metrics: *ValidatorMetrics,
    };

    allocator: Allocator,
    config: ValidatorConfig,
    metrics: *ValidatorMetrics,

    // Core components.
    clock: ValidatorSlotTicker,
    api: BeaconApiClient,
    validator_store: ValidatorStore,
    header_tracker: ChainHeaderTracker,

    // Services.
    block_service: BlockService,
    attestation_service: AttestationService,
    sync_committee_service: SyncCommitteeService,
    prepare_proposer: PrepareBeaconProposerService,
    /// Builder registration service — null when builder is not configured.
    builder_registration: ?BuilderRegistrationService,
    doppelganger: ?DoppelgangerService,

    // I/O context — stored so clock callbacks and background services can make HTTP calls.
    io: std.Io,

    // Index tracker — resolves pubkey → validator index mappings.
    index_tracker: IndexTracker,

    // Liveness tracker — records per-validator duty outcomes.
    liveness_tracker: LivenessTracker,

    // Signing context — fork schedule, genesis info for domain computation.
    signing_context: SigningContext,

    // Syncing tracker — pauses duties when BN sync distance is too large.
    syncing_tracker: SyncingTracker,

    // Shutdown requested flag — set on signal, stops the clock loop.
    shutdown_requested: std.atomic.Value(bool),
    running: std.atomic.Value(bool),

    // Long-lived background tasks owned by the validator runtime.
    header_tracker_task: ?BackgroundTaskFuture = null,
    remote_signer_sync_task: ?BackgroundTaskFuture = null,
    doppelganger_task: ?BackgroundTaskFuture = null,

    // Session stats.
    session_start_ns: u64,

    /// Stable remote signer objects owned by this validator client.
    remote_signers: std.array_list.Managed(*RemoteSigner),
    /// Local keystore ownership locks held for the process lifetime.
    local_keystore_locks: std.array_list.Managed(KeystoreLock),
    /// Serializes runtime keymanager mutations and remote-signer sync updates.
    runtime_mutex: std.Io.Mutex,

    // ---------------------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------------------

    /// Create and initialise the ValidatorClient.
    ///
    /// `signing_ctx` provides the fork_version and genesis_validators_root
    /// needed to compute signing domains. Obtain from BN genesis endpoint
    /// or supply from config.
    ///
    /// TS: Validator.init(opts, genesis)
    pub fn init(
        io: Io,
        allocator: Allocator,
        params: InitParams,
    ) !*ValidatorClient {
        const config = params.config;
        const signing_ctx = params.signing_context;
        var signers = params.startup_signers;
        defer signers.deinit(io);

        const self = try allocator.create(ValidatorClient);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.config = config;
        self.metrics = params.metrics;
        self.clock = ValidatorSlotTicker.init(
            config.genesis_time,
            config.seconds_per_slot,
            config.slots_per_epoch,
        );
        self.io = io;
        self.signing_context = signing_ctx;
        self.shutdown_requested = std.atomic.Value(bool).init(false);
        self.running = std.atomic.Value(bool).init(false);
        self.header_tracker_task = null;
        self.session_start_ns = time.awakeNanoseconds(io);
        self.remote_signers = std.array_list.Managed(*RemoteSigner).init(allocator);
        self.remote_signer_sync_task = null;
        self.doppelganger_task = null;
        self.local_keystore_locks = std.array_list.Managed(KeystoreLock).init(allocator);
        self.runtime_mutex = .init;

        self.api = try BeaconApiClient.initWithOptions(allocator, io, .{
            .base_url = config.beacon_node_url,
            .fallback_urls = config.beacon_node_fallback_urls,
            .request_timeout_ms = config.seconds_per_slot * std.time.ms_per_s,
            .metrics = self.metrics,
        });
        self.validator_store = try ValidatorStore.init(
            io,
            allocator,
            config.slashing_protection_path,
            .{
                .fee_recipient = config.suggested_fee_recipient,
                .graffiti = config.graffiti,
                .gas_limit = config.gas_limit,
                .builder_selection = config.builder_selection,
                .builder_boost_factor = config.builder_boost_factor,
                .strict_fee_recipient_check = config.strict_fee_recipient_check,
            },
            config.proposer_configs,
        );
        errdefer self.validator_store.deinit();

        self.header_tracker = ChainHeaderTracker.init(allocator, io, &self.api);
        self.block_service = BlockService.init(
            io,
            allocator,
            &self.api,
            &self.validator_store,
            signing_ctx,
            config.slots_per_epoch,
            config.seconds_per_slot,
            config.genesis_time,
            config.blinded_local,
            config.broadcast_validation,
            self.metrics,
        );
        errdefer self.block_service.deinit();
        self.attestation_service = AttestationService.init(
            io,
            allocator,
            &self.api,
            &self.validator_store,
            signing_ctx,
            config.seconds_per_slot,
            config.genesis_time,
            config.electra_fork_epoch,
            config.gloas_fork_epoch,
            config.attestation_due_ms,
            config.attestation_due_ms_gloas,
            config.aggregate_due_ms,
            config.aggregate_due_ms_gloas,
            self.metrics,
        );
        errdefer self.attestation_service.deinit();
        self.sync_committee_service = SyncCommitteeService.init(
            io,
            allocator,
            &self.api,
            &self.validator_store,
            signing_ctx,
            config.slots_per_epoch,
            config.epochs_per_sync_committee_period,
            config.sync_committee_size,
            config.sync_committee_subnet_count,
            config.seconds_per_slot,
            config.genesis_time,
            config.gloas_fork_epoch,
            config.sync_message_due_ms,
            config.sync_message_due_ms_gloas,
            config.sync_contribution_due_ms,
            config.sync_contribution_due_ms_gloas,
            self.metrics,
        );
        errdefer self.sync_committee_service.deinit();

        self.prepare_proposer = PrepareBeaconProposerService.init(
            allocator,
            &self.api,
            &self.validator_store,
        );

        self.builder_registration = if (config.builder_url != null)
            BuilderRegistrationService.init(
                allocator,
                &self.api,
                &self.validator_store,
            )
        else
            null;
        errdefer if (self.builder_registration) |*builder_registration| builder_registration.deinit();

        self.doppelganger = if (config.doppelganger_protection)
            DoppelgangerService.init(allocator, io, &self.api, self.metrics, &self.validator_store.slashing_db)
        else
            null;
        errdefer if (self.doppelganger) |*doppelganger| doppelganger.deinit();

        self.index_tracker = IndexTracker.init(allocator, io, &self.api);
        errdefer self.index_tracker.deinit();
        self.liveness_tracker = LivenessTracker.init(allocator, io);
        errdefer self.liveness_tracker.deinit();
        self.syncing_tracker = SyncingTracker.init(&self.api, self.metrics);

        var loaded_count: usize = 0;
        for (signers.local_keys) |k| {
            try self.validator_store.addKey(k.secret_key);
            loaded_count += 1;
        }
        log.info("validator local keys loaded at startup: {d}", .{loaded_count});

        if (config.interchange_import_path) |ipath| {
            const interchange_data = fs.readFileAlloc(io, allocator, ipath, 16 * 1024 * 1024) catch |err| blk: {
                log.err("failed to read interchange file {s}: {s}", .{ ipath, @errorName(err) });
                break :blk null;
            };
            if (interchange_data) |data| {
                defer allocator.free(data);
                const records = interchange_mod.importInterchangeVerified(
                    allocator,
                    data,
                    config.genesis_validators_root,
                ) catch |err| blk: {
                    log.err("interchange import failed: {s}", .{@errorName(err)});
                    break :blk null;
                };
                if (records) |recs| {
                    defer allocator.free(recs);
                    var imported_count: usize = 0;
                    for (recs) |rec| {
                        if (rec.last_signed_block_slot) |slot| {
                            _ = try self.validator_store.slashing_db.checkAndInsertBlock(rec.pubkey, slot);
                            imported_count += 1;
                        }
                        if (rec.last_signed_attestation_source_epoch) |src| {
                            if (rec.last_signed_attestation_target_epoch) |tgt| {
                                _ = try self.validator_store.slashing_db.checkAndInsertAttestation(
                                    rec.pubkey,
                                    src,
                                    tgt,
                                );
                            }
                        }
                    }
                    log.info("imported interchange: {d} validator records from {s}", .{ imported_count, ipath });
                }
            }
        }

        const startup_pubkeys = try self.validator_store.allPubkeys(allocator);
        defer allocator.free(startup_pubkeys);
        for (startup_pubkeys) |pubkey| {
            self.index_tracker.trackPubkey(pubkey);
            self.liveness_tracker.register(pubkey);
        }

        if (config.external_signer_urls.len > 0) {
            for (config.external_signer_urls) |url| {
                _ = try self.ensureRemoteSigner(url);
            }

            for (signers.remote_signers) |remote_signer_keys| {
                try self.addRemoteSignerKeys(remote_signer_keys);
            }
        }

        for (signers.local_keystore_locks) |lock| {
            try self.local_keystore_locks.append(lock);
        }
        signers.local_keystore_locks = &.{};
        self.syncValidatorMetrics();

        return self;
    }

    pub fn deinit(self: *ValidatorClient) void {
        self.block_service.deinit();
        self.attestation_service.deinit();
        self.sync_committee_service.deinit();
        if (self.builder_registration) |*br| br.deinit();
        if (self.doppelganger) |*d| d.deinit();
        self.index_tracker.deinit();
        self.liveness_tracker.deinit();
        for (self.local_keystore_locks.items) |*lock| lock.deinit(self.io);
        self.local_keystore_locks.deinit();
        self.validator_store.deinit();
        self.api.deinit();
        for (self.remote_signers.items) |remote_signer| {
            remote_signer.deinit();
            self.allocator.destroy(remote_signer);
        }
        self.remote_signers.deinit();
    }

    pub fn destroy(self: *ValidatorClient) void {
        const allocator = self.allocator;
        self.deinit();
        allocator.destroy(self);
    }

    pub fn validatorCounts(self: *ValidatorClient) ValidatorCounts {
        return self.validator_store.counts();
    }

    fn syncValidatorMetrics(self: *ValidatorClient) void {
        const counts = self.validator_store.counts();
        self.metrics.total_validators.set(@intCast(counts.total));
        self.metrics.active_validators.set(@intCast(counts.active));
    }

    /// Request graceful shutdown of the validator client.
    ///
    /// Can be called from a signal handler or external code.
    /// The run loop will stop at the next clock tick.
    ///
    /// TS: Validator.close(signal)
    pub fn requestShutdown(self: *ValidatorClient) void {
        log.info("shutdown requested", .{});
        self.shutdown_requested.store(true, .seq_cst);
        // BUG-7 Fix: Propagate shutdown to the clock's run loop.
        self.clock.requestShutdown();
    }

    /// Return true if shutdown has been requested.
    pub fn isShutdownRequested(self: *ValidatorClient) bool {
        return self.shutdown_requested.load(.seq_cst);
    }

    /// Sign and submit a voluntary exit for the given validator.
    ///
    /// Computes the signing root using the validator client's signing context,
    /// signs with the validator's key (local or remote), and submits the
    /// signed exit to the beacon node via POST /eth/v1/beacon/pool/voluntary_exits.
    ///
    /// Requires:
    /// - Validator index must be resolved (call after index tracker resolves)
    /// - Signing context must be initialized (after genesis data is fetched)
    ///
    /// TS: Lodestar CLI uses `validator-voluntary-exit` command.
    pub fn submitVoluntaryExit(
        self: *ValidatorClient,
        io: Io,
        pubkey: [48]u8,
        epoch: u64,
    ) !void {
        const signing = @import("signing.zig");

        const validator_index = self.validator_store.getValidatorIndex(pubkey) orelse
            return error.ValidatorNotFound;

        // Compute the signing root using the VC's signing context.
        var signing_root: [32]u8 = undefined;
        const voluntary_exit = @import("consensus_types").phase0.VoluntaryExit.Type{
            .epoch = epoch,
            .validator_index = validator_index,
        };
        try signing.voluntaryExitSigningRoot(
            self.signing_context,
            &voluntary_exit,
            epoch,
            &signing_root,
        );

        const signature = try self.validator_store.signVoluntaryExit(io, pubkey, signing_root);
        const sig_bytes = signature.compress();
        const sig_hex = std.fmt.bytesToHex(&sig_bytes, .lower);

        const json_body = try std.fmt.allocPrint(
            self.allocator,
            "{{\"message\":{{\"epoch\":{d},\"validator_index\":{d}}},\"signature\":\"0x{s}\"}}",
            .{ epoch, validator_index, sig_hex },
        );
        defer self.allocator.free(json_body);

        try self.api.publishVoluntaryExit(io, json_body);
        log.info("voluntary exit submitted for validator {d} at epoch {d}", .{
            validator_index, epoch,
        });
    }

    /// Add a validator secret key to the store.
    ///
    /// Must be called before `start()`.
    pub fn addKey(self: *ValidatorClient, secret_key: bls.SecretKey) !void {
        try self.validator_store.addKey(secret_key);
        try self.registerValidatorTracking(secret_key.toPublicKey().compress());
        self.syncValidatorMetrics();
    }

    pub fn addLocalKeyRuntime(self: *ValidatorClient, secret_key: bls.SecretKey, lock: ?KeystoreLock) !void {
        self.runtime_mutex.lockUncancelable(self.io);
        defer self.runtime_mutex.unlock(self.io);

        try self.validator_store.addKey(secret_key);
        try self.registerValidatorTracking(secret_key.toPublicKey().compress());
        if (lock) |owned_lock| {
            try self.local_keystore_locks.append(owned_lock);
        }
        self.syncValidatorMetrics();
        self.refreshCurrentEpochDuties(self.io);
    }

    pub fn addRemoteKeyRuntime(self: *ValidatorClient, pubkey: [48]u8, url: []const u8) !void {
        self.runtime_mutex.lockUncancelable(self.io);
        defer self.runtime_mutex.unlock(self.io);

        const signer = try self.ensureRemoteSigner(url);
        try self.validator_store.addRemotePubkey(pubkey, signer);
        try self.registerValidatorTracking(pubkey);
        self.syncValidatorMetrics();
        self.refreshCurrentEpochDuties(self.io);
    }

    pub fn removeValidatorRuntime(self: *ValidatorClient, pubkey: [48]u8) ?store_mod.SignerKind {
        self.runtime_mutex.lockUncancelable(self.io);
        defer self.runtime_mutex.unlock(self.io);

        const signer_kind = self.validator_store.signerKind(pubkey) orelse return null;
        if (!self.validator_store.removeValidator(pubkey)) return null;

        if (signer_kind == .local) self.removeLocalKeystoreLock(pubkey);
        self.unregisterValidatorTracking(pubkey);
        self.syncValidatorMetrics();
        return signer_kind;
    }

    fn applyResolvedIndices(self: *ValidatorClient) void {
        const resolved = self.index_tracker.allResolvedEntries(self.allocator) catch |err| {
            log.warn("snapshot resolved validator indices failed: {s}", .{@errorName(err)});
            return;
        };
        defer self.allocator.free(resolved);

        for (resolved) |entry| {
            self.validator_store.updateIndex(entry.pubkey, entry.index, entry.status);
            if (self.doppelganger) |*d| {
                d.updateIndex(entry.pubkey, entry.index);
            }
        }
    }

    fn syncDoppelgangerEntryIndices(self: *ValidatorClient) void {
        if (self.doppelganger) |*d| {
            const pubkeys = self.validator_store.allPubkeys(self.allocator) catch |err| {
                log.warn("snapshot validator pubkeys for doppelganger sync failed: {s}", .{@errorName(err)});
                return;
            };
            defer self.allocator.free(pubkeys);

            for (pubkeys) |pubkey| {
                d.updateIndex(pubkey, self.index_tracker.getIndex(pubkey));
            }
        }
    }

    fn registerAllValidatorsWithDoppelganger(self: *ValidatorClient) void {
        if (self.doppelganger) |*d| {
            const current_epoch = self.clock.currentEpoch(self.io);
            const pubkeys = self.validator_store.allPubkeys(self.allocator) catch |err| {
                log.warn("snapshot validator pubkeys for doppelganger registration failed: {s}", .{@errorName(err)});
                return;
            };
            defer self.allocator.free(pubkeys);

            for (pubkeys) |pubkey| {
                d.registerValidator(current_epoch, pubkey) catch |err| {
                    log.warn("doppelganger registerValidator error: {s}", .{@errorName(err)});
                };
            }
            self.syncDoppelgangerEntryIndices();
        }
    }

    fn sliceContainsPubkey(pubkeys: []const [48]u8, pubkey: [48]u8) bool {
        for (pubkeys) |candidate| {
            if (std.mem.eql(u8, &candidate, &pubkey)) return true;
        }
        return false;
    }

    fn registerValidatorTracking(self: *ValidatorClient, pubkey: [48]u8) !void {
        if (self.doppelganger) |*d| {
            try d.registerValidator(self.clock.currentEpoch(self.io), pubkey);
        }
        self.index_tracker.trackPubkey(pubkey);
        self.liveness_tracker.register(pubkey);
    }

    fn unregisterValidatorTracking(self: *ValidatorClient, pubkey: [48]u8) void {
        self.index_tracker.untrackPubkey(pubkey);
        if (self.doppelganger) |*d| {
            d.unregisterValidator(pubkey);
        }
        self.liveness_tracker.unregister(pubkey);
        self.block_service.removeDutiesForKey(pubkey);
        self.attestation_service.removeDutiesForKey(pubkey);
        self.sync_committee_service.removeDutiesForKey(pubkey);
    }

    fn refreshCurrentEpochDuties(self: *ValidatorClient, io: Io) void {
        if (!self.running.load(.acquire)) return;

        self.index_tracker.resolveIndices(io) catch |err| {
            log.warn("runtime index resolution failed: {s}", .{@errorName(err)});
        };
        self.applyResolvedIndices();

        const epoch = self.clock.currentEpoch(io);
        self.block_service.onEpoch(io, epoch);
        self.attestation_service.onEpoch(io, epoch);
        self.sync_committee_service.onEpoch(io, epoch);
        self.prepare_proposer.onEpoch(io, epoch);
        if (self.builder_registration) |*br| {
            br.onEpoch(io, epoch);
        }
    }

    fn ensureRemoteSigner(self: *ValidatorClient, url: []const u8) !*RemoteSigner {
        for (self.remote_signers.items) |remote_signer| {
            if (std.mem.eql(u8, remote_signer.base_url, url)) return remote_signer;
        }

        const remote_signer = try self.allocator.create(RemoteSigner);
        errdefer self.allocator.destroy(remote_signer);
        remote_signer.* = try RemoteSigner.initOwned(self.allocator, url);
        errdefer remote_signer.deinit();

        try self.remote_signers.append(remote_signer);
        return remote_signer;
    }

    fn removeLocalKeystoreLock(self: *ValidatorClient, pubkey: [48]u8) void {
        for (self.local_keystore_locks.items, 0..) |*lock, idx| {
            if (lock.pubkey) |locked_pubkey| {
                if (!std.mem.eql(u8, &locked_pubkey, &pubkey)) continue;
                lock.deinit(self.io);
                _ = self.local_keystore_locks.swapRemove(idx);
                return;
            }
        }
    }

    fn syncRemoteSignerKeys(self: *ValidatorClient, io: Io) !void {
        self.runtime_mutex.lockUncancelable(self.io);
        defer self.runtime_mutex.unlock(self.io);

        if (self.remote_signers.items.len == 0) return;

        const RemoteFetch = struct {
            signer: *RemoteSigner,
            pubkeys: [][48]u8,
        };

        var fetched_sets = std.ArrayListUnmanaged(RemoteFetch).empty;
        defer {
            for (fetched_sets.items) |item| {
                if (item.pubkeys.len > 0) self.allocator.free(item.pubkeys);
            }
            fetched_sets.deinit(self.allocator);
        }

        var first_seen_by_pubkey = std.AutoHashMap([48]u8, *RemoteSigner).init(self.allocator);
        defer first_seen_by_pubkey.deinit();

        for (self.remote_signers.items) |remote_signer| {
            const fetched_pubkeys = remote_signer.listKeys(io) catch |err| {
                log.warn("failed to fetch remote keys url={s}: {s}", .{
                    remote_signer.base_url,
                    @errorName(err),
                });
                continue;
            };

            try fetched_sets.append(self.allocator, .{
                .signer = remote_signer,
                .pubkeys = fetched_pubkeys,
            });
        }

        var added_count: usize = 0;
        var removed_count: usize = 0;

        for (fetched_sets.items) |fetched_set| {
            const signer = fetched_set.signer;

            var desired_pubkeys = std.ArrayListUnmanaged([48]u8).empty;
            defer desired_pubkeys.deinit(self.allocator);

            for (fetched_set.pubkeys) |pubkey| {
                const existing = try first_seen_by_pubkey.getOrPut(pubkey);
                if (existing.found_existing) {
                    if (existing.value_ptr.* != signer) {
                        log.warn(
                            "duplicate remote validator pubkey=0x{s} first_url={s} duplicate_url={s} - keeping first occurrence",
                            .{
                                std.fmt.bytesToHex(pubkey, .lower),
                                existing.value_ptr.*.base_url,
                                signer.base_url,
                            },
                        );
                    }
                    continue;
                }

                existing.value_ptr.* = signer;
                try desired_pubkeys.append(self.allocator, pubkey);
            }

            const existing_remote_pubkeys = try self.validator_store.allRemotePubkeysForSigner(self.allocator, signer);
            defer if (existing_remote_pubkeys.len > 0) self.allocator.free(existing_remote_pubkeys);

            for (desired_pubkeys.items) |pubkey| {
                if (sliceContainsPubkey(existing_remote_pubkeys, pubkey)) continue;

                self.validator_store.addRemotePubkey(pubkey, signer) catch |err| {
                    log.warn("addRemotePubkey failed pubkey=0x{s} url={s}: {s}", .{
                        std.fmt.bytesToHex(pubkey, .lower),
                        signer.base_url,
                        @errorName(err),
                    });
                    continue;
                };
                self.registerValidatorTracking(pubkey) catch |err| {
                    log.warn("failed to register runtime tracking pubkey=0x{s}: {s}", .{
                        std.fmt.bytesToHex(pubkey, .lower),
                        @errorName(err),
                    });
                };
                added_count += 1;
                log.info("registered remote validator pubkey=0x{s} url={s}", .{
                    std.fmt.bytesToHex(pubkey, .lower),
                    signer.base_url,
                });
            }

            for (existing_remote_pubkeys) |pubkey| {
                if (sliceContainsPubkey(desired_pubkeys.items, pubkey)) continue;

                if (self.validator_store.removeValidator(pubkey)) {
                    self.unregisterValidatorTracking(pubkey);
                    removed_count += 1;
                    log.info("removed remote validator pubkey=0x{s} url={s}", .{
                        std.fmt.bytesToHex(pubkey, .lower),
                        signer.base_url,
                    });
                }
            }
        }

        if (added_count > 0 or removed_count > 0) {
            self.syncValidatorMetrics();
            log.info("remote signer sync complete added={d} removed={d}", .{ added_count, removed_count });
            self.refreshCurrentEpochDuties(io);
        }
    }

    /// Start the validator client: wire up clock callbacks and enter the run loop.
    ///
    /// Blocks until error or explicit stop.
    ///
    /// TS: clock.start(signal) → runs all registered fns in background.
    pub fn start(self: *ValidatorClient) !void {
        log.info("starting validator client beacon_node={s}", .{self.config.beacon_node_url});
        self.running.store(true, .release);
        defer self.running.store(false, .release);

        // Wire up chain header tracker callbacks.
        self.sync_committee_service.setHeaderTracker(&self.header_tracker);
        self.attestation_service.setHeaderTracker(&self.header_tracker);

        // Wire safety checkers (doppelganger + syncing) into all signing services.
        const dopple_ptr: ?*DoppelgangerService = if (self.doppelganger != null) &self.doppelganger.? else null;
        const syncing_ptr: ?*SyncingTracker = &self.syncing_tracker;
        self.block_service.setSafetyCheckers(dopple_ptr, syncing_ptr);
        self.attestation_service.setSafetyCheckers(dopple_ptr, syncing_ptr);
        self.sync_committee_service.setSafetyCheckers(dopple_ptr, syncing_ptr);

        // Wire liveness tracker into services that record duty outcomes.
        self.attestation_service.setLivenessTracker(&self.liveness_tracker);
        self.sync_committee_service.setLivenessTracker(&self.liveness_tracker);
        self.syncing_tracker.onResynced(.{ .ctx = self, .fn_ptr = onResyncedDutyRefresh });

        // Register one coherent runtime callback per phase so sync gating and
        // index resolution complete before long-running duty work fans out.
        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochRuntime });
        self.clock.onSlot(.{ .ctx = self, .fn_ptr = onSlotRuntime });

        if (self.doppelganger) |*d| {
            // Wire shutdown callback: when doppelganger is detected, trigger VC shutdown.
            d.setShutdownCallback(.{
                .ctx = self,
                .fn_ptr = struct {
                    fn cb(ctx: *anyopaque) void {
                        const vc: *ValidatorClient = @ptrCast(@alignCast(ctx));
                        vc.requestShutdown();
                    }
                }.cb,
            });
        }

        // Resolve validator indices at startup.
        // This is required before duties can be fetched (duties use validator index, not pubkey).
        //
        // TS: IndicesService.pollValidatorIndices() on startup.
        log.info("resolving validator indices at startup", .{});
        self.index_tracker.resolveIndices(self.io) catch |err| {
            log.warn("startup index resolution failed: {s} — will retry on first epoch", .{@errorName(err)});
        };
        self.applyResolvedIndices();
        self.refreshCurrentEpochDuties(self.io);

        // Doppelganger startup: if enabled, validators start as Unverified and cannot sign.
        // The doppelganger service checks liveness each epoch and promotes to VerifiedSafe
        // after DEFAULT_REMAINING_DETECTION_EPOCHS clean epochs.
        //
        // TS: DoppelgangerService.pollLiveness — runs on each epoch, blocks signing until safe.
        if (self.doppelganger != null) {
            self.registerAllValidatorsWithDoppelganger();
            log.info("doppelganger protection enabled — signing blocked until {d} clean epoch(s) observed", .{
                dopple_mod.DEFAULT_REMAINING_DETECTION_EPOCHS,
            });
            try self.startDoppelgangerTask();
        }
        errdefer self.stopDoppelgangerTask();

        try self.startHeaderTrackerTask();
        errdefer self.stopHeaderTrackerTask();

        if (self.config.external_signer_fetch_enabled and self.remote_signers.items.len > 0) {
            try self.startRemoteSignerSyncTask();
            errdefer self.stopRemoteSignerSyncTask();
        }

        var run_error: ?anyerror = null;
        self.clock.run(self.io) catch |err| {
            run_error = err;
        };

        // Graceful shutdown sequence.
        log.info("validator client stopping...", .{});

        self.stopRemoteSignerSyncTask();
        self.stopDoppelgangerTask();
        self.stopHeaderTrackerTask();

        // Note: slashing_db.close() is called by validator_store.deinit() — do NOT call it here.

        // Log session summary.
        const session_end_ns = time.awakeNanoseconds(self.io);
        const session_duration_s = (session_end_ns -| self.session_start_ns) / std.time.ns_per_s;
        const counts = self.validator_store.counts();
        log.info(
            "validator client stopped: session_duration={d}s validators={d} missed_blocks={d}",
            .{
                session_duration_s,
                counts.total,
                self.block_service.missed_block_count,
            },
        );
        self.liveness_tracker.logSummary();

        if (run_error) |err| return err;
    }

    // -----------------------------------------------------------------------
    // Clock callback trampolines
    // -----------------------------------------------------------------------

    fn onSlotRuntime(ctx: *anyopaque, slot: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        self.runSlotRuntime(slot) catch |err| {
            log.err("validator slot runtime slot={d} error={s}", .{ slot, @errorName(err) });
        };
    }

    fn onEpochRuntime(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        self.runEpochRuntime(epoch) catch |err| {
            log.err("validator epoch runtime epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    fn runSlotRuntime(self: *ValidatorClient, slot: u64) !void {
        // Poll BN readiness before any duty work in this slot fans out.
        self.syncing_tracker.onSlot(self.io, slot);

        var group: Io.Group = .init;
        errdefer group.cancel(self.io);

        try group.concurrent(self.io, runBlockServiceSlotTask, .{ self, slot });
        try group.concurrent(self.io, runAttestationServiceSlotTask, .{ self, slot });
        try group.concurrent(self.io, runSyncCommitteeServiceSlotTask, .{ self, slot });
        try group.await(self.io);
    }

    fn runEpochRuntime(self: *ValidatorClient, epoch: u64) !void {
        // Resolve indices first so epoch duty refreshes do not race stale mappings.
        self.index_tracker.onEpoch(self.io, epoch);
        self.applyResolvedIndices();

        if (self.api.primaryUrlUnhealthy() and self.api.failoverStatus().configured) {
            log.warn("primary beacon node is unhealthy; validator is relying on fallback URLs", .{});
        }

        self.liveness_tracker.logEpochSummary(
            epoch,
            self.validator_store.counts().total,
            self.block_service.missed_block_count,
        );

        var group: Io.Group = .init;
        errdefer group.cancel(self.io);

        try group.concurrent(self.io, runBlockServiceEpochTask, .{ self, epoch });
        try group.concurrent(self.io, runAttestationServiceEpochTask, .{ self, epoch });
        try group.concurrent(self.io, runSyncCommitteeServiceEpochTask, .{ self, epoch });
        try group.concurrent(self.io, runPrepareProposerEpochTask, .{ self, epoch });
        if (self.builder_registration != null) {
            try group.concurrent(self.io, runBuilderRegistrationEpochTask, .{ self, epoch });
        }
        try group.await(self.io);
    }

    fn runBlockServiceSlotTask(self: *ValidatorClient, slot: u64) Io.Cancelable!void {
        self.block_service.onSlot(self.io, slot);
    }

    fn runAttestationServiceSlotTask(self: *ValidatorClient, slot: u64) Io.Cancelable!void {
        self.attestation_service.onSlot(self.io, slot);
    }

    fn runSyncCommitteeServiceSlotTask(self: *ValidatorClient, slot: u64) Io.Cancelable!void {
        self.sync_committee_service.onSlot(self.io, slot);
    }

    fn runBlockServiceEpochTask(self: *ValidatorClient, epoch: u64) Io.Cancelable!void {
        self.block_service.onEpoch(self.io, epoch);
    }

    fn runAttestationServiceEpochTask(self: *ValidatorClient, epoch: u64) Io.Cancelable!void {
        self.attestation_service.onEpoch(self.io, epoch);
    }

    fn runSyncCommitteeServiceEpochTask(self: *ValidatorClient, epoch: u64) Io.Cancelable!void {
        self.sync_committee_service.onEpoch(self.io, epoch);
    }

    fn runPrepareProposerEpochTask(self: *ValidatorClient, epoch: u64) Io.Cancelable!void {
        self.prepare_proposer.onEpoch(self.io, epoch);
    }

    fn runBuilderRegistrationEpochTask(self: *ValidatorClient, epoch: u64) Io.Cancelable!void {
        if (self.builder_registration) |*br| {
            br.onEpoch(self.io, epoch);
        }
    }

    fn onResyncedDutyRefresh(ctx: *anyopaque, slot: u64, io: Io) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));

        // Epoch-boundary work is already scheduled by the clock.
        if (slot % self.config.slots_per_epoch == 0) return;

        self.index_tracker.resolveIndices(io) catch |err| {
            log.warn("resynced index resolution failed: {s}", .{@errorName(err)});
        };
        self.applyResolvedIndices();

        const epoch = slot / self.config.slots_per_epoch;
        self.block_service.onEpoch(io, epoch);
        self.attestation_service.onEpoch(io, epoch);
        self.sync_committee_service.onEpoch(io, epoch);
    }

    /// Returns true if it is safe to sign for the given pubkey.
    ///
    /// Checks both:
    ///   1. Syncing status — BN is synced enough.
    ///   2. Doppelganger protection — no duplicate detected.
    ///
    /// Called by all services before signing operations.
    pub fn isSafeToSign(self: *const ValidatorClient, pubkey: [48]u8) bool {
        if (!self.syncing_tracker.isSynced()) return false;
        if (self.doppelganger) |*d| {
            if (!d.isSigningAllowed(pubkey)) return false;
        }
        return true;
    }

    fn addRemoteSignerKeys(self: *ValidatorClient, remote_signer_keys: RemoteSignerKeys) !void {
        const signer = try self.ensureRemoteSigner(remote_signer_keys.url);
        for (remote_signer_keys.pubkeys) |pubkey| {
            try self.validator_store.addRemotePubkey(pubkey, signer);
            try self.registerValidatorTracking(pubkey);
        }
        self.syncValidatorMetrics();
    }

    fn remoteSignerSyncIntervalNs(self: *const ValidatorClient) u64 {
        const interval_ms = self.config.external_signer_fetch_interval_ms orelse
            (self.config.slots_per_epoch * self.config.seconds_per_slot * std.time.ms_per_s);
        return interval_ms * std.time.ns_per_ms;
    }

    fn doppelgangerCheckTimeNs(self: *const ValidatorClient, epoch: u64) u64 {
        const last_slot = state_transition.computeStartSlotAtEpoch(epoch + 1) - 1;
        const slot_duration_ns = self.config.seconds_per_slot * std.time.ns_per_s;
        return self.config.genesis_time * std.time.ns_per_s +
            last_slot * slot_duration_ns +
            (3 * slot_duration_ns) / 4;
    }

    fn sleepInterruptiblyNs(self: *ValidatorClient, duration_ns: u64) !void {
        var remaining_ns = duration_ns;
        const sleep_slice_ns = std.time.ns_per_s;
        while (remaining_ns > 0 and !self.shutdown_requested.load(.acquire)) {
            const this_sleep = @min(remaining_ns, sleep_slice_ns);
            try self.io.sleep(.{ .nanoseconds = this_sleep }, .awake);
            remaining_ns -= this_sleep;
        }
    }

    fn runDoppelgangerTask(self: *ValidatorClient) anyerror!void {
        var last_checked_epoch: ?u64 = null;

        while (!self.shutdown_requested.load(.acquire)) {
            const current_epoch = self.clock.currentEpoch(self.io);

            if (last_checked_epoch != null and current_epoch <= last_checked_epoch.?) {
                const current_slot = self.clock.currentSlot(self.io);
                try self.sleepInterruptiblyNs(self.clock.nsUntilSlot(self.io, current_slot + 1));
                continue;
            }

            const target_ns = self.doppelgangerCheckTimeNs(current_epoch);
            const now_ns = time.realNanoseconds(self.io);
            if (now_ns < target_ns) {
                try self.sleepInterruptiblyNs(target_ns - now_ns);
                continue;
            }

            if (self.shutdown_requested.load(.acquire)) return;
            if (self.clock.currentEpoch(self.io) != current_epoch) continue;

            if (self.doppelganger) |*d| {
                d.pollLivenessForEpoch(self.io, current_epoch) catch |err| switch (err) {
                    error.DoppelgangerDetected => {},
                    else => log.warn("doppelganger check failed epoch={d}: {s}", .{ current_epoch, @errorName(err) }),
                };
            }
            last_checked_epoch = current_epoch;
        }
    }

    fn startDoppelgangerTask(self: *ValidatorClient) !void {
        std.debug.assert(self.doppelganger_task == null);
        self.doppelganger_task = try self.io.concurrent(runDoppelgangerTask, .{self});
    }

    fn stopDoppelgangerTask(self: *ValidatorClient) void {
        if (self.doppelganger_task) |*task| {
            _ = task.cancel(self.io) catch |err| switch (err) {
                error.Canceled => {},
                else => log.warn("doppelganger task exited during shutdown: {s}", .{@errorName(err)}),
            };
            self.doppelganger_task = null;
        }
    }

    fn runHeaderTrackerTask(self: *ValidatorClient) anyerror!void {
        try self.header_tracker.start(self.io);
    }

    fn startHeaderTrackerTask(self: *ValidatorClient) !void {
        std.debug.assert(self.header_tracker_task == null);
        self.header_tracker_task = try self.io.concurrent(runHeaderTrackerTask, .{self});
        log.info("ChainHeaderTracker SSE subscription started as concurrent std.Io task", .{});
    }

    fn stopHeaderTrackerTask(self: *ValidatorClient) void {
        self.header_tracker.requestShutdown();
        if (self.header_tracker_task) |*task| {
            _ = task.cancel(self.io) catch |err| switch (err) {
                error.Canceled => {},
                else => log.warn("chain header tracker task exited during shutdown: {s}", .{@errorName(err)}),
            };
            self.header_tracker_task = null;
        }
    }

    fn runRemoteSignerSyncTask(self: *ValidatorClient) anyerror!void {
        const interval_ns = self.remoteSignerSyncIntervalNs();
        const sleep_slice_ns = std.time.ns_per_s;

        while (!self.shutdown_requested.load(.acquire)) {
            var remaining_ns = interval_ns;
            while (remaining_ns > 0 and !self.shutdown_requested.load(.acquire)) {
                const this_sleep = @min(remaining_ns, sleep_slice_ns);
                try self.io.sleep(.{ .nanoseconds = this_sleep }, .real);
                remaining_ns -= this_sleep;
            }

            if (self.shutdown_requested.load(.acquire)) return;

            self.syncRemoteSignerKeys(self.io) catch |err| {
                log.warn("remote signer sync failed: {s}", .{@errorName(err)});
            };
        }
    }

    fn startRemoteSignerSyncTask(self: *ValidatorClient) !void {
        std.debug.assert(self.remote_signer_sync_task == null);
        self.remote_signer_sync_task = try self.io.concurrent(runRemoteSignerSyncTask, .{self});
    }

    fn stopRemoteSignerSyncTask(self: *ValidatorClient) void {
        if (self.remote_signer_sync_task) |*task| {
            _ = task.cancel(self.io) catch |err| switch (err) {
                error.Canceled => {},
                else => log.warn("remote signer sync task exited during shutdown: {s}", .{@errorName(err)}),
            };
            self.remote_signer_sync_task = null;
        }
    }
};
