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

const key_discovery_mod = @import("key_discovery.zig");
const KeyDiscovery = key_discovery_mod.KeyDiscovery;

const remote_signer_mod = @import("remote_signer.zig");
const RemoteSigner = remote_signer_mod.RemoteSigner;

const syncing_tracker_mod = @import("syncing_tracker.zig");
const SyncingTracker = syncing_tracker_mod.SyncingTracker;

const index_tracker_mod = @import("index_tracker.zig");
const IndexTracker = index_tracker_mod.IndexTracker;

const liveness_mod = @import("liveness.zig");
const LivenessTracker = liveness_mod.LivenessTracker;

const interchange_mod = @import("interchange.zig");

const log = std.log.scoped(.validator_client);

/// Default fee recipient (zero address) — operator should override.
const ZERO_FEE_RECIPIENT = "0x0000000000000000000000000000000000000000".*;

// ---------------------------------------------------------------------------
// ValidatorClient
// ---------------------------------------------------------------------------

pub const ValidatorClient = struct {
    allocator: Allocator,
    config: ValidatorConfig,

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

    // I/O context — stored so clock callbacks can make HTTP calls.
    // Set in start() before the run loop begins.
    io: ?std.Io,

    // Index tracker — resolves pubkey → validator index mappings.
    index_tracker: IndexTracker,

    // Liveness tracker — records per-validator duty outcomes.
    liveness_tracker: LivenessTracker,

    // Syncing tracker — pauses duties when BN sync distance is too large.
    syncing_tracker: SyncingTracker,

    // Shutdown requested flag — set on signal, stops the clock loop.
    shutdown_requested: std.atomic.Value(bool),

    // Session stats.
    session_start_ns: u64,

    /// Heap-allocated remote signer (web3signer). Null if not configured.
    remote_signer: ?*RemoteSigner = null,

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
    pub fn init(allocator: Allocator, config: ValidatorConfig, signing_ctx: SigningContext) !ValidatorClient {
        // Initialize API client — use multi-BN if fallback URLs provided.
        var api = if (config.beacon_node_fallback_urls.len > 0) blk: {
            // Build combined URL slice: [primary] ++ fallbacks.
            // NOTE: caller owns config memory; we borrow the slices.
            break :blk BeaconApiClient{
                .allocator = allocator,
                .base_url = config.beacon_node_url,
                .fallback_urls = config.beacon_node_fallback_urls,
                .active_url_idx = 0,
                .consecutive_failures = 0,
                .was_unreachable = false,
                .unreachable_since_ns = 0,
            };
        } else BeaconApiClient.init(allocator, config.beacon_node_url);
        var validator_store = try ValidatorStore.init(allocator, config.slashing_protection_path);
        errdefer validator_store.deinit();

        const clock = ValidatorSlotTicker.init(
            config.genesis_time,
            config.seconds_per_slot,
            config.slots_per_epoch,
        );

        // We use pointer-to-field for service references.
        // Pointers are stable because ValidatorClient is heap-allocated by the caller.
        // NOTE: Services store *BeaconApiClient and *ValidatorStore by pointer.
        //       These fields must not move after init; the client must be stable.
        //       Pass &vc.api / &vc.validator_store after heap-allocating if needed.

        const block_service = BlockService.init(allocator, &api, &validator_store, signing_ctx, config.slots_per_epoch, config.builder_boost_factor);
        const attestation_service = AttestationService.init(
            allocator,
            &api,
            &validator_store,
            signing_ctx,
            config.seconds_per_slot,
            config.genesis_time, // BUG-5 fix: pass genesis_time for correct sub-slot timing
        );
        const sync_committee_service = SyncCommitteeService.init(
            allocator,
            &api,
            &validator_store,
            signing_ctx,
            config.slots_per_epoch,
            config.epochs_per_sync_committee_period,
            config.sync_committee_size,
            config.sync_committee_subnet_count,
            config.seconds_per_slot,
            config.genesis_time, // BUG-5 fix: pass genesis_time for correct sub-slot timing
        );

        const header_tracker = ChainHeaderTracker.init(allocator, &api);

        const prepare_proposer = PrepareBeaconProposerService.init(
            allocator,
            &api,
            &validator_store,
            ZERO_FEE_RECIPIENT,
        );

        // Initialize builder registration service if builder is configured.
        const builder_registration: ?BuilderRegistrationService = if (config.builder_url != null)
            BuilderRegistrationService.init(
                allocator,
                &api,
                &validator_store,
                config.suggested_fee_recipient,
                config.gas_limit,
            )
        else
            null;

        const doppelganger: ?DoppelgangerService = if (config.doppelganger_protection)
            DoppelgangerService.init(allocator, &api)
        else
            null;

        // Load validator keys from disk if keystores_dir and secrets_dir are configured.
        var loaded_count: usize = 0;
        if (config.keystores_dir) |ks_dir| {
            if (config.secrets_dir) |sec_dir| {
                const loaded_keys = try KeyDiscovery.loadAllKeys(allocator, ks_dir, sec_dir);
                defer {
                    for (loaded_keys) |k| k.deinit(allocator);
                    allocator.free(loaded_keys);
                }
                for (loaded_keys) |k| {
                    try validator_store.addKey(k.secret_key);
                    if (doppelganger) |*d| {
                        try d.registerValidator(k.pubkey);
                    }
                    loaded_count += 1;
                }
            }
        }
        log.info("validator keys loaded from disk: {d}", .{loaded_count});

        // Import EIP-3076 slashing protection interchange if configured.
        // This must happen before any signing, so we do it during init().
        // TS: equivalent to --slashingProtection flag feeding importInterchange().
        if (config.interchange_import_path) |ipath| {
            const interchange_data = std.fs.cwd().readFileAlloc(allocator, ipath, 16 * 1024 * 1024) catch |err| blk: {
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
                        // Feed highest signed block slot into slashing DB.
                        if (rec.last_signed_block_slot) |slot| {
                            _ = validator_store.slashing_db.checkAndInsertBlock(rec.pubkey, slot) catch {};
                            imported_count += 1;
                        }
                        // Feed highest signed attestation epochs into slashing DB.
                        if (rec.last_signed_attestation_source_epoch) |src| {
                            if (rec.last_signed_attestation_target_epoch) |tgt| {
                                _ = validator_store.slashing_db.checkAndInsertAttestation(
                                    rec.pubkey, src, tgt,
                                ) catch {};
                            }
                        }
                    }
                    log.info("imported interchange: {d} validator records from {s}", .{ imported_count, ipath });
                }
            }
        }

        var idx_tracker = IndexTracker.init(allocator, &api);
        var live_tracker = LivenessTracker.init(allocator);

        // Register all loaded keys in the index tracker and liveness tracker.
        for (validator_store.validators.items) |v| {
            idx_tracker.trackPubkey(v.pubkey);
            live_tracker.register(v.pubkey);
        }

        return .{
            .allocator = allocator,
            .config = config,
            .clock = clock,
            .api = api,
            .validator_store = validator_store,
            .header_tracker = header_tracker,
            .block_service = block_service,
            .attestation_service = attestation_service,
            .sync_committee_service = sync_committee_service,
            .prepare_proposer = prepare_proposer,
            .builder_registration = builder_registration,
            .doppelganger = doppelganger,
            .io = null,
            .index_tracker = idx_tracker,
            .liveness_tracker = live_tracker,
            .syncing_tracker = SyncingTracker.init(allocator, &api),
            .shutdown_requested = std.atomic.Value(bool).init(false),
            .session_start_ns = @intCast(std.time.nanoTimestamp()),
        };
    }

    pub fn deinit(self: *ValidatorClient) void {
        self.block_service.deinit();
        self.attestation_service.deinit();
        self.sync_committee_service.deinit();
        if (self.builder_registration) |*br| br.deinit();
        if (self.doppelganger) |*d| d.deinit();
        self.index_tracker.deinit();
        self.liveness_tracker.deinit();
        self.validator_store.deinit();
        self.api.deinit();
        // Free the heap-allocated RemoteSigner if web3signer was configured.
        if (self.remote_signer) |rs| self.allocator.destroy(rs);
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

    /// Add a validator secret key to the store.
    ///
    /// Must be called before `start()`.
    pub fn addKey(self: *ValidatorClient, secret_key: bls.SecretKey) !void {
        try self.validator_store.addKey(secret_key);
        const pk = secret_key.toPublicKey();
        const pk_bytes = pk.compress();
        if (self.doppelganger) |*d| {
            try d.registerValidator(pk_bytes);
        }
        // Track in index tracker and liveness tracker.
        self.index_tracker.trackPubkey(pk_bytes);
        self.liveness_tracker.register(pk_bytes);
    }

    /// Re-wire all service api/store pointers to stable fields of this ValidatorClient.
    ///
    /// Must be called after the ValidatorClient is placed at a stable memory address
    /// (i.e., heap-allocated by the caller). start() calls this automatically.
    ///
    /// BUG-1 Fix: init() captures &api / &validator_store as local variable addresses.
    /// Once the caller assigns the returned struct to heap memory, those local addresses
    /// are stale. This method updates all service pointers to &self.api and &self.validator_store.
    pub fn wireServices(self: *ValidatorClient) void {
        self.block_service.api = &self.api;
        self.block_service.validator_store = &self.validator_store;
        self.attestation_service.api = &self.api;
        self.attestation_service.validator_store = &self.validator_store;
        self.sync_committee_service.api = &self.api;
        self.sync_committee_service.validator_store = &self.validator_store;
        self.header_tracker.api = &self.api;
        self.prepare_proposer.api = &self.api;
        self.prepare_proposer.validator_store = &self.validator_store;
        if (self.builder_registration) |*br| {
            br.api = &self.api;
            br.validator_store = &self.validator_store;
            br.remote_signer = self.remote_signer;
        }
        if (self.doppelganger) |*d| {
            d.api = &self.api;
        }
        self.index_tracker.api = &self.api;
        self.syncing_tracker.api = &self.api;
    }

    /// Start the validator client: wire up clock callbacks and enter the run loop.
    ///
    /// Blocks until error or explicit stop.
    ///
    /// TS: clock.start(signal) → runs all registered fns in background.
    pub fn start(self: *ValidatorClient, io: Io) !void {
        log.info("starting validator client beacon_node={s}", .{self.config.beacon_node_url});

        // BUG-1 Fix: Re-wire service pointers to stable self fields.
        // init() captures pointers to locals; now that self is at a stable address
        // (heap-allocated by the caller), update all service api/store pointers.
        self.wireServices();

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

        // Register clock callbacks.
        self.clock.onSlot(.{ .ctx = self, .fn_ptr = onSlotBlockService });
        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochBlockService });

        self.clock.onSlot(.{ .ctx = self, .fn_ptr = onSlotAttestationService });
        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochAttestationService });

        self.clock.onSlot(.{ .ctx = self, .fn_ptr = onSlotSyncCommitteeService });
        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochSyncCommitteeService });

        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochPrepareProposer });

        if (self.builder_registration != null) {
            self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochBuilderRegistration });
        }

        if (self.doppelganger) |*d| {
            self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochDoppelganger });
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

        // Syncing status tracker — poll every slot, gate signing when BN is behind.
        self.clock.onSlot(.{ .ctx = self, .fn_ptr = onSlotSyncingTracker });

        // Store io so clock callbacks can perform HTTP requests.
        self.io = io;

        // Resolve validator indices at startup.
        // This is required before duties can be fetched (duties use validator index, not pubkey).
        //
        // TS: IndicesService.pollValidatorIndices() on startup.
        log.info("resolving validator indices at startup", .{});
        self.index_tracker.resolveIndices(io) catch |err| {
            log.warn("startup index resolution failed: {s} — will retry on first epoch", .{@errorName(err)});
        };

        // Apply resolved indices to the validator store.
        for (self.index_tracker.entries.items) |e| {
            if (e.index) |idx| {
                self.validator_store.updateIndex(e.pubkey, idx, .active_ongoing);
            }
        }

        // Wire index tracker epoch callback.
        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochIndexTracker });

        // Doppelganger startup: if enabled, validators start as Unverified and cannot sign.
        // The doppelganger service checks liveness each epoch and promotes to VerifiedSafe
        // after DEFAULT_REMAINING_DETECTION_EPOCHS clean epochs.
        //
        // TS: DoppelgangerService.pollLiveness — runs on each epoch, blocks signing until safe.
        if (self.doppelganger) |*d| {
            // Register all validators that don't have indices yet.
            for (self.validator_store.validators.items) |v| {
                d.registerValidator(v.pubkey) catch |err| {
                    log.warn("doppelganger registerValidator error: {s}", .{@errorName(err)});
                };
                // Apply resolved index if available.
                if (self.index_tracker.getIndex(v.pubkey)) |idx| {
                    for (d.entries.items) |*de| {
                        if (std.mem.eql(u8, &de.pubkey, &v.pubkey)) {
                            de.index = idx;
                            break;
                        }
                    }
                }
            }
            log.info("doppelganger protection enabled — signing blocked until {d} clean epoch(s) observed", .{
                dopple_mod.DEFAULT_REMAINING_DETECTION_EPOCHS,
            });
        }

        // Fetch remote signer keys if web3signer is configured.
        // Create a heap-allocated RemoteSigner so the pointer remains stable after
        // ValidatorClient may be moved. Wire it into ValidatorStore for signing delegation.
        if (self.config.web3signer_url) |url| {
            log.info("fetching remote keys from web3signer url={s}", .{url});

            // Heap-allocate so the pointer is stable for the lifetime of ValidatorClient.
            const rs = try self.allocator.create(RemoteSigner);
            rs.* = RemoteSigner.init(self.allocator, url);
            self.remote_signer = rs;
            // Wire into validator_store so signing methods can delegate.
            self.validator_store.remote_signer = rs;

            const remote_pubkeys = rs.listKeys(io) catch |err| blk: {
                log.warn("failed to fetch remote keys: {s}", .{@errorName(err)});
                break :blk &[_][48]u8{};
            };
            defer if (remote_pubkeys.len > 0) self.allocator.free(remote_pubkeys);
            var remote_registered: usize = 0;
            for (remote_pubkeys) |pk| {
                // Register the pubkey in the validator store as remote-only.
                // Duty tracking (indices, attestation duties, etc.) works without
                // the secret key locally. Signing is delegated via remote_signer.
                self.validator_store.addRemotePubkey(pk) catch |err| {
                    log.warn("addRemotePubkey failed pubkey=0x{s}: {s}", .{
                        std.fmt.bytesToHex(pk, .lower), @errorName(err),
                    });
                    continue;
                };
                if (self.doppelganger) |*d| {
                    d.registerValidator(pk) catch {};
                }
                self.index_tracker.trackPubkey(pk);
                self.liveness_tracker.register(pk);
                remote_registered += 1;
                log.info("registered remote validator pubkey=0x{s}", .{std.fmt.bytesToHex(pk, .lower)});
            }
            log.info("fetched {d} remote validator keys from web3signer ({d} registered)", .{
                remote_pubkeys.len, remote_registered,
            });
        }

        // Start ChainHeaderTracker SSE subscription in a background thread.
        // The SSE stream provides head events for reorg detection and sync committee
        // block root tracking. We start it here so it runs concurrently with the clock loop.
        //
        // The thread receives a copy of io (std.Io is a pointer/handle, safe to copy).
        // If the SSE stream fails, the thread logs the error and exits — the VC
        // continues without head tracking (using fallback zero block root for sync committee).
        //
        // TODO(fix-8): For Zig 0.16 full evented I/O, migrate to io.spawn() once
        //     the evented fiber API stabilises. For now, std.Thread is sufficient.
        const SseThreadCtx = struct {
            tracker: *chain_header_mod.ChainHeaderTracker,
            io: Io,
        };
        const sse_ctx = try self.allocator.create(SseThreadCtx);
        sse_ctx.* = .{ .tracker = &self.header_tracker, .io = io };
        const sse_thread = std.Thread.spawn(.{}, struct {
            fn run(ctx: *SseThreadCtx) void {
                ctx.tracker.start(ctx.io) catch |err| {
                    log.warn("ChainHeaderTracker SSE stream ended: {s}", .{@errorName(err)});
                };
            }
        }.run, .{sse_ctx}) catch |err| blk: {
            log.warn("failed to start ChainHeaderTracker SSE thread: {s}", .{@errorName(err)});
            self.allocator.destroy(sse_ctx);
            break :blk null;
        };
        if (sse_thread) |t| {
            t.detach(); // Let it run independently; VC shutdown will kill the process.
            log.info("ChainHeaderTracker SSE subscription started in background thread", .{});
        }

        // Run the clock loop (blocking until shutdown or error).
        try self.clock.run(io);

        // Graceful shutdown sequence.
        log.info("validator client stopping...", .{});

        // Flush slashing protection DB.
        self.validator_store.slashing_db.close();

        // Log session summary.
        const session_end_ns: u64 = @intCast(std.time.nanoTimestamp());
        const session_duration_s = (session_end_ns -| self.session_start_ns) / std.time.ns_per_s;
        log.info(
            "validator client stopped: session_duration={d}s validators={d} missed_blocks={d}",
            .{
                session_duration_s,
                self.validator_store.validators.items.len,
                self.block_service.missed_block_count,
            },
        );
        self.liveness_tracker.logSummary();
    }

    // -----------------------------------------------------------------------
    // Clock callback trampolines
    // -----------------------------------------------------------------------

    fn onSlotBlockService(ctx: *anyopaque, slot: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.block_service.onSlot(io, slot);
    }

    fn onEpochBlockService(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.block_service.onEpoch(io, epoch);
    }

    fn onSlotAttestationService(ctx: *anyopaque, slot: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.attestation_service.onSlot(io, slot);
    }

    fn onEpochAttestationService(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.attestation_service.onEpoch(io, epoch);
    }

    fn onSlotSyncCommitteeService(ctx: *anyopaque, slot: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.sync_committee_service.onSlot(io, slot);
    }

    fn onEpochSyncCommitteeService(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.sync_committee_service.onEpoch(io, epoch);
    }

    fn onEpochPrepareProposer(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.prepare_proposer.onEpoch(io, epoch);
    }

    fn onEpochBuilderRegistration(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        if (self.builder_registration) |*br| {
            br.onEpoch(io, epoch);
        }
    }

    fn onEpochDoppelganger(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        if (self.doppelganger) |*d| {
            d.onEpoch(io, epoch);
        }
    }

    fn onEpochIndexTracker(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.index_tracker.onEpoch(io, epoch);

        // Apply any newly resolved indices to the validator store.
        for (self.index_tracker.entries.items) |e| {
            if (e.index) |idx| {
                self.validator_store.updateIndex(e.pubkey, idx, .active_ongoing);
            }
        }

        // Emit epoch effectiveness summary.
        self.liveness_tracker.logEpochSummary(
            epoch,
            self.validator_store.validators.items.len,
            self.block_service.missed_block_count,
        );
    }

    fn onSlotSyncingTracker(ctx: *anyopaque, slot: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        self.syncing_tracker.onSlot(io, slot);
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
};
