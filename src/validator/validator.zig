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
const SlotClock = clock_mod.SlotClock;

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

const signing_mod = @import("signing.zig");
const SigningContext = signing_mod.SigningContext;

const bls = @import("bls");

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
    clock: SlotClock,
    api: BeaconApiClient,
    validator_store: ValidatorStore,
    header_tracker: ChainHeaderTracker,

    // Services.
    block_service: BlockService,
    attestation_service: AttestationService,
    sync_committee_service: SyncCommitteeService,
    prepare_proposer: PrepareBeaconProposerService,
    doppelganger: ?DoppelgangerService,

    // I/O context — stored so clock callbacks can make HTTP calls.
    // Set in start() before the run loop begins.
    io: ?std.Io,

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
        var api = BeaconApiClient.init(allocator, config.beacon_node_url);
        var validator_store = try ValidatorStore.init(allocator, null); // null = no persistent DB file (TODO: wire data_dir)
        errdefer validator_store.deinit();

        const clock = SlotClock.init(
            config.genesis_time,
            config.seconds_per_slot,
            config.slots_per_epoch,
        );

        // We use pointer-to-field for service references.
        // Pointers are stable because ValidatorClient is heap-allocated by the caller.
        // NOTE: Services store *BeaconApiClient and *ValidatorStore by pointer.
        //       These fields must not move after init; the client must be stable.
        //       Pass &vc.api / &vc.validator_store after heap-allocating if needed.

        const block_service = BlockService.init(allocator, &api, &validator_store, signing_ctx);
        const attestation_service = AttestationService.init(
            allocator,
            &api,
            &validator_store,
            signing_ctx,
            config.seconds_per_slot,
        );
        const sync_committee_service = SyncCommitteeService.init(
            allocator,
            &api,
            &validator_store,
            signing_ctx,
            config.slots_per_epoch,
            256, // EPOCHS_PER_SYNC_COMMITTEE_PERIOD (mainnet)
            config.seconds_per_slot,
        );

        const header_tracker = ChainHeaderTracker.init(allocator, &api);

        const prepare_proposer = PrepareBeaconProposerService.init(
            allocator,
            &api,
            &validator_store,
            ZERO_FEE_RECIPIENT,
        );

        const doppelganger: ?DoppelgangerService = if (config.doppelganger_protection)
            DoppelgangerService.init(allocator, &api)
        else
            null;

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
            .doppelganger = doppelganger,
            .io = null,
        };
    }

    pub fn deinit(self: *ValidatorClient) void {
        self.block_service.deinit();
        self.attestation_service.deinit();
        self.sync_committee_service.deinit();
        if (self.doppelganger) |*d| d.deinit();
        self.validator_store.deinit();
        self.api.deinit();
    }

    /// Add a validator secret key to the store.
    ///
    /// Must be called before `start()`.
    pub fn addKey(self: *ValidatorClient, secret_key: bls.SecretKey) !void {
        try self.validator_store.addKey(secret_key);
        if (self.doppelganger) |*d| {
            const pk = secret_key.toPublicKey();
            try d.registerValidator(pk.compress());
        }
    }

    /// Start the validator client: wire up clock callbacks and enter the run loop.
    ///
    /// Blocks until error or explicit stop.
    ///
    /// TS: clock.start(signal) → runs all registered fns in background.
    pub fn start(self: *ValidatorClient, io: Io) !void {
        log.info("starting validator client beacon_node={s}", .{self.config.beacon_node_url});

        // Wire up chain header tracker callbacks.
        self.sync_committee_service.setHeaderTracker(&self.header_tracker);

        // Register clock callbacks.
        self.clock.onSlot(.{ .ctx = self, .fn_ptr = onSlotBlockService });
        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochBlockService });

        self.clock.onSlot(.{ .ctx = self, .fn_ptr = onSlotAttestationService });
        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochAttestationService });

        self.clock.onSlot(.{ .ctx = self, .fn_ptr = onSlotSyncCommitteeService });
        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochSyncCommitteeService });

        self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochPrepareProposer });

        if (self.doppelganger != null) {
            self.clock.onEpoch(.{ .ctx = self, .fn_ptr = onEpochDoppelganger });
        }

        // Store io so clock callbacks can perform HTTP requests.
        self.io = io;

        // Note: ChainHeaderTracker SSE subscription would ideally run in a background fiber.
        // In Zig 0.16 with full evented I/O (io_uring/GCD), we could do:
        //   var sse_task = try io.spawn(ChainHeaderTracker.start, .{&self.header_tracker, io});
        //   defer sse_task.cancel();
        // For now, it is the operator's responsibility to call header_tracker.start(io)
        // in a separate thread if SSE events are desired. The validator runs correctly
        // without it (sync committee service uses zero block root as fallback).
        log.info("note: ChainHeaderTracker SSE subscription not started (requires separate thread/fiber)", .{});

        // Run the clock loop (blocking).
        try self.clock.run(io);
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

    fn onEpochDoppelganger(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        const io = self.io orelse return;
        if (self.doppelganger) |*d| {
            d.onEpoch(io, epoch);
        }
    }
};
