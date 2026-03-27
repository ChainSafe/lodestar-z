//! Main Validator Client entry point.
//!
//! Coordinates the slot clock, service instances, and API client lifecycle.
//! Mirrors the TypeScript Validator class in packages/validator/src/validator.ts.
//!
//! Architecture:
//!
//!   ValidatorClient
//!     ├── SlotClock          — computes slots, fires callbacks
//!     ├── BeaconApiClient    — HTTP calls + SSE stream to BN
//!     ├── ValidatorStore     — BLS keys + slashing protection
//!     ├── BlockService       — block proposal duties
//!     ├── AttestationService — attester duties + aggregation
//!     ├── SyncCommitteeService — sync committee duties + contributions
//!     └── DoppelgangerService  — duplicate validator detection
//!
//! I/O model (Zig 0.16):
//!   All blocking I/O uses std.Io (evented I/O via io_uring on Linux / GCD on macOS).
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

const bls = @import("bls");

const log = std.log.scoped(.validator_client);

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

    // Services.
    block_service: BlockService,
    attestation_service: AttestationService,
    sync_committee_service: SyncCommitteeService,
    doppelganger: ?DoppelgangerService,

    // ---------------------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------------------

    /// Create and initialise the ValidatorClient.
    ///
    /// Does NOT start the clock or subscribe to SSE events.
    /// Call `start()` after adding validator keys.
    ///
    /// TS: Validator.init(opts, genesis)
    pub fn init(allocator: Allocator, config: ValidatorConfig) !ValidatorClient {
        const api = BeaconApiClient.init(allocator, config.beacon_node_url);
        var validator_store = ValidatorStore.init(allocator);

        const clock = SlotClock.init(
            config.genesis_time,
            config.seconds_per_slot,
            config.slots_per_epoch,
        );

        const block_service = BlockService.init(allocator, undefined, &validator_store);
        const attestation_service = AttestationService.init(
            allocator,
            undefined,
            &validator_store,
            config.seconds_per_slot,
        );
        // mainnet: EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256
        const sync_committee_service = SyncCommitteeService.init(
            allocator,
            undefined,
            &validator_store,
            config.slots_per_epoch,
            256,
        );

        const doppelganger: ?DoppelgangerService = if (config.doppelganger_protection)
            DoppelgangerService.init(allocator, undefined)
        else
            null;

        return .{
            .allocator = allocator,
            .config = config,
            .clock = clock,
            .api = api,
            .validator_store = validator_store,
            .block_service = block_service,
            .attestation_service = attestation_service,
            .sync_committee_service = sync_committee_service,
            .doppelganger = doppelganger,
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
    ///
    /// TS: ValidatorStore.init(opts, signers, ...)
    pub fn addKey(self: *ValidatorClient, secret_key: bls.SecretKey) !void {
        try self.validator_store.addKey(secret_key);
        if (self.doppelganger) |*d| {
            const pk = secret_key.toPublicKey();
            try d.registerValidator(pk.compress());
        }
    }

    /// Start the validator client: wire up clock callbacks and enter the run loop.
    ///
    /// Blocks until error or explicit stop (future: cancellation token).
    ///
    /// TS: clock.start(signal) → runs all registered fns in background
    pub fn start(self: *ValidatorClient, io: Io) !void {
        log.info("starting validator client beacon_node={s}", .{self.config.beacon_node_url});

        // Register clock callbacks.
        // Each service gets both a slot callback and an epoch callback.

        // Block service.
        self.clock.onSlot(.{
            .ctx = self,
            .fn_ptr = onSlotBlockService,
        });
        self.clock.onEpoch(.{
            .ctx = self,
            .fn_ptr = onEpochBlockService,
        });

        // Attestation service.
        self.clock.onSlot(.{
            .ctx = self,
            .fn_ptr = onSlotAttestationService,
        });
        self.clock.onEpoch(.{
            .ctx = self,
            .fn_ptr = onEpochAttestationService,
        });

        // Sync committee service.
        self.clock.onSlot(.{
            .ctx = self,
            .fn_ptr = onSlotSyncCommitteeService,
        });
        self.clock.onEpoch(.{
            .ctx = self,
            .fn_ptr = onEpochSyncCommitteeService,
        });

        // Doppelganger service (epoch only).
        if (self.doppelganger != null) {
            self.clock.onEpoch(.{
                .ctx = self,
                .fn_ptr = onEpochDoppelganger,
            });
        }

        // Subscribe to SSE head events (drives chain header tracker).
        // TODO: spawn async task to call api.subscribeToEvents(["head", "block"], headCallback).

        // Run the clock loop (blocking).
        try self.clock.run(io);
    }

    // -----------------------------------------------------------------------
    // Clock callback trampolines
    // -----------------------------------------------------------------------
    //
    // Zig doesn't have closures, so we use a pointer-to-self pattern.
    // The callback fn_ptr receives `*anyopaque` which we cast back to `*ValidatorClient`.

    fn onSlotBlockService(ctx: *anyopaque, slot: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        // We need io here — in the full implementation the clock passes io through.
        // For now this is a stub: the run loop will need to thread io through callbacks.
        // TODO: pass Io through callback context.
        _ = self;
        _ = slot;
    }

    fn onEpochBlockService(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = epoch;
    }

    fn onSlotAttestationService(ctx: *anyopaque, slot: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = slot;
    }

    fn onEpochAttestationService(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = epoch;
    }

    fn onSlotSyncCommitteeService(ctx: *anyopaque, slot: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = slot;
    }

    fn onEpochSyncCommitteeService(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = epoch;
    }

    fn onEpochDoppelganger(ctx: *anyopaque, epoch: u64) void {
        const self: *ValidatorClient = @ptrCast(@alignCast(ctx));
        _ = self;
        _ = epoch;
    }
};
