//! Prepare beacon proposer service for the Validator Client.
//!
//! Periodically registers fee recipients with the Beacon Node via
//! POST /eth/v1/validator/prepare_beacon_proposer.
//!
//! Must run once per epoch (or at startup) to ensure the BN knows which
//! execution address to use when building blocks for our validators.
//!
//! TS equivalent: packages/validator/src/services/prepareBeaconProposer.ts
//!               pollPrepareBeaconProposer()

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const api_client = @import("api_client.zig");
const BeaconApiClient = api_client.BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;

const log = std.log.scoped(.prepare_beacon_proposer);

// ---------------------------------------------------------------------------
// FeeRecipientEntry
// ---------------------------------------------------------------------------

/// A single validator index → fee recipient address mapping.
/// Used to build the JSON payload for the BN.
pub const FeeRecipientEntry = struct {
    /// Validator index on the beacon chain.
    validator_index: u64,
    /// Ethereum execution-layer fee recipient address (20 bytes, hex with 0x prefix).
    fee_recipient: [42]u8, // "0x" + 40 hex chars
};

// ---------------------------------------------------------------------------
// PrepareBeaconProposerService
// ---------------------------------------------------------------------------

pub const PrepareBeaconProposerService = struct {
    allocator: Allocator,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,

    /// Default fee recipient address used when no per-validator override exists.
    default_fee_recipient: [42]u8,

    /// Per-validator override map: validator_index → fee_recipient.
    /// Managed externally; pointer is borrowed (not owned).
    overrides: ?*const std.AutoHashMap(u64, [42]u8),

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        default_fee_recipient: [42]u8,
    ) PrepareBeaconProposerService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .default_fee_recipient = default_fee_recipient,
            .overrides = null,
        };
    }

    /// Set per-validator fee recipient overrides.
    ///
    /// The map lifetime must exceed the service lifetime.
    pub fn setOverrides(self: *PrepareBeaconProposerService, overrides: *const std.AutoHashMap(u64, [42]u8)) void {
        self.overrides = overrides;
    }

    // -----------------------------------------------------------------------
    // Clock callback
    // -----------------------------------------------------------------------

    /// Called once per epoch to register fee recipients.
    ///
    /// TS: pollPrepareBeaconProposer() via clock.runEveryEpoch
    pub fn onEpoch(self: *PrepareBeaconProposerService, io: Io, epoch: u64) void {
        self.registerFeeRecipients(io, epoch) catch |err| {
            log.err("registerFeeRecipients epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    // -----------------------------------------------------------------------
    // Implementation
    // -----------------------------------------------------------------------

    fn registerFeeRecipients(self: *PrepareBeaconProposerService, io: Io, epoch: u64) !void {
        // Collect validator indices.
        const indices = try self.validator_store.allIndices(self.allocator);
        defer self.allocator.free(indices);

        if (indices.len == 0) {
            log.debug("no validators registered — skipping prepare_beacon_proposer epoch={d}", .{epoch});
            return;
        }

        // Build entries list.
        var entries = try std.array_list.Managed(FeeRecipientEntry).initCapacity(self.allocator, indices.len);
        defer entries.deinit();

        for (indices) |idx| {
            const fee_recipient = if (self.overrides) |ov|
                ov.get(idx) orelse self.default_fee_recipient
            else
                self.default_fee_recipient;

            entries.appendAssumeCapacity(.{
                .validator_index = idx,
                .fee_recipient = fee_recipient,
            });
        }

        // Serialize to JSON: [{"validator_index":"N","fee_recipient":"0x..."},...]
        const json_body = try self.serializeEntries(entries.items);
        defer self.allocator.free(json_body);

        log.debug("registering {d} fee recipients epoch={d}", .{ entries.items.len, epoch });

        try self.api.prepareBeaconProposer(io, json_body);
        log.info("prepare_beacon_proposer registered {d} validators epoch={d}", .{ entries.items.len, epoch });
    }

    fn serializeEntries(self: *PrepareBeaconProposerService, entries: []const FeeRecipientEntry) ![]const u8 {
        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer buf.deinit();

        const writer = &buf.writer;
        try writer.writeByte('[');
        for (entries, 0..) |entry, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.print(
                "{{\"validator_index\":\"{d}\",\"fee_recipient\":\"{s}\"}}",
                .{ entry.validator_index, entry.fee_recipient },
            );
        }
        try writer.writeByte(']');

        return buf.toOwnedSlice();
    }
};
