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

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
    ) PrepareBeaconProposerService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
        };
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
        const pubkeys = try self.validator_store.allPubkeys(self.allocator);
        defer self.allocator.free(pubkeys);

        if (pubkeys.len == 0) {
            log.debug("no validators registered — skipping prepare_beacon_proposer epoch={d}", .{epoch});
            return;
        }

        // Build entries list.
        var entries = std.array_list.Managed(FeeRecipientEntry).init(self.allocator);
        defer entries.deinit();

        for (pubkeys) |pubkey| {
            const validator_index = self.validator_store.getValidatorIndex(pubkey) orelse continue;
            const fee_recipient = self.validator_store.getFeeRecipient(pubkey);

            var fee_recipient_hex: [42]u8 = undefined;
            fee_recipient_hex[0] = '0';
            fee_recipient_hex[1] = 'x';
            _ = std.fmt.bufPrint(fee_recipient_hex[2..], "{x}", .{fee_recipient}) catch unreachable;

            try entries.append(.{
                .validator_index = validator_index,
                .fee_recipient = fee_recipient_hex,
            });
        }

        if (entries.items.len == 0) return;

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
