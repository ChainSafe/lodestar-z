//! Builder registration service for the Validator Client.
//!
//! Sends signed validator registrations to the builder relay once per epoch.
//! Each registration tells the relay the validator's fee_recipient and gas_limit
//! preference so it can construct suitable blinded blocks.
//!
//! Per the builder spec:
//!   POST /eth/v1/builder/validators (on the relay directly) OR
//!   POST /eth/v1/validator/register_validator (on the BN, which forwards)
//!
//! TS equivalent: packages/validator/src/services/prepareBeaconProposer.ts
//!               pollBuilderValidatorRegistration()

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const api_client = @import("api_client.zig");
const BeaconApiClient = api_client.BeaconApiClient;
const ValidatorStore = @import("validator_store.zig").ValidatorStore;
const signing_mod = @import("signing.zig");

const log = std.log.scoped(.builder_registration);

fn unixTimestampSeconds() u64 {
    var ts: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => return if (ts.sec >= 0) @intCast(ts.sec) else 0,
        else => return 0,
    }
}

// ---------------------------------------------------------------------------
// BuilderRegistrationService
// ---------------------------------------------------------------------------

pub const BuilderRegistrationService = struct {
    allocator: Allocator,
    api: *BeaconApiClient,
    validator_store: *ValidatorStore,

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
    ) BuilderRegistrationService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
        };
    }

    pub fn deinit(_: *BuilderRegistrationService) void {}

    // -----------------------------------------------------------------------
    // Clock callback
    // -----------------------------------------------------------------------

    /// Called once per epoch to register validators with the builder relay.
    ///
    /// Errors are caught and logged — builder failure must not interrupt
    /// normal validator operation.
    pub fn onEpoch(self: *BuilderRegistrationService, io: Io, epoch: u64) void {
        self.registerValidators(io, epoch) catch |err| {
            log.err("registerValidators epoch={d} error={s}", .{ epoch, @errorName(err) });
        };
    }

    // -----------------------------------------------------------------------
    // Implementation
    // -----------------------------------------------------------------------

    fn registerValidators(self: *BuilderRegistrationService, io: Io, epoch: u64) !void {
        _ = epoch;

        const pubkeys = try self.validator_store.allPubkeys(self.allocator);
        defer self.allocator.free(pubkeys);

        if (pubkeys.len == 0) {
            log.debug("no validators — skipping builder registration", .{});
            return;
        }

        // Current Unix timestamp (seconds).
        const timestamp = unixTimestampSeconds();

        // Build signed registrations.
        var registrations = try std.array_list.Managed(RegistrationEntry).initCapacity(
            self.allocator,
            pubkeys.len,
        );
        defer registrations.deinit();

        for (pubkeys) |pubkey| {
            if (self.validator_store.getBuilderSelection(pubkey) == .executiononly) continue;

            const fee_recipient = self.validator_store.getFeeRecipient(pubkey);
            const gas_limit = self.validator_store.getGasLimit(pubkey);

            // Compute signing root (same path for local and remote).
            var signing_root: [32]u8 = undefined;
            signing_mod.builderRegistrationSigningRoot(
                fee_recipient,
                gas_limit,
                timestamp,
                pubkey,
                &signing_root,
            ) catch |err| {
                log.warn("failed to compute builder registration signing root for {x}: {s}", .{
                    pubkey,
                    @errorName(err),
                });
                continue;
            };

            const sig = self.validator_store.signBuilderRegistration(io, pubkey, signing_root) catch |err| {
                log.warn("failed builder registration signature for {x}: {s}", .{
                    pubkey,
                    @errorName(err),
                });
                continue;
            };
            const sig_bytes = sig.compress();

            try registrations.append(.{
                .pubkey = pubkey,
                .fee_recipient = fee_recipient,
                .gas_limit = gas_limit,
                .timestamp = timestamp,
                .signature = sig_bytes,
            });
        }

        if (registrations.items.len == 0) return;

        // Serialize and POST to BN.
        const json_body = try serializeRegistrations(self.allocator, registrations.items);
        defer self.allocator.free(json_body);

        log.debug("registering {d} validators with builder relay", .{registrations.items.len});
        try self.api.registerValidators(io, json_body);
        log.info("builder registrations sent: {d} validators", .{registrations.items.len});
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    fn serializeRegistrations(allocator: Allocator, entries: []const RegistrationEntry) ![]const u8 {
        var buf: std.Io.Writer.Allocating = .init(allocator);
        errdefer buf.deinit();
        const writer = &buf.writer;

        try writer.writeByte('[');
        for (entries, 0..) |e, i| {
            if (i > 0) try writer.writeByte(',');
            const fee_hex = std.fmt.bytesToHex(&e.fee_recipient, .lower);
            const pk_hex = std.fmt.bytesToHex(&e.pubkey, .lower);
            const sig_hex = std.fmt.bytesToHex(&e.signature, .lower);
            try writer.print(
                "{{\"message\":{{\"fee_recipient\":\"0x{s}\",\"gas_limit\":\"{d}\",\"timestamp\":\"{d}\",\"pubkey\":\"0x{s}\"}},\"signature\":\"0x{s}\"}}",
                .{ fee_hex, e.gas_limit, e.timestamp, pk_hex, sig_hex },
            );
        }
        try writer.writeByte(']');

        return buf.toOwnedSlice();
    }
};

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

const RegistrationEntry = struct {
    pubkey: [48]u8,
    fee_recipient: [20]u8,
    gas_limit: u64,
    timestamp: u64,
    signature: [96]u8,
};
