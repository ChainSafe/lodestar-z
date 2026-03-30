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
const SigningContext = signing_mod.SigningContext;
const remote_signer_mod = @import("remote_signer.zig");
const RemoteSigner = remote_signer_mod.RemoteSigner;
const SigningType = remote_signer_mod.SigningType;

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

    /// Suggested fee recipient (20 bytes). Set from ValidatorConfig.
    fee_recipient: [20]u8,
    /// Default gas limit for all validators.
    gas_limit: u64,
    /// Optional remote signer for builder registrations of remote validators.
    remote_signer: ?*RemoteSigner = null,

    pub fn init(
        allocator: Allocator,
        api: *BeaconApiClient,
        validator_store: *ValidatorStore,
        fee_recipient: [20]u8,
        gas_limit: u64,
    ) BuilderRegistrationService {
        return .{
            .allocator = allocator,
            .api = api,
            .validator_store = validator_store,
            .fee_recipient = fee_recipient,
            .gas_limit = gas_limit,
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

        // Snapshot validators under mutex to prevent data races with concurrent
        // Keymanager API add/remove operations (ArrayList reallocation → dangling ptr).
        self.validator_store.mutex.lock();
        const validators = try self.allocator.dupe(
            @import("validator_store.zig").ValidatorRecord,
            self.validator_store.validators.items,
        );
        self.validator_store.mutex.unlock();
        defer {
            // Zero secret keys before freeing — defence in depth against heap scanning.
            for (validators) |*v| {
                std.crypto.utils.secureZero(u8, std.mem.asBytes(&v.secret_key));
            }
            self.allocator.free(validators);
        }

        if (validators.len == 0) {
            log.debug("no validators — skipping builder registration", .{});
            return;
        }

        // Current Unix timestamp (seconds).
        const timestamp = unixTimestampSeconds();

        // Build signed registrations.
        var registrations = try std.ArrayList(RegistrationEntry).initCapacity(
            self.allocator,
            validators.len,
        );
        defer registrations.deinit();

        for (validators) |v| {
            // Compute signing root (same path for local and remote).
            var signing_root: [32]u8 = undefined;
            signing_mod.builderRegistrationSigningRoot(
                self.fee_recipient,
                self.gas_limit,
                timestamp,
                v.pubkey,
                &signing_root,
            ) catch |err| {
                log.warn("failed to compute builder registration signing root for {}: {s}", .{
                    std.fmt.fmtSliceHexLower(&v.pubkey),
                    @errorName(err),
                });
                continue;
            };

            // Sign: delegate to remote signer if this is a remote validator.
            const sig_bytes = blk: {
                if (v.is_remote) {
                    const rs = self.remote_signer orelse {
                        log.warn("skipping builder registration for remote key {} — no remote signer configured", .{
                            std.fmt.fmtSliceHexLower(&v.pubkey),
                        });
                        continue;
                    };
                    const sig = rs.sign(io, v.pubkey, signing_root, .VALIDATOR_REGISTRATION) catch |err| {
                        log.warn("remote signer failed builder registration for {}: {s}", .{
                            std.fmt.fmtSliceHexLower(&v.pubkey),
                            @errorName(err),
                        });
                        continue;
                    };
                    break :blk sig.compress();
                } else {
                    const sig = v.secret_key.sign(&signing_root, @import("bls").DST, null);
                    break :blk sig.compress();
                }
            };

            try registrations.append(.{
                .pubkey = v.pubkey,
                .fee_recipient = self.fee_recipient,
                .gas_limit = self.gas_limit,
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
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        var writer = buf.writer();

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
