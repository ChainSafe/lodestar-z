//! MEV-boost builder API interface stub.
//!
//! Provides the interface for interacting with MEV-boost block builder relays.
//! The builder API allows validators to receive externally built blocks from
//! searchers/builders, potentially yielding higher block rewards.
//!
//! Reference: https://github.com/ethereum/builder-specs
//!
//! Currently a stub implementation — all methods return error.NotImplemented.
//! This lets the chain code program against the interface before builder
//! integration is complete.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const types = @import("engine_api_types.zig");

// ── Builder API types ─────────────────────────────────────────────────────────

/// Validator registration for the builder API.
/// Sent once per epoch to builder relays.
pub const ValidatorRegistration = struct {
    /// Validator fee recipient address.
    fee_recipient: [20]u8,
    /// Maximum gas limit the validator will accept.
    gas_limit: u64,
    /// Registration timestamp.
    timestamp: u64,
    /// Validator BLS public key.
    pubkey: [48]u8,
};

/// Signed validator registration with BLS signature.
pub const SignedValidatorRegistration = struct {
    message: ValidatorRegistration,
    signature: [96]u8,
};

/// Execution payload header (blinded payload — without transactions).
pub const ExecutionPayloadHeader = struct {
    parent_hash: [32]u8,
    fee_recipient: [20]u8,
    state_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    prev_randao: [32]u8,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    base_fee_per_gas: u256,
    block_hash: [32]u8,
    /// Merkle root of the transactions list (not the transactions themselves).
    transactions_root: [32]u8,
    /// Merkle root of the withdrawals list (Capella+).
    withdrawals_root: ?[32]u8 = null,
    /// Blob gas used (Deneb+).
    blob_gas_used: ?u64 = null,
    /// Excess blob gas (Deneb+).
    excess_blob_gas: ?u64 = null,
};

/// Builder bid returned by getHeader — the blinded block with block value.
pub const BuilderBid = struct {
    /// The blinded execution payload header.
    header: ExecutionPayloadHeader,
    /// Blob KZG commitments (Deneb+).
    blob_kzg_commitments: []const [48]u8,
    /// MEV reward value in wei.
    value: u256,
    /// Builder BLS public key.
    pubkey: [48]u8,
};

/// Signed builder bid.
pub const SignedBuilderBid = struct {
    message: BuilderBid,
    signature: [96]u8,
};

/// Blinded beacon block body (contains header instead of full payload).
pub const BlindedBeaconBlockBody = struct {
    /// The blinded execution payload header.
    execution_payload_header: ExecutionPayloadHeader,
    // Other beacon block body fields would go here.
};

/// Signed blinded beacon block submitted to the builder relay.
pub const SignedBlindedBeaconBlock = struct {
    message: BlindedBeaconBlockBody,
    signature: [96]u8,
};

// ── Builder API interface ─────────────────────────────────────────────────────

/// Builder API vtable interface.
///
/// Abstracts over MEV-boost relay communication. Concrete implementations
/// handle the actual HTTP relay API.
pub const BuilderApi = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Register validators with the builder relay.
        /// Called once per epoch for all active validators.
        registerValidators: *const fn (
            ptr: *anyopaque,
            registrations: []const SignedValidatorRegistration,
        ) anyerror!void,

        /// Get a blinded execution payload header from the builder relay.
        /// Called during block production to check if builder has a better block.
        getHeader: *const fn (
            ptr: *anyopaque,
            slot: u64,
            parent_hash: [32]u8,
            pubkey: [48]u8,
        ) anyerror!?SignedBuilderBid,

        /// Submit a signed blinded beacon block to unblind and broadcast.
        /// Called after the proposer signs the blinded block.
        submitBlindedBlock: *const fn (
            ptr: *anyopaque,
            block: SignedBlindedBeaconBlock,
        ) anyerror!types.ExecutionPayloadV3,
    };

    /// Register validators with the builder relay.
    pub fn registerValidators(
        self: BuilderApi,
        registrations: []const SignedValidatorRegistration,
    ) !void {
        return self.vtable.registerValidators(self.ptr, registrations);
    }

    /// Get a blinded execution payload header.
    pub fn getHeader(
        self: BuilderApi,
        slot: u64,
        parent_hash: [32]u8,
        pubkey: [48]u8,
    ) !?SignedBuilderBid {
        return self.vtable.getHeader(self.ptr, slot, parent_hash, pubkey);
    }

    /// Submit a blinded beacon block and receive the full execution payload.
    pub fn submitBlindedBlock(
        self: BuilderApi,
        block: SignedBlindedBeaconBlock,
    ) !types.ExecutionPayloadV3 {
        return self.vtable.submitBlindedBlock(self.ptr, block);
    }
};

// ── Stub implementation ───────────────────────────────────────────────────────

/// Stub builder implementation — returns error.NotImplemented for all methods.
///
/// Use as a placeholder until the builder relay HTTP client is implemented.
/// Allows the rest of the chain code to compile and test without builder support.
pub const StubBuilder = struct {
    pub fn init() StubBuilder {
        return .{};
    }

    pub fn deinit(_: *StubBuilder) void {}

    /// Return a BuilderApi backed by this stub.
    pub fn builder(self: *StubBuilder) BuilderApi {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = BuilderApi.VTable{
        .registerValidators = @ptrCast(&registerValidatorsImpl),
        .getHeader = @ptrCast(&getHeaderImpl),
        .submitBlindedBlock = @ptrCast(&submitBlindedBlockImpl),
    };

    fn registerValidatorsImpl(
        _: *StubBuilder,
        _: []const SignedValidatorRegistration,
    ) anyerror!void {
        return error.NotImplemented;
    }

    fn getHeaderImpl(
        _: *StubBuilder,
        _: u64,
        _: [32]u8,
        _: [48]u8,
    ) anyerror!?SignedBuilderBid {
        return error.NotImplemented;
    }

    fn submitBlindedBlockImpl(
        _: *StubBuilder,
        _: SignedBlindedBeaconBlock,
    ) anyerror!types.ExecutionPayloadV3 {
        return error.NotImplemented;
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────────

test "StubBuilder: registerValidators returns NotImplemented" {
    var stub = StubBuilder.init();
    defer stub.deinit();

    const api = stub.builder();
    const result = api.registerValidators(&.{});
    try testing.expectError(error.NotImplemented, result);
}

test "StubBuilder: getHeader returns NotImplemented" {
    var stub = StubBuilder.init();
    defer stub.deinit();

    const api = stub.builder();
    const result = api.getHeader(1, std.mem.zeroes([32]u8), std.mem.zeroes([48]u8));
    try testing.expectError(error.NotImplemented, result);
}

test "StubBuilder: submitBlindedBlock returns NotImplemented" {
    var stub = StubBuilder.init();
    defer stub.deinit();

    const api = stub.builder();
    const result = api.submitBlindedBlock(.{
        .message = .{
            .execution_payload_header = .{
                .parent_hash = std.mem.zeroes([32]u8),
                .fee_recipient = std.mem.zeroes([20]u8),
                .state_root = std.mem.zeroes([32]u8),
                .receipts_root = std.mem.zeroes([32]u8),
                .logs_bloom = std.mem.zeroes([256]u8),
                .prev_randao = std.mem.zeroes([32]u8),
                .block_number = 0,
                .gas_limit = 0,
                .gas_used = 0,
                .timestamp = 0,
                .extra_data = &.{},
                .base_fee_per_gas = 0,
                .block_hash = std.mem.zeroes([32]u8),
                .transactions_root = std.mem.zeroes([32]u8),
            },
        },
        .signature = std.mem.zeroes([96]u8),
    });
    try testing.expectError(error.NotImplemented, result);
}

test "BuilderApi vtable struct layout" {
    const info = @typeInfo(BuilderApi.VTable);
    try testing.expectEqual(@as(usize, 3), info.@"struct".fields.len);
}

test "BuilderApi methods exist" {
    try testing.expect(@hasDecl(BuilderApi, "registerValidators"));
    try testing.expect(@hasDecl(BuilderApi, "getHeader"));
    try testing.expect(@hasDecl(BuilderApi, "submitBlindedBlock"));
}
