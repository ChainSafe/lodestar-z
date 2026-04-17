const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("consensus_types");
const BeaconConfig = @import("config").BeaconConfig;
const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const preset = @import("preset").preset;
const c = @import("constants");
const processDepositRequest = @import("./process_deposit_request.zig").processDepositRequest;
const processWithdrawalRequest = @import("./process_withdrawal_request.zig").processWithdrawalRequest;
const processConsolidationRequest = @import("./process_consolidation_request.zig").processConsolidationRequest;
const getExecutionPayloadEnvelopeSignatureSet = @import("../signature_sets/execution_payload_envelope.zig").getExecutionPayloadEnvelopeSignatureSet;
const verifySingleSignatureSet = @import("../utils/signature_sets.zig").verifySingleSignatureSet;

pub const ProcessExecutionPayloadEnvelopeOpts = struct {
    verify_signature: bool = true,
    verify_state_root: bool = true,
};

pub fn processExecutionPayloadEnvelope(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    signed_envelope: *const types.gloas.SignedExecutionPayloadEnvelope.Type,
    opts: ProcessExecutionPayloadEnvelopeOpts,
) !void {
    const envelope = &signed_envelope.message;
    const payload = &envelope.payload;
    if (opts.verify_signature) {
        if (!(try verifyExecutionPayloadEnvelopeSignature(allocator, config, epoch_cache, state, signed_envelope))) {
            return error.InvalidEnvelopeSignature;
        }
    }

    try validateExecutionPayloadEnvelope(allocator, config, state, envelope);

    const requests = &envelope.execution_requests;

    for (requests.deposits.items) |*deposit| {
        try processDepositRequest(.gloas, allocator, config, epoch_cache, state, deposit);
    }

    for (requests.withdrawals.items) |*withdrawal| {
        try processWithdrawalRequest(.gloas, config, @constCast(epoch_cache), state, withdrawal);
    }

    for (requests.consolidations.items) |*consolidation| {
        try processConsolidationRequest(.gloas, config, epoch_cache, state, consolidation);
    }

    // Queue the builder payment
    const payment_index = preset.SLOTS_PER_EPOCH + (try state.slot() % preset.SLOTS_PER_EPOCH);
    var builder_pending_payments = try state.inner.get("builder_pending_payments");
    var payment: types.gloas.BuilderPendingPayment.Type = undefined;
    try builder_pending_payments.getValue(allocator, payment_index, &payment);
    const amount = payment.withdrawal.amount;

    if (amount > 0) {
        var builder_pending_withdrawals = try state.inner.get("builder_pending_withdrawals");
        try builder_pending_withdrawals.pushValue(&payment.withdrawal);
        try state.inner.set("builder_pending_withdrawals", builder_pending_withdrawals);
    }

    const default_payment = types.gloas.BuilderPendingPayment.default_value;
    try builder_pending_payments.setValue(payment_index, &default_payment);

    // Cache the execution payload hash
    var execution_payload_availability = try state.inner.get("execution_payload_availability");
    try execution_payload_availability.set(try state.slot() % preset.SLOTS_PER_HISTORICAL_ROOT, true);
    try state.inner.setValue("latest_block_hash", &payload.block_hash);

    try state.commit();

    if (opts.verify_state_root) {
        const state_root = try state.hashTreeRoot();
        if (!std.mem.eql(u8, &envelope.state_root, state_root)) {
            return error.EnvelopeStateRootMismatch;
        }
    }
}

fn validateExecutionPayloadEnvelope(
    allocator: Allocator,
    config: *const BeaconConfig,
    state: *BeaconState(.gloas),
    envelope: *const types.gloas.ExecutionPayloadEnvelope.Type,
) !void {
    const payload = &envelope.payload;

    // Cache latest block header state root
    var latest_block_header = try state.latestBlockHeader();
    const latest_header_state_root = try latest_block_header.getFieldRoot("state_root");
    if (std.mem.eql(u8, latest_header_state_root, &c.ZERO_HASH)) {
        const previous_state_root = try state.hashTreeRoot();
        try latest_block_header.setValue("state_root", previous_state_root);
        try state.inner.set("latest_block_header", latest_block_header);
    }

    // Verify consistency with the beacon block
    const latest_block_header_root = try latest_block_header.hashTreeRoot();
    if (!std.mem.eql(u8, &envelope.beacon_block_root, latest_block_header_root)) {
        return error.EnvelopeBlockRootMismatch;
    }

    // Verify slot
    if (envelope.slot != try state.slot()) {
        return error.EnvelopeSlotMismatch;
    }

    // Verify consistency with the committed bid
    var committed_bid: types.gloas.ExecutionPayloadBid.Type = types.gloas.ExecutionPayloadBid.default_value;
    try state.inner.getValue(allocator, "latest_execution_payload_bid", &committed_bid);
    defer types.gloas.ExecutionPayloadBid.deinit(allocator, &committed_bid);

    if (envelope.builder_index != committed_bid.builder_index) {
        return error.EnvelopeBuilderIndexMismatch;
    }

    if (!std.mem.eql(u8, &committed_bid.prev_randao, &payload.prev_randao)) {
        return error.EnvelopePrevRandaoMismatch;
    }

    // Verify consistency with expected withdrawals
    var payload_withdrawals_root: [32]u8 = undefined;
    try types.capella.Withdrawals.hashTreeRoot(allocator, &payload.withdrawals, &payload_withdrawals_root);
    var expected_withdrawals = try state.inner.get("payload_expected_withdrawals");
    var expected_withdrawals_root: [32]u8 = undefined;
    try expected_withdrawals.hashTreeRootInto(&expected_withdrawals_root);
    if (!std.mem.eql(u8, &payload_withdrawals_root, &expected_withdrawals_root)) {
        return error.EnvelopeWithdrawalsMismatch;
    }

    // Verify the gas_limit
    if (committed_bid.gas_limit != payload.gas_limit) {
        return error.EnvelopeGasLimitMismatch;
    }

    // Verify the block hash
    if (!std.mem.eql(u8, &committed_bid.block_hash, &payload.block_hash)) {
        return error.EnvelopeBlockHashMismatch;
    }

    // Verify consistency of the parent hash with respect to the previous execution payload
    const latest_block_hash = try state.inner.getFieldRoot("latest_block_hash");
    if (!std.mem.eql(u8, &payload.parent_hash, latest_block_hash)) {
        return error.EnvelopeParentHashMismatch;
    }

    // Verify timestamp
    // compute_timestamp_at_slot: genesis_time + slot * SECONDS_PER_SLOT
    const expected_timestamp = (try state.genesisTime()) + (try state.slot()) * config.chain.SECONDS_PER_SLOT;
    if (payload.timestamp != expected_timestamp) {
        return error.EnvelopeTimestampMismatch;
    }

    // Skipped: Verify the execution payload is valid
}

fn verifyExecutionPayloadEnvelopeSignature(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
    signed_envelope: *const types.gloas.SignedExecutionPayloadEnvelope.Type,
) !bool {
    const signature_set = try getExecutionPayloadEnvelopeSignatureSet(
        allocator,
        config,
        epoch_cache,
        state,
        signed_envelope,
    );
    return verifySingleSignatureSet(&signature_set);
}
