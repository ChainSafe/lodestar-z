//! Node-owned execution and block production helpers.

const std = @import("std");
const log = @import("log");

const types = @import("consensus_types");
const fork_types = @import("fork_types");
const config_mod = @import("config");
const state_transition = @import("state_transition");
const chain_mod = @import("chain");
const ProducedBlockBody = chain_mod.ProducedBlockBody;
const ProposalSnapshot = chain_mod.ProposalSnapshot;
const PreparedProposalTemplate = chain_mod.PreparedProposalTemplate;
const ProducedBlock = chain_mod.ProducedBlock;
const ProducedBlindedBlock = chain_mod.ProducedBlindedBlock;
const BlockProductionConfig = chain_mod.BlockProductionConfig;
const execution_mod = @import("execution");
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;
const GetPayloadResponse = execution_mod.GetPayloadResponse;
const BlockType = fork_types.BlockType;
const AnyExecutionPayload = fork_types.AnyExecutionPayload;
const AnyExecutionPayloadHeader = fork_types.AnyExecutionPayloadHeader;
const execution_runtime_mod = @import("execution_runtime.zig");

const BLOCK_PRODUCTION_RACE_CUTOFF_MS: u64 = 2_000;
const BLOCK_PRODUCTION_RACE_TIMEOUT_MS: u64 = 12_000;

pub const SerializedUnsignedBlock = struct {
    ssz_bytes: []u8,
    fork_name: []const u8,
    block_type: BlockType,
    consensus_block_value: u256 = 0,
};

const ProducedStateTransitionMeta = struct {
    state_root: [32]u8,
    consensus_block_value: u256,
};

pub const ProducedProposal = union(enum) {
    engine: ProducedBlock,
    builder: ProducedBlindedBlock,

    pub fn deinit(self: *ProducedProposal, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .engine => |*produced| produced.deinit(allocator),
            .builder => |*produced| produced.deinit(allocator),
        }
    }
};

const PreparedProposalContext = struct {
    snapshot: ProposalSnapshot,
    config: BlockProductionConfig,
};

pub fn builderBoostFactorForConfig(self: *BeaconNode, prod_config: BlockProductionConfig) u64 {
    return prod_config.builder_boost_factor orelse self.node_options.builder_boost_factor;
}

const BuilderGasLimitBounds = struct {
    expected: u64,
    lower: u64,
    upper: u64,
};

fn expectedBuilderGasLimit(parent_gas_limit: u64, target_gas_limit: u64) u64 {
    const max_difference = (parent_gas_limit / 1024) -| 1;
    if (target_gas_limit > parent_gas_limit) {
        const gas_diff = target_gas_limit - parent_gas_limit;
        return parent_gas_limit + @min(gas_diff, max_difference);
    }

    const gas_diff = parent_gas_limit - target_gas_limit;
    return parent_gas_limit - @min(gas_diff, max_difference);
}

fn builderGasLimitBounds(parent_gas_limit: u64, target_gas_limit: u64) BuilderGasLimitBounds {
    const expected = expectedBuilderGasLimit(parent_gas_limit, target_gas_limit);
    return .{
        .expected = expected,
        .lower = @min(parent_gas_limit, expected),
        .upper = @max(parent_gas_limit, expected),
    };
}

fn engineValueMeetsBuilderThreshold(
    engine_value: u256,
    builder_value: u256,
    builder_boost_factor: u64,
) bool {
    if (builder_boost_factor == 0) return true;
    return engine_value >= (builder_value * @as(u256, builder_boost_factor)) / 100;
}

fn currentParentGasLimit(self: *BeaconNode) !u64 {
    const head_state = self.headState() orelse return error.NoHeadState;
    var payload_header: AnyExecutionPayloadHeader = undefined;
    try head_state.state.latestExecutionPayloadHeader(self.allocator, &payload_header);
    defer payload_header.deinit(self.allocator);
    return payload_header.gasLimit();
}

fn validateBuilderHeaderGasLimit(
    self: *BeaconNode,
    slot: u64,
    proposer_pubkey: [48]u8,
    header_gas_limit: u64,
) !void {
    const registration = self.execution_runtime.getValidatorRegistration(proposer_pubkey) orelse {
        log.logger(.node).warn(
            "Builder: missing cached validator registration, skipping header gas limit check slot={d} proposer=0x{s}",
            .{ slot, std.fmt.bytesToHex(proposer_pubkey[0..4], .lower) },
        );
        return;
    };

    const parent_gas_limit = try currentParentGasLimit(self);
    const bounds = builderGasLimitBounds(parent_gas_limit, registration.gas_limit);

    if (header_gas_limit < bounds.lower or header_gas_limit > bounds.upper) {
        log.logger(.node).warn(
            "Builder: rejecting bid with gas_limit={d} outside [{d}, {d}] slot={d} proposer=0x{s}",
            .{
                header_gas_limit,
                bounds.lower,
                bounds.upper,
                slot,
                std.fmt.bytesToHex(proposer_pubkey[0..4], .lower),
            },
        );
        return error.BuilderHeaderGasLimitOutOfRange;
    }

    if (header_gas_limit != bounds.expected) {
        log.logger(.node).warn(
            "Builder: bid gas_limit={d} differs from expected={d} (parent={d} target={d}) slot={d} proposer=0x{s}",
            .{
                header_gas_limit,
                bounds.expected,
                parent_gas_limit,
                registration.gas_limit,
                slot,
                std.fmt.bytesToHex(proposer_pubkey[0..4], .lower),
            },
        );
    }
}

pub fn refreshBuilderStatus(self: *BeaconNode, clock_slot: u64) void {
    if (self.execution_runtime.currentBuilderStatus() == .unavailable and
        self.execution_runtime.builderApi() == null) return;
    if (self.execution_runtime.lastBuilderStatusSlot() == clock_slot) return;
    self.execution_runtime.setLastBuilderStatusSlot(clock_slot);

    const previous_status = self.execution_runtime.currentBuilderStatus();
    const fault_window = self.execution_runtime.builderFaultInspectionWindow();
    const slots_present = self.chainQuery().slotsPresent(clock_slot -| fault_window);
    const should_enable = execution_mod.builder.shouldEnableBuilderForSlot(
        clock_slot,
        slots_present,
        fault_window,
        self.execution_runtime.builderAllowedFaults(),
    );

    if (!should_enable) {
        self.execution_runtime.updateBuilderStatus(.circuit_breaker);
    } else if (self.execution_runtime.builderApi()) |builder| {
        const status = builder.status() catch |err| blk: {
            log.logger(.node).warn("Builder status check failed", .{ .err = err });
            break :blk execution_mod.BuilderStatus.unavailable;
        };
        self.execution_runtime.updateBuilderStatus(status);
    } else {
        self.execution_runtime.updateBuilderStatus(.unavailable);
    }

    const current_status = self.execution_runtime.currentBuilderStatus();
    if (current_status != previous_status) {
        log.logger(.node).info(
            "External builder status updated: {s} -> {s} (slots_present={d} fault_window={d} allowed_faults={d})",
            .{
                @tagName(previous_status),
                @tagName(current_status),
                slots_present,
                fault_window,
                self.execution_runtime.builderAllowedFaults(),
            },
        );
    }
}

fn currentBuilderStatus(self: *BeaconNode) execution_mod.BuilderStatus {
    const clock_slot = if (self.clock) |clock|
        clock.currentSlot(self.io) orelse self.currentHeadSlot()
    else
        self.currentHeadSlot();
    refreshBuilderStatus(self, clock_slot);
    return self.execution_runtime.currentBuilderStatus();
}

fn normalizeBlockProductionConfig(
    self: *BeaconNode,
    slot: u64,
    prod_config: BlockProductionConfig,
) !BlockProductionConfig {
    var effective = prod_config;
    if (effective.graffiti == null) {
        effective.graffiti = self.node_options.graffiti;
    }
    if (std.mem.eql(u8, &effective.fee_recipient, &std.mem.zeroes([20]u8))) {
        effective.fee_recipient = payloadFeeRecipientForSlot(self, slot) orelse return error.MissingProposerFeeRecipient;
    }
    return effective;
}

pub fn preparePayload(
    self: *BeaconNode,
    slot: u64,
    timestamp: u64,
    prev_randao: [32]u8,
    fee_recipient: [20]u8,
    withdrawals_slice: []const execution_mod.engine_api_types.Withdrawal,
    parent_beacon_block_root: [32]u8,
) !void {
    const attrs = PayloadAttributesV3{
        .timestamp = timestamp,
        .prev_randao = prev_randao,
        .suggested_fee_recipient = fee_recipient,
        .withdrawals = withdrawals_slice,
        .parent_beacon_block_root = parent_beacon_block_root,
    };
    const fc_state = self.chainQuery().executionForkchoiceState(parent_beacon_block_root) orelse return;
    switch (try self.execution_runtime.ensurePayloadPreparationAsync(slot, .{
        .beacon_block_root = parent_beacon_block_root,
        .state = fc_state,
    }, attrs)) {
        .ready, .queued, .pending => {},
        .unavailable => return error.ExecutionRuntimeBusy,
    }
}

fn clearCachedPayloadIdIfCurrent(
    self: *BeaconNode,
    snapshot: *const ProposalSnapshot,
    payload_id: [8]u8,
) void {
    self.execution_runtime.clearCachedPayloadIfMatch(snapshot.slot, snapshot.parent_root, payload_id);
}

fn proposalRaceCutoffNs(self: *BeaconNode, slot: u64) u64 {
    const cutoff_ns = BLOCK_PRODUCTION_RACE_CUTOFF_MS * std.time.ns_per_ms;
    const clock = self.clock orelse return cutoff_ns;

    const slot_start_ns: i128 = @intCast(clock.slotStartNs(slot));
    const now_ns = std.Io.Clock.real.now(self.io).nanoseconds;
    if (now_ns <= slot_start_ns) return cutoff_ns;

    const elapsed_ns: u64 = @intCast(now_ns - slot_start_ns);
    return cutoff_ns -| elapsed_ns;
}

pub fn registerValidatorsWithBuilder(
    self: *BeaconNode,
    registrations: []const execution_mod.builder.SignedValidatorRegistration,
) void {
    const builder = self.execution_runtime.builderApi() orelse return;
    builder.registerValidators(registrations) catch |err| {
        std.log.warn("builder registerValidators failed: {} — continuing", .{err});
    };
}

pub fn produceBlock(self: *BeaconNode, slot: u64) !ProducedBlockBody {
    return self.chainService().produceBlock(slot);
}

fn payloadFeeRecipientForSlot(self: *BeaconNode, slot: u64) ?[20]u8 {
    return self.chainQuery().proposerFeeRecipientForSlot(slot, self.node_options.suggested_fee_recipient);
}

fn slotStartTimestamp(self: *BeaconNode, slot: u64) u64 {
    if (self.clock) |clock| return clock.slotStartSeconds(slot);
    return self.api_context.genesis_time + slot * self.config.chain.SECONDS_PER_SLOT;
}

fn prepareProposalContext(
    self: *BeaconNode,
    slot: u64,
    prod_config: BlockProductionConfig,
) !PreparedProposalContext {
    const effective_config = try normalizeBlockProductionConfig(self, slot, prod_config);
    return .{
        .snapshot = try self.chainService().prepareProposalSnapshot(slot),
        .config = effective_config,
    };
}

fn copyBlobCommitments(
    allocator: std.mem.Allocator,
    commitments: []const [48]u8,
) !std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type) {
    if (commitments.len == 0) return .empty;

    var out = try std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type).initCapacity(
        allocator,
        commitments.len,
    );
    for (commitments) |commitment| {
        out.appendAssumeCapacity(commitment);
    }
    return out;
}

fn copyBlobsBundle(
    allocator: std.mem.Allocator,
    bundle: execution_mod.engine_api_types.BlobsBundle,
) !?chain_mod.produce_block.BlobsBundle {
    if (bundle.commitments.len == 0 and bundle.proofs.len == 0 and bundle.blobs.len == 0) {
        return null;
    }

    const commitments = try allocator.dupe([48]u8, bundle.commitments);
    errdefer if (commitments.len > 0) allocator.free(commitments);

    const proofs = try allocator.dupe([48]u8, bundle.proofs);
    errdefer if (proofs.len > 0) allocator.free(proofs);

    const blobs = try allocator.dupe([131072]u8, bundle.blobs);
    errdefer if (blobs.len > 0) allocator.free(blobs);

    return .{
        .commitments = commitments,
        .proofs = proofs,
        .blobs = blobs,
    };
}

fn convertExecutionRequests(
    allocator: std.mem.Allocator,
    deposit_requests: []const execution_mod.engine_api_types.DepositRequest,
    withdrawal_requests: []const execution_mod.engine_api_types.WithdrawalRequest,
    consolidation_requests: []const execution_mod.engine_api_types.ConsolidationRequest,
) !types.electra.ExecutionRequests.Type {
    var deposits = try std.ArrayListUnmanaged(types.electra.DepositRequest.Type).initCapacity(
        allocator,
        deposit_requests.len,
    );
    errdefer deposits.deinit(allocator);
    for (deposit_requests) |request| {
        deposits.appendAssumeCapacity(.{
            .pubkey = request.pubkey,
            .withdrawal_credentials = request.withdrawal_credentials,
            .amount = request.amount,
            .signature = request.signature,
            .index = request.index,
        });
    }

    var withdrawals = try std.ArrayListUnmanaged(types.electra.WithdrawalRequest.Type).initCapacity(
        allocator,
        withdrawal_requests.len,
    );
    errdefer withdrawals.deinit(allocator);
    for (withdrawal_requests) |request| {
        withdrawals.appendAssumeCapacity(.{
            .source_address = request.source_address,
            .validator_pubkey = request.validator_pubkey,
            .amount = request.amount,
        });
    }

    var consolidations = try std.ArrayListUnmanaged(types.electra.ConsolidationRequest.Type).initCapacity(
        allocator,
        consolidation_requests.len,
    );
    errdefer consolidations.deinit(allocator);
    for (consolidation_requests) |request| {
        consolidations.appendAssumeCapacity(.{
            .source_address = request.source_address,
            .source_pubkey = request.source_pubkey,
            .target_pubkey = request.target_pubkey,
        });
    }

    return .{
        .deposits = deposits,
        .withdrawals = withdrawals,
        .consolidations = consolidations,
    };
}

fn convertBuilderPayloadHeader(
    allocator: std.mem.Allocator,
    header: execution_mod.builder.ExecutionPayloadHeader,
) !types.deneb.ExecutionPayloadHeader.Type {
    var extra_data: std.ArrayListUnmanaged(u8) = .empty;
    errdefer extra_data.deinit(allocator);
    if (header.extra_data.len > 0) {
        try extra_data.appendSlice(allocator, header.extra_data);
    }

    return .{
        .parent_hash = header.parent_hash,
        .fee_recipient = header.fee_recipient,
        .state_root = header.state_root,
        .receipts_root = header.receipts_root,
        .logs_bloom = header.logs_bloom,
        .prev_randao = header.prev_randao,
        .block_number = header.block_number,
        .gas_limit = header.gas_limit,
        .gas_used = header.gas_used,
        .timestamp = header.timestamp,
        .extra_data = extra_data,
        .base_fee_per_gas = header.base_fee_per_gas,
        .block_hash = header.block_hash,
        .transactions_root = header.transactions_root,
        .withdrawals_root = header.withdrawals_root orelse std.mem.zeroes([32]u8),
        .blob_gas_used = header.blob_gas_used orelse 0,
        .excess_blob_gas = header.excess_blob_gas orelse 0,
    };
}

fn ensureExecutionPayloadForTemplate(
    self: *BeaconNode,
    snapshot: *const ProposalSnapshot,
    fee_recipient: [20]u8,
) !void {
    if (!self.execution_runtime.hasExecutionEngine()) return error.NoEngineApi;

    self.execution_runtime.invalidatePreparedPayloadIfStale(snapshot.slot, snapshot.parent_root);
    if (self.execution_runtime.cachedPayloadFor(snapshot.slot, snapshot.parent_root)) return;

    const fc_state = self.chainQuery().executionForkchoiceState(snapshot.parent_root) orelse return;
    const queue_result = try self.execution_runtime.ensurePayloadPreparationAsync(snapshot.slot, .{
        .beacon_block_root = snapshot.parent_root,
        .state = fc_state,
    }, .{
        .timestamp = slotStartTimestamp(self, snapshot.slot),
        .prev_randao = snapshot.prev_randao,
        .suggested_fee_recipient = fee_recipient,
        .withdrawals = &.{},
        .parent_beacon_block_root = snapshot.parent_root,
    });
    switch (queue_result) {
        .ready => {},
        .queued => |ticket| switch (self.execution_runtime.waitForPayloadPreparation(
            ticket,
            snapshot.slot,
            snapshot.parent_root,
        )) {
            .ready => {},
            .unavailable => return error.NoEngineApi,
            .failed => return error.ExecutionForkchoiceUpdateFailed,
            .shutdown => return error.ExecutionRuntimeShutdown,
        },
        .pending => |ticket| switch (self.execution_runtime.waitForPayloadPreparation(
            ticket,
            snapshot.slot,
            snapshot.parent_root,
        )) {
            .ready => {},
            .unavailable => return error.NoEngineApi,
            .failed => return error.ExecutionForkchoiceUpdateFailed,
            .shutdown => return error.ExecutionRuntimeShutdown,
        },
        .unavailable => return error.ExecutionRuntimeBusy,
    }

    if (!self.execution_runtime.cachedPayloadFor(snapshot.slot, snapshot.parent_root)) {
        return error.NoPayloadId;
    }
}

fn assembleFullBlockFromPayloadResponse(
    self: *BeaconNode,
    template: PreparedProposalTemplate,
    resp: GetPayloadResponse,
) !ProducedBlock {
    defer self.execution_runtime.freeGetPayloadResponse(resp);

    var exec_payload = try convertEnginePayload(self.allocator, resp.execution_payload);
    errdefer types.electra.ExecutionPayload.deinit(self.allocator, &exec_payload);
    const blobs_bundle = try copyBlobsBundle(self.allocator, resp.blobs_bundle);
    errdefer if (blobs_bundle) |bundle| {
        if (bundle.commitments.len > 0) self.allocator.free(bundle.commitments);
        if (bundle.proofs.len > 0) self.allocator.free(bundle.proofs);
        if (bundle.blobs.len > 0) self.allocator.free(bundle.blobs);
    };
    var blob_commitments = try copyBlobCommitments(self.allocator, resp.blobs_bundle.commitments);
    errdefer blob_commitments.deinit(self.allocator);
    var execution_requests = try convertExecutionRequests(
        self.allocator,
        resp.deposit_requests,
        resp.withdrawal_requests,
        resp.consolidation_requests,
    );
    errdefer {
        execution_requests.deposits.deinit(self.allocator);
        execution_requests.withdrawals.deinit(self.allocator);
        execution_requests.consolidations.deinit(self.allocator);
    }

    const block = try self.chainService().assemblePreparedBlock(
        template,
        exec_payload,
        blobs_bundle,
        resp.block_value,
        blob_commitments,
        execution_requests,
    );

    std.log.info("produced full block: slot={d} proposer={d} parent={s}... value={d}", .{
        block.slot,
        block.proposer_index,
        &std.fmt.bytesToHex(block.parent_root[0..4], .lower),
        @as(u64, @truncate(block.block_value)),
    });

    return block;
}

fn assembleBlindedBlockFromBuilderBid(
    self: *BeaconNode,
    template: PreparedProposalTemplate,
    bid: execution_mod.builder.SignedBuilderBid,
) !ProducedBlindedBlock {
    defer execution_mod.builder.freeBid(self.allocator, bid);

    var header = try convertBuilderPayloadHeader(self.allocator, bid.message.header);
    errdefer types.deneb.ExecutionPayloadHeader.deinit(self.allocator, &header);
    var blob_commitments = try copyBlobCommitments(self.allocator, bid.message.blob_kzg_commitments);
    errdefer blob_commitments.deinit(self.allocator);
    var execution_requests = try convertExecutionRequests(
        self.allocator,
        bid.message.deposit_requests,
        bid.message.withdrawal_requests,
        bid.message.consolidation_requests,
    );
    errdefer {
        execution_requests.deposits.deinit(self.allocator);
        execution_requests.withdrawals.deinit(self.allocator);
        execution_requests.consolidations.deinit(self.allocator);
    }

    const block = try self.chainService().assemblePreparedBlindedBlock(
        template,
        header,
        bid.message.value,
        blob_commitments,
        execution_requests,
    );

    std.log.info("produced builder blinded block: slot={d} proposer={d} parent={s}... value={d}", .{
        block.slot,
        block.proposer_index,
        &std.fmt.bytesToHex(block.parent_root[0..4], .lower),
        @as(u64, @truncate(block.block_value)),
    });

    return block;
}

pub fn produceFullBlock(self: *BeaconNode, slot: u64, prod_config: BlockProductionConfig) !ProducedBlock {
    const context = try prepareProposalContext(self, slot, prod_config);

    try ensureExecutionPayloadForTemplate(self, &context.snapshot, context.config.fee_recipient);
    const payload_id = self.execution_runtime.cachedPayloadId() orelse return error.NoPayloadId;

    var payload_fetch = try self.execution_runtime.startPreparedPayloadFetch(payload_id);
    errdefer payload_fetch.deinit();

    const template = try self.chainService().buildProposalTemplate(context.snapshot, context.config);
    const payload_result = payload_fetch.finish();

    switch (payload_result) {
        .pending => unreachable,
        .success => |resp| {
            clearCachedPayloadIdIfCurrent(self, &context.snapshot, payload_id);
            return assembleFullBlockFromPayloadResponse(self, template, resp);
        },
        .unavailable => return error.NoEngineApi,
        .failure => |err| {
            std.log.warn("execution engine getPayload failed for slot={d}: {}", .{ slot, err });
            return err;
        },
        .canceled => return error.Canceled,
    }
}

pub fn produceEngineOrBuilderProposal(
    self: *BeaconNode,
    slot: u64,
    prod_config: BlockProductionConfig,
    builder_boost_factor: u64,
) !ProducedProposal {
    if (self.execution_runtime.builderApi() == null) {
        return .{ .engine = try produceFullBlock(self, slot, prod_config) };
    }
    switch (currentBuilderStatus(self)) {
        .available => {},
        .unavailable, .circuit_breaker => {
            return .{ .engine = try produceFullBlock(self, slot, prod_config) };
        },
    }

    const context = try prepareProposalContext(self, slot, prod_config);

    try ensureExecutionPayloadForTemplate(self, &context.snapshot, context.config.fee_recipient);
    const payload_id = self.execution_runtime.cachedPayloadId() orelse return error.NoPayloadId;
    const proposer_pubkey = context.snapshot.proposer_pubkey;
    const parent_hash = context.snapshot.execution_parent_hash;

    const template = try self.chainService().buildProposalTemplate(context.snapshot, context.config);
    var fetched = try self.execution_runtime.fetchProposalSources(
        self.allocator,
        payload_id,
        slot,
        parent_hash,
        proposer_pubkey,
        proposalRaceCutoffNs(self, slot),
        BLOCK_PRODUCTION_RACE_TIMEOUT_MS,
        builder_boost_factor == 0,
    );
    defer fetched.deinit(self.execution_runtime, self.allocator);

    if (fetched.payload != null) {
        clearCachedPayloadIdIfCurrent(self, &context.snapshot, payload_id);
    }
    if (fetched.engine_error) |err| {
        std.log.warn("execution engine getPayload failed for slot={d}: {}", .{ slot, err });
    }
    if (fetched.builder_no_bid) {
        std.log.debug("Builder: no bid available for slot={d}", .{slot});
    }
    if (fetched.builder_error) |err| {
        std.log.warn("builder getHeader failed for slot={d}: {}", .{ slot, err });
    }

    if (fetched.payload == null and fetched.builder_bid == null and fetched.timed_out) {
        return error.BlockProductionTimeout;
    }

    if (fetched.payload == null) {
        if (fetched.takeBuilderBid()) |bid| {
            validateBuilderHeaderGasLimit(self, slot, proposer_pubkey, bid.message.header.gas_limit) catch |err| switch (err) {
                error.BuilderHeaderGasLimitOutOfRange => {
                    execution_mod.builder.freeBid(self.allocator, bid);
                    return err;
                },
                else => {
                    execution_mod.builder.freeBid(self.allocator, bid);
                    return err;
                },
            };
            return .{ .builder = try assembleBlindedBlockFromBuilderBid(self, template, bid) };
        }
        if (fetched.engine_error) |err| return err;
        if (fetched.builder_error) |err| return err;
        if (fetched.builder_no_bid) return error.BuilderBidUnavailable;
        return error.BlockProductionTimeout;
    }

    const local_payload = fetched.takePayload().?;
    if (local_payload.should_override_builder or builder_boost_factor == 0) {
        if (fetched.takeBuilderBid()) |bid| execution_mod.builder.freeBid(self.allocator, bid);
        if (local_payload.should_override_builder) {
            std.log.debug("Builder: local execution payload overrides builder for slot={d}", .{slot});
        }
        return .{ .engine = try assembleFullBlockFromPayloadResponse(self, template, local_payload) };
    }

    const bid = fetched.takeBuilderBid() orelse {
        return .{ .engine = try assembleFullBlockFromPayloadResponse(self, template, local_payload) };
    };

    validateBuilderHeaderGasLimit(self, slot, proposer_pubkey, bid.message.header.gas_limit) catch |err| switch (err) {
        error.BuilderHeaderGasLimitOutOfRange => {
            execution_mod.builder.freeBid(self.allocator, bid);
            return .{ .engine = try assembleFullBlockFromPayloadResponse(self, template, local_payload) };
        },
        else => {
            self.execution_runtime.freeGetPayloadResponse(local_payload);
            execution_mod.builder.freeBid(self.allocator, bid);
            return err;
        },
    };

    const builder_value_scaled = (bid.message.value * @as(u256, builder_boost_factor)) / 100;
    if (bid.message.value == 0 or
        engineValueMeetsBuilderThreshold(local_payload.block_value, bid.message.value, builder_boost_factor))
    {
        std.log.debug(
            "Builder: local execution value {d} >= boosted builder value {d} (builder={d} boost={d}) for slot={d}",
            .{
                @as(u64, @truncate(local_payload.block_value)),
                @as(u64, @truncate(builder_value_scaled)),
                @as(u64, @truncate(bid.message.value)),
                builder_boost_factor,
                slot,
            },
        );
        execution_mod.builder.freeBid(self.allocator, bid);
        return .{ .engine = try assembleFullBlockFromPayloadResponse(self, template, local_payload) };
    }

    self.execution_runtime.freeGetPayloadResponse(local_payload);
    return .{ .builder = try assembleBlindedBlockFromBuilderBid(self, template, bid) };
}

pub fn produceBuilderBlindedBlock(
    self: *BeaconNode,
    slot: u64,
    prod_config: BlockProductionConfig,
    builder_boost_factor: ?u64,
    require_builder: bool,
) !?ProducedBlindedBlock {
    if (!require_builder) {
        if (builder_boost_factor) |boost_factor| {
            var produced = try produceEngineOrBuilderProposal(self, slot, prod_config, boost_factor);
            return switch (produced) {
                .builder => |value| value,
                .engine => |*engine_block| blk: {
                    engine_block.deinit(self.allocator);
                    break :blk null;
                },
            };
        }
    }

    if (self.execution_runtime.builderApi() == null) {
        if (require_builder) return error.BuilderNotConfigured;
        return null;
    }
    switch (currentBuilderStatus(self)) {
        .available => {},
        .unavailable => {
            if (require_builder) return error.BuilderUnavailable;
            return null;
        },
        .circuit_breaker => {
            if (require_builder) return error.BuilderCircuitBreaker;
            return null;
        },
    }

    const context = try prepareProposalContext(self, slot, prod_config);

    const proposer_pubkey = context.snapshot.proposer_pubkey;
    const parent_hash = context.snapshot.execution_parent_hash;

    var builder_bid_fetch = try self.execution_runtime.startBuilderBidFetch(
        slot,
        parent_hash,
        proposer_pubkey,
    );
    errdefer builder_bid_fetch.deinit();

    const template = try self.chainService().buildProposalTemplate(context.snapshot, context.config);
    const builder_bid_result = builder_bid_fetch.finish();

    switch (builder_bid_result) {
        .pending => unreachable,
        .success => |bid| {
            errdefer execution_mod.builder.freeBid(self.allocator, bid);
            validateBuilderHeaderGasLimit(self, slot, proposer_pubkey, bid.message.header.gas_limit) catch |err| switch (err) {
                error.BuilderHeaderGasLimitOutOfRange => {
                    if (require_builder) return err;
                    return null;
                },
                else => return err,
            };
            return try assembleBlindedBlockFromBuilderBid(self, template, bid);
        },
        .unavailable => {
            if (require_builder) return error.BuilderNotConfigured;
            return null;
        },
        .no_bid => {
            std.log.debug("Builder: no bid available for slot={d}", .{slot});
            if (require_builder) return error.BuilderBidUnavailable;
            return null;
        },
        .failure => |err| {
            std.log.warn("builder getHeader error for slot={d}: {}", .{ slot, err });
            if (require_builder) return error.BuilderBidUnavailable;
            return null;
        },
        .canceled => return error.Canceled,
    }
}

pub fn ensureProducedFeeRecipient(
    produced: *const ProducedBlock,
    expected_fee_recipient: [20]u8,
    strict_fee_recipient_check: bool,
) !void {
    if (!strict_fee_recipient_check) return;
    if (std.mem.eql(u8, &produced.block_body.execution_payload.fee_recipient, &expected_fee_recipient)) return;

    std.log.err("Produced block fee recipient mismatch expected=0x{s} actual=0x{s}", .{
        std.fmt.bytesToHex(&expected_fee_recipient, .lower),
        std.fmt.bytesToHex(&produced.block_body.execution_payload.fee_recipient, .lower),
    });
    return error.FeeRecipientMismatch;
}

pub fn ensureProducedBlindedFeeRecipient(
    produced: *const ProducedBlindedBlock,
    expected_fee_recipient: [20]u8,
    strict_fee_recipient_check: bool,
) !void {
    if (!strict_fee_recipient_check) return;
    if (std.mem.eql(u8, &produced.block_body.execution_payload_header.fee_recipient, &expected_fee_recipient)) return;

    std.log.err("Produced blinded block fee recipient mismatch expected=0x{s} actual=0x{s}", .{
        std.fmt.bytesToHex(&expected_fee_recipient, .lower),
        std.fmt.bytesToHex(&produced.block_body.execution_payload_header.fee_recipient, .lower),
    });
    return error.FeeRecipientMismatch;
}

fn computeStateTransitionMetaForAnyBlock(
    self: *BeaconNode,
    any_block: fork_types.AnySignedBeaconBlock,
) !ProducedStateTransitionMeta {
    const head_state = self.headState() orelse return error.NoHeadState;

    var state_graph_lease = self.chainService().acquireStateGraphLease();
    defer state_graph_lease.release();

    const post_state = state_transition.stateTransition(
        self.allocator,
        head_state,
        any_block,
        .{
            .verify_state_root = false,
            .verify_proposer = false,
            .verify_signatures = false,
            .transfer_cache = false,
        },
    ) catch |err| {
        std.log.warn("state transition for block state root failed: {}", .{err});
        return err;
    };
    defer {
        post_state.deinit();
        self.allocator.destroy(post_state);
    }

    return .{
        .state_root = (try post_state.state.hashTreeRoot()).*,
        .consensus_block_value = @as(u256, post_state.getProposerRewards().total()) * @as(u256, 1_000_000_000),
    };
}

fn computeProducedStateTransitionMeta(
    self: *BeaconNode,
    slot: u64,
    produced: *const ProducedBlock,
) !ProducedStateTransitionMeta {
    var signed_block = types.electra.SignedBeaconBlock.Type{
        .message = .{
            .slot = slot,
            .proposer_index = produced.proposer_index,
            .parent_root = produced.parent_root,
            .state_root = [_]u8{0} ** 32,
            .body = produced.block_body,
        },
        .signature = [_]u8{0} ** 96,
    };

    const any_block: fork_types.AnySignedBeaconBlock = switch (self.config.forkSeq(slot)) {
        .fulu => .{ .full_fulu = @ptrCast(&signed_block) },
        else => .{ .full_electra = &signed_block },
    };

    return computeStateTransitionMetaForAnyBlock(self, any_block);
}

fn computeProducedBlindedStateTransitionMeta(
    self: *BeaconNode,
    slot: u64,
    produced: *const ProducedBlindedBlock,
) !ProducedStateTransitionMeta {
    var signed_block = types.electra.SignedBlindedBeaconBlock.Type{
        .message = .{
            .slot = slot,
            .proposer_index = produced.proposer_index,
            .parent_root = produced.parent_root,
            .state_root = [_]u8{0} ** 32,
            .body = produced.block_body,
        },
        .signature = [_]u8{0} ** 96,
    };

    const any_block: fork_types.AnySignedBeaconBlock = switch (self.config.forkSeq(slot)) {
        .fulu => .{ .blinded_fulu = @ptrCast(&signed_block) },
        else => .{ .blinded_electra = &signed_block },
    };

    return computeStateTransitionMetaForAnyBlock(self, any_block);
}

pub fn serializeUnsignedBlock(
    self: *BeaconNode,
    allocator: std.mem.Allocator,
    slot: u64,
    produced: *const ProducedBlock,
    block_type: BlockType,
) !SerializedUnsignedBlock {
    return switch (block_type) {
        .full => serializeUnsignedFullBlock(self, allocator, slot, produced),
        .blinded => serializeUnsignedBlindedBlock(self, allocator, slot, produced),
    };
}

pub fn serializeUnsignedProducedBlindedBlock(
    self: *BeaconNode,
    allocator: std.mem.Allocator,
    slot: u64,
    produced: *const ProducedBlindedBlock,
) !SerializedUnsignedBlock {
    const transition_meta = try computeProducedBlindedStateTransitionMeta(self, slot, produced);
    const state_root = transition_meta.state_root;
    const fork_seq = self.config.forkSeq(slot);
    if (fork_seq.lt(.bellatrix)) return error.InvalidFork;

    const ssz_bytes = switch (fork_seq) {
        .electra => blk: {
            const block = types.electra.BlindedBeaconBlock.Type{
                .slot = slot,
                .proposer_index = produced.proposer_index,
                .parent_root = produced.parent_root,
                .state_root = state_root,
                .body = produced.block_body,
            };
            const out = try allocator.alloc(u8, types.electra.BlindedBeaconBlock.serializedSize(&block));
            errdefer allocator.free(out);
            _ = types.electra.BlindedBeaconBlock.serializeIntoBytes(&block, out);
            break :blk out;
        },
        .fulu => blk: {
            const block = types.fulu.BlindedBeaconBlock.Type{
                .slot = slot,
                .proposer_index = produced.proposer_index,
                .parent_root = produced.parent_root,
                .state_root = state_root,
                .body = produced.block_body,
            };
            const out = try allocator.alloc(u8, types.fulu.BlindedBeaconBlock.serializedSize(&block));
            errdefer allocator.free(out);
            _ = types.fulu.BlindedBeaconBlock.serializeIntoBytes(&block, out);
            break :blk out;
        },
        else => return error.UnsupportedFork,
    };

    return .{
        .ssz_bytes = ssz_bytes,
        .fork_name = @tagName(fork_seq),
        .block_type = .blinded,
        .consensus_block_value = transition_meta.consensus_block_value,
    };
}

fn serializeUnsignedFullBlock(
    self: *BeaconNode,
    allocator: std.mem.Allocator,
    slot: u64,
    produced: *const ProducedBlock,
) !SerializedUnsignedBlock {
    const transition_meta = try computeProducedStateTransitionMeta(self, slot, produced);
    const state_root = transition_meta.state_root;
    const fork_seq = self.config.forkSeq(slot);

    var block = types.electra.BeaconBlock.Type{
        .slot = slot,
        .proposer_index = produced.proposer_index,
        .parent_root = produced.parent_root,
        .state_root = state_root,
        .body = produced.block_body,
    };

    const ssz_bytes = switch (fork_seq) {
        .electra => blk: {
            const out = try allocator.alloc(u8, types.electra.BeaconBlock.serializedSize(&block));
            errdefer allocator.free(out);
            _ = types.electra.BeaconBlock.serializeIntoBytes(&block, out);
            break :blk out;
        },
        .fulu => blk: {
            const fulu_block: *const types.fulu.BeaconBlock.Type = @ptrCast(&block);
            const out = try allocator.alloc(u8, types.fulu.BeaconBlock.serializedSize(fulu_block));
            errdefer allocator.free(out);
            _ = types.fulu.BeaconBlock.serializeIntoBytes(fulu_block, out);
            break :blk out;
        },
        else => return error.UnsupportedFork,
    };

    return .{
        .ssz_bytes = ssz_bytes,
        .fork_name = @tagName(fork_seq),
        .block_type = .full,
        .consensus_block_value = transition_meta.consensus_block_value,
    };
}

fn createProducedPayloadHeader(
    allocator: std.mem.Allocator,
    fork_seq: config_mod.ForkSeq,
    payload: *const types.electra.ExecutionPayload.Type,
) !AnyExecutionPayloadHeader {
    var header = try AnyExecutionPayloadHeader.init(fork_seq);
    errdefer header.deinit(allocator);

    const any_payload: AnyExecutionPayload = .{ .deneb = payload.* };
    try any_payload.createPayloadHeader(allocator, &header);
    return header;
}

fn serializeUnsignedBlindedBlock(
    self: *BeaconNode,
    allocator: std.mem.Allocator,
    slot: u64,
    produced: *const ProducedBlock,
) !SerializedUnsignedBlock {
    const transition_meta = try computeProducedStateTransitionMeta(self, slot, produced);
    const state_root = transition_meta.state_root;
    const fork_seq = self.config.forkSeq(slot);
    if (fork_seq.lt(.bellatrix)) return error.InvalidFork;

    var payload_header = try createProducedPayloadHeader(allocator, fork_seq, &produced.block_body.execution_payload);
    defer payload_header.deinit(allocator);

    const ssz_bytes = switch (fork_seq) {
        .electra => blk: {
            const block = types.electra.BlindedBeaconBlock.Type{
                .slot = slot,
                .proposer_index = produced.proposer_index,
                .parent_root = produced.parent_root,
                .state_root = state_root,
                .body = .{
                    .randao_reveal = produced.block_body.randao_reveal,
                    .eth1_data = produced.block_body.eth1_data,
                    .graffiti = produced.block_body.graffiti,
                    .proposer_slashings = produced.block_body.proposer_slashings,
                    .attester_slashings = produced.block_body.attester_slashings,
                    .attestations = produced.block_body.attestations,
                    .deposits = produced.block_body.deposits,
                    .voluntary_exits = produced.block_body.voluntary_exits,
                    .sync_aggregate = produced.block_body.sync_aggregate,
                    .execution_payload_header = payload_header.deneb,
                    .bls_to_execution_changes = produced.block_body.bls_to_execution_changes,
                    .blob_kzg_commitments = produced.block_body.blob_kzg_commitments,
                    .execution_requests = produced.block_body.execution_requests,
                },
            };
            const out = try allocator.alloc(u8, types.electra.BlindedBeaconBlock.serializedSize(&block));
            errdefer allocator.free(out);
            _ = types.electra.BlindedBeaconBlock.serializeIntoBytes(&block, out);
            break :blk out;
        },
        .fulu => blk: {
            const block = types.fulu.BlindedBeaconBlock.Type{
                .slot = slot,
                .proposer_index = produced.proposer_index,
                .parent_root = produced.parent_root,
                .state_root = state_root,
                .body = .{
                    .randao_reveal = produced.block_body.randao_reveal,
                    .eth1_data = produced.block_body.eth1_data,
                    .graffiti = produced.block_body.graffiti,
                    .proposer_slashings = produced.block_body.proposer_slashings,
                    .attester_slashings = produced.block_body.attester_slashings,
                    .attestations = produced.block_body.attestations,
                    .deposits = produced.block_body.deposits,
                    .voluntary_exits = produced.block_body.voluntary_exits,
                    .sync_aggregate = produced.block_body.sync_aggregate,
                    .execution_payload_header = payload_header.deneb,
                    .bls_to_execution_changes = produced.block_body.bls_to_execution_changes,
                    .blob_kzg_commitments = produced.block_body.blob_kzg_commitments,
                    .execution_requests = produced.block_body.execution_requests,
                },
            };
            const out = try allocator.alloc(u8, types.fulu.BlindedBeaconBlock.serializedSize(&block));
            errdefer allocator.free(out);
            _ = types.fulu.BlindedBeaconBlock.serializeIntoBytes(&block, out);
            break :blk out;
        },
        else => return error.UnsupportedFork,
    };

    return .{
        .ssz_bytes = ssz_bytes,
        .fork_name = @tagName(fork_seq),
        .block_type = .blinded,
        .consensus_block_value = transition_meta.consensus_block_value,
    };
}

pub fn produceAndIngestBlock(
    self: *BeaconNode,
    slot: u64,
    prod_config: BlockProductionConfig,
) !struct { signed_block: *types.electra.SignedBeaconBlock.Type, ingress_result: BeaconNode.ReadyIngressResult } {
    var produced = try produceFullBlock(self, slot, prod_config);

    const signed_block = try self.allocator.create(types.electra.SignedBeaconBlock.Type);
    errdefer self.allocator.destroy(signed_block);

    signed_block.* = .{
        .message = .{
            .slot = slot,
            .proposer_index = produced.proposer_index,
            .parent_root = produced.parent_root,
            .state_root = [_]u8{0} ** 32,
            .body = produced.block_body,
        },
        .signature = [_]u8{0} ** 96,
    };

    if (self.headState()) |head_state| {
        const any_block: fork_types.AnySignedBeaconBlock = switch (self.config.forkSeq(slot)) {
            .fulu => .{ .full_fulu = @ptrCast(signed_block) },
            else => .{ .full_electra = signed_block },
        };

        var state_graph_lease = self.chainService().acquireStateGraphLease();
        defer state_graph_lease.release();

        const post_state = state_transition.stateTransition(
            self.allocator,
            head_state,
            any_block,
            .{
                .verify_state_root = false,
                .verify_proposer = false,
                .verify_signatures = false,
                .transfer_cache = false,
            },
        ) catch |err| {
            std.log.warn("state transition for state root computation failed: {}", .{err});
            return err;
        };
        defer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        const state_root = post_state.state.hashTreeRoot() catch |err| {
            std.log.warn("hashTreeRoot failed: {}", .{err});
            return err;
        };

        signed_block.message.state_root = state_root.*;

        std.log.debug("Computed state root for block: slot={d} state_root={s}...", .{
            slot,
            &std.fmt.bytesToHex(state_root[0..4], .lower),
        });
    } else {
        std.log.warn("no head state available for state root computation at slot={d}", .{slot});
    }

    const any_signed_produced: fork_types.AnySignedBeaconBlock = switch (self.config.forkSeq(slot)) {
        .fulu => .{ .full_fulu = @ptrCast(signed_block) },
        else => .{ .full_electra = signed_block },
    };
    const block_bytes = try any_signed_produced.serialize(self.allocator);
    defer self.allocator.free(block_bytes);

    const ingress_result = try self.ingestRawBlockBytes(block_bytes, .api);

    switch (ingress_result) {
        .ignored => {
            std.log.info("block produced and ignored during local ingest: slot={d}", .{slot});
        },
        .queued => {
            std.log.info("block produced and queued for local ingest: slot={d}", .{slot});
        },
        .imported => |import_result| {
            std.log.info("block produced and imported: slot={d} root={s}...", .{
                slot,
                &std.fmt.bytesToHex(import_result.block_root[0..4], .lower),
            });
        },
    }

    produced.block_body = types.electra.BeaconBlockBody.default_value;

    return .{
        .signed_block = signed_block,
        .ingress_result = ingress_result,
    };
}

pub fn broadcastBlock(
    self: *BeaconNode,
    signed_block: *const types.electra.SignedBeaconBlock.Type,
) !void {
    const p2p = self.p2p_service orelse {
        std.log.warn("no P2P service — cannot broadcast block at slot={d}", .{signed_block.message.slot});
        return;
    };

    const serialized_size = types.electra.SignedBeaconBlock.serializedSize(signed_block);
    const buf = try self.allocator.alloc(u8, serialized_size);
    defer self.allocator.free(buf);
    _ = types.electra.SignedBeaconBlock.serializeIntoBytes(signed_block, buf);

    _ = p2p.publishGossip(self.io, .beacon_block, null, buf) catch |err| {
        std.log.warn("failed to broadcast block at slot={d}: {}", .{ signed_block.message.slot, err });
        return;
    };

    std.log.info("broadcast block via gossip: slot={d}", .{signed_block.message.slot});
}

fn convertTransactions(
    allocator: std.mem.Allocator,
    engine_payload: execution_mod.engine_api_types.ExecutionPayloadV3,
) !std.ArrayListUnmanaged(types.bellatrix.Transactions.Element.Type) {
    var transactions = try std.ArrayListUnmanaged(
        types.bellatrix.Transactions.Element.Type,
    ).initCapacity(allocator, engine_payload.transactions.len);
    errdefer {
        for (transactions.items) |*tx| tx.deinit(allocator);
        transactions.deinit(allocator);
    }

    for (engine_payload.transactions) |tx_bytes| {
        var tx_data: std.ArrayListUnmanaged(u8) = .empty;
        try tx_data.appendSlice(allocator, tx_bytes);
        transactions.appendAssumeCapacity(tx_data);
    }

    return transactions;
}

fn convertWithdrawals(
    allocator: std.mem.Allocator,
    engine_payload: execution_mod.engine_api_types.ExecutionPayloadV3,
) !std.ArrayListUnmanaged(types.capella.Withdrawal.Type) {
    var withdrawals = try std.ArrayListUnmanaged(
        types.capella.Withdrawal.Type,
    ).initCapacity(allocator, engine_payload.withdrawals.len);
    errdefer withdrawals.deinit(allocator);

    for (engine_payload.withdrawals) |withdrawal| {
        withdrawals.appendAssumeCapacity(.{
            .index = withdrawal.index,
            .validator_index = withdrawal.validator_index,
            .address = withdrawal.address,
            .amount = withdrawal.amount,
        });
    }

    return withdrawals;
}

fn convertExtraData(
    allocator: std.mem.Allocator,
    engine_payload: execution_mod.engine_api_types.ExecutionPayloadV3,
) !std.ArrayListUnmanaged(u8) {
    var extra_data: std.ArrayListUnmanaged(u8) = .empty;
    errdefer extra_data.deinit(allocator);
    if (engine_payload.extra_data.len > 0) {
        try extra_data.appendSlice(allocator, engine_payload.extra_data);
    }
    return extra_data;
}

fn convertBellatrixPayload(
    allocator: std.mem.Allocator,
    engine_payload: execution_mod.engine_api_types.ExecutionPayloadV3,
) !types.bellatrix.ExecutionPayload.Type {
    const transactions = try convertTransactions(allocator, engine_payload);
    errdefer {
        for (transactions.items) |*tx| tx.deinit(allocator);
        var owned = transactions;
        owned.deinit(allocator);
    }
    const extra_data = try convertExtraData(allocator, engine_payload);
    errdefer {
        var owned = extra_data;
        owned.deinit(allocator);
    }

    return .{
        .parent_hash = engine_payload.parent_hash,
        .fee_recipient = engine_payload.fee_recipient,
        .state_root = engine_payload.state_root,
        .receipts_root = engine_payload.receipts_root,
        .logs_bloom = engine_payload.logs_bloom,
        .prev_randao = engine_payload.prev_randao,
        .block_number = engine_payload.block_number,
        .gas_limit = engine_payload.gas_limit,
        .gas_used = engine_payload.gas_used,
        .timestamp = engine_payload.timestamp,
        .extra_data = extra_data,
        .base_fee_per_gas = engine_payload.base_fee_per_gas,
        .block_hash = engine_payload.block_hash,
        .transactions = transactions,
    };
}

fn convertCapellaPayload(
    allocator: std.mem.Allocator,
    engine_payload: execution_mod.engine_api_types.ExecutionPayloadV3,
) !types.capella.ExecutionPayload.Type {
    const transactions = try convertTransactions(allocator, engine_payload);
    errdefer {
        for (transactions.items) |*tx| tx.deinit(allocator);
        var owned = transactions;
        owned.deinit(allocator);
    }
    const withdrawals = try convertWithdrawals(allocator, engine_payload);
    errdefer {
        var owned = withdrawals;
        owned.deinit(allocator);
    }
    const extra_data = try convertExtraData(allocator, engine_payload);
    errdefer {
        var owned = extra_data;
        owned.deinit(allocator);
    }

    return .{
        .parent_hash = engine_payload.parent_hash,
        .fee_recipient = engine_payload.fee_recipient,
        .state_root = engine_payload.state_root,
        .receipts_root = engine_payload.receipts_root,
        .logs_bloom = engine_payload.logs_bloom,
        .prev_randao = engine_payload.prev_randao,
        .block_number = engine_payload.block_number,
        .gas_limit = engine_payload.gas_limit,
        .gas_used = engine_payload.gas_used,
        .timestamp = engine_payload.timestamp,
        .extra_data = extra_data,
        .base_fee_per_gas = engine_payload.base_fee_per_gas,
        .block_hash = engine_payload.block_hash,
        .transactions = transactions,
        .withdrawals = withdrawals,
    };
}

fn convertEnginePayload(
    allocator: std.mem.Allocator,
    engine_payload: execution_mod.engine_api_types.ExecutionPayloadV3,
) !types.electra.ExecutionPayload.Type {
    const transactions = try convertTransactions(allocator, engine_payload);
    errdefer {
        for (transactions.items) |*tx| tx.deinit(allocator);
        var owned = transactions;
        owned.deinit(allocator);
    }
    const withdrawals = try convertWithdrawals(allocator, engine_payload);
    errdefer {
        var owned = withdrawals;
        owned.deinit(allocator);
    }
    const extra_data = try convertExtraData(allocator, engine_payload);
    errdefer {
        var owned = extra_data;
        owned.deinit(allocator);
    }

    return types.electra.ExecutionPayload.Type{
        .parent_hash = engine_payload.parent_hash,
        .fee_recipient = engine_payload.fee_recipient,
        .state_root = engine_payload.state_root,
        .receipts_root = engine_payload.receipts_root,
        .logs_bloom = engine_payload.logs_bloom,
        .prev_randao = engine_payload.prev_randao,
        .block_number = engine_payload.block_number,
        .gas_limit = engine_payload.gas_limit,
        .gas_used = engine_payload.gas_used,
        .timestamp = engine_payload.timestamp,
        .extra_data = extra_data,
        .base_fee_per_gas = engine_payload.base_fee_per_gas,
        .block_hash = engine_payload.block_hash,
        .transactions = transactions,
        .withdrawals = withdrawals,
        .blob_gas_used = engine_payload.blob_gas_used,
        .excess_blob_gas = engine_payload.excess_blob_gas,
    };
}

pub fn unblindPublishedBlock(
    self: *BeaconNode,
    blinded_block: fork_types.AnySignedBeaconBlock,
) !fork_types.AnySignedBeaconBlock {
    if (blinded_block.blockType() != .blinded) return error.InvalidBlockType;

    const builder = self.execution_runtime.builderApi() orelse return error.BuilderNotConfigured;
    const payload = try builder.submitBlindedBlock(blinded_block);
    defer execution_mod.builder.freeExecutionPayload(self.allocator, payload);

    switch (blinded_block) {
        .blinded_bellatrix => |signed_blinded| {
            const execution_payload = try convertBellatrixPayload(self.allocator, payload);
            const full = try self.allocator.create(types.bellatrix.SignedBeaconBlock.Type);
            full.* = .{
                .message = .{
                    .slot = signed_blinded.message.slot,
                    .proposer_index = signed_blinded.message.proposer_index,
                    .parent_root = signed_blinded.message.parent_root,
                    .state_root = signed_blinded.message.state_root,
                    .body = .{
                        .randao_reveal = signed_blinded.message.body.randao_reveal,
                        .eth1_data = signed_blinded.message.body.eth1_data,
                        .graffiti = signed_blinded.message.body.graffiti,
                        .proposer_slashings = signed_blinded.message.body.proposer_slashings,
                        .attester_slashings = signed_blinded.message.body.attester_slashings,
                        .attestations = signed_blinded.message.body.attestations,
                        .deposits = signed_blinded.message.body.deposits,
                        .voluntary_exits = signed_blinded.message.body.voluntary_exits,
                        .sync_aggregate = signed_blinded.message.body.sync_aggregate,
                        .execution_payload = execution_payload,
                    },
                },
                .signature = signed_blinded.signature,
            };
            types.bellatrix.ExecutionPayloadHeader.deinit(self.allocator, &signed_blinded.message.body.execution_payload_header);
            self.allocator.destroy(signed_blinded);
            return .{ .full_bellatrix = full };
        },
        .blinded_capella => |signed_blinded| {
            const execution_payload = try convertCapellaPayload(self.allocator, payload);
            const full = try self.allocator.create(types.capella.SignedBeaconBlock.Type);
            full.* = .{
                .message = .{
                    .slot = signed_blinded.message.slot,
                    .proposer_index = signed_blinded.message.proposer_index,
                    .parent_root = signed_blinded.message.parent_root,
                    .state_root = signed_blinded.message.state_root,
                    .body = .{
                        .randao_reveal = signed_blinded.message.body.randao_reveal,
                        .eth1_data = signed_blinded.message.body.eth1_data,
                        .graffiti = signed_blinded.message.body.graffiti,
                        .proposer_slashings = signed_blinded.message.body.proposer_slashings,
                        .attester_slashings = signed_blinded.message.body.attester_slashings,
                        .attestations = signed_blinded.message.body.attestations,
                        .deposits = signed_blinded.message.body.deposits,
                        .voluntary_exits = signed_blinded.message.body.voluntary_exits,
                        .sync_aggregate = signed_blinded.message.body.sync_aggregate,
                        .execution_payload = execution_payload,
                        .bls_to_execution_changes = signed_blinded.message.body.bls_to_execution_changes,
                    },
                },
                .signature = signed_blinded.signature,
            };
            types.capella.ExecutionPayloadHeader.deinit(self.allocator, &signed_blinded.message.body.execution_payload_header);
            self.allocator.destroy(signed_blinded);
            return .{ .full_capella = full };
        },
        .blinded_deneb => |signed_blinded| {
            const execution_payload = try convertEnginePayload(self.allocator, payload);
            const full = try self.allocator.create(types.deneb.SignedBeaconBlock.Type);
            full.* = .{
                .message = .{
                    .slot = signed_blinded.message.slot,
                    .proposer_index = signed_blinded.message.proposer_index,
                    .parent_root = signed_blinded.message.parent_root,
                    .state_root = signed_blinded.message.state_root,
                    .body = .{
                        .randao_reveal = signed_blinded.message.body.randao_reveal,
                        .eth1_data = signed_blinded.message.body.eth1_data,
                        .graffiti = signed_blinded.message.body.graffiti,
                        .proposer_slashings = signed_blinded.message.body.proposer_slashings,
                        .attester_slashings = signed_blinded.message.body.attester_slashings,
                        .attestations = signed_blinded.message.body.attestations,
                        .deposits = signed_blinded.message.body.deposits,
                        .voluntary_exits = signed_blinded.message.body.voluntary_exits,
                        .sync_aggregate = signed_blinded.message.body.sync_aggregate,
                        .execution_payload = execution_payload,
                        .bls_to_execution_changes = signed_blinded.message.body.bls_to_execution_changes,
                        .blob_kzg_commitments = signed_blinded.message.body.blob_kzg_commitments,
                    },
                },
                .signature = signed_blinded.signature,
            };
            types.deneb.ExecutionPayloadHeader.deinit(self.allocator, &signed_blinded.message.body.execution_payload_header);
            self.allocator.destroy(signed_blinded);
            return .{ .full_deneb = full };
        },
        .blinded_electra => |signed_blinded| {
            const execution_payload = try convertEnginePayload(self.allocator, payload);
            const full = try self.allocator.create(types.electra.SignedBeaconBlock.Type);
            full.* = .{
                .message = .{
                    .slot = signed_blinded.message.slot,
                    .proposer_index = signed_blinded.message.proposer_index,
                    .parent_root = signed_blinded.message.parent_root,
                    .state_root = signed_blinded.message.state_root,
                    .body = .{
                        .randao_reveal = signed_blinded.message.body.randao_reveal,
                        .eth1_data = signed_blinded.message.body.eth1_data,
                        .graffiti = signed_blinded.message.body.graffiti,
                        .proposer_slashings = signed_blinded.message.body.proposer_slashings,
                        .attester_slashings = signed_blinded.message.body.attester_slashings,
                        .attestations = signed_blinded.message.body.attestations,
                        .deposits = signed_blinded.message.body.deposits,
                        .voluntary_exits = signed_blinded.message.body.voluntary_exits,
                        .sync_aggregate = signed_blinded.message.body.sync_aggregate,
                        .execution_payload = execution_payload,
                        .bls_to_execution_changes = signed_blinded.message.body.bls_to_execution_changes,
                        .blob_kzg_commitments = signed_blinded.message.body.blob_kzg_commitments,
                        .execution_requests = signed_blinded.message.body.execution_requests,
                    },
                },
                .signature = signed_blinded.signature,
            };
            types.electra.ExecutionPayloadHeader.deinit(self.allocator, &signed_blinded.message.body.execution_payload_header);
            self.allocator.destroy(signed_blinded);
            return .{ .full_electra = full };
        },
        .blinded_fulu => |signed_blinded| {
            const execution_payload = try convertEnginePayload(self.allocator, payload);
            const full = try self.allocator.create(types.fulu.SignedBeaconBlock.Type);
            full.* = .{
                .message = .{
                    .slot = signed_blinded.message.slot,
                    .proposer_index = signed_blinded.message.proposer_index,
                    .parent_root = signed_blinded.message.parent_root,
                    .state_root = signed_blinded.message.state_root,
                    .body = .{
                        .randao_reveal = signed_blinded.message.body.randao_reveal,
                        .eth1_data = signed_blinded.message.body.eth1_data,
                        .graffiti = signed_blinded.message.body.graffiti,
                        .proposer_slashings = signed_blinded.message.body.proposer_slashings,
                        .attester_slashings = signed_blinded.message.body.attester_slashings,
                        .attestations = signed_blinded.message.body.attestations,
                        .deposits = signed_blinded.message.body.deposits,
                        .voluntary_exits = signed_blinded.message.body.voluntary_exits,
                        .sync_aggregate = signed_blinded.message.body.sync_aggregate,
                        .execution_payload = execution_payload,
                        .bls_to_execution_changes = signed_blinded.message.body.bls_to_execution_changes,
                        .blob_kzg_commitments = signed_blinded.message.body.blob_kzg_commitments,
                        .execution_requests = signed_blinded.message.body.execution_requests,
                    },
                },
                .signature = signed_blinded.signature,
            };
            types.fulu.ExecutionPayloadHeader.deinit(self.allocator, &signed_blinded.message.body.execution_payload_header);
            self.allocator.destroy(signed_blinded);
            return .{ .full_fulu = full };
        },
        else => return error.InvalidBlockType,
    }
}

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;

test "expectedBuilderGasLimit follows EIP-1559 adjustment bounds" {
    try std.testing.expectEqual(@as(u64, 30_029_295), expectedBuilderGasLimit(30_000_000, 60_000_000));
    try std.testing.expectEqual(@as(u64, 29_970_705), expectedBuilderGasLimit(30_000_000, 1));
    try std.testing.expectEqual(@as(u64, 30_000_000), expectedBuilderGasLimit(30_000_000, 30_000_000));
}

test "builderGasLimitBounds cover parent and expected gas limit" {
    const bounds = builderGasLimitBounds(30_000_000, 60_000_000);
    try std.testing.expectEqual(@as(u64, 30_029_295), bounds.expected);
    try std.testing.expectEqual(@as(u64, 30_000_000), bounds.lower);
    try std.testing.expectEqual(@as(u64, 30_029_295), bounds.upper);
}

test "engineValueMeetsBuilderThreshold matches builder boost semantics" {
    try std.testing.expect(engineValueMeetsBuilderThreshold(100, 100, 100));
    try std.testing.expect(!engineValueMeetsBuilderThreshold(99, 100, 100));
    try std.testing.expect(!engineValueMeetsBuilderThreshold(150, 100, 200));
    try std.testing.expect(engineValueMeetsBuilderThreshold(200, 100, 200));
    try std.testing.expect(engineValueMeetsBuilderThreshold(50, 100, 50));
    try std.testing.expect(engineValueMeetsBuilderThreshold(1, 10_000, 0));
}
