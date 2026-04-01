//! Node-owned execution and block production helpers.

const std = @import("std");
const log = @import("log");

const types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const chain_mod = @import("chain");
const ProducedBlockBody = chain_mod.ProducedBlockBody;
const ProducedBlock = chain_mod.ProducedBlock;
const BlockProductionConfig = chain_mod.BlockProductionConfig;
const ImportResult = chain_mod.ImportResult;
const execution_mod = @import("execution");
const ForkchoiceStateV1 = execution_mod.ForkchoiceStateV1;
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;
const GetPayloadResponse = execution_mod.GetPayloadResponse;
const BlockType = fork_types.BlockType;
const AnyExecutionPayload = fork_types.AnyExecutionPayload;
const AnyExecutionPayloadHeader = fork_types.AnyExecutionPayloadHeader;

pub const SerializedUnsignedBlock = struct {
    ssz_bytes: []u8,
    fork_name: []const u8,
    block_type: BlockType,
};

fn builderBidThresholdForConfig(self: *BeaconNode, prod_config: BlockProductionConfig) f64 {
    if (prod_config.builder_boost_factor) |boost_factor| {
        return @as(f64, @floatFromInt(boost_factor)) / 100.0;
    }
    return self.builder_bid_threshold;
}

pub fn notifyForkchoiceUpdate(self: *BeaconNode, new_head_root: [32]u8) !void {
    notifyForkchoiceUpdateWithAttrs(self, new_head_root, null) catch |err| {
        log.logger(.node).warn("forkchoiceUpdated failed: {}", .{err});
    };
}

pub fn notifyForkchoiceUpdateWithAttrs(
    self: *BeaconNode,
    new_head_root: [32]u8,
    payload_attrs: ?PayloadAttributesV3,
) !void {
    const engine = self.engine_api orelse return;
    const fc_state = self.chainQuery().executionForkchoiceState(new_head_root) orelse return;

    const fcu_state = ForkchoiceStateV1{
        .head_block_hash = fc_state.head_block_hash,
        .safe_block_hash = fc_state.safe_block_hash,
        .finalized_block_hash = fc_state.finalized_block_hash,
    };

    const result = engine.forkchoiceUpdated(fcu_state, payload_attrs) catch |err| {
        std.log.warn("engine_forkchoiceUpdatedV3 failed: {}", .{err});
        self.el_offline = true;
        if (self.metrics) |m| m.execution_errors_total.incr();
        return err;
    };

    self.el_offline = false;

    if (result.payload_id) |payload_id| {
        self.cached_payload_id = payload_id;
        std.log.info("forkchoiceUpdated: payload building started, id={s}", .{
            &std.fmt.bytesToHex(payload_id[0..8], .lower),
        });
    } else if (payload_attrs != null) {
        self.cached_payload_id = null;
        self.cached_payload_slot = null;
    }

    std.log.info("forkchoiceUpdated: status={s} head={s}... safe={s}... finalized={s}...", .{
        @tagName(result.payload_status.status),
        &std.fmt.bytesToHex(fc_state.head_block_hash[0..4], .lower),
        &std.fmt.bytesToHex(fc_state.safe_block_hash[0..4], .lower),
        &std.fmt.bytesToHex(fc_state.finalized_block_hash[0..4], .lower),
    });

    if (payload_attrs) |attrs| {
        self.event_bus.emit(.{ .payload_attributes = .{
            .proposer_index = 0,
            .proposal_slot = self.currentHeadSlot() + 1,
            .parent_block_number = 0,
            .parent_block_root = new_head_root,
            .parent_block_hash = fc_state.head_block_hash,
            .timestamp = attrs.timestamp,
            .prev_randao = attrs.prev_randao,
            .suggested_fee_recipient = attrs.suggested_fee_recipient,
        } });
    }
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
    try notifyForkchoiceUpdateWithAttrs(self, self.currentHeadRoot(), attrs);
    if (self.cached_payload_id != null) {
        self.cached_payload_slot = slot;
    } else {
        self.cached_payload_slot = null;
    }
}

fn getExecutionPayloadWithThreshold(self: *BeaconNode, builder_bid_threshold: f64) !GetPayloadResponse {
    const engine = self.engine_api orelse return error.NoEngineApi;
    const payload_id = self.cached_payload_id orelse return error.NoPayloadId;

    const result = engine.getPayload(payload_id) catch |err| {
        std.log.warn("engine_getPayloadV3 failed: {}", .{err});
        self.el_offline = true;
        return err;
    };

    self.el_offline = false;
    self.cached_payload_id = null;
    self.cached_payload_slot = null;

    std.log.info("getPayload: block_number={d} block_value={d} txs={d} blobs={d}", .{
        result.execution_payload.block_number,
        @as(u64, @truncate(result.block_value)),
        result.execution_payload.transactions.len,
        result.blobs_bundle.blobs.len,
    });

    if (self.builder_api) |builder| {
        const head = self.getHead();
        const proposer_pubkey = std.mem.zeroes([48]u8);
        const parent_hash = result.execution_payload.parent_hash;

        const maybe_bid = builder.getHeader(head.slot, parent_hash, proposer_pubkey) catch |err| {
            std.log.warn("Builder: getHeader error: {} — using local payload", .{err});
            return result;
        };

        if (maybe_bid) |bid| {
            const bid_value = bid.message.value;
            const local_value = result.block_value;
            const threshold_scaled = @as(u256, @intFromFloat(@as(f64, @floatFromInt(local_value)) * builder_bid_threshold));

            if (bid_value >= threshold_scaled and bid_value > 0) {
                std.log.info(
                    "Builder: bid {d} > local {d} — using blinded block path",
                    .{ @as(u64, @truncate(bid_value)), @as(u64, @truncate(local_value)) },
                );
                std.log.info("Builder: bid accepted (value={d}), blinded signing integration pending", .{
                    @as(u64, @truncate(bid.message.value)),
                });
            } else {
                std.log.info(
                    "Builder: bid {d} <= local {d} * {d:.2} — using local payload",
                    .{ @as(u64, @truncate(bid_value)), @as(u64, @truncate(local_value)), builder_bid_threshold },
                );
            }
        } else {
            std.log.debug("Builder: no bid available — using local payload", .{});
        }
    }

    return result;
}

pub fn getExecutionPayload(self: *BeaconNode) !GetPayloadResponse {
    return getExecutionPayloadWithThreshold(self, self.builder_bid_threshold);
}

pub fn registerValidatorsWithBuilder(
    self: *BeaconNode,
    registrations: []const execution_mod.builder.SignedValidatorRegistration,
) void {
    const builder = self.builder_api orelse return;
    builder.registerValidators(registrations) catch |err| {
        std.log.warn("Builder: registerValidators failed: {} — continuing", .{err});
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

fn prevRandaoForSlot(self: *BeaconNode, slot: u64) ![32]u8 {
    const head_state = self.headState() orelse return error.NoHeadState;
    const epoch = slot / preset.SLOTS_PER_EPOCH;
    const randao_index = epoch % preset.EPOCHS_PER_HISTORICAL_VECTOR;
    var mixes = try head_state.state.randaoMixes();
    const mix_ptr = try mixes.getFieldRoot(randao_index);
    return mix_ptr.*;
}

fn ensureExecutionPayloadForSlot(self: *BeaconNode, slot: u64) !void {
    _ = self.engine_api orelse return error.NoEngineApi;

    if (self.cached_payload_slot) |cached_slot| {
        if (cached_slot != slot) {
            self.cached_payload_id = null;
            self.cached_payload_slot = null;
        }
    }
    if (self.cached_payload_id != null) return;

    const fee_recipient = payloadFeeRecipientForSlot(self, slot) orelse return error.MissingProposerFeeRecipient;
    const prev_randao = try prevRandaoForSlot(self, slot);

    try self.preparePayload(
        slot,
        slotStartTimestamp(self, slot),
        prev_randao,
        fee_recipient,
        &.{},
        self.currentHeadRoot(),
    );
}

pub fn produceFullBlock(self: *BeaconNode, slot: u64, prod_config: BlockProductionConfig) !ProducedBlock {
    var effective_config = prod_config;
    if (effective_config.graffiti == null) {
        effective_config.graffiti = self.node_options.graffiti;
    }
    if (std.mem.eql(u8, &effective_config.fee_recipient, &std.mem.zeroes([20]u8))) {
        effective_config.fee_recipient = payloadFeeRecipientForSlot(self, slot) orelse return error.MissingProposerFeeRecipient;
    }

    try ensureExecutionPayloadForSlot(self, slot);
    const resp = try getExecutionPayloadWithThreshold(self, builderBidThresholdForConfig(self, effective_config));

    const exec_payload = try convertEnginePayload(self.allocator, resp.execution_payload);
    const blobs_bundle: ?chain_mod.produce_block.BlobsBundle = .{
        .commitments = resp.blobs_bundle.commitments,
        .proofs = resp.blobs_bundle.proofs,
        .blobs = resp.blobs_bundle.blobs,
    };
    const block_value: u256 = resp.block_value;
    var blob_commitments = std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type).empty;

    if (resp.blobs_bundle.commitments.len > 0) {
        blob_commitments = try std.ArrayListUnmanaged(
            types.primitive.KZGCommitment.Type,
        ).initCapacity(self.allocator, resp.blobs_bundle.commitments.len);
        for (resp.blobs_bundle.commitments) |commitment| {
            blob_commitments.appendAssumeCapacity(commitment);
        }
    }

    const block = try self.chainService().produceFullBlockWithPayload(
        slot,
        exec_payload,
        blobs_bundle,
        block_value,
        blob_commitments,
        effective_config,
    );

    std.log.info("Produced full block: slot={d} proposer={d} parent={s}... value={d}", .{
        slot,
        block.proposer_index,
        &std.fmt.bytesToHex(block.parent_root[0..4], .lower),
        @as(u64, @truncate(block.block_value)),
    });

    return block;
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

fn computeProducedStateRoot(
    self: *BeaconNode,
    slot: u64,
    produced: *const ProducedBlock,
) ![32]u8 {
    const head_state = self.headState() orelse return error.NoHeadState;

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
        std.log.warn("State transition for block state root failed: {}", .{err});
        return err;
    };
    defer {
        post_state.deinit();
        self.allocator.destroy(post_state);
    }

    return (try post_state.state.hashTreeRoot()).*;
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

fn serializeUnsignedFullBlock(
    self: *BeaconNode,
    allocator: std.mem.Allocator,
    slot: u64,
    produced: *const ProducedBlock,
) !SerializedUnsignedBlock {
    const state_root = try computeProducedStateRoot(self, slot, produced);
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
    const state_root = try computeProducedStateRoot(self, slot, produced);
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
    };
}

pub fn produceAndImportBlock(
    self: *BeaconNode,
    slot: u64,
    prod_config: BlockProductionConfig,
) !struct { signed_block: *types.electra.SignedBeaconBlock.Type, import_result: ImportResult } {
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
        const any_block = fork_types.AnySignedBeaconBlock{ .full_electra = signed_block };

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
            std.log.warn("State transition for state root computation failed: {}", .{err});
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

        std.log.info("Computed state root for block: slot={d} state_root={s}...", .{
            slot,
            &std.fmt.bytesToHex(state_root[0..4], .lower),
        });
    } else {
        std.log.warn("No head state available for state root computation at slot={d}", .{slot});
    }

    const any_signed_produced: fork_types.AnySignedBeaconBlock = switch (self.config.forkSeq(slot)) {
        .fulu => .{ .full_fulu = @ptrCast(signed_block) },
        else => .{ .full_electra = signed_block },
    };
    const import_result = try self.importBlock(any_signed_produced, .api);

    std.log.info("Block produced and imported: slot={d} root={s}...", .{
        slot,
        &std.fmt.bytesToHex(import_result.block_root[0..4], .lower),
    });

    produced.block_body = types.electra.BeaconBlockBody.default_value;

    return .{
        .signed_block = signed_block,
        .import_result = import_result,
    };
}

pub fn broadcastBlock(
    self: *BeaconNode,
    signed_block: *const types.electra.SignedBeaconBlock.Type,
) !void {
    const p2p = self.p2p_service orelse {
        std.log.warn("No P2P service — cannot broadcast block at slot={d}", .{signed_block.message.slot});
        return;
    };

    const serialized_size = types.electra.SignedBeaconBlock.serializedSize(signed_block);
    const buf = try self.allocator.alloc(u8, serialized_size);
    defer self.allocator.free(buf);
    _ = types.electra.SignedBeaconBlock.serializeIntoBytes(signed_block, buf);

    const head_slot = self.getHead().slot;
    const fork_digest = self.config.forkDigestAtSlot(head_slot, self.genesis_validators_root);
    var topic_buf: [128]u8 = undefined;
    const topic = std.fmt.bufPrint(&topic_buf, "/eth2/{s}/beacon_block/ssz_snappy", .{
        &std.fmt.bytesToHex(fork_digest[0..], .lower),
    }) catch return;

    _ = p2p.publishGossip(topic, buf) catch |err| {
        std.log.warn("Failed to broadcast block at slot={d}: {}", .{ signed_block.message.slot, err });
        return;
    };

    std.log.info("Broadcast block via gossip: slot={d}", .{signed_block.message.slot});
}

fn convertEnginePayload(
    allocator: std.mem.Allocator,
    engine_payload: execution_mod.engine_api_types.ExecutionPayloadV3,
) !types.electra.ExecutionPayload.Type {
    const bellatrix = @import("consensus_types").bellatrix;
    const capella = @import("consensus_types").capella;

    var transactions = try std.ArrayListUnmanaged(
        bellatrix.Transactions.Element.Type,
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

    var withdrawals = try std.ArrayListUnmanaged(
        capella.Withdrawal.Type,
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

    var extra_data: std.ArrayListUnmanaged(u8) = .empty;
    if (engine_payload.extra_data.len > 0) {
        try extra_data.appendSlice(allocator, engine_payload.extra_data);
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

const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
