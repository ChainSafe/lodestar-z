//! Node-owned execution and block production helpers.

const std = @import("std");

const types = @import("consensus_types");
const preset = @import("preset").preset;
const fork_types = @import("fork_types");
const config_mod = @import("config");
const BeaconConfig = config_mod.BeaconConfig;
const state_transition = @import("state_transition");
const chain_mod = @import("chain");
const produceBlockBody = chain_mod.produceBlockBody;
const ProducedBlockBody = chain_mod.ProducedBlockBody;
const ProducedBlock = chain_mod.ProducedBlock;
const BlockProductionConfig = chain_mod.BlockProductionConfig;
const assembleBlock = chain_mod.assembleBlock;
const ImportResult = chain_mod.ImportResult;
const execution_mod = @import("execution");
const ForkchoiceStateV1 = execution_mod.ForkchoiceStateV1;
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;
const GetPayloadResponse = execution_mod.GetPayloadResponse;

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
    const fc = self.fork_choice orelse return;

    const head_node = fc.getBlockDefaultStatus(new_head_root);
    const head_block_hash = if (head_node) |node|
        node.extra_meta.executionPayloadBlockHash() orelse return
    else
        return;

    const justified_cp = fc.getJustifiedCheckpoint();
    const safe_block_hash = if (fc.getBlockDefaultStatus(justified_cp.root)) |node|
        node.extra_meta.executionPayloadBlockHash() orelse std.mem.zeroes([32]u8)
    else
        std.mem.zeroes([32]u8);

    const finalized_cp = fc.getFinalizedCheckpoint();
    const finalized_block_hash = if (fc.getBlockDefaultStatus(finalized_cp.root)) |node|
        node.extra_meta.executionPayloadBlockHash() orelse std.mem.zeroes([32]u8)
    else
        std.mem.zeroes([32]u8);

    const fcu_state = ForkchoiceStateV1{
        .head_block_hash = head_block_hash,
        .safe_block_hash = safe_block_hash,
        .finalized_block_hash = finalized_block_hash,
    };

    const result = engine.forkchoiceUpdated(fcu_state, payload_attrs) catch |err| {
        std.log.warn("engine_forkchoiceUpdatedV3 failed: {}", .{err});
        self.el_offline = true;
        self.api_sync_status.el_offline = true;
        if (self.metrics) |m| m.execution_errors_total.incr();
        return err;
    };

    self.el_offline = false;
    self.api_sync_status.el_offline = false;

    if (result.payload_id) |payload_id| {
        self.cached_payload_id = payload_id;
        std.log.info("forkchoiceUpdated: payload building started, id={s}", .{
            &std.fmt.bytesToHex(payload_id[0..8], .lower),
        });
    }

    std.log.info("forkchoiceUpdated: status={s} head={s}... safe={s}... finalized={s}...", .{
        @tagName(result.payload_status.status),
        &std.fmt.bytesToHex(head_block_hash[0..4], .lower),
        &std.fmt.bytesToHex(safe_block_hash[0..4], .lower),
        &std.fmt.bytesToHex(finalized_block_hash[0..4], .lower),
    });

    if (payload_attrs) |attrs| {
        self.event_bus.emit(.{ .payload_attributes = .{
            .proposer_index = 0,
            .proposal_slot = self.head_tracker.head_slot + 1,
            .parent_block_number = 0,
            .parent_block_root = new_head_root,
            .parent_block_hash = head_block_hash,
            .timestamp = attrs.timestamp,
            .prev_randao = attrs.prev_randao,
            .suggested_fee_recipient = attrs.suggested_fee_recipient,
        } });
    }
}

pub fn preparePayload(
    self: *BeaconNode,
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
    try notifyForkchoiceUpdateWithAttrs(self, self.head_tracker.head_root, attrs);
}

pub fn getExecutionPayload(self: *BeaconNode) !GetPayloadResponse {
    const engine = self.engine_api orelse return error.NoEngineApi;
    const payload_id = self.cached_payload_id orelse return error.NoPayloadId;

    const result = engine.getPayload(payload_id) catch |err| {
        std.log.warn("engine_getPayloadV3 failed: {}", .{err});
        self.el_offline = true;
        self.api_sync_status.el_offline = true;
        return err;
    };

    self.el_offline = false;
    self.api_sync_status.el_offline = false;
    self.cached_payload_id = null;

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
            const threshold_scaled = @as(u256, @intFromFloat(
                @as(f64, @floatFromInt(local_value)) * self.builder_bid_threshold
            ));

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
                    .{ @as(u64, @truncate(bid_value)), @as(u64, @truncate(local_value)), self.builder_bid_threshold },
                );
            }
        } else {
            std.log.debug("Builder: no bid available — using local payload", .{});
        }
    }

    return result;
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
    return produceBlockBody(self.allocator, slot, self.op_pool);
}

pub fn produceFullBlock(self: *BeaconNode, slot: u64, prod_config: BlockProductionConfig) !ProducedBlock {
    var effective_config = prod_config;
    if (effective_config.graffiti == null) {
        effective_config.graffiti = self.node_options.graffiti;
    }

    const head = self.getHead();
    const parent_root = head.root;

    var exec_payload = types.electra.ExecutionPayload.default_value;
    var blobs_bundle: ?chain_mod.produce_block.BlobsBundle = null;
    var block_value: u256 = 0;
    var blob_commitments = std.ArrayListUnmanaged(types.primitive.KZGCommitment.Type).empty;

    if (self.cached_payload_id != null) {
        if (getExecutionPayload(self)) |resp| {
            exec_payload = try convertEnginePayload(self.allocator, resp.execution_payload);
            blobs_bundle = .{
                .commitments = resp.blobs_bundle.commitments,
                .proofs = resp.blobs_bundle.proofs,
                .blobs = resp.blobs_bundle.blobs,
            };
            block_value = resp.block_value;

            if (resp.blobs_bundle.commitments.len > 0) {
                blob_commitments = try std.ArrayListUnmanaged(
                    types.primitive.KZGCommitment.Type,
                ).initCapacity(self.allocator, resp.blobs_bundle.commitments.len);
                for (resp.blobs_bundle.commitments) |commitment| {
                    blob_commitments.appendAssumeCapacity(commitment);
                }
            }
        } else |err| {
            std.log.warn("Failed to get execution payload, producing block without it: {}", .{err});
        }
    }

    var eth1_data = types.phase0.Eth1Data.default_value;
    if (self.block_state_cache.get(parent_root)) |head_state| {
        const state_eth1 = head_state.state.eth1Data() catch null;
        if (state_eth1) |eth1_view| {
            eth1_data.deposit_root = (eth1_view.getFieldRoot("deposit_root") catch &std.mem.zeroes([32]u8)).*;
            eth1_data.deposit_count = eth1_view.get("deposit_count") catch 0;
            eth1_data.block_hash = (eth1_view.getFieldRoot("block_hash") catch &std.mem.zeroes([32]u8)).*;
        }
    }

    var proposer_index: u64 = 0;
    if (self.block_state_cache.get(parent_root)) |head_state| {
        proposer_index = head_state.getBeaconProposer(slot) catch 0;
    }

    const block = try assembleBlock(
        self.allocator,
        slot,
        proposer_index,
        parent_root,
        self.op_pool,
        exec_payload,
        blobs_bundle,
        block_value,
        blob_commitments,
        eth1_data,
        effective_config,
        self.sync_contribution_pool,
    );

    std.log.info("Produced full block: slot={d} proposer={d} parent={s}... value={d}", .{
        slot,
        proposer_index,
        &std.fmt.bytesToHex(parent_root[0..4], .lower),
        @as(u64, @truncate(block.block_value)),
    });

    return block;
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

    if (self.block_state_cache.get(produced.parent_root)) |head_state| {
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

const log = @import("log");
const beacon_node_mod = @import("beacon_node.zig");
const BeaconNode = beacon_node_mod.BeaconNode;
