const std = @import("std");
const Allocator = std.mem.Allocator;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ssz = @import("consensus_types");

pub fn upgradeStateToDeneb(allocator: Allocator, cached_state: *CachedBeaconStateAllForks) !void {
    var state = cached_state.state;
    if (!state.isCapella()) {
        return error.StateIsNotCapella;
    }

    const capella_state = state.capella;
    defer {
        ssz.capella.BeaconState.deinit(allocator, capella_state);
        allocator.destroy(capella_state);
    }
    _ = try state.upgradeUnsafe(allocator);
    state.forkPtr().* = .{
        .previous_version = capella_state.fork.current_version,
        .current_version = cached_state.config.chain.DENEB_FORK_VERSION,
        .epoch = cached_state.getEpochCache().epoch,
    };

    // add excessBlobGas and blobGasUsed to latestExecutionPayloadHeader
    // ownership is transferred to BeaconState
    var deneb_latest_execution_payload_header = ssz.deneb.ExecutionPayloadHeader.default_value;
    const capella_latest_execution_payload_header = capella_state.latest_execution_payload_header;

    deneb_latest_execution_payload_header.parent_hash = capella_latest_execution_payload_header.parent_hash;
    deneb_latest_execution_payload_header.fee_recipient = capella_latest_execution_payload_header.fee_recipient;
    deneb_latest_execution_payload_header.state_root = capella_latest_execution_payload_header.state_root;
    deneb_latest_execution_payload_header.receipts_root = capella_latest_execution_payload_header.receipts_root;
    deneb_latest_execution_payload_header.logs_bloom = capella_latest_execution_payload_header.logs_bloom;
    deneb_latest_execution_payload_header.prev_randao = capella_latest_execution_payload_header.prev_randao;
    deneb_latest_execution_payload_header.block_number = capella_latest_execution_payload_header.block_number;
    deneb_latest_execution_payload_header.gas_limit = capella_latest_execution_payload_header.gas_limit;
    deneb_latest_execution_payload_header.gas_used = capella_latest_execution_payload_header.gas_used;
    deneb_latest_execution_payload_header.timestamp = capella_latest_execution_payload_header.timestamp;
    deneb_latest_execution_payload_header.extra_data = capella_latest_execution_payload_header.extra_data;
    deneb_latest_execution_payload_header.base_fee_per_gas = capella_latest_execution_payload_header.base_fee_per_gas;
    deneb_latest_execution_payload_header.block_hash = capella_latest_execution_payload_header.block_hash;
    deneb_latest_execution_payload_header.transactions_root = capella_latest_execution_payload_header.transactions_root;
    deneb_latest_execution_payload_header.withdrawals_root = capella_latest_execution_payload_header.withdrawals_root;
    deneb_latest_execution_payload_header.excess_blob_gas = 0;
    deneb_latest_execution_payload_header.blob_gas_used = 0;

    state.setLatestExecutionPayloadHeader(.{
        .deneb = &deneb_latest_execution_payload_header,
    });
}
