const ct = @import("consensus_types");
const preset = @import("preset").preset;
const Eth1Data = ct.phase0.Eth1Data.Type;
const MAX_DEPOSITS = preset.MAX_DEPOSITS;
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;

pub fn getEth1DepositCount(cached_state: *const CachedBeaconStateAllForks, eth1_data: ?*const Eth1Data) u64 {
    const state = cached_state.state;

    const eth1_data_to_use = eth1_data orelse state.eth1Data();

    if (state.isPostElectra()) {
        const deposit_requests_start_index = state.depositRequestsStartIndex();
        // eth1DataIndexLimit = min(UintNum64, UintBn64) can be safely casted as UintNum64
        // since the result lies within upper and lower bound of UintNum64
        const eth1_data_index_limit: u64 = if (eth1_data_to_use.deposit_count < deposit_requests_start_index.*)
            eth1_data_to_use.deposit_count
        else
            deposit_requests_start_index.*;

        return if (state.eth1DepositIndex() < eth1_data_index_limit)
            @min(MAX_DEPOSITS, eth1_data_index_limit - state.eth1DepositIndex())
        else
            0;
    }

    return @min(MAX_DEPOSITS, eth1_data_to_use.deposit_count - state.eth1DepositIndex());
}
