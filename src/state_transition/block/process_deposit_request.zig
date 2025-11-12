const std = @import("std");
const CachedBeaconStateAllForks = @import("../cache/state_cache.zig").CachedBeaconStateAllForks;
const ct = @import("consensus_types");
const DepositRequest = ct.electra.DepositRequest.Type;
const PendingDeposit = ct.electra.PendingDeposit.Type;
const Root = ct.primitive.Root.Type;
const c = @import("constants");

pub fn processDepositRequest(allocator: std.mem.Allocator, cached_state: *CachedBeaconStateAllForks, deposit_request: *const DepositRequest) !void {
    const state = cached_state.state;
    const deposit_requests_start_index = state.depositRequestsStartIndex();
    if (deposit_requests_start_index.* == c.UNSET_DEPOSIT_REQUESTS_START_INDEX) {
        deposit_requests_start_index.* = deposit_request.index;
    }

    const pending_deposit = PendingDeposit{
        .pubkey = deposit_request.pubkey,
        .withdrawal_credentials = deposit_request.withdrawal_credentials,
        .amount = deposit_request.amount,
        .signature = deposit_request.signature,
        .slot = state.slot(),
    };

    try state.pendingDeposits().append(allocator, pending_deposit);
}
