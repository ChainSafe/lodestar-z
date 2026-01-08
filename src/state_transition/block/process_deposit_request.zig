const std = @import("std");
const CachedBeaconState = @import("../cache/state_cache.zig").CachedBeaconState;
const types = @import("consensus_types");
const DepositRequest = types.electra.DepositRequest.Type;
const PendingDeposit = types.electra.PendingDeposit.Type;
const Root = types.primitive.Root.Type;
const c = @import("constants");

pub fn processDepositRequest(allocator: std.mem.Allocator, cached_state: *CachedBeaconState, deposit_request: *const DepositRequest) !void {
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
