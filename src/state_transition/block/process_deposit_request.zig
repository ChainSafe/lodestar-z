const ForkSeq = @import("config").ForkSeq;
const ForkBeaconState = @import("fork_types").ForkBeaconState;
const types = @import("consensus_types");
const DepositRequest = types.electra.DepositRequest.Type;
const PendingDeposit = types.electra.PendingDeposit.Type;
const c = @import("constants");

pub fn processDepositRequest(comptime fork: ForkSeq, state: *ForkBeaconState(fork), deposit_request: *const DepositRequest) !void {
    const deposit_requests_start_index = try state.depositRequestsStartIndex();
    if (deposit_requests_start_index == c.UNSET_DEPOSIT_REQUESTS_START_INDEX) {
        try state.setDepositRequestsStartIndex(deposit_request.index);
    }

    const pending_deposit = PendingDeposit{
        .pubkey = deposit_request.pubkey,
        .withdrawal_credentials = deposit_request.withdrawal_credentials,
        .amount = deposit_request.amount,
        .signature = deposit_request.signature,
        .slot = try state.slot(),
    };

    var pending_deposits = try state.pendingDeposits();
    try pending_deposits.pushValue(&pending_deposit);
}
