const ForkSeq = @import("config").ForkSeq;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const DepositRequest = types.electra.DepositRequest.Type;
const PendingDeposit = types.electra.PendingDeposit.Type;
const c = @import("constants");

pub fn processDepositRequest(comptime fork: ForkSeq, state: *BeaconState(fork), deposit_request: *const DepositRequest) !void {
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

// ─── Tests ──────────────────────────────────────────────────────────────────

const std = @import("std");
const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/generate_state.zig").TestCachedBeaconState;

fn makeDepositRequest(index: u64) DepositRequest {
    return DepositRequest{
        .pubkey = [_]u8{@as(u8, @intCast(index & 0xFF))} ** 48,
        .withdrawal_credentials = [_]u8{0x01} ++ [_]u8{0} ** 11 ++ [_]u8{0xAA} ** 20,
        .amount = 32_000_000_000,
        .signature = [_]u8{0} ** 96,
        .index = index,
    };
}

test "processDepositRequest - first request sets depositRequestsStartIndex" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);

    // Set to UNSET value (as electra upgrade does)
    try state.setDepositRequestsStartIndex(c.UNSET_DEPOSIT_REQUESTS_START_INDEX);

    const request = makeDepositRequest(42);
    try processDepositRequest(.electra, state, &request);

    // Should have set the start index to the request's index
    try testing.expectEqual(@as(u64, 42), try state.depositRequestsStartIndex());

    // Should have appended one pending deposit
    var pending = try state.pendingDeposits();
    try testing.expectEqual(@as(u64, 1), try pending.length());
}

test "processDepositRequest - subsequent request does not change start index" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);

    // Set to UNSET, then process first request
    try state.setDepositRequestsStartIndex(c.UNSET_DEPOSIT_REQUESTS_START_INDEX);
    const first = makeDepositRequest(10);
    try processDepositRequest(.electra, state, &first);

    // Process second request with different index
    const second = makeDepositRequest(20);
    try processDepositRequest(.electra, state, &second);

    // Start index should still be 10 (from first request)
    try testing.expectEqual(@as(u64, 10), try state.depositRequestsStartIndex());

    // Should have two pending deposits
    var pending = try state.pendingDeposits();
    try testing.expectEqual(@as(u64, 2), try pending.length());
}

test "processDepositRequest - pending deposit fields match request" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);

    // Use a non-UNSET start index so we skip that branch
    try state.setDepositRequestsStartIndex(0);

    const request = makeDepositRequest(5);
    try processDepositRequest(.electra, state, &request);

    var pending = try state.pendingDeposits();
    var deposit = try pending.get(0);

    // Verify all fields were copied correctly from the request
    var actual_pubkey: [48]u8 = undefined;
    var pubkey_view = try deposit.get("pubkey");
    _ = try pubkey_view.getAllInto(actual_pubkey[0..]);
    try testing.expectEqualSlices(u8, &request.pubkey, &actual_pubkey);

    var actual_creds: [32]u8 = undefined;
    var creds_view = try deposit.get("withdrawal_credentials");
    _ = try creds_view.getAllInto(actual_creds[0..]);
    try testing.expectEqualSlices(u8, &request.withdrawal_credentials, &actual_creds);

    var actual_sig: [96]u8 = undefined;
    var sig_view = try deposit.get("signature");
    _ = try sig_view.getAllInto(actual_sig[0..]);
    try testing.expectEqualSlices(u8, &request.signature, &actual_sig);

    const amount_view = try deposit.get("amount");
    try testing.expectEqual(request.amount, amount_view);

    const slot_view = try deposit.get("slot");
    const state_slot = try state.slot();
    try testing.expectEqual(state_slot, slot_view);
}

test "processDepositRequest - already set start index is preserved" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 256 * 5);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, 16);
    defer test_state.deinit();

    var state = test_state.cached_state.state.castToFork(.electra);

    // Pre-set to a specific value (not UNSET)
    try state.setDepositRequestsStartIndex(100);

    const request = makeDepositRequest(200);
    try processDepositRequest(.electra, state, &request);

    // Start index should remain 100
    try testing.expectEqual(@as(u64, 100), try state.depositRequestsStartIndex());
}
