const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const BeaconState = @import("fork_types").BeaconState;
const ct = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");

const ExecutionPayloadBid = ct.gloas.ExecutionPayloadBid;
const PendingDeposit = ct.electra.PendingDeposit.Type;
const BitVector = @import("ssz").BitVector;
const ExecPayloadAvailability = BitVector(preset.SLOTS_PER_HISTORICAL_ROOT);
const isValidatorKnown = @import("../utils/electra.zig").isValidatorKnown;
const validateDepositSignature = @import("../block/process_deposit.zig").validateDepositSignature;
const gloas_utils = @import("../utils/gloas.zig");
const addBuilderToRegistry = gloas_utils.addBuilderToRegistry;
const findBuilderIndexByPubkey = gloas_utils.findBuilderIndexByPubkey;
const isBuilderWithdrawalCredential = gloas_utils.isBuilderWithdrawalCredential;
const initializePtcWindow = gloas_utils.initializePtcWindow;
const PendingDepositsLookup = @import("../utils/pending_deposits_lookup.zig").PendingDepositsLookup;

/// Upgrade a state from Fulu to Gloas.
pub fn upgradeStateToGloas(
    allocator: Allocator,
    io: std.Io,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    fulu_state: *BeaconState(.fulu),
) !BeaconState(.gloas) {
    const block_hash_ptr = try fulu_state.latestExecutionPayloadHeaderBlockHash();
    var block_hash: [32]u8 = undefined;
    @memcpy(&block_hash, block_hash_ptr);

    var latest_execution_payload_header = ct.fulu.ExecutionPayloadHeader.default_value;
    try fulu_state.latestExecutionPayloadHeader(allocator, &latest_execution_payload_header);
    defer ct.fulu.ExecutionPayloadHeader.deinit(allocator, &latest_execution_payload_header);

    var state = try fulu_state.upgradeUnsafe();
    errdefer state.deinit();

    const new_fork = ct.phase0.Fork.Type{
        .previous_version = try fulu_state.forkCurrentVersion(),
        .current_version = config.chain.GLOAS_FORK_VERSION,
        .epoch = epoch_cache.epoch,
    };
    try state.setFork(&new_fork);

    var bid = ExecutionPayloadBid.default_value;
    bid.block_hash = block_hash;
    bid.gas_limit = latest_execution_payload_header.gas_limit;
    try ct.gloas.ExecutionRequests.hashTreeRoot(allocator, &ct.gloas.ExecutionRequests.default_value, &bid.execution_requests_root);
    try state.inner.setValue("latest_execution_payload_bid", &bid);

    try state.inner.setValue("latest_block_hash", &block_hash);

    const availability = ExecPayloadAvailability{ .data = [_]u8{0xFF} ** @divExact(ExecPayloadAvailability.length, 8) };
    try state.inner.setValue("execution_payload_availability", &availability);

    const ptc_window = try initializePtcWindow(.gloas, allocator, epoch_cache, &state);
    try state.inner.setValue("ptc_window", &ptc_window);

    try onboardBuildersFromPendingDeposits(allocator, io, config, epoch_cache, &state);

    fulu_state.deinit();
    return state;
}

/// Applies any pending deposits for builders to onboard builders during the fork transition
/// Spec: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/fork.md#new-onboard_builders_from_pending_deposits
fn onboardBuildersFromPendingDeposits(
    allocator: Allocator,
    io: std.Io,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    state: *BeaconState(.gloas),
) !void {
    var remaining_pending_deposits: std.ArrayList(PendingDeposit) = .empty;
    defer remaining_pending_deposits.deinit(allocator);

    var pending_deposits_lookup = PendingDepositsLookup.init(allocator);
    defer pending_deposits_lookup.deinit();

    var pending_deposits = try state.pendingDeposits();
    const pending_deposits_len = try pending_deposits.length();
    var pending_it = pending_deposits.iteratorReadonly(0);

    for (0..pending_deposits_len) |_| {
        const deposit = try pending_it.nextValue();

        const validator_index = epoch_cache.pubkey_cache.get(io, deposit.pubkey);
        if (try isValidatorKnown(.gloas, state, validator_index)) {
            try remaining_pending_deposits.append(allocator, deposit);
            try pending_deposits_lookup.add(&deposit);
            continue;
        }

        const builder_index = try findBuilderIndexByPubkey(allocator, state, &deposit.pubkey);
        if (builder_index) |idx| {
            var builders = try state.inner.get("builders");
            var builder: ct.gloas.Builder.Type = undefined;
            try builders.getValue(allocator, idx, &builder);
            builder.balance += deposit.amount;
            try builders.setValue(idx, &builder);
            continue;
        } else {
            if (!isBuilderWithdrawalCredential(&deposit.withdrawal_credentials)) {
                try remaining_pending_deposits.append(allocator, deposit);
                try pending_deposits_lookup.add(&deposit);
                continue;
            }

            if (try pending_deposits_lookup.hasPendingValidator(config, &deposit.pubkey)) {
                try remaining_pending_deposits.append(allocator, deposit);
                try pending_deposits_lookup.add(&deposit);
                continue;
            }
        }

        validateDepositSignature(config, &deposit.pubkey, &deposit.withdrawal_credentials, deposit.amount, deposit.signature) catch continue;

        var execution_address: ct.primitive.ExecutionAddress.Type = undefined;
        @memcpy(&execution_address, deposit.withdrawal_credentials[12..32]);
        try addBuilderToRegistry(
            allocator,
            state,
            &deposit.pubkey,
            c.PAYLOAD_BUILDER_VERSION,
            &execution_address,
            deposit.amount,
            deposit.slot,
        );
    }

    var new_pending = try pending_deposits.sliceFrom(pending_deposits_len);
    for (remaining_pending_deposits.items) |dep| {
        try new_pending.pushValue(&dep);
    }
    try state.setPendingDeposits(new_pending);
}

const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const DoubleFreeDetectAllocator = @import("testing_allocators").DoubleFreeDetectAllocator;

fn tryGloasUpgrade(
    allocator: Allocator,
    config: *const BeaconConfig,
    epoch_cache: *const EpochCache,
    baseline: *BeaconState(.fulu),
) !void {
    var fulu_state = try baseline.clone(.{ .transfer_cache = false });
    var owns_fulu_state = true;
    defer if (owns_fulu_state) fulu_state.deinit();

    var gloas_state = try upgradeStateToGloas(allocator, std.testing.io, config, epoch_cache, &fulu_state);
    owns_fulu_state = false;
    defer gloas_state.deinit();
}

test "Gloas fork upgrade - OOM does not double-free transient allocations" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 500_000 });
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.initElectraForGloas(allocator, &pool, 64);
    defer test_state.deinit();
    try test_state.upgradeToFuluForGloas(allocator);
    const baseline = test_state.cached_state.state.castToFork(.fulu);

    var saw_oom = false;
    var saw_success = false;
    var fail_at: usize = 0;
    while (fail_at < 256) : (fail_at += 1) {
        var oom = DoubleFreeDetectAllocator.init(std.testing.allocator, fail_at);
        defer oom.deinit();

        tryGloasUpgrade(
            oom.allocator(),
            test_state.cached_state.config,
            test_state.cached_state.epoch_cache,
            baseline,
        ) catch |err| switch (err) {
            error.OutOfMemory => {
                saw_oom = true;
                try std.testing.expect(!oom.double_free);
                continue;
            },
            else => return err,
        };

        try std.testing.expect(!oom.double_free);
        saw_success = true;
        break;
    }

    try std.testing.expect(saw_oom);
    try std.testing.expect(saw_success);
}
