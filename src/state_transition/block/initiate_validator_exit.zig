const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const BeaconState = @import("fork_types").BeaconState;
const types = @import("consensus_types");
const c = @import("constants");
const FAR_FUTURE_EPOCH = c.FAR_FUTURE_EPOCH;
const EpochCache = @import("../cache/epoch_cache.zig").EpochCache;
const computeExitEpochAndUpdateChurn = @import("../utils/epoch.zig").computeExitEpochAndUpdateChurn;

/// Initiate the exit of the validator with index ``index``
///
/// NOTE: This function takes a `validator` as argument instead of the validator index.
/// SSZ TreeViews have a dangerous edge case that may break the code here in a non-obvious way.
/// When running `state.validators[i]` you get a SubTree of that validator with a hook to the state.
/// Then, when a property of `validator` is set it propagates the changes upwards to the parent tree up to the state.
/// This means that `validator` will propagate its new state along with the current state of its parent tree up to
/// the state, potentially overwriting changes done in other SubTrees before.
/// ```ts
/// // default state.validators, all zeroes
/// const validatorsA = state.validators
/// const validatorsB = state.validators
/// validatorsA[0].exitEpoch = 9
/// validatorsB[0].exitEpoch = 9 // Setting a value in validatorsB will overwrite all changes from validatorsA
/// // validatorsA[0].exitEpoch is 0
/// // validatorsB[0].exitEpoch is 9
/// ```
/// Forcing consumers to pass the SubTree of `validator` directly mitigates this issue.
///
pub fn initiateValidatorExit(
    comptime fork: ForkSeq,
    config: *const BeaconConfig,
    epoch_cache: *EpochCache,
    state: *BeaconState(fork),
    validator: *types.phase0.Validator.TreeView,
) !void {
    // return if validator already initiated exit
    if ((try validator.get("exit_epoch")) != FAR_FUTURE_EPOCH) {
        return;
    }

    if (comptime fork.lt(.electra)) {
        // Limits the number of validators that can exit on each epoch.
        // Expects all state.validators to follow this rule, i.e. no validator.exitEpoch is greater than exitQueueEpoch.
        // If there the churnLimit is reached at this current exitQueueEpoch, advance epoch and reset churn.
        if (epoch_cache.exit_queue_churn >= epoch_cache.churn_limit) {
            epoch_cache.exit_queue_epoch += 1;
            // = 1 to account for this validator with exitQueueEpoch
            epoch_cache.exit_queue_churn = 1;
        } else {
            // Add this validator to the current exitQueueEpoch churn
            epoch_cache.exit_queue_churn += 1;
        }

        // set validator exit epoch
        try validator.set("exit_epoch", epoch_cache.exit_queue_epoch);
    } else {
        // set validator exit epoch
        // Note we don't use epochCtx.exitQueueChurn and exitQueueEpoch anymore
        try validator.set(
            "exit_epoch",
            try computeExitEpochAndUpdateChurn(fork, epoch_cache, state, try validator.get("effective_balance")),
        );
    }

    try validator.set(
        "withdrawable_epoch",
        try std.math.add(u64, try validator.get("exit_epoch"), config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY),
    );
}

// ─── Tests ───────────────────────────────────────────────────────────

const std_testing = std.testing;
const TestCachedBeaconState = @import("../test_utils/root.zig").TestCachedBeaconState;
const Node = @import("persistent_merkle_tree").Node;
const preset = @import("preset").preset;

test "initiateValidatorExit - no-op if already exited" {
    const allocator = std_testing.allocator;
    const num_validators = 256;
    const pool_size = num_validators * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, num_validators);
    defer test_state.deinit();

    const state = test_state.cached_state.state.castToFork(.electra);
    const epoch_cache = test_state.cached_state.epoch_cache;

    // Set validator 0's exit_epoch to something other than FAR_FUTURE_EPOCH
    var validators = try state.validators();
    var validator = try validators.get(0);
    try validator.set("exit_epoch", 10);
    try validator.set("withdrawable_epoch", 10 + test_state.config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY);

    // Call initiateValidatorExit — should be a no-op
    try initiateValidatorExit(.electra, test_state.config, epoch_cache, state, validator);

    // exit_epoch should remain unchanged
    try std_testing.expectEqual(@as(u64, 10), try validator.get("exit_epoch"));
}

test "initiateValidatorExit - sets exit and withdrawable epochs" {
    const allocator = std_testing.allocator;
    const num_validators = 256;
    const pool_size = num_validators * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, num_validators);
    defer test_state.deinit();

    const state = test_state.cached_state.state.castToFork(.electra);
    const epoch_cache = test_state.cached_state.epoch_cache;

    var validators = try state.validators();
    var validator = try validators.get(0);

    // Validator should start with FAR_FUTURE_EPOCH
    try std_testing.expectEqual(FAR_FUTURE_EPOCH, try validator.get("exit_epoch"));

    try initiateValidatorExit(.electra, test_state.config, epoch_cache, state, validator);

    const exit_epoch = try validator.get("exit_epoch");
    try std_testing.expect(exit_epoch != FAR_FUTURE_EPOCH);
    try std_testing.expectEqual(
        exit_epoch + test_state.config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
        try validator.get("withdrawable_epoch"),
    );
}

test "initiateValidatorExit - multiple exits" {
    const allocator = std_testing.allocator;
    const num_validators = 256;
    const pool_size = num_validators * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, num_validators);
    defer test_state.deinit();

    const state = test_state.cached_state.state.castToFork(.electra);
    const epoch_cache = test_state.cached_state.epoch_cache;

    var validators = try state.validators();

    // Exit multiple validators and verify each gets a valid exit epoch
    var v0 = try validators.get(0);
    var v1 = try validators.get(1);
    var v2 = try validators.get(2);

    try initiateValidatorExit(.electra, test_state.config, epoch_cache, state, v0);
    try initiateValidatorExit(.electra, test_state.config, epoch_cache, state, v1);
    try initiateValidatorExit(.electra, test_state.config, epoch_cache, state, v2);

    const exit0 = try v0.get("exit_epoch");
    const exit1 = try v1.get("exit_epoch");
    const exit2 = try v2.get("exit_epoch");

    // All should have valid exit epochs
    try std_testing.expect(exit0 != FAR_FUTURE_EPOCH);
    try std_testing.expect(exit1 != FAR_FUTURE_EPOCH);
    try std_testing.expect(exit2 != FAR_FUTURE_EPOCH);

    // All should have valid withdrawable epochs
    const delay = test_state.config.chain.MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
    try std_testing.expectEqual(exit0 + delay, try v0.get("withdrawable_epoch"));
    try std_testing.expectEqual(exit1 + delay, try v1.get("withdrawable_epoch"));
    try std_testing.expectEqual(exit2 + delay, try v2.get("withdrawable_epoch"));
}

test "initiateValidatorExit - second call is no-op" {
    const allocator = std_testing.allocator;
    const num_validators = 256;
    const pool_size = num_validators * 5;
    var pool = try Node.Pool.init(allocator, pool_size);
    defer pool.deinit();

    var test_state = try TestCachedBeaconState.init(allocator, &pool, num_validators);
    defer test_state.deinit();

    const state = test_state.cached_state.state.castToFork(.electra);
    const epoch_cache = test_state.cached_state.epoch_cache;

    var validators = try state.validators();
    var validator = try validators.get(0);

    // First call — should set exit epoch
    try initiateValidatorExit(.electra, test_state.config, epoch_cache, state, validator);
    const exit_epoch = try validator.get("exit_epoch");
    try std_testing.expect(exit_epoch != FAR_FUTURE_EPOCH);

    // Second call — should be a no-op
    try initiateValidatorExit(.electra, test_state.config, epoch_cache, state, validator);
    try std_testing.expectEqual(exit_epoch, try validator.get("exit_epoch"));
}
