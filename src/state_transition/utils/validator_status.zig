const std = @import("std");
const types = @import("consensus_types");
const constants = @import("constants");

const Validator = types.phase0.Validator;
const Epoch = types.primitive.Epoch.Type;

/// Validator status as defined by https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ
pub const ValidatorStatus = enum {
    pending_initialized,
    pending_queued,
    active_ongoing,
    active_exiting,
    active_slashed,
    exited_unslashed,
    exited_slashed,
    withdrawal_possible,
    withdrawal_done,

    pub fn toString(self: ValidatorStatus) [:0]const u8 {
        return @tagName(self);
    }

    pub fn fromString(s: []const u8) ?ValidatorStatus {
        return std.meta.stringToEnum(ValidatorStatus, s);
    }

    /// Check if this status matches a general category.
    /// Categories: "pending", "active", "exited", "withdrawal"
    pub fn matchesCategory(self: ValidatorStatus, category: []const u8) bool {
        if (std.mem.eql(u8, category, "pending")) {
            return self == .pending_initialized or self == .pending_queued;
        }
        if (std.mem.eql(u8, category, "active")) {
            return self == .active_ongoing or self == .active_exiting or self == .active_slashed;
        }
        if (std.mem.eql(u8, category, "exited")) {
            return self == .exited_unslashed or self == .exited_slashed;
        }
        if (std.mem.eql(u8, category, "withdrawal")) {
            return self == .withdrawal_possible or self == .withdrawal_done;
        }
        return false;
    }
};

/// Get the status of a validator at a given epoch.
pub fn getValidatorStatus(validator: *const Validator.Type, current_epoch: Epoch) ValidatorStatus {
    const FAR_FUTURE_EPOCH = constants.FAR_FUTURE_EPOCH;

    // pending
    if (validator.activation_epoch > current_epoch) {
        if (validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH) {
            return .pending_initialized;
        }
        if (validator.activation_eligibility_epoch < FAR_FUTURE_EPOCH) {
            return .pending_queued;
        }
    }

    // active
    if (validator.activation_epoch <= current_epoch and current_epoch < validator.exit_epoch) {
        if (validator.exit_epoch == FAR_FUTURE_EPOCH) {
            return .active_ongoing;
        }
        if (validator.exit_epoch < FAR_FUTURE_EPOCH) {
            return if (validator.slashed) .active_slashed else .active_exiting;
        }
    }

    // exited
    if (validator.exit_epoch <= current_epoch and current_epoch < validator.withdrawable_epoch) {
        return if (validator.slashed) .exited_slashed else .exited_unslashed;
    }

    // withdrawal
    if (validator.withdrawable_epoch <= current_epoch) {
        return if (validator.effective_balance != 0) .withdrawal_possible else .withdrawal_done;
    }

    // Should not reach here for valid validators
    return .pending_initialized;
}

// ──── Tests ────

const testing = std.testing;


fn makeValidator(
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
    slashed: bool,
    effective_balance: u64,
) Validator.Type {
    return .{
        .pubkey = [_]u8{0} ** 48,
        .withdrawal_credentials = [_]u8{0} ** 32,
        .effective_balance = effective_balance,
        .slashed = slashed,
        .activation_eligibility_epoch = activation_eligibility_epoch,
        .activation_epoch = activation_epoch,
        .exit_epoch = exit_epoch,
        .withdrawable_epoch = withdrawable_epoch,
    };
}

test "getValidatorStatus - pending_initialized" {
    // activation_epoch > current_epoch AND activation_eligibility_epoch == FAR_FUTURE
    const v = makeValidator(constants.FAR_FUTURE_EPOCH, constants.FAR_FUTURE_EPOCH, constants.FAR_FUTURE_EPOCH, constants.FAR_FUTURE_EPOCH, false, 32_000_000_000);
    try testing.expectEqual(ValidatorStatus.pending_initialized, getValidatorStatus(&v, 100));
}

test "getValidatorStatus - pending_queued" {
    // activation_epoch > current_epoch AND activation_eligibility_epoch < FAR_FUTURE
    const v = makeValidator(50, constants.FAR_FUTURE_EPOCH, constants.FAR_FUTURE_EPOCH, constants.FAR_FUTURE_EPOCH, false, 32_000_000_000);
    try testing.expectEqual(ValidatorStatus.pending_queued, getValidatorStatus(&v, 100));
}

test "getValidatorStatus - active_ongoing" {
    // activation_epoch <= current_epoch < exit_epoch AND exit_epoch == FAR_FUTURE
    const v = makeValidator(10, 20, constants.FAR_FUTURE_EPOCH, constants.FAR_FUTURE_EPOCH, false, 32_000_000_000);
    try testing.expectEqual(ValidatorStatus.active_ongoing, getValidatorStatus(&v, 100));
}

test "getValidatorStatus - active_exiting" {
    // activation_epoch <= current_epoch < exit_epoch AND exit_epoch < FAR_FUTURE AND NOT slashed
    const v = makeValidator(10, 20, 200, 300, false, 32_000_000_000);
    try testing.expectEqual(ValidatorStatus.active_exiting, getValidatorStatus(&v, 100));
}

test "getValidatorStatus - active_slashed" {
    // activation_epoch <= current_epoch < exit_epoch AND exit_epoch < FAR_FUTURE AND slashed
    const v = makeValidator(10, 20, 200, 300, true, 32_000_000_000);
    try testing.expectEqual(ValidatorStatus.active_slashed, getValidatorStatus(&v, 100));
}

test "getValidatorStatus - exited_unslashed" {
    // exit_epoch <= current_epoch < withdrawable_epoch AND NOT slashed
    const v = makeValidator(10, 20, 80, 200, false, 32_000_000_000);
    try testing.expectEqual(ValidatorStatus.exited_unslashed, getValidatorStatus(&v, 100));
}

test "getValidatorStatus - exited_slashed" {
    // exit_epoch <= current_epoch < withdrawable_epoch AND slashed
    const v = makeValidator(10, 20, 80, 200, true, 32_000_000_000);
    try testing.expectEqual(ValidatorStatus.exited_slashed, getValidatorStatus(&v, 100));
}

test "getValidatorStatus - withdrawal_possible" {
    // withdrawable_epoch <= current_epoch AND effective_balance != 0
    const v = makeValidator(10, 20, 80, 90, false, 32_000_000_000);
    try testing.expectEqual(ValidatorStatus.withdrawal_possible, getValidatorStatus(&v, 100));
}

test "getValidatorStatus - withdrawal_done" {
    // withdrawable_epoch <= current_epoch AND effective_balance == 0
    const v = makeValidator(10, 20, 80, 90, false, 0);
    try testing.expectEqual(ValidatorStatus.withdrawal_done, getValidatorStatus(&v, 100));
}

test "ValidatorStatus.toString" {
    try testing.expectEqualStrings("active_ongoing", ValidatorStatus.active_ongoing.toString());
    try testing.expectEqualStrings("pending_initialized", ValidatorStatus.pending_initialized.toString());
    try testing.expectEqualStrings("withdrawal_done", ValidatorStatus.withdrawal_done.toString());
}

test "ValidatorStatus.fromString" {
    try testing.expectEqual(ValidatorStatus.active_ongoing, ValidatorStatus.fromString("active_ongoing"));
    try testing.expectEqual(ValidatorStatus.exited_slashed, ValidatorStatus.fromString("exited_slashed"));
    try testing.expectEqual(@as(?ValidatorStatus, null), ValidatorStatus.fromString("invalid_status"));
}

test "ValidatorStatus.matchesCategory" {
    try testing.expect(ValidatorStatus.pending_initialized.matchesCategory("pending"));
    try testing.expect(ValidatorStatus.pending_queued.matchesCategory("pending"));
    try testing.expect(!ValidatorStatus.active_ongoing.matchesCategory("pending"));

    try testing.expect(ValidatorStatus.active_ongoing.matchesCategory("active"));
    try testing.expect(ValidatorStatus.active_exiting.matchesCategory("active"));
    try testing.expect(ValidatorStatus.active_slashed.matchesCategory("active"));
    try testing.expect(!ValidatorStatus.exited_unslashed.matchesCategory("active"));

    try testing.expect(ValidatorStatus.exited_unslashed.matchesCategory("exited"));
    try testing.expect(ValidatorStatus.exited_slashed.matchesCategory("exited"));
    try testing.expect(!ValidatorStatus.withdrawal_possible.matchesCategory("exited"));

    try testing.expect(ValidatorStatus.withdrawal_possible.matchesCategory("withdrawal"));
    try testing.expect(ValidatorStatus.withdrawal_done.matchesCategory("withdrawal"));
    try testing.expect(!ValidatorStatus.active_ongoing.matchesCategory("withdrawal"));

    try testing.expect(!ValidatorStatus.active_ongoing.matchesCategory("unknown_category"));
}
