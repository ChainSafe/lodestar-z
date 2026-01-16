const napi = @import("zapi:napi");
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const computeCheckpointEpochAtStateSlot = state_transition.computeCheckpointEpochAtStateSlot;
const computeEndSlotAtEpoch = state_transition.computeEndSlotAtEpoch;
const computeActivationExitEpoch = state_transition.computeActivationExitEpoch;
const computePreviousEpoch = state_transition.computePreviousEpoch;
const computeSyncPeriodAtSlot = state_transition.computeSyncPeriodAtSlot;

pub fn Epoch_computeEpochAtSlot(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const slot_i64 = try cb.arg(0).getValueInt64();
    if (slot_i64 < 0) {
        return error.InvalidSlot;
    }
    const slot: u64 = @intCast(slot_i64);
    const epoch = computeEpochAtSlot(slot);
    return try env.createInt64(@intCast(epoch));
}

pub fn Epoch_computeStartSlotAtEpoch(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const epoch_i64 = try cb.arg(0).getValueInt64();
    if (epoch_i64 < 0) {
        return error.InvalidEpoch;
    }
    const epoch: u64 = @intCast(epoch_i64);
    const slot = computeStartSlotAtEpoch(epoch);
    return try env.createInt64(@intCast(slot));
}

pub fn Epoch_computeCheckpointEpochAtStateSlot(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const slot_i64 = try cb.arg(0).getValueInt64();
    if (slot_i64 < 0) {
        return error.InvalidSlot;
    }
    const slot: u64 = @intCast(slot_i64);
    const epoch = computeCheckpointEpochAtStateSlot(slot);
    return try env.createInt64(@intCast(epoch));
}

pub fn Epoch_computeEndSlotAtEpoch(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const epoch_i64 = try cb.arg(0).getValueInt64();
    if (epoch_i64 < 0) {
        return error.InvalidEpoch;
    }
    const epoch: u64 = @intCast(epoch_i64);
    const slot = computeEndSlotAtEpoch(epoch);
    return try env.createInt64(@intCast(slot));
}

pub fn Epoch_computeActivationExitEpoch(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const epoch_i64 = try cb.arg(0).getValueInt64();
    if (epoch_i64 < 0) {
        return error.InvalidEpoch;
    }
    const epoch: u64 = @intCast(epoch_i64);
    const result = computeActivationExitEpoch(epoch);
    return try env.createInt64(@intCast(result));
}

pub fn Epoch_computePreviousEpoch(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const epoch_i64 = try cb.arg(0).getValueInt64();
    if (epoch_i64 < 0) {
        return error.InvalidEpoch;
    }
    const epoch: u64 = @intCast(epoch_i64);
    const result = computePreviousEpoch(epoch);
    return try env.createInt64(@intCast(result));
}

pub fn Epoch_computeSyncPeriodAtSlot(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    const slot_i64 = try cb.arg(0).getValueInt64();
    if (slot_i64 < 0) {
        return error.InvalidSlot;
    }
    const slot: u64 = @intCast(slot_i64);
    const result = computeSyncPeriodAtSlot(slot);
    return try env.createInt64(@intCast(result));
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const epoch_obj = try env.createObject();
    try epoch_obj.setNamedProperty("computeEpochAtSlot", try env.createFunction(
        "computeEpochAtSlot",
        1,
        Epoch_computeEpochAtSlot,
        null,
    ));
    try epoch_obj.setNamedProperty("computeStartSlotAtEpoch", try env.createFunction(
        "computeStartSlotAtEpoch",
        1,
        Epoch_computeStartSlotAtEpoch,
        null,
    ));
    try epoch_obj.setNamedProperty("computeCheckpointEpochAtStateSlot", try env.createFunction(
        "computeCheckpointEpochAtStateSlot",
        1,
        Epoch_computeCheckpointEpochAtStateSlot,
        null,
    ));
    try epoch_obj.setNamedProperty("computeEndSlotAtEpoch", try env.createFunction(
        "computeEndSlotAtEpoch",
        1,
        Epoch_computeEndSlotAtEpoch,
        null,
    ));
    try epoch_obj.setNamedProperty("computeActivationExitEpoch", try env.createFunction(
        "computeActivationExitEpoch",
        1,
        Epoch_computeActivationExitEpoch,
        null,
    ));
    try epoch_obj.setNamedProperty("computePreviousEpoch", try env.createFunction(
        "computePreviousEpoch",
        1,
        Epoch_computePreviousEpoch,
        null,
    ));
    try epoch_obj.setNamedProperty("computeSyncPeriodAtSlot", try env.createFunction(
        "computeSyncPeriodAtSlot",
        1,
        Epoch_computeSyncPeriodAtSlot,
        null,
    ));
    try exports.setNamedProperty("epoch", epoch_obj);
}
