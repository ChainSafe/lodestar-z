const std = @import("std");
const js = @import("zapi:zapi").js;
const bls = @import("bls");
const preset = @import("preset").preset;
const signature_set_verifier = @import("state_transition").signature_set_verifier;

// Bound snapshot work and the fixed stack buffers. Lodestar jobs normally
// contain at most 128 sets, so 256 leaves room for cross-request batching.
pub const max_verify_sets = 256;
pub const max_same_message_sets = bls.MAX_AGGREGATE_PER_JOB;
pub const max_indices_per_set = preset.MAX_VALIDATORS_PER_COMMITTEE * preset.MAX_COMMITTEES_PER_SLOT;

pub const SignatureSetBatch = signature_set_verifier.SignatureSetBatch(max_verify_sets);
pub const SameMessageSignatureSetBatch = signature_set_verifier.SameMessageSignatureSetBatch(max_same_message_sets);

pub const SetType = enum(u32) {
    indexed = 0,
    aggregate = 1,
    single = 2,
};

pub const CommonSet = struct {
    type: js.Number,
    message: js.Uint8Array,
    signature: js.Uint8Array,
};

pub const IndexedSet = struct { index: js.Number };
pub const AggregateSet = struct { indices: js.Uint32Array };
pub const SingleSet = struct { pubkey: js.Uint8Array };

pub const SameMessageSet = struct {
    index: js.Number,
    signature: js.Uint8Array,
};

// TODO(zapi): Replace with value.toU32Exact() after next zapi release: see https://github.com/ChainSafe/zapi/pull/71
pub fn uint32(value: js.Number) !u32 {
    const number = try value.toF64();
    const max_u32: f64 = @floatFromInt(std.math.maxInt(u32));
    if (!std.math.isFinite(number) or number < 0 or number > max_u32 or @floor(number) != number) {
        return error.InvalidUint32;
    }
    return @intFromFloat(number);
}
