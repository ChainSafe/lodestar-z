//! BeaconEngine — orchestrates block verification on top of `state_transition`.

const std = @import("std");
const testing = std.testing;

pub const metrics = @import("metrics.zig");
pub const verify_blocks_state_transition_only = @import("verify_blocks_state_transition_only.zig");
pub const verify_blocks_signatures = @import("verify_blocks_signatures.zig");

pub const verifyBlocksStateTransitionOnly = verify_blocks_state_transition_only.verifyBlocksStateTransitionOnly;
pub const VerifyStateTransitionOpts = verify_blocks_state_transition_only.VerifyStateTransitionOpts;
pub const VerifyBlocksStateTransitionResult = verify_blocks_state_transition_only.VerifyBlocksStateTransitionResult;

pub const verifyBlocksSignatures = verify_blocks_signatures.verifyBlocksSignatures;
pub const VerifyBlocksSignaturesOpts = verify_blocks_signatures.VerifyBlocksSignaturesOpts;
pub const VerifyBlocksSignaturesResult = verify_blocks_signatures.VerifyBlocksSignaturesResult;

test {
    testing.refAllDecls(@This());
}
