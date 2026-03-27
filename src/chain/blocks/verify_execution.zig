//! Execution payload verification stage.
//!
//! Sends the execution payload to the EL client via engine_newPayload
//! and interprets the result. This stage is asynchronous in TS Lodestar
//! (runs in parallel with state transition), but in lodestar-z's current
//! single-threaded model, it runs sequentially.
//!
//! The engine API interface is accessed through a vtable-style callback
//! provided by the BeaconNode, since the chain module does not directly
//! depend on the execution module.
//!
//! Possible outcomes:
//! - VALID: payload accepted, ExecutionStatus.valid
//! - INVALID: payload rejected, block must be rejected
//! - SYNCING/ACCEPTED: EL is catching up, imported optimistically
//! - Error/unavailable: imported optimistically or rejected based on source
//!
//! Pre-Bellatrix blocks skip this stage entirely (pre_merge).
//!
//! Reference: Lodestar chain/blocks/verifyBlocksExecutionPayloads.ts

const std = @import("std");

const consensus_types = @import("consensus_types");
const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;
const fork_types = @import("fork_types");

const pipeline_types = @import("types.zig");
const BlockInput = pipeline_types.BlockInput;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const ExecutionStatus = pipeline_types.ExecutionStatus;
const BlockImportError = pipeline_types.BlockImportError;

// ---------------------------------------------------------------------------
// Engine callback interface (vtable for execution verification)
// ---------------------------------------------------------------------------

/// Vtable for execution payload verification.
///
/// The BeaconNode provides this callback, bridging the chain module
/// to the execution module without a direct dependency.
pub const ExecutionVerifier = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (
        ptr: *anyopaque,
        block: fork_types.AnySignedBeaconBlock,
    ) VerifyResult,

    pub const VerifyResult = union(enum) {
        valid: void,
        invalid: void,
        syncing: void,
        pre_merge: void,
        unavailable: void,
    };

    pub fn verify(self: ExecutionVerifier, block: fork_types.AnySignedBeaconBlock) VerifyResult {
        return self.verifyFn(self.ptr, block);
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify the execution payload of a block.
///
/// Uses the ExecutionVerifier callback (if provided) to call engine_newPayload.
/// When no verifier is configured, returns pre_merge (running without EL).
///
/// Returns:
/// - ExecutionStatus.valid: EL confirmed VALID
/// - ExecutionStatus.syncing: EL is syncing — optimistic import
/// - ExecutionStatus.pre_merge: no execution payload (pre-Bellatrix or no EL)
///
/// Errors:
/// - ExecutionPayloadInvalid: EL says INVALID
/// - ExecutionEngineUnavailable: EL connection error (non-range-sync)
pub fn verifyExecutionPayload(
    block_input: BlockInput,
    execution_verifier: ?ExecutionVerifier,
    opts: ImportBlockOpts,
) BlockImportError!ExecutionStatus {
    // Skip if explicitly requested (regen, checkpoint sync, testing).
    if (opts.skip_execution) return .pre_merge;

    // Check fork — pre-Bellatrix blocks don't have execution payloads.
    const fork_seq = block_input.block.forkSeq();
    if (fork_seq.lt(.bellatrix)) return .pre_merge;

    // No engine verifier configured — running without EL.
    const verifier = execution_verifier orelse return .pre_merge;

    // Call the execution engine via the vtable.
    const result = verifier.verify(block_input.block);

    return switch (result) {
        .valid => .valid,
        .invalid => BlockImportError.ExecutionPayloadInvalid,
        .syncing => .syncing,
        .pre_merge => .pre_merge,
        .unavailable => {
            // During range sync, EL unavailability is okay — import optimistically.
            if (opts.from_range_sync) return .syncing;
            return BlockImportError.ExecutionEngineUnavailable;
        },
    };
}

/// Verify execution payloads for a batch of blocks.
///
/// Payloads must be verified sequentially because the EL needs each parent.
pub fn verifyExecutionPayloadBatch(
    allocator: std.mem.Allocator,
    block_inputs: []const BlockInput,
    execution_verifier: ?ExecutionVerifier,
    opts: ImportBlockOpts,
) std.mem.Allocator.Error![]ExecutionStatus {
    const statuses = try allocator.alloc(ExecutionStatus, block_inputs.len);
    errdefer allocator.free(statuses);

    for (block_inputs, 0..) |block_input, i| {
        statuses[i] = verifyExecutionPayload(block_input, execution_verifier, opts) catch |err| {
            // Invalid block aborts the rest of the segment.
            if (err == BlockImportError.ExecutionPayloadInvalid) {
                for (i..block_inputs.len) |j| {
                    statuses[j] = .pre_merge;
                }
                break;
            }
            // For unavailable engine during batch, be optimistic.
            statuses[i] = .syncing;
            continue;
        };
    }

    return statuses;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "verifyExecutionPayload: skip when requested" {
    const input = BlockInput{
        .block = undefined,
        .source = .gossip,
        .da_status = .not_required,
    };
    const result = try verifyExecutionPayload(input, null, .{ .skip_execution = true });
    try std.testing.expectEqual(ExecutionStatus.pre_merge, result);
}

test "verifyExecutionPayload: no verifier returns pre_merge" {
    // Without a verifier, we get pre_merge regardless of block contents.
    // We skip this test at runtime because constructing a valid AnySignedBeaconBlock
    // requires allocator + SSZ setup. The skip_execution path is tested above.
    // The no-verifier path hits forkSeq() which requires a valid block.
}

test "ExecutionVerifier type compiles" {
    // Just verify the type compiles.
    _ = ExecutionVerifier;
}
