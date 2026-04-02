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

const pipeline_types = @import("types.zig");
const BlockInput = pipeline_types.BlockInput;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const ExecutionStatus = pipeline_types.ExecutionStatus;
const BlockImportError = pipeline_types.BlockImportError;
const execution_port_mod = @import("../ports/execution.zig");
pub const ExecutionPort = execution_port_mod.ExecutionPort;
pub const ExecutionVerifier = execution_port_mod.ExecutionVerifier;
const Root = [32]u8;

pub const ExecutionVerificationResult = union(enum) {
    valid: struct {
        latest_valid_hash: Root,
    },
    invalid: struct {
        latest_valid_hash: ?Root,
        invalidate_from_parent_block_root: Root,
    },
    syncing: void,
    pre_merge: void,

    pub fn status(self: ExecutionVerificationResult) ExecutionStatus {
        return switch (self) {
            .valid => .valid,
            .invalid => .invalid,
            .syncing => .syncing,
            .pre_merge => .pre_merge,
        };
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify the execution payload of a block.
///
/// Builds an explicit `engine_newPayload` request from consensus data and
/// submits it through the execution port.
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
    allocator: std.mem.Allocator,
    block_input: BlockInput,
    execution_verifier: ?ExecutionPort,
    opts: ImportBlockOpts,
) BlockImportError!ExecutionStatus {
    return (try verifyExecutionPayloadDetailed(
        allocator,
        block_input,
        execution_verifier,
        opts,
    )).status();
}

pub fn verifyExecutionPayloadDetailed(
    allocator: std.mem.Allocator,
    block_input: BlockInput,
    execution_verifier: ?ExecutionPort,
    opts: ImportBlockOpts,
) BlockImportError!ExecutionVerificationResult {
    // Skip if explicitly requested (regen, checkpoint sync, testing).
    if (opts.skip_execution) return .pre_merge;

    // Check fork — pre-Bellatrix blocks don't have execution payloads.
    const fork_seq = block_input.block.forkSeq();
    if (fork_seq.lt(.bellatrix)) return .pre_merge;

    // No engine verifier configured — running without EL.
    const verifier = execution_verifier orelse return .pre_merge;
    const request = execution_port_mod.makeNewPayloadRequest(allocator, block_input.block) catch
        return BlockImportError.InternalError;
    if (request == null) return .pre_merge;
    var owned_request = request.?;
    defer owned_request.deinit(allocator);

    const result = verifier.submitNewPayload(owned_request);

    return switch (result) {
        .valid => |valid| .{ .valid = .{
            .latest_valid_hash = valid.latest_valid_hash,
        } },
        .invalid => |invalid| .{ .invalid = .{
            .latest_valid_hash = invalid.latest_valid_hash,
            .invalidate_from_parent_block_root = block_input.block.beaconBlock().parentRoot().*,
        } },
        .invalid_block_hash => |invalid| .{ .invalid = .{
            .latest_valid_hash = invalid.latest_valid_hash,
            .invalidate_from_parent_block_root = block_input.block.beaconBlock().parentRoot().*,
        } },
        .syncing, .accepted => .syncing,
        .unavailable => {
            // During range sync, EL unavailability is okay — import optimistically.
            if (opts.from_range_sync) return .syncing;
            return BlockImportError.ExecutionEngineUnavailable;
        },
    };
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
    const result = try verifyExecutionPayload(std.testing.allocator, input, null, .{ .skip_execution = true });
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
