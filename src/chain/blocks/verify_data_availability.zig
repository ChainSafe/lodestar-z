//! Data availability verification stage.
//!
//! For Deneb+ blocks, verifies that all required blobs are present and
//! their KZG proofs are valid. For Fulu+ blocks, additionally handles
//! data column sidecars for PeerDAS.
//!
//! Pre-Deneb blocks skip this stage entirely (not_required).
//! Blocks beyond the blob retention window (MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS)
//! are marked out_of_range and also skip verification.
//!
//! The actual KZG verification is delegated to the consensus_types blob
//! validation or a future kzg module. This stage handles the policy:
//! - Should we check DA for this block?
//! - Is the DA status acceptable for import?
//! - Should we quarantine and wait for blobs?
//!
//! Reference: Lodestar chain/blocks/verifyBlocksDataAvailability.ts

const std = @import("std");

const pipeline_types = @import("types.zig");
const BlockInput = pipeline_types.BlockInput;
const ImportBlockOpts = pipeline_types.ImportBlockOpts;
const DataAvailabilityStatus = pipeline_types.DataAvailabilityStatus;
const BlockImportError = pipeline_types.BlockImportError;

/// Maximum time to wait for blobs/columns before giving up (milliseconds).
/// Matches TS Lodestar's BLOB_AVAILABILITY_TIMEOUT = 12_000.
/// We can wait the full 12s because unavailable block sync will try pulling
/// blobs from the network after 500ms of seeing the block.
pub const BLOB_AVAILABILITY_TIMEOUT_MS: u64 = 12_000;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify data availability for a block.
///
/// This is a synchronous check against the block input's DA status.
/// In a full node, the DA status is set by the gossip/sync handler that
/// collects blobs/columns and runs KZG verification before handing off
/// to the pipeline.
///
/// Returns the DA status to use for state transition:
/// - .available or .not_required: proceed with import
/// - .out_of_range: proceed (DA not enforced for old blocks)
/// - .pre_data: proceed (no data for this block type)
/// - .pending: block is quarantined, cannot import yet
///
/// Errors:
/// - DataUnavailable: blobs are required but not available (pending or missing)
pub fn verifyDataAvailability(
    block_input: BlockInput,
    opts: ImportBlockOpts,
) BlockImportError!DataAvailabilityStatus {
    _ = opts;

    return switch (block_input.da_status) {
        // Pre-Deneb: no DA required.
        .not_required => .not_required,

        // All data present and KZG-verified by the gossip/sync handler.
        .available => .available,

        // Block is beyond blob retention window — DA not enforced.
        .out_of_range => .out_of_range,

        // No data for this block type (e.g., Gloas separated payload).
        .pre_data => .pre_data,

        // Data not yet available — block should be quarantined.
        // In a full implementation, we would wait up to BLOB_AVAILABILITY_TIMEOUT_MS
        // for the data to arrive. For now, we reject immediately and let the
        // caller (gossip handler) re-queue when data arrives.
        .pending => BlockImportError.DataUnavailable,
    };
}

/// Verify data availability for a batch of blocks.
///
/// Returns an array of DA statuses. If any block has pending DA,
/// it's marked as DataUnavailable but processing continues for
/// subsequent blocks (they may have different DA requirements).
pub fn verifyDataAvailabilityBatch(
    allocator: std.mem.Allocator,
    block_inputs: []const BlockInput,
    opts: ImportBlockOpts,
) std.mem.Allocator.Error![]DataAvailabilityStatus {
    const results = try allocator.alloc(DataAvailabilityStatus, block_inputs.len);
    errdefer allocator.free(results);

    for (block_inputs, 0..) |block_input, i| {
        results[i] = verifyDataAvailability(block_input, opts) catch {
            // Mark as pending — caller decides whether to quarantine or skip.
            results[i] = .pending;
            continue;
        };
    }

    return results;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn makeTestInput(da: DataAvailabilityStatus) BlockInput {
    // Using undefined for block is safe here because verifyDataAvailability
    // only inspects da_status, never the block itself.
    return BlockInput{
        .block = undefined,
        .source = .gossip,
        .da_status = da,
    };
}

test "verifyDataAvailability: not_required passes through" {
    const result = try verifyDataAvailability(makeTestInput(.not_required), .{});
    try std.testing.expectEqual(DataAvailabilityStatus.not_required, result);
}

test "verifyDataAvailability: available passes through" {
    const result = try verifyDataAvailability(makeTestInput(.available), .{});
    try std.testing.expectEqual(DataAvailabilityStatus.available, result);
}

test "verifyDataAvailability: out_of_range passes through" {
    const result = try verifyDataAvailability(makeTestInput(.out_of_range), .{});
    try std.testing.expectEqual(DataAvailabilityStatus.out_of_range, result);
}

test "verifyDataAvailability: pending returns error" {
    try std.testing.expectError(
        BlockImportError.DataUnavailable,
        verifyDataAvailability(makeTestInput(.pending), .{}),
    );
}
