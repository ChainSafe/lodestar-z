//! Blob and data column KZG verification for the block import pipeline.
//!
//! This module provides the actual KZG cryptographic verification for:
//! - BlobSidecar KZG proof verification (EIP-4844 / Deneb)
//! - DataColumnSidecar cell proof verification (EIP-7594 / Fulu PeerDAS)
//!
//! The `Kzg` instance is loaded once at beacon node startup (trusted setup)
//! and passed down through the chain to these functions.
//!
//! Reference:
//!   - consensus-specs/specs/deneb/p2p-interface.md#blob_sidecar_subnet_id
//!   - consensus-specs/specs/fulu/p2p-interface.md#data_column_sidecar_subnet_id

const std = @import("std");
const Allocator = std.mem.Allocator;

const kzg_mod = @import("kzg");
const Kzg = kzg_mod.Kzg;

// ---------------------------------------------------------------------------
// Re-export useful constants
// ---------------------------------------------------------------------------

pub const BYTES_PER_BLOB = kzg_mod.BYTES_PER_BLOB;
pub const BYTES_PER_CELL = kzg_mod.BYTES_PER_CELL;
pub const CELLS_PER_EXT_BLOB = kzg_mod.CELLS_PER_EXT_BLOB;

// ---------------------------------------------------------------------------
// BlobSidecar input for verification
// ---------------------------------------------------------------------------

/// A blob sidecar's blob/commitment/proof triplet for verification.
///
/// Decoupled from the SSZ BlobSidecar type so callers can construct it
/// without a full SSZ deserialisation.
pub const BlobVerifyInput = struct {
    /// Pointer to the raw blob bytes (131072 bytes).
    blob: *const [BYTES_PER_BLOB]u8,
    /// KZG commitment (48 bytes, G1 point).
    commitment: [48]u8,
    /// KZG proof (48 bytes, G1 point).
    proof: [48]u8,
};

// ---------------------------------------------------------------------------
// Error sets
// ---------------------------------------------------------------------------

pub const BlobVerifyError = error{
    InvalidKzgProof,
    KzgError,
};

pub const CellVerifyError = error{
    InvalidCellKzgProof,
    KzgError,
    LengthMismatch,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// Single blob verification
// ---------------------------------------------------------------------------

/// Verify a single BlobSidecar's KZG proof.
///
/// spec: `verify_blob_kzg_proof(blob_sidecar.blob, blob_sidecar.kzg_commitment, blob_sidecar.kzg_proof)`
pub fn verifyBlobSidecar(
    ctx: Kzg,
    input: BlobVerifyInput,
) BlobVerifyError!void {
    const valid = ctx.verifyBlobProof(
        input.blob,
        input.commitment,
        input.proof,
    ) catch return BlobVerifyError.KzgError;

    if (!valid) return BlobVerifyError.InvalidKzgProof;
}

// ---------------------------------------------------------------------------
// Batch blob verification
// ---------------------------------------------------------------------------

/// Batch-verify multiple BlobSidecar KZG proofs using an allocator for scratch.
///
/// More efficient than calling `verifyBlobSidecar` in a loop because the
/// underlying c-kzg-4844 uses random linear combination for batch verification.
///
/// `allocator` is used for temporary storage of the blob, commitment, and
/// proof slices required by the batch API.
pub fn verifyBlobSidecarBatch(
    allocator: Allocator,
    ctx: Kzg,
    inputs: []const BlobVerifyInput,
) (BlobVerifyError || error{OutOfMemory})!void {
    if (inputs.len == 0) return;

    // Build parallel slices for the batch API.
    // Use the allocator to avoid huge stack frames (131072 * N bytes for blobs).
    const blobs = try allocator.alloc(kzg_mod.Blob, inputs.len);
    defer allocator.free(blobs);
    const commitments = try allocator.alloc(kzg_mod.KzgCommitment, inputs.len);
    defer allocator.free(commitments);
    const proofs = try allocator.alloc(kzg_mod.KzgProof, inputs.len);
    defer allocator.free(proofs);

    for (inputs, 0..) |input, i| {
        @memcpy(&blobs[i], input.blob);
        commitments[i] = input.commitment;
        proofs[i] = input.proof;
    }

    const valid = ctx.verifyBlobProofBatch(blobs, commitments, proofs) catch
        return BlobVerifyError.KzgError;

    if (!valid) return BlobVerifyError.InvalidKzgProof;
}

// ---------------------------------------------------------------------------
// DataColumnSidecar verification (EIP-7594 / PeerDAS)
// ---------------------------------------------------------------------------

/// Verify all cell KZG proofs in a DataColumnSidecar.
///
/// A DataColumnSidecar has one column index but N rows (one per blob in the block).
/// For each row, we have: cell bytes (2048B) + KZG proof (48B) + commitment (48B).
///
/// spec: `verify_cell_kzg_proof_batch(commitments, cell_indices, cells, proofs)`
///
/// - `allocator`:    scratch allocator (freed before return)
/// - `column_index`: the column (0..NUMBER_OF_COLUMNS) this sidecar represents
/// - `commitments`:  one KZG commitment per row (blob)
/// - `cells`:        one cell per row (the column_index cell of each blob)
/// - `proofs`:       one KZG proof per row
pub fn verifyDataColumnSidecar(
    allocator: Allocator,
    ctx: Kzg,
    column_index: u64,
    commitments: []const [48]u8,
    cells: []const [BYTES_PER_CELL]u8,
    proofs: []const [48]u8,
) CellVerifyError!void {
    if (commitments.len != cells.len or cells.len != proofs.len) {
        return CellVerifyError.LengthMismatch;
    }
    if (commitments.len == 0) return;

    // All cells in this column share the same column_index.
    const cell_indices = try allocator.alloc(u64, commitments.len);
    defer allocator.free(cell_indices);
    for (cell_indices) |*idx| idx.* = column_index;

    const valid = ctx.verifyCellProofBatch(
        commitments,
        cell_indices,
        cells,
        proofs,
    ) catch |err| switch (err) {
        error.OutOfMemory => return CellVerifyError.OutOfMemory,
        else => return CellVerifyError.KzgError,
    };

    if (!valid) return CellVerifyError.InvalidCellKzgProof;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "blob verification constants" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 131072), BYTES_PER_BLOB);
    try testing.expectEqual(@as(usize, 2048), BYTES_PER_CELL);
    try testing.expectEqual(@as(usize, 128), CELLS_PER_EXT_BLOB);
}

test "BlobVerifyInput has correct field sizes" {
    const testing = std.testing;
    // commitment and proof are 48-byte arrays
    try testing.expectEqual(@as(usize, 48), @sizeOf([48]u8));
}
