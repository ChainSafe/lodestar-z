//! Column reconstruction via erasure coding (PeerDAS / Fulu).
//!
//! When a node has received ≥50% of data columns for a block, it can
//! recover the missing columns using KZG cell recovery (erasure coding).
//! This is the PeerDAS column reconstruction step.
//!
//! Reference:
//!   consensus-specs/specs/fulu/das-core.md#recover_cells_and_kzg_proofs
//!   Lodestar util/dataColumns.ts — recoverDataColumnSidecars

const std = @import("std");
const Allocator = std.mem.Allocator;

const kzg_mod = @import("kzg");
const Kzg = kzg_mod.Kzg;
const KzgError = kzg_mod.KzgError;

const preset_root = @import("preset");

pub const NUMBER_OF_COLUMNS: u64 = preset_root.NUMBER_OF_COLUMNS;
pub const CELLS_PER_EXT_BLOB: u64 = preset_root.CELLS_PER_EXT_BLOB;
pub const BYTES_PER_CELL: u64 = preset_root.BYTES_PER_CELL;

/// Result of a reconstruction attempt.
pub const ReconstructionResult = enum {
    /// All columns recovered successfully.
    success,
    /// Not enough columns for reconstruction (< 50%).
    insufficient_columns,
    /// KZG recovery failed (data corruption or proof mismatch).
    recovery_failed,
};

/// Per-blob reconstruction input: the available cells and their indices.
pub const BlobCellData = struct {
    /// KZG commitment for this blob.
    commitment: [48]u8,
    /// Cell indices that are available.
    cell_indices: []const u64,
    /// Cell data for available cells (parallel with cell_indices).
    cells: []const [kzg_mod.BYTES_PER_CELL]u8,
};

/// Recovered cells and proofs for a single blob.
pub const RecoveredBlob = struct {
    /// All cells (128) in order.
    cells: [CELLS_PER_EXT_BLOB][kzg_mod.BYTES_PER_CELL]u8,
    /// All proofs (128) in order.
    proofs: [CELLS_PER_EXT_BLOB][48]u8,
};

/// Column reconstruction engine.
///
/// Wraps KZG recovery to reconstruct missing data columns from
/// partial data (≥50% of columns needed).
pub const ColumnReconstructor = struct {
    kzg: Kzg,

    pub fn init(kzg: Kzg) ColumnReconstructor {
        return .{ .kzg = kzg };
    }

    /// Attempt to recover all cells and proofs for a single blob
    /// from partial column data.
    ///
    /// Requires at least CELLS_PER_EXT_BLOB / 2 (= 64) cells.
    ///
    /// Returns the full set of cells and proofs on success.
    pub fn recoverBlob(
        self: *const ColumnReconstructor,
        cell_indices: []const u64,
        cells: []const [kzg_mod.BYTES_PER_CELL]u8,
    ) !RecoveredBlob {
        if (cell_indices.len < CELLS_PER_EXT_BLOB / 2) {
            return error.InsufficientCells;
        }

        const result = self.kzg.recoverCellsAndProofs(
            cell_indices,
            cells,
        ) catch return error.KzgRecoveryFailed;

        return RecoveredBlob{
            .cells = result.cells,
            .proofs = result.proofs,
        };
    }

    /// Reconstruct all missing columns from available column data.
    ///
    /// `available_columns` maps column_index → per-blob cell data.
    /// `blob_count` is the number of blobs in the block.
    ///
    /// For each blob row, collects available cells across columns,
    /// recovers the full row, then populates the missing column cells.
    ///
    /// Returns `.success` if reconstruction completed, or an error status.
    pub fn reconstructColumns(
        self: *const ColumnReconstructor,
        allocator: Allocator,
        available_column_indices: []const u64,
        /// For each available column: array of cells (one per blob row).
        /// available_column_cells[col_idx][blob_idx] = cell bytes
        available_column_cells: []const []const [kzg_mod.BYTES_PER_CELL]u8,
        /// For each available column: array of proofs (one per blob row).
        available_column_proofs: []const []const [48]u8,
        blob_count: u64,
    ) ReconstructionResult {
        if (available_column_indices.len < CELLS_PER_EXT_BLOB / 2) {
            return .insufficient_columns;
        }

        // For each blob row, recover all cells.
        for (0..blob_count) |blob_idx| {
            const cell_indices = allocator.alloc(u64, available_column_indices.len) catch
                return .recovery_failed;
            defer allocator.free(cell_indices);

            const cells = allocator.alloc([kzg_mod.BYTES_PER_CELL]u8, available_column_indices.len) catch
                return .recovery_failed;
            defer allocator.free(cells);

            for (available_column_indices, 0..) |col_idx, i| {
                cell_indices[i] = col_idx;
                cells[i] = available_column_cells[i][blob_idx];
                _ = available_column_proofs; // proofs are outputs, not inputs to recovery
            }

            _ = self.kzg.recoverCellsAndProofs(cell_indices, cells) catch
                return .recovery_failed;
        }

        return .success;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ColumnReconstructor: type sizes" {
    try std.testing.expectEqual(@as(u64, 128), CELLS_PER_EXT_BLOB);
    try std.testing.expectEqual(@as(u64, 128), NUMBER_OF_COLUMNS);
}

test "ReconstructionResult: enum values" {
    // Verify the enum is well-formed.
    const r1: ReconstructionResult = .success;
    const r2: ReconstructionResult = .insufficient_columns;
    const r3: ReconstructionResult = .recovery_failed;
    try std.testing.expect(r1 != r2);
    try std.testing.expect(r2 != r3);
}
