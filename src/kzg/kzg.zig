//! Idiomatic Zig KZG interface wrapping c-kzg-4844 bindings.
//!
//! Provides higher-level types and methods on top of the raw C bindings in
//! the `c_kzg` dependency.  The KZG settings (trusted setup) are loaded once
//! at node startup and then shared across the lifetime of the process.
//!
//! ## EIP-4844 (Deneb)
//! - `blobToCommitment`   — compute KZG commitment from blob
//! - `computeBlobProof`   — compute blob-level KZG proof
//! - `verifyBlobProof`    — verify a single blob proof
//! - `verifyBlobProofBatch` — batch-verify multiple blob proofs (cheaper per blob)
//!
//! ## EIP-7594 (PeerDAS / Fulu)
//! - `computeCellsAndProofs`    — split a blob into cells with per-cell proofs
//! - `recoverCellsAndProofs`    — recover from a subset of cells (erasure recovery)
//! - `verifyCellProofBatch`     — batch-verify cell KZG proofs

const std = @import("std");
const Allocator = std.mem.Allocator;

const c_kzg = @import("c_kzg");

// ---------------------------------------------------------------------------
// Re-export constants
// ---------------------------------------------------------------------------

pub const BYTES_PER_BLOB: usize = c_kzg.BYTES_PER_BLOB;
pub const FIELD_ELEMENTS_PER_BLOB: usize = c_kzg.FIELD_ELEMENTS_PER_BLOB;
pub const BYTES_PER_COMMITMENT: usize = c_kzg.BYTES_PER_COMMITMENT;
pub const BYTES_PER_PROOF: usize = c_kzg.BYTES_PER_PROOF;
pub const BYTES_PER_CELL: usize = c_kzg.BYTES_PER_CELL;
pub const CELLS_PER_EXT_BLOB: usize = c_kzg.CELLS_PER_EXT_BLOB;
pub const CELLS_PER_BLOB: usize = c_kzg.CELLS_PER_BLOB;
pub const COLUMNS_PER_BLOB: usize = c_kzg.CELLS_PER_EXT_BLOB; // alias: NUMBER_OF_COLUMNS

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Raw blob bytes — 131072 bytes (4096 field elements × 32 bytes).
pub const Blob = [BYTES_PER_BLOB]u8;

/// A 48-byte G1 point representing a KZG commitment.
pub const KzgCommitment = [48]u8;

/// A 48-byte G1 point representing a KZG proof.
pub const KzgProof = [48]u8;

/// A single data availability cell — 2048 bytes (64 field elements × 32 bytes).
pub const Cell = [BYTES_PER_CELL]u8;

/// All cells and their proofs for an extended blob (EIP-7594).
pub const CellsAndProofs = struct {
    cells: [CELLS_PER_EXT_BLOB]Cell,
    proofs: [CELLS_PER_EXT_BLOB]KzgProof,
};

// ---------------------------------------------------------------------------
// Error set
// ---------------------------------------------------------------------------

pub const KzgError = error{
    InvalidArgument,
    KzgInternalError,
    OutOfMemory,
    FileOpenFailed,
};

// ---------------------------------------------------------------------------
// Kzg — main interface struct
// ---------------------------------------------------------------------------

/// Top-level KZG interface.  One instance per process; load once and share.
///
/// ```zig
/// var kzg = try Kzg.initFromFile(allocator, "trusted_setup.txt");
/// defer kzg.deinit(allocator);
///
/// const commitment = try kzg.blobToCommitment(&blob);
/// const proof      = try kzg.computeBlobProof(&blob, commitment);
/// const valid      = try kzg.verifyBlobProof(&blob, commitment, proof);
/// ```
pub const Kzg = struct {
    settings: *c_kzg.KzgSettings,

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Load trusted setup from a file path (e.g. `trusted_setup.txt`).
    ///
    /// The allocator is used to heap-allocate the KzgSettings struct; the same
    /// allocator must be passed to `deinit`.
    pub fn initFromFile(allocator: Allocator, trusted_setup_path: []const u8) KzgError!Kzg {
        const settings = c_kzg.loadTrustedSetupFile(allocator, trusted_setup_path) catch |err| switch (err) {
            error.FileOpenFailed => return KzgError.FileOpenFailed,
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
        return Kzg{ .settings = settings };
    }

    /// Load trusted setup from raw bytes (for embedding the setup at compile time).
    ///
    /// - `g1_monomial_bytes`: G1 monomial-form points (n_g1 × 48 bytes)
    /// - `g1_lagrange_bytes`: G1 Lagrange-form points (n_g1 × 48 bytes)
    /// - `g2_monomial_bytes`: G2 monomial-form points (n_g2 × 96 bytes)
    pub fn initFromBytes(
        allocator: Allocator,
        g1_monomial_bytes: []const u8,
        g1_lagrange_bytes: []const u8,
        g2_monomial_bytes: []const u8,
    ) KzgError!Kzg {
        const settings = c_kzg.loadTrustedSetup(
            allocator,
            g1_monomial_bytes,
            g1_lagrange_bytes,
            g2_monomial_bytes,
        ) catch |err| switch (err) {
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
        return Kzg{ .settings = settings };
    }

    /// Free trusted setup memory.  Must use the same allocator as init*.
    pub fn deinit(self: *Kzg, allocator: Allocator) void {
        c_kzg.freeTrustedSetup(allocator, self.settings);
    }

    // -----------------------------------------------------------------------
    // EIP-4844 API
    // -----------------------------------------------------------------------

    /// Compute the KZG commitment for a blob.
    pub fn blobToCommitment(self: Kzg, blob: *const Blob) KzgError!KzgCommitment {
        return c_kzg.blobToKzgCommitment(blob, self.settings) catch |err| switch (err) {
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
    }

    /// Compute a blob KZG proof (Fiat-Shamir challenge over the entire blob).
    pub fn computeBlobProof(self: Kzg, blob: *const Blob, commitment: KzgCommitment) KzgError!KzgProof {
        return c_kzg.computeBlobKzgProof(blob, &commitment, self.settings) catch |err| switch (err) {
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
    }

    /// Verify a single blob KZG proof.
    pub fn verifyBlobProof(
        self: Kzg,
        blob: *const Blob,
        commitment: KzgCommitment,
        proof: KzgProof,
    ) KzgError!bool {
        return c_kzg.verifyBlobKzgProof(blob, &commitment, &proof, self.settings) catch |err| switch (err) {
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
    }

    /// Batch-verify multiple blob KZG proofs.
    ///
    /// All slices must have equal length.  More efficient than calling
    /// `verifyBlobProof` in a loop due to random-linear-combination tricks.
    pub fn verifyBlobProofBatch(
        self: Kzg,
        blobs: []const Blob,
        commitments: []const KzgCommitment,
        proofs: []const KzgProof,
    ) KzgError!bool {
        return c_kzg.verifyBlobKzgProofBatch(blobs, commitments, proofs, self.settings) catch |err| switch (err) {
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
    }

    // -----------------------------------------------------------------------
    // EIP-7594 / PeerDAS API
    // -----------------------------------------------------------------------

    /// Compute all 128 cells and their per-cell KZG proofs for a blob.
    ///
    /// Used when producing a block to construct data columns for gossip.
    pub fn computeCellsAndProofs(self: Kzg, blob: *const Blob) KzgError!CellsAndProofs {
        const raw = c_kzg.computeCellsAndKzgProofs(blob, self.settings) catch |err| switch (err) {
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
        return CellsAndProofs{
            .cells = raw.cells,
            .proofs = raw.proofs,
        };
    }

    /// Recover all 128 cells and their proofs from a subset (erasure recovery).
    ///
    /// - `cell_indices`: indices (0..CELLS_PER_EXT_BLOB) of the provided cells
    /// - `cells`: the corresponding cell data (same length as `cell_indices`)
    ///
    /// Requires at least CELLS_PER_EXT_BLOB/2 = 64 cells to recover.
    pub fn recoverCellsAndProofs(
        self: Kzg,
        cell_indices: []const u64,
        cells: []const Cell,
    ) KzgError!CellsAndProofs {
        const raw = c_kzg.recoverCellsAndKzgProofs(cell_indices, cells, self.settings) catch |err| switch (err) {
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
        return CellsAndProofs{
            .cells = raw.cells,
            .proofs = raw.proofs,
        };
    }

    /// Batch-verify cell KZG proofs (PeerDAS gossip validation).
    ///
    /// - `allocator`: used for a temporary C-compatible buffer (freed before return)
    /// - `commitments`: one KzgCommitment per cell (caller maps blob commitment to each cell)
    /// - `cell_indices`: which cell index within the extended blob (0..CELLS_PER_EXT_BLOB)
    /// - `cells`: the cell data
    /// - `proofs`: KZG proof per cell
    ///
    /// All slices must have equal length.
    pub fn verifyCellProofBatch(
        self: Kzg,
        allocator: Allocator,
        commitments: []const KzgCommitment,
        cell_indices: []const u64,
        cells: []const Cell,
        proofs: []const KzgProof,
    ) KzgError!bool {
        return c_kzg.verifyCellKzgProofBatch(
            allocator,
            commitments,
            cell_indices,
            cells,
            proofs,
            self.settings,
        ) catch |err| switch (err) {
            error.InvalidArgument => return KzgError.InvalidArgument,
            error.KzgInternalError => return KzgError.KzgInternalError,
            error.OutOfMemory => return KzgError.OutOfMemory,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests (unit — no trusted setup required)
// ---------------------------------------------------------------------------

test "constants match spec" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 131072), BYTES_PER_BLOB);
    try testing.expectEqual(@as(usize, 4096), FIELD_ELEMENTS_PER_BLOB);
    try testing.expectEqual(@as(usize, 48), BYTES_PER_COMMITMENT);
    try testing.expectEqual(@as(usize, 48), BYTES_PER_PROOF);
    try testing.expectEqual(@as(usize, 2048), BYTES_PER_CELL);
    try testing.expectEqual(@as(usize, 128), CELLS_PER_EXT_BLOB);
    try testing.expectEqual(@as(usize, 128), COLUMNS_PER_BLOB);
}

test "Kzg type sizes" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 131072), @sizeOf(Blob));
    try testing.expectEqual(@as(usize, 48), @sizeOf(KzgCommitment));
    try testing.expectEqual(@as(usize, 48), @sizeOf(KzgProof));
    try testing.expectEqual(@as(usize, 2048), @sizeOf(Cell));
    // CellsAndProofs: 128 cells × 2048 + 128 proofs × 48
    const expected_cap = 128 * 2048 + 128 * 48;
    try testing.expectEqual(@as(usize, expected_cap), @sizeOf(CellsAndProofs));
}
