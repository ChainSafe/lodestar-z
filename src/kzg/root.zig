//! KZG module root — idiomatic Zig wrapper over c-kzg-4844.
//!
//! This module provides:
//! - `Kzg` — the main interface struct (load trusted setup once, share everywhere)
//! - KZG type aliases (`Blob`, `KzgCommitment`, `KzgProof`, `Cell`, `CellsAndProofs`)
//! - Constants matching the Ethereum consensus spec (EIP-4844 + EIP-7594)
//!
//! Usage:
//! ```zig
//! const kzg = @import("kzg");
//! var ctx = try kzg.Kzg.initBundled();
//! defer ctx.deinit();
//! const commitment = try ctx.blobToCommitment(&blob);
//! ```

const kzg = @import("kzg.zig");

pub const c = @import("c_kzg");
pub const blst = @import("blst");
pub const Kzg = kzg.Kzg;
pub const KzgError = kzg.KzgError;

// Types
pub const Blob = kzg.Blob;
pub const KzgCommitment = kzg.KzgCommitment;
pub const KzgProof = kzg.KzgProof;
pub const Cell = kzg.Cell;
pub const CellsAndProofs = kzg.CellsAndProofs;

// Constants
pub const BYTES_PER_BLOB = kzg.BYTES_PER_BLOB;
pub const FIELD_ELEMENTS_PER_BLOB = kzg.FIELD_ELEMENTS_PER_BLOB;
pub const BYTES_PER_COMMITMENT = kzg.BYTES_PER_COMMITMENT;
pub const BYTES_PER_PROOF = kzg.BYTES_PER_PROOF;
pub const BYTES_PER_CELL = kzg.BYTES_PER_CELL;
pub const CELLS_PER_EXT_BLOB = kzg.CELLS_PER_EXT_BLOB;
pub const CELLS_PER_BLOB = kzg.CELLS_PER_BLOB;
pub const COLUMNS_PER_BLOB = kzg.COLUMNS_PER_BLOB;
