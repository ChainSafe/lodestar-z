//! Idiomatic Zig KZG interface wrapping the raw c-kzg-4844 C API.
//!
//! Provides higher-level types and methods on top of the installed `ckzg.h`
//! headers from the `c_kzg` dependency. The KZG settings (trusted setup) are
//! loaded once at node startup and then shared across the lifetime of the
//! process.

const std = @import("std");
const Allocator = std.mem.Allocator;

const c_kzg = @import("c.zig").c;

pub const BYTES_PER_BLOB: usize = c_kzg.BYTES_PER_BLOB;
pub const FIELD_ELEMENTS_PER_BLOB: usize = c_kzg.FIELD_ELEMENTS_PER_BLOB;
pub const BYTES_PER_COMMITMENT: usize = c_kzg.BYTES_PER_COMMITMENT;
pub const BYTES_PER_PROOF: usize = c_kzg.BYTES_PER_PROOF;
pub const BYTES_PER_CELL: usize = c_kzg.BYTES_PER_CELL;
pub const CELLS_PER_EXT_BLOB: usize = c_kzg.CELLS_PER_EXT_BLOB;
pub const CELLS_PER_BLOB: usize = c_kzg.CELLS_PER_BLOB;
pub const COLUMNS_PER_BLOB: usize = c_kzg.CELLS_PER_EXT_BLOB;

pub const Blob = [BYTES_PER_BLOB]u8;
pub const KzgCommitment = [BYTES_PER_COMMITMENT]u8;
pub const KzgProof = [BYTES_PER_PROOF]u8;
pub const Cell = [BYTES_PER_CELL]u8;

pub const CellsAndProofs = struct {
    cells: [CELLS_PER_EXT_BLOB]Cell,
    proofs: [CELLS_PER_EXT_BLOB]KzgProof,
};

pub const KzgError = error{
    InvalidArgument,
    KzgInternalError,
    OutOfMemory,
    FileOpenFailed,
};

pub const Kzg = struct {
    settings: *c_kzg.KZGSettings,

    pub fn initFromFile(allocator: Allocator, trusted_setup_path: []const u8) KzgError!Kzg {
        const path_z = try allocator.dupeZ(u8, trusted_setup_path);
        defer allocator.free(path_z);

        const file = c_kzg.fopen(path_z.ptr, "r") orelse return KzgError.FileOpenFailed;
        defer _ = c_kzg.fclose(file);

        const settings = try allocator.create(c_kzg.KZGSettings);
        errdefer allocator.destroy(settings);

        try check(c_kzg.load_trusted_setup_file(settings, file, 0));
        return .{ .settings = settings };
    }

    pub fn initFromBytes(
        allocator: Allocator,
        g1_monomial_bytes: []const u8,
        g1_lagrange_bytes: []const u8,
        g2_monomial_bytes: []const u8,
    ) KzgError!Kzg {
        const settings = try allocator.create(c_kzg.KZGSettings);
        errdefer allocator.destroy(settings);

        try check(c_kzg.load_trusted_setup(
            settings,
            ptrOrNull(g1_monomial_bytes),
            g1_monomial_bytes.len,
            ptrOrNull(g1_lagrange_bytes),
            g1_lagrange_bytes.len,
            ptrOrNull(g2_monomial_bytes),
            g2_monomial_bytes.len,
            0,
        ));
        return .{ .settings = settings };
    }

    pub fn deinit(self: *Kzg, allocator: Allocator) void {
        c_kzg.free_trusted_setup(self.settings);
        allocator.destroy(self.settings);
    }

    pub fn blobToCommitment(self: Kzg, blob: *const Blob) KzgError!KzgCommitment {
        var out: c_kzg.KZGCommitment = undefined;
        try check(c_kzg.blob_to_kzg_commitment(&out, @ptrCast(blob), self.settings));
        return out.bytes;
    }

    pub fn computeBlobProof(self: Kzg, blob: *const Blob, commitment: KzgCommitment) KzgError!KzgProof {
        var out: c_kzg.KZGProof = undefined;
        try check(c_kzg.compute_blob_kzg_proof(
            &out,
            @ptrCast(blob),
            @ptrCast(&commitment),
            self.settings,
        ));
        return out.bytes;
    }

    pub fn verifyBlobProof(
        self: Kzg,
        blob: *const Blob,
        commitment: KzgCommitment,
        proof: KzgProof,
    ) KzgError!bool {
        var ok = false;
        try check(c_kzg.verify_blob_kzg_proof(
            &ok,
            @ptrCast(blob),
            @ptrCast(&commitment),
            @ptrCast(&proof),
            self.settings,
        ));
        return ok;
    }

    pub fn verifyBlobProofBatch(
        self: Kzg,
        blobs: []const Blob,
        commitments: []const KzgCommitment,
        proofs: []const KzgProof,
    ) KzgError!bool {
        if (blobs.len != commitments.len or blobs.len != proofs.len) return KzgError.InvalidArgument;

        var ok = false;
        try check(c_kzg.verify_blob_kzg_proof_batch(
            &ok,
            @ptrCast(blobs.ptr),
            @ptrCast(commitments.ptr),
            @ptrCast(proofs.ptr),
            blobs.len,
            self.settings,
        ));
        return ok;
    }

    pub fn computeCellsAndProofs(self: Kzg, blob: *const Blob) KzgError!CellsAndProofs {
        var c_cells: [CELLS_PER_EXT_BLOB]c_kzg.Cell = undefined;
        var c_proofs: [CELLS_PER_EXT_BLOB]c_kzg.KZGProof = undefined;
        try check(c_kzg.compute_cells_and_kzg_proofs(
            &c_cells,
            &c_proofs,
            @ptrCast(blob),
            self.settings,
        ));

        var out: CellsAndProofs = undefined;
        for (0..CELLS_PER_EXT_BLOB) |i| {
            out.cells[i] = c_cells[i].bytes;
            out.proofs[i] = c_proofs[i].bytes;
        }
        return out;
    }

    pub fn recoverCellsAndProofs(
        self: Kzg,
        cell_indices: []const u64,
        cells: []const Cell,
    ) KzgError!CellsAndProofs {
        if (cell_indices.len != cells.len) return KzgError.InvalidArgument;

        var recovered_cells: [CELLS_PER_EXT_BLOB]c_kzg.Cell = undefined;
        var recovered_proofs: [CELLS_PER_EXT_BLOB]c_kzg.KZGProof = undefined;
        try check(c_kzg.recover_cells_and_kzg_proofs(
            &recovered_cells,
            &recovered_proofs,
            ptrOrNull(cell_indices),
            @ptrCast(ptrOrNull(cells)),
            cells.len,
            self.settings,
        ));

        var out: CellsAndProofs = undefined;
        for (0..CELLS_PER_EXT_BLOB) |i| {
            out.cells[i] = recovered_cells[i].bytes;
            out.proofs[i] = recovered_proofs[i].bytes;
        }
        return out;
    }

    pub fn verifyCellProofBatch(
        self: Kzg,
        allocator: Allocator,
        commitments: []const KzgCommitment,
        cell_indices: []const u64,
        cells: []const Cell,
        proofs: []const KzgProof,
    ) KzgError!bool {
        _ = allocator;
        if (commitments.len != cell_indices.len or commitments.len != cells.len or commitments.len != proofs.len) {
            return KzgError.InvalidArgument;
        }

        var ok = false;
        try check(c_kzg.verify_cell_kzg_proof_batch(
            &ok,
            @ptrCast(ptrOrNull(commitments)),
            ptrOrNull(cell_indices),
            @ptrCast(ptrOrNull(cells)),
            @ptrCast(ptrOrNull(proofs)),
            commitments.len,
            self.settings,
        ));
        return ok;
    }
};

fn check(ret: c_kzg.C_KZG_RET) KzgError!void {
    switch (ret) {
        c_kzg.C_KZG_OK => {},
        c_kzg.C_KZG_BADARGS => return KzgError.InvalidArgument,
        c_kzg.C_KZG_ERROR => return KzgError.KzgInternalError,
        c_kzg.C_KZG_MALLOC => return KzgError.OutOfMemory,
        else => return KzgError.KzgInternalError,
    }
}

fn ptrOrNull(slice: anytype) ?[*]const std.meta.Elem(@TypeOf(slice)) {
    if (slice.len == 0) return null;
    return slice.ptr;
}

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
    const expected_cap = 128 * 2048 + 128 * 48;
    try testing.expectEqual(@as(usize, expected_cap), @sizeOf(CellsAndProofs));
}
