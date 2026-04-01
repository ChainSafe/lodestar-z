//! Idiomatic Zig KZG interface wrapping the raw c-kzg-4844 C API.
//!
//! Production code should normally use `Kzg.initBundled()`, which loads the
//! single trusted setup bytes provided by the upstream dependency. Lower-level
//! `initFromFile()` and `initFromBytes()` entrypoints remain available for
//! tests and tooling, but callers should not need to thread a setup path
//! through the application in the normal case.

const std = @import("std");
const Allocator = std.mem.Allocator;

const c_kzg = @import("c.zig").c;
const trusted_setup = @import("trusted_setup");

pub const BYTES_PER_FIELD_ELEMENT: usize = c_kzg.BYTES_PER_FIELD_ELEMENT;
pub const FIELD_ELEMENTS_PER_BLOB: usize = c_kzg.FIELD_ELEMENTS_PER_BLOB;
pub const FIELD_ELEMENTS_PER_CELL: usize = c_kzg.FIELD_ELEMENTS_PER_CELL;
pub const BYTES_PER_BLOB: usize = c_kzg.BYTES_PER_BLOB;
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
pub const FieldElement = [BYTES_PER_FIELD_ELEMENT]u8;

pub const KzgProofEval = struct {
    proof: KzgProof,
    y: FieldElement,
};

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
    settings: c_kzg.KZGSettings,

    /// Load the single trusted setup bundled as parsed byte arrays by the upstream dependency.
    pub fn initBundled() KzgError!Kzg {
        return initFromBytes(
            trusted_setup.data.g1_monomial_bytes,
            trusted_setup.data.g1_lagrange_bytes,
            trusted_setup.data.g2_monomial_bytes,
        );
    }

    pub fn initFromFile(allocator: Allocator, trusted_setup_path: []const u8) KzgError!Kzg {
        const path_z = try allocator.dupeZ(u8, trusted_setup_path);
        defer allocator.free(path_z);

        const file = c_kzg.fopen(path_z.ptr, "r") orelse return KzgError.FileOpenFailed;
        defer _ = c_kzg.fclose(file);

        var settings: c_kzg.KZGSettings = undefined;
        errdefer c_kzg.free_trusted_setup(&settings);

        try check(c_kzg.load_trusted_setup_file(&settings, file, 0));
        return .{ .settings = settings };
    }

    pub fn initFromBytes(
        g1_monomial_bytes: []const u8,
        g1_lagrange_bytes: []const u8,
        g2_monomial_bytes: []const u8,
    ) KzgError!Kzg {
        var settings: c_kzg.KZGSettings = undefined;
        errdefer c_kzg.free_trusted_setup(&settings);

        try check(c_kzg.load_trusted_setup(
            &settings,
            bytesPtrOrNull(g1_monomial_bytes),
            g1_monomial_bytes.len,
            bytesPtrOrNull(g1_lagrange_bytes),
            g1_lagrange_bytes.len,
            bytesPtrOrNull(g2_monomial_bytes),
            g2_monomial_bytes.len,
            0,
        ));
        return .{ .settings = settings };
    }

    pub fn deinit(self: *Kzg) void {
        c_kzg.free_trusted_setup(&self.settings);
        self.* = undefined;
    }

    pub fn blobToCommitment(self: *const Kzg, blob: *const Blob) KzgError!KzgCommitment {
        var out: c_kzg.KZGCommitment = undefined;
        try check(c_kzg.blob_to_kzg_commitment(&out, asCBlob(blob), &self.settings));
        return out.bytes;
    }

    pub fn computeKzgProof(
        self: *const Kzg,
        blob: *const Blob,
        z: FieldElement,
    ) KzgError!KzgProofEval {
        var proof: c_kzg.KZGProof = undefined;
        var y: c_kzg.Bytes32 = undefined;
        try check(c_kzg.compute_kzg_proof(
            &proof,
            &y,
            asCBlob(blob),
            asCFieldElement(&z),
            &self.settings,
        ));
        return .{
            .proof = proof.bytes,
            .y = y.bytes,
        };
    }

    pub fn computeBlobProof(
        self: *const Kzg,
        blob: *const Blob,
        commitment: KzgCommitment,
    ) KzgError!KzgProof {
        var out: c_kzg.KZGProof = undefined;
        try check(c_kzg.compute_blob_kzg_proof(
            &out,
            asCBlob(blob),
            asCCommitment(&commitment),
            &self.settings,
        ));
        return out.bytes;
    }

    pub fn verifyKzgProof(
        self: *const Kzg,
        commitment: KzgCommitment,
        z: FieldElement,
        y: FieldElement,
        proof: KzgProof,
    ) KzgError!bool {
        var ok = false;
        try check(c_kzg.verify_kzg_proof(
            &ok,
            asCCommitment(&commitment),
            asCFieldElement(&z),
            asCFieldElement(&y),
            asCProof(&proof),
            &self.settings,
        ));
        return ok;
    }

    pub fn verifyBlobProof(
        self: *const Kzg,
        blob: *const Blob,
        commitment: KzgCommitment,
        proof: KzgProof,
    ) KzgError!bool {
        var ok = false;
        try check(c_kzg.verify_blob_kzg_proof(
            &ok,
            asCBlob(blob),
            asCCommitment(&commitment),
            asCProof(&proof),
            &self.settings,
        ));
        return ok;
    }

    pub fn verifyBlobProofBatch(
        self: *const Kzg,
        blobs: []const Blob,
        commitments: []const KzgCommitment,
        proofs: []const KzgProof,
    ) KzgError!bool {
        if (blobs.len != commitments.len or blobs.len != proofs.len) return KzgError.InvalidArgument;

        var ok = false;
        try check(c_kzg.verify_blob_kzg_proof_batch(
            &ok,
            blobSlicePtrOrNull(blobs),
            commitmentSlicePtrOrNull(commitments),
            proofSlicePtrOrNull(proofs),
            blobs.len,
            &self.settings,
        ));
        return ok;
    }

    pub fn computeCellsAndProofs(self: *const Kzg, blob: *const Blob) KzgError!CellsAndProofs {
        var c_cells: [CELLS_PER_EXT_BLOB]c_kzg.Cell = undefined;
        var c_proofs: [CELLS_PER_EXT_BLOB]c_kzg.KZGProof = undefined;
        try check(c_kzg.compute_cells_and_kzg_proofs(
            &c_cells,
            &c_proofs,
            asCBlob(blob),
            &self.settings,
        ));

        var out: CellsAndProofs = undefined;
        for (0..CELLS_PER_EXT_BLOB) |i| {
            out.cells[i] = c_cells[i].bytes;
            out.proofs[i] = c_proofs[i].bytes;
        }
        return out;
    }

    pub fn recoverCellsAndProofs(
        self: *const Kzg,
        cell_indices: []const u64,
        cells: []const Cell,
    ) KzgError!CellsAndProofs {
        if (cell_indices.len != cells.len) return KzgError.InvalidArgument;

        var recovered_cells: [CELLS_PER_EXT_BLOB]c_kzg.Cell = undefined;
        var recovered_proofs: [CELLS_PER_EXT_BLOB]c_kzg.KZGProof = undefined;
        try check(c_kzg.recover_cells_and_kzg_proofs(
            &recovered_cells,
            &recovered_proofs,
            u64SlicePtrOrNull(cell_indices),
            cellSlicePtrOrNull(cells),
            cells.len,
            &self.settings,
        ));

        var out: CellsAndProofs = undefined;
        for (0..CELLS_PER_EXT_BLOB) |i| {
            out.cells[i] = recovered_cells[i].bytes;
            out.proofs[i] = recovered_proofs[i].bytes;
        }
        return out;
    }

    pub fn verifyCellProofBatch(
        self: *const Kzg,
        commitments: []const KzgCommitment,
        cell_indices: []const u64,
        cells: []const Cell,
        proofs: []const KzgProof,
    ) KzgError!bool {
        if (commitments.len != cell_indices.len or commitments.len != cells.len or commitments.len != proofs.len) {
            return KzgError.InvalidArgument;
        }

        var ok = false;
        try check(c_kzg.verify_cell_kzg_proof_batch(
            &ok,
            commitmentSlicePtrOrNull(commitments),
            u64SlicePtrOrNull(cell_indices),
            cellSlicePtrOrNull(cells),
            proofSlicePtrOrNull(proofs),
            commitments.len,
            &self.settings,
        ));
        return ok;
    }
};

fn asCBlob(blob: *const Blob) *const c_kzg.Blob {
    return @ptrCast(blob);
}

fn asCCommitment(commitment: *const KzgCommitment) *const c_kzg.KZGCommitment {
    return @ptrCast(commitment);
}

fn asCProof(proof: *const KzgProof) *const c_kzg.KZGProof {
    return @ptrCast(proof);
}

fn asCFieldElement(value: *const FieldElement) *const c_kzg.Bytes32 {
    return @ptrCast(value);
}

fn blobSlicePtrOrNull(blobs: []const Blob) ?[*]const c_kzg.Blob {
    if (blobs.len == 0) return null;
    return @ptrCast(blobs.ptr);
}

fn commitmentSlicePtrOrNull(commitments: []const KzgCommitment) ?[*]const c_kzg.KZGCommitment {
    if (commitments.len == 0) return null;
    return @ptrCast(commitments.ptr);
}

fn proofSlicePtrOrNull(proofs: []const KzgProof) ?[*]const c_kzg.KZGProof {
    if (proofs.len == 0) return null;
    return @ptrCast(proofs.ptr);
}

fn cellSlicePtrOrNull(cells: []const Cell) ?[*]const c_kzg.Cell {
    if (cells.len == 0) return null;
    return @ptrCast(cells.ptr);
}

fn u64SlicePtrOrNull(values: []const u64) ?[*]const u64 {
    if (values.len == 0) return null;
    return values.ptr;
}

fn bytesPtrOrNull(bytes: []const u8) ?[*]const u8 {
    if (bytes.len == 0) return null;
    return bytes.ptr;
}

fn check(ret: c_kzg.C_KZG_RET) KzgError!void {
    switch (ret) {
        c_kzg.C_KZG_OK => {},
        c_kzg.C_KZG_BADARGS => return KzgError.InvalidArgument,
        c_kzg.C_KZG_ERROR => return KzgError.KzgInternalError,
        c_kzg.C_KZG_MALLOC => return KzgError.OutOfMemory,
        else => return KzgError.KzgInternalError,
    }
}

fn trustedSetupPathFromEnv(allocator: Allocator) ?[]u8 {
    const path = std.c.getenv("C_KZG_TRUSTED_SETUP_PATH") orelse return null;
    return allocator.dupe(u8, std.mem.span(path)) catch null;
}

test "constants match spec" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 32), BYTES_PER_FIELD_ELEMENT);
    try testing.expectEqual(@as(usize, 4096), FIELD_ELEMENTS_PER_BLOB);
    try testing.expectEqual(@as(usize, 64), FIELD_ELEMENTS_PER_CELL);
    try testing.expectEqual(@as(usize, 131072), BYTES_PER_BLOB);
    try testing.expectEqual(@as(usize, 48), BYTES_PER_COMMITMENT);
    try testing.expectEqual(@as(usize, 48), BYTES_PER_PROOF);
    try testing.expectEqual(@as(usize, 2048), BYTES_PER_CELL);
    try testing.expectEqual(@as(usize, 128), CELLS_PER_EXT_BLOB);
    try testing.expectEqual(@as(usize, 64), CELLS_PER_BLOB);
    try testing.expectEqual(@as(usize, 128), COLUMNS_PER_BLOB);
}

test "Kzg type sizes" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 131072), @sizeOf(Blob));
    try testing.expectEqual(@as(usize, 48), @sizeOf(KzgCommitment));
    try testing.expectEqual(@as(usize, 48), @sizeOf(KzgProof));
    try testing.expectEqual(@as(usize, 2048), @sizeOf(Cell));
    try testing.expectEqual(@sizeOf(c_kzg.KZGSettings), @sizeOf(Kzg));
}

test "load trusted setup from file" {
    const allocator = std.testing.allocator;
    const path = trustedSetupPathFromEnv(allocator) orelse return;
    defer allocator.free(path);

    var kzg = try Kzg.initFromFile(allocator, path);
    defer kzg.deinit();
}

test "load bundled trusted setup" {
    var kzg = try Kzg.initBundled();
    defer kzg.deinit();
}

test "blob commitment and proof roundtrip" {
    const allocator = std.testing.allocator;
    const path = trustedSetupPathFromEnv(allocator) orelse return;
    defer allocator.free(path);

    var kzg = try Kzg.initFromFile(allocator, path);
    defer kzg.deinit();

    var blob = std.mem.zeroes(Blob);
    const commitment = try kzg.blobToCommitment(&blob);
    const proof = try kzg.computeBlobProof(&blob, commitment);
    try std.testing.expect(try kzg.verifyBlobProof(&blob, commitment, proof));
}

test "cell recovery and verification roundtrip" {
    const allocator = std.testing.allocator;
    const path = trustedSetupPathFromEnv(allocator) orelse return;
    defer allocator.free(path);

    var kzg = try Kzg.initFromFile(allocator, path);
    defer kzg.deinit();

    var blob = std.mem.zeroes(Blob);
    const commitment = try kzg.blobToCommitment(&blob);
    const computed = try kzg.computeCellsAndProofs(&blob);

    const provided_count = CELLS_PER_EXT_BLOB / 2;
    var indices: [provided_count]u64 = undefined;
    var cells: [provided_count]Cell = undefined;
    var commitments: [provided_count]KzgCommitment = undefined;
    var proofs: [provided_count]KzgProof = undefined;
    for (0..provided_count) |i| {
        indices[i] = i;
        cells[i] = computed.cells[i];
        commitments[i] = commitment;
        proofs[i] = computed.proofs[i];
    }

    const recovered = try kzg.recoverCellsAndProofs(&indices, &cells);
    try std.testing.expectEqualSlices(u8, &computed.cells[0], &recovered.cells[0]);
    try std.testing.expectEqualSlices(u8, &computed.proofs[0], &recovered.proofs[0]);
    try std.testing.expect(try kzg.verifyCellProofBatch(&commitments, &indices, &cells, &proofs));
}
