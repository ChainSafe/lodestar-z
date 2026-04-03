//! Persistent slashing protection database for the Validator Client.
//!
//! Uses an append-only record file.
//! On startup: reads all records and rebuilds in-memory indices.
//! On sign: appends the new record, then updates the in-memory state.
//! fsync after each write for crash safety.
//!
//! Record format:
//!   Legacy block record:              [1][slot][pubkey]
//!   Legacy attestation record:        [2][source][target][pubkey]
//!   Block record with signing root:   [3][slot][pubkey][signing_root]
//!   Attestation record with root:     [4][source][target][pubkey][signing_root]
//!   Attestation lower-bound record:   [5][min_source][min_target][pubkey]
//!
//! TS equivalent: packages/validator/src/slashingProtection/
//!               (Lodestar uses LevelDB/SQLite-like repositories; we use one
//!               append-only file with in-memory indices)
//!
//! Thread safety: this struct does NOT provide internal locking. Callers are
//! responsible for serializing access. In production, ValidatorStore holds a
//! single mutex that is locked for the full check-and-sign sequence, which
//! prevents TOCTOU races between the protection check and the signing call.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fs = @import("fs.zig");
const types = @import("types.zig");
const SignedBlock = types.SlashingProtectionBlockRecord;
const SignedAttestation = types.SlashingProtectionAttestationRecord;
const SlashingProtectionHistory = types.SlashingProtectionHistory;
const UNKNOWN_SIGNING_ROOT = types.UNKNOWN_SIGNING_ROOT;

const log = std.log.scoped(.slashing_db);

// ---------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------

const RECORD_TYPE_BLOCK_V1: u8 = 0x01;
const RECORD_TYPE_ATTESTATION_V1: u8 = 0x02;
const RECORD_TYPE_BLOCK_V2: u8 = 0x03;
const RECORD_TYPE_ATTESTATION_V2: u8 = 0x04;
const RECORD_TYPE_ATTESTATION_LOWER_BOUND: u8 = 0x05;

const BLOCK_V1_RECORD_SIZE: usize = 1 + 8 + 48;
const ATTESTATION_V1_RECORD_SIZE: usize = 1 + 8 + 8 + 48;
const BLOCK_V2_RECORD_SIZE: usize = 1 + 8 + 48 + 32;
const ATTESTATION_V2_RECORD_SIZE: usize = 1 + 8 + 8 + 48 + 32;
const ATTESTATION_LOWER_BOUND_RECORD_SIZE: usize = 1 + 8 + 8 + 48;
const MAX_RECORD_SIZE: usize = ATTESTATION_V2_RECORD_SIZE;

// ---------------------------------------------------------------------------
// In-memory maps
// ---------------------------------------------------------------------------

pub const BlockRecord = struct {
    slot: u64,
    signing_root: [32]u8 = UNKNOWN_SIGNING_ROOT,
};

pub const AttestRecord = struct {
    source_epoch: u64,
    target_epoch: u64,
    signing_root: [32]u8 = UNKNOWN_SIGNING_ROOT,
};

pub const AttestationLowerBound = struct {
    min_source_epoch: u64,
    min_target_epoch: u64,
};

const BlockHistory = std.array_list.Managed(BlockRecord);
const AttestHistory = std.array_list.Managed(AttestRecord);
const BlockHistoryMap = std.HashMap([48]u8, BlockHistory, PubkeyContext, std.hash_map.default_max_load_percentage);
const AttestHistoryMap = std.HashMap([48]u8, AttestHistory, PubkeyContext, std.hash_map.default_max_load_percentage);
const LowerBoundMap = std.HashMap([48]u8, AttestationLowerBound, PubkeyContext, std.hash_map.default_max_load_percentage);

/// Hash context for [48]u8 pubkey keys.
const PubkeyContext = struct {
    pub fn hash(ctx: @This(), key: [48]u8) u64 {
        _ = ctx;
        return std.hash.Wyhash.hash(0, &key);
    }
    pub fn eql(ctx: @This(), a: [48]u8, b: [48]u8) bool {
        _ = ctx;
        return std.mem.eql(u8, &a, &b);
    }
};

// ---------------------------------------------------------------------------
// Surround vote detection
// ---------------------------------------------------------------------------

/// Surround vote result.
pub const SurroundResult = enum {
    /// New attestation surrounds an existing one (new_src < existing_src AND new_tgt > existing_tgt).
    surrounding,
    /// New attestation is surrounded by an existing one (new_src > existing_src AND new_tgt < existing_tgt).
    surrounded,
    /// No surround relationship detected.
    safe,
};

/// Check whether `new` would form a surround vote against any record in `history`.
///
/// Per EIP-3076 and the consensus spec:
///   - SURROUNDING: new_source < existing_source AND new_target > existing_target
///   - SURROUNDED:  new_source > existing_source AND new_target < existing_target
///
/// The history slice must be sorted by target_epoch ascending (guaranteed by our insert path).
/// We use this to skip records that cannot possibly surround or be surrounded:
///   - A record with target_epoch >= new_target cannot be surrounded by new (new_target is smaller).
///   - A record with target_epoch <= new_source cannot surround new (target too old).
///
/// This gives us O(n) in the worst case but typically much less for a validator with
/// well-behaved attestation history.
pub fn checkSurroundVote(history: []const AttestRecord, new_source: u64, new_target: u64) SurroundResult {
    for (history) |rec| {
        // Optimization: records are sorted by target_epoch asc.
        // If rec.target_epoch > new_target, we're past any record that could be
        // SURROUNDED (new would need smaller target to be surrounded, done).
        // But we still need to check SURROUNDING (rec.target could be > new_target).
        // So we can't break early on target alone — continue full scan.

        // SURROUNDING: new wraps around existing.
        if (new_source < rec.source_epoch and new_target > rec.target_epoch) {
            return .surrounding;
        }

        // SURROUNDED: new is inside existing.
        if (new_source > rec.source_epoch and new_target < rec.target_epoch) {
            return .surrounded;
        }
    }
    return .safe;
}

// ---------------------------------------------------------------------------
// SlashingProtectionDb
// ---------------------------------------------------------------------------

pub const SlashingProtectionDb = struct {
    io: Io,
    allocator: Allocator,
    file: ?Io.File,
    /// Full block history per validator (sorted by slot ascending).
    block_history: BlockHistoryMap,
    /// Full attestation history per validator (sorted by target_epoch ascending).
    attest_history: AttestHistoryMap,
    /// Imported attestation lower bounds (persisted separately from history).
    attestation_lower_bounds: LowerBoundMap,

    /// Initialize the slashing protection database.
    ///
    /// Opens or creates the file at db_path, reads all existing records into memory.
    /// Pass db_path = null to create an in-memory-only instance (for tests).
    pub fn init(io: Io, allocator: Allocator, db_path: ?[]const u8) !SlashingProtectionDb {
        var self = SlashingProtectionDb{
            .io = io,
            .allocator = allocator,
            .file = null,
            .block_history = BlockHistoryMap.init(allocator),
            .attest_history = AttestHistoryMap.init(allocator),
            .attestation_lower_bounds = LowerBoundMap.init(allocator),
        };

        if (db_path) |path| {
            const abs_path = try fs.resolvePath(allocator, path);
            defer allocator.free(abs_path);
            const file = try Io.Dir.createFileAbsolute(io, abs_path, .{
                .read = true,
                .truncate = false,
            });
            self.file = file;

            // Read and replay all existing records.
            try self.loadRecords();
        }

        return self;
    }

    pub fn close(self: *SlashingProtectionDb) void {
        if (self.file) |f| {
            f.close(self.io);
            self.file = null;
        }
        var block_it = self.block_history.valueIterator();
        while (block_it.next()) |history| {
            history.deinit();
        }
        self.block_history.deinit();

        var attest_it = self.attest_history.valueIterator();
        while (attest_it.next()) |history| {
            history.deinit();
        }
        self.attest_history.deinit();
        self.attestation_lower_bounds.deinit();
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Check if a block can be signed and, if safe, record it.
    ///
    /// Mirrors Lodestar more closely than the older monotonic-slot shortcut:
    /// - same slot + same non-zero signing root => safe repeat sign
    /// - same slot + different / unknown root => refuse double proposal
    /// - slot <= minimum recorded slot => refuse lower-bound violation
    pub fn checkAndInsertBlock(
        self: *SlashingProtectionDb,
        pubkey: [48]u8,
        slot: u64,
        signing_root: [32]u8,
    ) !bool {
        if (self.block_history.get(pubkey)) |history| {
            var matched_same_data = false;
            for (history.items) |rec| {
                if (rec.slot != slot) continue;
                if (sameNonZeroSigningRoot(rec.signing_root, signing_root)) {
                    matched_same_data = true;
                    continue;
                }
                log.warn("slashing protection: double proposal at slot={d}", .{slot});
                return false;
            }
            if (matched_same_data) return true;

            if (history.items.len > 0 and slot <= history.items[0].slot) {
                log.warn(
                    "slashing protection: block slot={d} <= lower_bound_slot={d}",
                    .{ slot, history.items[0].slot },
                );
                return false;
            }
        }

        try self.appendBlockRecord(pubkey, .{ .slot = slot, .signing_root = signing_root });
        try self.insertBlockRecord(pubkey, .{ .slot = slot, .signing_root = signing_root });
        return true;
    }

    /// Check if an attestation can be signed (no double vote / surround vote) and,
    /// if safe, record the signing and return true. Returns false if slashing
    /// protection triggers.
    ///
    /// Protection rules (Lodestar/EIP-3076 aligned):
    ///   1. Double vote: same target_epoch with different / unknown signing root => refuse.
    ///      Same target_epoch with the same non-zero signing root is a safe repeat sign.
    ///   2. Surround vote: refuse if new attestation surrounds or is surrounded by any existing.
    ///      - SURROUNDING: new_source < existing_source AND new_target > existing_target
    ///      - SURROUNDED:  new_source > existing_source AND new_target < existing_target
    ///   3. Imported lower-bound protection:
    ///      - source_epoch < min_source_epoch => refuse
    ///      - target_epoch <= min_target_epoch => refuse
    ///
    /// TS equivalent: SlashingProtectionAttestation.checkAndInsertAttestation
    pub fn checkAndInsertAttestation(
        self: *SlashingProtectionDb,
        pubkey: [48]u8,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: [32]u8,
    ) !bool {
        if (source_epoch > target_epoch) {
            log.warn("slashing protection: source_epoch={d} > target_epoch={d}: invalid attestation", .{ source_epoch, target_epoch });
            return false;
        }

        if (self.attest_history.get(pubkey)) |history| {
            var matched_same_data = false;
            for (history.items) |rec| {
                if (target_epoch != rec.target_epoch) continue;
                if (sameNonZeroSigningRoot(rec.signing_root, signing_root)) {
                    matched_same_data = true;
                    continue;
                }
                log.warn("slashing protection: double vote target={d}", .{target_epoch});
                return false;
            }
            if (matched_same_data) return true;

            const surround = checkSurroundVote(history.items, source_epoch, target_epoch);
            switch (surround) {
                .surrounding => {
                    log.warn("slashing protection: surround vote — new ({d},{d}) surrounds an existing attestation", .{ source_epoch, target_epoch });
                    return false;
                },
                .surrounded => {
                    log.warn("slashing protection: surround vote — new ({d},{d}) is surrounded by an existing attestation", .{ source_epoch, target_epoch });
                    return false;
                },
                .safe => {},
            }
        }

        if (self.attestation_lower_bounds.get(pubkey)) |lower_bound| {
            if (source_epoch < lower_bound.min_source_epoch) {
                log.warn(
                    "slashing protection: source_epoch={d} < lower_bound_source={d}",
                    .{ source_epoch, lower_bound.min_source_epoch },
                );
                return false;
            }
            if (target_epoch <= lower_bound.min_target_epoch) {
                log.warn(
                    "slashing protection: target_epoch={d} <= lower_bound_target={d}",
                    .{ target_epoch, lower_bound.min_target_epoch },
                );
                return false;
            }
        }

        try self.appendAttestationRecord(pubkey, .{
            .source_epoch = source_epoch,
            .target_epoch = target_epoch,
            .signing_root = signing_root,
        });
        try self.insertAttestRecord(pubkey, .{
            .source_epoch = source_epoch,
            .target_epoch = target_epoch,
            .signing_root = signing_root,
        });
        return true;
    }

    pub fn importHistory(self: *SlashingProtectionDb, history: SlashingProtectionHistory) !void {
        var min_source_epoch: ?u64 = null;
        var min_target_epoch: ?u64 = null;

        for (history.signed_blocks) |record| {
            try self.appendBlockRecord(history.pubkey, .{
                .slot = record.slot,
                .signing_root = record.signing_root,
            });
            try self.insertBlockRecord(history.pubkey, .{
                .slot = record.slot,
                .signing_root = record.signing_root,
            });
        }

        for (history.signed_attestations) |record| {
            try self.appendAttestationRecord(history.pubkey, .{
                .source_epoch = record.source_epoch,
                .target_epoch = record.target_epoch,
                .signing_root = record.signing_root,
            });
            try self.insertAttestRecord(history.pubkey, .{
                .source_epoch = record.source_epoch,
                .target_epoch = record.target_epoch,
                .signing_root = record.signing_root,
            });
            min_source_epoch = if (min_source_epoch) |existing|
                @min(existing, record.source_epoch)
            else
                record.source_epoch;
            min_target_epoch = if (min_target_epoch) |existing|
                @min(existing, record.target_epoch)
            else
                record.target_epoch;
        }

        if (min_source_epoch) |min_source| {
            const lower_bound = AttestationLowerBound{
                .min_source_epoch = min_source,
                .min_target_epoch = min_target_epoch.?,
            };
            try self.mergeAttestationLowerBound(history.pubkey, lower_bound, true);
        }
    }

    /// Return the current persisted slashing protection history for one validator.
    pub fn exportHistory(self: *const SlashingProtectionDb, allocator: Allocator, pubkey: [48]u8) !?SlashingProtectionHistory {
        const blocks = if (self.block_history.get(pubkey)) |history|
            try copyBlockHistory(allocator, history.items)
        else
            try allocator.alloc(SignedBlock, 0);
        errdefer allocator.free(blocks);

        const attestations = if (self.attest_history.get(pubkey)) |history|
            try copyAttestHistory(allocator, history.items)
        else
            try allocator.alloc(SignedAttestation, 0);
        errdefer allocator.free(attestations);

        if (blocks.len == 0 and attestations.len == 0) {
            allocator.free(blocks);
            allocator.free(attestations);
            return null;
        }

        return .{
            .pubkey = pubkey,
            .signed_blocks = blocks,
            .signed_attestations = attestations,
        };
    }

    pub fn hasAttestedInEpoch(self: *const SlashingProtectionDb, pubkey: [48]u8, target_epoch: u64) bool {
        const history = self.attest_history.get(pubkey) orelse return false;
        for (history.items) |record| {
            if (record.target_epoch == target_epoch) return true;
            if (record.target_epoch > target_epoch) break;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Internal: attestation history management
    // -----------------------------------------------------------------------

    fn insertBlockRecord(self: *SlashingProtectionDb, pubkey: [48]u8, rec: BlockRecord) !void {
        const gop = try self.block_history.getOrPut(pubkey);
        if (!gop.found_existing) gop.value_ptr.* = BlockHistory.init(self.allocator);

        const history = gop.value_ptr;
        var lo: usize = 0;
        var hi: usize = history.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (history.items[mid].slot < rec.slot) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        var idx = lo;
        while (idx < history.items.len and history.items[idx].slot == rec.slot) : (idx += 1) {
            if (std.mem.eql(u8, &history.items[idx].signing_root, &rec.signing_root)) return;
        }
        try history.insert(lo, rec);
    }

    /// Insert an attestation record into the in-memory history for pubkey,
    /// maintaining sort order by target_epoch ascending.
    fn insertAttestRecord(self: *SlashingProtectionDb, pubkey: [48]u8, rec: AttestRecord) !void {
        const gop = try self.attest_history.getOrPut(pubkey);
        if (!gop.found_existing) {
            gop.value_ptr.* = AttestHistory.init(self.allocator);
        }

        const history = gop.value_ptr;

        // Binary search for insertion point (sorted by target_epoch asc).
        var lo: usize = 0;
        var hi: usize = history.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (history.items[mid].target_epoch < rec.target_epoch) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        var idx = lo;
        while (idx < history.items.len and history.items[idx].target_epoch == rec.target_epoch) : (idx += 1) {
            const existing = history.items[idx];
            if (existing.source_epoch == rec.source_epoch and std.mem.eql(u8, &existing.signing_root, &rec.signing_root)) {
                return;
            }
        }
        try history.insert(lo, rec);
    }

    // -----------------------------------------------------------------------
    // Internal: I/O
    // -----------------------------------------------------------------------

    fn loadRecords(self: *SlashingProtectionDb) !void {
        const file = self.file orelse return;

        var buf: [MAX_RECORD_SIZE]u8 = undefined;
        var count_blocks: u32 = 0;
        var count_attests: u32 = 0;
        var count_lower_bounds: u32 = 0;
        const stat = try file.stat(self.io);
        var offset: u64 = 0;

        while (offset < stat.size) {
            // Read type byte.
            const n = try file.readPositionalAll(self.io, buf[0..1], offset);
            if (n != 1) break;
            offset += 1;

            const record_type = buf[0];
            switch (record_type) {
                RECORD_TYPE_BLOCK_V1 => {
                    if (!try self.readRecordBody(file, stat.size, &offset, &buf, BLOCK_V1_RECORD_SIZE - 1, "block")) break;
                    const slot = std.mem.readInt(u64, buf[0..8], .little);
                    var pubkey: [48]u8 = undefined;
                    @memcpy(&pubkey, buf[8..56]);
                    try self.insertBlockRecord(pubkey, .{ .slot = slot, .signing_root = UNKNOWN_SIGNING_ROOT });
                    count_blocks += 1;
                },
                RECORD_TYPE_ATTESTATION_V1 => {
                    if (!try self.readRecordBody(file, stat.size, &offset, &buf, ATTESTATION_V1_RECORD_SIZE - 1, "attestation")) break;
                    const source_epoch = std.mem.readInt(u64, buf[0..8], .little);
                    const target_epoch = std.mem.readInt(u64, buf[8..16], .little);
                    var pubkey: [48]u8 = undefined;
                    @memcpy(&pubkey, buf[16..64]);
                    try self.insertAttestRecord(pubkey, .{
                        .source_epoch = source_epoch,
                        .target_epoch = target_epoch,
                        .signing_root = UNKNOWN_SIGNING_ROOT,
                    });
                    count_attests += 1;
                },
                RECORD_TYPE_BLOCK_V2 => {
                    if (!try self.readRecordBody(file, stat.size, &offset, &buf, BLOCK_V2_RECORD_SIZE - 1, "block")) break;
                    const slot = std.mem.readInt(u64, buf[0..8], .little);
                    var pubkey: [48]u8 = undefined;
                    @memcpy(&pubkey, buf[8..56]);
                    var signing_root: [32]u8 = undefined;
                    @memcpy(&signing_root, buf[56..88]);
                    try self.insertBlockRecord(pubkey, .{ .slot = slot, .signing_root = signing_root });
                    count_blocks += 1;
                },
                RECORD_TYPE_ATTESTATION_V2 => {
                    if (!try self.readRecordBody(file, stat.size, &offset, &buf, ATTESTATION_V2_RECORD_SIZE - 1, "attestation")) break;
                    const source_epoch = std.mem.readInt(u64, buf[0..8], .little);
                    const target_epoch = std.mem.readInt(u64, buf[8..16], .little);
                    var pubkey: [48]u8 = undefined;
                    @memcpy(&pubkey, buf[16..64]);
                    var signing_root: [32]u8 = undefined;
                    @memcpy(&signing_root, buf[64..96]);
                    try self.insertAttestRecord(pubkey, .{
                        .source_epoch = source_epoch,
                        .target_epoch = target_epoch,
                        .signing_root = signing_root,
                    });
                    count_attests += 1;
                },
                RECORD_TYPE_ATTESTATION_LOWER_BOUND => {
                    if (!try self.readRecordBody(file, stat.size, &offset, &buf, ATTESTATION_LOWER_BOUND_RECORD_SIZE - 1, "attestation lower-bound")) break;
                    const min_source_epoch = std.mem.readInt(u64, buf[0..8], .little);
                    const min_target_epoch = std.mem.readInt(u64, buf[8..16], .little);
                    var pubkey: [48]u8 = undefined;
                    @memcpy(&pubkey, buf[16..64]);
                    try self.mergeAttestationLowerBound(pubkey, .{
                        .min_source_epoch = min_source_epoch,
                        .min_target_epoch = min_target_epoch,
                    }, false);
                    count_lower_bounds += 1;
                },
                else => {
                    log.warn("slashing_db: unknown record type 0x{x:0>2} — stopping replay", .{record_type});
                    break;
                },
            }
        }

        log.debug(
            "slashing_db loaded: {d} block records, {d} attestation records, {d} lower bounds",
            .{ count_blocks, count_attests, count_lower_bounds },
        );
    }

    fn appendBlockRecord(self: *SlashingProtectionDb, pubkey: [48]u8, block: SignedBlock) !void {
        const file = self.file orelse return; // no-op for in-memory instance

        var record: [BLOCK_V2_RECORD_SIZE]u8 = undefined;
        record[0] = RECORD_TYPE_BLOCK_V2;
        std.mem.writeInt(u64, record[1..9], block.slot, .little);
        @memcpy(record[9..57], &pubkey);
        @memcpy(record[57..89], &block.signing_root);

        const end = (try file.stat(self.io)).size;
        try file.writePositionalAll(self.io, &record, end);
        try file.sync(self.io);
    }

    fn appendAttestationRecord(self: *SlashingProtectionDb, pubkey: [48]u8, attestation: SignedAttestation) !void {
        const file = self.file orelse return;

        var record: [ATTESTATION_V2_RECORD_SIZE]u8 = undefined;
        record[0] = RECORD_TYPE_ATTESTATION_V2;
        std.mem.writeInt(u64, record[1..9], attestation.source_epoch, .little);
        std.mem.writeInt(u64, record[9..17], attestation.target_epoch, .little);
        @memcpy(record[17..65], &pubkey);
        @memcpy(record[65..97], &attestation.signing_root);

        const end = (try file.stat(self.io)).size;
        try file.writePositionalAll(self.io, &record, end);
        try file.sync(self.io);
    }

    fn appendAttestationLowerBoundRecord(self: *SlashingProtectionDb, pubkey: [48]u8, lower_bound: AttestationLowerBound) !void {
        const file = self.file orelse return;

        var record: [ATTESTATION_LOWER_BOUND_RECORD_SIZE]u8 = undefined;
        record[0] = RECORD_TYPE_ATTESTATION_LOWER_BOUND;
        std.mem.writeInt(u64, record[1..9], lower_bound.min_source_epoch, .little);
        std.mem.writeInt(u64, record[9..17], lower_bound.min_target_epoch, .little);
        @memcpy(record[17..65], &pubkey);

        const end = (try file.stat(self.io)).size;
        try file.writePositionalAll(self.io, &record, end);
        try file.sync(self.io);
    }

    fn mergeAttestationLowerBound(
        self: *SlashingProtectionDb,
        pubkey: [48]u8,
        lower_bound: AttestationLowerBound,
        persist: bool,
    ) !void {
        const next = if (self.attestation_lower_bounds.get(pubkey)) |existing|
            AttestationLowerBound{
                .min_source_epoch = @min(existing.min_source_epoch, lower_bound.min_source_epoch),
                .min_target_epoch = @min(existing.min_target_epoch, lower_bound.min_target_epoch),
            }
        else
            lower_bound;

        const changed = if (self.attestation_lower_bounds.get(pubkey)) |existing|
            existing.min_source_epoch != next.min_source_epoch or existing.min_target_epoch != next.min_target_epoch
        else
            true;

        try self.attestation_lower_bounds.put(pubkey, next);
        if (persist and changed) try self.appendAttestationLowerBoundRecord(pubkey, next);
    }

    fn readRecordBody(
        self: *SlashingProtectionDb,
        file: Io.File,
        file_size: u64,
        offset: *u64,
        buf: []u8,
        rest_size: usize,
        label: []const u8,
    ) !bool {
        if (file_size - offset.* < rest_size) {
            log.warn("slashing_db: truncated {s} record at EOF (expected {d} bytes, got {d})", .{ label, rest_size, file_size - offset.* });
            return false;
        }
        const m = try file.readPositionalAll(self.io, buf[0..rest_size], offset.*);
        if (m != rest_size) {
            log.warn("slashing_db: truncated {s} record at EOF (expected {d} bytes, got {d})", .{ label, rest_size, m });
            return false;
        }
        offset.* += rest_size;
        return true;
    }

    fn copyBlockHistory(allocator: Allocator, records: []const BlockRecord) ![]SignedBlock {
        const out = try allocator.alloc(SignedBlock, records.len);
        for (records, out) |record, *dst| {
            dst.* = .{
                .slot = record.slot,
                .signing_root = record.signing_root,
            };
        }
        return out;
    }

    fn copyAttestHistory(allocator: Allocator, records: []const AttestRecord) ![]SignedAttestation {
        const out = try allocator.alloc(SignedAttestation, records.len);
        for (records, out) |record, *dst| {
            dst.* = .{
                .source_epoch = record.source_epoch,
                .target_epoch = record.target_epoch,
                .signing_root = record.signing_root,
            };
        }
        return out;
    }

    fn sameNonZeroSigningRoot(a: [32]u8, b: [32]u8) bool {
        return !std.mem.eql(u8, &a, &UNKNOWN_SIGNING_ROOT) and std.mem.eql(u8, &a, &b);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "SlashingProtectionDb: in-memory block protection" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0xAB} ** 48;
    const root_a = [_]u8{0xAA} ** 32;
    const root_b = [_]u8{0xBB} ** 32;
    const root_c = [_]u8{0xCC} ** 32;

    // First sign at slot 10 — allowed.
    try testing.expect(try db.checkAndInsertBlock(pubkey, 10, root_a));

    // Same slot, same signing root — safe repeat sign.
    try testing.expect(try db.checkAndInsertBlock(pubkey, 10, root_a));

    // Same slot, different root — double proposal.
    try testing.expect(!(try db.checkAndInsertBlock(pubkey, 10, root_b)));

    // Earlier slot violates the lower bound.
    try testing.expect(!(try db.checkAndInsertBlock(pubkey, 9, root_c)));

    // Later slot — allowed.
    try testing.expect(try db.checkAndInsertBlock(pubkey, 11, root_b));
}

test "SlashingProtectionDb: in-memory attestation double vote protection" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0xCD} ** 48;
    const root_a = [_]u8{0x11} ** 32;
    const root_b = [_]u8{0x22} ** 32;

    // First attestation source=1, target=5 — allowed.
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 5, root_a));

    // Same target + same root — safe repeat sign.
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 5, root_a));

    // Same target + different root — double vote.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 2, 5, root_b)));

    // Surrounded by existing (1,5) — refused.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 2, 4, root_b)));

    // Valid next attestation.
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 6, root_b));
}

test "SlashingProtectionDb: surround vote — new surrounds existing" {
    // Existing (2, 5), new (1, 6): new_source < existing_source AND new_target > existing_target
    // → SURROUNDING — refuse.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x01} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5, [_]u8{0x01} ** 32));
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 1, 6, [_]u8{0x02} ** 32)));
}

test "SlashingProtectionDb: surround vote — new surrounded by existing" {
    // Existing (1, 6), new (2, 5): new_source > existing_source AND new_target < existing_target
    // → SURROUNDED — refuse.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x02} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 6, [_]u8{0x03} ** 32));
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 2, 5, [_]u8{0x04} ** 32)));
}

test "SlashingProtectionDb: non-overlapping attestations — accept" {
    // Existing (2, 5), new (6, 8): completely non-overlapping — accept.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x03} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5, [_]u8{0x05} ** 32));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 6, 8, [_]u8{0x06} ** 32));
}

test "SlashingProtectionDb: adjacent attestations — accept" {
    // Existing (2, 5), new (5, 7): source of new == target of existing — not surrounding.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x04} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5, [_]u8{0x07} ** 32));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 5, 7, [_]u8{0x08} ** 32));
}

test "SlashingProtectionDb: multiple existing records — surround detected" {
    // Build history: (1,3), (4,6), (7,9)
    // New (5, 10): source=5 < 7 AND target=10 > 9 → surrounds (7,9)
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x05} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 3, [_]u8{0x09} ** 32));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 4, 6, [_]u8{0x0A} ** 32));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 7, 9, [_]u8{0x0B} ** 32));

    // New (5, 10) surrounds (7, 9): 5 < 7 AND 10 > 9 → refuse.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 5, 10, [_]u8{0x0C} ** 32)));
}

test "SlashingProtectionDb: multiple existing records — surrounded detected" {
    // Build history: (1,3), (2,8)
    // New (3, 7): source=3 > 2 AND target=7 < 8 → surrounded by (2,8)
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x06} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 3, [_]u8{0x0D} ** 32));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 8, [_]u8{0x0E} ** 32));

    // New (3, 7): 3 > 2 AND 7 < 8 → surrounded by (2,8) → refuse.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 3, 7, [_]u8{0x0F} ** 32)));
}

test "SlashingProtectionDb: double vote still detected (same target, different source)" {
    // Existing (2, 5), new (3, 5): same target epoch — double vote — refuse.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x07} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5, [_]u8{0x10} ** 32));
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 3, 5, [_]u8{0x11} ** 32)));
}

test "SlashingProtectionDb: different validators are independent" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey1: [48]u8 = [_]u8{0xAA} ** 48;
    const pubkey2: [48]u8 = [_]u8{0xBB} ** 48;

    // pubkey1: existing (1, 6)
    try testing.expect(try db.checkAndInsertAttestation(pubkey1, 1, 6, [_]u8{0x12} ** 32));

    // pubkey2: new (2, 5) — would be surrounded if pubkey1's records applied, but they don't.
    try testing.expect(try db.checkAndInsertAttestation(pubkey2, 2, 5, [_]u8{0x13} ** 32));
}

test "SlashingProtectionDb: persistent storage round-trip with surround check" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const db_path = try std.fs.path.join(testing.allocator, &.{ ".zig-cache", "tmp", &tmp_dir.sub_path, "slashing.db" });
    defer testing.allocator.free(db_path);

    const pubkey: [48]u8 = [_]u8{0x42} ** 48;

    // Write records: (2, 5) and (6, 8).
    {
        var db = try SlashingProtectionDb.init(testing.io, testing.allocator, db_path);
        defer db.close();

        try testing.expect(try db.checkAndInsertBlock(pubkey, 100, [_]u8{0x21} ** 32));
        try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5, [_]u8{0x22} ** 32));
        try testing.expect(try db.checkAndInsertAttestation(pubkey, 6, 8, [_]u8{0x23} ** 32));
    }

    // Reload and verify surround check works on replayed history.
    {
        var db = try SlashingProtectionDb.init(testing.io, testing.allocator, db_path);
        defer db.close();

        // Same block data may be repeated safely after replay.
        try testing.expect(try db.checkAndInsertBlock(pubkey, 100, [_]u8{0x21} ** 32));
        // Different data at the same slot is slashable.
        try testing.expect(!(try db.checkAndInsertBlock(pubkey, 100, [_]u8{0x24} ** 32)));
        // Block at slot 101 — allowed.
        try testing.expect(try db.checkAndInsertBlock(pubkey, 101, [_]u8{0x25} ** 32));

        // Surround against (6, 8): new (5, 9) surrounds (6, 8): 5 < 6 AND 9 > 8 → refuse.
        try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 5, 9, [_]u8{0x26} ** 32)));

        // Valid next attestation.
        try testing.expect(try db.checkAndInsertAttestation(pubkey, 8, 10, [_]u8{0x27} ** 32));
    }
}

test "SlashingProtectionDb: imported attestation lower bounds stay active" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey = [_]u8{0x31} ** 48;
    const imported_history = SlashingProtectionHistory{
        .pubkey = pubkey,
        .signed_blocks = &.{},
        .signed_attestations = &.{
            .{ .source_epoch = 10, .target_epoch = 20, .signing_root = [_]u8{0x32} ** 32 },
            .{ .source_epoch = 21, .target_epoch = 22, .signing_root = [_]u8{0x33} ** 32 },
        },
    };

    try db.importHistory(imported_history);
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 9, 21, [_]u8{0x34} ** 32)));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 10, 20, [_]u8{0x32} ** 32));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 22, 23, [_]u8{0x35} ** 32));
}

test "SlashingProtectionDb: exportHistory preserves full records and signing roots" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey = [_]u8{0x41} ** 48;
    try testing.expect(try db.checkAndInsertBlock(pubkey, 12, [_]u8{0x44} ** 32));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 3, 7, [_]u8{0x45} ** 32));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 7, 8, [_]u8{0x46} ** 32));

    const history = (try db.exportHistory(testing.allocator, pubkey)).?;
    defer {
        testing.allocator.free(history.signed_blocks);
        testing.allocator.free(history.signed_attestations);
    }

    try testing.expectEqual(@as(usize, 1), history.signed_blocks.len);
    try testing.expectEqual(@as(u64, 12), history.signed_blocks[0].slot);
    try testing.expectEqualSlices(u8, &([_]u8{0x44} ** 32), &history.signed_blocks[0].signing_root);
    try testing.expectEqual(@as(usize, 2), history.signed_attestations.len);
    try testing.expectEqual(@as(u64, 7), history.signed_attestations[0].target_epoch);
    try testing.expectEqual(@as(u64, 8), history.signed_attestations[1].target_epoch);
}

test "SlashingProtectionDb: checkSurroundVote unit tests" {
    const history = [_]AttestRecord{
        .{ .source_epoch = 2, .target_epoch = 5 },
        .{ .source_epoch = 6, .target_epoch = 8 },
    };

    // Surrounding: 1 < 2 AND 6 > 5 → surrounding
    try testing.expectEqual(SurroundResult.surrounding, checkSurroundVote(&history, 1, 6));

    // Surrounded: 3 > 2 AND 4 < 5 → surrounded
    try testing.expectEqual(SurroundResult.surrounded, checkSurroundVote(&history, 3, 4));

    // Non-overlapping (after history): safe
    try testing.expectEqual(SurroundResult.safe, checkSurroundVote(&history, 9, 11));

    // New (5,9) surrounds the later record (6,8).
    try testing.expectEqual(SurroundResult.surrounding, checkSurroundVote(&history, 5, 9));

    // Equal source and target: not a surround (needs strict inequality)
    try testing.expectEqual(SurroundResult.safe, checkSurroundVote(&history, 2, 5));
}
