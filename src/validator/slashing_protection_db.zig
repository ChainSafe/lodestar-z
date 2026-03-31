//! Persistent slashing protection database for the Validator Client.
//!
//! Uses a simple append-only file of fixed-size records.
//! On startup: reads all records and builds in-memory maps.
//! On sign: appends the new record, then updates the in-memory map.
//! fsync after each write for crash safety.
//!
//! Record format:
//!   Block record:       [1 byte type=0x01][8 bytes slot (little-endian)][48 bytes pubkey] = 57 bytes
//!   Attestation record: [1 byte type=0x02][8 bytes source_epoch][8 bytes target_epoch][48 bytes pubkey] = 65 bytes
//!
//! TS equivalent: packages/validator/src/slashingProtection/
//!               (SlashingProtectionLevelDB in TS uses LevelDB; we use a simple append-only file)
//!
//! Thread safety: this struct does NOT provide internal locking. Callers are
//! responsible for serializing access. In production, ValidatorStore holds a
//! single mutex that is locked for the full check-and-sign sequence, which
//! prevents TOCTOU races between the protection check and the signing call.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fs = @import("fs.zig");

const log = std.log.scoped(.slashing_db);

// ---------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------

const RECORD_TYPE_BLOCK: u8 = 0x01;
const RECORD_TYPE_ATTESTATION: u8 = 0x02;

const BLOCK_RECORD_SIZE: usize = 1 + 8 + 48; // type + slot + pubkey = 57
const ATTESTATION_RECORD_SIZE: usize = 1 + 8 + 8 + 48; // type + source + target + pubkey = 65

// ---------------------------------------------------------------------------
// In-memory maps
// ---------------------------------------------------------------------------

/// Last signed block slot per validator public key.
const BlockMap = std.HashMap([48]u8, u64, PubkeyContext, std.hash_map.default_max_load_percentage);

/// Attestation record: source and target epochs.
pub const AttestRecord = struct {
    source_epoch: u64,
    target_epoch: u64,
};

/// All attestation records for a single validator, kept sorted by target_epoch ascending.
/// Sorted order enables efficient surround vote detection.
const AttestHistory = std.array_list.Managed(AttestRecord);

/// Map from pubkey → list of all attestation records (sorted by target_epoch asc).
const AttestHistoryMap = std.HashMap([48]u8, AttestHistory, PubkeyContext, std.hash_map.default_max_load_percentage);

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
    block_map: BlockMap,
    /// Full attestation history per validator (sorted by target_epoch asc).
    attest_history: AttestHistoryMap,

    /// Initialize the slashing protection database.
    ///
    /// Opens or creates the file at db_path, reads all existing records into memory.
    /// Pass db_path = null to create an in-memory-only instance (for tests).
    pub fn init(io: Io, allocator: Allocator, db_path: ?[]const u8) !SlashingProtectionDb {
        var self = SlashingProtectionDb{
            .io = io,
            .allocator = allocator,
            .file = null,
            .block_map = BlockMap.init(allocator),
            .attest_history = AttestHistoryMap.init(allocator),
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
        self.block_map.deinit();

        // Free all per-validator attestation history lists.
        var it = self.attest_history.valueIterator();
        while (it.next()) |history| {
            history.deinit();
        }
        self.attest_history.deinit();
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Check if a block can be signed (not a double proposal) and, if safe,
    /// record the signing and return true. Returns false if slashing protection
    /// triggers.
    ///
    /// Protection rule: refuse if slot <= last_signed_block_slot for this pubkey.
    pub fn checkAndInsertBlock(self: *SlashingProtectionDb, pubkey: [48]u8, slot: u64) !bool {
        if (self.block_map.get(pubkey)) |last_slot| {
            if (slot <= last_slot) {
                log.warn("slashing protection: block slot={d} <= last_slot={d}", .{ slot, last_slot });
                return false;
            }
        }

        // Append record first (crash-safe: if we crash after append but before
        // in-memory update, we'll replay and the map will be consistent on restart).
        try self.appendBlockRecord(pubkey, slot);
        try self.block_map.put(pubkey, slot);
        return true;
    }

    /// Check if an attestation can be signed (no double vote / surround vote) and,
    /// if safe, record the signing and return true. Returns false if slashing
    /// protection triggers.
    ///
    /// Protection rules (EIP-3076 compliant):
    ///   1. Double vote: refuse if target_epoch == any existing target_epoch for this validator.
    ///      (target_epoch < max existing target is also refused — monotonic target enforcement)
    ///   2. Surround vote: refuse if new attestation surrounds or is surrounded by any existing.
    ///      - SURROUNDING: new_source < existing_source AND new_target > existing_target
    ///      - SURROUNDED:  new_source > existing_source AND new_target < existing_target
    ///
    /// TS equivalent: SlashingProtectionAttestation.checkAndInsertAttestation
    pub fn checkAndInsertAttestation(
        self: *SlashingProtectionDb,
        pubkey: [48]u8,
        source_epoch: u64,
        target_epoch: u64,
    ) !bool {
        // Reject if source >= target — this is always invalid per Casper FFG.
        if (source_epoch >= target_epoch) {
            log.warn("slashing protection: source_epoch={d} >= target_epoch={d}: invalid attestation", .{ source_epoch, target_epoch });
            return false;
        }

        if (self.attest_history.get(pubkey)) |history| {
            // Check all existing records.
            for (history.items) |rec| {
                // Double vote: same target epoch.
                if (target_epoch == rec.target_epoch) {
                    log.warn("slashing protection: double vote target={d}", .{target_epoch});
                    return false;
                }
                // Monotonic target: refuse attestations with older target than existing max.
                // (The max is the last element since history is sorted asc by target.)
            }

            // Monotonic target enforcement: refuse if target <= max existing target.
            if (history.items.len > 0) {
                const max_target = history.items[history.items.len - 1].target_epoch;
                if (target_epoch < max_target) {
                    log.warn("slashing protection: attest target={d} < max_target={d}", .{ target_epoch, max_target });
                    return false;
                }
            }

            // Surround vote check across all historical records.
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

        // Safe to sign — persist and update in-memory history.
        try self.appendAttestationRecord(pubkey, source_epoch, target_epoch);
        try self.insertAttestRecord(pubkey, source_epoch, target_epoch);
        return true;
    }

    // -----------------------------------------------------------------------
    // Internal: attestation history management
    // -----------------------------------------------------------------------

    /// Insert an attestation record into the in-memory history for pubkey,
    /// maintaining sort order by target_epoch ascending.
    fn insertAttestRecord(self: *SlashingProtectionDb, pubkey: [48]u8, source_epoch: u64, target_epoch: u64) !void {
        const rec = AttestRecord{ .source_epoch = source_epoch, .target_epoch = target_epoch };

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
            if (history.items[mid].target_epoch < target_epoch) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // lo is the insertion index.
        try history.insert(lo, rec);
    }

    // -----------------------------------------------------------------------
    // Internal: I/O
    // -----------------------------------------------------------------------

    fn loadRecords(self: *SlashingProtectionDb) !void {
        const file = self.file orelse return;

        var buf: [ATTESTATION_RECORD_SIZE]u8 = undefined; // largest record
        var count_blocks: u32 = 0;
        var count_attests: u32 = 0;
        const stat = try file.stat(self.io);
        var offset: u64 = 0;

        while (offset < stat.size) {
            // Read type byte.
            const n = try file.readPositionalAll(self.io, buf[0..1], offset);
            if (n != 1) break;
            offset += 1;

            const record_type = buf[0];
            switch (record_type) {
                RECORD_TYPE_BLOCK => {
                    const rest_size = BLOCK_RECORD_SIZE - 1; // already read type byte
                    if (stat.size - offset < rest_size) {
                        log.warn("slashing_db: truncated block record at EOF (expected {d} bytes, got {d})", .{ rest_size, stat.size - offset });
                        break;
                    }
                    const m = try file.readPositionalAll(self.io, buf[0..rest_size], offset);
                    if (m != rest_size) {
                        log.warn("slashing_db: truncated block record at EOF (expected {d} bytes, got {d})", .{ rest_size, m });
                        break;
                    }
                    offset += rest_size;

                    const slot = std.mem.readInt(u64, buf[0..8], .little);
                    var pubkey: [48]u8 = undefined;
                    @memcpy(&pubkey, buf[8..56]);

                    // Update map (last slot wins on replay).
                    const existing = self.block_map.get(pubkey);
                    if (existing == null or slot > existing.?) {
                        try self.block_map.put(pubkey, slot);
                    }
                    count_blocks += 1;
                },
                RECORD_TYPE_ATTESTATION => {
                    const rest_size = ATTESTATION_RECORD_SIZE - 1;
                    if (stat.size - offset < rest_size) {
                        log.warn("slashing_db: truncated attestation record at EOF (expected {d} bytes, got {d})", .{ rest_size, stat.size - offset });
                        break;
                    }
                    const m = try file.readPositionalAll(self.io, buf[0..rest_size], offset);
                    if (m != rest_size) {
                        log.warn("slashing_db: truncated attestation record at EOF (expected {d} bytes, got {d})", .{ rest_size, m });
                        break;
                    }
                    offset += rest_size;

                    const source_epoch = std.mem.readInt(u64, buf[0..8], .little);
                    const target_epoch = std.mem.readInt(u64, buf[8..16], .little);
                    var pubkey: [48]u8 = undefined;
                    @memcpy(&pubkey, buf[16..64]);

                    // Insert into sorted history (duplicates are possible from crash recovery — skip).
                    const gop = try self.attest_history.getOrPut(pubkey);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = AttestHistory.init(self.allocator);
                    }
                    const history = gop.value_ptr;

                    // Check for duplicate target_epoch (can happen if we replayed a partial write).
                    var is_dup = false;
                    for (history.items) |rec| {
                        if (rec.target_epoch == target_epoch) {
                            is_dup = true;
                            break;
                        }
                    }
                    if (!is_dup) {
                        try self.insertAttestRecord(pubkey, source_epoch, target_epoch);
                    }
                    count_attests += 1;
                },
                else => {
                    log.warn("slashing_db: unknown record type 0x{x:0>2} — stopping replay", .{record_type});
                    break;
                },
            }
        }

        log.debug("slashing_db loaded: {d} block records, {d} attestation records", .{ count_blocks, count_attests });
    }

    fn appendBlockRecord(self: *SlashingProtectionDb, pubkey: [48]u8, slot: u64) !void {
        const file = self.file orelse return; // no-op for in-memory instance

        var record: [BLOCK_RECORD_SIZE]u8 = undefined;
        record[0] = RECORD_TYPE_BLOCK;
        std.mem.writeInt(u64, record[1..9], slot, .little);
        @memcpy(record[9..57], &pubkey);

        const end = (try file.stat(self.io)).size;
        try file.writePositionalAll(self.io, &record, end);
        try file.sync(self.io);
    }

    fn appendAttestationRecord(self: *SlashingProtectionDb, pubkey: [48]u8, source_epoch: u64, target_epoch: u64) !void {
        const file = self.file orelse return;

        var record: [ATTESTATION_RECORD_SIZE]u8 = undefined;
        record[0] = RECORD_TYPE_ATTESTATION;
        std.mem.writeInt(u64, record[1..9], source_epoch, .little);
        std.mem.writeInt(u64, record[9..17], target_epoch, .little);
        @memcpy(record[17..65], &pubkey);

        const end = (try file.stat(self.io)).size;
        try file.writePositionalAll(self.io, &record, end);
        try file.sync(self.io);
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

    // First sign at slot 10 — allowed.
    try testing.expect(try db.checkAndInsertBlock(pubkey, 10));

    // Same slot — double proposal — refused.
    try testing.expect(!(try db.checkAndInsertBlock(pubkey, 10)));

    // Earlier slot — refused.
    try testing.expect(!(try db.checkAndInsertBlock(pubkey, 9)));

    // Later slot — allowed.
    try testing.expect(try db.checkAndInsertBlock(pubkey, 11));
}

test "SlashingProtectionDb: in-memory attestation double vote protection" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0xCD} ** 48;

    // First attestation source=1, target=5 — allowed.
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 5));

    // Same target — double vote — refused.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 2, 5)));

    // Earlier target — refused.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 2, 4)));

    // Valid next attestation.
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 6));
}

test "SlashingProtectionDb: surround vote — new surrounds existing" {
    // Existing (2, 5), new (1, 6): new_source < existing_source AND new_target > existing_target
    // → SURROUNDING — refuse.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x01} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5));
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 1, 6)));
}

test "SlashingProtectionDb: surround vote — new surrounded by existing" {
    // Existing (1, 6), new (2, 5): new_source > existing_source AND new_target < existing_target
    // → SURROUNDED — refuse.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x02} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 6));
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 2, 5)));
}

test "SlashingProtectionDb: non-overlapping attestations — accept" {
    // Existing (2, 5), new (6, 8): completely non-overlapping — accept.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x03} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 6, 8));
}

test "SlashingProtectionDb: adjacent attestations — accept" {
    // Existing (2, 5), new (5, 7): source of new == target of existing — not surrounding.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x04} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 5, 7));
}

test "SlashingProtectionDb: multiple existing records — surround detected" {
    // Build history: (1,3), (4,6), (7,9)
    // New (5, 10): source=5 < 7 AND target=10 > 9 → surrounds (7,9)
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x05} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 3));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 4, 6));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 7, 9));

    // New (5, 10) surrounds (7, 9): 5 < 7 AND 10 > 9 → refuse.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 5, 10)));
}

test "SlashingProtectionDb: multiple existing records — surrounded detected" {
    // Build history: (1,3), (2,8)
    // New (3, 7): source=3 > 2 AND target=7 < 8 → surrounded by (2,8)
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x06} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 3));
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 8));

    // New (3, 7): 3 > 2 AND 7 < 8 → surrounded by (2,8) → refuse.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 3, 7)));
}

test "SlashingProtectionDb: double vote still detected (same target, different source)" {
    // Existing (2, 5), new (3, 5): same target epoch — double vote — refuse.
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0x07} ** 48;

    try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5));
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 3, 5)));
}

test "SlashingProtectionDb: different validators are independent" {
    var db = try SlashingProtectionDb.init(testing.io, testing.allocator, null);
    defer db.close();

    const pubkey1: [48]u8 = [_]u8{0xAA} ** 48;
    const pubkey2: [48]u8 = [_]u8{0xBB} ** 48;

    // pubkey1: existing (1, 6)
    try testing.expect(try db.checkAndInsertAttestation(pubkey1, 1, 6));

    // pubkey2: new (2, 5) — would be surrounded if pubkey1's records applied, but they don't.
    try testing.expect(try db.checkAndInsertAttestation(pubkey2, 2, 5));
}

test "SlashingProtectionDb: persistent storage round-trip with surround check" {
    const tmp_dir = testing.tmpDir(.{});
    const tmp_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    const db_path = try std.fmt.allocPrint(testing.allocator, "{s}/slashing.db", .{tmp_path});
    defer testing.allocator.free(db_path);

    const pubkey: [48]u8 = [_]u8{0x42} ** 48;

    // Write records: (2, 5) and (6, 8).
    {
        var db = try SlashingProtectionDb.init(testing.io, testing.allocator, db_path);
        defer db.close();

        try testing.expect(try db.checkAndInsertBlock(pubkey, 100));
        try testing.expect(try db.checkAndInsertAttestation(pubkey, 2, 5));
        try testing.expect(try db.checkAndInsertAttestation(pubkey, 6, 8));
    }

    // Reload and verify surround check works on replayed history.
    {
        var db = try SlashingProtectionDb.init(testing.io, testing.allocator, db_path);
        defer db.close();

        // Block at slot 100 was already signed — refused.
        try testing.expect(!(try db.checkAndInsertBlock(pubkey, 100)));
        // Block at slot 101 — allowed.
        try testing.expect(try db.checkAndInsertBlock(pubkey, 101));

        // Surround against (6, 8): new (5, 9) surrounds (6, 8): 5 < 6 AND 9 > 8 → refuse.
        try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 5, 9)));

        // Valid next attestation.
        try testing.expect(try db.checkAndInsertAttestation(pubkey, 8, 10));
    }
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

    // Adjacent (source == target of existing): safe (not strict surround)
    try testing.expectEqual(SurroundResult.safe, checkSurroundVote(&history, 5, 9));

    // Equal source and target: not a surround (needs strict inequality)
    try testing.expectEqual(SurroundResult.safe, checkSurroundVote(&history, 2, 5));
}
