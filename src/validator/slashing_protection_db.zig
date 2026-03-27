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

const std = @import("std");
const Allocator = std.mem.Allocator;

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

/// Attestation record: last signed source and target epochs.
const AttestRecord = struct {
    source_epoch: u64,
    target_epoch: u64,
};

const AttestMap = std.HashMap([48]u8, AttestRecord, PubkeyContext, std.hash_map.default_max_load_percentage);

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
// SlashingProtectionDb
// ---------------------------------------------------------------------------

pub const SlashingProtectionDb = struct {
    allocator: Allocator,
    file: ?std.fs.File,
    block_map: BlockMap,
    attest_map: AttestMap,

    /// Initialize the slashing protection database.
    ///
    /// Opens or creates the file at db_path, reads all existing records into memory.
    /// Pass db_path = null to create an in-memory-only instance (for tests).
    pub fn init(allocator: Allocator, db_path: ?[]const u8) !SlashingProtectionDb {
        var self = SlashingProtectionDb{
            .allocator = allocator,
            .file = null,
            .block_map = BlockMap.init(allocator),
            .attest_map = AttestMap.init(allocator),
        };

        if (db_path) |path| {
            const file = try std.fs.cwd().createFile(path, .{
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
            f.close();
            self.file = null;
        }
        self.block_map.deinit();
        self.attest_map.deinit();
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
    /// Protection rules (conservative EIP-3076 compliant):
    ///   - Double vote: refuse if target_epoch <= last_signed_target_epoch.
    ///   - Surround vote: refuse if source_epoch < last_signed_source_epoch.
    pub fn checkAndInsertAttestation(
        self: *SlashingProtectionDb,
        pubkey: [48]u8,
        source_epoch: u64,
        target_epoch: u64,
    ) !bool {
        if (self.attest_map.get(pubkey)) |last| {
            if (target_epoch <= last.target_epoch) {
                log.warn("slashing protection: attest target={d} <= last_target={d}", .{ target_epoch, last.target_epoch });
                return false;
            }
            if (source_epoch < last.source_epoch) {
                log.warn("slashing protection: attest source={d} < last_source={d} (surround risk)", .{ source_epoch, last.source_epoch });
                return false;
            }
        }

        try self.appendAttestationRecord(pubkey, source_epoch, target_epoch);
        try self.attest_map.put(pubkey, .{
            .source_epoch = source_epoch,
            .target_epoch = target_epoch,
        });
        return true;
    }

    // -----------------------------------------------------------------------
    // Internal: I/O
    // -----------------------------------------------------------------------

    fn loadRecords(self: *SlashingProtectionDb) !void {
        const file = self.file orelse return;

        // Seek to start.
        try file.seekTo(0);

        var buf: [ATTESTATION_RECORD_SIZE]u8 = undefined; // largest record
        var count_blocks: u32 = 0;
        var count_attests: u32 = 0;

        while (true) {
            // Read type byte.
            const n = file.read(buf[0..1]) catch break;
            if (n == 0) break; // EOF

            const record_type = buf[0];
            switch (record_type) {
                RECORD_TYPE_BLOCK => {
                    const rest_size = BLOCK_RECORD_SIZE - 1; // already read type byte
                    const m = try file.readAll(buf[0..rest_size]);
                    if (m != rest_size) break; // truncated record — stop

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
                    const m = try file.readAll(buf[0..rest_size]);
                    if (m != rest_size) break;

                    const source_epoch = std.mem.readInt(u64, buf[0..8], .little);
                    const target_epoch = std.mem.readInt(u64, buf[8..16], .little);
                    var pubkey: [48]u8 = undefined;
                    @memcpy(&pubkey, buf[16..64]);

                    // Update map: keep the highest target epoch seen for each pubkey.
                    const existing = self.attest_map.get(pubkey);
                    if (existing == null or target_epoch > existing.?.target_epoch) {
                        try self.attest_map.put(pubkey, .{
                            .source_epoch = source_epoch,
                            .target_epoch = target_epoch,
                        });
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

        // Seek to end and append.
        try file.seekFromEnd(0);
        try file.writeAll(&record);
        try file.sync();
    }

    fn appendAttestationRecord(self: *SlashingProtectionDb, pubkey: [48]u8, source_epoch: u64, target_epoch: u64) !void {
        const file = self.file orelse return;

        var record: [ATTESTATION_RECORD_SIZE]u8 = undefined;
        record[0] = RECORD_TYPE_ATTESTATION;
        std.mem.writeInt(u64, record[1..9], source_epoch, .little);
        std.mem.writeInt(u64, record[9..17], target_epoch, .little);
        @memcpy(record[17..65], &pubkey);

        try file.seekFromEnd(0);
        try file.writeAll(&record);
        try file.sync();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "SlashingProtectionDb: in-memory block protection" {
    var db = try SlashingProtectionDb.init(testing.allocator, null);
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

test "SlashingProtectionDb: in-memory attestation protection" {
    var db = try SlashingProtectionDb.init(testing.allocator, null);
    defer db.close();

    const pubkey: [48]u8 = [_]u8{0xCD} ** 48;

    // First attestation source=1, target=5 — allowed.
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 5));

    // Same target — double vote — refused.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 2, 5)));

    // Earlier target — refused.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 2, 4)));

    // Source goes backward — surround risk — refused.
    try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 0, 6)));

    // Valid next attestation.
    try testing.expect(try db.checkAndInsertAttestation(pubkey, 1, 6));
}

test "SlashingProtectionDb: persistent storage round-trip" {
    const tmp_dir = testing.tmpDir(.{});
    const tmp_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);

    const db_path = try std.fmt.allocPrint(testing.allocator, "{s}/slashing.db", .{tmp_path});
    defer testing.allocator.free(db_path);

    const pubkey: [48]u8 = [_]u8{0x42} ** 48;

    // Write some records.
    {
        var db = try SlashingProtectionDb.init(testing.allocator, db_path);
        defer db.close();

        try testing.expect(try db.checkAndInsertBlock(pubkey, 100));
        try testing.expect(try db.checkAndInsertAttestation(pubkey, 10, 20));
    }

    // Reload and check the records are still enforced.
    {
        var db = try SlashingProtectionDb.init(testing.allocator, db_path);
        defer db.close();

        // Block at slot 100 was already signed — refused.
        try testing.expect(!(try db.checkAndInsertBlock(pubkey, 100)));
        // Block at slot 101 — allowed.
        try testing.expect(try db.checkAndInsertBlock(pubkey, 101));

        // Attestation with target 20 — refused (double vote).
        try testing.expect(!(try db.checkAndInsertAttestation(pubkey, 10, 20)));
        // Next valid attestation.
        try testing.expect(try db.checkAndInsertAttestation(pubkey, 10, 21));
    }
}
