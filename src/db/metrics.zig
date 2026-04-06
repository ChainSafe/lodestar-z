const DatabaseId = @import("buckets.zig").DatabaseId;

pub const MetricsSnapshot = struct {
    total_entries: u64 = 0,
    entry_counts: [DatabaseId.count]u64 = [_]u64{0} ** DatabaseId.count,
    lmdb_map_size_bytes: u64 = 0,
    lmdb_data_size_bytes: u64 = 0,
    lmdb_page_size_bytes: u64 = 0,
    lmdb_last_page_number: u64 = 0,
    lmdb_last_txnid: u64 = 0,
    lmdb_readers_used: u64 = 0,
    lmdb_readers_max: u64 = 0,

    pub fn entryCount(self: *const MetricsSnapshot, db_id: DatabaseId) u64 {
        return self.entry_counts[@intFromEnum(db_id)];
    }
};
