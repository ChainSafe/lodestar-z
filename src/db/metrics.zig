const std = @import("std");
const DatabaseId = @import("buckets.zig").DatabaseId;

pub const Operation = enum(u8) {
    get,
    put,
    delete,
    write_batch,
    all_keys,
    all_entries,
    first_key,
    last_key,
};

pub const metric_operations = [_]Operation{
    .get,
    .put,
    .delete,
    .write_batch,
    .all_keys,
    .all_entries,
    .first_key,
    .last_key,
};

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
    operation_counts: [metric_operations.len]u64 = [_]u64{0} ** metric_operations.len,
    operation_time_ns: [metric_operations.len]u64 = [_]u64{0} ** metric_operations.len,

    pub fn entryCount(self: *const MetricsSnapshot, db_id: DatabaseId) u64 {
        return self.entry_counts[@intFromEnum(db_id)];
    }

    pub fn operationCount(self: *const MetricsSnapshot, operation: Operation) u64 {
        return self.operation_counts[@intFromEnum(operation)];
    }

    pub fn operationTimeNs(self: *const MetricsSnapshot, operation: Operation) u64 {
        return self.operation_time_ns[@intFromEnum(operation)];
    }
};
