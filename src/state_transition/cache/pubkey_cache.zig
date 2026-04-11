const std = @import("std");
const bls = @import("bls");
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;

const max_parallel_workers: usize = 8;
const min_parallel_batch_size: usize = 2048;

/// Map from pubkey to validator index
pub const PubkeyIndexMap = std.AutoHashMap([48]u8, u64);

/// Map from validator index to pubkey
pub const Index2PubkeyCache = std.array_list.AlignedManaged(bls.PublicKey, null);

/// Populate `pubkey_to_index` and `index_to_pubkey` caches from validators list.
pub fn syncPubkeys(
    validators: []const Validator,
    pubkey_to_index: *PubkeyIndexMap,
    index_to_pubkey: *Index2PubkeyCache,
) !void {
    const old_len = index_to_pubkey.items.len;
    if (pubkey_to_index.count() != old_len) {
        return error.InconsistentCache;
    }

    const new_count = validators.len;
    if (new_count <= old_len) {
        return;
    }

    try index_to_pubkey.resize(new_count);
    try pubkey_to_index.ensureTotalCapacity(@intCast(new_count));

    for (old_len..new_count) |i| {
        const pubkey = &validators[i].pubkey;
        pubkey_to_index.putAssumeCapacity(pubkey.*, @intCast(i));
        index_to_pubkey.items[i] = try bls.PublicKey.uncompress(pubkey);
    }
}

fn uncompressPubkeys(
    start_index: usize,
    end_index_exclusive: usize,
    validators: []const Validator,
    index_to_pubkey: *Index2PubkeyCache,
    uncompress_error: *std.atomic.Value(bool),
) void {
    std.debug.assert(start_index <= end_index_exclusive);
    std.debug.assert(end_index_exclusive <= validators.len);
    std.debug.assert(end_index_exclusive <= index_to_pubkey.items.len);

    for (start_index..end_index_exclusive) |i| {
        if (uncompress_error.load(.monotonic)) return;
        const pubkey = &validators[i].pubkey;
        index_to_pubkey.items[i] = bls.PublicKey.uncompress(pubkey) catch {
            uncompress_error.store(true, .release);
            return;
        };
    }
}

const UncompressTask = struct {
    start_index: usize,
    end_index_exclusive: usize,
    validators: []const Validator,
    index_to_pubkey_items: []bls.PublicKey,
    uncompress_error: *std.atomic.Value(bool),
};

fn uncompressPubkeysTask(task: UncompressTask) void {
    std.debug.assert(task.end_index_exclusive <= task.index_to_pubkey_items.len);
    for (task.start_index..task.end_index_exclusive) |i| {
        if (task.uncompress_error.load(.monotonic)) return;
        const pubkey = &task.validators[i].pubkey;
        task.index_to_pubkey_items[i] = bls.PublicKey.uncompress(pubkey) catch {
            task.uncompress_error.store(true, .release);
            return;
        };
    }
}

/// Populate `pubkey_to_index` and `index_to_pubkey` caches from validators list.
/// Spawns a temporary thread pool to parallelize the work.
pub fn syncPubkeysParallel(
    allocator: std.mem.Allocator,
    validators: []const Validator,
    pubkey_to_index: *PubkeyIndexMap,
    index_to_pubkey: *Index2PubkeyCache,
) !void {
    _ = allocator;
    const old_len = index_to_pubkey.items.len;
    if (pubkey_to_index.count() != old_len) {
        return error.InconsistentCache;
    }

    const new_count = validators.len;
    if (new_count <= old_len) {
        return;
    }

    try index_to_pubkey.resize(new_count);
    errdefer index_to_pubkey.shrinkRetainingCapacity(old_len);

    try pubkey_to_index.ensureTotalCapacity(@intCast(new_count));

    var uncompress_error = std.atomic.Value(bool).init(false);
    const new_items = new_count - old_len;
    const cpu_count = std.Thread.getCpuCount() catch 4;
    const worker_count = @max(
        @min(@min(new_items, cpu_count), max_parallel_workers),
        1,
    );

    if (worker_count == 1 or new_items < min_parallel_batch_size) {
        uncompressPubkeys(
            old_len,
            new_count,
            validators,
            index_to_pubkey,
            &uncompress_error,
        );
    } else {
        var tasks: [max_parallel_workers]UncompressTask = undefined;
        var threads: [max_parallel_workers - 1]std.Thread = undefined;
        const batch_size = new_items / worker_count;
        const remainder = new_items % worker_count;

        var task_start = old_len;
        for (0..worker_count) |worker_index| {
            const extra: usize = if (worker_index < remainder) 1 else 0;
            const task_end = task_start + batch_size + extra;
            tasks[worker_index] = .{
                .start_index = task_start,
                .end_index_exclusive = task_end,
                .validators = validators,
                .index_to_pubkey_items = index_to_pubkey.items,
                .uncompress_error = &uncompress_error,
            };
            task_start = task_end;
        }

        var started_threads: usize = 0;
        var next_inline_task: usize = worker_count - 1;
        for (0..worker_count - 1) |worker_index| {
            threads[started_threads] = std.Thread.spawn(.{}, uncompressPubkeysTask, .{tasks[worker_index]}) catch {
                next_inline_task = worker_index;
                break;
            };
            started_threads += 1;
        }

        for (next_inline_task..worker_count) |worker_index| {
            uncompressPubkeysTask(tasks[worker_index]);
        }

        for (threads[0..started_threads]) |*thread| {
            thread.join();
        }
    }

    if (uncompress_error.load(.acquire)) {
        return error.InvalidPubkey;
    }

    // Update the shared map in single thread
    for (old_len..new_count) |j| {
        pubkey_to_index.putAssumeCapacity(validators[j].pubkey, @intCast(j));
    }
}

const testing = std.testing;
const interop = @import("../test_utils/interop_pubkeys.zig");

test "syncPubkeys populates both caches" {
    const allocator = testing.allocator;
    const count = 4;

    var pubkeys: [count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(count, &pubkeys);

    var validators: [count]Validator = undefined;
    for (0..count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey = Index2PubkeyCache.init(allocator);
    defer index_to_pubkey.deinit();

    try syncPubkeys(&validators, &pubkey_to_index, &index_to_pubkey);

    try testing.expectEqual(@as(usize, count), index_to_pubkey.items.len);
    try testing.expectEqual(@as(u32, count), pubkey_to_index.count());

    // Verify each pubkey maps to the correct index
    for (0..count) |i| {
        const idx = pubkey_to_index.get(pubkeys[i]).?;
        try testing.expectEqual(@as(u64, i), idx);
    }
}

test "syncPubkeys incremental sync adds only new validators" {
    const allocator = testing.allocator;
    const initial_count = 2;
    const total_count = 4;

    var pubkeys: [total_count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(total_count, &pubkeys);

    var validators: [total_count]Validator = undefined;
    for (0..total_count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey = Index2PubkeyCache.init(allocator);
    defer index_to_pubkey.deinit();

    // Initial sync with first 2 validators
    try syncPubkeys(validators[0..initial_count], &pubkey_to_index, &index_to_pubkey);
    try testing.expectEqual(@as(usize, initial_count), index_to_pubkey.items.len);

    // Incremental sync with all 4 validators
    try syncPubkeys(&validators, &pubkey_to_index, &index_to_pubkey);
    try testing.expectEqual(@as(usize, total_count), index_to_pubkey.items.len);
    try testing.expectEqual(@as(u32, total_count), pubkey_to_index.count());

    // Verify all pubkeys are correctly mapped
    for (0..total_count) |i| {
        const idx = pubkey_to_index.get(pubkeys[i]).?;
        try testing.expectEqual(@as(u64, i), idx);
    }
}

test "syncPubkeys no-op when already synced" {
    const allocator = testing.allocator;
    const count = 2;

    var pubkeys: [count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(count, &pubkeys);

    var validators: [count]Validator = undefined;
    for (0..count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey = Index2PubkeyCache.init(allocator);
    defer index_to_pubkey.deinit();

    try syncPubkeys(&validators, &pubkey_to_index, &index_to_pubkey);
    // Second call should be no-op
    try syncPubkeys(&validators, &pubkey_to_index, &index_to_pubkey);
    try testing.expectEqual(@as(usize, count), index_to_pubkey.items.len);
}

test "syncPubkeys keeps append-only cache on historical validator set" {
    const allocator = testing.allocator;
    const larger_count = 4;
    const smaller_count = 2;

    var pubkeys: [larger_count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(larger_count, &pubkeys);

    var validators: [larger_count]Validator = undefined;
    for (0..larger_count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey = Index2PubkeyCache.init(allocator);
    defer index_to_pubkey.deinit();

    try syncPubkeys(&validators, &pubkey_to_index, &index_to_pubkey);
    try syncPubkeys(validators[0..smaller_count], &pubkey_to_index, &index_to_pubkey);

    try testing.expectEqual(@as(usize, larger_count), index_to_pubkey.items.len);
    try testing.expectEqual(@as(u32, larger_count), pubkey_to_index.count());
}

test "syncPubkeys detects inconsistent cache" {
    const allocator = testing.allocator;

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey = Index2PubkeyCache.init(allocator);
    defer index_to_pubkey.deinit();

    // Manually desync: add to pubkey_to_index but not index_to_pubkey
    const dummy_key = [_]u8{0} ** 48;
    try pubkey_to_index.put(dummy_key, 0);

    var validators: [1]Validator = undefined;
    validators[0] = std.mem.zeroes(Validator);

    try testing.expectError(error.InconsistentCache, syncPubkeys(&validators, &pubkey_to_index, &index_to_pubkey));
}

test "syncPubkeysParallel populates both caches" {
    const allocator = testing.allocator;
    const count = 8;

    var pubkeys: [count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(count, &pubkeys);

    var validators: [count]Validator = undefined;
    for (0..count) |i| {
        validators[i] = std.mem.zeroes(Validator);
        validators[i].pubkey = pubkeys[i];
    }

    var pubkey_to_index = PubkeyIndexMap.init(allocator);
    defer pubkey_to_index.deinit();
    var index_to_pubkey = Index2PubkeyCache.init(allocator);
    defer index_to_pubkey.deinit();

    try syncPubkeysParallel(allocator, &validators, &pubkey_to_index, &index_to_pubkey);

    try testing.expectEqual(@as(usize, count), index_to_pubkey.items.len);
    try testing.expectEqual(@as(u32, count), pubkey_to_index.count());

    for (0..count) |i| {
        const idx = pubkey_to_index.get(pubkeys[i]).?;
        try testing.expectEqual(@as(u64, i), idx);
    }
}
