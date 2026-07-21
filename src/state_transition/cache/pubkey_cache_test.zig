const std = @import("std");
const bls = @import("bls");
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;
const cache_module = @import("pubkey_cache.zig");
const PubkeyCache = cache_module.PubkeyCache;
const testing = std.testing;
const interop = @import("../test_utils/interop_pubkeys.zig");

fn validatorsForPubkeys(
    pubkeys: []const types.primitive.BLSPubkey.Type,
    validators: []Validator,
    validator_ptrs: []*const Validator,
) void {
    std.debug.assert(pubkeys.len == validators.len);
    std.debug.assert(pubkeys.len == validator_ptrs.len);
    for (pubkeys, validators, validator_ptrs) |pubkey, *validator, *validator_ptr| {
        validator.* = std.mem.zeroes(Validator);
        validator.pubkey = pubkey;
        validator_ptr.* = validator;
    }
}

test "syncPubkeys populates both lookup directions and grows from empty" {
    const count = 4;
    var pubkeys: [count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(count, &pubkeys);

    var validators: [count]Validator = undefined;
    var validator_ptrs: [count]*const Validator = undefined;
    validatorsForPubkeys(&pubkeys, &validators, &validator_ptrs);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    try testing.expectEqual(@as(usize, 0), cache.capacity(testing.io));

    try cache.syncPubkeys(testing.io, &validator_ptrs);

    try testing.expectEqual(@as(u32, count), cache.count(testing.io));
    try testing.expect(cache.capacity(testing.io) >= count);
    for (pubkeys, 0..) |pubkey, expected_index| {
        try testing.expectEqual(
            @as(u64, @intCast(expected_index)),
            cache.get(testing.io, pubkey).?,
        );
        const compressed = cache.getPubkey(testing.io, expected_index).?.compress();
        try testing.expectEqualSlices(u8, &pubkey, &compressed);
    }
}

test "syncPubkeys incrementally appends and may grow existing storage" {
    const initial_count = 2;
    const total_count = 16;
    var pubkeys: [total_count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(total_count, &pubkeys);

    var validators: [total_count]Validator = undefined;
    var validator_ptrs: [total_count]*const Validator = undefined;
    validatorsForPubkeys(&pubkeys, &validators, &validator_ptrs);

    var cache = try PubkeyCache.initCapacity(testing.allocator, testing.io, initial_count);
    defer cache.deinit();

    try cache.syncPubkeys(testing.io, validator_ptrs[0..initial_count]);
    const initial_capacity = cache.capacity(testing.io);
    try cache.syncPubkeys(testing.io, &validator_ptrs);

    try testing.expectEqual(@as(u32, total_count), cache.count(testing.io));
    try testing.expect(cache.capacity(testing.io) >= total_count);
    try testing.expect(cache.capacity(testing.io) > initial_capacity);
    for (pubkeys, 0..) |pubkey, expected_index| {
        try testing.expectEqual(
            @as(u64, @intCast(expected_index)),
            cache.get(testing.io, pubkey).?,
        );
    }
}

test "syncPubkeys accepts a historical validator slice" {
    var pubkeys: [4]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var validators: [4]Validator = undefined;
    var validator_ptrs: [4]*const Validator = undefined;
    validatorsForPubkeys(pubkeys[0..validators.len], &validators, &validator_ptrs);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    try cache.syncPubkeys(testing.io, &validator_ptrs);

    try cache.syncPubkeys(testing.io, validator_ptrs[0..2]);
    try testing.expectEqual(@as(u32, validators.len), cache.count(testing.io));
    try testing.expectEqual(@as(u64, 3), cache.get(testing.io, pubkeys[3]).?);
    const future_pubkey = cache.getPubkey(testing.io, 3).?.compress();
    try testing.expectEqualSlices(u8, &pubkeys[3], &future_pubkey);
}

test "syncPubkeys rejects a duplicate without publishing a partial suffix" {
    var pubkeys: [2]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var validators = [_]Validator{
        std.mem.zeroes(Validator),
        std.mem.zeroes(Validator),
        std.mem.zeroes(Validator),
    };
    validators[0].pubkey = pubkeys[0];
    validators[1].pubkey = pubkeys[1];
    validators[2].pubkey = pubkeys[1];
    const validator_ptrs = [_]*const Validator{
        &validators[0],
        &validators[1],
        &validators[2],
    };

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    try cache.append(testing.io, pubkeys[0], 0);

    try testing.expectError(
        error.DuplicatePubkey,
        cache.syncPubkeys(testing.io, &validator_ptrs),
    );
    try testing.expectEqual(@as(u32, 1), cache.count(testing.io));
    try testing.expectEqual(@as(?u64, null), cache.get(testing.io, pubkeys[1]));
}

test "syncPubkeys rejects a suffix key already present in the prefix" {
    var pubkeys: [1]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var validators = [_]Validator{
        std.mem.zeroes(Validator),
        std.mem.zeroes(Validator),
    };
    validators[0].pubkey = pubkeys[0];
    validators[1].pubkey = pubkeys[0];
    const validator_ptrs = [_]*const Validator{
        &validators[0],
        &validators[1],
    };

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    try cache.append(testing.io, pubkeys[0], 0);

    try testing.expectError(
        error.DuplicatePubkey,
        cache.syncPubkeys(testing.io, &validator_ptrs),
    );
    try testing.expectEqual(@as(u32, 1), cache.count(testing.io));
}

test "syncPubkeys rejects an invalid suffix before changing the cache" {
    var pubkeys: [1]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var validators = [_]Validator{ std.mem.zeroes(Validator), std.mem.zeroes(Validator) };
    validators[0].pubkey = pubkeys[0];
    validators[1].pubkey = std.mem.zeroes([48]u8);
    const validator_ptrs = [_]*const Validator{ &validators[0], &validators[1] };

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    try cache.append(testing.io, pubkeys[0], 0);

    try testing.expectError(error.BadEncoding, cache.syncPubkeys(testing.io, &validator_ptrs));
    try testing.expectEqual(@as(u32, 1), cache.count(testing.io));
}

test "append is bidirectional, idempotent, and grows as needed" {
    var pubkeys: [3]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    for (pubkeys, 0..) |pubkey, index| {
        try cache.append(testing.io, pubkey, index);
    }
    try cache.append(testing.io, pubkeys[0], 0);

    for (pubkeys, 0..) |pubkey, expected_index| {
        try testing.expectEqual(
            @as(u64, @intCast(expected_index)),
            cache.get(testing.io, pubkey).?,
        );
        const compressed = cache.getPubkey(testing.io, expected_index).?.compress();
        try testing.expectEqualSlices(u8, &pubkey, &compressed);
    }
    try testing.expectError(
        error.InvalidIndexToAppend,
        cache.append(testing.io, pubkeys[0], pubkeys.len + 1),
    );
    try testing.expectError(
        error.DuplicatePubkey,
        cache.append(testing.io, pubkeys[0], pubkeys.len),
    );
    try testing.expectError(
        error.ConflictingPubkey,
        cache.append(testing.io, pubkeys[1], 0),
    );
    try testing.expectEqual(@as(u32, pubkeys.len), cache.count(testing.io));
}

test "append rejects invalid operations before attempting curve decoding" {
    var pubkeys: [1]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    try cache.append(testing.io, pubkeys[0], 0);

    const malformed = std.mem.zeroes([48]u8);
    try testing.expectError(
        error.ConflictingPubkey,
        cache.append(testing.io, malformed, 0),
    );
    try testing.expectError(
        error.InvalidIndexToAppend,
        cache.append(testing.io, malformed, 2),
    );
    try testing.expectError(error.BadEncoding, cache.append(testing.io, malformed, 1));
}

test "capacity guard rejects oversized reservations" {
    const unsupported = cache_module.max_capacity + 1;
    try testing.expectError(
        error.CapacityOverflow,
        PubkeyCache.initCapacity(testing.allocator, testing.io, unsupported),
    );

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    try testing.expectError(
        error.CapacityOverflow,
        cache.ensureTotalCapacity(testing.io, unsupported),
    );
}

test "ensureTotalCapacity grows a populated cache without changing entries" {
    var pubkeys: [2]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = try PubkeyCache.initCapacity(testing.allocator, testing.io, 1);
    defer cache.deinit();
    try cache.append(testing.io, pubkeys[0], 0);

    try cache.ensureTotalCapacity(testing.io, 128);
    try testing.expect(cache.capacity(testing.io) >= 128);
    try testing.expectEqual(@as(u32, 1), cache.count(testing.io));
    try testing.expectEqual(@as(u64, 0), cache.get(testing.io, pubkeys[0]).?);
    const compressed = cache.getPubkey(testing.io, 0).?.compress();
    try testing.expectEqualSlices(u8, &pubkeys[0], &compressed);

    try cache.append(testing.io, pubkeys[1], 1);
    try testing.expectEqual(@as(u64, 1), cache.get(testing.io, pubkeys[1]).?);
}

test "clear removes entries but retains capacity" {
    var pubkeys: [2]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = try PubkeyCache.initCapacity(testing.allocator, testing.io, 32);
    defer cache.deinit();
    try cache.append(testing.io, pubkeys[0], 0);
    const capacity_before = cache.capacity(testing.io);

    try cache.clear(testing.io);

    try testing.expectEqual(@as(u32, 0), cache.count(testing.io));
    try testing.expectEqual(capacity_before, cache.capacity(testing.io));
    try testing.expectEqual(@as(?u64, null), cache.get(testing.io, pubkeys[0]));
    try cache.append(testing.io, pubkeys[1], 0);
    try testing.expectEqual(@as(u64, 0), cache.get(testing.io, pubkeys[1]).?);
}

test "aggregate holds one shared snapshot and validates indices" {
    var pubkeys: [3]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    for (pubkeys, 0..) |pubkey, index| try cache.append(testing.io, pubkey, index);

    const aggregate = try cache.aggregate(testing.io, &.{ 0, 1, 2 });
    _ = aggregate;
    try testing.expectError(error.InvalidLength, cache.aggregate(testing.io, &.{}));
    try testing.expectError(error.InvalidIndex, cache.aggregate(testing.io, &.{3}));
}

test "batch forward lookup copies under one validated shared snapshot" {
    var pubkeys: [3]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    for (pubkeys, 0..) |pubkey, index| try cache.append(testing.io, pubkey, index);

    const indices = [_]u64{ 2, 0, 2 };
    var affine_pubkeys: [indices.len]bls.PublicKey = undefined;
    try cache.getPubkeys(testing.io, &indices, &affine_pubkeys);
    for (affine_pubkeys, indices) |affine, index| {
        const compressed = affine.compress();
        try testing.expectEqualSlices(u8, &pubkeys[index], &compressed);
    }

    try testing.expectError(
        error.InvalidLength,
        cache.getPubkeys(testing.io, &indices, affine_pubkeys[0..2]),
    );
    try testing.expectError(
        error.InvalidIndex,
        cache.getPubkeys(testing.io, &.{ 0, 3, 1 }, &affine_pubkeys),
    );
}

test "batch reverse lookup resolves under one shared snapshot" {
    var pubkeys: [4]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    for (pubkeys[0..3], 0..) |pubkey, index| {
        try cache.append(testing.io, pubkey, index);
    }

    const lookup = [_][48]u8{ pubkeys[2], pubkeys[0], pubkeys[2] };
    var indices: [lookup.len]u64 = undefined;
    try cache.getValidatorIndices(testing.io, &lookup, &indices);
    try testing.expectEqualSlices(u64, &.{ 2, 0, 2 }, &indices);

    try testing.expectError(
        error.InvalidLength,
        cache.getValidatorIndices(testing.io, &lookup, indices[0..2]),
    );
    try testing.expectError(
        error.PubkeyNotFound,
        cache.getValidatorIndices(
            testing.io,
            &.{ pubkeys[0], pubkeys[3], pubkeys[1] },
            &indices,
        ),
    );
}

const ConcurrentReaderContext = struct {
    cache: *const PubkeyCache,
    io: std.Io,
    pubkeys: []const types.primitive.BLSPubkey.Type,
    stop: *std.atomic.Value(bool),
    failed: *std.atomic.Value(bool),
};

fn readWhileAppending(context: *const ConcurrentReaderContext) void {
    while (!context.stop.load(.acquire)) {
        const visible = context.cache.count(context.io);
        for (context.pubkeys[0..visible], 0..) |pubkey, expected_index| {
            if (context.cache.get(context.io, pubkey) != expected_index) {
                context.failed.store(true, .release);
                return;
            }
            const affine = context.cache.getPubkey(context.io, expected_index) orelse {
                context.failed.store(true, .release);
                return;
            };
            const compressed = affine.compress();
            if (!std.mem.eql(u8, &compressed, &pubkey)) {
                context.failed.store(true, .release);
                return;
            }
        }
    }
}

test "shared readers remain consistent while appends repeatedly resize" {
    const pubkey_count = 128;
    var pubkeys: [pubkey_count]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();

    var stop = std.atomic.Value(bool).init(false);
    var failed = std.atomic.Value(bool).init(false);
    const context = ConcurrentReaderContext{
        .cache = &cache,
        .io = testing.io,
        .pubkeys = &pubkeys,
        .stop = &stop,
        .failed = &failed,
    };

    var group: std.Io.Group = .init;
    errdefer {
        stop.store(true, .release);
        group.cancel(testing.io);
    }
    for (0..4) |_| try group.concurrent(testing.io, readWhileAppending, .{&context});

    for (pubkeys, 0..) |pubkey, index| try cache.append(testing.io, pubkey, index);
    stop.store(true, .release);
    try group.await(testing.io);

    try testing.expect(!failed.load(.acquire));
    try testing.expectEqual(@as(u32, pubkey_count), cache.count(testing.io));
}

const ConcurrentWriterContext = struct {
    cache: *PubkeyCache,
    io: std.Io,
    pubkey: types.primitive.BLSPubkey.Type,
    result: *std.atomic.Value(u8),
};

fn appendConcurrently(context: *const ConcurrentWriterContext) void {
    context.cache.append(context.io, context.pubkey, 0) catch |err| {
        context.result.store(if (err == error.ConflictingPubkey) 2 else 3, .release);
        return;
    };
    context.result.store(1, .release);
}

test "writer mutex serializes competing writers" {
    var pubkeys: [2]types.primitive.BLSPubkey.Type = undefined;
    try interop.interopPubkeysCached(pubkeys.len, &pubkeys);

    var cache = PubkeyCache.init(testing.allocator, testing.io);
    defer cache.deinit();
    var first_result = std.atomic.Value(u8).init(0);
    var second_result = std.atomic.Value(u8).init(0);
    const first = ConcurrentWriterContext{
        .cache = &cache,
        .io = testing.io,
        .pubkey = pubkeys[0],
        .result = &first_result,
    };
    const second = ConcurrentWriterContext{
        .cache = &cache,
        .io = testing.io,
        .pubkey = pubkeys[1],
        .result = &second_result,
    };

    var group: std.Io.Group = .init;
    errdefer group.cancel(testing.io);
    try group.concurrent(testing.io, appendConcurrently, .{&first});
    try group.concurrent(testing.io, appendConcurrently, .{&second});
    try group.await(testing.io);

    const first_value = first_result.load(.acquire);
    const second_value = second_result.load(.acquire);
    try testing.expect(
        (first_value == 1 and second_value == 2) or
            (first_value == 2 and second_value == 1),
    );
    try testing.expectEqual(@as(u32, 1), cache.count(testing.io));
}
