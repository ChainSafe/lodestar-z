const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");
const fuzz_options = @import("fuzz_options");
const oracle = @import("bls_oracle.zig");

const PublicKey = bls.PublicKey;
const AggregatePublicKey = bls.AggregatePublicKey;
const BlstError = bls.BlstError;
const MAX_AGGREGATE_PER_JOB = bls.MAX_AGGREGATE_PER_JOB;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len > fuzz_options.max_input_len) return;
    if (len <= oracle.generated_input_len_max) fuzzGenerated(buf[0..len]);
    fuzzAggregate(buf[0..len]);
}

fn fuzzGenerated(input: []const u8) void {
    var seed: [oracle.generated_input_len_max]u8 = @splat(0);
    @memcpy(seed[0..input.len], input);
    const count = 1 + @as(usize, seed[16] % oracle.generated_key_count_max);
    var public_keys: [oracle.generated_key_count_max]PublicKey = undefined;
    var scalar_sum: u64 = 0;
    for (public_keys[0..count], 0..) |*public_key, index| {
        const offset = index * 4;
        const scalar = @as(u64, std.mem.readInt(u32, seed[offset..][0..4], .little)) + 1;
        scalar_sum += scalar;
        const secret_key = oracle.secretKey(scalar);
        public_key.* = secret_key.toPublicKey();
    }
    const secret_key_sum = oracle.secretKey(scalar_sum);
    const expected = secret_key_sum.toPublicKey();
    for ([_]bool{ false, true }) |validate| {
        const aggregate = AggregatePublicKey.aggregate(public_keys[0..count], validate) catch
            @panic("generated public key aggregation failed");
        const actual = aggregate.toPublicKey();
        assert(expected.isEqual(&actual));
    }
    var incremental = public_keys[0].toAggregate();
    for (public_keys[1..count]) |*public_key| incremental.add(public_key);
    const actual = incremental.toPublicKey();
    assert(expected.isEqual(&actual));
}

fn fuzzAggregate(input: []const u8) void {
    const public_key_size = PublicKey.COMPRESS_SIZE;
    if (input.len < public_key_size) return;

    const record_count = input.len / public_key_size;
    if (record_count > MAX_AGGREGATE_PER_JOB) return;

    var public_keys: [MAX_AGGREGATE_PER_JOB]PublicKey = undefined;
    var public_key_count: usize = 0;
    for (0..record_count) |record_index| {
        const offset = record_index * public_key_size;
        const chunk = input[offset .. offset + public_key_size];
        const public_key = PublicKey.deserialize(chunk) catch |err| switch (err) {
            BlstError.BadEncoding,
            BlstError.PointNotOnCurve,
            BlstError.PointNotInGroup,
            BlstError.PkIsInfinity,
            => continue,
            else => @panic("unexpected public key deserialize error"),
        };
        const compressed = public_key.compress();
        assert(std.mem.eql(u8, chunk, &compressed));
        public_keys[public_key_count] = public_key;
        public_key_count += 1;
    }
    if (public_key_count == 0) return;

    const aggregate = AggregatePublicKey.aggregate(
        public_keys[0..public_key_count],
        false,
    ) catch @panic("nonempty public key aggregation failed");
    const aggregate_public_key = aggregate.toPublicKey();
    const aggregate_bytes = aggregate_public_key.serialize();

    var reversed: [MAX_AGGREGATE_PER_JOB]PublicKey = undefined;
    for (0..public_key_count) |index| {
        reversed[index] = public_keys[public_key_count - 1 - index];
    }
    const reversed_aggregate = AggregatePublicKey.aggregate(
        reversed[0..public_key_count],
        false,
    ) catch @panic("reversed public key aggregation failed");
    const reversed_public_key = reversed_aggregate.toPublicKey();
    const reversed_bytes = reversed_public_key.serialize();
    assert(std.mem.eql(u8, &aggregate_bytes, &reversed_bytes));

    var incremental = public_keys[0].toAggregate();
    for (public_keys[1..public_key_count]) |*public_key| incremental.add(public_key);
    const incremental_public_key = incremental.toPublicKey();
    const incremental_bytes = incremental_public_key.serialize();
    assert(std.mem.eql(u8, &aggregate_bytes, &incremental_bytes));

    const validated = AggregatePublicKey.aggregate(
        public_keys[0..public_key_count],
        true,
    ) catch |err| switch (err) {
        BlstError.PointNotInGroup, BlstError.PkIsInfinity => return,
        else => @panic("unexpected validated public key aggregation error"),
    };
    const validated_public_key = validated.toPublicKey();
    const validated_bytes = validated_public_key.serialize();
    assert(std.mem.eql(u8, &aggregate_bytes, &validated_bytes));
}

test "public key aggregate oracle covers scalar sums and raw records" {
    for (1..oracle.generated_key_count_max + 1) |count| {
        var input: [oracle.generated_input_len_max]u8 = @splat(255);
        input[16] = @intCast(count - 1);
        zig_fuzz_test(&input, input.len);
        var encoded: [oracle.generated_key_count_max * PublicKey.COMPRESS_SIZE]u8 = undefined;
        for (0..count) |index| {
            const secret_key = oracle.secretKey(index + 1);
            const public_key = secret_key.toPublicKey();
            const offset = index * PublicKey.COMPRESS_SIZE;
            @memcpy(encoded[offset..][0..PublicKey.COMPRESS_SIZE], &public_key.compress());
        }
        zig_fuzz_test(&encoded, count * PublicKey.COMPRESS_SIZE);
    }
}
