const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");
const fuzz_options = @import("fuzz_options");

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
    fuzzAggregate(buf[0..len]);
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
