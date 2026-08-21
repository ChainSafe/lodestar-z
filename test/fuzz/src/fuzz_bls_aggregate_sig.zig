const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");
const fuzz_options = @import("fuzz_options");

const Signature = bls.Signature;
const AggregateSignature = bls.AggregateSignature;
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
    const signature_size = Signature.COMPRESS_SIZE;
    if (input.len < signature_size) return;
    if (input.len % signature_size != 0) return;

    const record_count = input.len / signature_size;
    if (record_count > MAX_AGGREGATE_PER_JOB) return;

    var signatures: [MAX_AGGREGATE_PER_JOB]Signature = undefined;
    var signature_count: usize = 0;
    for (0..record_count) |record_index| {
        const offset = record_index * signature_size;
        const chunk = input[offset .. offset + signature_size];
        const signature = Signature.deserialize(chunk) catch |err| switch (err) {
            BlstError.BadEncoding,
            BlstError.PointNotOnCurve,
            BlstError.PointNotInGroup,
            BlstError.PkIsInfinity,
            => continue,
            else => @panic("unexpected signature deserialize error"),
        };
        signatures[signature_count] = signature;
        signature_count += 1;
    }
    if (signature_count == 0) return;

    const aggregate = AggregateSignature.aggregate(
        signatures[0..signature_count],
        false,
    ) catch @panic("nonempty signature aggregation failed");
    const aggregate_signature = aggregate.toSignature();
    const aggregate_bytes = aggregate_signature.serialize();

    var reversed: [MAX_AGGREGATE_PER_JOB]Signature = undefined;
    for (0..signature_count) |index| {
        reversed[index] = signatures[signature_count - 1 - index];
    }
    const reversed_aggregate = AggregateSignature.aggregate(
        reversed[0..signature_count],
        false,
    ) catch @panic("reversed signature aggregation failed");
    const reversed_signature = reversed_aggregate.toSignature();
    const reversed_bytes = reversed_signature.serialize();
    assert(std.mem.eql(u8, &aggregate_bytes, &reversed_bytes));

    const validated = AggregateSignature.aggregate(
        signatures[0..signature_count],
        true,
    ) catch |err| switch (err) {
        BlstError.PointNotInGroup => return,
        else => @panic("unexpected validated signature aggregation error"),
    };
    const validated_signature = validated.toSignature();
    const validated_bytes = validated_signature.serialize();
    assert(std.mem.eql(u8, &aggregate_bytes, &validated_bytes));
}
