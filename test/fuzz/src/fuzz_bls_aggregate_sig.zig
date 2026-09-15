const std = @import("std");
const assert = std.debug.assert;
const bls = @import("bls");
const fuzz_options = @import("fuzz_options");
const oracle = @import("bls_oracle.zig");

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
    if (len <= oracle.generated_input_len_max) fuzzGenerated(buf[0..len]);
    fuzzAggregate(buf[0..len]);
}

fn fuzzGenerated(input: []const u8) void {
    var message: bls.SigningRoot = @splat(0);
    @memcpy(message[0..input.len], input);
    const count = 1 + @as(usize, message[16] % oracle.generated_key_count_max);
    var signatures: [oracle.generated_key_count_max]Signature = undefined;
    var scalar_sum: u64 = 0;
    for (signatures[0..count], 0..) |*signature, index| {
        const offset = index * 4;
        const scalar = @as(u64, std.mem.readInt(u32, message[offset..][0..4], .little)) + 1;
        scalar_sum += scalar;
        const secret_key = oracle.secretKey(scalar);
        signature.* = secret_key.sign(&message, bls.DST, null);
    }
    const secret_key_sum = oracle.secretKey(scalar_sum);
    const expected = secret_key_sum.sign(&message, bls.DST, null);
    const aggregate = AggregateSignature.aggregate(signatures[0..count], false) catch
        @panic("generated signature aggregation failed");
    const actual = aggregate.toSignature();
    assert(expected.isEqual(&actual));
    const validated = AggregateSignature.aggregate(signatures[0..count], true) catch
        @panic("generated validated signature aggregation failed");
    const validated_signature = validated.toSignature();
    assert(expected.isEqual(&validated_signature));
    const public_key_sum = secret_key_sum.toPublicKey();
    actual.verify(true, &message, bls.DST, null, &public_key_sum, true) catch
        @panic("generated aggregate signature failed verification");
    message[0] ^= 1;
    if (actual.verify(true, &message, bls.DST, null, &public_key_sum, true)) {
        @panic("aggregate signature accepted a changed message");
    } else |err| {
        assert(err == BlstError.VerifyFail);
    }
}

fn fuzzAggregate(input: []const u8) void {
    const signature_size = Signature.COMPRESS_SIZE;
    if (input.len < signature_size) return;

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
        const compressed = signature.compress();
        assert(std.mem.eql(u8, chunk, &compressed));
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

test "signature aggregate oracle covers scalar sums and raw records" {
    for (1..oracle.generated_key_count_max + 1) |count| {
        var message: bls.SigningRoot = @splat(255);
        message[16] = @intCast(count - 1);
        zig_fuzz_test(&message, message.len);
        var encoded: [oracle.generated_key_count_max * Signature.COMPRESS_SIZE]u8 = undefined;
        for (0..count) |index| {
            const secret_key = oracle.secretKey(index + 1);
            const signature = secret_key.sign(&message, bls.DST, null);
            const offset = index * Signature.COMPRESS_SIZE;
            @memcpy(encoded[offset..][0..Signature.COMPRESS_SIZE], &signature.compress());
        }
        zig_fuzz_test(&encoded, count * Signature.COMPRESS_SIZE);
    }
}
