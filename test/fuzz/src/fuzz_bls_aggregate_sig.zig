const bls = @import("bls");

const Signature = bls.Signature;
const AggregateSignature = bls.AggregateSignature;
const BlstError = bls.BlstError;
const MAX_AGGREGATE_PER_JOB = bls.MAX_AGGREGATE_PER_JOB;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    const input = buf[0..len];
    fuzzAggregate(input);
    fuzzAggregateWithRandomness(input);
}

fn fuzzAggregate(input: []const u8) void {
    const sig_size = Signature.COMPRESS_SIZE;
    const n = @min(input.len / sig_size, MAX_AGGREGATE_PER_JOB);
    if (n == 0) return;

    var sigs: [MAX_AGGREGATE_PER_JOB]Signature = undefined;
    var count: usize = 0;

    for (0..n) |i| {
        const chunk = input[i * sig_size .. (i + 1) * sig_size];
        const sig = Signature.deserialize(chunk) catch continue;
        sigs[count] = sig;
        count += 1;
    }

    if (count == 0) return;

    _ = AggregateSignature.aggregate(sigs[0..count], false) catch |err| {
        if (err != BlstError.AggrTypeMismatch) {
            @panic("unexpected aggregate signature error");
        }
    };
}

fn fuzzAggregateWithRandomness(input: []const u8) void {
    const sig_size = Signature.COMPRESS_SIZE;
    const rand_size = 32;
    const item_size = sig_size + rand_size;
    if (input.len < item_size) return;

    const n = @min(input.len / item_size, MAX_AGGREGATE_PER_JOB);
    if (n == 0) return;

    var sigs: [MAX_AGGREGATE_PER_JOB]Signature = undefined;
    var sig_refs: [MAX_AGGREGATE_PER_JOB]*const Signature = undefined;
    var randomness: [MAX_AGGREGATE_PER_JOB * rand_size]u8 = undefined;
    var count: usize = 0;

    for (0..n) |i| {
        const off = i * item_size;
        const sig_chunk = input[off .. off + sig_size];
        const rand_chunk = input[off + sig_size .. off + item_size];

        const sig = Signature.deserialize(sig_chunk) catch continue;
        sigs[count] = sig;
        sig_refs[count] = &sigs[count];
        @memcpy(randomness[count * rand_size .. (count + 1) * rand_size], rand_chunk);
        count += 1;
    }

    if (count == 0) return;

    var scratch: [1 << 16]u64 = undefined;

    _ = AggregateSignature.aggregateWithRandomness(
        sig_refs[0..count],
        randomness[0 .. count * rand_size],
        false,
        &scratch,
    ) catch |err| {
        if (err != BlstError.AggrTypeMismatch) {
            @panic("unexpected aggregateWithRandomness signature error");
        }
    };
}
