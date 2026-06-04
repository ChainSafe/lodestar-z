const bls = @import("bls");

const PublicKey = bls.PublicKey;
const AggregatePublicKey = bls.AggregatePublicKey;
const blstError = bls.BlstError;
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
    const pk_size = PublicKey.COMPRESS_SIZE;
    if (input.len < pk_size or input.len > pk_size * MAX_AGGREGATE_PER_JOB) return;

    const n = @min(input.len / pk_size, MAX_AGGREGATE_PER_JOB);
    if (n == 0) return;

    var pks: [MAX_AGGREGATE_PER_JOB]PublicKey = undefined;
    var count: usize = 0;

    for (0..n) |i| {
        const chunk = input[i * pk_size .. (i + 1) * pk_size];
        const pk = PublicKey.deserialize(chunk) catch continue;
        pks[count] = pk;
        count += 1;
    }

    if (count == 0) return;

    _ = AggregatePublicKey.aggregate(pks[0..count], false) catch |err| {
        if (err != blstError.AggrTypeMismatch) {
            @panic("unexpected aggregate public key error");
        }
    };
}

fn fuzzAggregateWithRandomness(input: []const u8) void {
    const pk_size = PublicKey.COMPRESS_SIZE;
    const rand_size = 32;
    const item_size = pk_size + rand_size;
    if (input.len < item_size) return;

    const n = @min(input.len / item_size, MAX_AGGREGATE_PER_JOB);
    if (n == 0) return;

    var pks: [MAX_AGGREGATE_PER_JOB]PublicKey = undefined;
    var pks_refs: [MAX_AGGREGATE_PER_JOB]*const PublicKey = undefined;
    var randomness: [MAX_AGGREGATE_PER_JOB * rand_size]u8 = undefined;
    var count: usize = 0;

    for (0..n) |i| {
        const off = i * item_size;
        const pk_chunk = input[off .. off + pk_size];
        const rand_chunk = input[off + pk_size .. off + item_size];

        const pk = PublicKey.deserialize(pk_chunk) catch continue;
        pks[count] = pk;
        pks_refs[count] = &pks[count];
        @memcpy(randomness[count * rand_size .. (count + 1) * rand_size], rand_chunk);
        count += 1;
    }

    if (count == 0) return;

    var scratch: [1 << 14]u64 = undefined;

    _ = AggregatePublicKey.aggregateWithRandomness(
        pks_refs[0..count],
        randomness[0 .. count * rand_size],
        false,
        &scratch,
    ) catch |err| {
        if (err != blstError.AggrTypeMismatch) {
            @panic("unexpected aggregateWithRandomness public key error");
        }
    };
}
