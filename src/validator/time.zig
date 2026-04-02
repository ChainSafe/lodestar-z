const std = @import("std");
const Io = std.Io;

pub fn realNanoseconds(io: Io) u64 {
    return timestampNanoseconds(Io.Clock.real.now(io));
}

pub fn realMilliseconds(io: Io) u64 {
    return realNanoseconds(io) / std.time.ns_per_ms;
}

pub fn realSeconds(io: Io) u64 {
    return realNanoseconds(io) / std.time.ns_per_s;
}

pub fn awakeNanoseconds(io: Io) u64 {
    return timestampNanoseconds(Io.Clock.awake.now(io));
}

fn timestampNanoseconds(ts: Io.Timestamp) u64 {
    if (ts.nanoseconds <= 0) return 0;
    return std.math.cast(u64, ts.nanoseconds) orelse std.math.maxInt(u64);
}
