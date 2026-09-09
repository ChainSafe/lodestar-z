const std = @import("std");
const js = @import("zapi:zapi").js;
const Value = @import("zapi:zapi").napi.Value;
const logging = @import("network").logging;
const cfg = @import("network_config.zig");
const Runtime = @import("network_runtime.zig").Runtime;

pub fn drain(runtime: *Runtime, limit: Value) !js.Value {
    const max = cfg.integer(limit, logging.drain_max) catch return error.InvalidDrainLimit;
    if (max == 0) return error.InvalidDrainLimit;
    var records: [logging.drain_max]logging.Record = undefined;
    const batch = runtime.logs.peek(records[0..@intCast(max)]);
    const env = js.env();
    const array = try env.createArrayWithLength(batch.count);
    for (records[0..batch.count], 0..) |*record, i| {
        const value = try env.createObject();
        try value.setNamedProperty("level", try env.createStringUtf8(logging.levelName(record.level)));
        try value.setNamedProperty("scope", try env.createStringUtf8(@tagName(record.scope)));
        try value.setNamedProperty("message", try env.createStringUtf8(record.message[0..record.len]));
        try value.setNamedProperty("session", try env.createBigintUint64(runtime.diag.session));
        try value.setNamedProperty("sequence", try env.createBigintUint64(record.sequence));
        try value.setNamedProperty("timestampMs", try env.createBigintUint64(record.timestamp_ms));
        try value.setNamedProperty("monotonicMs", try env.createBigintUint64(record.monotonic_ms));
        try value.setNamedProperty("truncated", try env.getBoolean(record.truncated));
        var key: [11]u8 = undefined;
        try array.setNamedProperty(try std.fmt.bufPrintZ(&key, "{d}", .{i}), value);
    }
    const result = try env.createObject();
    try result.setNamedProperty("records", array);
    try result.setNamedProperty("more", try env.getBoolean(batch.more));
    inline for (.{ "dropped", "suppressed", "truncated" }) |kind| {
        try result.setNamedProperty(kind, try env.createBigintUint64(batch.stats.total(kind)));
    }
    try @import("network_faults.zig").check(.drain_copy);
    runtime.logs.commit(batch.count);
    return .{ .val = result };
}

pub fn configure(runtime: *Runtime, value: Value) !void {
    var buffer: [5]u8 = undefined;
    const len = @import("network_application_config.zig").text(value, &buffer) catch return error.InvalidNetworkLogLevel;
    const text = buffer[0..len];
    inline for (.{ "error", "warn", "info", "debug", "off" }, 0..) |name, index| {
        if (std.mem.eql(u8, text, name)) {
            runtime.logs.configure(if (index == 4) null else @enumFromInt(index));
            return;
        }
    }
    return error.InvalidNetworkLogLevel;
}
