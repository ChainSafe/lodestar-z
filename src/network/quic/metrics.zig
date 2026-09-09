const std = @import("std");
const types = @import("../types.zig");
const prom = @import("../metrics_prometheus.zig");
const reason_count = @typeInfo(types.CloseReason).@"union".fields.len;

pub const Counters = struct {
    established: [2]u64 = @splat(0),
    closed: [2][reason_count]u64 = @splat(@splat(0)),

    pub fn write(self: *const Counters, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try prom.family(w, "lodestar_native_quic_connections_established_total", .counter, "QUIC connections with authenticated expected identities by direction");
        try prom.family(w, "lodestar_native_quic_connections_closed_total", .counter, "QUIC closes including pre-admission failures; wire error codes share bounded reason labels");
        inline for (@typeInfo(types.Direction).@"enum".fields) |direction| {
            try prom.sample(w, "lodestar_native_quic_connections_established_total", "direction", direction.name, self.established[direction.value]);
            inline for (@typeInfo(types.CloseReason).@"union".fields, 0..) |reason, index| {
                try w.print("lodestar_native_quic_connections_closed_total{{direction=\"" ++ direction.name ++
                    "\",reason=\"" ++ reason.name ++ "\"}} {d}\n", .{self.closed[direction.value][index]});
            }
        }
    }
};
