const std = @import("std");
const t = @import("types.zig");
const goodbye = @import("goodbye.zig");
const prom = @import("../metrics_prometheus.zig");
const long_connection_ms = 24 * 60 * 60 * 1000;

pub const Relevance = enum { relevant, invalid_status, incompatible_fork, future_head, finalized_mismatch, missing_availability };

pub const Counters = struct {
    connected: [2]u64 = @splat(0),
    disconnected: [2]u64 = @splat(0),
    goodbyes: [goodbye.count]u64 = @splat(0),
    sent_goodbyes: [goodbye.count]u64 = @splat(0),
    long_goodbyes: [goodbye.count]u64 = @splat(0),
    relevance: [@typeInfo(Relevance).@"enum".fields.len]u64 = @splat(0),

    pub fn observeGoodbye(self: *Counters, code: u64, sent: bool, connected_at_ms: u64, now_ms: u64) void {
        const index = @intFromEnum(goodbye.reason(code));
        if (sent) self.sent_goodbyes[index] +|= 1 else self.goodbyes[index] +|= 1;
        if (now_ms -| connected_at_ms > long_connection_ms) self.long_goodbyes[index] +|= 1;
    }

    pub fn observeRelevance(self: *Counters, reason: ?t.DisconnectReason) void {
        const result: Relevance = if (reason) |value| switch (value) {
            .invalid_status => .invalid_status,
            .incompatible_fork => .incompatible_fork,
            .future_head => .future_head,
            .finalized_mismatch => .finalized_mismatch,
            .missing_availability => .missing_availability,
            else => unreachable,
        } else .relevant;
        self.relevance[@intFromEnum(result)] +|= 1;
    }

    pub fn write(self: *const Counters, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try prom.family(w, "lodestar_peer_connected_total", .counter, "Authenticated connections admitted to the native peer manager");
        try prom.family(w, "lodestar_peer_disconnected_total", .counter, "Admitted connections retired by the native peer manager");
        inline for (.{ "inbound", "outbound" }, 0..) |direction, index| {
            try w.print("lodestar_peer_connected_total{{direction=\"" ++ direction ++ "\",status=\"open\"}} {d}\n", .{self.connected[index]});
            try prom.sample(w, "lodestar_peer_disconnected_total", "direction", direction, self.disconnected[index]);
        }
        inline for (.{
            .{ "lodestar_peer_goodbye_received_total", "goodbyes", "Decoded peer Goodbye requests" },
            .{ "lodestar_peer_goodbye_sent_total", "sent_goodbyes", "Local Goodbye requests admitted to the request engine" },
            .{ "lodestar_peer_long_connection_disconnect_total", "long_goodbyes", "Sent or received Goodbyes on connections older than 24 hours" },
        }) |metric| {
            try prom.family(w, metric[0], .counter, metric[2]);
            inline for (@typeInfo(goodbye.Reason).@"enum".fields) |field|
                try prom.sample(w, metric[0], "reason", goodbyeLabel(@enumFromInt(field.value)), @field(self, metric[1])[field.value]);
        }
        try prom.family(w, "lodestar_peer_relevance_check_total", .counter, "Native Status evaluations, excluding obsolete fork transition responses");
        inline for (@typeInfo(Relevance).@"enum".fields) |field|
            try prom.sample(w, "lodestar_peer_relevance_check_total", "result", relevanceLabel(@enumFromInt(field.value)), self.relevance[field.value]);
    }
};

fn goodbyeLabel(reason: goodbye.Reason) []const u8 {
    return switch (reason) {
        .shutdown => "Client shutdown",
        .irrelevant_network => "Irrelevant network",
        .fault => "Internal fault/error",
        .unable_to_verify => "Unable to verify network",
        .too_many_peers => "Client has too many peers",
        .bad_score => "Peer score too low",
        .banned => "Peer banned this node",
        .banned_ip => "Peer banned this IP",
        .unknown => "Unknown",
    };
}

fn relevanceLabel(result: Relevance) []const u8 {
    return switch (result) {
        .relevant => "relevant",
        .invalid_status => "error",
        .incompatible_fork => "IRRELEVANT_PEER_INCOMPATIBLE_FORKS",
        .future_head => "IRRELEVANT_PEER_DIFFERENT_CLOCKS",
        .finalized_mismatch => "IRRELEVANT_PEER_DIFFERENT_FINALIZED",
        .missing_availability => "NO_EARLIEST_AVAILABLE_SLOT",
    };
}

test "peer event metrics bound unknown reasons and count long Goodbye boundaries" {
    var counters: Counters = .{};
    counters.observeGoodbye(129, false, 10, long_connection_ms + 10);
    counters.observeGoodbye(129, true, 10, long_connection_ms + 11);
    counters.observeGoodbye(std.math.maxInt(u64), false, 10, 0);
    counters.observeRelevance(.future_head);
    counters.observeRelevance(null);
    try std.testing.expectEqual(@as(u64, 1), counters.long_goodbyes[@intFromEnum(goodbye.Reason.too_many_peers)]);
    try std.testing.expectEqual(@as(u64, 1), counters.goodbyes[@intFromEnum(goodbye.Reason.unknown)]);
    var buffer: [8192]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try counters.write(&writer);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_peer_goodbye_sent_total{reason=\"Client has too many peers\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "lodestar_peer_relevance_check_total{result=\"IRRELEVANT_PEER_DIFFERENT_CLOCKS\"} 1\n") != null);
}
