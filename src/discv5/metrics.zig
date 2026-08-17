const std = @import("std");
const messages = @import("protocol/message.zig");

/// Standalone in-memory discv5 metrics surface mirroring the ChainSafe TS
/// `IDiscv5Metrics` names. The carve-out intentionally does not depend on a
/// process-wide Prometheus registry; embedders can poll `MetricsSnapshot` and
/// export these values under the documented `discv5_*` metric names.
pub const MessageType = enum(u8) {
    ping = messages.MSG_PING,
    pong = messages.MSG_PONG,
    findnode = messages.MSG_FINDNODE,
    nodes = messages.MSG_NODES,
    talkreq = messages.MSG_TALKREQ,
    talkresp = messages.MSG_TALKRESP,

    pub fn fromByte(byte: u8) ?MessageType {
        // The enum is backed by the wire message-type bytes, so a valid byte
        // maps straight to its tag.
        return std.enums.fromInt(MessageType, byte);
    }

    pub fn label(self: MessageType) []const u8 {
        return switch (self) {
            .ping => "PING",
            .pong => "PONG",
            .findnode => "FINDNODE",
            .nodes => "NODES",
            .talkreq => "TALKREQ",
            .talkresp => "TALKRESP",
        };
    }

    pub fn index(self: MessageType) usize {
        return switch (self) {
            .ping => 0,
            .pong => 1,
            .findnode => 2,
            .nodes => 3,
            .talkreq => 4,
            .talkresp => 5,
        };
    }
};

/// Human-readable wire name for a message-type byte, or "unknown".
pub fn messageLabel(byte: u8) []const u8 {
    return if (MessageType.fromByte(byte)) |t| t.label() else "unknown";
}

pub const message_type_count = @typeInfo(MessageType).@"enum".fields.len;

pub const ProtocolMetrics = struct {
    sent_message_count: [message_type_count]u64 = [_]u64{0} ** message_type_count,
    rcvd_message_count: [message_type_count]u64 = [_]u64{0} ** message_type_count,

    pub fn incSent(self: *ProtocolMetrics, message_type: MessageType) void {
        self.sent_message_count[message_type.index()] += 1;
    }

    pub fn incReceived(self: *ProtocolMetrics, message_type: MessageType) void {
        self.rcvd_message_count[message_type.index()] += 1;
    }
};

pub const MetricsSnapshot = struct {
    /// TS: discv5_kad_table_size
    kad_table_size: usize = 0,
    /// TS: discv5_active_session_count
    active_session_count: usize = 0,
    /// TS: discv5_connected_peer_count
    connected_peer_count: usize = 0,
    /// TS: discv5_lookup_count
    lookup_count: u64 = 0,
    /// TS: discv5_rate_limit_hit_ip
    rate_limit_hit_ip: u64 = 0,
    /// TS: discv5_rate_limit_hit_total
    rate_limit_hit_total: u64 = 0,
    /// TS: discv5_sent_message_count{type}
    sent_message_count: [message_type_count]u64 = [_]u64{0} ** message_type_count,
    /// TS: discv5_rcvd_message_count{type}
    rcvd_message_count: [message_type_count]u64 = [_]u64{0} ** message_type_count,
    /// Completed events dropped before reaching consumers (allocation pressure).
    dropped_event_count: u64 = 0,

    pub fn sentMessageCount(self: *const MetricsSnapshot, message_type: MessageType) u64 {
        return self.sent_message_count[message_type.index()];
    }

    pub fn rcvdMessageCount(self: *const MetricsSnapshot, message_type: MessageType) u64 {
        return self.rcvd_message_count[message_type.index()];
    }
};

test "discv5 metrics message labels mirror ChainSafe TS enum labels" {
    try std.testing.expectEqualStrings("PING", MessageType.ping.label());
    try std.testing.expectEqualStrings("PONG", MessageType.pong.label());
    try std.testing.expectEqualStrings("FINDNODE", MessageType.findnode.label());
    try std.testing.expectEqualStrings("NODES", MessageType.nodes.label());
    try std.testing.expectEqualStrings("TALKREQ", MessageType.talkreq.label());
    try std.testing.expectEqualStrings("TALKRESP", MessageType.talkresp.label());
}
