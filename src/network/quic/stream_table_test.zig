const std = @import("std");
const limits = @import("limits.zig");
const stream_table = @import("stream_table.zig");

const StreamTable = stream_table.StreamTable;
const half = limits.streams_per_connection / 2;

test "stream table keeps local and peer claims in disjoint halves" {
    var table = StreamTable.init(.outbound);

    var claimed: usize = 0;
    while (claimed < half) : (claimed += 1) {
        const index = table.freeLocal() orelse return error.TestUnexpectedResult;
        try std.testing.expect(index < half);
        table.claimLocal(index, table.next_local_id);
    }
    try std.testing.expect(table.freeLocal() == null);

    const peer = table.claimPeer(1) orelse return error.TestUnexpectedResult;
    try std.testing.expect(peer >= half);
    try std.testing.expectEqual(@as(u16, 1), table.pending);
    try std.testing.expectEqual(peer, table.find(1).?);
}

test "stream table fills the peer half before refusing a claim" {
    var table = StreamTable.init(.inbound);

    var claimed: u64 = 0;
    while (claimed < half) : (claimed += 1) {
        const index = table.claimPeer(claimed * 4) orelse return error.TestUnexpectedResult;
        try std.testing.expect(index >= half);
    }
    try std.testing.expectEqual(@as(u16, half), table.pending);
    try std.testing.expect(table.claimPeer(claimed * 4) == null);
    try std.testing.expect(table.freeLocal() != null);
}

test "stream table find returns null for a cleared entry" {
    var table = StreamTable.init(.outbound);

    const index = table.freeLocal() orelse return error.TestUnexpectedResult;
    table.claimLocal(index, 0);
    try std.testing.expectEqual(index, table.find(0).?);

    table.markFinSent(index);
    table.markFinReceived(index);
    try std.testing.expect(table.entries[index].fin_sent);
    try std.testing.expect(table.entries[index].fin_received);

    table.clear(index);
    try std.testing.expect(table.find(0) == null);
    try std.testing.expect(table.entries[index].id == null);
    try std.testing.expect(!table.entries[index].fin_sent);
}

test "stream table pending never underflows across repeated clears" {
    var table = StreamTable.init(.outbound);

    const peer = table.claimPeer(1) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 1), table.pending);
    table.clear(peer);
    try std.testing.expectEqual(@as(u16, 0), table.pending);
    table.clear(peer);
    try std.testing.expectEqual(@as(u16, 0), table.pending);

    const local = table.freeLocal() orelse return error.TestUnexpectedResult;
    table.claimLocal(local, 0);
    table.clear(local);
    try std.testing.expectEqual(@as(u16, 0), table.pending);
}

test "stream table parity follows the connection direction" {
    try std.testing.expect(StreamTable.isPeerInitiated(.outbound, 1));
    try std.testing.expect(StreamTable.isPeerInitiated(.outbound, 5));
    try std.testing.expect(!StreamTable.isPeerInitiated(.outbound, 0));
    try std.testing.expect(!StreamTable.isPeerInitiated(.outbound, 4));

    try std.testing.expect(StreamTable.isPeerInitiated(.inbound, 0));
    try std.testing.expect(StreamTable.isPeerInitiated(.inbound, 4));
    try std.testing.expect(!StreamTable.isPeerInitiated(.inbound, 1));
    try std.testing.expect(!StreamTable.isPeerInitiated(.inbound, 5));
}

test "stream table local ids advance by four from the direction parity" {
    var outbound = StreamTable.init(.outbound);
    try std.testing.expectEqual(@as(u64, 0), outbound.next_local_id);
    outbound.claimLocal(outbound.freeLocal().?, 0);
    try std.testing.expectEqual(@as(u64, 4), outbound.next_local_id);
    outbound.claimLocal(outbound.freeLocal().?, 4);
    try std.testing.expectEqual(@as(u64, 8), outbound.next_local_id);

    var inbound = StreamTable.init(.inbound);
    try std.testing.expectEqual(@as(u64, 1), inbound.next_local_id);
    inbound.claimLocal(inbound.freeLocal().?, 1);
    try std.testing.expectEqual(@as(u64, 5), inbound.next_local_id);
    inbound.claimLocal(inbound.freeLocal().?, 5);
    try std.testing.expectEqual(@as(u64, 9), inbound.next_local_id);
}
