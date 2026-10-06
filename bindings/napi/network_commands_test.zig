const std = @import("std");
const Now = @import("network").Now;
const n = @import("network");
const commands = @import("network_commands.zig");
const Table = commands.Table;

test "application admission reserves one local-state cell and at most 16 connects" {
    var table: Table = .{};
    for (0..16) |_| _ = try table.reserve(.connect);
    try std.testing.expectError(error.NetworkCommandFull, table.reserve(.connect));
    for (0..15) |_| _ = try table.reserve(.getIdentity);
    try std.testing.expectError(error.NetworkCommandFull, table.reserve(.getIdentity));
    const state = try table.reserve(.applyIntent);
    try std.testing.expectError(error.NetworkCommandFull, table.reserve(.updateStatus));
    table.retire(state);
    _ = try table.reserve(.updateStatus);
}

test "typed reservations unwind and identities never wrap" {
    var table: Table = .{};
    const first = try table.reserve(.applyIntent);
    _ = try table.reserve(.applyIntent);
    try std.testing.expectError(error.NetworkCommandFull, table.reserve(.applyIntent));
    try std.testing.expectEqual(@as(u8, 2), table.occupied);
    table.retire(first);
    const next = try table.reserve(.applyIntent);
    try std.testing.expectEqual(first.generation + 1, next.generation);
    table.retire(next);
    table.cells[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.NetworkSequenceExhausted, table.reserve(.updateStatus));
    table.sequence = std.math.maxInt(u64);
    try std.testing.expectError(error.NetworkSequenceExhausted, table.advance());
    table.admission_sequence = std.math.maxInt(u64) - 2;
    try std.testing.expectEqual(std.math.maxInt(u64) - 1, try table.nextOrder());
    try std.testing.expectError(error.NetworkSequenceExhausted, table.nextOrder());
}

test "authenticated connect completion latches before a later close in the borrowed batch" {
    const key = try n.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{2}));
    const peer = n.PeerId.fromPublicKey(&key.publicKey());
    const handle: n.Handle = .{ .index = 3, .generation = 7 };
    const events = [_]n.Event{
        .{ .connected = .{ .conn = handle, .peer_id = peer, .direction = .outbound } },
        .{ .closed = .{ .conn = handle, .peer_id = peer, .direction = .outbound, .reason = .host } },
    };
    var table: Table = .{};
    const token = try table.reserve(.connect);
    table.transition(table.get(token), .waiting);
    table.cells[token.index].input.peer = peer;
    table.cells[token.index].deadline = 2;
    try std.testing.expect(commands.latchConnects(&table, &events, Now.fromMilliseconds(.{ .mono_ms = 3, .unix_s = 0 })));
    try std.testing.expectEqual(commands.State.terminal, table.get(token).state);
    try std.testing.expect(table.cells[token.index].failure == null);
    try std.testing.expect(!commands.latchConnects(&table, &events, Now.fromMilliseconds(.{ .mono_ms = 4, .unix_s = 0 })));
    try std.testing.expect(table.cells[token.index].failure == null);
    table.retire(token);
}

test "reserved state capacity retains ordinary execution order" {
    var table: Table = .{};
    const first = try table.reserve(.getIdentity);
    const state = try table.reserve(.applyIntent);
    const last = try table.reserve(.getIdentity);
    for ([_]commands.Token{ first, state, last }) |token| table.transition(table.get(token), .queued);
    for ([_]commands.Token{ first, state, last }) |token| {
        try std.testing.expectEqual(token, table.nextQueued().?);
        table.retire(token);
    }
    try std.testing.expect(table.nextQueued() == null);
}
