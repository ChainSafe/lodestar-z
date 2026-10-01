const std = @import("std");
const rr = @import("network").reqresp;
const incoming = @import("network_incoming.zig");
const Budget = @import("network_budget.zig").Budget;
const Table = incoming.Table;
const Cell = incoming.Cell;

test "incoming reservation shares exact aggregate credits and rolls back allocation failure" {
    const amount: usize = 64;
    var budget: Budget = .{ .limit = amount };
    var table = try Table.init(std.testing.allocator, 1, &budget);
    defer table.deinit();
    budget.limit -= 1;
    try std.testing.expectError(error.NetworkBridgeFull, table.reserve(.blocks_by_root_v2, 32));
    try std.testing.expectEqual(@as(usize, 0), budget.used);
    budget.limit += 1;
    const first = try table.reserve(.blocks_by_root_v2, 32);
    try std.testing.expectEqual(amount, budget.used);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    table.backing = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, table.allocate(first, "01234567890123456789012345678901"));
    table.retire(first);
    table.backing = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), budget.used);
    const second = try table.reserve(.blocks_by_root_v2, 32);
    try std.testing.expect(table.get(first) == null);
    try std.testing.expectEqual(first.generation + 1, second.generation);
    table.retire(second);
    table.cells[0].generation = std.math.maxInt(u64);
    try std.testing.expectError(error.NetworkIncomingFull, table.reserve(.blocks_by_root_v2, 32));
}

test "incoming and outbound reservations cannot each spend the aggregate remainder" {
    const protocol = rr.Protocol.blocks_by_root_v2;
    const outbound_amount = 32 + 2 * protocol.info().response_max;
    const inbound_amount: usize = 64;
    var budget: Budget = .{ .limit = outbound_amount + inbound_amount - 1 };
    var outgoing = try @import("network_requests.zig").Table.init(std.testing.allocator, 1, &budget);
    defer outgoing.deinit();
    var inbound = try Table.init(std.testing.allocator, 1, &budget);
    defer inbound.deinit();
    const first = try outgoing.reserve(protocol, 32);
    try std.testing.expectError(error.NetworkBridgeFull, inbound.reserve(protocol, 32));
    try std.testing.expectEqual(outbound_amount, budget.used);
    outgoing.retire(first);
    const second = try inbound.reserve(protocol, 32);
    try std.testing.expectEqual(inbound_amount, budget.used);
    try std.testing.expectError(error.NetworkBridgeFull, outgoing.reserve(protocol, 32));
    inbound.retire(second);
    try std.testing.expectEqual(@as(usize, 0), budget.used);
}

test "incoming submission recognizes a genuine native terminal awaiting output capacity" {
    var pair: rr.testing.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const sink = try std.testing.allocator.alloc(u8, rr.Protocol.blocks_by_root_v2.info().response_max);
    defer {
        pair.shared.client.reqresp.shutdown(&pair.shared.pair.client, &pair.shared.client.router);
        std.testing.allocator.free(sink);
    }
    const query = [_]u8{0} ** 32;
    _ = try pair.shared.client.reqresp.request(&pair.shared.pair.client, &pair.shared.client.router, pair.shared.handles.client, .blocks_by_root_v2, &query, sink, .{}, pair.shared.pair.now);
    var handle: ?rr.RequestHandle = null;
    for (0..20) |_| {
        try pair.pumpOnce();
        for (pair.serverEvents()) |event| if (event == .request) {
            handle = event.request.request;
        };
        if (handle != null) break;
    }
    const request = handle.?;
    try std.testing.expectEqual(.ready, pair.shared.server.reqresp.responseReadiness(request));
    try std.testing.expect(pair.shared.server.reqresp.cancel(request));
    pair.server_event_capacity = 0;
    try pair.pumpOnce();
    try std.testing.expectEqual(@as(usize, 0), pair.serverEvents().len);
    const response = [_]u8{0} ** 4000;
    try std.testing.expectError(error.Terminal, pair.shared.server.reqresp.respond(request, &response, .{ .digest = rr.testing.deneb_digest, .fork = .deneb }, pair.shared.pair.now));
    try std.testing.expectEqual(.terminal, pair.shared.server.reqresp.responseReadiness(request));
    var stale = request;
    stale.generation += 1;
    try std.testing.expectEqual(.stale, pair.shared.server.reqresp.responseReadiness(stale));
    stale = request;
    stale.direction = .outbound;
    try std.testing.expectEqual(.stale, pair.shared.server.reqresp.responseReadiness(stale));
    pair.server_event_capacity = 16;
    try pair.pumpOnce();
    var terminal = false;
    for (pair.serverEvents()) |event| if (event == .failed and std.meta.eql(event.failed.request, request)) {
        try std.testing.expect(event.failed.reason == .cancelled);
        terminal = true;
    };
    try std.testing.expect(terminal);
}

test "queued requests reserve only input and response credits follow a chunk lifetime" {
    const response_max = rr.Protocol.blocks_by_root_v2.info().response_max;
    var budget: Budget = .{ .limit = 32 * 64 + response_max };
    var table = try Table.init(std.testing.allocator, 32, &budget);
    defer table.deinit();
    var tokens: [32]incoming.Token = undefined;
    for (&tokens) |*token| token.* = try table.reserve(.blocks_by_root_v2, 32);
    try std.testing.expectEqual(@as(usize, 32 * 64), budget.used);
    const first = table.get(tokens[0]).?;
    const second = table.get(tokens[1]).?;
    try table.reserveResponse(first, response_max);
    try std.testing.expectError(error.NetworkBridgeFull, table.reserveResponse(second, 1));
    try std.testing.expectEqual(@as(usize, 0), second.response_reservation);
    try table.reserveResponse(first, 4000);
    try std.testing.expectEqual(@as(usize, 32 * 64 + 4000), budget.used);
    table.releaseResponse(first);
    try table.reserveResponse(second, response_max);
    table.releaseResponse(second);
    for (tokens) |token| table.retire(token);
    try std.testing.expectEqual(@as(usize, 0), budget.used);
}
