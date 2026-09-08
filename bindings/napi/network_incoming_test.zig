const std = @import("std");
const rr = @import("network").reqresp;
const incoming = @import("network_incoming.zig");
const Budget = incoming.Budget;
const Table = incoming.Table;
const Cell = incoming.Cell;

test "incoming reservation shares exact aggregate credits and rolls back allocation failure" {
    const amount = 64 + rr.Protocol.blocks_by_root_v2.info().response_max;
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

test "incoming response allocation stays borrowed through real quota withholding and exact expiry" {
    const harness = rr.testing;
    var quotas = rr.limiter.defaultQuotas();
    quotas[@intFromEnum(rr.Protocol.blocks_by_root_v2)] = .{ .tokens = 1, .period_ms = 3000 };
    var pair: harness.ReqRespPair = .{};
    try pair.init(.{}, .{ .quotas = quotas, .quota_timeout_ms = 1000 });
    defer pair.deinit();
    var budget: Budget = .{ .limit = 2 * (64 + rr.Protocol.blocks_by_root_v2.info().response_max) };
    var table = try Table.init(std.testing.allocator, 2, &budget);
    defer {
        pair.server.shutdown(&pair.pair.server, &pair.server_neg);
        for (table.cells, 0..) |*cell, i| {
            if (cell.state == .free) continue;
            cell.native = false;
            table.retire(.{ .index = @intCast(i), .generation = cell.generation });
        }
        table.deinit();
    }
    const query = [_]u8{0} ** 32;
    const response_max = rr.Protocol.blocks_by_root_v2.info().response_max;
    const sinks = try std.testing.allocator.alloc(u8, 2 * response_max);
    defer {
        pair.client.shutdown(&pair.pair.client, &pair.client_neg);
        std.testing.allocator.free(sinks);
    }
    for (0..2) |i| _ = try pair.client.request(&pair.pair.client, &pair.client_neg, pair.handles.client, .blocks_by_root_v2, &query, sinks[i * response_max ..][0..response_max], .{}, pair.pair.now);
    try submitWithheld(&pair, &table);
    try std.testing.expectEqual(@as(usize, 1), pair.server.resourceSnapshot().withheld_chunks);
    var withheld: ?*Cell = null;
    for (table.cells) |*cell| if (cell.response.len > 0) {
        withheld = cell;
    };
    const cell = withheld.?;
    const native = &pair.server.inbound[cell.handle.index];
    try std.testing.expectEqual(native.pending_ssz.ptr, cell.response.ptr);
    try std.testing.expectEqual(@as(usize, 4000), table.snapshot().responseBytes);
    const deadline = native.withheld_since_ms.? + 1000;
    pair.pair.advance(deadline - pair.pair.now.mono_ms - 1);
    try pair.pumpOnce();
    try std.testing.expectEqual(@as(usize, 1), pair.server.resourceSnapshot().withheld_chunks);
    try std.testing.expectEqual(native.pending_ssz.ptr, cell.response.ptr);
    pair.pair.advance(1);
    var terminal_seen = false;
    for (0..10) |_| {
        try pair.pumpOnce();
        for (pair.serverEvents()) |event| {
            if (event != .failed or !std.meta.eql(event.failed.request, cell.handle)) continue;
            try std.testing.expect(event.failed.reason == .quota_timeout);
            cell.native = false;
            cell.state = .terminal;
            table.releasePayload(cell);
            terminal_seen = true;
        }
        if (terminal_seen) break;
    }
    try std.testing.expect(terminal_seen);
    try std.testing.expectEqual(@as(usize, 0), table.snapshot().responseBytes);
}

test "incoming and outbound reservations cannot each spend the aggregate remainder" {
    const protocol = rr.Protocol.blocks_by_root_v2;
    const outbound_amount = 32 + 2 * protocol.info().response_max;
    const inbound_amount = 64 + protocol.info().response_max;
    var budget: Budget = .{ .limit = outbound_amount + inbound_amount - 1 };
    var outgoing = try @import("network_requests.zig").Table.init(std.testing.allocator, 1, budget.limit);
    outgoing.shared = &budget;
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

fn submitWithheld(pair: *rr.testing.ReqRespPair, table: *Table) !void {
    var admitted: usize = 0;
    var acknowledged: usize = 0;
    for (0..30) |_| {
        try pair.pumpOnce();
        for (pair.serverEvents()) |event| switch (event) {
            .request => |request| {
                const token = try table.reserve(request.protocol, request.bytes.len);
                try table.allocate(token, request.bytes);
                const cell = table.get(token).?;
                cell.handle = request.request;
                cell.native = true;
                cell.state = .response_native;
                cell.response = try std.testing.allocator.alloc(u8, 4000);
                @memset(cell.response, 71);
                try pair.server.respond(request.request, cell.response, .{ .digest = rr.testing.deneb_digest, .fork = .deneb }, pair.pair.now);
                admitted += 1;
            },
            .chunk_sent => |sent| {
                for (table.cells) |*cell| {
                    if (!cell.native or !std.meta.eql(cell.handle, sent.request)) continue;
                    table.releaseResponse(cell);
                    cell.state = .serving;
                    acknowledged += 1;
                }
            },
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        if (admitted == 2 and acknowledged == 1) break;
    }
    try std.testing.expectEqual(@as(usize, 2), admitted);
    try std.testing.expectEqual(@as(usize, 1), acknowledged);
}

test "incoming submission recognizes a genuine native terminal awaiting output capacity" {
    var pair: rr.testing.ReqRespPair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const sink = try std.testing.allocator.alloc(u8, rr.Protocol.blocks_by_root_v2.info().response_max);
    defer {
        pair.client.shutdown(&pair.pair.client, &pair.client_neg);
        std.testing.allocator.free(sink);
    }
    const query = [_]u8{0} ** 32;
    _ = try pair.client.request(&pair.pair.client, &pair.client_neg, pair.handles.client, .blocks_by_root_v2, &query, sink, .{}, pair.pair.now);
    var handle: ?rr.RequestHandle = null;
    for (0..20) |_| {
        try pair.pumpOnce();
        for (pair.serverEvents()) |event| if (event == .request) {
            handle = event.request.request;
        };
        if (handle != null) break;
    }
    const request = handle.?;
    try std.testing.expect(!incoming.awaitingTerminal(&pair.server, request, error.Busy));
    try std.testing.expect(pair.server.cancel(request));
    pair.server_event_capacity = 0;
    try pair.pumpOnce();
    try std.testing.expectEqual(@as(usize, 0), pair.serverEvents().len);
    const response = [_]u8{0} ** 4000;
    try std.testing.expectError(error.Busy, pair.server.respond(request, &response, .{ .digest = rr.testing.deneb_digest, .fork = .deneb }, pair.pair.now));
    try std.testing.expect(incoming.awaitingTerminal(&pair.server, request, error.Busy));
    var stale = request;
    stale.generation += 1;
    try std.testing.expect(!incoming.awaitingTerminal(&pair.server, stale, error.Busy));
    stale = request;
    stale.direction = .outbound;
    try std.testing.expect(!incoming.awaitingTerminal(&pair.server, stale, error.Busy));
    try std.testing.expect(!incoming.awaitingTerminal(&pair.server, request, error.StaleHandle));
    pair.server_event_capacity = 16;
    try pair.pumpOnce();
    var terminal = false;
    for (pair.serverEvents()) |event| if (event == .failed and std.meta.eql(event.failed.request, request)) {
        try std.testing.expect(event.failed.reason == .cancelled);
        terminal = true;
    };
    try std.testing.expect(terminal);
}
