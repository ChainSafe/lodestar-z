const std = @import("std");
const invariant = @import("route_invariant.zig");
const support = @import("../quic/test_support.zig");
const Client = @import("Client.zig");
const Server = @import("Server.zig");
const StreamOwner = @import("../types.zig").StreamOwner;

test "reverse route invariant detects orphans without a forward request to visit" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    const stream = try pair.client.openStream(handles.client);
    var outbound = [_]Client{.{}};
    var inbound = [_]Server{.{}};
    try invariant.check(&pair.client, &outbound, &inbound);
    for ([_]StreamOwner{ .reqresp_outbound, .reqresp_inbound }) |owner| {
        try pair.client.bindStream(stream, .{ .owner = owner, .row = 0 });
        try std.testing.expectError(error.OrphanedRoute, invariant.check(&pair.client, &outbound, &inbound));
        try pair.client.bindStream(stream, .{ .owner = owner, .row = 1 });
        try std.testing.expectError(error.OrphanedRoute, invariant.check(&pair.client, &outbound, &inbound));
    }
    // A closed route awaits event delivery and no longer obligates a request owner.
    pair.client.closeStream(stream, 0);
    try invariant.check(&pair.client, &outbound, &inbound);
}

test "reverse route invariant requires the full handle and protocol ownership" {
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    const stream = try pair.client.openStream(handles.client);
    var outbound = [_]Client{.{}};
    outbound[0].request = .{ .completion = .running, .stream = stream };
    try pair.client.bindStream(stream, .{ .owner = .reqresp_outbound, .row = 0 });
    try invariant.check(&pair.client, &outbound, &.{});
    for (0..4) |changed| {
        var wrong = stream;
        switch (changed) {
            0 => wrong.conn.generation += 1,
            1 => wrong.conn.index += 1,
            2 => wrong.id += 4,
            3 => wrong.slot += 1,
            else => unreachable,
        }
        outbound[0].request.stream = wrong;
        try std.testing.expectError(error.MismatchedRoute, invariant.check(&pair.client, &outbound, &.{}));
    }
    outbound[0].request.stream = stream;
    outbound[0].request.stream_owner = .router;
    try std.testing.expectError(error.OrphanedRoute, invariant.check(&pair.client, &outbound, &.{}));
    // Closing retains readable streams, but no longer requires a live protocol request.
    try std.testing.expect(pair.client.close(handles.client, 0));
    try invariant.check(&pair.client, &outbound, &.{});
}
