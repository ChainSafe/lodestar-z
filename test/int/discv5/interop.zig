const std = @import("std");
const discv5 = @import("discv5");

const duration_ms: u64 = 8_000;
const steps_max: usize = 512;
const call_capacity: usize = 4;
const Phase = enum { waiting, ping, ping_complete, nodes, done };

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.ExpectedModeAndGethRecord;
    const zig_first = std.mem.eql(u8, args[1], "zig-first");
    if (!zig_first and !std.mem.eql(u8, args[1], "geth-first")) return error.InvalidMode;
    const remote = try discv5.identity.enr.Record.initText(args[2]);
    const address = remote.endpoint() orelse return error.MissingEndpoint;
    if (address != .ip4 or address.ip4.octets[0] != 127) return error.NonLoopbackEndpoint;
    const peer = discv5.types.Endpoint{ .node_id = remote.node_id, .address = address };

    var udp = try discv5.Udp.bind(io, try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0"));
    defer udp.close(io);
    var key = try discv5.identity.crypto.keyPairFromSecret(&([_]u8{0x11} ** 32));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    const local = try discv5.identity.enr.Record.create(&key, 1, udp.localAddress());
    var core: discv5.Engine = undefined;
    try core.initWithConfig(allocator, key, local, .{
        .session_capacity = 4,
        .challenge_capacity = 4,
        .call_capacity = call_capacity,
        .request_timeout_ms = 2_000,
        .challenge_timeout_ms = 2_000,
        .session_idle_timeout_ms = 60_000,
    });
    defer core.deinit(allocator);
    var driver = try discv5.Driver.initWithConfig(&core, &udp, .{ .poll_interval_ms = 25 });
    try printRecord(io, &local);

    const deadline_ms = (try discv5.Driver.monotonicMilliseconds(io)) + duration_ms;
    var phase: Phase = .waiting;
    var pending: ?discv5.CallTable.Handle = null;
    defer if (pending) |handle| {
        _ = core.cancelCall(handle);
    };
    var served: usize = 0;
    var expired: [call_capacity]discv5.CallTable.Expired = undefined;
    for (0..steps_max) |_| {
        if (try discv5.Driver.monotonicMilliseconds(io) >= deadline_ms)
            return error.InteropTimedOut;
        if (phase == .waiting and (zig_first or served >= 2)) {
            const ping = discv5.wire.message.Message{ .ping = .{
                .request_id = try discv5.wire.message.RequestId.init(&.{1}),
                .enr_sequence = local.sequence,
            } };
            pending = try driver.startCall(io, peer, &remote, &ping);
            phase = .ping;
        } else if (phase == .ping_complete) {
            const find_node = discv5.wire.message.Message{ .find_node = .{
                .request_id = try discv5.wire.message.RequestId.init(&.{2}),
                .distances = &.{0},
            } };
            pending = try driver.startCall(io, peer, &remote, &find_node);
            phase = .nodes;
        } else if (phase == .done and served >= 2) {
            try std.Io.File.stdout().writeStreamingAll(io, "DONE\n");
            return;
        }

        const result = try driver.stepUntil(io, &expired, deadline_ms);
        served += result.progress.standard_responses;
        var call_expired = false;
        for (expired[0..result.calls_expired]) |entry| {
            if (pending) |handle| if (std.meta.eql(handle, entry.handle)) {
                pending = null;
                call_expired = true;
            };
        }
        var call_failure: ?discv5.Engine.Error = null;
        switch (result.event) {
            .response => |response| {
                const handle = pending orelse return error.UnexpectedResponse;
                if (!std.meta.eql(handle, response.matched.handle) or
                    !std.meta.eql(peer, response.peer) or !response.matched.terminal)
                    return error.UnexpectedResponse;
                switch (phase) {
                    .ping => {
                        if (response.matched.response != .pong) return error.ExpectedPong;
                        const pong = response.matched.response.pong;
                        if (pong.enr_sequence != remote.sequence or
                            pong.recipient_port != local.endpoint().?.port() or
                            pong.recipient_ip != .ip4 or
                            !std.mem.eql(u8, &pong.recipient_ip.ip4, &.{ 127, 0, 0, 1 }))
                            return error.InvalidPong;
                        phase = .ping_complete;
                        try std.Io.File.stdout().writeStreamingAll(io, "ZIG_PONG\n");
                    },
                    .nodes => {
                        if (response.matched.response != .nodes or response.node_records.len != 1)
                            return error.ExpectedSelfRecord;
                        if (!std.mem.eql(u8, response.node_records[0].slice(), remote.slice()))
                            return error.InvalidSelfRecord;
                        phase = .done;
                        try std.Io.File.stdout().writeStreamingAll(io, "ZIG_ENR\n");
                    },
                    else => return error.UnexpectedResponse,
                }
                pending = null;
            },
            .failed => |failure| {
                pending = null;
                call_failure = failure.reason;
            },
            .none => {},
            .request => return error.UnexpectedRequest,
        }
        if (result.failure) |failure| return failure;
        if (call_failure) |failure| return failure;
        if (call_expired) return error.RequestTimedOut;
        if (result.datagram == .rejected) {
            std.debug.print("rejected {s}\n", .{@tagName(result.datagram.rejected)});
            return error.RejectedDatagram;
        }
    }
    return error.StepBudgetExhausted;
}

fn printRecord(io: std.Io, record: *const discv5.identity.enr.Record) !void {
    var encoded_buffer: [512]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&encoded_buffer, record.slice());
    var line_buffer: [528]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buffer, "ENR enr:{s}\n", .{encoded});
    try std.Io.File.stdout().writeStreamingAll(io, line);
}
