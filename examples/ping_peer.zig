const std = @import("std");
const network = @import("network");

const engine_mod = network.quic.engine;
const keys = network.wire.keys;
const multiaddr = network.wire.multiaddr;
const negotiate = network.negotiate;
const peer_id = network.wire.peer_id;

const ping_protocol = "/ipfs/ping/1.0.0";
const ping_size = 32;
const sessions_max = 8;
const negotiations_max = 16;
const dial_steps_max = 2_000;
const read_max = 256;
const supported = [_][]const u8{ping_protocol};

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 4 and std.mem.eql(u8, args[1], "listen")) {
        return listen(allocator, io, args[2], try std.fmt.parseInt(u16, args[3], 10));
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "dial")) {
        return dial(allocator, io, args[2]);
    }
    std.debug.print("usage: {s} listen <ip4> <port> | dial <multiaddr>\n", .{args[0]});
    std.process.exit(2);
}

fn initNode(node: *network.Transport, allocator: std.mem.Allocator, io: std.Io, bind: std.Io.net.IpAddress) !void {
    const key = keys.KeyPair.generate(io);
    try node.init(allocator, io, .{ .host = &key, .bind = bind });
}

const Session = struct {
    stream: engine_mod.StreamHandle = undefined,
    out: negotiate.Outbox = .{},
    buffer: [read_max]u8 = undefined,
    closing: bool = false,
    active: bool = false,
};

fn listen(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16) !void {
    var node: network.Transport = .{};
    try initNode(&node, allocator, io, try std.Io.net.IpAddress.parseIp4(host, port));
    defer node.deinit(io);
    var negotiator = try negotiate.Negotiator.init(allocator, negotiations_max);
    defer negotiator.deinit();

    const local = node.localMultiaddr();
    var text: [multiaddr.text_length_max]u8 = undefined;
    std.debug.print("{s}\n", .{try local.toText(&text)});

    var sessions = [_]Session{.{}} ** sessions_max;
    var events: [16]engine_mod.Event = undefined;
    var activity: [8]engine_mod.Handle = undefined;
    var outcomes: [8]negotiate.Outcome = undefined;
    while (true) {
        const result = try node.step(io, &events, &activity, .{});
        for (events[0..result.events]) |event| switch (event) {
            .connected => |connected| printPeer("connected", &connected.peer_id),
            .closed => |closed| {
                std.debug.print("closed reason={s}\n", .{@tagName(closed.reason)});
                for (&sessions) |*session| {
                    if (session.active and std.meta.eql(session.stream.conn, closed.conn)) session.active = false;
                }
            },
            .stream_opened => |stream| negotiator.acceptInbound(stream, &supported, result.now) catch {
                node.engine.closeStream(stream, 0);
            },
            .path_changed => |changed| std.debug.print("path changed port={d}\n", .{changed.peer.port()}),
            .stream_closed => |closed| {
                for (&sessions) |*session| {
                    if (session.active and std.meta.eql(session.stream, closed.stream)) session.active = false;
                }
            },
        };
        const ready = negotiator.pump(&node.engine, result.now, &outcomes);
        for (outcomes[0..ready]) |outcome| switch (outcome.result) {
            .ready => |accepted| {
                const free = freeSession(&sessions) orelse {
                    node.engine.closeStream(outcome.stream, 0);
                    continue;
                };
                free.* = .{ .stream = outcome.stream, .active = true };
                if (accepted.leftover.len > read_max) {
                    node.engine.closeStream(outcome.stream, 0);
                    free.active = false;
                    continue;
                }
                @memcpy(free.buffer[0..accepted.leftover.len], accepted.leftover);
                free.out.queue(free.buffer[0..accepted.leftover.len], false);
            },
            .rejected => {},
            .failed => |failure| std.debug.print("negotiation failed: {s}\n", .{@tagName(failure)}),
        };
        for (&sessions) |*session| {
            if (!session.active) continue;
            serve(&node.engine, session) catch |err| {
                std.debug.print("session failed: {s}\n", .{@errorName(err)});
                node.engine.closeStream(session.stream, 0);
                session.active = false;
            };
        }
    }
}

fn freeSession(sessions: []Session) ?*Session {
    for (sessions) |*session| {
        if (!session.active) return session;
    }
    return null;
}

fn serve(engine: *engine_mod.Engine, session: *Session) !void {
    if (!try session.out.pump(engine, session.stream)) return;
    if (session.closing) {
        session.active = false;
        return;
    }
    const read = try engine.read(session.stream, &session.buffer);
    if (read.len == 0 and !read.fin) return;
    session.closing = read.fin;
    session.out.queue(session.buffer[0..read.len], read.fin);
    if (try session.out.pump(engine, session.stream) and session.closing) session.active = false;
}

fn dial(allocator: std.mem.Allocator, io: std.Io, text: []const u8) !void {
    const target = try multiaddr.Multiaddr.parse(text);
    const bind: std.Io.net.IpAddress = switch (target.address) {
        .ip4 => .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .ip6 => .{ .ip6 = .{ .bytes = [_]u8{0} ** 16, .port = 0, .flow = 0, .interface = .{ .index = 0 } } },
    };
    var node: network.Transport = .{};
    try initNode(&node, allocator, io, bind);
    defer node.deinit(io);
    var negotiator = try negotiate.Negotiator.init(allocator, 1);
    defer negotiator.deinit();

    const handle = try node.dial(io, &target);
    var payload: [ping_size]u8 = undefined;
    try std.Io.randomSecure(io, &payload);
    var echo: [ping_size]u8 = undefined;
    var echoed: usize = 0;
    var sent_at: u64 = 0;
    var out: negotiate.Outbox = .{};
    var stream: ?engine_mod.StreamHandle = null;
    var state: enum { connecting, negotiating, pinging, closing, done } = .connecting;
    var events: [16]engine_mod.Event = undefined;
    var activity: [8]engine_mod.Handle = undefined;
    var outcomes: [1]negotiate.Outcome = undefined;
    var steps: u32 = 0;
    while (steps < dial_steps_max and state != .done) : (steps += 1) {
        const result = try node.step(io, &events, &activity, .{});
        for (events[0..result.events]) |event| switch (event) {
            .connected => |connected| {
                printPeer("connected", &connected.peer_id);
                stream = try negotiator.beginOutbound(&node.engine, handle, ping_protocol, result.now);
                state = .negotiating;
            },
            .closed => |closed| {
                std.debug.print("closed reason={s}\n", .{@tagName(closed.reason)});
                return error.ConnectionClosed;
            },
            .stream_opened => |opened| node.engine.closeStream(opened, 0),
            .path_changed => |changed| std.debug.print("path changed port={d}\n", .{changed.peer.port()}),
            .stream_closed => {},
        };
        if (state == .negotiating) {
            if (negotiator.pump(&node.engine, result.now, &outcomes) == 1) switch (outcomes[0].result) {
                .ready => |accepted| {
                    if (accepted.leftover.len != 0) return error.UnexpectedData;
                    sent_at = result.now.mono_ms;
                    out.queue(&payload, false);
                    state = .pinging;
                },
                .rejected => return error.ProtocolRejected,
                .failed => return error.NegotiationFailed,
            };
            if (state == .negotiating) continue;
        }
        const active = stream orelse continue;
        if (!try out.pump(&node.engine, active)) continue;
        if (state == .closing) {
            _ = node.engine.close(handle, 0);
            state = .done;
            continue;
        }
        if (state != .pinging) continue;
        var buffer: [read_max]u8 = undefined;
        const read = try node.engine.read(active, &buffer);
        if (read.len == 0) continue;
        const take = @min(read.len, ping_size - echoed);
        @memcpy(echo[echoed..][0..take], buffer[0..take]);
        echoed += take;
        if (echoed == ping_size) {
            if (!std.mem.eql(u8, &payload, &echo)) return error.PingMismatch;
            std.debug.print("ping rtt_ms={d}\n", .{result.now.mono_ms -| sent_at});
            out.queue("", true);
            state = .closing;
        }
    }
    if (state != .done) return error.Timeout;
    _ = try node.step(io, &events, &activity, .{});
}

fn printPeer(label: []const u8, id: *const peer_id.PeerId) void {
    var text: [peer_id.text_length_max]u8 = undefined;
    std.debug.print("{s} peer={s}\n", .{ label, id.toText(&text) });
}
