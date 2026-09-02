const std = @import("std");
const network = @import("network");

const constants = network.constants;
const driver_mod = network.driver;
const engine_mod = network.quic.engine;
const keys = network.identity.keys;
const multiaddr = network.identity.multiaddr;
const multistream = network.multistream;
const peer_id = network.identity.peer_id;
const runtime = network.runtime;
const tls = network.tls.context;
const types = network.types;

const ping_protocol = "/ipfs/ping/1.0.0";
const ping_size = 32;
const sessions_max = 8;
const dial_steps_max = 2_000;
const read_max = 256;
const session_write_max = multistream.listener_write_max + read_max;
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

const Node = struct {
    ctx: tls.Context = undefined,
    engine: engine_mod.Engine = undefined,
    udp: runtime.Udp = undefined,
    driver: driver_mod.Driver = undefined,

    fn init(self: *Node, allocator: std.mem.Allocator, io: std.Io, bind: std.Io.net.IpAddress) !void {
        const key = keys.KeyPair.generate(io);
        var serial: [8]u8 = undefined;
        try std.Io.randomSecure(io, &serial);
        self.ctx = try tls.Context.init(&key, (try driver_mod.currentTime(io)).unix_s, serial);
        errdefer self.ctx.deinit();
        self.engine = try engine_mod.Engine.init(allocator, &self.ctx, .{});
        errdefer self.engine.deinit();
        self.udp = try runtime.Udp.bind(io, bind);
        errdefer self.udp.close(io);
        self.driver = driver_mod.Driver.init(&self.engine, &self.udp);
    }

    fn deinit(self: *Node, io: std.Io) void {
        self.udp.close(io);
        self.engine.deinit();
        self.ctx.deinit();
    }
};

const Outbox = struct {
    bytes: []const u8 = &.{},
    offset: usize = 0,
    fin: bool = false,

    fn queue(self: *Outbox, bytes: []const u8, fin: bool) void {
        self.* = .{ .bytes = bytes, .offset = 0, .fin = fin };
    }

    fn pump(self: *Outbox, engine: *engine_mod.Engine, stream: engine_mod.StreamHandle) !bool {
        var attempts: u32 = 0;
        while (attempts < constants.send_burst_max) : (attempts += 1) {
            const remaining = self.bytes[self.offset..];
            if (remaining.len == 0 and !self.fin) return true;
            self.offset += engine.write(stream, remaining, self.fin) catch |err| switch (err) {
                error.WouldBlock => return false,
                else => return err,
            };
            if (self.offset == self.bytes.len) {
                self.fin = false;
                return true;
            }
        }
        return false;
    }
};

const Session = struct {
    stream: engine_mod.StreamHandle = undefined,
    listener: multistream.Listener = undefined,
    out: Outbox = .{},
    out_buffer: [session_write_max]u8 = undefined,
    negotiated: bool = false,
    closing: bool = false,
    active: bool = false,
};

fn listen(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16) !void {
    var node: Node = .{};
    try node.init(allocator, io, try std.Io.net.IpAddress.parseIp4(host, port));
    defer node.deinit(io);

    const local = multiaddr.Multiaddr{ .address = node.udp.localAddress(), .peer = node.ctx.local_peer_id };
    var text: [multiaddr.text_length_max]u8 = undefined;
    std.debug.print("{s}\n", .{try local.toText(&text)});

    var sessions = [_]Session{.{}} ** sessions_max;
    var events: [16]engine_mod.Event = undefined;
    while (true) {
        const result = try node.driver.step(io, &events);
        for (events[0..result.events]) |event| switch (event) {
            .connected => |connected| printPeer("connected", &connected.peer_id),
            .closed => |closed| {
                std.debug.print("closed reason={s}\n", .{@tagName(closed.reason)});
                for (&sessions) |*session| {
                    if (session.active and std.meta.eql(session.stream.conn, closed.conn)) session.active = false;
                }
            },
            .stream_opened => |stream| {
                const free = freeSession(&sessions) orelse {
                    node.engine.closeStream(stream, 0);
                    continue;
                };
                free.* = .{ .stream = stream, .listener = multistream.Listener.init(&supported), .active = true };
            },
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
    var buffer: [read_max]u8 = undefined;
    const read = try engine.read(session.stream, &buffer);
    if (read.len == 0 and !read.fin) return;
    var cursor: usize = 0;
    var length: usize = 0;
    if (!session.negotiated and read.len > 0) {
        var reply: [multistream.listener_write_max]u8 = undefined;
        const outcome = try session.listener.feed(buffer[0..read.len], &reply);
        switch (outcome.status) {
            .selected => session.negotiated = true,
            .failed => return error.NegotiationFailed,
            .pending => {},
        }
        cursor = outcome.consumed;
        @memcpy(session.out_buffer[0..outcome.write.len], outcome.write);
        length = outcome.write.len;
    }
    if (session.negotiated and cursor < read.len) {
        const echo = buffer[cursor..read.len];
        @memcpy(session.out_buffer[length..][0..echo.len], echo);
        length += echo.len;
    }
    session.closing = read.fin;
    session.out.queue(session.out_buffer[0..length], read.fin);
    if (try session.out.pump(engine, session.stream) and session.closing) session.active = false;
}

fn dial(allocator: std.mem.Allocator, io: std.Io, text: []const u8) !void {
    const target = try multiaddr.Multiaddr.parse(text);
    const expected = target.peer orelse return error.MissingPeerId;
    const bind: std.Io.net.IpAddress = switch (target.address) {
        .ip4 => .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .ip6 => .{ .ip6 = .{ .bytes = [_]u8{0} ** 16, .port = 0, .flow = 0, .interface = .{ .index = 0 } } },
    };
    var node: Node = .{};
    try node.init(allocator, io, bind);
    defer node.deinit(io);

    const handle = try node.driver.dial(io, target.address, expected);
    var dialer = try multistream.Dialer.init(ping_protocol);
    var payload: [ping_size]u8 = undefined;
    try std.Io.randomSecure(io, &payload);
    var echo: [ping_size]u8 = undefined;
    var echoed: usize = 0;
    var sent_at: u64 = 0;
    var hello: [2 * multistream.message_length_max]u8 = undefined;
    var out: Outbox = .{};
    var stream: ?engine_mod.StreamHandle = null;
    var state: enum { connecting, negotiating, pinging, closing, done } = .connecting;
    var events: [16]engine_mod.Event = undefined;
    var steps: u32 = 0;
    while (steps < dial_steps_max and state != .done) : (steps += 1) {
        const result = try node.driver.step(io, &events);
        for (events[0..result.events]) |event| switch (event) {
            .connected => |connected| {
                printPeer("connected", &connected.peer_id);
                stream = try node.engine.openStream(handle);
                out.queue(try dialer.initialWrite(&hello), false);
                state = .negotiating;
            },
            .closed => |closed| {
                std.debug.print("closed reason={s}\n", .{@tagName(closed.reason)});
                return error.ConnectionClosed;
            },
            .stream_opened => |opened| node.engine.closeStream(opened, 0),
        };
        const active = stream orelse continue;
        if (!try out.pump(&node.engine, active)) continue;
        if (state == .closing) {
            node.engine.close(handle, 0);
            state = .done;
            continue;
        }
        var buffer: [read_max]u8 = undefined;
        const read = try node.engine.read(active, &buffer);
        if (read.len == 0) continue;
        switch (state) {
            .negotiating => {
                const outcome = try dialer.feed(buffer[0..read.len]);
                switch (outcome.status) {
                    .accepted => {
                        sent_at = result.now.mono_ms;
                        out.queue(&payload, false);
                        _ = try out.pump(&node.engine, active);
                        state = .pinging;
                    },
                    .rejected => return error.ProtocolRejected,
                    .pending => {},
                }
            },
            .pinging => {
                const take = @min(read.len, ping_size - echoed);
                @memcpy(echo[echoed..][0..take], buffer[0..take]);
                echoed += take;
                if (echoed == ping_size) {
                    if (!std.mem.eql(u8, &payload, &echo)) return error.PingMismatch;
                    std.debug.print("ping rtt_ms={d}\n", .{result.now.mono_ms -| sent_at});
                    out.queue("", true);
                    state = .closing;
                }
            },
            else => {},
        }
    }
    if (state != .done) return error.Timeout;
    _ = try node.driver.step(io, &events);
}

fn printPeer(label: []const u8, id: *const peer_id.PeerId) void {
    var text: [peer_id.text_length_max]u8 = undefined;
    std.debug.print("{s} peer={s}\n", .{ label, id.toText(&text) });
}
