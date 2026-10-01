//! Control RPC mechanics: the Status, Metadata, Ping and Goodbye requests the node sends to its
//! peers and the responses it serves them. This module encodes, submits, matches, consumes,
//! cancels and retires them in bounded storage. Peer control decides what to send and what a reply
//! means; the owner executes both, so this module changes no peer state and closes no connection.

const std = @import("std");
const t = @import("types.zig");
const values = @import("control_values.zig");
const wire = @import("control_wire.zig");
const rr = @import("reqresp/root.zig");
const Router = @import("router.zig").Router;
const Engine = @import("quic/Engine.zig");
const Now = @import("types.zig").Now;
const assert = std.debug.assert;
/// An `operation_by_peer` entry with no request in flight.
const no_operation = std.math.maxInt(u16);
const RequestEvent = @FieldType(rr.ReqResp.Event, "request");

pub const Probe = wire.Probe;
pub const Operation = struct {
    request: ?rr.ReqResp.RequestHandle = null,
    peer: t.PeerRef = undefined,
    conn: t.Handle = undefined,
    protocol: rr.Protocol = .ping_v1,
    cancelled: bool = false,
    received: bool = false,
    /// Started after the connection's Status and Metadata exchange, so its success proves health.
    after_ready: bool = false,
    bytes: [wire.status_size_max]u8 = undefined,
    sink: [wire.status_size_max]u8 = undefined,

    pub fn reply(self: *const Operation) wire.ControlReply {
        return .{ .peer = self.peer, .conn = self.conn, .request = self.request, .protocol = self.protocol, .cancelled = self.cancelled, .received = self.received, .after_ready = self.after_ready };
    }
};
const Response = struct {
    request: ?rr.ReqResp.RequestHandle = null,
    peer: t.PeerRef = undefined,
    conn: t.Handle = undefined,
    bytes: [wire.status_size_max]u8 = undefined,
};

pub const ControlProtocol = struct {
    operations: []Operation,
    responses: []Response,
    /// Per catalog index, the operation whose request is in flight for that index, or
    /// `no_operation`. A replacement owner of the index waits for that request's terminal event.
    operation_by_peer: []u16,

    pub fn init(
        a: std.mem.Allocator,
        peer_capacity: u16,
        connected_capacity: u16,
        inbound_capacity: u16,
    ) !ControlProtocol {
        if (connected_capacity == 0 or connected_capacity > peer_capacity or connected_capacity > 256)
            return error.InvalidOptions;
        const operations = try a.alloc(Operation, connected_capacity);
        errdefer a.free(operations);
        const responses = try a.alloc(Response, inbound_capacity);
        errdefer a.free(responses);
        const operation_by_peer = try a.alloc(u16, peer_capacity);
        @memset(operations, .{});
        @memset(responses, .{});
        @memset(operation_by_peer, no_operation);
        return .{
            .operations = operations,
            .responses = responses,
            .operation_by_peer = operation_by_peer,
        };
    }
    pub fn deinit(self: *ControlProtocol, a: std.mem.Allocator) void {
        a.free(self.operation_by_peer);
        a.free(self.responses);
        a.free(self.operations);
        self.* = undefined;
    }

    /// Whether a request holds the catalog index's operation, including a replaced connection's
    /// cancelled request that has not reached its terminal event.
    pub fn busy(self: *const ControlProtocol, index: usize) bool {
        return self.operation_by_peer[index] != no_operation;
    }

    /// Encodes the probe into a free operation and submits it, returning its token when it starts. The
    /// operation's buffers stay immutable until the request's terminal event retires it.
    pub fn start(
        self: *ControlProtocol,
        reqresp: *rr.ReqResp,
        router: *Router,
        engine: *Engine,
        peer: t.PeerRef,
        conn: t.Handle,
        probe: *const Probe,
        local: *const values.LocalState,
        now: Now,
    ) ?rr.ReqResp.RequestHandle {
        assert(self.operation_by_peer[peer.index] == no_operation);
        defer if (@import("builtin").is_test) self.checkIndex();
        for (self.operations, 0..) |*op, index| {
            if (op.request != null) continue;
            const len = switch (probe.protocol) {
                .status_v1, .status_v2 => wire.encodeStatus(
                    probe.protocol,
                    &local.status,
                    &op.bytes,
                ) catch return null,
                .ping_v1, .goodbye_v1 => wire.encodeScalar(
                    if (probe.protocol == .ping_v1) local.metadata.seq_number else probe.code,
                    &op.bytes,
                ) catch unreachable,
                .metadata_v1, .metadata_v2, .metadata_v3 => 0,
                else => unreachable,
            };
            const request = reqresp.request(
                engine,
                router,
                conn,
                probe.protocol,
                op.bytes[0..len],
                &op.sink,
                .{},
                now,
            ) catch return null;
            op.peer = peer;
            op.conn = conn;
            op.protocol = probe.protocol;
            op.cancelled = false;
            op.received = false;
            op.after_ready = probe.after_ready;
            op.request = request;
            self.operation_by_peer[peer.index] = @intCast(index);
            return request;
        }
        return null;
    }

    /// Cancels the peer's in-flight request on this connection. Its operation stays held until
    /// the request's terminal event.
    pub fn cancel(self: *ControlProtocol, reqresp: *rr.ReqResp, peer: t.PeerRef, conn: t.Handle, now: Now) void {
        if (peer.index >= self.operation_by_peer.len) return;
        const index = self.operation_by_peer[peer.index];
        if (index == no_operation) return;
        const op = &self.operations[index];
        if (!std.meta.eql(op.peer, peer) or !std.meta.eql(op.conn, conn)) return;
        op.cancelled = true;
        _ = reqresp.cancel(op.request.?, now);
    }

    /// Cancels the connection's in-flight request and the responses it is being served, and
    /// closes their streams.
    pub fn cancelConnection(
        self: *ControlProtocol,
        reqresp: *rr.ReqResp,
        router: *Router,
        engine: *Engine,
        peer: t.PeerRef,
        conn: t.Handle,
        now: Now,
    ) void {
        self.cancel(reqresp, peer, conn, now);
        for (self.responses) |*response| if (response.request) |request| {
            if (std.meta.eql(response.peer, peer) and std.meta.eql(response.conn, conn)) {
                _ = reqresp.cancel(request, now);
            }
        };
        reqresp.cleanupPending(engine, router);
    }

    /// Answers a peer's control request from the local state, or cancels a request it cannot
    /// answer. The response bytes stay immutable until reqresp reports them served or failed.
    pub fn respond(
        self: *ControlProtocol,
        reqresp: *rr.ReqResp,
        peer: t.PeerRef,
        event: *const RequestEvent,
        local: *const values.LocalState,
        now: Now,
    ) void {
        const response = available: {
            for (self.responses) |*candidate| if (candidate.request == null) break :available candidate;
            unreachable;
        };
        response.peer = peer;
        response.conn = event.peer;
        const len: usize = switch (event.protocol) {
            .status_v1, .status_v2 => wire.encodeStatus(event.protocol, &local.status, &response.bytes) catch {
                _ = reqresp.cancel(event.request, now);
                return;
            },
            .ping_v1 => blk: {
                _ = wire.decodeScalar(event.bytes) catch {
                    _ = reqresp.cancel(event.request, now);
                    return;
                };
                break :blk wire.encodeScalar(local.metadata.seq_number, &response.bytes) catch unreachable;
            },
            .metadata_v1, .metadata_v2, .metadata_v3 => wire.encodeMetadata(
                event.protocol,
                &local.metadata,
                local.fork,
                &response.bytes,
            ) catch {
                _ = reqresp.cancel(event.request, now);
                return;
            },
            .goodbye_v1 => wire.encodeScalar(1, &response.bytes) catch unreachable,
            else => unreachable,
        };
        reqresp.respond(event.request, response.bytes[0..len], null, now) catch {
            _ = reqresp.cancel(event.request, now);
            return;
        };
        response.request = event.request;
    }

    /// Settles a result for a response this module serves, or returns the operation an outbound
    /// result belongs to. Peer control reads that operation before `settle` consumes or retires it.
    pub fn result(self: *ControlProtocol, reqresp: *rr.ReqResp, event: rr.ReqResp.Event, now: Now) ?u16 {
        const request = switch (event) {
            .chunk => |e| e.request,
            .done => |e| e.request,
            .failed => |e| e.request,
            .chunk_sent => |e| e.request,
            .served => |e| e.request,
            else => unreachable,
        };
        if (request.direction == .inbound) {
            const response = matching: {
                for (self.responses) |*candidate| if (std.meta.eql(candidate.request, request)) break :matching candidate;
                return null;
            };
            switch (event) {
                .chunk_sent => {
                    _ = reqresp.finish(request, now);
                },
                .served, .failed => response.request = null,
                else => {},
            }
            return null;
        }
        for (self.operations, 0..) |*op, index| {
            if (std.meta.eql(op.request, request)) return @intCast(index);
        }
        return null;
    }

    /// Consumes the operation's reply chunk, or retires the operation at its terminal event and
    /// frees its peer's index. Peer policy observes the matching outcome before this call.
    pub fn settle(
        self: *ControlProtocol,
        reqresp: *rr.ReqResp,
        router: *Router,
        engine: *Engine,
        index: u16,
        event: rr.ReqResp.Event,
        now: Now,
    ) void {
        const op = &self.operations[index];
        switch (event) {
            .chunk => {
                _ = reqresp.consume(op.request.?, now);
                op.received = true;
            },
            .done, .failed => {
                reqresp.cleanupPending(engine, router);
                op.request = null;
                assert(self.operation_by_peer[op.peer.index] == index);
                self.operation_by_peer[op.peer.index] = no_operation;
                if (@import("builtin").is_test) self.checkIndex();
            },
            else => {},
        }
    }

    /// Test builds check that the index names exactly the operations holding a request.
    fn checkIndex(self: *const ControlProtocol) void {
        var in_flight: usize = 0;
        for (self.operations, 0..) |*op, index| if (op.request != null) {
            in_flight += 1;
            assert(self.operation_by_peer[op.peer.index] == index);
        };
        var indexed: usize = 0;
        for (self.operation_by_peer) |entry| indexed += @intFromBool(entry != no_operation);
        assert(in_flight == indexed);
    }
};
