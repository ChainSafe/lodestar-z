const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Address = Io.net.IpAddress;

const messages = @import("message.zig");
const request_tracker = @import("request_tracker.zig");
const NodeId = @import("../enr.zig").NodeId;

pub const PongEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
    req_id: messages.ReqId,
    enr_seq: u64,
    recipient_ip: messages.Pong.RecipientIp,
    recipient_port: u16,
};

pub const NodesEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
    req_id: messages.ReqId,
    enrs: [][]u8,

    pub fn deinit(self: *NodesEvent, alloc: Allocator) void {
        for (self.enrs) |enr| alloc.free(enr);
        alloc.free(self.enrs);
    }
};

pub const TalkReqEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
    req_id: messages.ReqId,
    protocol: []u8,
    request: []u8,

    pub fn deinit(self: *TalkReqEvent, alloc: Allocator) void {
        alloc.free(self.protocol);
        alloc.free(self.request);
    }
};

pub const TalkRespEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
    req_id: messages.ReqId,
    response: []u8,

    pub fn deinit(self: *TalkRespEvent, alloc: Allocator) void {
        alloc.free(self.response);
    }
};

pub const RequestTimeoutEvent = struct {
    peer_id: NodeId,
    req_id: messages.ReqId,
    kind: request_tracker.RequestKind,
};

pub const Event = union(enum) {
    pong: PongEvent,
    nodes: NodesEvent,
    talkreq: TalkReqEvent,
    talkresp: TalkRespEvent,
    request_timeout: RequestTimeoutEvent,

    pub fn deinit(self: *Event, alloc: Allocator) void {
        switch (self.*) {
            .pong => {},
            .nodes => |*nodes| nodes.deinit(alloc),
            .talkreq => |*talkreq| talkreq.deinit(alloc),
            .talkresp => |*talkresp| talkresp.deinit(alloc),
            .request_timeout => {},
        }
    }
};
