const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Address = Io.net.IpAddress;

const enr_mod = @import("../enr.zig");
const protocol_mod = @import("../protocol.zig");

pub const NodeId = enr_mod.NodeId;

pub const LookupFinishedEvent = struct {
    lookup_id: u32,
    target: NodeId,
    enrs: [][]u8,
    timed_out: bool,

    pub fn deinit(self: *LookupFinishedEvent, alloc: Allocator) void {
        for (self.enrs) |enr| alloc.free(enr);
        alloc.free(self.enrs);
    }
};

pub const DiscoveredEnrEvent = struct {
    raw: enr_mod.RawEnr,
    enr: enr_mod.Enr,

    pub fn deinit(_: *DiscoveredEnrEvent, _: Allocator) void {}
};

pub const EnrAddedEvent = struct {
    node_id: NodeId,
    addr: Address,
    enr: []u8,
    replaced_enr: ?[]u8 = null,

    pub fn deinit(self: *EnrAddedEvent, alloc: Allocator) void {
        alloc.free(self.enr);
        if (self.replaced_enr) |replaced| alloc.free(replaced);
    }
};

pub const LocalEnrUpdatedEvent = struct {
    seq: u64,
    enr: []u8,

    pub fn deinit(self: *LocalEnrUpdatedEvent, alloc: Allocator) void {
        alloc.free(self.enr);
    }
};

pub const PeerConnectedEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
};

pub const PeerDisconnectedEvent = struct {
    peer_id: NodeId,
    peer_addr: Address,
};

pub const EventKind = enum {
    discovered,
    enr_added,
    multiaddr_updated,
    talk_req_received,
    talk_resp_received,
    session_established,
    request_failed,
    response_received,
    lookup_finished,
    peer_disconnected,
};

pub const Event = union(enum) {
    pong: protocol_mod.PongEvent,
    nodes: protocol_mod.NodesEvent,
    talkreq: protocol_mod.TalkReqEvent,
    talkresp: protocol_mod.TalkRespEvent,
    request_timeout: protocol_mod.RequestTimeoutEvent,
    discovered_enr: DiscoveredEnrEvent,
    enr_added: EnrAddedEvent,
    lookup_finished: LookupFinishedEvent,
    local_enr_updated: LocalEnrUpdatedEvent,
    peer_connected: PeerConnectedEvent,
    peer_disconnected: PeerDisconnectedEvent,

    pub fn kind(self: *const Event) EventKind {
        return switch (self.*) {
            .discovered_enr => .discovered,
            .enr_added => .enr_added,
            .local_enr_updated => .multiaddr_updated,
            .talkreq => .talk_req_received,
            .talkresp => .talk_resp_received,
            .peer_connected => .session_established,
            .request_timeout => .request_failed,
            .pong, .nodes => .response_received,
            .lookup_finished => .lookup_finished,
            .peer_disconnected => .peer_disconnected,
        };
    }

    pub fn tsEventName(self: *const Event) []const u8 {
        return switch (self.kind()) {
            .discovered => "discovered",
            .enr_added => "enrAdded",
            .multiaddr_updated => "multiaddrUpdated",
            .talk_req_received => "talkReqReceived",
            .talk_resp_received => "talkRespReceived",
            .session_established => "established",
            .request_failed => "requestFailed",
            .response_received => "response",
            .lookup_finished => "lookupFinished",
            .peer_disconnected => "disconnected",
        };
    }

    pub fn deinit(self: *Event, alloc: Allocator) void {
        switch (self.*) {
            // Events that own no heap memory.
            .pong, .request_timeout, .peer_connected, .peer_disconnected => {},
            // The remaining payloads own their deinit; call it directly rather
            // than round-tripping through a reconstructed protocol_mod.Event.
            .nodes => |*nodes| nodes.deinit(alloc),
            .talkreq => |*talkreq| talkreq.deinit(alloc),
            .talkresp => |*talkresp| talkresp.deinit(alloc),
            .discovered_enr => |*discovered_enr| discovered_enr.deinit(alloc),
            .enr_added => |*enr_added| enr_added.deinit(alloc),
            .lookup_finished => |*lookup_finished| lookup_finished.deinit(alloc),
            .local_enr_updated => |*local_enr_updated| local_enr_updated.deinit(alloc),
        }
    }
};
