const network = @import("network");
const control = @import("peer_control.zig");
const Peer = @import("network_peer.zig").Peer;

pub fn emit(peer: *Peer, id: u32) !void {
    const reqresp = peer.service.reqresp.active();
    const gossip = peer.service.gossipsub.resourceSnapshot();
    const transport = peer.transport.engine.counters;
    var streams: usize = 0;
    for (peer.transport.engine.driverView().activeIndices()) |index| {
        for (peer.transport.engine.registry.slots[index].table.entries) |entry| {
            if (entry.claimed) streams += 1;
        }
    }
    var negotiations: usize = 0;
    for (peer.service.router.negotiator.entries) |entry| {
        if (entry.state != .free) negotiations += 1;
    }
    var inbound_version: ?[]const u8 = null;
    var outbound_version: ?[]const u8 = null;
    for (peer.service.gossipsub.inner.state.peers) |entry| {
        if (!entry.active) continue;
        if (entry.in_stream != null) inbound_version = @tagName(entry.inbound_version);
        if (entry.out_stream != null) outbound_version = @tagName(entry.version);
    }
    try control.emit(peer.allocator, .{
        .id = id,
        .ok = true,
        .connections = peer.transport.engine.driverView().activeIndices().len,
        .accepted = transport.accepted,
        .streams = streams,
        .heldFin = peer.held_finish != null,
        .finishCalls = peer.finish_calls,
        .negotiations = negotiations,
        .inboundVersion = inbound_version,
        .outboundVersion = outbound_version,
        .rpcsReceived = peer.service.gossipsub.inner.counters.rpcs_received,
        .duplicates = peer.service.gossipsub.inner.counters.duplicates,
        .steps = peer.steps,
        .connectionIndex = if (peer.conn) |conn| @as(?u16, conn.index) else null,
        .connectionDirection = if (peer.conn) |conn| if (peer.transport.engine.direction(conn)) |direction| @as(?[]const u8, @tagName(direction)) else null else null,
        .connectionGeneration = if (peer.conn) |conn| @as(?u32, conn.generation) else null,
        .malformedRpcs = peer.service.gossipsub.inner.counters.malformed_rpcs,
        .droppedUnroutable = transport.dropped_unroutable,
        .droppedFull = transport.dropped_full,
        .droppedNoEntropy = transport.dropped_no_entropy,
        .recvErrors = transport.recv_errors,
        .gossipPeers = gossip.admitted_peers,
        .remoteSubscriptions = gossip.remote_subscriptions,
        .meshMembers = gossip.mesh_members,
        .reqrespOutbound = reqresp.outbound,
        .reqrespInbound = reqresp.inbound,
        .gossipDescriptors = gossip.queued_descriptors,
        .gossipQueuedBytes = gossip.queued_bytes,
        .heldFrames = gossip.held_frames,
        .txRetains = gossip.held_tx_retains,
        .storeEntries = gossip.store_entries,
        .storePages = gossip.store_pages,
        .pendingValidations = gossip.pending_validations,
        .promises = gossip.promises,
        .emitted = peer.emitted,
    });
}

pub fn ids(a: @import("std").mem.Allocator, id: u32) !void {
    const topic = "/eth2/01000000/beacon_block/ssz_snappy";
    const other = "/eth2/01000000/voluntary_exit/ssz_snappy";
    const phase0 = network.gossipsub.topic.MessageIdPolicy{ .phase0_digest = .{ 1, 0, 0, 0 } };
    try control.emit(a, .{
        .id = id,
        .ok = true,
        .phase0Other = @import("std").fmt.bytesToHex(network.gossipsub.topic.validMessageId(other, "hello", phase0), .lower),
        .phase0 = @import("std").fmt.bytesToHex(network.gossipsub.topic.validMessageId(topic, "hello", phase0), .lower),
        .altair = @import("std").fmt.bytesToHex(network.gossipsub.topic.validMessageId(topic, "hello", .{}), .lower),
        .invalid = @import("std").fmt.bytesToHex(network.gossipsub.topic.invalidMessageId(topic, &.{0xff}, .{}), .lower),
        .other = @import("std").fmt.bytesToHex(network.gossipsub.topic.validMessageId(other, "hello", .{}), .lower),
    });
}
