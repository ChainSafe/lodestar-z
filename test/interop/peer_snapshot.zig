const network = @import("network");
const control = @import("peer_control.zig");
const Peer = @import("network_peer.zig").Peer;

pub fn emit(peer: *Peer, id: u32) !void {
    const reqresp = peer.service.reqresp.active();
    const gossip = peer.service.gossipsub.resourceSnapshot();
    const transport = peer.transport.engine.counters;
    try control.emit(peer.allocator, .{
        .id = id,
        .ok = true,
        .connections = peer.transport.engine.driverView().activeIndices().len,
        .accepted = transport.accepted,
        .steps = peer.steps,
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
        .phase0 = @import("std").fmt.bytesToHex(network.gossipsub.topic.validMessageId(topic, "hello", phase0), .lower),
        .altair = @import("std").fmt.bytesToHex(network.gossipsub.topic.validMessageId(topic, "hello", .{}), .lower),
        .invalid = @import("std").fmt.bytesToHex(network.gossipsub.topic.invalidMessageId(topic, &.{0xff}, .{}), .lower),
        .other = @import("std").fmt.bytesToHex(network.gossipsub.topic.validMessageId(other, "hello", .{}), .lower),
    });
}
