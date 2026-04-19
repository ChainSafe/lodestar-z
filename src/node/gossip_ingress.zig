//! Node-owned inbound gossip routing.
//!
//! Keeps topic parsing, fork resolution, and invalid-message feedback out of
//! the main P2P runtime loop.

const std = @import("std");
const scoped_log = std.log.scoped(.gossip_ingress);

const config_mod = @import("config");
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const networking = @import("networking");
const processor = @import("processor");

const BeaconNode = @import("beacon_node.zig").BeaconNode;
const GossipIngressMetadata = @import("gossip_handler.zig").GossipIngressMetadata;
const MessageId = processor.work_item.MessageId;
const WorkItem = processor.WorkItem;
const GossipWork = processor.work_item.GossipWork;
const OwnedSszBytes = processor.work_item.OwnedSszBytes;
const GossipDataHandle = processor.work_item.GossipDataHandle;
const PeerIdHandle = processor.PeerIdHandle;

pub fn processEvents(self: *BeaconNode, io: std.Io, p2p: *networking.P2pService) usize {
    const events = p2p.drainGossipEvents(io) catch |err| {
        scoped_log.debug("failed to drain gossip events: {}", .{err});
        return 0;
    };
    defer {
        for (events) |*event| event.deinit(self.allocator);
        self.allocator.free(events);
    }

    var processed_messages: usize = 0;

    for (events) |event| {
        switch (event) {
            .message => |msg| {
                processed_messages += 1;
                const peer = optionalPeerId(msg.peer_id);
                const metadata = GossipIngressMetadata{
                    .source = processor.work_item.GossipSource.fromOpaqueBytes(0x70656572, peer),
                    .message_id = gossipMessageIdFromBytes(msg.msg_id),
                    .seen_timestamp_ns = currentUnixTimeNs(io),
                    .peer_id = peer,
                };

                const parsed = networking.gossip_topics.parseTopic(msg.topic) orelse {
                    recordInvalidMessage(io, p2p, peer, msg.topic);
                    _ = p2p.reportGossipValidationResult(io, msg.msg_id, .reject);
                    continue;
                };
                const fork_seq = resolveForkSeq(self, io, parsed) orelse {
                    _ = p2p.reportGossipValidationResult(io, msg.msg_id, .ignore);
                    continue;
                };
                enqueueValidatedMessage(self, io, p2p, peer, parsed, fork_seq, msg.data, metadata);
            },
            else => {},
        }
    }

    return processed_messages;
}

fn enqueueValidatedMessage(
    self: *BeaconNode,
    io: std.Io,
    p2p: *networking.P2pService,
    peer: ?[]const u8,
    parsed: networking.GossipTopic,
    fork_seq: config_mod.ForkSeq,
    data: []const u8,
    metadata: GossipIngressMetadata,
) void {
    const bp = self.beacon_processor orelse {
        _ = p2p.reportGossipValidationResult(io, &metadata.message_id, .ignore);
        return;
    };
    const gossip_work = makeGossipWork(self, peer, parsed, fork_seq, data, metadata) catch |err| {
        _ = p2p.reportGossipValidationResult(io, &metadata.message_id, .ignore);
        scoped_log.warn("failed to queue gossip work {s}: {}", .{ parsed.topic_type.topicName(), err });
        return;
    };
    bp.ingestGossipWork(gossipWorkItem(parsed.topic_type, gossip_work));
}

fn makeGossipWork(
    self: *BeaconNode,
    peer: ?[]const u8,
    parsed: networking.GossipTopic,
    fork_seq: config_mod.ForkSeq,
    data: []const u8,
    metadata: GossipIngressMetadata,
) !GossipWork {
    const peer_id = if (peer) |peer_id_bytes|
        try PeerIdHandle.initOwned(self.allocator, peer_id_bytes)
    else
        PeerIdHandle.none;
    errdefer {
        var owned_peer_id = peer_id;
        owned_peer_id.deinit();
    }

    const owned_data = try self.allocator.create(OwnedSszBytes);
    errdefer self.allocator.destroy(owned_data);
    owned_data.* = try OwnedSszBytes.dupe(self.allocator, data);
    errdefer owned_data.deinit();

    return .{
        .source = metadata.source,
        .message_id = metadata.message_id,
        .peer_id = peer_id,
        .subnet_id = parsed.subnet_id,
        .fork_digest = parsed.fork_digest,
        .fork_seq = fork_seq,
        .data = GossipDataHandle.initOwned(OwnedSszBytes, owned_data),
        .seen_timestamp_ns = metadata.seen_timestamp_ns,
    };
}

fn gossipWorkItem(topic_type: networking.GossipTopicType, work: GossipWork) WorkItem {
    return switch (topic_type) {
        .beacon_block => .{ .gossip_block_ingress = work },
        .blob_sidecar => .{ .gossip_blob_ingress = work },
        .data_column_sidecar => .{ .gossip_data_column_ingress = work },
        .beacon_attestation => .{ .gossip_attestation_ingress = work },
        .beacon_aggregate_and_proof => .{ .gossip_aggregate_ingress = work },
        .sync_committee_contribution_and_proof => .{ .gossip_sync_contribution_ingress = work },
        .sync_committee => .{ .gossip_sync_message_ingress = work },
        .voluntary_exit => .{ .gossip_voluntary_exit_ingress = work },
        .proposer_slashing => .{ .gossip_proposer_slashing_ingress = work },
        .attester_slashing => .{ .gossip_attester_slashing_ingress = work },
        .bls_to_execution_change => .{ .gossip_bls_to_exec_ingress = work },
    };
}

fn gossipMessageIdFromBytes(bytes: []const u8) MessageId {
    var out = std.mem.zeroes(MessageId);
    const len = @min(out.len, bytes.len);
    @memcpy(out[0..len], bytes[0..len]);
    return out;
}

fn recordInvalidMessage(io: std.Io, p2p: *networking.P2pService, peer: ?[]const u8, topic: []const u8) void {
    if (peer) |peer_id| p2p.recordInvalidGossipMessage(io, peer_id, topic);
}

fn resolveForkSeq(self: *BeaconNode, io: std.Io, parsed: networking.GossipTopic) ?config_mod.ForkSeq {
    const slot = currentNetworkSlot(self, io);
    const epoch = computeEpochAtSlot(slot);
    return self.config.forkSeqForGossipDigestAtEpoch(epoch, parsed.fork_digest, self.genesis_validators_root);
}

fn optionalPeerId(peer_id: []const u8) ?[]const u8 {
    return if (peer_id.len == 0) null else peer_id;
}

fn currentNetworkSlot(self: *BeaconNode, io: std.Io) u64 {
    if (self.clock) |clock| {
        if (clock.currentSlot(io)) |slot| return slot;
    }
    return self.currentHeadSlot();
}

fn currentUnixTimeNs(io: std.Io) i64 {
    const ns = std.Io.Timestamp.now(io, .real).toNanoseconds();
    return if (ns > std.math.maxInt(i64))
        std.math.maxInt(i64)
    else if (ns < std.math.minInt(i64))
        std.math.minInt(i64)
    else
        @intCast(ns);
}
