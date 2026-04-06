//! Node-owned inbound gossip routing.
//!
//! Keeps topic parsing, fork resolution, and invalid-message feedback out of
//! the main P2P runtime loop.

const std = @import("std");

const config_mod = @import("config");
const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const networking = @import("networking");
const processor = @import("processor");

const BeaconNode = @import("beacon_node.zig").BeaconNode;
const GossipIngressMetadata = @import("gossip_handler.zig").GossipIngressMetadata;

pub fn processEvents(self: *BeaconNode, io: std.Io, p2p: *networking.P2pService) usize {
    const events = p2p.drainGossipEvents() catch |err| {
        std.log.warn("Failed to drain gossip events: {}", .{err});
        return 0;
    };
    defer self.allocator.free(events);

    var processed_messages: usize = 0;

    for (events) |event| {
        switch (event) {
            .message => |msg| {
                processed_messages += 1;
                const metadata = GossipIngressMetadata{
                    .source = processor.work_item.GossipSource.fromOpaqueBytes(0x70656572, msg.from),
                    .message_id = networking.computeGossipMessageId(self.allocator, msg.data) catch std.mem.zeroes(networking.GossipMessageId),
                    .seen_timestamp_ns = currentUnixTimeNs(io),
                };

                const parsed = networking.gossip_topics.parseTopic(msg.topic) orelse {
                    recordInvalidMessage(p2p, msg.from, msg.topic);
                    continue;
                };
                const fork_seq = resolveForkSeq(self, io, parsed) orelse continue;
                processValidatedMessage(self, io, p2p, msg.from, msg.topic, parsed, fork_seq, msg.data, metadata);
            },
            else => {},
        }
    }

    return processed_messages;
}

fn processValidatedMessage(
    self: *BeaconNode,
    io: std.Io,
    p2p: *networking.P2pService,
    peer: ?[]const u8,
    topic: []const u8,
    parsed: networking.GossipTopic,
    fork_seq: config_mod.ForkSeq,
    data: []const u8,
    metadata: GossipIngressMetadata,
) void {
    if (self.gossip_handler) |gh| {
        const slot = currentNetworkSlot(self, io);
        gh.updateClock(slot, computeEpochAtSlot(slot), self.currentFinalizedSlot());
        gh.updateForkSeq(fork_seq);
        switch (gh.processGossipMessageWithSubnetAndMetadata(parsed.topic_type, parsed.subnet_id, data, metadata)) {
            .accepted, .ignored => {},
            .rejected => |reason| {
                recordInvalidMessage(p2p, peer, topic);
                applyGossipPenalty(self, io, p2p, peer, reason);
                std.log.debug("Gossip {s} rejected ({s})", .{ parsed.topic_type.topicName(), @tagName(reason) });
            },
            .failed => |err| {
                std.log.warn("Gossip {s} error: {}", .{ parsed.topic_type.topicName(), err });
            },
        }
    }
}

fn resolveForkSeq(self: *BeaconNode, io: std.Io, parsed: networking.GossipTopic) ?config_mod.ForkSeq {
    const slot = currentNetworkSlot(self, io);
    const epoch = computeEpochAtSlot(slot);
    return self.config.forkSeqForGossipDigestAtEpoch(epoch, parsed.fork_digest, self.genesis_validators_root);
}

fn recordInvalidMessage(p2p: *networking.P2pService, peer: ?[]const u8, topic: []const u8) void {
    if (peer) |peer_id| p2p.recordInvalidGossipMessage(peer_id, topic);
}

fn applyGossipPenalty(
    self: *BeaconNode,
    io: std.Io,
    p2p: *networking.P2pService,
    peer: ?[]const u8,
    reason: networking.peer_scoring.GossipRejectReason,
) void {
    const peer_id = peer orelse return;
    const pm = self.peer_manager orelse return;
    const action = networking.peer_scoring.gossipFailureAction(reason);
    const state = pm.reportPeer(peer_id, action, .gossipsub, currentUnixTimeMs(io)) orelse return;
    switch (state) {
        .healthy => {},
        .disconnected, .banned => {
            _ = p2p.disconnectPeer(io, peer_id);
        },
    }
}

fn currentNetworkSlot(self: *BeaconNode, io: std.Io) u64 {
    if (self.clock) |clock| {
        if (clock.currentSlot(io)) |slot| return slot;
    }
    return self.currentHeadSlot();
}

fn currentUnixTimeMs(io: std.Io) u64 {
    const ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    return if (ms < 0) 0 else @intCast(ms);
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
