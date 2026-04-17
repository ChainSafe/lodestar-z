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
                processValidatedMessage(self, io, p2p, peer, msg.msg_id, msg.topic, parsed, fork_seq, msg.data, metadata);
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
    msg_id: []const u8,
    topic: []const u8,
    parsed: networking.GossipTopic,
    fork_seq: config_mod.ForkSeq,
    data: []const u8,
    metadata: GossipIngressMetadata,
) void {
    const gh = self.gossip_handler orelse {
        _ = p2p.reportGossipValidationResult(io, msg_id, .ignore);
        return;
    };

    const slot = currentNetworkSlot(self, io);
    gh.updateClock(slot, computeEpochAtSlot(slot), self.currentFinalizedSlot());
    gh.updateForkSeq(fork_seq);
    switch (gh.processGossipMessageWithSubnetAndMetadata(parsed.topic_type, parsed.subnet_id, data, metadata)) {
        .accepted => {
            _ = p2p.reportGossipValidationResult(io, msg_id, .accept);
        },
        .deferred => {
            self.beginPendingGossipValidation(metadata.message_id, peer, topic) catch |err| {
                _ = p2p.reportGossipValidationResult(io, msg_id, .ignore);
                scoped_log.warn("failed to track deferred gossip validation: {}", .{err});
            };
        },
        .ignored => {
            _ = p2p.reportGossipValidationResult(io, msg_id, .ignore);
        },
        .rejected => |reason| {
            self.handleGossipReject(io, p2p, peer, topic, reason);
            _ = p2p.reportGossipValidationResult(io, msg_id, .reject);
            scoped_log.debug(
                "Gossip {s} rejected ({s}) fork_seq={s} subnet={?d} topic={s} payload_len={d}",
                .{
                    parsed.topic_type.topicName(),
                    @tagName(reason),
                    @tagName(fork_seq),
                    parsed.subnet_id,
                    topic,
                    data.len,
                },
            );
        },
        .failed => |err| {
            _ = p2p.reportGossipValidationResult(io, msg_id, .ignore);
            scoped_log.debug(
                "gossip {s} error: {} fork_seq={s} subnet={?d} topic={s} payload_len={d}",
                .{ parsed.topic_type.topicName(), err, @tagName(fork_seq), parsed.subnet_id, topic, data.len },
            );
        },
    }
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
