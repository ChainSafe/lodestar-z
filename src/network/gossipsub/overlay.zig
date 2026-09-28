const std = @import("std");
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const topic_policy = @import("topic_policy.zig");
const score_mod = @import("score.zig");
const local_intent = @import("local_intent.zig");
const prom = @import("../metrics/registry.zig");
const Sessions = @import("sessions.zig").Sessions;
const PeerSet = @import("sessions.zig").PeerSet;
const assert = std.debug.assert;

const c = constants;
const Set = PeerSet;

pub const Context = struct {
    sessions: *Sessions,
    peers: *@import("peer_book.zig").PeerBook,
    options: *const @import("options.zig").Options,
    now: u64,
    snapshot: ?*const @import("heartbeat_cycle.zig").Scores = null,
};

pub const Row = struct {
    retire_after_ms: ?u64 = null,
    generation: u64 = 0,
    active: bool = false,
    subscribed: bool = false,
    ordinal: ?u16 = null,
    kind: ?topic_mod.Kind = null,
    string: [topic_mod.topic_max_len]u8 = undefined,
    string_len: u8 = 0,
    subscribers: PeerSet = PeerSet.initEmpty(),
    mesh: PeerSet = PeerSet.initEmpty(),
    fanout: PeerSet = PeerSet.initEmpty(),
    fanout_last_ms: u64 = 0,

    fn topicString(self: *const Row) []const u8 {
        return self.string[0..self.string_len];
    }
};

/// Why a peer joined or left a topic mesh. Each reason implies its event.
const MeshReason = enum {
    fill_mesh,
    fill_outbound,
    opportunistic,
    remote_graft,
    ineligible,
    excess,
    remote_prune,
    local_unsubscribe,
    remote_unsubscribe,
    session_end,
    direct_peer,
    refused_graft,

    fn event(self: MeshReason) enum { join, leave } {
        return switch (self) {
            .fill_mesh, .fill_outbound, .opportunistic, .remote_graft => .join,
            .ineligible, .excess, .remote_prune, .local_unsubscribe, .remote_unsubscribe, .session_end, .direct_peer, .refused_graft => .leave,
        };
    }
};

/// Committed mesh membership changes by topic kind and reason. GRAFT and PRUNE controls that
/// change no membership do not count.
pub const MeshChanges = struct {
    counts: [topic_policy.kind_count + 1][std.meta.fields(MeshReason).len]u64 = @splat(@splat(0)),

    fn record(self: *MeshChanges, kind: ?topic_mod.Kind, reason: MeshReason) void {
        const index = if (kind) |known| @intFromEnum(known) else topic_policy.kind_count;
        self.counts[index][@intFromEnum(reason)] +|= 1;
    }

    pub fn write(self: *const MeshChanges, w: *prom.Encoder) prom.Error!void {
        const changes = try w.family(.{
            .name = "lodestar_native_gossip_mesh_changes_total",
            .kind = .counter,
            .help = "Committed mesh joins and leaves by topic kind and reason, not GRAFT or PRUNE controls",
            .labels = &.{ "topic", "event", "reason" },
        });
        inline for (0..topic_policy.kind_count + 1) |kind| {
            const topic = if (kind < topic_policy.kind_count) @tagName(@as(topic_policy.Kind, @enumFromInt(kind))) else "unknown";
            inline for (std.meta.fields(MeshReason)) |reason| {
                const event = comptime @tagName(@as(MeshReason, @enumFromInt(reason.value)).event());
                try changes.sample(.{ topic, event, reason.name }, self.counts[kind][reason.value]);
            }
        }
    }
};

pub const Overlay = struct {
    rng: std.Random.DefaultPrng,

    rows: [constants.topics_cap]Row = @splat(.{}),
    namespace: ?topic_policy.Namespace = null,
    subscription_revision: u64 = 0,
    slot: u64 = 0,
    mesh_changes: MeshChanges = .{},

    pub fn deinit(self: *Overlay, a: std.mem.Allocator) void {
        if (self.namespace) |*ns| ns.deinit(a);
    }

    pub fn setLocal(self: *Overlay, context: *const Context, index: u16, on: bool) void {
        const row = &self.rows[index];
        assert(row.active);
        if (row.subscribed == on) return;
        if (on) {
            row.fanout = .initEmpty();
            row.retire_after_ms = null;
        } else {
            var it = row.mesh.iterator(.{});
            while (it.next()) |peer| self.prune(context, index, @intCast(peer), constants.unsubscribe_backoff_ms, .local_unsubscribe);
            row.retire_after_ms = context.now +| context.options.retained_score_ms;
        }
        row.subscribed = on;
        self.subscription_revision +|= 1;
        for (context.sessions.rows, 0..) |*peer, position| {
            const io = &peer.io;
            if (!peer.active or peer.outStream() == null) continue;
            io.tx.subscriptionChanged(index, context.now);
            context.sessions.settle(@intCast(position), context.options);
        }
    }

    pub fn synchronize(self: *const Overlay, outbox: *@import("outbox.zig").Outbox, now: u64) void {
        var announcements = std.StaticBitSet(constants.topics_cap).initEmpty();
        for (self.rows, 0..) |row, index| if (row.active and row.subscribed) {
            announcements.set(index);
        };
        outbox.synchronize(&announcements, now);
    }

    pub fn flushSubscriptions(self: *const Overlay, outbox: *@import("outbox.zig").Outbox, now: u64) void {
        for (0..constants.topics_cap) |_| {
            const index = outbox.nextSubscription() orelse return;
            const row = &self.rows[index];
            assert(row.active);
            if (!outbox.announce(index, row.string[0..row.string_len], row.subscribed, now)) return;
        }
    }

    pub fn internTopic(self: *Overlay, context: *const Context, validation_pins: *const local_intent.TopicSet, name: []const u8) ?u16 {
        if (!self.validTopic(name)) return null;
        if (self.findTopic(name)) |topic| return topic;
        const pins = retirementPins(context, validation_pins);
        var cursor: usize = 0;
        const index = self.vacantRow(context, &pins, &.initEmpty(), &cursor, context.now) orelse return null;
        var bytes: [topic_mod.topic_max_len]u8 = undefined;
        const copied = bytes[0..name.len];
        @memcpy(copied, name);
        const row = &self.rows[index];
        if (row.active) context.peers.scores.resetTopic(index);
        row.active = false;
        self.assignTopic(index, copied, row.generation);
        return self.initializeTopic(context, index);
    }

    pub fn validTopic(self: *const Overlay, name: []const u8) bool {
        if (self.namespace) |*ns| return ns.lookup(name) != null;
        return name.len <= topic_mod.topic_max_len and topic_mod.parse(name) != null;
    }

    fn initializeTopic(self: *Overlay, context: *const Context, topic: u16) u16 {
        context.peers.scores.applyValidatedTopic(topic, self.topicParams(context, self.rows[topic].kind, self.slot));
        if (self.namespace) |*ns| {
            const match = ns.lookup(self.topicString(topic)).?;
            ns.initializeSubscribers(match.ordinal, &self.rows[topic].subscribers);
        }
        return topic;
    }

    fn retirementPins(context: *const Context, validation_pins: *const local_intent.TopicSet) local_intent.Pins {
        var pins: local_intent.Pins = .{ .validation = validation_pins.* };
        for (context.sessions.rows) |*peer| {
            if (peer.active) {
                pins.outbound.setUnion(peer.io.tx.subscription_dirty);
            }
        }
        return pins;
    }

    const Retirement = struct { blocked: bool, expired: bool, reusable: bool };

    fn retirement(self: *const Overlay, context: *const Context, topic: u16, pins: *const local_intent.Pins, now_ms: u64) Retirement {
        const row = &self.rows[topic];
        if (!row.active or row.subscribed or row.mesh.count() > 0 or row.fanout.count() > 0 or
            pins.validation.isSet(topic) or
            pins.outbound.isSet(topic)) return .{ .blocked = true, .expired = false, .reusable = false };
        const expired = if (row.retire_after_ms) |deadline| now_ms >= deadline else false;
        var backoff = false;
        for (0..context.peers.rows.len) |peer| {
            const value = context.peers.backoffs[peer * constants.topics_cap + topic];
            if (value.topic_generation == row.generation and now_ms < value.until) {
                backoff = true;
                break;
            }
        }
        return .{ .blocked = false, .expired = expired, .reusable = (expired or !context.peers.scores.retainsTopic(topic)) and !backoff };
    }

    fn vacantRow(self: *const Overlay, context: *const Context, pins: *const local_intent.Pins, reserved: *const local_intent.TopicSet, cursor: *usize, now_ms: u64) ?u16 {
        assert(cursor.* <= 2 * constants.topics_cap);
        // Exhaust unused rows before reclaiming retained topic state.
        while (cursor.* < 2 * constants.topics_cap) {
            const reclaim = cursor.* >= constants.topics_cap;
            const index: u16 = @intCast(cursor.* % constants.topics_cap);
            cursor.* += 1;
            const row = &self.rows[index];
            if (row.active != reclaim or reserved.isSet(index) or row.generation == std.math.maxInt(u64)) continue;
            if (reclaim and !self.retirement(context, index, pins, now_ms).reusable) continue;
            return index;
        }
        return null;
    }

    fn reclaimObserved(self: *Overlay, context: *const Context, topic: u16, observed: Retirement) void {
        if (observed.blocked) return;
        if (observed.expired) context.peers.scores.resetTopic(topic);
        if (!observed.reusable) return;
        self.rows[topic].active = false;
        self.rows[topic].subscribers = .initEmpty();
        context.peers.scores.applyValidatedTopic(topic, context.options.score_params.topic);
    }

    pub fn reclaimTopic(self: *Overlay, context: *const Context, validation_pins: *const local_intent.TopicSet, topic: u16) void {
        const pins = retirementPins(context, validation_pins);
        self.reclaimObserved(context, topic, self.retirement(context, topic, &pins, context.now));
    }

    fn topicParams(_: *const Overlay, context: *const Context, kind: ?topic_mod.Kind, slot: u64) score_mod.TopicParams {
        if (kind) |k| if (context.options.topic_params) |*policies| return policies[@intFromEnum(k)].atSlot(slot);
        return context.options.score_params.topic;
    }

    /// Does not mutate protocol state or end event borrows. Commit must immediately follow acceptance.
    pub fn prepareSubscriptions(self: *Overlay, context: *const Context, validation_pins: *const local_intent.TopicSet, subscriptions: []const local_intent.Boundary, workspace: *local_intent.Workspace, now_ms: u64, slot: u64) local_intent.Error!bool {
        workspace.prepared = false;
        if (subscriptions.len > topic_policy.boundary_max) return error.TopicCapacity;
        if (subscriptions.len > 0 and self.namespace == null) return error.TopicPolicyRequired;
        workspace.len = 0;
        workspace.desired = .initEmpty();
        workspace.reserved = .initEmpty();
        workspace.now_ms = @max(context.now, now_ms);
        workspace.slot = slot;
        var boundaries = std.StaticBitSet(topic_policy.boundary_max).initEmpty();
        var count: usize = 0;
        for (subscriptions) |*subscription| {
            const ns = &self.namespace.?;
            const boundary_index = for (ns.boundaries, 0..) |*boundary, i| {
                if (std.mem.eql(u8, &boundary.digest, &subscription.digest)) break i;
            } else return error.InvalidTopic;
            if (boundaries.isSet(boundary_index)) return error.DuplicateBoundary;
            boundaries.set(boundary_index);
            for (ns.boundaries[boundary_index].rules, ns.offsets[boundary_index], 0..) |rule, start, k| {
                const mask = subscription.maskConst(@enumFromInt(k));
                if (subscription.lengths[k] > (rule.count + 7) / 8) return error.InvalidTopic;
                for (mask, 0..) |bits, byte| {
                    var remaining = bits;
                    for (0..8) |_| {
                        if (remaining == 0) break;
                        const subnet = byte * 8 + @as(usize, @ctz(remaining));
                        if (byte >= subscription.lengths[k] or subnet >= rule.count) return error.InvalidTopic;
                        count += 1;
                        if (count > constants.topics_cap) return error.TopicCapacity;
                        workspace.desired.set(start + subnet);
                        remaining &= remaining - 1;
                    }
                }
            }
        }
        var changed = false;
        // Reserve retained matches before selecting any rows for replacement.
        for (&self.rows, 0..) |*row, i| {
            if (!row.active) continue;
            if (row.ordinal) |ordinal| if (workspace.desired.isSet(ordinal)) {
                workspace.entries[workspace.len] = .{ .ordinal = ordinal, .row = @intCast(i), .generation = row.generation, .existing = true };
                workspace.len += 1;
                workspace.reserved.set(i);
                workspace.desired.unset(ordinal);
                changed = changed or !row.subscribed or !std.meta.eql(context.peers.scores.topic_params[i], self.topicParams(context, row.kind, slot));
                continue;
            };
            if (row.subscribed) changed = true;
        }
        workspace.pins = retirementPins(context, validation_pins);
        var cursor: usize = 0;
        var desired = workspace.desired.iterator(.{});
        for (0..constants.topics_cap) |_| {
            const ordinal = desired.next() orelse break;
            changed = true;
            const index = self.vacantRow(context, &workspace.pins, &workspace.reserved, &cursor, workspace.now_ms) orelse return error.TopicCapacity;
            workspace.entries[workspace.len] = .{ .ordinal = @intCast(ordinal), .row = @intCast(index), .generation = self.rows[index].generation, .existing = false };
            workspace.len += 1;
            workspace.reserved.set(index);
        }
        assert(workspace.len == count);
        workspace.prepared = true;
        return changed;
    }

    pub fn commitSubscriptions(self: *Overlay, context: *const Context, workspace: *local_intent.Workspace) void {
        assert(workspace.prepared and context.now == workspace.now_ms);
        workspace.prepared = false;
        self.slot = workspace.slot;
        for (workspace.entries[0..workspace.len]) |*entry| {
            const index = entry.row;
            const row = &self.rows[index];
            assert(row.generation == entry.generation);
            if (!entry.existing) {
                context.peers.scores.resetTopic(index);
                row.active = false;
                var bytes: [topic_mod.topic_max_len]u8 = undefined;
                const name = topic_mod.buildCanonical(self.namespace.?.topicAt(entry.ordinal), &bytes);
                self.assignTopic(index, name, entry.generation);
                self.namespace.?.initializeSubscribers(entry.ordinal, &row.subscribers);
            }
            context.peers.scores.applyValidatedTopic(index, self.topicParams(context, row.kind, self.slot));
            self.setLocal(context, index, true);
        }
        for (&self.rows, 0..) |*row, index| {
            if (row.active and row.subscribed and !workspace.reserved.isSet(index)) self.setLocal(context, @intCast(index), false);
        }
    }
    fn assignTopic(self: *Overlay, index: u16, copied: []const u8, generation: u64) void {
        assert(copied.len <= topic_mod.topic_max_len);
        const topic = &self.rows[index];
        assert(topic.generation == generation and generation != std.math.maxInt(u64));
        assert(!topic.active);
        topic.* = .{ .active = true, .generation = generation + 1 };
        @memcpy(topic.string[0..copied.len], copied);
        topic.string_len = @intCast(copied.len);
        if (topic_mod.parseCanonical(copied)) |parsed| topic.kind = parsed.name.kind;
        if (self.namespace) |*ns| topic.ordinal = ns.lookup(copied).?.ordinal;
    }

    pub fn findTopic(self: *const Overlay, topic_str: []const u8) ?u16 {
        for (&self.rows, 0..) |*topic, index| {
            if (!topic.active) continue;
            if (std.mem.eql(u8, topic.topicString(), topic_str)) return @intCast(index);
        }
        return null;
    }

    pub fn ref(self: *const Overlay, index: u16) @import("topic.zig").Ref {
        assert(self.rows[index].active);
        return .{ .index = index, .generation = self.rows[index].generation };
    }

    pub fn matches(self: *const Overlay, topic: @import("topic.zig").Ref) bool {
        return topic.index < self.rows.len and self.rows[topic.index].active and self.rows[topic.index].generation == topic.generation;
    }

    pub fn inMesh(self: *const Overlay, topic: u16, session: u16) bool {
        return self.rows[topic].mesh.isSet(session);
    }

    pub fn topicString(self: *const Overlay, index: u16) []const u8 {
        return self.rows[index].topicString();
    }

    pub fn subscribed(self: *const Overlay, index: u16) bool {
        return self.rows[index].active and self.rows[index].subscribed;
    }

    fn applySubscription(self: *Overlay, context: *const Context, topic: u16, peer: u16, on: bool, leave: MeshReason) void {
        assert(self.rows[topic].active);
        if (self.rows[topic].subscribers.isSet(peer) != on) self.subscription_revision +|= 1;
        if (on) self.rows[topic].subscribers.set(peer) else {
            self.rows[topic].subscribers.unset(peer);
            self.leaveMesh(context, topic, peer, leave);
            self.rows[topic].fanout.unset(peer);
        }
    }

    pub fn subscribers(self: *const Overlay, topic: u16) *const PeerSet {
        return &self.rows[topic].subscribers;
    }

    pub fn subnetSubscriptions(self: *const Overlay, peer: ?u16, digest: [4]u8) topic_policy.Subnets {
        if (peer) |index| if (self.namespace) |*ns| return ns.subnets(index, digest);
        var result: topic_policy.Subnets = .{};
        for (&self.rows) |*row| {
            if (!row.active or !(if (peer) |index| row.subscribers.isSet(index) else row.subscribed)) continue;
            const parsed = topic_mod.parseCanonical(row.topicString()) orelse continue;
            if (std.mem.eql(u8, &digest, &parsed.digest)) result.add(parsed.name);
        }
        if (self.namespace == null) result.column_subnet_count = 128;
        return result;
    }

    pub fn mesh(self: *const Overlay, topic: u16) *const PeerSet {
        return &self.rows[topic].mesh;
    }

    pub fn fanoutMembers(self: *const Overlay, topic: u16) *const PeerSet {
        return &self.rows[topic].fanout;
    }

    pub fn init(seed: u64) Overlay {
        return .{ .rng = std.Random.DefaultPrng.init(seed) };
    }

    fn score(context: *const Context, peer: u16) f64 {
        const snapshot = context.snapshot orelse return context.peers.score(context.sessions.rows[peer].logical, context.now);
        if (snapshot[peer].generation != context.sessions.peerGeneration(peer)) return context.peers.score(context.sessions.rows[peer].logical, context.now);
        return snapshot[peer].value;
    }

    fn eligiblePeer(context: *const Context, peer: u16, threshold: f64) bool {
        const row = &context.sessions.rows[peer];
        if (!row.active or context.peers.rows[row.logical.index].direct or row.outStream() == null) return false;
        return score(context, peer) >= threshold;
    }

    fn eligibleSubscriber(self: *const Overlay, context: *const Context, topic: u16, peer: u16, threshold: f64) bool {
        return self.subscribers(topic).isSet(peer) and eligiblePeer(context, peer, threshold);
    }

    fn graftEligible(self: *const Overlay, context: *const Context, topic: u16, peer: u16) bool {
        if (!self.eligibleSubscriber(context, topic, peer, 0)) return false;
        return !context.peers.backedOff(context.sessions.rows[peer].logical, topic, self.rows[topic].generation, context.now -| (c.backoff_slack_heartbeats * context.options.heartbeat_interval_ms));
    }

    fn outbound(context: *const Context, peer: u16) bool {
        return context.peers.rows[context.sessions.rows[peer].logical.index].direction == .outbound;
    }

    fn outboundCount(context: *const Context, members: *const Set) usize {
        var count: usize = 0;
        var it = members.iterator(.{});
        while (it.next()) |peer| if (outbound(context, @intCast(peer))) {
            count += 1;
        };
        return count;
    }

    pub fn maintain(self: *Overlay, context: *const Context, topic: u16) void {
        const members = &self.rows[topic].mesh;
        var it = members.iterator(.{});
        while (it.next()) |index| {
            const peer: u16 = @intCast(index);
            if (!eligiblePeer(context, peer, 0)) self.prune(context, topic, peer, c.prune_backoff_ms, .ineligible);
        }
        if (!self.subscribed(topic)) return;
        var candidate_peers: [c.peers_cap]u16 = undefined;
        const n = self.candidates(context, topic, &candidate_peers, true, 0);
        self.shuffle(candidate_peers[0..n]);
        var out = outboundCount(context, members);
        for (candidate_peers[0..n]) |peer| {
            if (out >= c.mesh_d_out) break;
            if (outbound(context, peer) and self.graft(context, topic, peer, .fill_outbound)) out += 1;
        }
        if (members.count() < c.mesh_d_low) {
            for (candidate_peers[0..n]) |peer| {
                if (members.count() >= c.mesh_d) break;
                _ = self.graft(context, topic, peer, .fill_mesh);
            }
        }
        if (members.count() > c.mesh_d_high) self.trim(context, topic);
    }

    fn shuffle(self: *Overlay, members: []u16) void {
        assert(members.len <= c.peers_cap);
        for (0..members.len -| 1) |i| {
            const offset = self.rng.random().uintLessThanBiased(u64, @intCast(members.len - i));
            const chosen = i + @as(usize, @intCast(offset));
            std.mem.swap(u16, &members[i], &members[chosen]);
        }
    }

    fn candidates(self: *Overlay, context: *const Context, topic: u16, out: *[c.peers_cap]u16, graft_only: bool, threshold: f64) usize {
        var count: usize = 0;
        for (0..context.sessions.rows.len) |index| {
            const peer: u16 = @intCast(index);
            if (self.mesh(topic).isSet(peer)) continue;
            if (!self.eligibleSubscriber(context, topic, peer, threshold)) continue;
            if (graft_only and !self.graftEligible(context, topic, peer)) continue;
            out[count] = peer;
            count += 1;
        }
        return count;
    }

    fn graft(self: *Overlay, context: *const Context, topic: u16, peer: u16, reason: MeshReason) bool {
        assert(reason.event() == .join);
        const members = &self.rows[topic].mesh;
        if (members.isSet(peer) or !self.graftEligible(context, topic, peer)) return false;
        const outbox = &context.sessions.rows[peer].io.tx;
        const name = self.topicString(topic);
        // A peer can reach mesh maintenance before its next I/O turn announces our subscription.
        if (outbox.subscription_dirty.isSet(topic) and !outbox.announce(topic, name, true, context.now)) return false;
        defer context.sessions.settle(peer, context.options);
        if (outbox.submit(&.{ .graft = name }, context.now) == null) return false;
        members.set(peer);
        self.mesh_changes.record(self.rows[topic].kind, reason);
        context.peers.scores.graft(context.sessions.rows[peer].logical.index, topic, context.now);
        self.logChange(context, topic, peer, "mesh_graft_queued", 0);
        return true;
    }

    pub fn prune(self: *Overlay, context: *const Context, topic: u16, peer: u16, backoff_ms: u64, reason: MeshReason) void {
        if (self.mesh(topic).isSet(peer)) {
            self.logChange(context, topic, peer, "mesh_prune_local", backoff_ms);
            self.leaveMesh(context, topic, peer, reason);
        }
        const row = &context.sessions.rows[peer];
        if (!row.active) return;
        context.peers.addBackoff(row.logical, topic, self.rows[topic].generation, context.now, backoff_ms);
        const stream = row.outStream() orelse return;
        if (row.io.tx.submit(&.{ .prune = .{ .topic = self.topicString(topic), .backoff_s = backoff_ms / 1000 } }, context.now) == null) {
            context.sessions.setOutbound(peer, .{ .closing = stream });
        }
        context.sessions.settle(peer, context.options);
    }

    pub fn onGraft(self: *Overlay, context: *const Context, topic: u16, peer: u16) void {
        const row = &context.sessions.rows[peer];
        const backoff = context.peers.backoff(row.logical, topic);
        const blocked = backoff.topic_generation == self.rows[topic].generation and context.now < backoff.until;
        if (blocked) {
            context.peers.scores.penalizeFor(row.logical.index, .graft_backoff);
            if (backoff.until -| context.now > c.prune_backoff_ms - c.graft_flood_threshold_ms) context.peers.scores.penalizeFor(row.logical.index, .graft_flood);
        }
        if (row.outStream() == null) return;
        const refused = !self.subscribed(topic) or context.peers.rows[row.logical.index].direct or blocked or context.peers.score(row.logical, context.now) < 0 or
            (!self.mesh(topic).isSet(peer) and self.mesh(topic).count() >= c.mesh_d_high and !outbound(context, peer));
        if (refused) return self.prune(context, topic, peer, c.prune_backoff_ms, .refused_graft);
        if (self.mesh(topic).isSet(peer)) return;
        self.rows[topic].mesh.set(peer);
        self.mesh_changes.record(self.rows[topic].kind, .remote_graft);
        context.peers.scores.graft(row.logical.index, topic, context.now);
        self.logChange(context, topic, peer, "mesh_graft_received", 0);
    }

    pub fn onPrune(self: *Overlay, context: *const Context, topic: u16, peer: u16, backoff_ms: u64) void {
        self.logChange(context, topic, peer, "mesh_prune_received", backoff_ms);
        self.leaveMesh(context, topic, peer, .remote_prune);
        context.peers.addBackoff(context.sessions.rows[peer].logical, topic, self.rows[topic].generation, context.now, backoff_ms);
    }

    fn trim(self: *Overlay, context: *const Context, topic: u16) void {
        var ordered: [c.peers_cap]u16 = undefined;
        var count: usize = 0;
        var it = self.mesh(topic).iterator(.{});
        while (it.next()) |peer| {
            ordered[count] = @intCast(peer);
            count += 1;
        }
        sort(context, ordered[0..count]);
        self.shuffle(ordered[c.mesh_d_score..count]);
        var survivors: Set = .initEmpty();
        for (ordered[0..c.mesh_d_score]) |peer| survivors.set(peer);
        var out = outboundCount(context, &survivors);
        for (ordered[c.mesh_d_score..count]) |peer| {
            if (out >= c.mesh_d_out) break;
            if (outbound(context, peer)) {
                survivors.set(peer);
                out += 1;
            }
        }
        for (ordered[c.mesh_d_score..count]) |peer| {
            if (survivors.count() >= c.mesh_d) break;
            survivors.set(peer);
        }
        for (ordered[0..count]) |peer| if (!survivors.isSet(peer)) self.prune(context, topic, peer, c.prune_backoff_ms, .excess);
        assert(self.mesh(topic).count() == c.mesh_d);
    }

    fn sort(context: *const Context, members: []u16) void {
        assert(members.len <= c.peers_cap);
        for (members, 0..) |peer, i| {
            var j = i;
            for (0..i) |_| {
                if (score(context, members[j - 1]) >= score(context, peer)) break;
                members[j] = members[j - 1];
                j -= 1;
                if (j == 0) break;
            }
            members[j] = peer;
        }
    }

    pub fn opportunistic(self: *Overlay, context: *const Context, topic: u16) void {
        const members = &self.rows[topic].mesh;
        if (members.count() < 2) return;
        var ordered: [c.peers_cap]u16 = undefined;
        var n: usize = 0;
        var it = members.iterator(.{});
        while (it.next()) |peer| {
            ordered[n] = @intCast(peer);
            n += 1;
        }
        sort(context, ordered[0..n]);
        const median = if (n % 2 == 0)
            (score(context, ordered[n / 2 - 1]) + score(context, ordered[n / 2])) / 2
        else
            score(context, ordered[n / 2]);
        if (median >= context.peers.scores.params.opportunistic_graft_threshold) return;
        n = self.candidates(context, topic, &ordered, true, 0);
        self.shuffle(ordered[0..n]);
        var added: usize = 0;
        for (ordered[0..n]) |peer| {
            if (added == c.opportunistic_graft_peers) break;
            if (score(context, peer) > median and self.graft(context, topic, peer, .opportunistic)) added += 1;
        }
    }

    pub fn publicationRecipients(self: *Overlay, context: *const Context, topic: u16, flood: bool) Set {
        var result: Set = .initEmpty();
        const threshold = context.peers.scores.params.publish_threshold;
        if (flood) {
            for (0..context.sessions.rows.len) |index| {
                if (self.eligibleSubscriber(context, topic, @intCast(index), threshold)) result.set(index);
            }
        } else {
            var it = self.mesh(topic).iterator(.{});
            while (it.next()) |index| {
                if (eligiblePeer(context, @intCast(index), threshold)) result.set(index);
            }
            if (result.count() == 0) {
                result = self.maintainFanout(context, topic, true).*;
            } else self.fillPublication(context, topic, &result);
        }
        for (context.sessions.rows, 0..) |*row, index| {
            if (row.active and row.outStream() != null and context.peers.rows[row.logical.index].direct and self.subscribers(topic).isSet(index)) result.set(index);
        }
        return result;
    }

    fn fillPublication(self: *Overlay, context: *const Context, topic: u16, members: *Set) void {
        if (members.count() >= c.mesh_d) return;
        var candidate_peers: [c.peers_cap]u16 = undefined;
        var count: usize = 0;
        for (0..context.sessions.rows.len) |index| {
            const peer: u16 = @intCast(index);
            if (members.isSet(peer)) continue;
            if (!self.eligibleSubscriber(context, topic, peer, context.peers.scores.params.publish_threshold)) continue;
            candidate_peers[count] = peer;
            count += 1;
        }
        self.shuffle(candidate_peers[0..count]);
        for (candidate_peers[0..count]) |peer| {
            if (members.count() >= c.mesh_d) break;
            members.set(peer);
        }
    }

    pub fn maintainFanout(self: *Overlay, context: *const Context, topic: u16, publishing: bool) *Set {
        const row = &self.rows[topic];
        if (!publishing and context.now -| row.fanout_last_ms >= c.fanout_ttl_ms) {
            row.fanout = .initEmpty();
            return &row.fanout;
        }
        if (publishing) row.fanout_last_ms = context.now;
        var it = row.fanout.iterator(.{});
        while (it.next()) |peer| if (!self.eligibleSubscriber(context, topic, @intCast(peer), context.peers.scores.params.publish_threshold)) {
            row.fanout.unset(peer);
        };
        self.fillPublication(context, topic, &row.fanout);
        return &row.fanout;
    }

    pub fn gossipRecipients(self: *Overlay, context: *const Context, topic: u16, factor: f64) Set {
        assert(std.math.isFinite(factor) and factor >= 0 and factor <= 1);
        var candidates_buf: [c.peers_cap]u16 = undefined;
        const count = self.candidates(context, topic, &candidates_buf, false, context.peers.scores.params.gossip_threshold);
        var n: usize = 0;
        for (candidates_buf[0..count]) |peer| {
            if (self.fanoutMembers(topic).isSet(peer)) continue;
            candidates_buf[n] = peer;
            n += 1;
        }
        self.shuffle(candidates_buf[0..n]);
        const wanted = @min(n, @max(c.mesh_d_lazy, @as(usize, @intFromFloat(@ceil(factor * @as(f64, @floatFromInt(n)))))));
        var result: Set = .initEmpty();
        for (candidates_buf[0..wanted]) |peer| result.set(peer);
        return result;
    }
    fn leaveMesh(self: *Overlay, context: *const Context, topic: u16, peer: u16, reason: MeshReason) void {
        assert(reason.event() == .leave);
        if (!self.rows[topic].mesh.isSet(peer)) return;
        context.peers.scores.prune(context.sessions.rows[peer].logical.index, topic, context.now);
        self.rows[topic].mesh.unset(peer);
        self.mesh_changes.record(self.rows[topic].kind, reason);
    }

    pub fn peerDisconnected(self: *Overlay, context: *const Context, peer: u16) void {
        for (&self.rows, 0..) |*row, topic| {
            if (row.active) self.applySubscription(context, @intCast(topic), peer, false, .session_end);
        }
        if (self.namespace) |*ns| ns.clearPeer(peer);
    }

    pub fn peerSubscription(self: *Overlay, context: *const Context, peer: u16, name: []const u8, on: bool) ?u16 {
        if (self.namespace) |*ns| {
            const match = ns.lookup(name) orelse return null;
            ns.setSubscription(peer, match.ordinal, on);
        }
        const topic = self.findTopic(name) orelse return null;
        self.applySubscription(context, topic, peer, on, .remote_unsubscribe);
        return topic;
    }

    fn logChange(self: *const Overlay, context: *const Context, topic: u16, peer: u16, comptime event: []const u8, backoff_ms: u64) void {
        const row = &self.rows[topic];
        const conn = context.sessions.rows[peer].conn;
        std.log.scoped(.network_mesh).debug(event ++ " connection={d}:{d} topic={s} backoff_ms={d}", .{ conn.index, conn.generation, row.string[0..row.string_len], backoff_ms });
    }
};

test "gossip policy review I3 shuffle budget holds at empty singleton and capacity" {
    var members: [c.peers_cap]u16 = undefined;
    for ([_]usize{ 0, 1, 3, c.peers_cap }) |len| {
        var mesh = Overlay.init(17);
        var expected = mesh.rng;
        for (0..len -| 1) |_| _ = expected.next();
        for (members[0..len], 0..) |*peer, i| peer.* = @intCast(i);
        mesh.shuffle(members[0..len]);
        try std.testing.expectEqualSlices(u64, &expected.s, &mesh.rng.s);
        var seen: Set = .initEmpty();
        for (members[0..len]) |peer| {
            try std.testing.expect(peer < len and !seen.isSet(peer));
            seen.set(peer);
        }
    }
    var mesh = Overlay.init(17);
    var ordered = [_]u16{ 0, 1, 2, 3, 4, 5, 6, 7 };
    mesh.shuffle(&ordered);
    try std.testing.expectEqualSlices(u16, &.{ 6, 7, 2, 0, 5, 1, 3, 4 }, &ordered);
}

test {
    _ = @import("overlay_test.zig");
}
