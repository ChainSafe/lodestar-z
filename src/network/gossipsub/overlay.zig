const std = @import("std");
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const topic_policy = @import("topic_policy.zig");
const score_mod = @import("score.zig");
const local_intent = @import("local_intent.zig");
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
    name: [topic_mod.name_max_len]u8 = undefined,
    name_len: u8 = 0,
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

pub const Overlay = struct {
    rng: std.Random.DefaultPrng,
    outbound_deficits: u64 = 0,

    rows: [constants.topics_cap]Row = @splat(.{}),
    namespace: ?topic_policy.Namespace = null,

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
            while (it.next()) |peer| self.prune(context, index, @intCast(peer), constants.unsubscribe_backoff_ms);
            row.retire_after_ms = context.now +| context.options.retained_score_ms;
        }
        row.subscribed = on;
        for (context.sessions.rows) |*peer| {
            const io = &peer.io;
            if (!peer.active) continue;
            io.tx.subscriptionChanged(index, context.now);
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
        if (self.internVacant(name)) |topic| return self.initializeTopic(topic);
        const pins = retirementPins(context, validation_pins);
        for (0..constants.topics_cap) |index| {
            const topic: u16 = @intCast(index);
            if (self.rows[topic].generation == std.math.maxInt(u64) or
                !self.retirement(context, topic, &pins, context.now).reusable) continue;
            for (0..constants.topics_cap) |reclaim| self.reclaimObserved(context, @intCast(reclaim), self.retirement(context, @intCast(reclaim), &pins, context.now));
            return self.initializeTopic(self.internVacant(name) orelse unreachable);
        }
        return null;
    }

    pub fn validTopic(self: *const Overlay, name: []const u8) bool {
        if (self.namespace) |*ns| return ns.lookup(name) != null;
        return name.len <= topic_mod.topic_max_len and topic_mod.parse(name) != null;
    }

    fn initializeTopic(self: *Overlay, topic: u16) u16 {
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
                pins.outbound.setUnion(peer.io.tx.pending_prunes);
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

    /// Does not mutate protocol state or end event borrows. Commit must immediately follow acceptance.
    pub fn prepareSubscriptions(self: *Overlay, context: *const Context, validation_pins: *const local_intent.TopicSet, subscriptions: []const local_intent.Subscription, workspace: *local_intent.Workspace, now_ms: u64) local_intent.Error!bool {
        workspace.prepared = false;
        if (subscriptions.len > constants.topics_cap) return error.TopicCapacity;
        if (subscriptions.len > 0 and self.namespace == null) return error.TopicPolicyRequired;
        workspace.len = @intCast(subscriptions.len);
        workspace.reserved = .initEmpty();
        workspace.now_ms = @max(context.now, now_ms);
        var changed = false;
        for (subscriptions, 0..) |*subscription, i| {
            const match = self.namespace.?.lookup(subscription.name) orelse return error.InvalidTopic;
            try score_mod.validateTopic(subscription.params);
            const entry = &workspace.entries[i];
            entry.name_len = @intCast(subscription.name.len - topic_mod.prefix.len - topic_mod.digest_hex_len - 1 - topic_mod.suffix.len);
            entry.ordinal = match.ordinal;
            entry.len = @intCast(subscription.name.len);
            @memcpy(entry.bytes[0..entry.len], subscription.name);
            entry.params = subscription.params;
            for (workspace.entries[0..i]) |*earlier| {
                if (std.mem.eql(u8, entry.name(), earlier.name())) return error.DuplicateTopic;
            }
            entry.row = self.findTopic(entry.name());
            entry.existing = entry.row != null;
            if (entry.row) |row| {
                workspace.reserved.set(row);
                entry.generation = self.rows[row].generation;
                changed = changed or !self.subscribed(row) or !std.meta.eql(entry.params, context.peers.scores.topic_params[row]);
            } else changed = true;
        }
        workspace.pins = retirementPins(context, validation_pins);
        var cursor: usize = 0;
        for (workspace.entries[0..workspace.len]) |*entry| {
            if (entry.existing) continue;
            while (cursor < constants.topics_cap) : (cursor += 1) {
                const row = &self.rows[cursor];
                if (workspace.reserved.isSet(cursor) or row.generation == std.math.maxInt(u64)) continue;
                if (row.active and !self.retirement(context, @intCast(cursor), &workspace.pins, workspace.now_ms).reusable) continue;
                entry.row = @intCast(cursor);
                entry.generation = row.generation;
                workspace.reserved.set(cursor);
                cursor += 1;
                break;
            }
            if (entry.row == null) return error.TopicCapacity;
        }
        for (&self.rows, 0..) |*row, index| {
            if (row.active and row.subscribed and !workspace.reserved.isSet(index)) changed = true;
        }
        workspace.prepared = true;
        return changed;
    }

    pub fn commitSubscriptions(self: *Overlay, context: *const Context, workspace: *local_intent.Workspace) void {
        assert(workspace.prepared and context.now == workspace.now_ms);
        workspace.prepared = false;
        for (workspace.entries[0..workspace.len]) |*entry| {
            const index = entry.row.?;
            const row = &self.rows[index];
            assert(row.generation == entry.generation);
            if (!entry.existing) {
                context.peers.scores.resetTopic(index);
                row.active = false;
                self.assignTopic(index, entry.name(), entry.generation, entry.name_len);
                self.namespace.?.initializeSubscribers(entry.ordinal, &row.subscribers);
            }
            context.peers.scores.applyValidatedTopic(index, entry.params);
            self.setLocal(context, index, true);
        }
        for (&self.rows, 0..) |*row, index| {
            if (row.active and row.subscribed and !workspace.reserved.isSet(index)) self.setLocal(context, @intCast(index), false);
        }
    }
    pub fn internVacant(self: *Overlay, topic_str: []const u8) ?u16 {
        if (topic_str.len > topic_mod.topic_max_len) return null;
        var copied_bytes: [topic_mod.topic_max_len]u8 = undefined;
        const copied = copied_bytes[0..topic_str.len];
        @memcpy(copied, topic_str);
        const parsed = topic_mod.parse(copied) orelse return null;
        if (self.findTopic(copied)) |index| return index;
        const index = self.freeTopic() orelse return null;
        self.assignTopic(@intCast(index), copied, self.rows[index].generation, @intCast(parsed.name.len));
        return @intCast(index);
    }

    pub fn assignTopic(self: *Overlay, index: u16, copied: []const u8, generation: u64, name_len: u8) void {
        assert(copied.len <= topic_mod.topic_max_len);
        const name = copied[topic_mod.prefix.len + topic_mod.digest_hex_len + 1 ..][0..name_len];
        const topic = &self.rows[index];
        assert(topic.generation == generation and generation != std.math.maxInt(u64));
        assert(!topic.active);
        topic.* = .{ .active = true, .generation = generation + 1 };
        @memcpy(topic.name[0..name_len], name);
        topic.name_len = @intCast(name_len);
        @memcpy(topic.string[0..copied.len], copied);
        topic.string_len = @intCast(copied.len);
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

    pub fn setSubscription(self: *Overlay, context: *const Context, topic: u16, peer: u16, on: bool) void {
        assert(self.rows[topic].active);
        if (on) self.rows[topic].subscribers.set(peer) else {
            self.rows[topic].subscribers.unset(peer);
            self.leaveMesh(context, topic, peer);
            self.rows[topic].fanout.unset(peer);
        }
    }

    pub fn subscribers(self: *const Overlay, topic: u16) *const PeerSet {
        return &self.rows[topic].subscribers;
    }

    pub fn mesh(self: *const Overlay, topic: u16) *const PeerSet {
        return &self.rows[topic].mesh;
    }

    pub fn fanoutMembers(self: *const Overlay, topic: u16) *const PeerSet {
        return &self.rows[topic].fanout;
    }

    fn freeTopic(self: *Overlay) ?usize {
        for (&self.rows, 0..) |*topic, index| {
            if (!topic.active and topic.generation != std.math.maxInt(u64)) return index;
        }
        return null;
    }
    pub fn init(seed: u64) Overlay {
        return .{ .rng = std.Random.DefaultPrng.init(seed) };
    }

    fn score(context: *const Context, peer: u16) f64 {
        const snapshot = context.snapshot orelse return context.peers.score(context.sessions.rows[peer].logical, context.now);
        if (snapshot[peer].generation != context.sessions.peerGeneration(peer)) return -score_mod.counter_max;
        return snapshot[peer].value;
    }

    fn eligible(self: *const Overlay, context: *const Context, topic: u16, peer: u16, threshold: f64) bool {
        const row = &context.sessions.rows[peer];
        if (!row.active or context.peers.rows[row.logical.index].direct or context.sessions.rows[peer].io.tx.pruneExpired(context.now, context.options.pressure_timeout_ms)) return false;
        return self.subscribers(topic).isSet(peer) and score(context, peer) >= threshold;
    }

    fn graftEligible(self: *const Overlay, context: *const Context, topic: u16, peer: u16) bool {
        if (!self.eligible(context, topic, peer, 0) or context.sessions.rows[peer].io.tx.pending_prunes.isSet(topic)) return false;
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
        self.flushPrunes(context, topic);
        const members = &self.rows[topic].mesh;
        var it = members.iterator(.{});
        while (it.next()) |index| {
            const peer: u16 = @intCast(index);
            if (!self.eligible(context, topic, peer, 0)) self.prune(context, topic, peer, c.prune_backoff_ms);
        }
        if (!self.subscribed(topic)) return;
        var candidate_peers: [c.peers_cap]u16 = undefined;
        const n = self.candidates(context, topic, &candidate_peers, true, 0);
        self.shuffle(candidate_peers[0..n]);
        var out = outboundCount(context, members);
        for (candidate_peers[0..n]) |peer| {
            if (out >= c.mesh_d_out) break;
            if (outbound(context, peer) and self.graft(context, topic, peer)) out += 1;
        }
        if (out < c.mesh_d_out) self.outbound_deficits += 1;
        if (members.count() < c.mesh_d_low) {
            for (candidate_peers[0..n]) |peer| {
                if (members.count() >= c.mesh_d) break;
                _ = self.graft(context, topic, peer);
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
            if (!self.eligible(context, topic, peer, threshold)) continue;
            if (graft_only and !self.graftEligible(context, topic, peer)) continue;
            out[count] = peer;
            count += 1;
        }
        return count;
    }

    fn graft(self: *Overlay, context: *const Context, topic: u16, peer: u16) bool {
        const members = &self.rows[topic].mesh;
        if (members.isSet(peer) or !self.graftEligible(context, topic, peer)) return false;
        if (context.sessions.rows[peer].io.tx.submit(&.{ .graft = self.topicString(topic) }, context.now) == null) return false;
        members.set(peer);
        context.peers.scores.graft(context.sessions.rows[peer].logical.index, topic, context.now);
        self.logChange(context, topic, peer, "mesh_graft_queued", 0);
        return true;
    }

    pub fn prune(self: *Overlay, context: *const Context, topic: u16, peer: u16, backoff_ms: u64) void {
        if (self.mesh(topic).isSet(peer)) {
            self.logChange(context, topic, peer, "mesh_prune_local", backoff_ms);
            self.leaveMesh(context, topic, peer);
        }
        const row = &context.sessions.rows[peer];
        if (!row.active) return;
        context.peers.addBackoff(row.logical, topic, self.rows[topic].generation, context.now, backoff_ms);
        if (row.io.tx.submit(&.{ .prune = .{ .topic = self.topicString(topic), .backoff_s = backoff_ms / 1000 } }, context.now) != null) {
            context.sessions.rows[peer].io.tx.pruneQueued(topic);
        } else row.io.tx.deferPrune(topic, context.now);
    }

    fn flushPrunes(self: *Overlay, context: *const Context, topic: u16) void {
        for (context.sessions.rows, 0..) |*row, peer| {
            if (!row.io.tx.pending_prunes.isSet(topic)) continue;
            assert(row.active);
            if (row.io.tx.pruneExpired(context.now, context.options.pressure_timeout_ms)) continue;
            const logical = context.sessions.rows[peer].logical;
            const entry = context.peers.backoff(logical, topic);
            const remaining_ms = entry.until -| context.now;
            const backoff_ms = if (remaining_ms == 0) c.prune_backoff_ms else remaining_ms;
            const seconds = backoff_ms / 1000 + @intFromBool(backoff_ms % 1000 != 0);
            if (row.io.tx.submit(&.{ .prune = .{ .topic = self.topicString(topic), .backoff_s = seconds } }, context.now) != null) {
                if (remaining_ms == 0) context.peers.addBackoff(logical, topic, self.rows[topic].generation, context.now, backoff_ms);
                entry.until = @max(entry.until, context.now +| (seconds *| 1000));
                context.sessions.rows[peer].io.tx.pruneQueued(topic);
            }
        }
    }

    pub fn onGraft(self: *Overlay, context: *const Context, topic: u16, peer: u16) void {
        const row = &context.sessions.rows[peer];
        const backoff = context.peers.backoff(row.logical, topic);
        const blocked = backoff.topic_generation == self.rows[topic].generation and context.now < backoff.until;
        if (blocked) {
            context.peers.scores.penalize(row.logical.index, 1);
            context.peers.scores.penalties.graft_backoff +|= 1;
            if (context.now -| backoff.pruned_at < c.graft_flood_threshold_ms) {
                context.peers.scores.penalize(row.logical.index, 1);
                context.peers.scores.penalties.graft_backoff +|= 1;
            }
        }
        if (context.sessions.rows[peer].io.tx.pruneExpired(context.now, context.options.pressure_timeout_ms) or context.sessions.rows[peer].io.tx.pending_prunes.isSet(topic)) return;
        if (!self.subscribed(topic) or context.peers.rows[row.logical.index].direct or blocked or
            context.peers.score(row.logical, context.now) < 0 or
            (!self.mesh(topic).isSet(peer) and self.mesh(topic).count() >= c.mesh_d_high and !outbound(context, peer)))
        {
            self.prune(context, topic, peer, c.prune_backoff_ms);
            return;
        }
        if (self.mesh(topic).isSet(peer)) return;
        self.setSubscription(context, topic, peer, true);
        self.rows[topic].mesh.set(peer);
        context.peers.scores.graft(row.logical.index, topic, context.now);
        self.logChange(context, topic, peer, "mesh_graft_received", 0);
    }

    pub fn onPrune(self: *Overlay, context: *const Context, topic: u16, peer: u16, backoff_ms: u64) void {
        self.logChange(context, topic, peer, "mesh_prune_received", backoff_ms);
        self.leaveMesh(context, topic, peer);
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
        for (ordered[0..count]) |peer| if (!survivors.isSet(peer)) self.prune(context, topic, peer, c.prune_backoff_ms);
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
        if (members.count() < c.mesh_d) return;
        var ordered: [c.peers_cap]u16 = undefined;
        var n: usize = 0;
        var it = members.iterator(.{});
        while (it.next()) |peer| {
            ordered[n] = @intCast(peer);
            n += 1;
        }
        sort(context, ordered[0..n]);
        const median = score(context, ordered[n / 2]);
        if (median >= context.peers.scores.params.opportunistic_graft_threshold) return;
        n = self.candidates(context, topic, &ordered, true, 0);
        self.shuffle(ordered[0..n]);
        var added: usize = 0;
        for (ordered[0..n]) |peer| {
            if (added == c.opportunistic_graft_peers) break;
            if (score(context, peer) > median and self.graft(context, topic, peer)) added += 1;
        }
    }

    pub fn publicationRecipients(self: *Overlay, context: *const Context, topic: u16, flood: bool) Set {
        var result: Set = .initEmpty();
        const threshold = context.peers.scores.params.publish_threshold;
        if (flood) {
            for (0..context.sessions.rows.len) |index| {
                if (self.eligible(context, topic, @intCast(index), threshold)) result.set(index);
            }
        } else {
            var it = self.mesh(topic).iterator(.{});
            while (it.next()) |index| {
                if (self.eligible(context, topic, @intCast(index), threshold)) result.set(index);
            }
            if (result.count() == 0) {
                result = self.maintainFanout(context, topic, true).*;
            } else self.fillPublication(context, topic, &result);
        }
        for (context.sessions.rows, 0..) |*row, index| {
            if (row.active and !context.sessions.rows[index].io.tx.pruneExpired(context.now, context.options.pressure_timeout_ms) and context.peers.rows[row.logical.index].direct and self.subscribers(topic).isSet(index)) result.set(index);
        }
        return result;
    }

    fn fillPublication(self: *Overlay, context: *const Context, topic: u16, members: *Set) void {
        if (members.count() >= c.mesh_d) return;
        var candidate_peers: [c.peers_cap]u16 = undefined;
        var count: usize = 0;
        for (0..context.sessions.rows.len) |index| {
            const peer: u16 = @intCast(index);
            if (members.isSet(peer) or context.sessions.rows[peer].outStream() == null) continue;
            if (!self.eligible(context, topic, peer, context.peers.scores.params.publish_threshold)) continue;
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
        while (it.next()) |peer| if (!self.eligible(context, topic, @intCast(peer), context.peers.scores.params.publish_threshold)) {
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
    fn leaveMesh(self: *Overlay, context: *const Context, topic: u16, peer: u16) void {
        if (!self.rows[topic].mesh.isSet(peer)) return;
        context.peers.scores.prune(context.sessions.rows[peer].logical.index, topic, context.now);
        self.rows[topic].mesh.unset(peer);
    }

    pub fn peerDisconnected(self: *Overlay, context: *const Context, peer: u16) void {
        for (&self.rows, 0..) |*row, topic| {
            if (row.active) self.setSubscription(context, @intCast(topic), peer, false);
        }
        if (self.namespace) |*ns| ns.clearPeer(peer);
        context.sessions.rows[peer].io.tx.forgetIntent();
    }

    pub fn peerSubscription(self: *Overlay, context: *const Context, peer: u16, name: []const u8, on: bool) ?u16 {
        if (self.namespace) |*ns| {
            const match = ns.lookup(name) orelse return null;
            ns.setSubscription(peer, match.ordinal, on);
        }
        const topic = self.findTopic(name) orelse return null;
        self.setSubscription(context, topic, peer, on);
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
