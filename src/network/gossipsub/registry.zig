const std = @import("std");
const constants = @import("constants.zig");
const topic_mod = @import("topic.zig");
const topic_policy = @import("topic_policy.zig");
const score_mod = @import("score.zig");
const local_intent = @import("local_intent.zig");
const State = @import("state.zig").State;
const PeerSet = @import("state.zig").PeerSet;
const assert = std.debug.assert;

pub const Context = struct {
    state: *State,
    peers: *@import("peers.zig").Peers,
    scores: *score_mod.PeerScore,
    validation: *const @import("validation.zig").Validation,
    mesh_policy: *@import("mesh.zig").Mesh,
    options: *const @import("options.zig").Options,
    now: u64,
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

pub const Registry = struct {
    rows: [constants.topics_cap]Row = @splat(.{}),
    namespace: ?topic_policy.Namespace = null,

    pub fn deinit(self: *Registry, a: std.mem.Allocator) void {
        if (self.namespace) |*ns| ns.deinit(a);
    }

    pub fn setLocal(self: *Registry, context: *const Context, index: u16, on: bool) void {
        const row = &self.rows[index];
        assert(row.active);
        if (row.subscribed == on) return;
        if (on) {
            row.fanout = .initEmpty();
            row.retire_after_ms = null;
        } else {
            const mesh_context: @import("mesh.zig").Context = .{ .state = context.state, .peers = context.peers, .scores = context.scores, .now = context.now, .heartbeat_ms = context.options.heartbeat_interval_ms, .pressure_ms = context.options.pressure_timeout_ms };
            var it = row.mesh.iterator(.{});
            while (it.next()) |peer| context.mesh_policy.prune(&mesh_context, index, @intCast(peer), constants.unsubscribe_backoff_ms);
            row.retire_after_ms = context.now +| context.options.retained_score_ms;
        }
        row.subscribed = on;
        for (context.state.peers) |*peer| {
            const io = &peer.io;
            if (!peer.active) continue;
            io.subscription_dirty.set(index);
            if (io.subscription_since == null) io.subscription_since = context.now;
            io.tx_ready = true;
        }
    }

    pub fn internTopic(self: *Registry, context: *const Context, name: []const u8) ?u16 {
        if (!self.validTopic(name)) return null;
        if (self.findTopic(name)) |topic| return topic;
        if (self.internVacant(name)) |topic| return self.initializeTopic(topic);
        const pins = retirementPins(context);
        for (0..constants.topics_cap) |index| {
            const topic: u16 = @intCast(index);
            if (self.rows[topic].generation == std.math.maxInt(u64) or
                !self.retirement(context, topic, &pins, context.now).reusable) continue;
            for (0..constants.topics_cap) |reclaim| self.reclaimObserved(context, @intCast(reclaim), self.retirement(context, @intCast(reclaim), &pins, context.now));
            return self.initializeTopic(self.internVacant(name) orelse unreachable);
        }
        return null;
    }

    pub fn validTopic(self: *const Registry, name: []const u8) bool {
        if (self.namespace) |*ns| return ns.lookup(name) != null;
        return name.len <= topic_mod.topic_max_len and topic_mod.parse(name) != null;
    }

    fn initializeTopic(self: *Registry, topic: u16) u16 {
        if (self.namespace) |*ns| {
            const match = ns.lookup(self.topicString(topic)).?;
            ns.initializeSubscribers(match.ordinal, &self.rows[topic].subscribers);
        }
        return topic;
    }

    fn retirementPins(context: *const Context) local_intent.Pins {
        var pins: local_intent.Pins = .{};
        for (context.validation.recent) |*entry| if (entry.pinned) {
            pins.validation.set(entry.topic);
        };
        for (context.state.peers) |*peer| {
            if (peer.active) pins.announcements.setUnion(peer.io.subscription_dirty);
        }
        return pins;
    }

    const Retirement = struct { blocked: bool, expired: bool, reusable: bool };

    fn retirement(self: *const Registry, context: *const Context, topic: u16, pins: *const local_intent.Pins, now_ms: u64) Retirement {
        const row = &self.rows[topic];
        if (!row.active or row.subscribed or row.mesh.count() > 0 or row.fanout.count() > 0 or
            context.mesh_policy.pending_prunes[topic].count() > 0 or pins.validation.isSet(topic) or
            pins.announcements.isSet(topic)) return .{ .blocked = true, .expired = false, .reusable = false };
        const expired = if (row.retire_after_ms) |deadline| now_ms >= deadline else false;
        var backoff = false;
        for (0..context.peers.rows.len) |peer| {
            const value = context.peers.backoffs[peer * constants.topics_cap + topic];
            if (value.topic_generation == row.generation and now_ms < value.until) {
                backoff = true;
                break;
            }
        }
        return .{ .blocked = false, .expired = expired, .reusable = (expired or !context.scores.retainsTopic(topic)) and !backoff };
    }

    fn reclaimObserved(self: *Registry, context: *const Context, topic: u16, observed: Retirement) void {
        if (observed.blocked) return;
        if (observed.expired) context.scores.resetTopic(topic);
        if (!observed.reusable) return;
        self.rows[topic].active = false;
        self.rows[topic].subscribers = .initEmpty();
        context.scores.applyValidatedTopic(topic, context.options.score_params.topic);
    }

    pub fn reclaimTopic(self: *Registry, context: *const Context, topic: u16) void {
        const pins = retirementPins(context);
        self.reclaimObserved(context, topic, self.retirement(context, topic, &pins, context.now));
    }

    /// Does not mutate protocol state or end event borrows. Commit must immediately follow acceptance.
    pub fn prepareSubscriptions(self: *Registry, context: *const Context, subscriptions: []const local_intent.Subscription, workspace: *local_intent.Workspace, now_ms: u64) local_intent.Error!bool {
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
                changed = changed or !self.subscribed(row) or !std.meta.eql(entry.params, context.scores.topic_params[row]);
            } else changed = true;
        }
        workspace.pins = retirementPins(context);
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

    pub fn commitSubscriptions(self: *Registry, context: *const Context, workspace: *local_intent.Workspace) void {
        assert(workspace.prepared and context.now == workspace.now_ms);
        workspace.prepared = false;
        for (workspace.entries[0..workspace.len]) |*entry| {
            const index = entry.row.?;
            const row = &self.rows[index];
            assert(row.generation == entry.generation);
            if (!entry.existing) {
                context.scores.resetTopic(index);
                row.active = false;
                self.assignTopic(index, entry.name(), entry.generation, entry.name_len);
                self.namespace.?.initializeSubscribers(entry.ordinal, &row.subscribers);
            }
            context.scores.applyValidatedTopic(index, entry.params);
            self.setLocal(context, index, true);
        }
        for (&self.rows, 0..) |*row, index| {
            if (row.active and row.subscribed and !workspace.reserved.isSet(index)) self.setLocal(context, @intCast(index), false);
        }
    }
    pub fn internVacant(self: *Registry, topic_str: []const u8) ?u16 {
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

    pub fn assignTopic(self: *Registry, index: u16, copied: []const u8, generation: u64, name_len: u8) void {
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

    pub fn findTopic(self: *Registry, topic_str: []const u8) ?u16 {
        for (&self.rows, 0..) |*topic, index| {
            if (!topic.active) continue;
            if (std.mem.eql(u8, topic.topicString(), topic_str)) return @intCast(index);
        }
        return null;
    }

    pub fn topicString(self: *const Registry, index: u16) []const u8 {
        return self.rows[index].topicString();
    }

    pub fn setSubscribed(self: *Registry, index: u16, on: bool) void {
        assert(self.rows[index].active);
        self.rows[index].subscribed = on;
    }

    pub fn subscribed(self: *const Registry, index: u16) bool {
        return self.rows[index].active and self.rows[index].subscribed;
    }

    pub fn setSubscription(self: *Registry, topic: u16, peer: u16, on: bool) void {
        assert(self.rows[topic].active);
        if (on) self.rows[topic].subscribers.set(peer) else {
            self.rows[topic].subscribers.unset(peer);
            self.rows[topic].mesh.unset(peer);
            self.rows[topic].fanout.unset(peer);
        }
    }

    pub fn subscribers(self: *const Registry, topic: u16) *const PeerSet {
        return &self.rows[topic].subscribers;
    }

    pub fn mesh(self: *Registry, topic: u16) *PeerSet {
        return &self.rows[topic].mesh;
    }

    pub fn fanout(self: *Registry, topic: u16) *PeerSet {
        return &self.rows[topic].fanout;
    }

    fn freeTopic(self: *Registry) ?usize {
        for (&self.rows, 0..) |*topic, index| {
            if (!topic.active and topic.generation != std.math.maxInt(u64)) return index;
        }
        return null;
    }
};
