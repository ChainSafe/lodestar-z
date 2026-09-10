const std = @import("std");
const mcache = @import("mcache.zig");
const storage = @import("message_store.zig");
const validation = @import("validation.zig");
const Options = @import("options.zig").Options;
const MessageId = @import("topic.zig").MessageId;
const Peers = @import("peer_book.zig").PeerBook;

pub const Context = struct {
    sessions: *@import("sessions.zig").Sessions,
    overlay: *@import("overlay.zig").Overlay,
    peers: *Peers,
    options: *const Options,
};

pub const Messages = struct {
    store: storage.Store,
    history: mcache.History,
    seen: mcache.SeenCache,
    validation: validation.Validation,
    gossip_ids: []MessageId,

    pub fn init(a: std.mem.Allocator, options: *const Options) !Messages {
        var store = try storage.Store.init(a, options.mcache_capacity + options.validation_capacity, options.mcache_arena_bytes);
        errdefer store.deinit(a);
        var history = try mcache.History.initCapacity(a, options.mcache_capacity, options.retained_capacity);
        errdefer history.deinit(a);
        var seen = try mcache.SeenCache.init(a, options.seen_capacity, options.seen_ttl_ms);
        errdefer seen.deinit(a);
        var pending = try validation.Validation.init(a, options.validation_capacity, options.validation_timeout_ms, options.validation_tombstone_ms);
        errdefer pending.deinit(a);
        const gossip_ids = try a.alloc(MessageId, options.mcache_capacity);
        return .{ .store = store, .history = history, .seen = seen, .validation = pending, .gossip_ids = gossip_ids };
    }

    pub fn deinit(self: *Messages, a: std.mem.Allocator, peers: *Peers) void {
        self.validation.clear(&self.store, peers);
        self.validation.deinit(a);
        self.history.deinit(a);
        self.seen.deinit(a);
        self.store.deinit(a);
        a.free(self.gossip_ids);
        self.* = undefined;
    }

    pub fn metadataBytes(self: *const Messages) usize {
        return self.store.entries.len * @sizeOf(storage.Entry) + self.store.next.len * @sizeOf(u32) + self.validation.memoryBytes() +
            self.history.entries.len * @sizeOf(mcache.HistoryEntry) + self.history.counts.len + self.history.generations.len * @sizeOf(u64) +
            self.history.ids.len * @sizeOf(MessageId) + self.history.index.slots.len * @sizeOf(u32) + self.gossip_ids.len * @sizeOf(MessageId) +
            self.seen.ids.len * (@sizeOf(MessageId) + @sizeOf(u64)) + self.seen.index.slots.len * @sizeOf(u32);
    }

    pub fn publish(self: *Messages, id: MessageId, name: []const u8, compressed: []const u8, now: u64) ?storage.Handle {
        const handle = self.history.admitPayload(&self.store, id, name, compressed) orelse return null;
        self.history.put(&self.store, handle);
        self.store.seal(handle);
        std.debug.assert(self.seen.add(id, now));
        return handle;
    }

    fn validationContext(self: *Messages, context: *const Context) validation.Context {
        return .{ .sessions = context.sessions, .overlay = context.overlay, .peers = context.peers, .options = context.options, .store = &self.store, .history = &self.history, .seen = &self.seen };
    }

    pub fn receive(self: *Messages, context: *const Context, workspace: *const validation.Workspace, peer: u16, message: @import("protobuf.zig").Message, now: u64) validation.Received {
        const owner = self.validationContext(context);
        return self.validation.receive(&owner, workspace, peer, message, now);
    }

    pub fn report(self: *Messages, context: *const Context, handle: validation.Handle, verdict: validation.Verdict, now: u64) validation.Report {
        const owner = self.validationContext(context);
        return self.validation.report(&owner, handle, verdict, now);
    }

    pub fn topicPins(self: *const Messages) @import("local_intent.zig").TopicSet {
        var pins: @import("local_intent.zig").TopicSet = .initEmpty();
        for (self.validation.recent) |*entry| if (entry.pinned) {
            pins.set(entry.topic);
        };
        return pins;
    }

    pub fn expire(self: *Messages, peers: *Peers, now: u64) void {
        self.validation.expire(&self.store, peers, now);
    }
};
