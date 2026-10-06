const std = @import("std");
const messages = @import("messages.zig");
const storage = @import("message_store.zig");
const validation = @import("validation.zig");
const topic = @import("topic.zig");
const assert = std.debug.assert;
const turn = @import("turn.zig");

/// A synchronous borrow. Preflight and commit run under the processor lock on the
/// network owner; no admission or validation mutation may intervene.
pub const Admission = struct {
    messages: *messages.Messages,
    context: *const messages.Context,
    source: *const messages.Source,
    topic_index: u16,
    canonical: topic.Canonical,
    maximum_compressed: usize,
    compressed: []const u8,
    event: messages.MessageEvent,
    workspace: *const turn.Workspace,
    committed: bool = false,
    refusal: messages.StorageRefusal = .processor_capacity,

    pub const Usage = struct {
        available: usize,
        records: usize,
        pages: usize,
        entries: usize,
        kind_pending: usize,
        kind_pages: usize,
        kind_entries: usize,
    };

    pub const SourceUsage = struct {
        items: usize,
        kind_items: usize,
        kind_bytes: usize,
        maximum_bytes: usize,
        validation_capacity: usize,
    };

    pub fn sourceUsage(self: *const Admission) SourceUsage {
        const pending = &self.messages.validation;
        const k = @intFromEnum(self.kind());
        return .{
            .items = pending.pending_per_peer[self.source.peer.index],
            .kind_items = pending.pending_per_peer_kind[self.source.peer.index][k],
            .kind_bytes = pending.bytes_per_peer_kind[self.source.peer.index][k],
            .maximum_bytes = validation.Validation.chargedBytes(self.maximum_compressed),
            .validation_capacity = pending.entries.len,
        };
    }

    fn kind(self: *const Admission) topic.Kind {
        return self.canonical.name.kind;
    }

    pub fn charge(self: *const Admission, cost: usize) bool {
        return self.workspace.chargeWork(self.context.options, cost);
    }

    pub fn victimBytes(self: *const Admission, handle: validation.Handle) usize {
        const pending = &self.messages.validation;
        if (handle.index >= pending.entries.len) return 0;
        const entry = &pending.entries[handle.index];
        if (entry.generation != handle.generation or entry.state != .pending) return 0;
        return self.messages.store.get(entry.state.pending.message).?.len;
    }

    pub fn usage(self: *const Admission, victims: []const validation.Handle) Usage {
        const owner = self.messages;
        const pending = &owner.validation;
        const store = &owner.store;
        const incoming_kind = self.kind();
        const k = @intFromEnum(incoming_kind);
        var available = pending.available_entries.len;
        var records = pending.free_records.len + pending.resolved_records.len;
        var kind_pending: usize = pending.pending_per_kind[k];
        var pages = store.free_pages;
        var entries = store.entries.len - store.used_entries - store.retired_entries;
        var kind_pages = store.used_by_kind[k] - store.retained_by_kind[k];
        var kind_entries = store.entries_by_kind[k] - store.retained_entries_by_kind[k];
        for (victims, 0..) |handle, i| {
            for (victims[0..i]) |previous| assert(!std.meta.eql(handle, previous));
            if (handle.index >= pending.entries.len) continue;
            const entry = &pending.entries[handle.index];
            if (entry.generation != handle.generation or entry.state != .pending) continue;
            available += @intFromBool(entry.generation != std.math.maxInt(u64));
            records += 1;
            const payload = store.get(entry.state.pending.message).?;
            if (payload.kind == incoming_kind) kind_pending -= 1;
            if (payload.provisional or payload.history) continue;
            const released = storage.Store.pagesFor(payload.len);
            pages += released;
            entries += @intFromBool(payload.generation != std.math.maxInt(u64));
            if (payload.kind == incoming_kind) {
                kind_pages -= released;
                kind_entries -= 1;
            }
        }
        return .{ .available = available, .records = records, .pages = pages, .entries = entries, .kind_pending = kind_pending, .kind_pages = kind_pages, .kind_entries = kind_entries };
    }

    /// Global physical feasibility only. Per-kind and source policy belongs to the processor.
    pub fn feasible(self: *Admission, resources: *const Usage) bool {
        const owner = self.messages;
        const pending = &owner.validation;
        const store = &owner.store;
        if (resources.available == 0 or resources.records == 0) return self.refuse(.validation_capacity);
        if (pending.index.find(self.event.id)) |index| {
            if (pending.recent[index].reserved or pending.recent[index].state == .pending) return self.refuse(.validation_capacity);
        }
        if (!owner.history.canAdmitPayload(store, self.compressed.len, resources.pages, resources.entries)) return self.refuse(.payload_capacity);
        return true;
    }

    pub fn refuse(self: *Admission, reason: messages.StorageRefusal) bool {
        self.refusal = reason;
        return false;
    }

    pub fn commit(self: *Admission) void {
        assert(!self.committed);
        const owner = self.messages;
        const resources = self.usage(&.{});
        assert(self.feasible(&resources));
        var reservation = owner.validation.reserve(self.event.id).?;
        const payload = owner.history.admitPayload(&owner.store, self.event.id, self.event.topic, self.compressed).?;
        self.event.handle = reservation.commit(&owner.store, self.context.peers, payload, self.source.peer, self.topic_index, self.event.admitted_ms);
        owner.validation.attribution(self.event.handle).source_eligible = self.context.overlay.inMesh(self.topic_index, self.source.session.index);
        owner.store.seal(payload);
        _ = owner.seen.add(self.event.id, self.event.admitted_ms);
        self.committed = true;
    }
};
