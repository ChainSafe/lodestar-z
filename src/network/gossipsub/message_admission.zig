const std = @import("std");
const messages = @import("messages.zig");
const storage = @import("message_store.zig");
const validation = @import("validation.zig");
const topic = @import("topic.zig");
const assert = std.debug.assert;

/// A synchronous borrow. Preflight and commit run under the processor lock on the
/// network owner; no admission or validation mutation may intervene.
pub const Admission = struct {
    messages: *messages.Messages,
    context: *const messages.Context,
    source: *const messages.Source,
    topic_index: u16,
    compressed: []const u8,
    event: messages.MessageEvent,
    committed: bool = false,
    refusal: messages.StorageRefusal = .processor_capacity,

    pub fn feasible(self: *Admission, victims: []const validation.Handle) bool {
        const owner = self.messages;
        const pending = &owner.validation;
        const store = &owner.store;
        const kind = if (topic.parseCanonical(self.event.topic)) |canonical| canonical.name.kind else .beacon_block;
        const k = @intFromEnum(kind);
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
            if (payload.kind == kind) kind_pending -= 1;
            if (payload.provisional or payload.history or payload.tx != 0) continue;
            const released = storage.Store.pagesFor(payload.len);
            pages += released;
            entries += @intFromBool(payload.generation != std.math.maxInt(u64));
            if (payload.kind == kind and !payload.retention_charged) {
                kind_pages -= released;
                kind_entries -= 1;
            }
        }
        if (self.context.options.processor_limits) |limits| {
            if (kind_pending >= limits[k].items) return self.refuse(.kind_validations);
        }
        if (store.limits) |limits| {
            if (kind_entries >= limits[k].items or storage.Store.pagesFor(self.compressed.len) > limits[k].bytes / storage.page_bytes -| kind_pages) return self.refuse(.kind_payload);
        }
        if (available == 0 or records == 0) return self.refuse(.validation_capacity);
        if (pending.index.find(self.event.id)) |index| {
            if (pending.recent[index].reserved or pending.recent[index].state == .pending) return self.refuse(.validation_capacity);
        }
        if (!owner.history.canAdmitPayload(store, self.compressed.len, pages, entries)) return self.refuse(.payload_capacity);
        return true;
    }

    fn refuse(self: *Admission, reason: messages.StorageRefusal) bool {
        self.refusal = reason;
        return false;
    }

    pub fn commit(self: *Admission) void {
        assert(!self.committed);
        const owner = self.messages;
        assert(self.feasible(&.{}));
        var reservation = owner.validation.reserve(self.event.id).?;
        const payload = owner.history.admitPayload(&owner.store, self.event.id, self.event.topic, self.compressed).?;
        self.event.handle = reservation.commit(&owner.store, self.context.peers, payload, self.source.peer, self.context.overlay.ref(self.topic_index), self.event.admitted_ms);
        owner.validation.attribution(self.event.handle).source_eligible = self.context.overlay.inMesh(self.topic_index, self.source.session.index);
        owner.store.seal(payload);
        _ = owner.seen.add(self.event.id, self.event.admitted_ms);
        self.committed = true;
    }
};
