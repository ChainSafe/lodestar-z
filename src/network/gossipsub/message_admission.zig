const std = @import("std");
const messages = @import("messages.zig");
const storage = @import("message_store.zig");
const validation = @import("validation.zig");
const topic = @import("topic.zig");
const assert = std.debug.assert;
const turn = @import("turn.zig");
const limits_mod = @import("../gossip_limits.zig");

/// A synchronous borrow on the network owner. The consumer serializes preflight,
/// replacement and commit with its own state. Only preflighted victims may be
/// retired between preflight and commit.
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

    const Usage = struct {
        available: usize,
        records: usize,
        pages: usize,
        entries: usize,
        kind_pages: usize,
        kind_entries: usize,
    };

    /// Check before considering victims: replacing one's own work must not renew
    /// a source's full share.
    pub fn sourceRoom(self: *Admission) bool {
        const pending = &self.messages.validation;
        const source = self.source.peer.index;
        const k = @intFromEnum(self.kind());
        if (self.context.options.payload_limits) |limits| {
            const limit = limits[k];
            const maximum = validation.Validation.chargedBytes(self.maximum_compressed);
            const bytes = limits_mod.sourceBytes(limit, maximum, storage.inline_bytes);
            if (pending.pending_per_peer_kind[source][k] >= limits_mod.sourceItems(limit) or
                validation.Validation.chargedBytes(self.compressed.len) > bytes -| pending.bytes_per_peer_kind[source][k])
                return self.refuse(.peer_validations);
        } else if (pending.pending_per_peer[source] >= @max(1, pending.entries.len / 2)) return self.refuse(.peer_validations);
        return true;
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

    fn usage(self: *const Admission, victims: []const validation.Handle) Usage {
        const owner = self.messages;
        const pending = &owner.validation;
        const store = &owner.store;
        const incoming_kind = self.kind();
        const k = @intFromEnum(incoming_kind);
        var available = pending.available_entries.len;
        var records = pending.free_records.len + pending.resolved_records.len;
        var pages = store.free_pages;
        var entries = store.entries.len - store.used_entries - store.retired_entries;
        var kind_pages = store.used_by_kind[k] - store.retained_by_kind[k];
        // At admission boundaries, every unretained entry belongs to a pending validation.
        // Acceptance moves the entry to history and finishes validation in one owner call.
        var kind_entries = store.entries_by_kind[k] - store.retained_entries_by_kind[k];
        for (victims, 0..) |handle, i| {
            for (victims[0..i]) |previous| assert(!std.meta.eql(handle, previous));
            if (handle.index >= pending.entries.len) continue;
            const entry = &pending.entries[handle.index];
            if (entry.generation != handle.generation or entry.state != .pending) continue;
            available += @intFromBool(entry.generation != std.math.maxInt(u64));
            records += 1;
            const payload = store.get(entry.state.pending.message).?;
            if (payload.provisional or payload.history) continue;
            const released = storage.Store.pagesFor(payload.len);
            pages += released;
            entries += @intFromBool(payload.generation != std.math.maxInt(u64));
            if (payload.kind == incoming_kind) {
                kind_pages -= released;
                kind_entries -= 1;
            }
        }
        return .{ .available = available, .records = records, .pages = pages, .entries = entries, .kind_pages = kind_pages, .kind_entries = kind_entries };
    }

    /// Checks compressed storage and validation capacity after retiring `victims`.
    /// Does not release victims or retained history. Call `sourceRoom` first.
    pub fn feasible(self: *Admission, victims: []const validation.Handle) bool {
        // Receipt work covers constant-time admission; replacement pays for each repeated preflight.
        if (!self.charge(victims.len * @sizeOf(Usage))) return false;
        const resources = self.usage(victims);
        if (self.context.options.payload_limits) |limits| {
            const limit = limits[@intFromEnum(self.kind())];
            if (resources.kind_entries >= limit.items) return self.refuse(.kind_validations);
            if (storage.Store.pagesFor(self.compressed.len) > limit.bytes / storage.page_bytes -| resources.kind_pages) return self.refuse(.kind_payload);
        }
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

    fn refuse(self: *Admission, reason: messages.StorageRefusal) bool {
        self.refusal = reason;
        return false;
    }

    /// Ignore a victim included in the successful preflight, before committing its replacement.
    pub fn discardVictim(self: *Admission, handle: validation.Handle) validation.Outcome {
        assert(!self.committed);
        return self.messages.report(self.context, handle, .ignore, self.event.admitted_ms).outcome();
    }

    pub fn commit(self: *Admission) void {
        assert(!self.committed);
        const owner = self.messages;
        const feasible_now = self.feasible(&.{});
        assert(feasible_now);
        var reservation = owner.validation.reserve(self.event.id).?;
        const payload = owner.history.admitPayload(&owner.store, self.event.id, self.event.topic, self.compressed).?;
        self.event.handle = reservation.commit(&owner.store, self.context.peers, payload, self.source.peer, self.topic_index, self.event.admitted_ms);
        owner.validation.attribution(self.event.handle).source_eligible = self.context.overlay.inMesh(self.topic_index, self.source.session.index);
        owner.store.seal(payload);
        _ = owner.seen.add(self.event.id, self.event.admitted_ms);
        self.committed = true;
    }
};

test {
    _ = @import("message_admission_test.zig");
}
