const std = @import("std");
const processor = @import("root.zig");
const gossip = @import("../gossipsub/root.zig");
const storage = @import("../gossipsub/message_store.zig");
const none = @import("../index_list.zig").none;
const assert = std.debug.assert;

pub fn admit(table: *processor.GossipProcessor, owner: *gossip.Gossipsub, candidate: *gossip.Admission, now: u64, received_at: u64, slot: u64) bool {
    const message = &candidate.event;
    if (table.closed or now >= message.deadline or table.order == std.math.maxInt(u64)) return false;
    const topic = gossip.topic.parseCanonical(message.topic) orelse return false;
    const kind = topic.name.kind;
    const fork = table.fork(topic.digest) orelse return false;
    const deneb = @intFromEnum(fork) >= @intFromEnum(@as(@TypeOf(fork), .deneb));
    const electra = @intFromEnum(fork) >= @intFromEnum(@as(@TypeOf(fork), .electra));
    const metadata = processor.metadata_mod.extract(kind, electra, message.bytes);
    if (!processor.metadata_mod.eligible(&metadata, kind, deneb, slot)) {
        table.diag.slotRefusals +|= 1;
        return false;
    }
    if (!table.sourceRoom(message.source, kind, message.bytes.len)) return false;
    var tokens: [processor.batch_max]processor.Token = undefined;
    var handles: [processor.batch_max]gossip.ValidationHandle = undefined;
    var count: usize = 0;
    var bytes: usize = 0;
    const states = [_]processor.State{ .queued, .needs_check, .checking, .waiting };
    var cursors: [states.len]u32 = undefined;
    const k = @intFromEnum(kind);
    for (states, &cursors) |state, *cursor| cursor.* = table.queues[k][@intFromEnum(state)].head;
    while (count <= tokens.len) {
        if (capacityAfter(table, kind, message.bytes.len, tokens[0..count]) and candidate.feasible(handles[0..count])) {
            for (tokens[0..count], handles[0..count]) |token, handle| {
                table.outcome(owner.report(handle, .ignore, .{ .mono_ms = now, .unix_s = 0 }));
                table.retire(token);
            }
            candidate.commit();
            table.capture(message, &metadata, deneb, received_at) catch unreachable;
            return true;
        }
        if (count == tokens.len or !processor.limits_mod.newestFirst(kind)) break;
        var selected: ?usize = null;
        for (cursors, 0..) |index, i| {
            if (index != none and (selected == null or table.cells[index].order < table.cells[cursors[selected.?]].order)) selected = i;
        }
        const lane = selected orelse break;
        const index = cursors[lane];
        const cell = &table.cells[index];
        assert(!cell.executing and cell.state != .copying);
        cursors[lane] = cell.state_link.next;
        var cost = cell.input.len;
        const pending = &candidate.messages.validation;
        if (cell.handle.index < pending.entries.len) {
            const entry = &pending.entries[cell.handle.index];
            if (entry.generation == cell.handle.generation and entry.state == .pending) cost += candidate.messages.store.get(entry.state.pending.message).?.len;
        }
        if (cost > processor.batch_bytes -| bytes) break;
        bytes += cost;
        tokens[count] = .{ .index = @intCast(index), .generation = cell.generation };
        handles[count] = cell.handle;
        count += 1;
    }
    table.diag.capacityRefusals +|= 1;
    return false;
}

fn capacityAfter(table: *const processor.GossipProcessor, kind: processor.limits_mod.Kind, len: usize, victims: []const processor.Token) bool {
    if (victims.len == 0) return table.hasCapacity(kind, len);
    const k = @intFromEnum(kind);
    var free_cells: usize = table.queues[k][@intFromEnum(processor.State.free)].len;
    var pages = table.store.free_pages - table.staging_pages;
    var entries = table.store.entries.len - table.store.used_entries - table.store.retired_entries - table.staging_items;
    var used = table.used_bytes[k];
    for (victims) |token| {
        const cell = &table.cells[token.index];
        assert(cell.kind == kind and cell.input.handle != null);
        const payload = table.store.get(cell.input.handle.?).?;
        assert(!payload.provisional and !payload.history and payload.tx == 0);
        const released = storage.Store.pagesFor(cell.input.len);
        pages += released;
        used -= released * storage.page_bytes;
        free_cells += @intFromBool(cell.generation < std.math.maxInt(u64));
        entries += @intFromBool(payload.generation < std.math.maxInt(u64));
    }
    const limits = table.limits[k];
    const required = storage.Store.pagesFor(len);
    return free_cells > 0 and entries > 0 and required <= pages and table.used_items[k] - victims.len < limits.items and required * storage.page_bytes <= limits.bytes -| used;
}
