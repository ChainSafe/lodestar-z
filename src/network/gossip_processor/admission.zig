const std = @import("std");
const Now = @import("../types.zig").Now;
const processor = @import("root.zig");
const gossip = @import("../gossipsub/root.zig");
const storage = @import("../gossipsub/message_store.zig");
const policy = @import("policy.zig");
const none = @import("../index_list.zig").none;
const assert = std.debug.assert;

pub fn admit(table: *processor.GossipProcessor, owner: *gossip.Gossipsub, candidate: *gossip.Gossipsub.MessageAdmission, now: u64, received_at: u64, slot: u64) bool {
    const message = &candidate.event;
    if (table.closed or now >= message.deadline or table.order == std.math.maxInt(u64)) return false;
    const topic = candidate.canonical orelse return false;
    const kind = topic.name.kind;
    const fork = table.fork(topic.digest) orelse {
        table.refuse(kind, .ineligible);
        return false;
    };
    const deneb = @intFromEnum(fork) >= @intFromEnum(@as(@TypeOf(fork), .deneb));
    const electra = @intFromEnum(fork) >= @intFromEnum(@as(@TypeOf(fork), .electra));
    const metadata = processor.metadata.extract(kind, electra, message.bytes);
    if (!processor.metadata.eligible(&metadata, kind, deneb, slot)) {
        table.diag.slotRefusals +|= 1;
        table.refuse(kind, .ineligible);
        return false;
    }
    if (!policy.sourceRoom(candidate)) return false;
    if (!table.sourceRoom(message.source, kind, message.bytes.len)) {
        table.refuse(kind, .source_full);
        return false;
    }
    const tokens = &table.victim_tokens;
    const handles = &table.victim_handles;
    var count: usize = 0;
    var bytes: usize = 0;
    var cursor = table.expiry.head;
    var inspected: usize = 0;
    while (count <= tokens.len) {
        if (!candidate.charge(count * @sizeOf(processor.GossipProcessor.Cell))) break;
        if (capacityAfter(table, kind, message.bytes.len, tokens[0..count]) and policy.feasible(candidate, handles[0..count])) {
            for (tokens[0..count], handles[0..count]) |token, handle| {
                table.outcome(owner.report(handle, .ignore, Now.fromMilliseconds(.{ .mono_ms = now, .unix_s = 0 })));
                table.retire(token);
            }
            candidate.commit();
            table.capture(message, topic, &metadata, deneb, received_at) catch unreachable;
            return true;
        }
        if (count == tokens.len or !processor.limits.newestFirst(kind)) break;
        var selected: u32 = none;
        // This chain retains network admission order across dependency promotion
        // and copy rollback. State and ready queues deliberately do not.
        while (cursor != none and inspected < table.cells.len) {
            if (!candidate.charge(@sizeOf(processor.GossipProcessor.Cell))) break;
            const index = cursor;
            const cell = &table.cells[index];
            cursor = cell.expiry_link.next;
            inspected += 1;
            if (cell.kind != kind or !cell.replaceable()) continue;
            selected = index;
            break;
        }
        if (selected == none) break;
        const index = selected;
        const cell = &table.cells[index];
        const cost = cell.input.len + candidate.victimBytes(cell.handle);
        if (cost > processor.GossipProcessor.batch_bytes -| bytes or !candidate.charge(cost)) break;
        bytes += cost;
        tokens[count] = .{ .index = @intCast(index), .generation = cell.generation };
        handles[count] = cell.handle;
        count += 1;
    }
    table.diag.capacityRefusals +|= 1;
    table.refuseCapacity(kind, message.bytes.len);
    return false;
}

fn capacityAfter(table: *const processor.GossipProcessor, kind: processor.limits.Kind, len: usize, victims: []const processor.GossipProcessor.Token) bool {
    if (victims.len == 0) return table.hasCapacity(kind, len);
    const k = @intFromEnum(kind);
    var free_cells: usize = table.queues[k][@intFromEnum(processor.GossipProcessor.State.free)].len;
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
