const std = @import("std");
const gossip = @import("network").gossipsub;
const Messages = @FieldType(gossip.Gossipsub, "messages");
const Peers = @FieldType(gossip.Gossipsub, "peers");
const Validation = @FieldType(Messages, "validation");
const Store = @FieldType(Messages, "store");
const Handle = @FieldType(gossip.mcache.HistoryEntry, "message");
const assert = std.debug.assert;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(input: [*]const u8, len: usize) callconv(.c) void {
    if (len == 0 or len > 512) return;
    var memory: [256 * 1024]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const a = arena.allocator();
    var peers = Peers.initCapacity(a, 20, 4, 1) catch unreachable;
    defer peers.deinit(a);
    var messages = Messages.init(a, &.{ .mcache_capacity = 4, .validation_capacity = 2, .seen_capacity = 8, .retained_capacity = 4, .mcache_arena_bytes = 12288, .validation_timeout_ms = 10, .validation_tombstone_ms = 20 }) catch unreachable;
    defer messages.deinit(a, &peers);
    const source = peers.admit(.{ .index = 0, .generation = 1 }, &.{ .identity = .{ .bytes = @splat(1) }, .address = .unspecified, .direction = .inbound }, 0).admitted.peer;
    const duplicate = peers.admit(.{ .index = 1, .generation = 1 }, &.{ .identity = .{ .bytes = @splat(2) }, .address = .unspecified, .direction = .inbound }, 0).admitted.peer;
    var handles: [16]gossip.ValidationHandle = @splat(.{ .index = 0, .generation = 0 });
    var tx: [6]?Handle = @splat(null);
    var now: u64 = 1;
    var payload: [16384]u8 = @splat(9);
    for (input[0..len], 0..) |byte, step| {
        const at = byte / 16;
        const store = &messages.store;
        const validation = &messages.validation;
        switch (byte % 10) {
            0, 1 => if (validation.available()) {
                var id: gossip.MessageId = @splat(0);
                std.mem.writeInt(u64, id[0..8], step + 1, .little);
                if (messages.history.admitPayload(store, id, "/eth2/01020304/beacon_block/ssz_snappy", payload[0 .. 1 + @as(usize, at) * 1024])) |message| {
                    handles[at] = validation.admit(store, &peers, message, source, 0, now);
                    store.seal(message);
                }
            },
            2, 3 => if (validation.inspect(store, &peers, handles[at], now) == null) {
                const handle = handles[at];
                if (byte % 10 == 2) messages.history.put(store, validation.entries[handle.index].state.pending.message);
                validation.finish(store, &peers, handle, if (byte % 10 == 2) .accept else .ignore, now);
            },
            4 => {
                now += 1 + at;
                messages.expire(&peers, now);
            },
            5 => {
                if (messages.history.cycling) messages.history.finishCycle(store) else messages.history.beginCycle();
            },
            6 => {
                const index = at % tx.len;
                const entry = &store.entries[index];
                if (entry.active and tx[index] == null) {
                    const handle: Handle = .{ .index = @intCast(index), .generation = entry.generation };
                    store.retainTx(handle);
                    tx[index] = handle;
                }
            },
            7 => {
                const index = at % tx.len;
                if (tx[index]) |handle| store.releaseTx(handle);
                tx[index] = null;
            },
            8 => if (validation.inspect(store, &peers, handles[at], now) == null) {
                _ = Validation.duplicate(validation.delivery(handles[at]), &peers, duplicate, byte < 128);
            },
            9 => {
                peers.disconnect(source, now, true);
                const admitted = peers.admit(.{ .index = 0, .generation = @intCast(step + 2) }, &.{ .identity = .{ .bytes = @splat(1) }, .address = .unspecified, .direction = .inbound }, now).admitted;
                assert(std.meta.eql(source, admitted.peer));
            },
            else => unreachable,
        }
        var pages: usize = 0;
        var entries: usize = 0;
        var history: usize = 0;
        var pending: usize = 0;
        var pins: [4]u32 = @splat(0);
        for (store.entries, 0..) |entry, i| {
            assert(entry.tx == @intFromBool(tx[i] != null));
            if (!entry.active) continue;
            assert(!entry.provisional);
            assert(entry.validation or entry.history or entry.tx > 0);
            pages += Store.pagesFor(entry.len);
            entries += 1;
            history += @intFromBool(entry.history);
            pending += @intFromBool(entry.validation);
        }
        assert(pages + store.free_pages == store.next.len);
        assert(entries == store.used_entries);
        assert(history == messages.history.count);
        var records: usize = 0;
        for (validation.recent) |record| {
            if (record.state == .pending) records += 1;
            if (!record.pinned) continue;
            assert(peers.matches(record.source));
            pins[record.source.index] += 1;
            for (record.duplicates[0..record.duplicate_len]) |peer| {
                assert(peers.matches(peer.peer));
                pins[peer.peer.index] += 1;
            }
        }
        assert(records == pending);
        for (peers.rows, pins) |peer, expected| assert(peer.pins == expected);
    }
    messages.validation.clear(&messages.store, &peers);
    for (tx) |maybe| if (maybe) |handle| messages.store.releaseTx(handle);
    for (0..messages.history.entries.len) |_| {
        if (!messages.history.evictOldest(&messages.store)) break;
    }
    assert(messages.store.used_entries == 0);
    assert(messages.store.free_pages == messages.store.next.len);
    for (peers.rows) |peer| assert(peer.pins == 0);
}
