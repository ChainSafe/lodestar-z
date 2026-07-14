const std = @import("std");
const js = @import("zapi:zapi").js;
const bls = @import("bls");
const blst_bindings = @import("./blst.zig");
const PubkeyIndexMap = @import("state_transition").PubkeyIndexMap;
const Index2PubkeyCache = @import("state_transition").Index2PubkeyCache;
const napi_io = @import("./io.zig");
const preset = @import("preset").preset;

/// Uses page allocator for internal allocations.
/// It's recommended to never reallocate the pubkey2index after initialization.
const allocator = std.heap.page_allocator;

const default_initial_capacity: u32 = 0;
const max_stack_aggregate_pubkeys = 512;

/// Capacity added when a set() outgrows the current capacity. Covers ~3 months of
/// worst-case validator registry growth (MAX_PENDING_DEPOSITS_PER_EPOCH new validators
/// per epoch at 12s slots), so growth stays proportionate at any network scale.
const growth_step: u32 = preset.MAX_PENDING_DEPOSITS_PER_EPOCH * ((90 * 24 * 60 * 60) / (12 * preset.SLOTS_PER_EPOCH));

const State = struct {
    pubkey2index: PubkeyIndexMap = undefined,
    index2pubkey: Index2PubkeyCache = undefined,
    initialized: bool = false,

    pub fn init(self: *State) !void {
        if (self.initialized) return;
        self.pubkey2index = PubkeyIndexMap.init(allocator);
        try self.pubkey2index.ensureTotalCapacity(default_initial_capacity);
        self.index2pubkey = try Index2PubkeyCache.initCapacity(allocator, default_initial_capacity);
        self.initialized = true;
    }

    pub fn deinit(self: *State) void {
        if (!self.initialized) return;
        self.pubkey2index.deinit();
        self.index2pubkey.deinit(allocator);
        self.initialized = false;
    }

    pub fn reset(self: *State) !void {
        if (!self.initialized) return;

        self.pubkey2index.clearRetainingCapacity();
        self.index2pubkey.shrinkRetainingCapacity(0);
    }
};

pub var state: State = .{};

/// Must only be called after pubkey2index has been initialized with a capacity.
/// Must be kept in sync with std/hashmap.zig
fn pubkey2indexWrittenSize() usize {
    const K = [48]u8;
    const V = u64;
    const Header = struct {
        values: [*]V,
        keys: [*]K,
        capacity: u32,
    };
    const Metadata = packed struct {
        const FingerPrint = u7;
        fingerprint: FingerPrint,
        used: u1,
    };
    const header_align = @alignOf(Header);
    const key_align = @alignOf(K);
    const val_align = @alignOf(V);
    const max_align = comptime @max(header_align, key_align, val_align);

    const new_cap: usize = state.pubkey2index.capacity();
    const meta_size = @sizeOf(Header) + new_cap * @sizeOf(Metadata);

    const keys_start = std.mem.alignForward(usize, meta_size, key_align);
    const keys_end = keys_start + new_cap * @sizeOf(K);

    const vals_start = std.mem.alignForward(usize, keys_end, val_align);
    const vals_end = vals_start + new_cap * @sizeOf(V);

    const total_size = std.mem.alignForward(usize, vals_end, max_align);

    return total_size - @sizeOf(Header);
}

/// JS: pubkeys.save(filePath)
pub fn save(file_path: js.String) !void {
    var file_path_buf: [1024]u8 = undefined;
    const path = try file_path.toSlice(&file_path_buf);
    const io = napi_io.get();
    const file = try std.Io.Dir.createFile(.cwd(), io, path, .{});
    defer file.close(io);

    // Write header: Magic "PKIX" + len + capacity
    var header: [12]u8 = [_]u8{ 'P', 'K', 'I', 'X', 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, header[4..8], @intCast(state.index2pubkey.items.len), .little);
    std.mem.writeInt(u32, header[8..12], @intCast(state.index2pubkey.capacity), .little);

    var write_buf: [4096]u8 = undefined;
    var file_writer = file.writer(io, &write_buf);
    var writer = &file_writer.interface;
    try writer.writeAll(header[0..12]);

    // Write pubkey2index entries
    const p2i_size = pubkey2indexWrittenSize();
    const ptr: [*]u8 = @ptrCast(state.pubkey2index.unmanaged.metadata.?);
    try writer.writeAll(ptr[0..p2i_size]);

    // Write index2pubkey entries
    try writer.writeAll(std.mem.sliceAsBytes(state.index2pubkey.items));

    try file_writer.end();
}

/// JS: pubkeys.load(filePath)
pub fn load(file_path: js.String) !void {
    var file_path_buf: [1024]u8 = undefined;
    const path = try file_path.toSlice(&file_path_buf);
    const io = napi_io.get();
    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);

    if (state.initialized) {
        state.deinit();
    }

    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &read_buf);

    const header = try file_reader.interface.takeArray(12);

    if (!std.mem.eql(u8, header[0..4], &[_]u8{ 'P', 'K', 'I', 'X' })) {
        return error.InvalidPubkeyIndexFile;
    }

    const len = std.mem.readInt(u32, header[4..8], .little);
    const saved_capacity = std.mem.readInt(u32, header[8..12], .little);

    const file_size = try file.length(io);

    state.pubkey2index = PubkeyIndexMap.init(allocator);
    try state.pubkey2index.ensureTotalCapacity(saved_capacity);
    errdefer state.pubkey2index.deinit();
    state.index2pubkey = try Index2PubkeyCache.initCapacity(allocator, saved_capacity);
    errdefer state.index2pubkey.deinit(allocator);
    try state.index2pubkey.resize(allocator, len);

    const p2i_size = pubkey2indexWrittenSize();
    const i2p_size = @sizeOf(bls.PublicKey) * len;

    if (file_size != 12 + p2i_size + i2p_size) {
        return error.InvalidPubkeyIndexFile;
    }

    // Read pubkey2index entries
    const ptr: [*]u8 = @ptrCast(state.pubkey2index.unmanaged.metadata.?);
    try file_reader.interface.readSliceAll(ptr[0..p2i_size]);

    state.pubkey2index.unmanaged.size = len;
    state.pubkey2index.unmanaged.available = saved_capacity - len;

    // Read index2pubkey entries
    try file_reader.interface.readSliceAll(std.mem.sliceAsBytes(state.index2pubkey.items));

    state.initialized = true;
}

/// JS: pubkeys.reset()
pub fn reset() !void {
    try state.reset();
}

/// JS: pubkeys.getIndex(pubkeyBytes) → number | null
pub fn getIndex(pubkey: js.Uint8Array) !js.Value {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const pubkey_slice = try pubkey.toSlice();
    if (pubkey_slice.len != 48) return error.InvalidPubkeyLength;

    const e = js.env();
    if (state.pubkey2index.get(pubkey_slice[0..48].*)) |index| {
        return .{ .val = try e.createUint32(@intCast(index)) };
    }
    return .{ .val = try e.getNull() };
}

/// JS: pubkeys.get(index) → PublicKey | undefined
pub fn get(index: js.Number) !?blst_bindings.PublicKey {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const idx = try index.toU32();
    if (idx >= state.index2pubkey.items.len) return null;

    return .{ .raw = state.index2pubkey.items[@intCast(idx)] };
}

/// Aggregate multiple `PublicKey`s by the given
/// validator `indices` into one.
///
/// Validation is not required here since it is done upon
/// processing validator deposits.
///
/// JS: pubkeys.aggregate(indices) → PublicKey
pub fn aggregate(indices: js.Array) !blst_bindings.PublicKey {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const len = try indices.length();
    if (len == 0) return error.EmptyPublicKeyArray;

    if (len == 1) {
        const idx = try (try indices.getNumber(0)).toU32();
        if (idx >= state.index2pubkey.items.len) return error.PubkeyIndexNotFound;
        return .{ .raw = state.index2pubkey.items[@intCast(idx)] };
    }

    var pks_stack: [max_stack_aggregate_pubkeys]bls.PublicKey = undefined;
    const pks = if (len <= pks_stack.len)
        pks_stack[0..len]
    else blk: {
        const buf = try allocator.alloc(bls.PublicKey, len);
        break :blk buf;
    };
    defer if (len > pks_stack.len) allocator.free(pks);

    for (0..len) |i| {
        const idx = try (try indices.getNumber(@intCast(i))).toU32();
        if (idx >= state.index2pubkey.items.len) return error.PubkeyIndexNotFound;
        pks[i] = state.index2pubkey.items[@intCast(idx)];
    }

    const agg_pk = bls.AggregatePublicKey.aggregate(pks, false) catch
        return error.AggregationFailed;

    return .{ .raw = agg_pk.toPublicKey() };
}

/// JS: pubkeys.set(index, pubkeyBytes)
pub fn set(index: js.Number, pubkey: js.Uint8Array) !void {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const idx = try index.toU32();

    // Since the cache is append only, if the index is less than
    // the cache's items length, we assume it already exists
    if (idx < state.index2pubkey.items.len)
        return;

    const pubkey_slice = try pubkey.toSlice();
    if (pubkey_slice.len != 48) return error.InvalidPubkeyLength;

    const pubkey_bytes = pubkey_slice[0..48];

    // Ensure capacity if needed
    if (idx >= state.index2pubkey.capacity) {
        const new_cap: u32 = @intCast(@max(idx + 1, state.index2pubkey.capacity + growth_step));
        try state.pubkey2index.ensureTotalCapacity(new_cap);
        try state.index2pubkey.ensureTotalCapacityPrecise(allocator, new_cap);
    }

    // Extend length if needed
    if (idx >= state.index2pubkey.items.len) {
        try state.index2pubkey.resize(allocator, idx + 1);
    }

    // Set pubkey2index
    state.pubkey2index.put(pubkey_bytes.*, @intCast(idx)) catch return error.PubkeyIndexInsertFailed;

    // Deserialize and set index2pubkey
    state.index2pubkey.items[@intCast(idx)] = try bls.PublicKey.uncompress(pubkey_bytes);
}

/// JS: pubkeys.size() → number
/// Note: zapi DSL does not yet support namespace-level getters, so this is a function.
pub fn size() !js.Number {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    return js.Number.from(@as(u32, @intCast(state.index2pubkey.items.len)));
}

/// JS: pubkeys.ensureCapacity(newSize)
pub fn ensureCapacity(new_size: js.Number) !void {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const requested = try new_size.toU32();
    const old_size = state.index2pubkey.capacity;
    if (requested <= old_size) return;

    try state.pubkey2index.ensureTotalCapacity(requested);
    // Not precise on purpose, the growth curve overshoot leaves slack for states with
    // slightly more validators than reserved, which the zig-side syncPubkeys cannot
    // grow safely (it does not own the backing allocator)
    try state.index2pubkey.ensureTotalCapacity(allocator, requested);
}

/// JS: pubkeys.capacity() → number
/// Note: zapi DSL does not yet support namespace-level getters, so this is a function.
pub fn capacity() !js.Number {
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    return js.Number.from(@as(u32, @intCast(state.index2pubkey.capacity)));
}
