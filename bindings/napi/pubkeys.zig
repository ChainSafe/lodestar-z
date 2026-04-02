const std = @import("std");
const js = @import("zapi").js;
const napi = @import("zapi").napi;
const bls = @import("bls");
const blst_bindings = @import("./blst.zig");
const PubkeyIndexMap = @import("state_transition").PubkeyIndexMap;
const Index2PubkeyCache = @import("state_transition").Index2PubkeyCache;

/// Uses page allocator for internal allocations.
/// It's recommended to never reallocate the pubkey2index after initialization.
const allocator = std.heap.page_allocator;

const default_initial_capacity: u32 = 0;

pub const State = struct {
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
        self.index2pubkey.deinit();
        self.initialized = false;
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
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();

    // Write header: Magic "PKIX" + len + capacity
    var header: [12]u8 = [_]u8{ 'P', 'K', 'I', 'X', 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, header[4..8], @intCast(state.index2pubkey.items.len), .little);
    std.mem.writeInt(u32, header[8..12], @intCast(state.index2pubkey.capacity), .little);
    try file.writeAll(header[0..12]);

    // Write pubkey2index entries
    const p2i_size = pubkey2indexWrittenSize();
    const ptr: [*]u8 = @ptrCast(state.pubkey2index.unmanaged.metadata.?);
    try file.writeAll(ptr[0..p2i_size]);

    // Write index2pubkey entries
    try file.writeAll(std.mem.sliceAsBytes(state.index2pubkey.items));
}

/// JS: pubkeys.load(filePath)
pub fn load(file_path: js.String) !void {
    var file_path_buf: [1024]u8 = undefined;
    const path = try file_path.toSlice(&file_path_buf);
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    if (state.initialized) {
        state.deinit();
    }

    var header: [12]u8 = undefined;
    const header_len = try file.readAll(&header);
    if (header_len != 12) {
        return error.InvalidPubkeyIndexFile;
    }

    if (!std.mem.eql(u8, header[0..4], &[_]u8{ 'P', 'K', 'I', 'X' })) {
        return error.InvalidPubkeyIndexFile;
    }

    const len = std.mem.readInt(u32, header[4..8], .little);
    const capacity = std.mem.readInt(u32, header[8..12], .little);

    const file_size = try file.getEndPos();

    state.pubkey2index = PubkeyIndexMap.init(allocator);
    try state.pubkey2index.ensureTotalCapacity(capacity);
    errdefer state.pubkey2index.deinit();
    state.index2pubkey = try Index2PubkeyCache.initCapacity(allocator, capacity);
    errdefer state.index2pubkey.deinit();
    state.index2pubkey.items.len = len;

    const p2i_size = pubkey2indexWrittenSize();
    const i2p_size = @sizeOf(bls.PublicKey) * len;

    if (file_size != 12 + p2i_size + i2p_size) {
        return error.InvalidPubkeyIndexFile;
    }

    // Read pubkey2index entries
    const ptr: [*]u8 = @ptrCast(state.pubkey2index.unmanaged.metadata.?);
    _ = try file.readAll(ptr[0..p2i_size]);

    state.pubkey2index.unmanaged.size = len;
    state.pubkey2index.unmanaged.available = capacity - len;

    // Read index2pubkey entries
    _ = try file.readAll(std.mem.sliceAsBytes(state.index2pubkey.items));

    state.initialized = true;
}

/// JS: pubkeys.getIndex(pubkeyBytes) → number | null
/// Returns the index for a 48-byte pubkey, or undefined if not found.
pub fn getIndex(pubkey: js.Uint8Array) !js.Value {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const pubkey_slice = try pubkey.toSlice();
    if (pubkey_slice.len != 48) {
        return error.InvalidPubkeyLength;
    }

    const e = js.env();
    if (state.pubkey2index.get(pubkey_slice[0..48].*)) |index| {
        const val = try e.createUint32(@intCast(index));
        return .{ .val = val };
    } else {
        const val = try e.getNull();
        return .{ .val = val };
    }
}

/// JS: pubkeys.get(index) → PublicKey | undefined
/// Returns the PublicKey at the given index, or undefined if out of bounds.
/// Uses low-level N-API for PublicKey class interop.
pub fn get(index: js.Number) !js.Value {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const e = js.env();
    const idx = index.assertU32();
    if (idx >= state.index2pubkey.items.len) {
        const undef = try e.getUndefined();
        return .{ .val = undef };
    }

    // Drop to low-level for PublicKey class interop
    const out = try blst_bindings.newPublicKeyInstance(e);
    const out_pubkey = try e.unwrap(bls.PublicKey, out);
    out_pubkey.* = state.index2pubkey.items[@intCast(idx)];
    return .{ .val = out };
}

/// JS: pubkeys.set(index, pubkeyBytes)
pub fn set(index: js.Number, pubkey: js.Uint8Array) !void {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const idx = index.assertU32();
    const pubkey_slice = try pubkey.toSlice();
    if (pubkey_slice.len != 48) {
        return error.InvalidPubkeyLength;
    }

    const pubkey_bytes = pubkey_slice[0..48];

    // Ensure capacity if needed
    if (idx >= state.index2pubkey.capacity) {
        const new_cap: u32 = @intCast(@max(idx + 1, state.index2pubkey.capacity * 2));
        try state.pubkey2index.ensureTotalCapacity(new_cap);
        try state.index2pubkey.ensureTotalCapacity(new_cap);
    }

    // Extend length if needed
    if (idx >= state.index2pubkey.items.len) {
        state.index2pubkey.items.len = idx + 1;
    }

    // Set pubkey2index
    state.pubkey2index.put(pubkey_bytes.*, @intCast(idx)) catch return error.PubkeyIndexInsertFailed;

    // Deserialize and set index2pubkey
    state.index2pubkey.items[@intCast(idx)] = try bls.PublicKey.uncompress(pubkey_bytes);
}

/// JS: pubkeys.size → number (getter)
/// Note: DSL doesn't support getters yet, so this is a function.
pub fn size() !js.Number {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    return js.Number.from(@as(u32, @intCast(state.index2pubkey.items.len)));
}

/// JS: pubkeys.ensureCapacity(newSize)
pub fn ensureCapacity(new_size: js.Number) !void {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const requested = new_size.assertU32();
    const old_size = state.index2pubkey.capacity;
    if (requested <= old_size) {
        return;
    }
    try state.pubkey2index.ensureTotalCapacity(requested);
    try state.index2pubkey.ensureTotalCapacity(requested);
}
