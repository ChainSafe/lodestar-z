const std = @import("std");
const napi = @import("zapi:napi");
const blst = @import("blst");
const blst_bindings = @import("./blst.zig");
const PubkeyIndexMap = @import("state_transition").PubkeyIndexMap;
const Index2PubkeyCache = @import("state_transition").Index2PubkeyCache;
const getter = @import("napi_property_descriptor.zig").getter;
const method = @import("napi_property_descriptor.zig").method;

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

pub fn pubkeys_save(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    var file_path_buf: [1024]u8 = undefined;
    const file_path = try cb.arg(0).getValueStringUtf8(&file_path_buf);
    var file = try std.fs.cwd().createFile(file_path, .{ .truncate = true });
    defer file.close();

    // Write header
    // Magic "PKIX" + len + capacity

    var header: [12]u8 = [_]u8{ 'P', 'K', 'I', 'X', 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, header[4..8], @intCast(state.index2pubkey.items.len), .little);
    std.mem.writeInt(u32, header[8..12], @intCast(state.index2pubkey.capacity), .little);
    try file.writeAll(header[0..12]);

    // Write pubkey2index entries
    const p2i_size = pubkey2indexWrittenSize();
    const ptr: [*]u8 = @ptrCast(state.pubkey2index.unmanaged.metadata.?);
    const slice = ptr[0..p2i_size];
    try file.writeAll(slice);

    // Write index2pubkey entries
    try file.writeAll(std.mem.sliceAsBytes(state.index2pubkey.items));

    return env.getUndefined();
}

pub fn pubkeys_load(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    var file_path_buf: [1024]u8 = undefined;
    const file_path = try cb.arg(0).getValueStringUtf8(&file_path_buf);
    var file = try std.fs.cwd().openFile(file_path, .{});
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
    const i2p_size = @sizeOf(blst.PublicKey) * len;

    if (file_size != 12 + p2i_size + i2p_size) {
        return error.InvalidPubkeyIndexFile;
    }

    // Read pubkey2index entries
    const ptr: [*]u8 = @ptrCast(state.pubkey2index.unmanaged.metadata.?);
    const slice = ptr[0..p2i_size];
    _ = try file.readAll(slice);

    state.pubkey2index.unmanaged.size = len;
    state.pubkey2index.unmanaged.available = capacity - len;

    // Read index2pubkey entries
    const index2pubkey_bytes = std.mem.sliceAsBytes(state.index2pubkey.items);
    _ = try file.readAll(index2pubkey_bytes);

    state.initialized = true;
    return env.getUndefined();
}

pub fn pubkeys_getIndex(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const pubkey_info = try cb.arg(0).getTypedarrayInfo();
    if (pubkey_info.data.len != 48) {
        return error.InvalidPubkeyLength;
    }

    const index = state.pubkey2index.get(pubkey_info.data[0..48].*) orelse return env.getNull();
    return try env.createUint32(@intCast(index));
}

pub fn pubkeys_get(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const index = try cb.arg(0).getValueUint32();
    if (index >= state.index2pubkey.items.len) {
        return env.getUndefined();
    }

    const out = try blst_bindings.newPublicKeyInstance(env);
    const out_pubkey = try env.unwrap(blst.PublicKey, out);
    out_pubkey.* = state.index2pubkey.items[@intCast(index)];
    return out;
}

pub fn pubkeys_set(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const index = try cb.arg(0).getValueUint32();
    const pubkey_info = try cb.arg(1).getTypedarrayInfo();
    if (pubkey_info.data.len != 48) {
        return error.InvalidPubkeyLength;
    }

    const pubkey_bytes = pubkey_info.data[0..48];

    // Ensure capacity if needed
    if (index >= state.index2pubkey.capacity) {
        const new_cap: u32 = @intCast(@max(index + 1, state.index2pubkey.capacity * 2));
        try state.pubkey2index.ensureTotalCapacity(new_cap);
        try state.index2pubkey.ensureTotalCapacity(new_cap);
    }

    // Extend length if needed
    if (index >= state.index2pubkey.items.len) {
        state.index2pubkey.items.len = index + 1;
    }

    // Set pubkey2index
    state.pubkey2index.put(pubkey_bytes.*, @intCast(index)) catch return error.PubkeyIndexInsertFailed;

    // Deserialize and set index2pubkey
    state.index2pubkey.items[@intCast(index)] = try blst.PublicKey.uncompress(pubkey_bytes);

    return env.getUndefined();
}

pub fn pubkeys_size(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    return try env.createUint32(@intCast(state.index2pubkey.items.len));
}

pub fn pubkeys_ensureCapacity(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!state.initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const old_size = state.index2pubkey.capacity;
    const new_size = try cb.arg(0).getValueUint32();
    if (new_size <= old_size) {
        return env.getUndefined();
    }
    try state.pubkey2index.ensureTotalCapacity(new_size);
    try state.index2pubkey.ensureTotalCapacity(new_size);
    return env.getUndefined();
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const pubkeys_obj = try env.createObject();

    try pubkeys_obj.defineProperties(&[_]napi.c.napi_property_descriptor{
        method(1, pubkeys_load),
        method(1, pubkeys_save),
        method(1, pubkeys_ensureCapacity),
        method(1, pubkeys_get),
        method(1, pubkeys_getIndex),
        method(2, pubkeys_set),
        getter(pubkeys_size),
    });

    try exports.setNamedProperty("pubkeys", pubkeys_obj);
}
