const std = @import("std");
const napi = @import("zapi:napi");
const blst = @import("blst");
const PubkeyIndexMap = @import("state_transition").PubkeyIndexMap;
const Index2PubkeyCache = @import("state_transition").Index2PubkeyCache;

/// Pool uses page allocator for internal allocations.
/// It's recommended to never reallocate the pubkey2index after initialization.
const allocator = std.heap.page_allocator;

/// A global pubkey2index for N-API bindings to use.
pub var pubkey2index: PubkeyIndexMap = undefined;
/// A global index2pubkey for N-API bindings to use.
pub var index2pubkey: Index2PubkeyCache = undefined;
var initialized: bool = false;

const default_initial_capacity: u32 = 0;

pub fn init() !void {
    if (initialized) {
        return;
    }

    pubkey2index = PubkeyIndexMap.init(allocator);
    try pubkey2index.ensureTotalCapacity(default_initial_capacity);
    index2pubkey = try Index2PubkeyCache.initCapacity(allocator, default_initial_capacity);
    initialized = true;
}

pub fn deinit() void {
    if (!initialized) {
        return;
    }

    pubkey2index.deinit();
    index2pubkey.deinit();
    initialized = false;
}

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

    const new_cap: usize = pubkey2index.capacity();
    const meta_size = @sizeOf(Header) + new_cap * @sizeOf(Metadata);

    const keys_start = std.mem.alignForward(usize, meta_size, key_align);
    const keys_end = keys_start + new_cap * @sizeOf(K);

    const vals_start = std.mem.alignForward(usize, keys_end, val_align);
    const vals_end = vals_start + new_cap * @sizeOf(V);

    const total_size = std.mem.alignForward(usize, vals_end, max_align);

    return total_size - @sizeOf(Header);
}

pub fn save(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    var file_path_buf: [1024]u8 = undefined;
    const file_path = try cb.arg(0).getValueStringUtf8(&file_path_buf);
    var file = try std.fs.cwd().createFile(file_path, .{ .truncate = true });
    defer file.close();

    // Write header
    // Magic "PKIX" + len + capacity

    var header: [12]u8 = [_]u8{ 'P', 'K', 'I', 'X', 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, header[4..8], @intCast(index2pubkey.items.len), .little);
    std.mem.writeInt(u32, header[8..12], @intCast(index2pubkey.capacity), .little);
    try file.writeAll(header[0..12]);

    // Write pubkey2index entries
    const p2i_size = pubkey2indexWrittenSize();
    const ptr: [*]u8 = @ptrCast(pubkey2index.unmanaged.metadata.?);
    const slice = ptr[0..p2i_size];
    try file.writeAll(slice);

    // Write index2pubkey entries
    try file.writeAll(std.mem.sliceAsBytes(index2pubkey.items));

    return env.getUndefined();
}

pub fn load(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    var file_path_buf: [1024]u8 = undefined;
    const file_path = try cb.arg(0).getValueStringUtf8(&file_path_buf);
    var file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    if (initialized) {
        deinit();
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

    pubkey2index = PubkeyIndexMap.init(allocator);
    try pubkey2index.ensureTotalCapacity(capacity);
    errdefer pubkey2index.deinit();
    index2pubkey = try Index2PubkeyCache.initCapacity(allocator, capacity);
    errdefer index2pubkey.deinit();
    index2pubkey.items.len = len;

    const p2i_size = pubkey2indexWrittenSize();
    const i2p_size = @sizeOf(blst.PublicKey) * len;

    if (file_size != 12 + p2i_size + i2p_size) {
        return error.InvalidPubkeyIndexFile;
    }

    // Read pubkey2index entries
    const ptr: [*]u8 = @ptrCast(pubkey2index.unmanaged.metadata.?);
    const slice = ptr[0..p2i_size];
    _ = try file.readAll(slice);

    pubkey2index.unmanaged.size = len;
    pubkey2index.unmanaged.available = capacity - len;

    // Read index2pubkey entries
    const index2pubkey_bytes = std.mem.sliceAsBytes(index2pubkey.items);
    _ = try file.readAll(index2pubkey_bytes);

    initialized = true;
    return env.getUndefined();
}

pub fn pubkey2indexGet(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const pubkey_info = try cb.arg(0).getTypedarrayInfo();
    if (pubkey_info.data.len != 48) {
        return error.InvalidPubkeyLength;
    }

    const index = pubkey2index.get(pubkey_info.data[0..48].*) orelse return env.getUndefined();
    return try env.createUint32(@intCast(index));
}

pub fn index2pubkeyGet(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const index = try cb.arg(0).getValueUint32();
    if (index >= index2pubkey.items.len) {
        return env.getUndefined();
    }

    // TODO expose bls classes, this is not what we want at all
    const pubkey = index2pubkey.items[@intCast(index)];
    var pubkey_arraybuffer_bytes: [*]u8 = undefined;
    const pubkey_arraybuffer = try env.createArrayBuffer(48, &pubkey_arraybuffer_bytes);
    const pubkey_array = try env.createTypedarray(.uint8, 48, pubkey_arraybuffer, 0);
    @memcpy(pubkey_arraybuffer_bytes, &pubkey.compress());
    return pubkey_array;
}

pub fn ensureCapacity(env: napi.Env, cb: napi.CallbackInfo(1)) !napi.Value {
    if (!initialized) {
        return error.PubkeyIndexNotInitialized;
    }

    const old_size = index2pubkey.capacity;
    const new_size = try cb.arg(0).getValueUint32();
    if (new_size <= old_size) {
        return env.getUndefined();
    }
    try pubkey2index.ensureTotalCapacity(new_size);
    try index2pubkey.ensureTotalCapacity(new_size);
    return env.getUndefined();
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const pubkeys_obj = try env.createObject();
    try pubkeys_obj.setNamedProperty("ensureCapacity", try env.createFunction(
        "ensureCapacity",
        1,
        ensureCapacity,
        null,
    ));
    try pubkeys_obj.setNamedProperty("load", try env.createFunction(
        "load",
        1,
        load,
        null,
    ));
    try pubkeys_obj.setNamedProperty("save", try env.createFunction(
        "save",
        1,
        save,
        null,
    ));

    const pubkey2index_obj = try env.createObject();
    const index2pubkey_obj = try env.createObject();

    try pubkey2index_obj.setNamedProperty("get", try env.createFunction(
        "get",
        1,
        pubkey2indexGet,
        null,
    ));

    try index2pubkey_obj.setNamedProperty("get", try env.createFunction(
        "get",
        1,
        index2pubkeyGet,
        null,
    ));

    try pubkeys_obj.setNamedProperty("pubkey2index", pubkey2index_obj);
    try pubkeys_obj.setNamedProperty("index2pubkey", index2pubkey_obj);

    try exports.setNamedProperty("pubkeys", pubkeys_obj);
}
