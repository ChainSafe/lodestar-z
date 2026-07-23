const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const napi = zapi.napi;
const blst_bindings = @import("./blst.zig");
const state_transition = @import("state_transition");
const PubkeyCache = state_transition.PubkeyCache;
const pkix = state_transition.pkix;
const napi_io = @import("./io.zig");

/// Uses the page allocator for the process-wide cache's internal allocations.
const allocator = std.heap.page_allocator;

const default_initial_capacity: u32 = 0;
const max_stack_aggregate_pubkeys = 512;

const State = struct {
    cache: PubkeyCache = undefined,
    initialized: bool = false,
    control_env: napi.c.napi_env = null,

    pub fn init(self: *State, env: napi.Env) !void {
        if (self.initialized) return;

        self.cache = try PubkeyCache.initCapacity(allocator, napi_io.get(), default_initial_capacity);
        self.initialized = true;
        self.control_env = env.env;
    }

    /// Last-environment cleanup runs after JS calls stop. Remaining view
    /// finalizers do not dereference their retained pubkey-cache pointer.
    pub fn deinit(self: *State) void {
        if (!self.initialized) return;
        self.cache.deinit();
        self.initialized = false;
        self.control_env = null;
    }

    fn requireControlEnvironment(self: *const State, env: napi.Env) !void {
        if (self.control_env == null or self.control_env != env.env) {
            return error.PubkeyCacheControlEnvironmentOnly;
        }
    }
};

pub var state: State = .{};

/// JS: pubkeys.save(filePath)
pub fn save(file_path: js.String) !void {
    try state.requireControlEnvironment(js.env());

    const path = try file_path.toOwnedSlice(allocator);
    defer allocator.free(path);
    const io = napi_io.get();

    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    // `createFileAtomic` creates a sibling temporary file so replacement cannot
    // cross filesystems. `deinit` removes the temporary file on every failure.
    var atomic_file = try std.Io.Dir.createFileAtomic(.cwd(), io, path, .{ .replace = true });
    defer atomic_file.deinit(io);

    var write_buf: [4096]u8 = undefined;
    var file_writer = atomic_file.file.writer(io, &write_buf);
    try pkix.save(&state.cache, io, &file_writer.interface);

    try file_writer.end();
    try atomic_file.file.sync(io);
    try atomic_file.replace(io);
}

/// JS: pubkeys.load(filePath, maxCapacity)
pub fn load(file_path: js.String, max_capacity: js.Number) !void {
    try state.requireControlEnvironment(js.env());

    const path = try file_path.toOwnedSlice(allocator);
    defer allocator.free(path);
    const capacity_limit = try max_capacity.toU32();
    const io = napi_io.get();

    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);

    const file_size = try file.length(io);
    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &read_buf);

    var loaded_cache = try pkix.load(
        allocator,
        io,
        &file_reader.interface,
        file_size,
        capacity_limit,
    );
    defer loaded_cache.deinit();

    try pkix.install(&state.cache, io, &loaded_cache);
}

/// JS: pubkeys.reset()
pub fn reset() !void {
    try state.requireControlEnvironment(js.env());

    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    try state.cache.clear(napi_io.get());
}

/// JS: pubkeys.getIndex(pubkeyBytes) → number | null
pub fn getIndex(pubkey: js.Uint8Array) !js.Value {
    const pubkey_slice = try pubkey.toSlice();
    if (pubkey_slice.len != 48) return error.InvalidPubkeyLength;
    const pubkey_bytes = pubkey_slice[0..48].*;

    const io = napi_io.get();
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    const index = state.cache.get(io, pubkey_bytes);

    const e = js.env();
    if (index) |validator_index| {
        return .{ .val = try e.createUint32(@intCast(validator_index)) };
    }
    return .{ .val = try e.getNull() };
}

/// JS: pubkeys.get(index) → PublicKey | undefined
pub fn get(index: js.Number) !?blst_bindings.PublicKey {
    const idx = try index.toU32();
    const io = napi_io.get();
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    const public_key = state.cache.getPubkey(io, idx) orelse return null;
    return .{ .raw = public_key };
}

/// Aggregate multiple `PublicKey`s by the given
/// validator `indices` into one.
///
/// Validation is not required here since it is done upon
/// processing validator deposits.
///
/// JS: pubkeys.aggregate(indices) → PublicKey
pub fn aggregate(indices: js.Array) !blst_bindings.PublicKey {
    const len = try indices.length();
    if (len == 0) return error.EmptyPublicKeyArray;

    var indices_stack: [max_stack_aggregate_pubkeys]u64 = undefined;
    const exact_indices = if (len <= indices_stack.len)
        indices_stack[0..len]
    else blk: {
        const buf = try allocator.alloc(u64, len);
        break :blk buf;
    };
    defer if (len > indices_stack.len) allocator.free(exact_indices);

    for (0..len) |i| {
        exact_indices[i] = try (try indices.getNumber(@intCast(i))).toU32();
    }

    const io = napi_io.get();
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    const aggregate_pubkey = if (exact_indices.len == 1)
        state.cache.getPubkey(io, exact_indices[0]) orelse return error.PubkeyIndexNotFound
    else
        state.cache.aggregate(io, exact_indices) catch |err| switch (err) {
            error.InvalidIndex => return error.PubkeyIndexNotFound,
            else => return error.AggregationFailed,
        };

    return .{ .raw = aggregate_pubkey };
}

/// JS: pubkeys.append(index, pubkeyBytes)
pub fn append(index: js.Number, pubkey: js.Uint8Array) !void {
    const idx = try index.toU32();
    const io = napi_io.get();
    if (!state.initialized) return error.PubkeyIndexNotInitialized;

    const pubkey_slice = try pubkey.toSlice();
    if (pubkey_slice.len != 48) return error.InvalidPubkeyLength;
    const pubkey_bytes = pubkey_slice[0..48].*;

    try state.cache.append(io, pubkey_bytes, idx);
}

/// JS: pubkeys.size() → number
/// Note: zapi DSL does not yet support namespace-level getters, so this is a function.
pub fn size() !js.Number {
    const io = napi_io.get();
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    return js.Number.from(state.cache.count(io));
}

/// JS: pubkeys.ensureCapacity(newSize)
pub fn ensureCapacity(new_size: js.Number) !void {
    const requested = try new_size.toU32();
    const io = napi_io.get();
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    try state.cache.ensureTotalCapacity(io, requested);
}

/// JS: pubkeys.capacity() → number
/// Note: zapi DSL does not yet support namespace-level getters, so this is a function.
pub fn capacity() !js.Number {
    const io = napi_io.get();
    if (!state.initialized) return error.PubkeyIndexNotInitialized;
    const current_capacity: u32 = @intCast(state.cache.capacity(io));
    return js.Number.from(current_capacity);
}
