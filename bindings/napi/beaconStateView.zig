const std = @import("std");
const napi = @import("zapi:napi");
const c = @import("config");
const BeaconState = @import("state_transition").BeaconState;
const CachedBeaconState = @import("state_transition").CachedBeaconState;
const pool = @import("./pool.zig");
const config = @import("./config.zig");
const pubkey = @import("./pubkey2index.zig");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = gpa.allocator();

pub fn BeaconStateView_finalize(_: napi.Env, cached_state: *CachedBeaconState, _: ?*anyopaque) void {
    cached_state.deinit();
    allocator.destroy(cached_state);
}

pub fn BeaconStateView_ctor(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try allocator.create(CachedBeaconState);
    errdefer allocator.destroy(cached_state);

    _ = try env.wrap(
        cb.this(),
        CachedBeaconState,
        cached_state,
        BeaconStateView_finalize,
        null,
    );

    return cb.this();
}

pub fn BeaconStateView_createFromBytes(env: napi.Env, cb: napi.CallbackInfo(2)) !napi.Value {
    const ctor = cb.this();

    var fork_name_buf: [16]u8 = undefined;
    const fork_name = try cb.arg(0).getValueStringUtf8(&fork_name_buf);
    const fork = c.ForkSeq.fromName(fork_name);

    const bytes_info = try cb.arg(1).getTypedarrayInfo();
    const state = try allocator.create(BeaconState);
    errdefer allocator.destroy(state);

    state.* = try BeaconState.deserialize(allocator, &pool.pool, fork, bytes_info.data);
    errdefer state.deinit();

    const cached_state_value = try env.newInstance(ctor, .{});

    const cached_state = try env.unwrap(CachedBeaconState, cached_state_value);

    try cached_state.init(
        allocator,
        state,
        .{
            .config = &config.config,
            .index_to_pubkey = &pubkey.index2pubkey,
            .pubkey_to_index = &pubkey.pubkey2index,
        },
        null,
    );

    return cached_state_value;
}

pub fn BeaconStateView_slot(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const slot = try cached_state.state.slot();
    return try env.createInt64(@intCast(slot));
}

pub fn BeaconStateView_root(env: napi.Env, cb: napi.CallbackInfo(0)) !napi.Value {
    const cached_state = try env.unwrap(CachedBeaconState, cb.this());
    const root = try cached_state.state.hashTreeRoot();
    var arraybuffer_bytes: [*]u8 = undefined;
    const arraybuffer = try env.createArrayBuffer(32, &arraybuffer_bytes);
    const typedarray = try env.createTypedarray(.uint8, 32, arraybuffer, 0);
    @memcpy(arraybuffer_bytes[0..32], root);
    return typedarray;
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    const beacon_state_view_ctor = try env.defineClass(
        "BeaconStateView",
        0,
        BeaconStateView_ctor,
        null,
        &[_]napi.c.napi_property_descriptor{
            .{ .utf8name = "slot", .getter = napi.wrapCallback(0, BeaconStateView_slot) },
            .{ .utf8name = "root", .getter = napi.wrapCallback(0, BeaconStateView_root) },
        },
    );
    try beacon_state_view_ctor.defineProperties(&[_]napi.c.napi_property_descriptor{.{
        .utf8name = "createFromBytes",
        .method = napi.wrapCallback(2, BeaconStateView_createFromBytes),
    }});
    try exports.setNamedProperty("BeaconStateView", beacon_state_view_ctor);
}
