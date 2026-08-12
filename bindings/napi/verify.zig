//! Index-based BLS verification bindings.
//!
//! Thin unmarshaling layer over `state_transition.indexed_verify`: signature
//! sets arrive as discriminated descriptors referencing validators by index,
//! keys are resolved from the process-wide pubkey cache, and verification
//! runs on the shared BLS thread pool. Exported on the blst (verification)
//! JS surface; the pubkeyCache JS object stays a dumb cache.
//!
//! Cache lifecycle: production populates the cache (syncPubkeys/load) before
//! verification traffic starts; reset() is test-only under external
//! exclusion.
//!
//! Both functions block the calling thread while the pool verifies — the
//! intended callers are Lodestar's BLS worker threads (the Node main event
//! loop stays free).

const std = @import("std");
const zapi = @import("zapi:zapi");
const js = zapi.js;
const blst_bindings = @import("./blst.zig");
const pubkeys = @import("./pubkeys.zig");
const state_transition = @import("state_transition");
const indexed_verify = state_transition.indexed_verify;

const allocator = std.heap.page_allocator;

// Private copies of blst.zig's file-private helpers: zapi's exportModule
// reflects every `pub fn` of an exported namespace into JS, so they cannot
// be shared as pub without appearing on the JS surface.
fn unwrapClass(comptime T: type, value: js.Value) !*T {
    const raw = value.toValue();
    return js.convertArg(*T, raw.value, raw.env);
}

fn uint8SliceFromValue(value: js.Value) ![]u8 {
    const raw = value.toValue();
    if (!(try raw.isTypedarray())) return error.TypeMismatch;
    const info = try raw.getTypedarrayInfo();
    if (info.array_type != .uint8) return error.TypeMismatch;
    return info.data;
}

/// JS: blst.verifyIndexedSignatureSets(sets) -> boolean
/// sets: [{type: "single"|"indexed"|"aggregate", ...}] — see blst.d.ts.
pub fn verifyIndexedSignatureSets(sets: js.Array) !js.Boolean {
    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
    const pool = blst_bindings.state.thread_pool orelse return error.ThreadPoolNotInitialized;

    const n = try sets.length();
    if (n == 0) return js.Boolean.from(false);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = try arena.alloc(indexed_verify.VerifySet, n);
    for (0..n) |i| {
        parsed[i] = try parseSet(arena, (try sets.get(@intCast(i))).toValue());
    }

    const result = try indexed_verify.verifyIndexedSets(
        arena,
        js.io(),
        &pubkeys.state.cache,
        pool,
        parsed,
    );
    return js.Boolean.from(result);
}

/// JS: blst.verifySameMessageSetsByIndex(message, sets) -> boolean
/// sets: [{index: number, signature: Uint8Array}]
pub fn verifySameMessageSetsByIndex(message: js.Uint8Array, sets: js.Array) !js.Boolean {
    if (!pubkeys.state.initialized) return error.PubkeyIndexNotInitialized;
    const pool = blst_bindings.state.thread_pool orelse return error.ThreadPoolNotInitialized;

    const message_bytes = try message.toSlice();

    const n = try sets.length();
    if (n == 0) return js.Boolean.from(false);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = try arena.alloc(indexed_verify.SameMessageSet, n);
    for (0..n) |i| {
        const set = (try sets.get(@intCast(i))).toValue();
        parsed[i] = .{
            .index = try (js.Number{ .val = try set.getNamedProperty("index") }).toU32(),
            .signature = try uint8SliceFromValue(.{ .val = try set.getNamedProperty("signature") }),
        };
    }

    const result = try indexed_verify.verifySameMessageSets(
        arena,
        js.io(),
        &pubkeys.state.cache,
        pool,
        message_bytes,
        parsed,
    );
    return js.Boolean.from(result);
}

fn parseSet(arena: std.mem.Allocator, set: zapi.napi.Value) !indexed_verify.VerifySet {
    const type_value = js.String{ .val = try set.getNamedProperty("type") };
    const type_name = try type_value.toOwnedSlice(arena);

    const message = try uint8SliceFromValue(.{ .val = try set.getNamedProperty("message") });
    const signature = try uint8SliceFromValue(.{ .val = try set.getNamedProperty("signature") });

    if (std.mem.eql(u8, type_name, "indexed")) {
        return .{ .indexed = .{
            .index = try (js.Number{ .val = try set.getNamedProperty("index") }).toU32(),
            .message = message,
            .signature = signature,
        } };
    }
    if (std.mem.eql(u8, type_name, "aggregate")) {
        return .{ .aggregate = .{
            .indices = try uint32SliceFromValue(arena, .{ .val = try set.getNamedProperty("indices") }),
            .message = message,
            .signature = signature,
        } };
    }
    if (std.mem.eql(u8, type_name, "single")) {
        const pk_value: js.Value = .{ .val = try set.getNamedProperty("publicKey") };
        // Accept either raw compressed bytes or an existing PublicKey wrapper.
        const pk_bytes = uint8SliceFromValue(pk_value) catch blk: {
            const wrapped = try unwrapClass(blst_bindings.PublicKey, pk_value);
            const compressed = try arena.alloc(u8, 48);
            compressed[0..48].* = wrapped.raw.compress();
            break :blk compressed;
        };
        return .{ .single = .{
            .public_key = pk_bytes,
            .message = message,
            .signature = signature,
        } };
    }
    return error.UnknownSignatureSetType;
}

/// Copy a JS Uint32Array's elements out. Copied (not viewed) so alignment
/// and lifetime are owned by the arena for the duration of the call.
fn uint32SliceFromValue(arena: std.mem.Allocator, value: js.Value) ![]u32 {
    const raw = value.toValue();
    if (!(try raw.isTypedarray())) return error.TypeMismatch;
    const info = try raw.getTypedarrayInfo();
    if (info.array_type != .uint32) return error.TypeMismatch;
    const elements = std.mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(info.data)));
    const copied = try arena.alloc(u32, elements.len);
    @memcpy(copied, elements);
    return copied;
}
