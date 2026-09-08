const std = @import("std");
const napi = @import("zapi:zapi").napi;
const faults = @import("network_faults.zig");
const Runtime = @import("network_runtime.zig").Runtime;
const incoming = @import("network_incoming.zig");
const Snapshot = struct {
    nativeOwned: bool = false,
    copying: bool = false,
    quiescent: bool = false,
    acknowledged: bool = false,
    nativeBorrowed: bool = false,
    writing: bool = false,
    withheld: bool = false,
    requestBytes: usize = 0,
    responseBytes: usize = 0,
    destinationBytes: usize = 0,
    reservedBytes: usize = 0,
    nativeInbound: u16 = 0,
};
var mutex: std.Io.Mutex = .init;
var snapshot: Snapshot = .{};
var released = std.atomic.Value(bool).init(false);

fn publish(value: *const Snapshot) void {
    std.Io.Threaded.mutexLock(&mutex);
    snapshot = value.*;
    std.Io.Threaded.mutexUnlock(&mutex);
}
fn capture(runtime: *const Runtime, cell: *const incoming.Cell) Snapshot {
    return .{ .nativeOwned = cell.native, .copying = cell.copying, .quiescent = runtime.quiescent, .acknowledged = cell.ack != null and cell.ack.? == .sent, .requestBytes = cell.input.len, .responseBytes = cell.response.len, .reservedBytes = cell.reservation, .nativeInbound = if (runtime.heavy) |heavy| heavy.core.core.service.reqresp.inner.active().inbound else 0 };
}
pub fn register(env: napi.Env, exports: napi.Value) !void {
    if (comptime !faults.enabled) return;
    try exports.setNamedProperty("networkTestIncoming", try env.createFunction("networkTestIncoming", 0, get, null));
    try exports.setNamedProperty("networkTestIncomingRelease", try env.createFunction("networkTestIncomingRelease", 0, release, null));
}
fn get(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    std.Io.Threaded.mutexLock(&mutex);
    const value = snapshot;
    std.Io.Threaded.mutexUnlock(&mutex);
    const object = try env.createObject();
    inline for (@typeInfo(Snapshot).@"struct".fields) |field| {
        try object.setNamedProperty(field.name ++ "\x00", if (field.type == bool) try env.getBoolean(@field(value, field.name)) else try env.createDouble(@floatFromInt(@field(value, field.name))));
    }
    return object;
}
fn release(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    released.store(true, .release);
    return env.getUndefined();
}
pub fn turnLocked(runtime: *Runtime, now: @import("network").Now) void {
    if (comptime !faults.enabled) return;
    if (runtime.test_scenario == .incoming_observe) {
        for (runtime.incoming.?.cells) |*cell| {
            if (cell.state != .response_native) continue;
            const native = &runtime.heavy.?.core.core.service.reqresp.inner.inbound[cell.handle.index];
            std.debug.assert(std.meta.eql(native.handle(cell.handle.index), cell.handle));
            var value = capture(runtime, cell);
            value.nativeBorrowed = native.pending_ssz.ptr == cell.response.ptr and native.pending_ssz.len == cell.response.len;
            value.writing = native.state == .writing_chunk;
            value.withheld = native.state == .withheld;
            publish(&value);
        }
    }
    if (runtime.test_scenario != .incoming_hold) return;
    if (runtime.test_incoming_deadline == 0) {
        runtime.test_incoming_deadline = now.mono_ms + 5000;
        released.store(false, .release);
    }
    if (released.load(.acquire) or now.mono_ms >= runtime.test_incoming_deadline) {
        runtime.test_scenario = .none;
        runtime.pingLocked();
    } else {
        const value: Snapshot = .{ .nativeInbound = runtime.heavy.?.core.core.service.reqresp.inner.active().inbound };
        publish(&value);
    }
}
pub fn holdSettlement(runtime: *Runtime) bool {
    if (comptime !faults.enabled) return false;
    runtime.lock();
    defer runtime.unlock();
    return !runtime.quiescent and (runtime.test_scenario == .incoming_ack_close or (runtime.test_scenario == .incoming_hold and !runtime.stop));
}
pub fn ackLocked(runtime: *Runtime, cell: *const incoming.Cell) void {
    if (comptime !faults.enabled) return;
    if (runtime.test_scenario != .incoming_ack_close) return;
    std.debug.assert(cell.ack.? == .sent and cell.state == .response_native);
    publish(&capture(runtime, cell));
    runtime.stop = true;
    runtime.graceful = false;
    faults.reached.store(.incoming_ack_close, .release);
}
pub fn responseLocked(runtime: *Runtime, cell: *const incoming.Cell) void {
    if (comptime !faults.enabled) return;
    if (runtime.test_scenario != .incoming_response_close) return;
    std.debug.assert(cell.native and cell.state == .response_native and cell.ack == null);
    publish(&capture(runtime, cell));
    runtime.stop = true;
    runtime.graceful = false;
    faults.reached.store(.incoming_response_close, .release);
}
pub fn copy(runtime: *Runtime, cell: *const incoming.Cell, destination: []u8) !void {
    if (comptime !faults.enabled) return;
    runtime.lock();
    if (runtime.test_scenario != .incoming_copy_close) {
        runtime.unlock();
        return;
    }
    runtime.test_scenario = .none;
    std.debug.assert(cell.copying and destination.len == cell.input.len);
    runtime.unlock();
    runtime.requestStop();
    for (0..500) |_| {
        runtime.lock();
        const closed = runtime.quiescent;
        if (closed) {
            std.debug.assert(runtime.heavy == null and !cell.native and cell.copying);
            var value = capture(runtime, cell);
            value.destinationBytes = destination.len;
            publish(&value);
            faults.reached.store(.incoming_copy_closed, .release);
        }
        runtime.unlock();
        if (closed) return;
        var fd = std.c.pollfd{ .fd = -1, .events = 0, .revents = 0 };
        const rc = std.c.poll(@ptrCast(&fd), 1, 10);
        if (rc < 0 and std.c.errno(rc) != .INTR) return error.NetworkWakeFailed;
    }
    return error.NetworkTestBarrierTimeout;
}
