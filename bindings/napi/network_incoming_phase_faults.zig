const std = @import("std");
const napi = @import("zapi:zapi").napi;
const faults = @import("network_faults.zig");
const incoming = @import("network_incoming.zig");
const Runtime = @import("network_runtime.zig").Runtime;
pub const Preparation = enum { refs, buffer, deferred };
pub const TerminalProof = struct { session: u64, handle: @import("network").reqresp.RequestHandle };
const Snapshot = struct {
    preparing: bool = false,
    heavyFreed: bool = false,
    currentRefs: usize = 0,
    nextRefs: usize = 0,
    responseBytes: usize = 0,
    deferred: bool = false,
    copiedFirstByte: u8 = 0,
    rollback: bool = false,
    rollbackNextRefs: usize = 0,
    rollbackReserved: usize = 0,
    bufferReleased: bool = false,
    deferredRetired: bool = false,
    pendingPublished: bool = false,
    terminalBefore: bool = false,
    terminalAccepted: bool = false,
    nativeFinishing: bool = false,
    nativeErrorWriting: bool = false,
    nativeTerminal: bool = false,
    chunks: u32 = 0,
    stepObserved: bool = false,
    stepFinishing: bool = false,
    stepWriting: bool = false,
    stepCloseAfterWrite: bool = false,
    stepErrorStatus: u8 = 0,
    stepNativeState: u8 = 0,
    stepTerminal: bool = false,
    stepChunks: u32 = 0,
};
var mutex: std.Io.Mutex = .init;
var snapshot: Snapshot = .{};

pub fn reset() void {
    if (comptime !faults.enabled) return;
    std.Io.Threaded.mutexLock(&mutex);
    defer std.Io.Threaded.mutexUnlock(&mutex);
    snapshot = .{};
}
pub fn register(env: napi.Env, exports: napi.Value) !void {
    if (comptime !faults.enabled) return;
    try exports.setNamedProperty("networkTestIncomingPhase", try env.createFunction("networkTestIncomingPhase", 0, get, null));
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
fn preparationScenario(scenario: faults.Scenario) bool {
    return scenario == .incoming_prepare_refs or scenario == .incoming_prepare_buffer or scenario == .incoming_prepare_deferred;
}
fn refCount(refs: *const incoming.ResultRefs) usize {
    var count: usize = 0;
    for (refs) |ref| count += @intFromBool(ref != null);
    return count;
}
fn waitTick() !void {
    var fd = std.c.pollfd{ .fd = -1, .events = 0, .revents = 0 };
    const rc = std.c.poll(@ptrCast(&fd), 1, 10);
    if (rc < 0 and std.c.errno(rc) != .INTR) return error.NetworkWakeFailed;
}
pub fn preparing(runtime: *Runtime, cell: *const incoming.Cell, phase: Preparation, buffer: []const u8, deferred: ?napi.Deferred) !void {
    if (comptime !faults.enabled) return;
    const selected: faults.Scenario = switch (phase) {
        .refs => .incoming_prepare_refs,
        .buffer => .incoming_prepare_buffer,
        .deferred => .incoming_prepare_deferred,
    };
    runtime.lock();
    const active = runtime.test_scenario == selected;
    if (active) std.debug.assert(cell.state == .response_preparing and cell.pending == null and cell.response.len == 0);
    runtime.unlock();
    if (!active) return;
    runtime.requestStop();
    for (0..500) |_| {
        runtime.lock();
        const closed = runtime.quiescent;
        if (closed) {
            std.debug.assert(runtime.heavy == null and !cell.native and cell.state == .response_preparing);
            std.Io.Threaded.mutexLock(&mutex);
            snapshot = .{ .preparing = true, .heavyFreed = true, .currentRefs = refCount(&cell.results), .nextRefs = refCount(&cell.next_results), .responseBytes = buffer.len, .deferred = deferred != null, .copiedFirstByte = if (phase == .deferred and buffer.len > 0) buffer[0] else 0 };
            std.Io.Threaded.mutexUnlock(&mutex);
        }
        runtime.unlock();
        if (closed) {
            try faults.check(.operation_copy);
            return;
        }
        try waitTick();
    }
    return error.NetworkTestBarrierTimeout;
}
pub fn released(runtime: *Runtime, resource: enum { buffer, deferred }) void {
    if (comptime !faults.enabled) return;
    runtime.lock();
    const active = preparationScenario(runtime.test_scenario);
    runtime.unlock();
    if (!active) return;
    std.Io.Threaded.mutexLock(&mutex);
    defer std.Io.Threaded.mutexUnlock(&mutex);
    switch (resource) {
        .buffer => snapshot.bufferReleased = true,
        .deferred => snapshot.deferredRetired = true,
    }
}
pub fn rollbackLocked(runtime: *Runtime, cell: *const incoming.Cell) void {
    if (comptime !faults.enabled) return;
    if (!preparationScenario(runtime.test_scenario)) return;
    std.Io.Threaded.mutexLock(&mutex);
    defer std.Io.Threaded.mutexUnlock(&mutex);
    snapshot.rollback = true;
    snapshot.rollbackNextRefs = refCount(&cell.next_results);
    snapshot.rollbackReserved = cell.reservation;
    snapshot.pendingPublished = cell.pending != null;
}
pub fn terminalBarrier(runtime: *Runtime, accepted: bool) !?TerminalProof {
    if (comptime !faults.enabled) return null;
    runtime.lock();
    const selected: faults.Scenario = if (accepted) .incoming_terminal_after else .incoming_terminal_before;
    if (runtime.test_scenario != selected) {
        runtime.unlock();
        return null;
    }
    const cell = terminalCell(runtime, accepted) orelse {
        runtime.unlock();
        return null;
    };
    const native = runtime.heavy.?.core.core.service.reqresp.inner.inboundSlot(cell.handle).?;
    std.debug.assert(native.terminal == null and native.chunks == cell.chunks);
    if (accepted) std.debug.assert(native.state == .finishing or (native.state == .writing_chunk and native.close_after_write)) else std.debug.assert(native.state == .serving);
    std.Io.Threaded.mutexLock(&mutex);
    snapshot = .{ .terminalBefore = !accepted, .terminalAccepted = accepted, .nativeFinishing = native.state == .finishing, .nativeErrorWriting = native.state == .writing_chunk and native.close_after_write, .nativeTerminal = native.terminal != null, .chunks = native.chunks };
    std.Io.Threaded.mutexUnlock(&mutex);
    const proof: TerminalProof = .{ .session = runtime.diag.session, .handle = cell.handle };
    runtime.unlock();
    for (0..500) |_| {
        runtime.lock();
        const observe = accepted and cell.action == .cancel and !runtime.stop;
        const released_now = cell.action == .cancel or runtime.stop;
        if (released_now) runtime.test_scenario = .none;
        runtime.unlock();
        if (released_now) return if (observe) proof else null;
        try waitTick();
    }
    return error.NetworkTestBarrierTimeout;
}
fn terminalCell(runtime: *Runtime, accepted: bool) ?*incoming.Cell {
    for (runtime.incoming.?.cells) |*cell| {
        if (!cell.native) continue;
        if (if (accepted) cell.action == .submitted else cell.action == .finish or cell.action == .fail) return cell;
    }
    return null;
}

pub fn afterStep(runtime: *Runtime, proof: *const TerminalProof, events: []const @import("network").reqresp.Event) void {
    if (comptime !faults.enabled) return;
    runtime.lock();
    defer runtime.unlock();
    std.debug.assert(runtime.diag.session == proof.session);
    for (runtime.incoming.?.cells) |*cell| {
        if (!cell.native or !std.meta.eql(cell.handle, proof.handle)) continue;
        std.debug.assert(cell.action == .cancel);
        const native = runtime.heavy.?.core.core.service.reqresp.inner.inboundSlot(cell.handle);
        std.Io.Threaded.mutexLock(&mutex);
        defer std.Io.Threaded.mutexUnlock(&mutex);
        std.debug.assert(!snapshot.stepObserved);
        snapshot.stepObserved = true;
        if (native) |slot| {
            std.debug.assert(slot.terminal == null);
            snapshot.stepFinishing = slot.state == .finishing;
            snapshot.stepWriting = slot.state == .writing_chunk;
            snapshot.stepCloseAfterWrite = slot.close_after_write;
            snapshot.stepErrorStatus = slot.pending_result;
            snapshot.stepNativeState = @intFromEnum(slot.state);
            snapshot.stepChunks = slot.chunks;
        } else {
            std.debug.assert(events.len <= 32);
            for (events) |event| if (event == .served and std.meta.eql(event.served.request, cell.handle)) {
                std.debug.assert(!snapshot.stepTerminal);
                snapshot.stepTerminal = true;
                snapshot.stepChunks = event.served.chunks;
            };
            std.debug.assert(snapshot.stepTerminal);
        }
        return;
    }
    unreachable;
}
