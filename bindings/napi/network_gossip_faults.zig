const std = @import("std");
const faults = @import("network_faults.zig");
const g = @import("network_gossip.zig");
const napi = @import("zapi:zapi").napi;
var released = std.atomic.Value(bool).init(false);
const Runtime = @import("network_runtime.zig").Runtime;

pub fn copy(runtime: *Runtime, token: g.Token, ordinal: usize) !void {
    if (comptime !faults.enabled) return;
    if (runtime.test_scenario == .gossip_second_copy_fail and ordinal == 1) return error.InjectedNetworkFailure;
    if (ordinal != 0) return;
    if (runtime.test_scenario == .gossip_copy_close or runtime.test_scenario == .gossip_copy_close_fail) {
        runtime.forceStop(false);
        runtime.lock();
        std.debug.assert(runtime.heavy == null and runtime.quiescent);
        const cell = runtime.gossip.?.get(token).?;
        std.debug.assert(cell.state == .copying and cell.retired and cell.input.len > 0);
        std.debug.assert(cell.reservation == 2 * cell.input.len);
        faults.reached.store(.gossip_copy_closed, .release);
        runtime.unlock();
        if (runtime.test_scenario == .gossip_copy_close_fail) return error.InjectedNetworkFailure;
    } else if (runtime.test_scenario == .gossip_copy_expire) {
        runtime.lock();
        runtime.test_gossip_expiry = token;
        runtime.signalLocked();
        runtime.unlock();
        for (0..1000) |_| {
            if (faults.reached.load(.acquire) == .gossip_copy_expired) return;
            var fd: std.c.pollfd = .{ .fd = -1, .events = 0, .revents = 0 };
            const rc = std.c.poll(@ptrCast(&fd), 1, 5);
            if (rc < 0 and std.c.errno(rc) != .INTR) return error.NetworkWakeFailed;
        }
        return error.NetworkTestBarrierTimeout;
    }
}

pub fn afterStep(runtime: *Runtime) void {
    if (comptime !faults.enabled) return;
    runtime.lock();
    defer runtime.unlock();
    if (runtime.test_scenario == .gossip_owner_hold and !runtime.test_gossip_held) {
        var delivered = false;
        for (runtime.gossip.?.cells) |cell| if (cell.state == .delivered) {
            delivered = true;
            break;
        };
        if (delivered) {
            runtime.test_gossip_held = true;
            released.store(false, .release);
            faults.reached.store(.gossip_owner_held, .release);
            runtime.unlock();
            var wait_failed = false;
            for (0..1000) |_| {
                if (released.load(.acquire)) break;
                var fd: std.c.pollfd = .{ .fd = -1, .events = 0, .revents = 0 };
                const rc = std.c.poll(@ptrCast(&fd), 1, 5);
                if (rc < 0 and std.c.errno(rc) != .INTR) {
                    wait_failed = true;
                    break;
                }
            }
            runtime.lock();
            if (wait_failed or !released.load(.acquire)) {
                runtime.stop = true;
                runtime.reason = .failed;
                runtime.startup_error = if (wait_failed) error.NetworkWakeFailed else error.NetworkTestBarrierTimeout;
            }
        }
    }
    const token = runtime.test_gossip_expiry orelse return;
    const cell = runtime.gossip.?.get(token).?;
    const entry = &runtime.heavy.?.core.core.service.gossipsub.inner.validation.entries[cell.handle.index];
    if (entry.generation != cell.handle.generation or entry.state != .expired or !cell.retired) return;
    std.debug.assert(cell.state == .copying and cell.input.len > 0 and cell.reservation == 2 * cell.input.len);
    runtime.test_gossip_expiry = null;
    faults.reached.store(.gossip_copy_expired, .release);
}

pub fn register(env: napi.Env, exports: napi.Value) !void {
    if (comptime !faults.enabled) return;
    try exports.setNamedProperty("networkTestGossipRelease", try env.createFunction("networkTestGossipRelease", 0, release, null));
}
fn release(env: napi.Env, _: napi.CallbackInfo(0)) !napi.Value {
    released.store(true, .release);
    return env.getUndefined();
}
