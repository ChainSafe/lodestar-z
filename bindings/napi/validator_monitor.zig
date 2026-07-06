//! Process-wide validator monitor shared by the NAPI bindings.
//!
//! This file is intentionally NOT exported as a JS module in `root.zig`:
//! it only holds native state. JS interacts with it through
//! `metrics.registerLocalValidator()` and the metrics scraped via
//! `metrics.scrapeMetrics()`.

const std = @import("std");
const builtin = @import("builtin");
const state_transition = @import("state_transition");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

/// Fed by `BeaconStateView.processSlots`/`stateTransition` on every epoch
/// transition. Only records metrics for validators registered via
/// `metrics.registerLocalValidator()`.
var monitor = state_transition.ValidatorMonitor.init(allocator);

/// Returns the process-wide validator monitor.
pub fn get() *state_transition.ValidatorMonitor {
    return &monitor;
}

/// Frees all monitor state. Meant to be called once on module cleanup.
pub fn deinit() void {
    monitor.deinit();
    monitor = state_transition.ValidatorMonitor.init(allocator);
}
