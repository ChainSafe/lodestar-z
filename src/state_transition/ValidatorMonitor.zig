//! Consumes the per-validator status data produced by the epoch transition
//! and records validator metrics for the validators registered with `registerLocalValidator`.

const std = @import("std");

const types = @import("consensus_types");
const metrics = @import("metrics.zig");
const attester_status = @import("utils/attester_status.zig");
const hasMarkers = attester_status.hasMarkers;

const Allocator = std.mem.Allocator;
const Epoch = types.primitive.Epoch.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;

pub const ValidatorMonitor = @This();

allocator: Allocator,
/// The validators that require additional monitoring.
validators: std.AutoArrayHashMapUnmanaged(ValidatorIndex, void),
/// Prevents registering statuses for the same epoch twice.
/// processEpoch() may be run more than once for the same epoch.
last_registered_status_epoch: ?Epoch,

pub fn init(allocator: Allocator) ValidatorMonitor {
    return .{
        .allocator = allocator,
        .validators = .empty,
        .last_registered_status_epoch = null,
    };
}

pub fn deinit(self: *ValidatorMonitor) void {
    self.validators.deinit(self.allocator);
    self.* = undefined;
}

/// Adds a validator to the list of monitored validators.
/// Registering an already-monitored validator is a no-op.
///
/// Note: the count of monitored validators (`validator_monitor_validators`) is
/// reported by the lodestar-ts validator monitor, which owns the registration
/// flow, so no gauge is set here.
pub fn registerLocalValidator(self: *ValidatorMonitor, index: ValidatorIndex) !void {
    try self.validators.put(self.allocator, index, {});
}

/// Registers the per-validator statuses produced by one epoch transition and
/// records metrics for all monitored validators.
///
/// Mirrors the state-derived part of `registerValidatorStatuses()` in lodestar-ts:
/// - `flags` are the packed attester flags of `EpochTransitionCache` (see `utils/attester_status.zig`).
/// - `balances` is optional; when present the total balance of all monitored
///   validators is reported.
///
/// Gossip-derived metrics (inclusion distance, attester hit/miss, correct head)
/// are recorded by the lodestar-ts validator monitor, which observes attestations
/// on the network; the state transition cannot see them post-altair.
pub fn registerValidatorStatuses(
    self: *ValidatorMonitor,
    current_epoch: Epoch,
    flags: []const u8,
    balances: ?[]const u64,
) void {
    // Prevent registering statuses for the same epoch twice.
    if (self.last_registered_status_epoch) |last|
        if (current_epoch <= last) return;

    self.last_registered_status_epoch = current_epoch;

    // There won't be any validator activity in epoch -1.
    if (current_epoch == 0) return;

    const vm = &metrics.validator_monitor;

    // Track total balance instead of per-validator balance to reduce metric cardinality.
    var total_balance: u64 = 0;

    for (self.validators.keys()) |index| {
        // The monitored validator may not be in the state yet.
        if (index >= flags.len) continue;

        const flag = flags[index];

        if (hasMarkers(flag, attester_status.FLAG_PREV_SOURCE_ATTESTER)) {
            vm.prev_epoch_on_chain_source_attester_hit.incr();
        } else {
            vm.prev_epoch_on_chain_source_attester_miss.incr();
        }
        if (hasMarkers(flag, attester_status.FLAG_PREV_HEAD_ATTESTER)) {
            vm.prev_epoch_on_chain_head_attester_hit.incr();
        } else {
            vm.prev_epoch_on_chain_head_attester_miss.incr();
        }
        if (hasMarkers(flag, attester_status.FLAG_PREV_TARGET_ATTESTER)) {
            vm.prev_epoch_on_chain_target_attester_hit.incr();
        } else {
            vm.prev_epoch_on_chain_target_attester_miss.incr();
        }

        if (balances) |b| {
            if (index < b.len) total_balance += b[index];
        }
    }

    if (balances != null) {
        vm.prev_epoch_on_chain_balance.set(total_balance);
    }
}

test "registerValidatorStatuses records metrics" {
    const allocator = std.testing.allocator;
    try metrics.init(allocator, std.testing.io, .{});
    defer metrics.deinit();

    var monitor = ValidatorMonitor.init(allocator);
    defer monitor.deinit();
    try monitor.registerLocalValidator(0);
    try monitor.registerLocalValidator(1);

    const flags = [_]u8{
        attester_status.FLAG_PREV_SOURCE_ATTESTER |
            attester_status.FLAG_PREV_TARGET_ATTESTER |
            attester_status.FLAG_PREV_HEAD_ATTESTER,
        0,
    };
    const balances = [_]u64{ 32_000_000_000, 31_000_000_000 };
    monitor.registerValidatorStatuses(1, &flags, &balances);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    var list = list: {
        errdefer aw.deinit();
        try metrics.write(&aw.writer);
        break :list aw.toArrayList();
    };
    defer list.deinit(allocator);

    const expectations = [_][]const u8{
        "validator_monitor_prev_epoch_on_chain_source_attester_hit_total 1",
        "validator_monitor_prev_epoch_on_chain_source_attester_miss_total 1",
        "validator_monitor_prev_epoch_on_chain_target_attester_hit_total 1",
        "validator_monitor_prev_epoch_on_chain_target_attester_miss_total 1",
        "validator_monitor_prev_epoch_on_chain_head_attester_hit_total 1",
        "validator_monitor_prev_epoch_on_chain_head_attester_miss_total 1",
        "validator_monitor_prev_epoch_on_chain_balance 63000000000",
    };
    for (expectations) |expected| {
        std.testing.expect(std.mem.indexOf(u8, list.items, expected) != null) catch |err| {
            std.debug.print("expected metric not found: {s}\n", .{expected});
            return err;
        };
    }
}

test "registerValidatorStatuses guards" {
    var monitor = ValidatorMonitor.init(std.testing.allocator);
    defer monitor.deinit();

    try monitor.registerLocalValidator(0);
    try monitor.registerLocalValidator(2);
    // registering twice is a no-op
    try monitor.registerLocalValidator(0);
    try std.testing.expectEqual(@as(usize, 2), monitor.validators.count());

    const flags = [_]u8{
        attester_status.FLAG_PREV_SOURCE_ATTESTER | attester_status.FLAG_PREV_TARGET_ATTESTER,
        0,
        attester_status.FLAG_PREV_HEAD_ATTESTER,
    };
    const balances = [_]u64{ 32_000_000_000, 31_000_000_000, 33_000_000_000 };

    // epoch 0 is registered but has no previous epoch activity
    monitor.registerValidatorStatuses(0, &flags, &balances);
    try std.testing.expectEqual(@as(?Epoch, 0), monitor.last_registered_status_epoch);

    monitor.registerValidatorStatuses(1, &flags, &balances);
    try std.testing.expectEqual(@as(?Epoch, 1), monitor.last_registered_status_epoch);

    // same epoch twice is a no-op
    monitor.registerValidatorStatuses(1, &flags, &balances);
    try std.testing.expectEqual(@as(?Epoch, 1), monitor.last_registered_status_epoch);
}
