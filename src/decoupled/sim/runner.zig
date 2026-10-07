//! Drives a run: at every public time, deliveries that arrived inside the
//! previous interval, then every honest node's tick, then deliveries at the
//! time itself, then the scenario's hook, then the invariants.
//!
//! Honest emissions reach every other honest node before the next public
//! time (`PartialSynchrony` with `Δ` = one tick and `t_GST = 0`). The
//! scenario sees every emission and may queue its own deliveries.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const BoundedArray = @import("bounded_array").BoundedArray;
const limits = @import("../limits.zig");
const types = @import("../types.zig");
const Schedule = @import("../schedule.zig").Schedule;
const store_mod = @import("../store.zig");
const Store = store_mod.Store;
const invariants = @import("../invariants.zig");
const event = @import("event.zig");
const Node = @import("node.zig").Node;
const Scheduler = @import("scheduler.zig").Scheduler;

pub fn Runner(comptime Scenario: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        schedule: *const Schedule,
        scheduler: *Scheduler,
        nodes: [limits.max_nodes]Node,
        node_count: u32,
        node_of_validator: [limits.max_validators]?u32,
        proposals: BoundedArray(invariants.Proposal, limits.max_slots),
        scenario: *Scenario,
        now: types.Time,

        /// One node per honest validator, in validator order.
        pub fn init(
            allocator: Allocator,
            schedule: *const Schedule,
            rule: store_mod.ForkChoiceRule,
            scenario: *Scenario,
        ) !*Self {
            assert(schedule.honestCount() <= limits.max_nodes);
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            self.allocator = allocator;
            self.schedule = schedule;
            self.scenario = scenario;
            self.now = 0;
            self.node_count = 0;
            self.node_of_validator = [_]?u32{null} ** limits.max_validators;
            self.proposals = .{};

            self.scheduler = try allocator.create(Scheduler);
            errdefer allocator.destroy(self.scheduler);
            self.scheduler.init();

            errdefer for (self.nodes[0..self.node_count]) |*node| allocator.destroy(node.store);
            for (0..schedule.validator_count) |v| {
                const val_index: types.ValidatorIndex = @intCast(v);
                if (!schedule.isHonest(val_index)) continue;
                const store = try allocator.create(Store);
                store.init(schedule, rule);
                self.nodes[self.node_count] = .{ .store = store, .val_index = val_index };
                self.node_of_validator[v] = self.node_count;
                self.node_count += 1;
            }
            assert(self.node_count == schedule.honestCount());
            return self;
        }

        pub fn deinit(self: *Self) void {
            for (self.nodes[0..self.node_count]) |*node| self.allocator.destroy(node.store);
            self.allocator.destroy(self.scheduler);
            self.allocator.destroy(self);
        }

        pub fn nodeFor(self: *Self, v: types.ValidatorIndex) ?*Node {
            assert(v < self.schedule.validator_count);
            const index = self.node_of_validator[v] orelse return null;
            return &self.nodes[index];
        }

        fn broadcast(self: *Self, from: u32, payload: *const event.Payload) void {
            assert(from < self.node_count);
            const arrival = self.now + 1;
            if (arrival >= limits.max_time) return;
            for (0..self.node_count) |n| {
                if (n == from) continue;
                self.scheduler.push(arrival, .before_tick, @intCast(n), payload);
            }
            self.scenario.onEmission(self, payload, self.now);
        }

        fn deliverPhase(self: *Self, phase: event.Phase) void {
            var delivered: u32 = 0;
            while (self.scheduler.popAt(self.now, phase)) |delivery| : (delivered += 1) {
                assert(delivered < limits.max_pending);
                assert(delivery.node < self.node_count);
                self.nodes[delivery.node].deliver(&delivery.payload);
            }
        }

        fn checkInvariants(self: *Self) invariants.Violation!void {
            for (self.nodes[0..self.node_count]) |*node| try invariants.checkNested(node.store);
            for (self.proposals.constSlice()) |*proposal| {
                if (types.slotStart(proposal.slot) + 6 != self.now) continue;
                try invariants.checkConfirmedAvailability(self, proposal);
            }
        }

        /// Runs the public time `now`, then advances it.
        pub fn step(self: *Self) invariants.Violation!void {
            assert(self.now < limits.max_time);
            self.deliverPhase(.before_tick);
            for (0..self.node_count) |n| {
                const node = &self.nodes[n];
                node.tick(self.now);
                for (node.outbox.constSlice()) |*payload| {
                    if (payload.* == .block) {
                        self.proposals.push(.{ .root = payload.block.root, .slot = payload.block.slot });
                    }
                    self.broadcast(@intCast(n), payload);
                }
            }
            self.deliverPhase(.after_tick);
            self.scenario.onTime(self, self.now);
            try self.checkInvariants();
            self.now += 1;
        }

        pub fn runUntil(self: *Self, last: types.Time) invariants.Violation!void {
            assert(last < limits.max_time);
            assert(self.now <= last);
            while (self.now <= last) try self.step();
            assert(self.now == last + 1);
        }
    };
}

const NullScenario = struct {
    emissions: u32 = 0,
    fn onEmission(self: *NullScenario, runner: anytype, payload: *const event.Payload, t: types.Time) void {
        _ = runner;
        _ = payload;
        _ = t;
        self.emissions += 1;
    }
    fn onTime(self: *NullScenario, runner: anytype, t: types.Time) void {
        _ = self;
        _ = runner;
        _ = t;
    }
};

test "four honest validators confirm every proposal" {
    var schedule = Schedule.blank(4);
    for (0..limits.max_slots) |s| {
        schedule.proposer[s] = @intCast(s % 4);
        for (0..4) |v| schedule.committee[s][v] = true;
    }
    var scenario: NullScenario = .{};
    const runner = try Runner(NullScenario).init(std.testing.allocator, &schedule, .goldfish, &scenario);
    defer runner.deinit();
    // Slots 1 to 7 propose before the run ends at `t_6 + 6 = t_7 + 2`.
    try runner.runUntil(types.slotStart(6) + 6);
    try std.testing.expectEqual(@as(u32, 7), runner.proposals.count);
    try std.testing.expectEqual(@as(u32, 7 + 7 * 4), scenario.emissions);
    const store = runner.nodes[0].store;
    const sixth = store.tree.find(&runner.proposals.buffer[5].root).?;
    try std.testing.expectEqual(sixth, store.getConfirmed());
}
