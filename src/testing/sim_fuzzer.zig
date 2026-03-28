//! Simulation fuzzer for random event injection and invariant checking.
//!
//! Generates random simulation steps weighted by configurable probabilities,
//! checks invariants after each step, and dumps a reproducer on failure.
//!
//! All randomness comes from a seeded PRNG — same seed = identical fuzz run.

const std = @import("std");
const Allocator = std.mem.Allocator;

const SimController = @import("sim_controller.zig").SimController;
const ControllerConfig = @import("sim_controller.zig").ControllerConfig;
const Step = @import("scenario.zig").Step;
const Invariant = @import("scenario.zig").Invariant;
const Fault = @import("scenario.zig").Fault;

pub const FuzzWeights = struct {
    /// Weight for advance_slot steps (normal progression).
    advance_slot: u32 = 70,
    /// Weight for skip_slot steps.
    skip_slot: u32 = 10,
    /// Weight for fault injection steps.
    inject_fault: u32 = 10,
    /// Weight for network partition/heal steps.
    network_ops: u32 = 5,
    /// Weight for participation rate changes.
    participation_change: u32 = 5,
};

pub const InvariantFailure = struct {
    step_index: u64,
    invariant: Invariant,
    step: Step,
    err: anyerror,
};

pub const FuzzResult = struct {
    steps_run: u64,
    invariant_failures: std.ArrayListUnmanaged(InvariantFailure),
    /// The step history for reproduction.
    step_history: std.ArrayListUnmanaged(Step),

    pub fn deinit(self: *FuzzResult, allocator: Allocator) void {
        self.invariant_failures.deinit(allocator);
        self.step_history.deinit(allocator);
    }

    pub fn ok(self: *const FuzzResult) bool {
        return self.invariant_failures.items.len == 0;
    }
};

pub const SimFuzzer = struct {
    allocator: Allocator,
    controller: *SimController,
    prng: std.Random.DefaultPrng,
    weights: FuzzWeights,

    /// Invariants to check after each step.
    invariants: []const Invariant,

    pub fn init(
        allocator: Allocator,
        controller: *SimController,
        seed: u64,
        weights: FuzzWeights,
        invariants: []const Invariant,
    ) SimFuzzer {
        return .{
            .allocator = allocator,
            .controller = controller,
            .prng = std.Random.DefaultPrng.init(seed),
            .weights = weights,
            .invariants = invariants,
        };
    }

    /// Run `num_steps` random steps, checking invariants after each.
    pub fn fuzz(self: *SimFuzzer, num_steps: u64) !FuzzResult {
        var result = FuzzResult{
            .steps_run = 0,
            .invariant_failures = .empty,
            .step_history = .empty,
        };
        errdefer result.deinit(self.allocator);

        for (0..num_steps) |step_idx| {
            const step = self.randomStep();
            try result.step_history.append(self.allocator, step);

            // Execute the step — catch errors as invariant failures.
            self.controller.executeStep(step) catch |err| {
                try result.invariant_failures.append(self.allocator, .{
                    .step_index = step_idx,
                    .invariant = .safety,
                    .step = step,
                    .err = err,
                });
                result.steps_run = step_idx + 1;
                return result;
            };

            // Check invariants after the step.
            for (self.invariants) |invariant| {
                self.controller.checkInvariant(invariant) catch |err| {
                    try result.invariant_failures.append(self.allocator, .{
                        .step_index = step_idx,
                        .invariant = invariant,
                        .step = step,
                        .err = err,
                    });
                };
            }

            result.steps_run = step_idx + 1;

            // Stop early on safety violation.
            if (self.controller.checker.safety_violations > 0) {
                return result;
            }
        }

        return result;
    }

    /// Generate a random step weighted by the configured weights.
    fn randomStep(self: *SimFuzzer) Step {
        const total = self.weights.advance_slot +
            self.weights.skip_slot +
            self.weights.inject_fault +
            self.weights.network_ops +
            self.weights.participation_change;

        const roll = self.prng.random().intRangeAtMost(u32, 0, total - 1);

        var threshold: u32 = 0;

        // advance_slot
        threshold += self.weights.advance_slot;
        if (roll < threshold) return .{ .advance_slot = {} };

        // skip_slot
        threshold += self.weights.skip_slot;
        if (roll < threshold) return .{ .skip_slot = {} };

        // inject_fault
        threshold += self.weights.inject_fault;
        if (roll < threshold) return self.randomFault();

        // network_ops
        threshold += self.weights.network_ops;
        if (roll < threshold) return self.randomNetworkOp();

        // participation_change
        return self.randomParticipationChange();
    }

    fn randomFault(self: *SimFuzzer) Step {
        const fault_type = self.prng.random().intRangeAtMost(u32, 0, 3);
        const num_nodes = self.controller.num_nodes;

        return switch (fault_type) {
            0 => .{ .inject_fault = .{ .missed_proposal = self.prng.random().intRangeAtMost(usize, 0, num_nodes - 1) } },
            1 => .{ .inject_fault = .{ .missed_attestation = self.prng.random().intRangeAtMost(usize, 0, num_nodes - 1) } },
            2 => .{ .inject_fault = .{ .message_drop_rate = @as(f64, @floatFromInt(self.prng.random().intRangeAtMost(u32, 0, 50))) / 100.0 } },
            3 => .{ .inject_fault = .{
                .message_delay = .{
                    .min_ms = self.prng.random().intRangeAtMost(u64, 1, 50),
                    .max_ms = self.prng.random().intRangeAtMost(u64, 50, 200),
                },
            } },
            else => .{ .advance_slot = {} },
        };
    }

    fn randomNetworkOp(self: *SimFuzzer) Step {
        const op_type = self.prng.random().intRangeAtMost(u32, 0, 2);
        const num_nodes = self.controller.num_nodes;

        return switch (op_type) {
            0 => .{ .heal_partition = {} },
            1 => .{ .disconnect_node = self.prng.random().intRangeAtMost(u8, 0, num_nodes - 1) },
            2 => .{ .reconnect_node = self.prng.random().intRangeAtMost(u8, 0, num_nodes - 1) },
            else => .{ .heal_partition = {} },
        };
    }

    fn randomParticipationChange(self: *SimFuzzer) Step {
        // Random participation rate between 0.3 and 1.0.
        const val = self.prng.random().intRangeAtMost(u32, 30, 100);
        return .{ .set_participation_rate = @as(f64, @floatFromInt(val)) / 100.0 };
    }

    /// Dump the step history as a reproducer (for debugging).
    pub fn dumpReproducer(self: *const SimFuzzer, result: *const FuzzResult) void {
        _ = self;
        std.log.info("=== Fuzzer Reproducer ===", .{});
        std.log.info("Steps run: {d}", .{result.steps_run});
        std.log.info("Failures: {d}", .{result.invariant_failures.items.len});

        for (result.step_history.items, 0..) |step, i| {
            const is_failure = for (result.invariant_failures.items) |f| {
                if (f.step_index == i) break true;
            } else false;
            const marker: []const u8 = if (is_failure) " <-- FAILURE" else "";
            std.log.info("  Step {d}: {}{s}", .{ i, step, marker });
        }
    }
};
