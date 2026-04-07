//! Deterministic simulation controller.
//!
//! Orchestrates multi-node simulations with deterministic slot advancement:
//!   tick clock → validators produce → gossip → nodes process → check invariants
//!
//! Sits above SimCluster, adding SimValidator integration and scenario support.
//! The controller owns the simulation lifecycle and provides higher-level
//! operations like advanceToEpoch, runUntilFinality, and runScenario.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const config_mod = @import("config");
const fork_types = @import("fork_types");

const state_transition = @import("state_transition");
const computeEpochAtSlot = state_transition.computeEpochAtSlot;

const node_pkg = @import("node");
const BeaconNode = node_pkg.BeaconNode;
const identity_mod = node_pkg.identity;
const SimNodeHarness = @import("sim_node_harness.zig").SimNodeHarness;
const SimValidator = @import("sim_validator.zig").SimValidator;
const SimNetwork = @import("sim_network.zig").SimNetwork;
const sim_network = @import("sim_network.zig");
const ClusterInvariantChecker = @import("cluster_invariant_checker.zig").ClusterInvariantChecker;
const Scenario = @import("scenario.zig").Scenario;
const Step = @import("scenario.zig").Step;
const Fault = @import("scenario.zig").Fault;
const Invariant = @import("scenario.zig").Invariant;

pub const ControllerConfig = struct {
    num_nodes: u8 = 4,
    validators_per_node: u64 = 16,
    seed: u64 = 42,
    /// Network fault configuration.
    network: sim_network.Config = .{},
    /// Total validator count for the test state.
    validator_count: usize = 64,
    /// Default participation rate for all validators.
    participation_rate: f64 = 1.0,
};

pub const FinalityResult = struct {
    slots_processed: u64,
    blocks_produced: u64,
    finalized_epoch: u64,
    safety_violations: u64,
    state_divergences: u64,
};

pub const SlotTickResult = struct {
    slot: u64,
    block_produced: bool,
    epoch_transition: bool,
};

pub const SimController = struct {
    allocator: Allocator,
    prng: std.Random.DefaultPrng,

    // Nodes
    nodes: []SimNodeHarness,
    beacon_nodes: []*BeaconNode,
    num_nodes: u8,

    // Validators (one per node)
    validators: []SimValidator,

    // Network
    net_prng: *std.Random.DefaultPrng,
    network: SimNetwork,

    // Invariant checker
    checker: ClusterInvariantChecker,

    // State
    current_slot: u64,
    total_slots: u64 = 0,
    total_blocks: u64 = 0,
    nodes_processed: []bool,

    // Proposer offline rate for skip logic
    proposer_offline_rate: f64 = 0.0,

    // Shared consensus config borrowed by every simulated node builder.
    primary_config: *config_mod.BeaconConfig,

    // Config
    config: ControllerConfig,

    pub fn init(allocator: Allocator, config: ControllerConfig) !SimController {
        var cluster_prng = std.Random.DefaultPrng.init(config.seed);

        const net_prng = try allocator.create(std.Random.DefaultPrng);
        net_prng.* = std.Random.DefaultPrng.init(config.seed +% 100);

        const primary_config = try @import("sim_test_harness.zig").createTestConfig(allocator, config.validator_count);
        errdefer allocator.destroy(primary_config);

        // Allocate arrays.
        const nodes = try allocator.alloc(SimNodeHarness, config.num_nodes);
        errdefer allocator.free(nodes);
        const beacon_nodes = try allocator.alloc(*BeaconNode, config.num_nodes);
        errdefer allocator.free(beacon_nodes);
        const validators = try allocator.alloc(SimValidator, config.num_nodes);
        errdefer allocator.free(validators);
        const nodes_processed = try allocator.alloc(bool, config.num_nodes);
        @memset(nodes_processed, false);

        // Node 0: from the shared published anchor state.
        const seed_0 = cluster_prng.random().int(u64);
        const bn0_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
        var bn0_builder = try BeaconNode.Builder.init(allocator, std.testing.io, primary_config, .{
            .options = .{ .engine_mock = true },
            .node_identity = bn0_identity,
        });
        errdefer bn0_builder.deinit();
        const bn0_anchor = try @import("sim_test_harness.zig").createPublishedAnchorState(
            allocator,
            bn0_builder.sharedStateGraph(),
            config.validator_count,
        );
        const start_slot = try bn0_anchor.state.slot();
        const bn0 = try @import("sim_test_harness.zig").finishBuilderFromPublishedAnchor(&bn0_builder, bn0_anchor);
        beacon_nodes[0] = bn0;
        nodes[0] = SimNodeHarness.init(allocator, bn0, seed_0);
        nodes[0].participation_rate = config.participation_rate;

        // Distribute validators evenly across nodes.
        const total_validators: u64 = @intCast(config.validator_count);
        const per_node = total_validators / config.num_nodes;
        const remainder = total_validators % config.num_nodes;

        var vi_start: u64 = 0;
        for (0..config.num_nodes) |i| {
            const extra: u64 = if (i < remainder) 1 else 0;
            const vi_end = vi_start + per_node + extra;
            const val_seed = cluster_prng.random().int(u64);
            validators[i] = SimValidator.init(allocator, vi_start, vi_end, val_seed);
            validators[i].participation_rate = config.participation_rate;
            vi_start = vi_end;
        }

        // Nodes 1..N: use the same published anchor state shape.
        for (1..config.num_nodes) |i| {
            const seed_i = cluster_prng.random().int(u64);
            const bn_i_identity = try identity_mod.createEphemeralIdentity(allocator, std.testing.io, .{});
            var bn_i_builder = try BeaconNode.Builder.init(allocator, std.testing.io, primary_config, .{
                .options = .{ .engine_mock = true },
                .node_identity = bn_i_identity,
            });
            errdefer bn_i_builder.deinit();
            const anchor_i = try @import("sim_test_harness.zig").createPublishedAnchorState(
                allocator,
                bn_i_builder.sharedStateGraph(),
                config.validator_count,
            );
            const bn_i = try @import("sim_test_harness.zig").finishBuilderFromPublishedAnchor(&bn_i_builder, anchor_i);
            beacon_nodes[i] = bn_i;
            nodes[i] = SimNodeHarness.init(allocator, bn_i, seed_i);
            nodes[i].participation_rate = config.participation_rate;
        }

        const checker = try ClusterInvariantChecker.init(allocator, config.num_nodes);

        return .{
            .allocator = allocator,
            .prng = cluster_prng,
            .nodes = nodes,
            .beacon_nodes = beacon_nodes,
            .num_nodes = config.num_nodes,
            .validators = validators,
            .net_prng = net_prng,
            .network = SimNetwork.init(allocator, net_prng, config.network),
            .checker = checker,
            .current_slot = start_slot,
            .nodes_processed = nodes_processed,
            .primary_config = primary_config,
            .config = config,
        };
    }

    pub fn deinit(self: *SimController) void {
        for (0..self.num_nodes) |i| {
            self.nodes[i].deinit();
            self.beacon_nodes[i].deinit();
        }

        state_transition.deinitStateTransition();

        self.allocator.destroy(self.primary_config);

        self.checker.deinit();
        self.network.deinit();
        self.allocator.destroy(self.net_prng);
        self.allocator.free(self.nodes);
        self.allocator.free(self.beacon_nodes);
        self.allocator.free(self.validators);
        self.allocator.free(self.nodes_processed);
    }

    /// Advance all nodes by one slot (with block production).
    pub fn advanceSlot(self: *SimController) !SlotTickResult {
        return self.advanceSlotImpl(false);
    }

    /// Advance one slot, skipping block production (empty slot).
    pub fn advanceSlotWithSkip(self: *SimController, force_skip: bool) !SlotTickResult {
        return self.advanceSlotImpl(force_skip);
    }

    /// Core slot advancement. All nodes process the slot synchronously.
    /// Each SimNodeHarness has its own BlockGenerator and handles
    /// proposer determination internally (via the epoch cache of the
    /// post-advance state). The controller does NOT try to determine
    /// the proposer upfront — that would require advancing state first.
    fn advanceSlotImpl(self: *SimController, force_skip: bool) !SlotTickResult {
        const target_slot = self.current_slot + 1;
        const current_epoch = computeEpochAtSlot(self.current_slot);
        const target_epoch = computeEpochAtSlot(target_slot);
        const is_epoch_transition = target_epoch != current_epoch;

        // Decide whether to skip (proposer offline).
        const skip = force_skip or self.shouldSkip();

        @memset(self.nodes_processed, false);

        var node_imported = [_]bool{false} ** 256;
        var produced_any = false;

        if (!skip) {
            const send_time_ns = self.nodes[0].sim_io.monotonic_ns;
            const slot_deadline_ns = send_time_ns + self.nodes[0].clock.seconds_per_slot * std.time.ns_per_s;

            for (0..self.num_nodes) |i| {
                const maybe_block_bytes = try self.maybeProduceValidatorBlockBytes(i, target_slot);
                if (maybe_block_bytes) |block_bytes| {
                    produced_any = true;
                    defer self.allocator.free(block_bytes);

                    for (0..self.num_nodes) |to| {
                        _ = try self.network.send(
                            @intCast(i),
                            @intCast(to),
                            block_bytes,
                            .gossip,
                            send_time_ns,
                        );
                    }
                }
            }

            const delivered = try self.network.tick(slot_deadline_ns);
            for (delivered) |msg| {
                defer self.allocator.free(msg.data);

                if (msg.message_type != .gossip) continue;

                const to: usize = @intCast(msg.to);
                const imported = try self.nodes[to].importExternalBlockBytes(msg.data, .gossip);
                node_imported[to] = node_imported[to] or imported;
            }
        }

        for (0..self.num_nodes) |i| {
            if (!node_imported[i]) {
                node_imported[i] = try self.catchUpLaggingNodeViaReqResp(i, target_slot);
            }

            const head_state = self.nodes[i].getHeadState() orelse return error.NoHeadState;
            const head_slot = try head_state.state.slot();
            if (head_slot < target_slot) {
                try self.nodes[i].advanceEmptyToSlot(target_slot);
            }

            const result = try self.nodes[i].observeSlot(target_slot, node_imported[i]);
            self.nodes_processed[i] = true;

            const fin_epoch = self.nodes[i].checker.finalized_epoch;
            try self.checker.recordNodeState(
                @intCast(i),
                result.slot,
                result.state_root,
                fin_epoch,
            );
        }

        try self.checker.checkTick(target_slot, self.nodes_processed);

        // Produce attestations from each node's validators and feed to fork choice.
        for (0..self.num_nodes) |i| {
            const head_state = self.nodes[i].getHeadState() orelse continue;
            var attestations = try self.validators[i].produceAttestations(
                self.allocator,
                head_state,
                target_slot,
            );
            defer attestations.deinit(self.allocator);

            for (attestations.attestations.items) |*att| {
                const att_data = &att.data;
                const committee = head_state.epoch_cache.getBeaconCommittee(
                    att_data.slot,
                    att_data.index,
                ) catch continue;

                for (committee, 0..) |vi, pos| {
                    const is_set = att.aggregation_bits.get(pos) catch false;
                    if (is_set) {
                        self.beacon_nodes[i].chainService().applyAttestationVote(
                            @intCast(vi),
                            att_data.slot,
                            att_data.beacon_block_root,
                            att_data.target.epoch,
                        ) catch {};
                    }
                }
            }
        }

        self.current_slot = target_slot;
        self.total_slots += 1;
        if (produced_any) self.total_blocks += 1;

        return .{
            .slot = target_slot,
            .block_produced = produced_any,
            .epoch_transition = is_epoch_transition,
        };
    }

    fn maybeProduceValidatorBlockBytes(
        self: *SimController,
        node_idx: usize,
        target_slot: u64,
    ) !?[]u8 {
        const head_state = self.nodes[node_idx].getHeadState() orelse return error.NoHeadState;

        var post_state = try head_state.clone(
            self.allocator,
            .{ .transfer_cache = false },
        );
        defer {
            post_state.deinit();
            self.allocator.destroy(post_state);
        }

        try state_transition.processSlots(
            self.allocator,
            post_state,
            target_slot,
            .{},
        );
        try post_state.state.commit();

        const produced = try self.validators[node_idx].produceBlock(post_state, target_slot);
        if (produced == null) return null;

        var any_signed = fork_types.AnySignedBeaconBlock{ .full_electra = produced.?.signed_block };
        errdefer any_signed.deinit(self.allocator);

        const block_bytes = try any_signed.serialize(self.allocator);
        any_signed.deinit(self.allocator);
        return block_bytes;
    }

    fn catchUpLaggingNodeViaReqResp(
        self: *SimController,
        node_idx: usize,
        target_slot: u64,
    ) !bool {
        var imported_any = false;

        while (true) {
            const local_head = self.beacon_nodes[node_idx].getHead();
            const peer_idx = self.bestReachableSyncPeer(node_idx) orelse break;
            const peer_head = self.beacon_nodes[peer_idx].getHead();

            const local_finalized_slot = local_head.finalized_epoch * preset.SLOTS_PER_EPOCH;
            const peer_finalized_slot = peer_head.finalized_epoch * preset.SLOTS_PER_EPOCH;
            const common_finalized_slot = @min(local_finalized_slot, peer_finalized_slot);
            const start_slot = common_finalized_slot + 1;

            if (start_slot > peer_head.slot) break;

            const imported = try self.nodes[node_idx].syncBlocksByRangeFromPeer(
                self.beacon_nodes[peer_idx],
                start_slot,
                peer_head.slot,
            );
            if (imported == 0) break;
            imported_any = true;

            const updated_head = self.beacon_nodes[node_idx].getHead();
            if (updated_head.slot >= target_slot and std.mem.eql(u8, &updated_head.root, &peer_head.root)) {
                break;
            }
        }

        return imported_any or (try self.nodes[node_idx].currentSlot()) >= target_slot;
    }

    fn bestReachableSyncPeer(
        self: *const SimController,
        node_idx: usize,
    ) ?usize {
        const local_head = self.beacon_nodes[node_idx].getHead();
        var best_idx: ?usize = null;
        var best_slot: u64 = local_head.slot;

        for (0..self.num_nodes) |peer_idx| {
            if (peer_idx == node_idx) continue;
            if (self.network.partition_set[node_idx][peer_idx] or self.network.partition_set[peer_idx][node_idx]) {
                continue;
            }

            const peer_head = self.beacon_nodes[peer_idx].getHead();
            if (peer_head.slot > best_slot) {
                best_slot = peer_head.slot;
                best_idx = peer_idx;
                continue;
            }
            if (peer_head.slot == best_slot and
                best_idx == null and
                !std.mem.eql(u8, &peer_head.root, &local_head.root))
            {
                best_idx = peer_idx;
            }
        }

        return best_idx;
    }

    fn shouldSkip(self: *SimController) bool {
        if (self.proposer_offline_rate <= 0.0) return false;
        const val: f64 = @as(f64, @floatFromInt(self.prng.random().int(u32))) /
            @as(f64, @floatFromInt(std.math.maxInt(u32)));
        return val < self.proposer_offline_rate;
    }

    /// Advance to a specific epoch (inclusive of the first slot of the epoch).
    pub fn advanceToEpoch(self: *SimController, target_epoch: u64) !void {
        const target_slot = target_epoch * preset.SLOTS_PER_EPOCH;
        while (self.current_slot < target_slot) {
            _ = try self.advanceSlot();
        }
    }

    /// Advance forward by N epochs from the current slot.
    pub fn advanceEpochs(self: *SimController, count: u64) !void {
        const current_epoch = computeEpochAtSlot(self.current_slot);
        try self.advanceToEpoch(current_epoch + count);
    }

    /// Advance N slots.
    pub fn advanceSlots(self: *SimController, count: u64) !void {
        for (0..count) |_| {
            _ = try self.advanceSlot();
        }
    }

    /// Run until finality advances past epoch 0, or max_slots is reached.
    pub fn runUntilFinality(self: *SimController, max_slots: u64) !FinalityResult {
        for (0..max_slots) |_| {
            _ = try self.advanceSlot();

            for (self.checker.node_finalized_epochs[0..self.num_nodes]) |e| {
                if (e > 0) return self.getFinalityResult();
            }
        }
        return self.getFinalityResult();
    }

    /// Run a scenario.
    pub fn runScenario(self: *SimController, scenario: Scenario) !FinalityResult {
        for (scenario.steps) |step| {
            try self.executeStep(step);
        }
        return self.getFinalityResult();
    }

    /// Execute a single scenario step.
    pub fn executeStep(self: *SimController, step: Step) !void {
        switch (step) {
            .advance_slot => {
                _ = try self.advanceSlot();
            },
            .advance_to_epoch => |epoch| {
                try self.advanceToEpoch(epoch);
            },
            .advance_epochs => |count| {
                try self.advanceEpochs(count);
            },
            .skip_slot => {
                _ = try self.advanceSlotImpl(true);
            },
            .check_invariant => |invariant| {
                try self.checkInvariant(invariant);
            },
            .network_partition => |partition| {
                for (partition.group_a) |a| {
                    for (partition.group_b) |b| {
                        self.network.partition(a, b);
                    }
                }
            },
            .heal_partition => {
                self.network.healAll();
            },
            .disconnect_node => |node_id| {
                for (0..self.num_nodes) |i| {
                    if (i != node_id) {
                        self.network.partition(node_id, @intCast(i));
                    }
                }
            },
            .reconnect_node => |node_id| {
                for (0..self.num_nodes) |i| {
                    if (i != node_id) {
                        self.network.heal(node_id, @intCast(i));
                    }
                }
            },
            .inject_fault => |fault| {
                self.injectFault(fault);
            },
            .set_participation_rate => |rate| {
                for (self.validators) |*v| {
                    v.participation_rate = rate;
                }
                for (self.nodes) |*n| {
                    n.participation_rate = rate;
                }
            },
        }
    }

    /// Check a specific invariant.
    pub fn checkInvariant(self: *SimController, invariant: Invariant) !void {
        switch (invariant) {
            .finality_agreement => {
                if (self.num_nodes < 2) return;
                const first = self.checker.node_finalized_epochs[0];
                for (self.checker.node_finalized_epochs[1..self.num_nodes]) |e| {
                    if (e != first) return error.FinalityDisagreement;
                }
            },
            .safety => {
                if (self.checker.safety_violations > 0) return error.SafetyViolation;
            },
            .liveness => |max_gap_epochs| {
                const gap_slots = self.current_slot - self.checker.last_finality_advance_slot;
                const gap_epochs = gap_slots / preset.SLOTS_PER_EPOCH;
                if (gap_epochs > max_gap_epochs) return error.LivenessStall;
            },
            .head_agreement => {
                if (self.num_nodes < 2) return;
                const head_0 = self.nodes[0].getHeadState() orelse return error.NoHeadState;
                const root_0 = (try head_0.state.hashTreeRoot()).*;
                for (1..self.num_nodes) |i| {
                    const head_i = self.nodes[i].getHeadState() orelse continue;
                    const root_i = (try head_i.state.hashTreeRoot()).*;
                    if (!std.mem.eql(u8, &root_0, &root_i)) return error.HeadDisagreement;
                }
            },
            .head_freshness => |max_behind| {
                for (0..self.num_nodes) |i| {
                    const head_slot = self.beacon_nodes[i].getHead().slot;
                    if (self.current_slot > head_slot + max_behind) return error.HeadTooStale;
                }
            },
            .no_state_divergence => {
                if (self.checker.state_divergences > 0) return error.StateDivergence;
            },
        }
    }

    /// Inject a fault into the simulation.
    fn injectFault(self: *SimController, fault: Fault) void {
        switch (fault) {
            .missed_proposal => |node_idx| {
                if (node_idx < self.validators.len) {
                    self.validators[node_idx].skip_next_proposal = true;
                }
            },
            .missed_attestation => |node_idx| {
                if (node_idx < self.validators.len) {
                    self.validators[node_idx].skip_attestations = true;
                }
            },
            .message_drop_rate => |rate| {
                self.network.config.packet_loss_rate = rate;
            },
            .message_delay => |delay| {
                self.network.config.min_latency_ms = delay.min_ms;
                self.network.config.max_latency_ms = delay.max_ms;
            },
            .node_crash => |node_idx| {
                for (0..self.num_nodes) |i| {
                    if (i != node_idx) {
                        self.network.partition(node_idx, @intCast(i));
                    }
                }
            },
            .node_restart => |node_idx| {
                for (0..self.num_nodes) |i| {
                    if (i != node_idx) {
                        self.network.heal(node_idx, @intCast(i));
                    }
                }
            },
        }
    }

    pub fn getFinalityResult(self: *const SimController) FinalityResult {
        var max_finalized: u64 = 0;
        for (self.checker.node_finalized_epochs[0..self.num_nodes]) |e| {
            max_finalized = @max(max_finalized, e);
        }

        return .{
            .slots_processed = self.total_slots,
            .blocks_produced = self.total_blocks,
            .finalized_epoch = max_finalized,
            .safety_violations = self.checker.safety_violations,
            .state_divergences = self.checker.state_divergences,
        };
    }

    /// Get the current finalized epoch (max across all nodes).
    pub fn finalizedEpoch(self: *const SimController) u64 {
        var max_epoch: u64 = 0;
        for (self.checker.node_finalized_epochs[0..self.num_nodes]) |e| {
            max_epoch = @max(max_epoch, e);
        }
        return max_epoch;
    }
};
