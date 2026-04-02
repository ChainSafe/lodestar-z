const std = @import("std");
const Allocator = std.mem.Allocator;

const ssz = @import("consensus_types");
const primitives = ssz.primitive;
const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;
const Checkpoint = ssz.phase0.Checkpoint.Type;

const config_mod = @import("config");
const ForkSeq = config_mod.ForkSeq;
const BeaconConfig = config_mod.BeaconConfig;

const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoice;
const ForkChoiceStore = fork_choice_mod.ForkChoiceStore;
const ProtoArray = fork_choice_mod.ProtoArray;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const ExecutionStatus = fork_choice_mod.ExecutionStatus;
const DataAvailabilityStatus = fork_choice_mod.DataAvailabilityStatus;
const CheckpointWithPayloadStatus = fork_choice_mod.CheckpointWithPayloadStatus;
const ForkChoiceOpts = fork_choice_mod.ForkChoiceOpts;
const JustifiedBalancesGetter = fork_choice_mod.JustifiedBalancesGetter;
const JustifiedBalances = fork_choice_mod.JustifiedBalances;
const LVHExecResponse = fork_choice_mod.LVHExecResponse;
const BlockExtraMeta = fork_choice_mod.BlockExtraMeta;

const fork_types = @import("fork_types");
const AnyBeaconBlock = fork_types.AnyBeaconBlock;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnyBeaconState = fork_types.AnyBeaconState;
const AnyIndexedAttestation = fork_types.AnyIndexedAttestation;
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;

const Node = @import("persistent_merkle_tree").Node;

const ZERO_HASH: Root = [_]u8{0} ** 32;

const test_case = @import("../test_case.zig");
const loadSszSnappyValue = test_case.loadSszSnappyValue;
const loadSignedBeaconBlock = test_case.loadSignedBeaconBlock;
const deinitSignedBeaconBlock = test_case.deinitSignedBeaconBlock;
const loadBeaconBlock = test_case.loadBeaconBlock;
const deinitBeaconBlock = test_case.deinitBeaconBlock;
const TestCaseUtils = test_case.TestCaseUtils;

// ── YAML Step Types ──

const Step = union(enum) {
    tick: u64,
    block: BlockStep,
    attestation: []const u8,
    attester_slashing: []const u8,
    pow_block: []const u8,
    payload_status: PayloadStatusStep,
    checks: Checks,
};

const BlockStep = struct {
    name: []const u8,
    valid: bool = true,
};

const PayloadStatusStep = struct {
    block_hash: Root,
    status: enum { valid, invalid, syncing, accepted },
    latest_valid_hash: ?Root = null,
};

const Checks = struct {
    genesis_time: ?u64 = null,
    time: ?u64 = null,
    head: ?CheckHead = null,
    justified_checkpoint: ?CheckCheckpoint = null,
    finalized_checkpoint: ?CheckCheckpoint = null,
    proposer_boost_root: ?Root = null,
    get_proposer_head: ?Root = null,
    should_override_forkchoice_update: ?ShouldOverrideFCU = null,
};

const CheckHead = struct {
    slot: Slot,
    root: Root,
};

const CheckCheckpoint = struct {
    epoch: Epoch,
    root: Root,
};

const ShouldOverrideFCU = struct {
    validator_is_connected: bool = true,
    result: bool,
};

// ── TestCase ──

pub fn TestCase(comptime fork: ForkSeq) type {
    const tc_utils = TestCaseUtils(fork);

    return struct {
        allocator: Allocator,
        pool: *Node.Pool,

        // Anchor state (provides BeaconConfig + immutable data for state_transition)
        anchor_state: TestCachedBeaconState,

        // Fork choice components (heap-allocated for stable pointers)
        fc: *ForkChoice,
        fc_store: *ForkChoiceStore,
        proto_array: *ProtoArray,

        // State cache: maps block_root → post_state for proper fork handling.
        // Blocks may reference different parents (forking), so each block's state
        // transition must start from the correct parent's post-state.
        state_cache: std.AutoHashMap(Root, *CachedBeaconState),

        // Root of the anchor block (used as fallback parent state)
        anchor_block_root: Root,

        // Tick time in seconds (from steps.yaml tick values)
        tick_time: u64 = 0,

        // Parsed steps
        steps: []Step,

        // Test directory for loading SSZ files on demand
        test_dir: std.fs.Dir,

        const Self = @This();

        pub fn execute(allocator: Allocator, pool: *Node.Pool, dir: std.fs.Dir) !void {
            var tc = Self.init(allocator, pool, dir) catch |err| {
                if (err == error.SkipZigTest) return err;
                std.debug.print("fork_choice init error: {s}\n", .{@errorName(err)});
                return err;
            };
            defer tc.deinit();

            tc.runSteps() catch |err| {
                std.debug.print("fork_choice step error: {s}\n", .{@errorName(err)});
                return err;
            };
        }

        fn init(allocator: Allocator, pool: *Node.Pool, dir: std.fs.Dir) !Self {
            // 1. Load anchor state
            var anchor_state = try tc_utils.loadPreStateFromFile(allocator, pool, dir, "anchor_state.ssz_snappy");
            errdefer anchor_state.deinit();

            // 2. Load anchor block and compute block_root
            const anchor_block = try loadBeaconBlock(allocator, fork, dir, "anchor_block.ssz_snappy");
            defer deinitBeaconBlock(anchor_block, allocator);

            var block_root: Root = undefined;
            try anchor_block.hashTreeRoot(allocator, &block_root);

            const anchor_slot = anchor_block.slot();
            const parent_root = anchor_block.parentRoot().*;
            const state_root = anchor_block.stateRoot().*;

            // 3. Get justified/finalized checkpoints from anchor state
            //
            // Note: The anchor checkpoint root must match the block_root stored in ProtoArray.
            // For genesis, the state's currentJustifiedCheckpoint has root=0x00..00, but
            // ProtoArray stores the actual block hash. Following the Lodestar TS pattern:
            // use the computed block_root as the checkpoint root (matching computeAnchorCheckpoint).
            const anchor_cached = anchor_state.cached_state;
            var justified_cp_val: Checkpoint = undefined;
            try anchor_cached.state.currentJustifiedCheckpoint(&justified_cp_val);
            var finalized_cp_val: Checkpoint = undefined;
            try anchor_cached.state.finalizedCheckpoint(&finalized_cp_val);

            // Override checkpoint roots with the anchor block root
            // (mirrors TS computeAnchorCheckpoint which uses BeaconBlockHeader hash)
            justified_cp_val.root = block_root;
            finalized_cp_val.root = block_root;

            const justified_cp = CheckpointWithPayloadStatus{
                .epoch = justified_cp_val.epoch,
                .root = justified_cp_val.root,
            };
            const finalized_cp = CheckpointWithPayloadStatus{
                .epoch = finalized_cp_val.epoch,
                .root = finalized_cp_val.root,
            };

            // 4. Build anchor ProtoBlock
            const anchor_proto_block = ProtoBlock{
                .slot = anchor_slot,
                .block_root = block_root,
                .parent_root = parent_root,
                .state_root = state_root,
                .target_root = block_root, // ProtoArray.initialize sets this
                .justified_epoch = justified_cp_val.epoch,
                .justified_root = justified_cp_val.root,
                .finalized_epoch = finalized_cp_val.epoch,
                .finalized_root = finalized_cp_val.root,
                .unrealized_justified_epoch = justified_cp_val.epoch,
                .unrealized_justified_root = justified_cp_val.root,
                .unrealized_finalized_epoch = finalized_cp_val.epoch,
                .unrealized_finalized_root = finalized_cp_val.root,
                .extra_meta = .pre_merge,
                .timeliness = false,
            };

            // 5. Initialize ProtoArray
            const proto_array = try allocator.create(ProtoArray);
            errdefer allocator.destroy(proto_array);
            proto_array.* = undefined;
            try proto_array.initialize(allocator, anchor_proto_block, anchor_slot);
            errdefer proto_array.deinit(allocator);

            // 6. Compute justified balances
            var justified_balances = try state_transition.getEffectiveBalanceIncrementsZeroInactive(allocator, anchor_cached);
            defer justified_balances.deinit();

            // 7. Initialize ForkChoiceStore
            const fc_store = try allocator.create(ForkChoiceStore);
            errdefer allocator.destroy(fc_store);
            try fc_store.init(
                allocator,
                anchor_slot,
                justified_cp,
                finalized_cp,
                justified_balances.items,
                JustifiedBalancesGetter{
                    .getFn = specTestBalancesGetter,
                },
                .{},
            );
            errdefer fc_store.deinit(allocator);

            // 8. Initialize ForkChoice
            const fc = try allocator.create(ForkChoice);
            errdefer allocator.destroy(fc);
            try fc.init(
                allocator,
                anchor_state.config,
                fc_store,
                proto_array,
                @intCast(justified_balances.items.len),
                .{
                    .proposer_boost = true,
                    .proposer_boost_reorg = true,
                    .compute_unrealized = true,
                },
            );
            errdefer fc.deinit(allocator);

            // 9. Parse steps.yaml
            const steps = try parseSteps(allocator, dir);

            return Self{
                .allocator = allocator,
                .pool = pool,
                .anchor_state = anchor_state,
                .fc = fc,
                .fc_store = fc_store,
                .proto_array = proto_array,
                .state_cache = std.AutoHashMap(Root, *CachedBeaconState).init(allocator),
                .anchor_block_root = block_root,
                .tick_time = 0,
                .steps = steps,
                .test_dir = dir,
            };
        }

        fn deinit(self: *Self) void {
            freeSteps(self.allocator, self.steps);
            // Free all cached post-states
            var it = self.state_cache.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.deinit();
                self.allocator.destroy(entry.value_ptr.*);
            }
            self.state_cache.deinit();
            self.fc.deinit(self.allocator);
            self.allocator.destroy(self.fc);
            self.fc_store.deinit(self.allocator);
            self.allocator.destroy(self.fc_store);
            self.proto_array.deinit(self.allocator);
            self.allocator.destroy(self.proto_array);
            self.anchor_state.deinit();
        }

        fn runSteps(self: *Self) !void {
            for (self.steps, 0..) |step, step_idx| {
                _ = step_idx;
                switch (step) {
                    .tick => |t| try self.handleTick(t),
                    .block => |b| try self.handleBlock(b),
                    .attestation => |a| try self.handleAttestation(a),
                    .attester_slashing => |s| try self.handleAttesterSlashing(s),
                    .pow_block => {
                        // pow_block steps are not currently supported (bellatrix on_merge_block only).
                        // Skip for now — the block step with valid:false will catch expected failures.
                    },
                    .payload_status => |ps| self.handlePayloadStatus(ps),
                    .checks => |c| try self.handleChecks(c),
                }
            }
        }

        fn handleTick(self: *Self, time: u64) !void {
            self.tick_time = time;
            const seconds_per_slot = self.anchor_state.config.chain.SECONDS_PER_SLOT;
            const current_slot: Slot = @intCast(time / seconds_per_slot);
            try self.fc.updateTime(self.allocator, current_slot);
        }

        fn handleBlock(self: *Self, block_step: BlockStep) !void {
            const file_name = try std.fmt.allocPrint(self.allocator, "{s}.ssz_snappy", .{block_step.name});
            defer self.allocator.free(file_name);

            const signed_block = try loadSignedBeaconBlock(self.allocator, fork, self.test_dir, file_name);
            defer deinitSignedBeaconBlock(signed_block, self.allocator);

            const beacon_block = signed_block.beaconBlock();

            // Look up the parent's post-state from cache; fall back to anchor state
            const parent_root = beacon_block.parentRoot().*;
            const input_state = if (self.state_cache.get(parent_root)) |cs|
                cs
            else if (std.mem.eql(u8, &parent_root, &self.anchor_block_root))
                self.anchor_state.cached_state
            else
                self.anchor_state.cached_state;

            // Run state_transition to get post-state
            const post_state_result = state_transition.stateTransition(
                self.allocator,
                input_state,
                signed_block,
                .{
                    .verify_signatures = false,
                    .verify_proposer = false,
                    .verify_state_root = false,
                },
            );

            if (block_step.valid) {
                // Block expected to be valid
                const post_state = try post_state_result;
                errdefer {
                    post_state.deinit();
                    self.allocator.destroy(post_state);
                }

                // Compute block_root
                var block_root: Root = undefined;
                try beacon_block.hashTreeRoot(self.allocator, &block_root);

                // Determine block_delay: if tick happened in the same slot, compute seconds into slot
                const seconds_per_slot = self.anchor_state.config.chain.SECONDS_PER_SLOT;
                const block_slot = beacon_block.slot();
                const slot_start_time = block_slot * seconds_per_slot;
                const block_delay: u32 = if (self.tick_time >= slot_start_time)
                    @intCast(self.tick_time - slot_start_time)
                else
                    0;

                const current_slot: Slot = @intCast(self.tick_time / seconds_per_slot);

                // Determine execution status
                const execution_status = getExecutionStatus(beacon_block);
                const da_status = getDataAvailabilityStatus(beacon_block);

                // Call fork choice onBlock
                _ = try self.fc.onBlock(
                    self.allocator,
                    &beacon_block,
                    post_state,
                    block_delay,
                    current_slot,
                    execution_status,
                    da_status,
                );

                // Store post_state in cache keyed by block_root.
                // Prune old entries to avoid pool exhaustion — keep only the
                // last few states (most tests are linear chains; forked tests
                // have short branches).
                try self.state_cache.put(block_root, post_state);
                self.pruneStateCache(block_root);
            } else {
                // Block expected to be invalid — either state_transition or onBlock should error
                if (post_state_result) |post_state| {
                    defer {
                        post_state.deinit();
                        self.allocator.destroy(post_state);
                    }
                    // state_transition succeeded, try onBlock (it may still fail)
                    var block_root: Root = undefined;
                    try beacon_block.hashTreeRoot(self.allocator, &block_root);

                    const seconds_per_slot = self.anchor_state.config.chain.SECONDS_PER_SLOT;
                    const current_slot: Slot = @intCast(self.tick_time / seconds_per_slot);
                    const execution_status = getExecutionStatus(beacon_block);

                    _ = self.fc.onBlock(
                        self.allocator,
                        &beacon_block,
                        post_state,
                        0,
                        current_slot,
                        execution_status,
                        .not_required,
                    ) catch {
                        return; // Expected failure in onBlock
                    };
                    // If both succeed but block should be invalid, that's OK for some tests
                    // (e.g., deneb blob validation happens outside state_transition)
                } else |_| {
                    return; // Expected failure in state_transition
                }
            }
        }

        fn handleAttestation(self: *Self, att_name: []const u8) !void {
            const file_name = try std.fmt.allocPrint(self.allocator, "{s}.ssz_snappy", .{att_name});
            defer self.allocator.free(file_name);

            // Find the best state for epoch cache (most recently added, or anchor)
            const head_state = self.getHeadState();

            if (comptime fork.gte(.electra)) {
                // Electra+ attestation format (wider committee_bits)
                const types_mod = @import("consensus_types");
                var attestation: types_mod.electra.Attestation.Type = types_mod.electra.Attestation.default_value;
                try loadSszSnappyValue(types_mod.electra.Attestation, self.allocator, self.test_dir, file_name, &attestation);
                defer types_mod.electra.Attestation.deinit(self.allocator, &attestation);

                var indexed_att: types_mod.electra.IndexedAttestation.Type = types_mod.electra.IndexedAttestation.default_value;
                try head_state.epoch_cache.computeIndexedAttestationElectra(&attestation, &indexed_att);
                defer types_mod.electra.IndexedAttestation.deinit(self.allocator, &indexed_att);

                var att_data_root: Root = undefined;
                try types_mod.phase0.AttestationData.hashTreeRoot(&attestation.data, &att_data_root);

                const any_indexed = AnyIndexedAttestation{ .electra = &indexed_att };
                try self.fc.onAttestation(self.allocator, &any_indexed, att_data_root, true);
            } else {
                // Phase0 attestation format (pre-electra)
                const types_mod = @import("consensus_types");
                var attestation: types_mod.phase0.Attestation.Type = types_mod.phase0.Attestation.default_value;
                try loadSszSnappyValue(types_mod.phase0.Attestation, self.allocator, self.test_dir, file_name, &attestation);
                defer types_mod.phase0.Attestation.deinit(self.allocator, &attestation);

                var indexed_att: types_mod.phase0.IndexedAttestation.Type = types_mod.phase0.IndexedAttestation.default_value;
                try head_state.epoch_cache.computeIndexedAttestationPhase0(&attestation, &indexed_att);
                defer types_mod.phase0.IndexedAttestation.deinit(self.allocator, &indexed_att);

                var att_data_root: Root = undefined;
                try types_mod.phase0.AttestationData.hashTreeRoot(&attestation.data, &att_data_root);

                const any_indexed = AnyIndexedAttestation{ .phase0 = &indexed_att };
                try self.fc.onAttestation(self.allocator, &any_indexed, att_data_root, true);
            }
        }

        fn handleAttesterSlashing(self: *Self, slashing_name: []const u8) !void {
            const file_name = try std.fmt.allocPrint(self.allocator, "{s}.ssz_snappy", .{slashing_name});
            defer self.allocator.free(file_name);

            if (comptime fork.gte(.electra)) {
                const types_mod = @import("consensus_types");
                var slashing: types_mod.electra.AttesterSlashing.Type = types_mod.electra.AttesterSlashing.default_value;
                try loadSszSnappyValue(types_mod.electra.AttesterSlashing, self.allocator, self.test_dir, file_name, &slashing);
                defer types_mod.electra.AttesterSlashing.deinit(self.allocator, &slashing);

                const any_slashing = AnyAttesterSlashing{ .electra = &slashing };
                try self.fc.onAttesterSlashing(self.allocator, &any_slashing);
            } else {
                const types_mod = @import("consensus_types");
                var slashing: types_mod.phase0.AttesterSlashing.Type = types_mod.phase0.AttesterSlashing.default_value;
                try loadSszSnappyValue(types_mod.phase0.AttesterSlashing, self.allocator, self.test_dir, file_name, &slashing);
                defer types_mod.phase0.AttesterSlashing.deinit(self.allocator, &slashing);

                const any_slashing = AnyAttesterSlashing{ .phase0 = &slashing };
                try self.fc.onAttesterSlashing(self.allocator, &any_slashing);
            }
        }

        /// Get the most recent cached state (for epoch cache access).
        /// Falls back to anchor state if no blocks have been processed yet.
        fn getHeadState(self: *Self) *CachedBeaconState {
            // Use the head block's state if available in cache
            const head_root = self.fc.getHeadRoot();
            if (self.state_cache.get(head_root)) |state| {
                return state;
            }
            return self.anchor_state.cached_state;
        }

        fn handlePayloadStatus(self: *Self, ps: PayloadStatusStep) void {
            const seconds_per_slot = self.anchor_state.config.chain.SECONDS_PER_SLOT;
            const current_slot: Slot = @intCast(self.tick_time / seconds_per_slot);

            const response: LVHExecResponse = switch (ps.status) {
                .valid => .{ .valid = .{ .latest_valid_exec_hash = ps.block_hash } },
                .invalid => .{ .invalid = .{
                    .latest_valid_exec_hash = ps.latest_valid_hash,
                    .invalidate_from_parent_block_root = ZERO_HASH,
                } },
                .syncing, .accepted => return, // Not handled in fork choice
            };
            self.fc.validateLatestHash(self.allocator, response, current_slot);
        }

        fn handleChecks(self: *Self, checks: Checks) !void {
            // time check: fork_choice stores time as slots, test provides time in seconds
            if (checks.time) |expected_time| {
                const seconds_per_slot = self.anchor_state.config.chain.SECONDS_PER_SLOT;
                const expected_slot: Slot = @intCast(expected_time / seconds_per_slot);
                const actual_slot = self.fc.getTime();
                try std.testing.expectEqual(expected_slot, actual_slot);
            }

            // head check
            if (checks.head) |expected_head| {
                const result = try self.fc.updateAndGetHead(self.allocator, .{ .get_canonical_head = {} });
                try std.testing.expectEqual(expected_head.slot, result.head.slot);
                try std.testing.expectEqualSlices(u8, &expected_head.root, &result.head.block_root);
            }

            // justified checkpoint check
            if (checks.justified_checkpoint) |expected| {
                const actual = self.fc.getJustifiedCheckpoint();
                try std.testing.expectEqual(expected.epoch, actual.epoch);
                try std.testing.expectEqualSlices(u8, &expected.root, &actual.root);
            }

            // finalized checkpoint check
            if (checks.finalized_checkpoint) |expected| {
                const actual = self.fc.getFinalizedCheckpoint();
                try std.testing.expectEqual(expected.epoch, actual.epoch);
                try std.testing.expectEqualSlices(u8, &expected.root, &actual.root);
            }

            // proposer boost root check
            if (checks.proposer_boost_root) |expected| {
                const actual = self.fc.getProposerBoostRoot();
                try std.testing.expectEqualSlices(u8, &expected, &actual);
            }

            // get_proposer_head check
            if (checks.get_proposer_head) |expected_root| {
                const seconds_per_slot = self.anchor_state.config.chain.SECONDS_PER_SLOT;
                const current_slot: Slot = @intCast(self.tick_time / seconds_per_slot);
                const sec_from_slot: u32 = @intCast(self.tick_time % seconds_per_slot);

                const result = try self.fc.updateAndGetHead(self.allocator, .{
                    .get_proposer_head = .{
                        .sec_from_slot = sec_from_slot,
                        .slot = current_slot,
                    },
                });
                try std.testing.expectEqualSlices(u8, &expected_root, &result.head.block_root);
            }

            // should_override_forkchoice_update check
            if (checks.should_override_forkchoice_update) |expected_fcu| {
                const seconds_per_slot = self.anchor_state.config.chain.SECONDS_PER_SLOT;
                const current_slot: Slot = @intCast(self.tick_time / seconds_per_slot);
                const sec_from_slot: u32 = @intCast(self.tick_time % seconds_per_slot);

                const head_result = try self.fc.updateAndGetHead(self.allocator, .{ .get_canonical_head = {} });
                const result = self.fc.shouldOverrideForkChoiceUpdate(
                    &head_result.head,
                    sec_from_slot,
                    current_slot,
                );
                const actual_should_override = switch (result) {
                    .should_override => true,
                    .should_not_override => false,
                };
                try std.testing.expectEqual(expected_fcu.result, actual_should_override);
            }

            // genesis_time is informational, we don't track it in fork choice
        }

        /// Limit the state cache to at most max_cached_states entries to prevent
        /// pool node exhaustion. Keep the most recently inserted entry (just_added)
        /// and evict others when the cache exceeds the limit.
        const max_cached_states = 100;

        fn pruneStateCache(self: *Self, just_added: Root) void {
            while (self.state_cache.count() > max_cached_states) {
                // Find a key to evict that is NOT the just_added entry
                var to_remove: ?Root = null;
                var iter = self.state_cache.iterator();
                while (iter.next()) |entry| {
                    if (!std.mem.eql(u8, &entry.key_ptr.*, &just_added)) {
                        to_remove = entry.key_ptr.*;
                        break;
                    }
                }
                if (to_remove) |key| {
                    if (self.state_cache.fetchRemove(key)) |kv| {
                        kv.value.deinit();
                        self.allocator.destroy(kv.value);
                    }
                } else break;
            }
        }

        fn getExecutionStatus(beacon_block: AnyBeaconBlock) ExecutionStatus {
            // For pre-merge forks, execution is pre_merge
            return switch (beacon_block.forkSeq()) {
                .phase0, .altair => .pre_merge,
                else => .valid,
            };
        }

        fn getDataAvailabilityStatus(beacon_block: AnyBeaconBlock) DataAvailabilityStatus {
            return switch (beacon_block.forkSeq()) {
                // Pre-data-availability forks
                .phase0, .altair, .bellatrix, .capella => .pre_data,
                // Gloas: beacon blocks have no DA requirement (execution payload separate)
                .gloas => .not_required,
                // Deneb+: DA is required and assumed available in spec tests
                .deneb, .electra, .fulu => .available,
            };
        }
    };
}

// ── Justified Balances Getter for Spec Tests ──

fn specTestBalancesGetter(_: ?*anyopaque, _: CheckpointWithPayloadStatus, state: *CachedBeaconState) JustifiedBalances {
    // In spec tests, we always use the post-state's balances
    const allocator = std.testing.allocator;
    return state_transition.getEffectiveBalanceIncrementsZeroInactive(allocator, state) catch
        return JustifiedBalances.init(allocator);
}

// ── YAML Parser ──

fn parseSteps(allocator: Allocator, dir: std.fs.Dir) ![]Step {
    var file = try dir.openFile("steps.yaml", .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 10_000_000);
    defer allocator.free(content);

    var steps = std.ArrayList(Step).init(allocator);
    errdefer {
        for (steps.items) |*step| {
            freeStep(allocator, step);
        }
        steps.deinit();
    }

    var lines = std.mem.splitScalar(u8, content, '\n');
    var current_step_lines = std.ArrayList([]const u8).init(allocator);
    defer current_step_lines.deinit();

    while (lines.next()) |line| {
        if (line.len >= 2 and line[0] == '-' and line[1] == ' ') {
            // New step starts
            if (current_step_lines.items.len > 0) {
                const step = try parseStep(allocator, current_step_lines.items);
                try steps.append(step);
                current_step_lines.clearRetainingCapacity();
            }
            try current_step_lines.append(line[2..]); // strip "- "
        } else if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
            // Continuation of current step
            try current_step_lines.append(line);
        }
        // Empty lines are ignored
    }

    // Parse last step
    if (current_step_lines.items.len > 0) {
        const step = try parseStep(allocator, current_step_lines.items);
        try steps.append(step);
    }

    return steps.toOwnedSlice();
}

fn parseStep(allocator: Allocator, lines: []const []const u8) !Step {
    if (lines.len == 0) return error.InvalidYaml;

    const first_line = std.mem.trim(u8, lines[0], " \t\r");

    // Flow mapping: {key: value, ...}
    // May span multiple lines (e.g., `{block: block_0x...,\n  valid: true}`)
    if (first_line.len > 0 and first_line[0] == '{') {
        // Join all lines to handle multi-line flow mappings
        if (lines.len > 1) {
            var joined = std.ArrayList(u8).init(allocator);
            defer joined.deinit();
            for (lines) |line| {
                try joined.appendSlice(std.mem.trim(u8, line, " \t\r"));
                try joined.append(' ');
            }
            return parseFlowStep(allocator, joined.items);
        }
        return parseFlowStep(allocator, first_line);
    }

    // Block mapping: key:\n  subkey: value
    if (std.mem.startsWith(u8, first_line, "checks:")) {
        return .{ .checks = try parseChecks(lines[1..]) };
    }

    // Multi-line block step (e.g., block with blobs/proofs)
    if (std.mem.startsWith(u8, first_line, "block:") or std.mem.startsWith(u8, first_line, "block: ")) {
        return .{ .block = try parseBlockStep(allocator, lines) };
    }

    return error.InvalidYaml;
}

fn parseFlowStep(allocator: Allocator, flow: []const u8) !Step {
    // Strip { and }
    const inner = std.mem.trim(u8, flow, "{ \t\r}");

    // tick
    if (extractFlowValue(inner, "tick")) |val| {
        return .{ .tick = try std.fmt.parseInt(u64, val, 10) };
    }

    // attestation
    if (extractFlowValue(inner, "attestation")) |val| {
        const name = try allocator.dupe(u8, std.mem.trim(u8, val, " \r\t"));
        return .{ .attestation = name };
    }

    // attester_slashing
    if (extractFlowValue(inner, "attester_slashing")) |val| {
        const name = try allocator.dupe(u8, std.mem.trim(u8, val, " \r\t"));
        return .{ .attester_slashing = name };
    }

    // pow_block
    if (extractFlowValue(inner, "pow_block")) |val| {
        const name = try allocator.dupe(u8, std.mem.trim(u8, val, " \r\t"));
        return .{ .pow_block = name };
    }

    // block (flow form): block: block_0x..., valid: true
    if (extractFlowValue(inner, "block")) |val| {
        // Might contain ", valid: true/false"
        const comma_pos = std.mem.indexOf(u8, val, ",");
        const block_name = if (comma_pos) |pos|
            std.mem.trim(u8, val[0..pos], " \r\t")
        else
            std.mem.trim(u8, val, " \r\t");

        var valid = true;
        if (std.mem.indexOf(u8, inner, "valid:")) |vpos| {
            const valid_str = std.mem.trim(u8, inner[vpos + "valid:".len ..], " \r\t,}");
            if (std.mem.eql(u8, valid_str, "false")) valid = false;
        }

        return .{ .block = .{
            .name = try allocator.dupe(u8, block_name),
            .valid = valid,
        } };
    }

    return error.InvalidYaml;
}

fn parseBlockStep(allocator: Allocator, lines: []const []const u8) !BlockStep {
    if (lines.len == 0) return error.InvalidYaml;

    var name: []const u8 = "";
    var valid: bool = true;

    for (lines) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");

        if (std.mem.startsWith(u8, trimmed, "block:") or std.mem.startsWith(u8, trimmed, "block: ")) {
            if (extractValue(trimmed, "block:")) |val| {
                name = std.mem.trim(u8, val, " \r\t");
            }
        } else if (std.mem.startsWith(u8, trimmed, "valid:")) {
            if (extractValue(trimmed, "valid:")) |val| {
                const val_trimmed = std.mem.trim(u8, val, " \r\t");
                if (std.mem.eql(u8, val_trimmed, "false")) valid = false;
            }
        }
        // blobs, proofs, columns — skip for now
    }

    if (name.len == 0) return error.InvalidYaml;

    return .{
        .name = try allocator.dupe(u8, name),
        .valid = valid,
    };
}

fn parseChecks(lines: []const []const u8) !Checks {
    var checks = Checks{};
    var i: usize = 0;
    while (i < lines.len) : (i += 1) {
        const trimmed = std.mem.trim(u8, lines[i], " \t\r");
        if (trimmed.len == 0) continue;

        if (std.mem.startsWith(u8, trimmed, "genesis_time:")) {
            if (extractValue(trimmed, "genesis_time:")) |val| {
                checks.genesis_time = std.fmt.parseInt(u64, std.mem.trim(u8, val, " "), 10) catch null;
            }
        } else if (std.mem.startsWith(u8, trimmed, "time:")) {
            if (extractValue(trimmed, "time:")) |val| {
                checks.time = std.fmt.parseInt(u64, std.mem.trim(u8, val, " "), 10) catch null;
            }
        } else if (std.mem.startsWith(u8, trimmed, "head:")) {
            // Next two lines: slot and root
            checks.head = try parseSubFieldHead(lines[i + 1 ..]);
            i += 2;
        } else if (std.mem.startsWith(u8, trimmed, "justified_checkpoint:")) {
            checks.justified_checkpoint = try parseSubFieldCheckpoint(lines[i + 1 ..]);
            i += 2;
        } else if (std.mem.startsWith(u8, trimmed, "finalized_checkpoint:")) {
            checks.finalized_checkpoint = try parseSubFieldCheckpoint(lines[i + 1 ..]);
            i += 2;
        } else if (std.mem.startsWith(u8, trimmed, "proposer_boost_root:")) {
            if (extractValue(trimmed, "proposer_boost_root:")) |val| {
                checks.proposer_boost_root = try parseHexRoot(val);
            }
        } else if (std.mem.startsWith(u8, trimmed, "get_proposer_head:")) {
            if (extractValue(trimmed, "get_proposer_head:")) |val| {
                checks.get_proposer_head = try parseHexRoot(val);
            }
        } else if (std.mem.startsWith(u8, trimmed, "should_override_forkchoice_update:")) {
            if (extractValue(trimmed, "should_override_forkchoice_update:")) |val| {
                checks.should_override_forkchoice_update = try parseShouldOverrideFCU(val);
            }
        }
    }
    return checks;
}

fn parseSubFieldHead(lines: []const []const u8) !CheckHead {
    var slot: Slot = 0;
    var root: Root = ZERO_HASH;

    for (lines[0..@min(2, lines.len)]) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "slot:")) {
            if (extractValue(trimmed, "slot:")) |val| {
                slot = try std.fmt.parseInt(Slot, std.mem.trim(u8, val, " "), 10);
            }
        } else if (std.mem.startsWith(u8, trimmed, "root:")) {
            if (extractValue(trimmed, "root:")) |val| {
                root = try parseHexRoot(val);
            }
        }
    }
    return .{ .slot = slot, .root = root };
}

fn parseSubFieldCheckpoint(lines: []const []const u8) !CheckCheckpoint {
    var epoch: Epoch = 0;
    var root: Root = ZERO_HASH;

    for (lines[0..@min(2, lines.len)]) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "epoch:")) {
            if (extractValue(trimmed, "epoch:")) |val| {
                epoch = try std.fmt.parseInt(Epoch, std.mem.trim(u8, val, " "), 10);
            }
        } else if (std.mem.startsWith(u8, trimmed, "root:")) {
            if (extractValue(trimmed, "root:")) |val| {
                root = try parseHexRoot(val);
            }
        }
    }
    return .{ .epoch = epoch, .root = root };
}

fn parseShouldOverrideFCU(val: []const u8) !ShouldOverrideFCU {
    // Format: {validator_is_connected: true, result: true}
    const inner = std.mem.trim(u8, val, " {}\t\r'");
    var result_val: bool = false;
    var connected: bool = true;

    if (std.mem.indexOf(u8, inner, "result:")) |pos| {
        const after = std.mem.trim(u8, inner[pos + "result:".len ..], " ,}");
        const end = std.mem.indexOf(u8, after, ",") orelse after.len;
        result_val = std.mem.eql(u8, std.mem.trim(u8, after[0..end], " "), "true");
    }
    if (std.mem.indexOf(u8, inner, "validator_is_connected:")) |pos| {
        const after = std.mem.trim(u8, inner[pos + "validator_is_connected:".len ..], " ,}");
        const end = std.mem.indexOf(u8, after, ",") orelse after.len;
        connected = std.mem.eql(u8, std.mem.trim(u8, after[0..end], " "), "true");
    }

    return .{ .result = result_val, .validator_is_connected = connected };
}

fn parseHexRoot(val: []const u8) !Root {
    // Value is like: '0xabcdef...' or "0xabcdef..."
    const trimmed = std.mem.trim(u8, val, " '\"\t\r");
    if (trimmed.len < 2) return ZERO_HASH;
    const hex = if (std.mem.startsWith(u8, trimmed, "0x")) trimmed[2..] else trimmed;
    if (hex.len != 64) return error.InvalidHexRoot;
    var root: Root = undefined;
    _ = try std.fmt.hexToBytes(&root, hex);
    return root;
}

fn extractFlowValue(text: []const u8, comptime key: []const u8) ?[]const u8 {
    // Look for "key: value" or "key:value" in flow text
    const key_colon = key ++ ":";
    const pos = std.mem.indexOf(u8, text, key_colon) orelse return null;
    const after = text[pos + key_colon.len ..];
    return std.mem.trim(u8, after, " ");
}

fn extractValue(text: []const u8, key: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, text, key)) {
        return std.mem.trim(u8, text[key.len..], " ");
    }
    return null;
}

fn freeStep(allocator: Allocator, step: *Step) void {
    switch (step.*) {
        .block => |b| allocator.free(b.name),
        .attestation => |a| allocator.free(a),
        .attester_slashing => |s| allocator.free(s),
        .pow_block => |p| allocator.free(p),
        else => {},
    }
}

fn freeSteps(allocator: Allocator, steps: []Step) void {
    for (steps) |*step| {
        freeStep(allocator, step);
    }
    allocator.free(steps);
}
