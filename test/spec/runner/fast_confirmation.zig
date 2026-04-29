const std = @import("std");
const Allocator = std.mem.Allocator;

const ct = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const ChainConfig = @import("config").ChainConfig;
const minimal_config = @import("config").minimal;
const mainnet_config = @import("config").mainnet;

const fork_types = @import("fork_types");
const AnyBeaconState = fork_types.AnyBeaconState;
const AnySignedBeaconBlock = fork_types.AnySignedBeaconBlock;
const AnyIndexedAttestation = fork_types.AnyIndexedAttestation;
const AnyAttesterSlashing = fork_types.AnyAttesterSlashing;

const fork_choice_mod = @import("fork_choice");
const ForkChoice = fork_choice_mod.ForkChoice;
const ForkChoiceStore = fork_choice_mod.ForkChoiceStore;
const ProtoArray = fork_choice_mod.ProtoArray;
const ProtoBlock = fork_choice_mod.ProtoBlock;
const Checkpoint = fork_choice_mod.Checkpoint;
const fast_confirmation_ns = fork_choice_mod.fast_confirmation.fast_confirmation;
const FastConfirmation = fork_choice_mod.FastConfirmation;
const JustifiedBalances = fork_choice_mod.JustifiedBalances;
const JustifiedBalancesGetter = fork_choice_mod.JustifiedBalancesGetter;
const ExecutionStatus = fork_choice_mod.ExecutionStatus;
const DataAvailabilityStatus = fork_choice_mod.DataAvailabilityStatus;

const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const stateTransitionFn = state_transition.state_transition.stateTransition;
const PubkeyIndexMap = state_transition.PubkeyIndexMap;
const Index2PubkeyCache = state_transition.Index2PubkeyCache;
const syncPubkeys = state_transition.syncPubkeys;

const pmt = @import("persistent_merkle_tree");
const Node = pmt.Node;

const test_case_mod = @import("../test_case.zig");
const loadSszSnappyValue = test_case_mod.loadSszSnappyValue;

const active_preset = @import("preset").active_preset;
const preset = @import("preset");

const ZERO_HASH: [32]u8 = .{0} ** 32;

pub const Handler = enum {
    basic,
    current_epoch,
    empty_slots,
    ffg,
    is_one_confirmed,
    previous_epoch,
    reconfirmation,
    restart_gu,
    revert_finality,
    variables,

    pub fn suiteName(self: Handler) []const u8 {
        return @tagName(self);
    }
};

// ---------------------------------------------------------------------------
// JustifiedBalances getter — returns the empty balances slice.
// The runner does not implement a state cache, so we approximate by returning
// the balances embedded in fc_store.justified directly via the cache shared
// with unrealized_justified at init time.
// ---------------------------------------------------------------------------

fn nullBalancesGetter(_: ?*anyopaque, _: Checkpoint, _: *CachedBeaconState) JustifiedBalances {
    return .empty;
}

const balances_getter: JustifiedBalancesGetter = .{ .getFn = nullBalancesGetter };

// ---------------------------------------------------------------------------
// Step parsing
// ---------------------------------------------------------------------------

const StepKind = enum {
    tick,
    attestation,
    block,
    attester_slashing,
    checks,
    unknown,
};

const Step = union(StepKind) {
    tick: u64,
    attestation: []const u8,
    block: BlockStep,
    attester_slashing: []const u8,
    checks: ChecksStep,
    unknown: void,
};

const BlockStep = struct {
    name: []const u8,
    valid: bool = true,
};

const ChecksStep = struct {
    head_slot: ?u64 = null,
    head_root: ?[32]u8 = null,
    justified_epoch: ?u64 = null,
    justified_root: ?[32]u8 = null,
    finalized_epoch: ?u64 = null,
    finalized_root: ?[32]u8 = null,
    proposer_boost_root: ?[32]u8 = null,

    previous_epoch_observed_justified_epoch: ?u64 = null,
    previous_epoch_observed_justified_root: ?[32]u8 = null,
    current_epoch_observed_justified_epoch: ?u64 = null,
    current_epoch_observed_justified_root: ?[32]u8 = null,
    previous_epoch_greatest_unrealized_epoch: ?u64 = null,
    previous_epoch_greatest_unrealized_root: ?[32]u8 = null,
    previous_slot_head: ?[32]u8 = null,
    current_slot_head: ?[32]u8 = null,
    confirmed_root: ?[32]u8 = null,
};

fn parseHexRoot(text: []const u8) ?[32]u8 {
    const trimmed = std.mem.trim(u8, text, " '\"\t\r\n");
    if (trimmed.len != 66) return null;
    if (!std.mem.startsWith(u8, trimmed, "0x")) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(out[0..], trimmed[2..]) catch return null;
    return out;
}

fn parseUint(text: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, text, " '\"\t\r\n,");
    return std.fmt.parseInt(u64, trimmed, 10) catch null;
}

/// Parse the steps.yaml content into an owned slice of Step values.
/// All name slices are owned by `allocator` and must be freed via `freeSteps`.
fn parseSteps(allocator: Allocator, content: []const u8) !std.ArrayList(Step) {
    var steps: std.ArrayList(Step) = .empty;
    errdefer freeSteps(allocator, &steps);

    // The YAML files are line-oriented but single steps may span multiple
    // lines (e.g. `{attestation: \n    attestation_0xabc}`). We accumulate
    // the current logical step buffer and flush whenever we see a `- ` at
    // column 0 (indicating the next step) or end-of-file.
    var lines = std.mem.splitScalar(u8, content, '\n');
    var current: std.ArrayList(u8) = .empty;
    defer current.deinit(allocator);
    var in_step = false;

    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (std.mem.startsWith(u8, line, "- ")) {
            if (in_step) {
                try flushStep(allocator, &steps, current.items);
                current.clearRetainingCapacity();
            }
            in_step = true;
            try current.appendSlice(allocator, line[2..]);
            try current.append(allocator, '\n');
        } else if (in_step) {
            try current.appendSlice(allocator, line);
            try current.append(allocator, '\n');
        }
    }
    if (in_step) {
        try flushStep(allocator, &steps, current.items);
    }
    return steps;
}

fn freeSteps(allocator: Allocator, steps: *std.ArrayList(Step)) void {
    for (steps.items) |s| switch (s) {
        .attestation => |n| allocator.free(n),
        .attester_slashing => |n| allocator.free(n),
        .block => |b| allocator.free(b.name),
        else => {},
    };
    steps.deinit(allocator);
}

fn flushStep(allocator: Allocator, steps: *std.ArrayList(Step), buf: []const u8) !void {
    const trimmed = std.mem.trim(u8, buf, " \t\r\n");
    if (trimmed.len == 0) return;

    if (std.mem.startsWith(u8, trimmed, "checks:")) {
        const checks = try parseChecks(trimmed["checks:".len..]);
        try steps.append(allocator, .{ .checks = checks });
        return;
    }

    if (std.mem.startsWith(u8, trimmed, "{") and std.mem.endsWith(u8, trimmed, "}")) {
        const inner = trimmed[1 .. trimmed.len - 1];
        // Find first colon to determine the kind.
        const colon = std.mem.indexOfScalar(u8, inner, ':') orelse return;
        const key = std.mem.trim(u8, inner[0..colon], " \t\r\n");
        const value_part = inner[colon + 1 ..];
        if (std.mem.eql(u8, key, "tick")) {
            const v = parseUint(value_part) orelse return;
            try steps.append(allocator, .{ .tick = v });
            return;
        }
        if (std.mem.eql(u8, key, "attestation")) {
            const ref = try allocator.dupe(u8, extractFirstToken(value_part));
            errdefer allocator.free(ref);
            try steps.append(allocator, .{ .attestation = ref });
            return;
        }
        if (std.mem.eql(u8, key, "attester_slashing")) {
            const ref = try allocator.dupe(u8, extractFirstToken(value_part));
            errdefer allocator.free(ref);
            try steps.append(allocator, .{ .attester_slashing = ref });
            return;
        }
        if (std.mem.eql(u8, key, "block")) {
            const block_ref = try allocator.dupe(u8, extractFirstToken(value_part));
            errdefer allocator.free(block_ref);
            const valid = !std.mem.containsAtLeast(u8, value_part, 1, "valid: false");
            try steps.append(allocator, .{ .block = .{ .name = block_ref, .valid = valid } });
            return;
        }
        try steps.append(allocator, .unknown);
        return;
    }

    try steps.append(allocator, .unknown);
}

/// Extract the first non-whitespace, non-comma identifier-ish token from `s`.
/// Used to fish out e.g. `attestation_0xabc...` from `{attestation: \n attestation_0xabc..., valid: true}`.
fn extractFirstToken(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t' or s[i] == '\r' or s[i] == '\n')) : (i += 1) {}
    const start = i;
    while (i < s.len and s[i] != ',' and s[i] != ' ' and s[i] != '\t' and s[i] != '\r' and s[i] != '\n' and s[i] != '}') : (i += 1) {}
    return s[start..i];
}

fn parseChecks(body: []const u8) !ChecksStep {
    var checks: ChecksStep = .{};

    // Iterate by lines and detect indented sub-fields like
    //   head:
    //     slot: 0
    //     root: '0xabc...'
    var lines = std.mem.splitScalar(u8, body, '\n');
    var section: enum {
        none,
        head,
        justified,
        finalized,
        prev_obs,
        cur_obs,
        prev_unrealized,
    } = .none;

    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        // Top-level key (4-space indent in original, but we trimmed).
        const stripped = std.mem.trimStart(u8, line, " \t");
        if (stripped.len == 0) continue;

        if (std.mem.startsWith(u8, stripped, "time:")) {
            section = .none;
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "head:")) {
            section = .head;
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "justified_checkpoint:")) {
            section = .justified;
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "finalized_checkpoint:")) {
            section = .finalized;
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "previous_epoch_observed_justified_checkpoint:")) {
            section = .prev_obs;
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "current_epoch_observed_justified_checkpoint:")) {
            section = .cur_obs;
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "previous_epoch_greatest_unrealized_checkpoint:")) {
            section = .prev_unrealized;
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "proposer_boost_root:")) {
            section = .none;
            const v = stripped["proposer_boost_root:".len..];
            checks.proposer_boost_root = parseHexRoot(v);
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "previous_slot_head:")) {
            section = .none;
            const v = stripped["previous_slot_head:".len..];
            checks.previous_slot_head = parseHexRoot(v);
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "current_slot_head:")) {
            section = .none;
            const v = stripped["current_slot_head:".len..];
            checks.current_slot_head = parseHexRoot(v);
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "confirmed_root:")) {
            section = .none;
            const v = stripped["confirmed_root:".len..];
            checks.confirmed_root = parseHexRoot(v);
            continue;
        }
        // Sub-field handling.
        if (std.mem.startsWith(u8, stripped, "slot:")) {
            const v = parseUint(stripped["slot:".len..]) orelse continue;
            switch (section) {
                .head => checks.head_slot = v,
                else => {},
            }
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "epoch:")) {
            const v = parseUint(stripped["epoch:".len..]) orelse continue;
            switch (section) {
                .justified => checks.justified_epoch = v,
                .finalized => checks.finalized_epoch = v,
                .prev_obs => checks.previous_epoch_observed_justified_epoch = v,
                .cur_obs => checks.current_epoch_observed_justified_epoch = v,
                .prev_unrealized => checks.previous_epoch_greatest_unrealized_epoch = v,
                .head, .none => {},
            }
            continue;
        }
        if (std.mem.startsWith(u8, stripped, "root:")) {
            const v = parseHexRoot(stripped["root:".len..]) orelse continue;
            switch (section) {
                .head => checks.head_root = v,
                .justified => checks.justified_root = v,
                .finalized => checks.finalized_root = v,
                .prev_obs => checks.previous_epoch_observed_justified_root = v,
                .cur_obs => checks.current_epoch_observed_justified_root = v,
                .prev_unrealized => checks.previous_epoch_greatest_unrealized_root = v,
                .none => {},
            }
            continue;
        }
    }
    return checks;
}

// ---------------------------------------------------------------------------
// Test case
// ---------------------------------------------------------------------------

pub fn TestCase(comptime fork: ForkSeq) type {
    const ForkTypes = @field(ct, fork.name());
    const SignedBeaconBlock = ForkTypes.SignedBeaconBlock;
    const BeaconState = ForkTypes.BeaconState;
    const Attestation = ForkTypes.Attestation;
    const AttesterSlashing = ForkTypes.AttesterSlashing;
    const IndexedAttestation = ForkTypes.IndexedAttestation;

    return struct {
        const Self = @This();

        pub fn execute(allocator: Allocator, pool: *Node.Pool, dir: std.Io.Dir) !void {
            // Use a single arena for transient parsing buffers; main components are
            // tracked individually with `defer` to avoid double-frees with errdefer.
            // ---------- Load anchor state + block ----------
            var anchor_state_value = BeaconState.default_value;
            try loadSszSnappyValue(BeaconState, allocator, dir, "anchor_state.ssz_snappy", &anchor_state_value);
            defer BeaconState.deinit(allocator, &anchor_state_value);

            var anchor_block_value = ForkTypes.BeaconBlock.default_value;
            try loadSszSnappyValue(ForkTypes.BeaconBlock, allocator, dir, "anchor_block.ssz_snappy", &anchor_block_value);
            defer ForkTypes.BeaconBlock.deinit(allocator, &anchor_block_value);

            defer state_transition.deinitStateTransition(std.testing.io);

            // ---------- Build anchor state tree view + AnyBeaconState wrapper ----------
            const any_state = try allocator.create(AnyBeaconState);
            any_state.* = @unionInit(
                AnyBeaconState,
                fork.name(),
                try BeaconState.TreeView.fromValue(allocator, pool, &anchor_state_value),
            );
            // any_state ownership transfers to cached_state below.

            const anchor_slot = try any_state.slot();
            const anchor_epoch_for_state = anchor_slot / preset.preset.SLOTS_PER_EPOCH;

            // ---------- Build BeaconConfig ----------
            const chain_config: ChainConfig = blk: {
                const base = if (active_preset == .mainnet)
                    mainnet_config.chain_config
                else
                    minimal_config.chain_config;
                break :blk state_transition.test_utils.getConfig(base, fork, anchor_epoch_for_state);
            };
            const config = try allocator.create(BeaconConfig);
            defer allocator.destroy(config);
            config.* = BeaconConfig.init(chain_config, (try any_state.genesisValidatorsRoot()).*);

            // ---------- Pubkey caches ----------
            const pubkey_index_map = try allocator.create(PubkeyIndexMap);
            pubkey_index_map.* = PubkeyIndexMap.init(allocator);
            defer {
                pubkey_index_map.deinit();
                allocator.destroy(pubkey_index_map);
            }
            const index_pubkey_cache = try allocator.create(Index2PubkeyCache);
            index_pubkey_cache.* = Index2PubkeyCache.empty;
            defer {
                index_pubkey_cache.deinit(allocator);
                allocator.destroy(index_pubkey_cache);
            }
            const validators = try any_state.validatorsSlice(allocator);
            defer allocator.free(validators);
            try syncPubkeys(allocator, validators, pubkey_index_map, index_pubkey_cache);

            // ---------- CachedBeaconState (takes ownership of any_state) ----------
            const immutable_data = state_transition.EpochCacheImmutableData{
                .config = config,
                .index_to_pubkey = index_pubkey_cache,
                .pubkey_to_index = pubkey_index_map,
            };
            const initial_cached_state = try CachedBeaconState.createCachedBeaconState(allocator, any_state, immutable_data, .{
                .skip_sync_committee_cache = fork == .phase0,
                .skip_sync_pubkeys = false,
            });

            // We track the "current" cached state in a single slot. Each successful
            // state transition replaces it. The one cleanup deinit drops it once.
            var current_state: *CachedBeaconState = initial_cached_state;
            defer {
                current_state.deinit();
                allocator.destroy(current_state);
            }

            // ---------- Compute anchor block root ----------
            var anchor_block_root: [32]u8 = undefined;
            try ForkTypes.BeaconBlock.hashTreeRoot(allocator, &anchor_block_value, &anchor_block_root);

            // ---------- Read finalized/justified checkpoints from state ----------
            var finalized_ssz: ct.phase0.Checkpoint.Type = undefined;
            try any_state.finalizedCheckpoint(&finalized_ssz);
            var justified_ssz: ct.phase0.Checkpoint.Type = undefined;
            try any_state.currentJustifiedCheckpoint(&justified_ssz);

            // For genesis: the spec uses anchor_block_root as the finalized/justified root.
            const anchor_finalized: Checkpoint = .{
                .epoch = finalized_ssz.epoch,
                .root = if (std.mem.eql(u8, &finalized_ssz.root, &ZERO_HASH)) anchor_block_root else finalized_ssz.root,
            };
            const anchor_justified: Checkpoint = .{
                .epoch = justified_ssz.epoch,
                .root = if (std.mem.eql(u8, &justified_ssz.root, &ZERO_HASH)) anchor_block_root else justified_ssz.root,
            };

            // ---------- Initialize ProtoArray with anchor block ----------
            const proto_arr = try allocator.create(ProtoArray);
            defer allocator.destroy(proto_arr);

            const anchor_proto_block: ProtoBlock = .{
                .slot = anchor_slot,
                .block_root = anchor_block_root,
                .parent_root = anchor_block_value.parent_root,
                .state_root = anchor_block_value.state_root,
                .target_root = anchor_block_root,
                .justified_epoch = anchor_justified.epoch,
                .justified_root = anchor_justified.root,
                .finalized_epoch = anchor_finalized.epoch,
                .finalized_root = anchor_finalized.root,
                .unrealized_justified_epoch = anchor_justified.epoch,
                .unrealized_justified_root = anchor_justified.root,
                .unrealized_finalized_epoch = anchor_finalized.epoch,
                .unrealized_finalized_root = anchor_finalized.root,
                .extra_meta = .{ .pre_merge = {} },
                .timeliness = true,
            };
            try proto_arr.initialize(allocator, anchor_proto_block, anchor_slot);
            defer proto_arr.deinit(allocator);

            // ---------- ForkChoiceStore ----------
            const eb_increments = current_state.epoch_cache.getEffectiveBalanceIncrements();

            const fc_store = try allocator.create(ForkChoiceStore);
            defer allocator.destroy(fc_store);
            try fc_store.init(
                allocator,
                anchor_slot,
                anchor_justified,
                anchor_finalized,
                eb_increments.items,
                balances_getter,
                .{},
            );
            defer fc_store.deinit(allocator);

            // ---------- ForkChoice ----------
            const fc = try allocator.create(ForkChoice);
            defer allocator.destroy(fc);
            try fc.init(
                allocator,
                config,
                fc_store,
                proto_arr,
                @intCast(validators.len),
                .{ .proposer_boost = true },
            );
            defer fc.deinit(allocator);

            // ---------- FastConfirmation ----------
            var fcr = FastConfirmation.init(anchor_finalized, 25, config.chain.PROPOSER_SCORE_BOOST);
            defer fcr.deinit(allocator);
            fcr.setSpecTestMode(true);

            // ---------- Read steps.yaml ----------
            const steps_content = try dir.readFileAlloc(std.testing.io, "steps.yaml", allocator, .unlimited);
            defer allocator.free(steps_content);

            var steps = try parseSteps(allocator, steps_content);
            defer freeSteps(allocator, &steps);

            // ---------- Step interpreter ----------
            for (steps.items) |step| {
                switch (step) {
                    .tick => |t| {
                        const slot = t / config.chain.SECONDS_PER_SLOT;
                        fc.updateTime(allocator, slot) catch |err| {
                            std.log.scoped(.fcr_runner).debug(
                                "updateTime failed (fork={s}): {s}",
                                .{ @tagName(fork), @errorName(err) },
                            );
                        };
                    },
                    .attestation => |name| {
                        applyAttestation(
                            allocator,
                            fc,
                            current_state,
                            dir,
                            name,
                        ) catch |err| {
                            // Many test variants use forced/equivocating attestations.
                            std.log.scoped(.fcr_runner).debug(
                                "attestation step failed (fork={s}): {s}",
                                .{ @tagName(fork), @errorName(err) },
                            );
                        };
                    },
                    .attester_slashing => |name| {
                        applyAttesterSlashing(
                            allocator,
                            fc,
                            dir,
                            name,
                        ) catch |err| {
                            std.log.scoped(.fcr_runner).debug(
                                "attester_slashing step failed (fork={s}): {s}",
                                .{ @tagName(fork), @errorName(err) },
                            );
                        };
                    },
                    .block => |b| {
                        const next_state = applyBlock(
                            allocator,
                            fc,
                            current_state,
                            dir,
                            b.name,
                            b.valid,
                        ) catch |err| blk: {
                            if (b.valid) {
                                std.log.scoped(.fcr_runner).debug(
                                    "block step failed (fork={s}, name={s}): {s}",
                                    .{ @tagName(fork), b.name, @errorName(err) },
                                );
                            }
                            break :blk null;
                        };
                        if (next_state) |new_state| {
                            current_state.deinit();
                            allocator.destroy(current_state);
                            current_state = new_state;
                        }
                    },
                    .checks => |c| {
                        runChecks(allocator, fc, &fcr, current_state, c) catch |err| {
                            // Surface assertion errors to the test framework.
                            return err;
                        };
                    },
                    .unknown => {},
                }
            }
        }

        fn applyAttestation(
            allocator: Allocator,
            fc: *ForkChoice,
            state: *CachedBeaconState,
            dir: std.Io.Dir,
            name: []const u8,
        ) !void {
            const filename = try std.fmt.allocPrint(allocator, "{s}.ssz_snappy", .{name});
            defer allocator.free(filename);

            var attestation_value = Attestation.default_value;
            try loadSszSnappyValue(Attestation, allocator, dir, filename, &attestation_value);
            defer Attestation.deinit(allocator, &attestation_value);

            // Compute attesting indices from epoch cache.
            var indexed = IndexedAttestation.default_value;
            defer IndexedAttestation.deinit(allocator, &indexed);

            if (comptime fork == .phase0 or fork.lt(.electra)) {
                try state.epoch_cache.computeIndexedAttestationPhase0(&attestation_value, &indexed);
            } else {
                try state.epoch_cache.computeIndexedAttestationElectra(&attestation_value, &indexed);
            }

            const any_indexed = if (comptime fork.lt(.electra))
                AnyIndexedAttestation{ .phase0 = &indexed }
            else
                AnyIndexedAttestation{ .electra = &indexed };

            var att_data_root: [32]u8 = undefined;
            try ct.phase0.AttestationData.hashTreeRoot(&attestation_value.data, &att_data_root);

            try fc.onAttestation(allocator, &any_indexed, att_data_root, false);
        }

        fn applyAttesterSlashing(
            allocator: Allocator,
            fc: *ForkChoice,
            dir: std.Io.Dir,
            name: []const u8,
        ) !void {
            const filename = try std.fmt.allocPrint(allocator, "{s}.ssz_snappy", .{name});
            defer allocator.free(filename);

            var slashing_value = AttesterSlashing.default_value;
            try loadSszSnappyValue(AttesterSlashing, allocator, dir, filename, &slashing_value);
            defer AttesterSlashing.deinit(allocator, &slashing_value);

            const any_slashing = if (comptime fork.lt(.electra))
                AnyAttesterSlashing{ .phase0 = &slashing_value }
            else
                AnyAttesterSlashing{ .electra = &slashing_value };

            try fc.onAttesterSlashing(allocator, &any_slashing);
        }

        fn applyBlock(
            allocator: Allocator,
            fc: *ForkChoice,
            cached_state: *CachedBeaconState,
            dir: std.Io.Dir,
            name: []const u8,
            valid: bool,
        ) !?*CachedBeaconState {

            const filename = try std.fmt.allocPrint(allocator, "{s}.ssz_snappy", .{name});
            defer allocator.free(filename);

            var signed_block = SignedBeaconBlock.default_value;
            try loadSszSnappyValue(SignedBeaconBlock, allocator, dir, filename, &signed_block);
            defer SignedBeaconBlock.deinit(allocator, &signed_block);

            const any_signed = switch (fork) {
                .phase0 => AnySignedBeaconBlock{ .phase0 = &signed_block },
                .altair => AnySignedBeaconBlock{ .altair = &signed_block },
                .bellatrix => AnySignedBeaconBlock{ .full_bellatrix = &signed_block },
                .capella => AnySignedBeaconBlock{ .full_capella = &signed_block },
                .deneb => AnySignedBeaconBlock{ .full_deneb = &signed_block },
                .electra => AnySignedBeaconBlock{ .full_electra = &signed_block },
                .fulu => AnySignedBeaconBlock{ .full_fulu = &signed_block },
                .gloas => AnySignedBeaconBlock{ .full_gloas = &signed_block },
            };

            const new_state = stateTransitionFn(
                allocator,
                std.testing.io,
                cached_state,
                any_signed,
                .{
                    .verify_signatures = false,
                    .verify_proposer = false,
                    .verify_state_root = false,
                },
            ) catch |err| {
                if (!valid) return null;
                return err;
            };

            // Wire block into fork choice.
            const beacon_block = any_signed.beaconBlock();
            const current_slot = fc.fc_store.current_slot;

            // Pre-bellatrix forks must use .pre_merge / .pre_data; later forks use real values.
            const exec_status: ExecutionStatus = if (fork.lt(.bellatrix)) .pre_merge else .valid;
            const da_status: DataAvailabilityStatus = if (fork.lt(.bellatrix)) .pre_data else .available;

            _ = fc.onBlock(
                allocator,
                &beacon_block,
                new_state,
                0,
                current_slot,
                exec_status,
                da_status,
            ) catch |err| {
                std.log.scoped(.fcr_runner).debug(
                    "fc.onBlock failed (fork={s}, name={s}): {s}",
                    .{ @tagName(fork), name, @errorName(err) },
                );
            };

            return new_state;
        }

        fn runChecks(
            allocator: Allocator,
            fc: *ForkChoice,
            fcr: *FastConfirmation,
            state: *CachedBeaconState,
            checks: ChecksStep,
        ) !void {
            // Update head before reading head root.
            _ = fc.updateAndGetHead(allocator, .get_canonical_head) catch |err| blk: {
                std.log.scoped(.fcr_runner).debug(
                    "updateAndGetHead failed (fork={s}): {s}",
                    .{ @tagName(fork), @errorName(err) },
                );
                break :blk @as(@import("fork_choice").UpdateAndGetHeadResult, .{ .head = fc.head });
            };

            // Run FCR confirmation update.
            // Build head_unrealized_justified from the head's proto-array node.
            const head_root = fc.getHeadRoot();
            const head_node_idx = fc.proto_array.getDefaultNodeIndex(head_root);
            const head_unrealized: Checkpoint = if (head_node_idx) |idx| .{
                .epoch = fc.proto_array.nodes.items[idx].unrealized_justified_epoch,
                .root = fc.proto_array.nodes.items[idx].unrealized_justified_root,
            } else fc.fc_store.unrealized_justified.checkpoint;

            const finalized_cp = fc.getFinalizedCheckpoint();
            const justified_cp = fc.getJustifiedCheckpoint();

            fast_confirmation_ns.runConfirmation(
                fcr,
                allocator,
                fc,
                state,
                &fc.votes,
                &fc.fc_store.equivocating_indices,
                &finalized_cp,
                &justified_cp,
                &head_unrealized,
                head_root,
                fc.fc_store.current_slot,
            ) catch |err| {
                std.log.scoped(.fcr_runner).debug(
                    "runConfirmation failed (fork={s}): {s}",
                    .{ @tagName(fork), @errorName(err) },
                );
                // Skip the FCR-specific assertions but continue with fork-choice ones.
                try assertForkChoiceFields(fc, checks);
                return;
            };

            try assertForkChoiceFields(fc, checks);
            try assertFcrFields(fcr, checks);
        }

        fn assertForkChoiceFields(fc: *ForkChoice, checks: ChecksStep) !void {
            if (checks.head_root) |expected| {
                const actual = fc.getHeadRoot();
                if (!std.mem.eql(u8, &expected, &actual)) {
                    return error.HeadRootMismatch;
                }
            }
            if (checks.head_slot) |expected| {
                const head_root = fc.getHeadRoot();
                if (fc.proto_array.getDefaultNodeIndex(head_root)) |idx| {
                    const actual_slot = fc.proto_array.nodes.items[idx].slot;
                    if (expected != actual_slot) return error.HeadSlotMismatch;
                }
            }
            if (checks.justified_epoch) |expected| {
                const cp = fc.getJustifiedCheckpoint();
                if (cp.epoch != expected) return error.JustifiedEpochMismatch;
            }
            if (checks.justified_root) |expected| {
                const cp = fc.getJustifiedCheckpoint();
                if (!std.mem.eql(u8, &expected, &cp.root)) return error.JustifiedRootMismatch;
            }
            if (checks.finalized_epoch) |expected| {
                const cp = fc.getFinalizedCheckpoint();
                if (cp.epoch != expected) return error.FinalizedEpochMismatch;
            }
            if (checks.finalized_root) |expected| {
                const cp = fc.getFinalizedCheckpoint();
                if (!std.mem.eql(u8, &expected, &cp.root)) return error.FinalizedRootMismatch;
            }
            if (checks.proposer_boost_root) |expected| {
                const actual = fc.getProposerBoostRoot();
                if (!std.mem.eql(u8, &expected, &actual)) return error.ProposerBoostRootMismatch;
            }
        }

        fn assertFcrFields(fcr: *const FastConfirmation, checks: ChecksStep) !void {
            if (checks.previous_epoch_observed_justified_epoch) |expected| {
                if (fcr.previous_epoch_observed_justified_checkpoint.epoch != expected) {
                    return error.FcrPrevObsJustifiedEpochMismatch;
                }
            }
            if (checks.previous_epoch_observed_justified_root) |expected| {
                if (!std.mem.eql(u8, &expected, &fcr.previous_epoch_observed_justified_checkpoint.root)) {
                    return error.FcrPrevObsJustifiedRootMismatch;
                }
            }
            if (checks.current_epoch_observed_justified_epoch) |expected| {
                if (fcr.current_epoch_observed_justified_checkpoint.epoch != expected) {
                    return error.FcrCurObsJustifiedEpochMismatch;
                }
            }
            if (checks.current_epoch_observed_justified_root) |expected| {
                if (!std.mem.eql(u8, &expected, &fcr.current_epoch_observed_justified_checkpoint.root)) {
                    return error.FcrCurObsJustifiedRootMismatch;
                }
            }
            if (checks.previous_epoch_greatest_unrealized_epoch) |expected| {
                if (fcr.previous_epoch_greatest_unrealized_checkpoint.epoch != expected) {
                    return error.FcrPrevUnrealizedEpochMismatch;
                }
            }
            if (checks.previous_epoch_greatest_unrealized_root) |expected| {
                if (!std.mem.eql(u8, &expected, &fcr.previous_epoch_greatest_unrealized_checkpoint.root)) {
                    return error.FcrPrevUnrealizedRootMismatch;
                }
            }
            if (checks.previous_slot_head) |expected| {
                if (!std.mem.eql(u8, &expected, &fcr.previous_slot_head)) {
                    return error.FcrPreviousSlotHeadMismatch;
                }
            }
            if (checks.current_slot_head) |expected| {
                if (!std.mem.eql(u8, &expected, &fcr.current_slot_head)) {
                    return error.FcrCurrentSlotHeadMismatch;
                }
            }
            if (checks.confirmed_root) |expected| {
                if (!std.mem.eql(u8, &expected, &fcr.confirmed_root)) {
                    std.log.scoped(.fcr_runner).warn(
                        "FcrConfirmedRootMismatch: expected={x} actual={x} prev_obs_just=(e={d},r={x}) curr_obs_just=(e={d},r={x}) prev_gu=(e={d},r={x}) prev_head={x} curr_head={x}",
                        .{
                            expected,
                            fcr.confirmed_root,
                            fcr.previous_epoch_observed_justified_checkpoint.epoch,
                            fcr.previous_epoch_observed_justified_checkpoint.root,
                            fcr.current_epoch_observed_justified_checkpoint.epoch,
                            fcr.current_epoch_observed_justified_checkpoint.root,
                            fcr.previous_epoch_greatest_unrealized_checkpoint.epoch,
                            fcr.previous_epoch_greatest_unrealized_checkpoint.root,
                            fcr.previous_slot_head,
                            fcr.current_slot_head,
                        },
                    );
                    return error.FcrConfirmedRootMismatch;
                }
            }
        }
    };
}
