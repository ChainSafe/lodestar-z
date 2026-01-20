const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;

const ssz_bytes = @import("ssz_bytes.zig");
const ssz_container = @import("ssz_container.zig");

const BeaconStateTreeViewAllForks = @import("../types/beacon_state_tree_view.zig").BeaconStateTreeViewAllForks;

const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Slot = types.primitive.Slot.Type;

/// Inactivity score is `uint64` (8 bytes).
const INACTIVITY_SCORE_SIZE: usize = 8;

// BeaconState field indices are stable across forks.
// Keep a single source of truth in `state_transition/types/beacon_state_tree_view.zig`.

pub const MigrateStateOutput = struct {
    state: BeaconStateTreeViewAllForks,
    modified_validators: []ValidatorIndex,
};

pub fn loadState(
    allocator: Allocator,
    config: *const BeaconConfig,
    seed_state: *BeaconStateTreeViewAllForks,
    state_bytes: []const u8,
    seed_validators_bytes: ?[]const u8,
) !MigrateStateOutput {
    const fork = try ssz_bytes.getForkFromStateBytes(config, state_bytes);
    const seed_fork = config.forkSeq(try seed_state.slot());
    const pool = seed_state.pool();

    return switch (fork) {
        .phase0 => try loadStateForFork(allocator, pool, .phase0, seed_fork, seed_state, types.phase0.BeaconState, state_bytes, seed_validators_bytes),
        .altair => try loadStateForFork(allocator, pool, .altair, seed_fork, seed_state, types.altair.BeaconState, state_bytes, seed_validators_bytes),
        .bellatrix => try loadStateForFork(allocator, pool, .bellatrix, seed_fork, seed_state, types.bellatrix.BeaconState, state_bytes, seed_validators_bytes),
        .capella => try loadStateForFork(allocator, pool, .capella, seed_fork, seed_state, types.capella.BeaconState, state_bytes, seed_validators_bytes),
        .deneb => try loadStateForFork(allocator, pool, .deneb, seed_fork, seed_state, types.deneb.BeaconState, state_bytes, seed_validators_bytes),
        .electra => try loadStateForFork(allocator, pool, .electra, seed_fork, seed_state, types.electra.BeaconState, state_bytes, seed_validators_bytes),
        .fulu => try loadStateForFork(allocator, pool, .fulu, seed_fork, seed_state, types.fulu.BeaconState, state_bytes, seed_validators_bytes),
    };
}

fn deserializeBeaconStateTreeViewWithSeedOverrides(
    allocator: Allocator,
    pool: *Node.Pool,
    comptime out_fork: ForkSeq,
    seed_fork: ForkSeq,
    seed_state: *BeaconStateTreeViewAllForks,
    comptime StateST: type,
    state_bytes: []const u8,
    ranges: *const [StateST.fields.len][2]usize,
    seed_validators_node: Node.Id,
) !StateST.TreeView {
    if (comptime out_fork.gte(.altair)) {
        const scores_field_index = comptime StateST.getFieldIndex("inactivity_scores");
        const scores_range = ranges[scores_field_index];
        const inactivity_scores_bytes = state_bytes[scores_range[0]..scores_range[1]];
        const ScoresType = comptime StateST.getFieldType("inactivity_scores");

        var scores_node: Node.Id = undefined;
        var owns_scores_node = false;
        if (seed_fork.gte(.altair)) {
            var seed_scores = try seed_state.inactivityScores();
            defer seed_scores.deinit();
            scores_node = seed_scores.base_view.data.root;
        } else {
            owns_scores_node = true;
            scores_node = try ScoresType.tree.deserializeFromBytes(pool, inactivity_scores_bytes);
        }
        errdefer if (owns_scores_node) pool.unref(scores_node);

        return try ssz_container.deserializeContainerOverrideFieldsWithRanges(
            allocator,
            pool,
            StateST,
            state_bytes,
            ranges,
            .{ .validators = seed_validators_node, .inactivity_scores = scores_node },
        );
    }

    return try ssz_container.deserializeContainerOverrideFieldsWithRanges(
        allocator,
        pool,
        StateST,
        state_bytes,
        ranges,
        .{ .validators = seed_validators_node },
    );
}

fn loadStateForFork(
    allocator: Allocator,
    pool: *Node.Pool,
    comptime out_fork: ForkSeq,
    seed_fork: ForkSeq,
    seed_state: *BeaconStateTreeViewAllForks,
    comptime StateST: type,
    state_bytes: []const u8,
    seed_validators_bytes: ?[]const u8,
) !MigrateStateOutput {
    const ranges = try StateST.readFieldRanges(state_bytes);

    const validators_field_index = comptime StateST.getFieldIndex("validators");

    var seed_validators_view = try seed_state.validators();
    defer seed_validators_view.deinit();
    const seed_validators_node = seed_validators_view.base_view.data.root;

    const migrated_view = try deserializeBeaconStateTreeViewWithSeedOverrides(
        allocator,
        pool,
        out_fork,
        seed_fork,
        seed_state,
        StateST,
        state_bytes,
        &ranges,
        seed_validators_node,
    );

    var migrated_state: BeaconStateTreeViewAllForks = BeaconStateTreeViewAllForks.fromTreeView(out_fork, migrated_view);
    errdefer migrated_state.deinit();

    const validators_range = ranges[validators_field_index];
    const new_validators_bytes = state_bytes[validators_range[0]..validators_range[1]];
    const modified_validators = try loadValidators(allocator, &migrated_state, seed_state, new_validators_bytes, seed_validators_bytes);
    errdefer allocator.free(modified_validators);

    if (comptime out_fork.gte(.altair)) {
        if (seed_fork.gte(.altair)) {
            const scores_field_index = comptime StateST.getFieldIndex("inactivity_scores");
            const scores_range = ranges[scores_field_index];
            const inactivity_scores_bytes = state_bytes[scores_range[0]..scores_range[1]];
            try loadInactivityScores(allocator, &migrated_state, seed_state, inactivity_scores_bytes);
        }
    }

    try migrated_state.commit();

    return .{ .state = migrated_state, .modified_validators = modified_validators };
}

fn loadInactivityScores(
    allocator: Allocator,
    migrated_state: *BeaconStateTreeViewAllForks,
    seed_state: *BeaconStateTreeViewAllForks,
    inactivity_scores_bytes: []const u8,
) !void {
    var seed_scores = try seed_state.inactivityScores();
    defer seed_scores.deinit();

    var migrated_scores = try seed_scores.clone(.{});
    errdefer migrated_scores.deinit();

    const old_validator_count = try migrated_scores.length();
    const new_validator_count = inactivity_scores_bytes.len / INACTIVITY_SCORE_SIZE;
    const is_more_validator = new_validator_count >= old_validator_count;
    const min_validator_count = @min(old_validator_count, new_validator_count);

    const old_size = try migrated_scores.serializedSize();
    const old_bytes = try allocator.alloc(u8, old_size);
    defer allocator.free(old_bytes);
    _ = try migrated_scores.serializeIntoBytes(old_bytes);

    var modified_validators = std.ArrayList(ValidatorIndex).init(allocator);
    defer modified_validators.deinit();

    const old_scores_slice = if (is_more_validator)
        old_bytes
    else
        old_bytes[0 .. min_validator_count * INACTIVITY_SCORE_SIZE];
    const new_scores_slice = if (is_more_validator)
        inactivity_scores_bytes[0 .. min_validator_count * INACTIVITY_SCORE_SIZE]
    else
        inactivity_scores_bytes;

    try findModifiedInactivityScores(old_scores_slice, new_scores_slice, &modified_validators, 0);

    for (modified_validators.items) |validator_index| {
        const i: usize = @intCast(validator_index);
        const start = i * INACTIVITY_SCORE_SIZE;
        const chunk: *const [INACTIVITY_SCORE_SIZE]u8 = @ptrCast(inactivity_scores_bytes[start .. start + INACTIVITY_SCORE_SIZE].ptr);
        const value = std.mem.readInt(u64, chunk, .little);
        try migrated_scores.set(i, @intCast(value));
    }

    if (new_validator_count >= old_validator_count) {
        var idx: usize = old_validator_count;
        while (idx < new_validator_count) : (idx += 1) {
            const start = idx * INACTIVITY_SCORE_SIZE;
            const chunk: *const [INACTIVITY_SCORE_SIZE]u8 = @ptrCast(inactivity_scores_bytes[start .. start + INACTIVITY_SCORE_SIZE].ptr);
            const value = std.mem.readInt(u64, chunk, .little);
            try migrated_scores.push(@intCast(value));
        }
    } else {
        if (new_validator_count == 0) {
            const scores_pool = migrated_scores.base_view.pool;
            const empty_scores = blk: {
                const empty_root = try types.altair.InactivityScores.tree.fromValue(
                    scores_pool,
                    &types.altair.InactivityScores.default_value,
                );
                errdefer scores_pool.unref(empty_root);
                break :blk try types.altair.InactivityScores.TreeView.init(allocator, scores_pool, empty_root);
            };
            migrated_scores.deinit();
            migrated_scores = empty_scores;
        } else {
            const trimmed = try migrated_scores.sliceTo(new_validator_count - 1);
            migrated_scores.deinit();
            migrated_scores = trimmed;
        }
    }

    try migrated_state.setInactivityScores(migrated_scores);
}

fn loadValidators(
    allocator: Allocator,
    migrated_state: *BeaconStateTreeViewAllForks,
    seed_state: *BeaconStateTreeViewAllForks,
    new_validators_bytes: []const u8,
    seed_state_validators_bytes: ?[]const u8,
) ![]ValidatorIndex {
    var seed_validators = try seed_state.validators();
    defer seed_validators.deinit();

    const seed_count = try seed_validators.length();
    const new_count = new_validators_bytes.len / ssz_bytes.VALIDATOR_BYTES_SIZE;
    const min_count = @min(seed_count, new_count);

    var migrated_validators = try seed_validators.clone(.{});
    errdefer migrated_validators.deinit();

    const seed_bytes = blk: {
        if (seed_state_validators_bytes) |b| break :blk b;
        const size = try seed_validators.serializedSize();
        const out = try allocator.alloc(u8, size);
        errdefer allocator.free(out);
        _ = try seed_validators.serializeIntoBytes(out);
        break :blk out;
    };
    defer if (seed_state_validators_bytes == null) allocator.free(seed_bytes);

    var modified_validators = std.ArrayList(ValidatorIndex).init(allocator);
    errdefer modified_validators.deinit();

    const old_validators_slice = seed_bytes[0 .. min_count * ssz_bytes.VALIDATOR_BYTES_SIZE];
    const new_validators_slice = new_validators_bytes[0 .. min_count * ssz_bytes.VALIDATOR_BYTES_SIZE];
    try findModifiedValidators(old_validators_slice, new_validators_slice, &modified_validators, 0);

    for (modified_validators.items) |validator_index| {
        const i: usize = @intCast(validator_index);

        const start = i * ssz_bytes.VALIDATOR_BYTES_SIZE;
        const new_bytes = new_validators_bytes[start .. start + ssz_bytes.VALIDATOR_BYTES_SIZE];
        const seed_val_bytes = seed_bytes[start .. start + ssz_bytes.VALIDATOR_BYTES_SIZE];

        var seed_validator = try seed_validators.get(i);
        // seed_validator is borrowed from seed_validators; do not deinit.

        var new_validator = try loadValidatorWithSeedReuse(
            allocator,
            migrated_validators.base_view.pool,
            &seed_validator,
            seed_val_bytes,
            new_bytes,
        );
        errdefer new_validator.deinit();
        try migrated_validators.set(i, new_validator);
    }

    if (new_count >= seed_count) {
        const extra_count = new_count - seed_count;
        try modified_validators.ensureUnusedCapacity(extra_count);

        var idx: usize = seed_count;
        while (idx < new_count) : (idx += 1) {
            const start = idx * ssz_bytes.VALIDATOR_BYTES_SIZE;
            const new_bytes = new_validators_bytes[start .. start + ssz_bytes.VALIDATOR_BYTES_SIZE];

            const pool = migrated_validators.base_view.pool;
            var v: ?types.phase0.Validator.TreeView = blk: {
                const root = try types.phase0.Validator.tree.deserializeFromBytes(pool, new_bytes);
                errdefer pool.unref(root);
                break :blk try types.phase0.Validator.TreeView.init(allocator, pool, root);
            };
            errdefer if (v) |*vv| vv.deinit();

            try migrated_validators.push(v.?);
            v = null;
            modified_validators.appendAssumeCapacity(@intCast(idx));
        }
    } else {
        if (new_count == 0) {
            const v_pool = migrated_validators.base_view.pool;
            const empty_validators = blk: {
                const empty_root = try types.phase0.Validators.tree.fromValue(
                    v_pool,
                    &types.phase0.Validators.default_value,
                );
                errdefer v_pool.unref(empty_root);
                break :blk try types.phase0.Validators.TreeView.init(allocator, v_pool, empty_root);
            };
            migrated_validators.deinit();
            migrated_validators = empty_validators;
        } else {
            const trimmed = try migrated_validators.sliceTo(new_count - 1);
            migrated_validators.deinit();
            migrated_validators = trimmed;
        }
    }

    const out_slice = try modified_validators.toOwnedSlice();
    errdefer allocator.free(out_slice);

    try migrated_state.setValidators(migrated_validators);
    return out_slice;
}

fn loadValidatorWithSeedReuse(
    allocator: Allocator,
    pool: *Node.Pool,
    seed_validator: *types.phase0.Validator.TreeView,
    seed_validator_bytes: []const u8,
    new_validator_bytes: []const u8,
) !types.phase0.Validator.TreeView {
    // Pubkey: [0..48), withdrawal_credentials: [48..80)
    const pubkey_same = std.mem.eql(u8, new_validator_bytes[0..48], seed_validator_bytes[0..48]);
    const withdrawal_same = std.mem.eql(u8, new_validator_bytes[48..80], seed_validator_bytes[48..80]);

    if (!pubkey_same and !withdrawal_same) {
        const root = try types.phase0.Validator.tree.deserializeFromBytes(pool, new_validator_bytes);
        errdefer pool.unref(root);
        return try types.phase0.Validator.TreeView.init(allocator, pool, root);
    }

    var nodes: [types.phase0.Validator.chunk_count]Node.Id = undefined;
    var owned_nodes: [types.phase0.Validator.chunk_count]Node.Id = undefined;
    var owned_len: usize = 0;
    errdefer {
        for (owned_nodes[0..owned_len]) |node_id| {
            pool.unref(node_id);
        }
    }

    inline for (types.phase0.Validator.fields, 0..) |field, i| {
        const start = types.phase0.Validator.field_offsets[i];
        const end = start + field.type.fixed_size;
        const bytes = new_validator_bytes[start..end];

        if (comptime std.mem.eql(u8, field.name, "pubkey")) {
            if (pubkey_same) {
                const gindex = Gindex.fromDepth(types.phase0.Validator.chunk_depth, i);
                nodes[i] = try seed_validator.base_view.getChildNode(gindex);
            } else {
                const node_id = try field.type.tree.deserializeFromBytes(pool, bytes);
                owned_nodes[owned_len] = node_id;
                owned_len += 1;
                nodes[i] = node_id;
            }
        } else if (comptime std.mem.eql(u8, field.name, "withdrawal_credentials")) {
            if (withdrawal_same) {
                const gindex = Gindex.fromDepth(types.phase0.Validator.chunk_depth, i);
                nodes[i] = try seed_validator.base_view.getChildNode(gindex);
            } else {
                const node_id = try field.type.tree.deserializeFromBytes(pool, bytes);
                owned_nodes[owned_len] = node_id;
                owned_len += 1;
                nodes[i] = node_id;
            }
        } else {
            const node_id = try field.type.tree.deserializeFromBytes(pool, bytes);
            owned_nodes[owned_len] = node_id;
            owned_len += 1;
            nodes[i] = node_id;
        }
    }

    const root = try Node.fillWithContents(pool, &nodes, types.phase0.Validator.chunk_depth);
    errdefer pool.unref(root);
    owned_len = 0;
    return try types.phase0.Validator.TreeView.init(allocator, pool, root);
}

fn findModifiedValidators(
    validators_bytes: []const u8,
    validators_bytes2: []const u8,
    modified_validators: *std.ArrayList(ValidatorIndex),
    validator_offset: usize,
) !void {
    if (validators_bytes.len != validators_bytes2.len) return error.InvalidSize;

    if (std.mem.eql(u8, validators_bytes, validators_bytes2)) return;

    if (validators_bytes.len == ssz_bytes.VALIDATOR_BYTES_SIZE) {
        try modified_validators.append(@intCast(validator_offset));
        return;
    }

    const num_validator = validators_bytes.len / ssz_bytes.VALIDATOR_BYTES_SIZE;
    const half_validator = num_validator / 2;
    const split = half_validator * ssz_bytes.VALIDATOR_BYTES_SIZE;

    try findModifiedValidators(
        validators_bytes[0..split],
        validators_bytes2[0..split],
        modified_validators,
        validator_offset,
    );
    try findModifiedValidators(
        validators_bytes[split..],
        validators_bytes2[split..],
        modified_validators,
        validator_offset + half_validator,
    );
}

fn findModifiedInactivityScores(
    inactivity_scores_bytes: []const u8,
    inactivity_scores_bytes2: []const u8,
    modified_validators: *std.ArrayList(ValidatorIndex),
    validator_offset: usize,
) !void {
    if (inactivity_scores_bytes.len != inactivity_scores_bytes2.len) return error.InvalidSize;

    if (std.mem.eql(u8, inactivity_scores_bytes, inactivity_scores_bytes2)) return;

    if (inactivity_scores_bytes.len == INACTIVITY_SCORE_SIZE) {
        try modified_validators.append(@intCast(validator_offset));
        return;
    }

    const num_validator = inactivity_scores_bytes.len / INACTIVITY_SCORE_SIZE;
    const half_validator = num_validator / 2;
    const split = half_validator * INACTIVITY_SCORE_SIZE;

    try findModifiedInactivityScores(
        inactivity_scores_bytes[0..split],
        inactivity_scores_bytes2[0..split],
        modified_validators,
        validator_offset,
    );
    try findModifiedInactivityScores(
        inactivity_scores_bytes[split..],
        inactivity_scores_bytes2[split..],
        modified_validators,
        validator_offset + half_validator,
    );
}

test "loadValidatorWithSeedReuse: reuse vs rebuild" {
    const allocator = std.testing.allocator;

    var pool = try Node.Pool.init(allocator, 1024);
    defer pool.deinit();

    const gen = @import("../test_utils/generate_state.zig");
    const chain_config = gen.getConfig(@import("config").minimal.chain_config, .electra, 0);

    const state_ptr = try gen.generateElectraState(allocator, &pool, chain_config, 64);
    defer {
        state_ptr.deinit();
        allocator.destroy(state_ptr);
    }

    // Build a seed BeaconState TreeView in this pool, then take a validator element as the seed.
    const seed_state_bytes = try state_ptr.serialize(allocator);
    defer allocator.free(seed_state_bytes);

    const seed_root = try types.electra.BeaconState.tree.deserializeFromBytes(&pool, seed_state_bytes);
    errdefer pool.unref(seed_root);
    var seed_state: BeaconStateTreeViewAllForks = .{ .electra = try types.electra.BeaconState.TreeView.init(allocator, &pool, seed_root) };
    defer seed_state.deinit();

    var seed_validators = try seed_state.validators();
    defer seed_validators.deinit();

    const target_index: usize = 3;
    var seed_validator = try seed_validators.get(target_index);
    // seed_validator is borrowed from seed_validators; do not deinit.

    var seed_validator_bytes: [ssz_bytes.VALIDATOR_BYTES_SIZE]u8 = undefined;
    _ = try seed_validator.serializeIntoBytes(&seed_validator_bytes);

    var new_validator_bytes = seed_validator_bytes;
    // Modify only withdrawal_credentials ([48..80))
    @memset(new_validator_bytes[48..80], 0x11);

    var new_validator = try loadValidatorWithSeedReuse(
        allocator,
        &pool,
        &seed_validator,
        seed_validator_bytes[0..],
        new_validator_bytes[0..],
    );
    defer new_validator.deinit();

    const pubkey_i = comptime types.phase0.Validator.getFieldIndex("pubkey");
    const withdrawal_i = comptime types.phase0.Validator.getFieldIndex("withdrawal_credentials");
    const pubkey_g = Gindex.fromDepth(types.phase0.Validator.chunk_depth, pubkey_i);
    const withdrawal_g = Gindex.fromDepth(types.phase0.Validator.chunk_depth, withdrawal_i);

    try std.testing.expectEqual(
        try seed_validator.base_view.getChildNode(pubkey_g),
        try new_validator.base_view.getChildNode(pubkey_g),
    );
    try std.testing.expect(
        try seed_validator.base_view.getChildNode(withdrawal_g) != try new_validator.base_view.getChildNode(withdrawal_g),
    );
}

test "loadState scenarios" {
    const allocator = std.testing.allocator;
    const gen = @import("../test_utils/generate_state.zig");
    const chain_config = gen.getConfig(@import("config").minimal.chain_config, .electra, 0);

    const Mutation = union(enum) {
        none,
        validator_withdrawal_bytes: struct { index: usize, fill: u8 },
        validator_pubkey_and_withdrawal_bytes: struct { index: usize, pub_fill: u8, wd_fill: u8 },
        scores_struct: struct { index: usize, value: u64 },
        append_one_validator_struct: struct { pub_fill: u8 },
        trim_struct: struct { new_len: usize },
    };

    const Case = struct {
        name: []const u8,
        mutation: Mutation,
        expect_modified: []const ValidatorIndex,
        expect_validators_len: usize,
        expect_scores_len: usize,
        expect_score: ?struct { index: usize, value: u64 } = null,
        expect_validator_bytes_match_state_bytes: ?struct { index: usize } = null,
    };

    const expect_none = [_]ValidatorIndex{};
    const expect_one_3 = [_]ValidatorIndex{@intCast(3)};
    const expect_one_5 = [_]ValidatorIndex{@intCast(5)};
    const expect_one_64 = [_]ValidatorIndex{@intCast(64)};

    const cases = [_]Case{
        .{ .name = "no changes", .mutation = .none, .expect_modified = expect_none[0..], .expect_validators_len = 64, .expect_scores_len = 64 },
        .{ .name = "validator withdrawal change (bytes)", .mutation = .{ .validator_withdrawal_bytes = .{ .index = 3, .fill = 0x11 } }, .expect_modified = expect_one_3[0..], .expect_validators_len = 64, .expect_scores_len = 64, .expect_validator_bytes_match_state_bytes = .{ .index = 3 } },
        .{ .name = "validator pubkey+withdrawal change (bytes)", .mutation = .{ .validator_pubkey_and_withdrawal_bytes = .{ .index = 5, .pub_fill = 0x22, .wd_fill = 0x33 } }, .expect_modified = expect_one_5[0..], .expect_validators_len = 64, .expect_scores_len = 64, .expect_validator_bytes_match_state_bytes = .{ .index = 5 } },
        .{ .name = "scores-only change (struct)", .mutation = .{ .scores_struct = .{ .index = 7, .value = 123 } }, .expect_modified = expect_none[0..], .expect_validators_len = 64, .expect_scores_len = 64, .expect_score = .{ .index = 7, .value = 123 } },
        .{ .name = "append one validator (struct)", .mutation = .{ .append_one_validator_struct = .{ .pub_fill = 0x44 } }, .expect_modified = expect_one_64[0..], .expect_validators_len = 65, .expect_scores_len = 65 },
        .{ .name = "trim validators to 63 (struct)", .mutation = .{ .trim_struct = .{ .new_len = 63 } }, .expect_modified = expect_none[0..], .expect_validators_len = 63, .expect_scores_len = 63 },
        .{ .name = "trim validators to 0 (struct)", .mutation = .{ .trim_struct = .{ .new_len = 0 } }, .expect_modified = expect_none[0..], .expect_validators_len = 0, .expect_scores_len = 0 },
    };

    inline for (cases) |case| {
        var pool = try Node.Pool.init(allocator, 8192);
        defer pool.deinit();

        const state_ptr = try gen.generateElectraState(allocator, &pool, chain_config, 64);
        defer {
            state_ptr.deinit();
            allocator.destroy(state_ptr);
        }

        const genesis_root = (try state_ptr.genesisValidatorsRoot()).*;
        const beacon_config = @import("config").BeaconConfig.init(chain_config, genesis_root);

        const seed_bytes = try state_ptr.serialize(allocator);
        defer allocator.free(seed_bytes);

        const seed_root = try types.electra.BeaconState.tree.deserializeFromBytes(&pool, seed_bytes);
        errdefer pool.unref(seed_root);
        var seed_all: BeaconStateTreeViewAllForks = .{ .electra = try types.electra.BeaconState.TreeView.init(allocator, &pool, seed_root) };
        defer seed_all.deinit();

        const mutated_bytes = blk: {
            switch (case.mutation) {
                .none => break :blk seed_bytes,
                .validator_withdrawal_bytes => |m| {
                    const validators_field_index = comptime types.electra.BeaconState.getFieldIndex("validators");
                    const ranges = try types.electra.BeaconState.readFieldRanges(seed_bytes);
                    const validators_range = ranges[validators_field_index];
                    const out = try allocator.dupe(u8, seed_bytes);
                    const base = validators_range[0] + m.index * ssz_bytes.VALIDATOR_BYTES_SIZE;
                    @memset(out[base + 48 .. base + 80], m.fill);
                    break :blk out;
                },
                .validator_pubkey_and_withdrawal_bytes => |m| {
                    const validators_field_index = comptime types.electra.BeaconState.getFieldIndex("validators");
                    const ranges = try types.electra.BeaconState.readFieldRanges(seed_bytes);
                    const validators_range = ranges[validators_field_index];
                    const out = try allocator.dupe(u8, seed_bytes);
                    const base = validators_range[0] + m.index * ssz_bytes.VALIDATOR_BYTES_SIZE;
                    @memset(out[base + 0 .. base + 48], m.pub_fill);
                    @memset(out[base + 48 .. base + 80], m.wd_fill);
                    break :blk out;
                },
                .scores_struct => |m| {
                    var scores = try state_ptr.inactivityScores();
                    try scores.set(m.index, m.value);
                    break :blk try state_ptr.serialize(allocator);
                },
                .append_one_validator_struct => |m| {
                    var validators = try state_ptr.validators();
                    var v: types.phase0.Validator.Type = undefined;
                    try validators.getValue(allocator, 0, &v);
                    v.pubkey = @as(@TypeOf(v.pubkey), [_]u8{m.pub_fill} ** 48);
                    try validators.pushValue(&v);

                    var balances = try state_ptr.balances();
                    try balances.push(try balances.get(0));

                    var scores = try state_ptr.inactivityScores();
                    try scores.push(try scores.get(0));

                    var previous_epoch_participation = try state_ptr.previousEpochParticipation();
                    try previous_epoch_participation.push(try previous_epoch_participation.get(0));

                    var current_epoch_participation = try state_ptr.currentEpochParticipation();
                    try current_epoch_participation.push(try current_epoch_participation.get(0));

                    var eth1_data = try state_ptr.eth1Data();
                    const deposit_count = try eth1_data.get("deposit_count");
                    try eth1_data.set("deposit_count", deposit_count + 1);
                    try state_ptr.setEth1DepositIndex(try state_ptr.eth1DepositIndex() + 1);
                    break :blk try state_ptr.serialize(allocator);
                },
                .trim_struct => |m| {
                    var validators = try state_ptr.validators();
                    try validators.setLength(m.new_len);

                    var balances = try state_ptr.balances();
                    try balances.setLength(m.new_len);

                    var scores = try state_ptr.inactivityScores();
                    try scores.setLength(m.new_len);

                    var previous_epoch_participation = try state_ptr.previousEpochParticipation();
                    try previous_epoch_participation.setLength(m.new_len);

                    var current_epoch_participation = try state_ptr.currentEpochParticipation();
                    try current_epoch_participation.setLength(m.new_len);

                    if (m.new_len == 0) {
                        var eth1_data = try state_ptr.eth1Data();
                        try eth1_data.set("deposit_count", 0);
                        try state_ptr.setEth1DepositIndex(0);
                    }
                    break :blk try state_ptr.serialize(allocator);
                },
            }
        };
        defer if (mutated_bytes.ptr != seed_bytes.ptr) allocator.free(mutated_bytes);

        var out = try loadState(allocator, &beacon_config, &seed_all, mutated_bytes, null);
        defer {
            allocator.free(out.modified_validators);
            var s = out.state;
            s.deinit();
        }

        try std.testing.expectEqual(case.expect_modified.len, out.modified_validators.len);
        for (case.expect_modified, out.modified_validators) |e, got| {
            try std.testing.expectEqual(e, got);
        }

        var migrated_validators = try out.state.validators();
        defer migrated_validators.deinit();
        try std.testing.expectEqual(case.expect_validators_len, try migrated_validators.length());

        var scores = try out.state.inactivityScores();
        defer scores.deinit();
        try std.testing.expectEqual(case.expect_scores_len, try scores.length());

        if (case.expect_score) |exp| {
            try std.testing.expectEqual(exp.value, try scores.get(exp.index));
        }

        if (case.expect_validator_bytes_match_state_bytes) |exp| {
            const validators_field_index = comptime types.electra.BeaconState.getFieldIndex("validators");
            const ranges = try types.electra.BeaconState.readFieldRanges(mutated_bytes);
            const validators_range = ranges[validators_field_index];
            const base = validators_range[0] + exp.index * ssz_bytes.VALIDATOR_BYTES_SIZE;
            var mv = try migrated_validators.get(exp.index);
            // mv is borrowed from migrated_validators; do not deinit.
            var mv_bytes: [ssz_bytes.VALIDATOR_BYTES_SIZE]u8 = undefined;
            _ = try mv.serializeIntoBytes(&mv_bytes);
            try std.testing.expectEqualSlices(u8, mutated_bytes[base .. base + ssz_bytes.VALIDATOR_BYTES_SIZE], mv_bytes[0..]);
        }
    }
}

test "diff helpers cases" {
    const allocator = std.testing.allocator;

    const Kind = enum { validators, scores };
    const Case = struct {
        name: []const u8,
        kind: Kind,
        count: usize,
        modified: []const usize,
    };

    const mod_none = [_]usize{};
    const mod_some_validators = [_]usize{ 0, 1, 63, 64, 127 };
    const mod_some_scores = [_]usize{ 0, 7, 31, 32, 63 };

    const cases = [_]Case{
        .{ .name = "validators: no diff", .kind = .validators, .count = 128, .modified = mod_none[0..] },
        .{ .name = "validators: some diff", .kind = .validators, .count = 128, .modified = mod_some_validators[0..] },
        .{ .name = "scores: no diff", .kind = .scores, .count = 64, .modified = mod_none[0..] },
        .{ .name = "scores: some diff", .kind = .scores, .count = 64, .modified = mod_some_scores[0..] },
    };

    for (cases) |case| {
        var got = std.ArrayList(ValidatorIndex).init(allocator);
        defer got.deinit();

        if (case.kind == .validators) {
            const total = case.count * ssz_bytes.VALIDATOR_BYTES_SIZE;
            const old_bytes = try allocator.alloc(u8, total);
            defer allocator.free(old_bytes);
            const new_bytes = try allocator.alloc(u8, total);
            defer allocator.free(new_bytes);

            for (0..case.count) |i| {
                const start = i * ssz_bytes.VALIDATOR_BYTES_SIZE;
                for (0..ssz_bytes.VALIDATOR_BYTES_SIZE) |j| {
                    old_bytes[start + j] = @intCast((i + 31 * j) & 0xff);
                }
            }
            @memcpy(new_bytes, old_bytes);

            for (case.modified) |idx| {
                const start = idx * ssz_bytes.VALIDATOR_BYTES_SIZE;
                new_bytes[start] ^= 0x5a;
            }

            try findModifiedValidators(old_bytes, new_bytes, &got, 0);
        } else {
            const total = case.count * INACTIVITY_SCORE_SIZE;
            const old_bytes = try allocator.alloc(u8, total);
            defer allocator.free(old_bytes);
            const new_bytes = try allocator.alloc(u8, total);
            defer allocator.free(new_bytes);

            for (0..case.count) |i| {
                const start = i * INACTIVITY_SCORE_SIZE;
                std.mem.writeInt(u64, @ptrCast(old_bytes[start .. start + INACTIVITY_SCORE_SIZE].ptr), @intCast(i * 3), .little);
            }
            @memcpy(new_bytes, old_bytes);

            for (case.modified) |idx| {
                const start = idx * INACTIVITY_SCORE_SIZE;
                new_bytes[start] ^= 0xa5;
            }

            try findModifiedInactivityScores(old_bytes, new_bytes, &got, 0);
        }

        try std.testing.expectEqual(case.modified.len, got.items.len);
        for (case.modified, got.items) |e, g| {
            try std.testing.expectEqual(@as(ValidatorIndex, @intCast(e)), g);
        }
    }
}
