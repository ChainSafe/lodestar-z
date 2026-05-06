const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const ssz = @import("ssz");
const ct = @import("consensus_types");
const ForkSeq = @import("config").ForkSeq;
const BeaconConfig = @import("config").BeaconConfig;
const fork_types = @import("fork_types");
const AnyBeaconState = fork_types.AnyBeaconState;
const ForkTypes = fork_types.ForkTypes;
const readSlotFromAnyBeaconStateBytes = fork_types.readSlotFromAnyBeaconStateBytes;

pub const INACTIVITY_SCORE_SIZE: usize = ct.primitive.Uint64.fixed_size;

const Validator = ct.phase0.Validator;
const Validators = ct.phase0.Validators;
const InactivityScores = ct.altair.InactivityScores;

/// Recursively find validators that differ between two byte regions.
/// Mirrors `loadState/findModifiedValidators.ts`. Pushes absolute validator
/// indices into `modified` when a 121-byte slot differs.
pub fn findModifiedValidators(
    allocator: Allocator,
    a: []const u8,
    b: []const u8,
    modified: *std.ArrayListUnmanaged(usize),
    offset: usize,
) !void {
    assert(a.len == b.len);
    if (std.mem.eql(u8, a, b)) return;
    if (a.len == Validator.fixed_size) {
        try modified.append(allocator, offset);
        return;
    }
    const num = a.len / Validator.fixed_size;
    const half = num / 2;
    const split = half * Validator.fixed_size;
    try findModifiedValidators(allocator, a[0..split], b[0..split], modified, offset);
    try findModifiedValidators(allocator, a[split..], b[split..], modified, offset + half);
}

/// Recursively find inactivity scores that differ between two byte regions.
/// Pushes absolute validator indices for each differing 8-byte slot.
pub fn findModifiedInactivityScores(
    allocator: Allocator,
    a: []const u8,
    b: []const u8,
    modified: *std.ArrayListUnmanaged(usize),
    offset: usize,
) !void {
    assert(a.len == b.len);
    if (std.mem.eql(u8, a, b)) return;
    if (a.len == INACTIVITY_SCORE_SIZE) {
        try modified.append(allocator, offset);
        return;
    }
    const num = a.len / INACTIVITY_SCORE_SIZE;
    const half = num / 2;
    const split = half * INACTIVITY_SCORE_SIZE;
    try findModifiedInactivityScores(allocator, a[0..split], b[0..split], modified, offset);
    try findModifiedInactivityScores(allocator, a[split..], b[split..], modified, offset + half);
}

/// Build a Validator subtree from `new_bytes`, reusing the seed view's pubkey and
/// withdrawal_credentials field nodes when their byte regions match to save memory.
///
/// If it's a new validator, deserialize it.
///
/// Returns a Node.Id with refcount 0 - caller is responsible for wrapping
/// it in a TreeView or attaching it as a parent's child to acquire ownership.
pub fn loadValidator(
    pool: *Node.Pool,
    seed_view: *Validator.TreeView,
    seed_bytes: *const [Validator.fixed_size]u8,
    new_bytes: *const [Validator.fixed_size]u8,
) !Node.Id {
    var nodes: [Validator.chunk_count]Node.Id = undefined;
    inline for (Validator.fields, 0..) |field, i| {
        const start = comptime Validator.field_offsets[i];
        const end = comptime start + field.type.fixed_size;
        const reusable = comptime std.mem.eql(u8, field.name, "pubkey") or
            std.mem.eql(u8, field.name, "withdrawal_credentials");
        if (reusable and std.mem.eql(u8, seed_bytes[start..end], new_bytes[start..end])) {
            nodes[i] = try seed_view.getRootNode(field.name);
        } else {
            nodes[i] = try field.type.tree.deserializeFromBytes(pool, new_bytes[start..end]);
        }
    }
    return try Node.fillWithContents(pool, &nodes, Validator.chunk_depth);
}

/// Tree-reuse-optimized validators load. Clones the seed validators tree, then patches
/// only the differing entries (using `loadValidator` for byte-level pubkey/withdrawal
/// credentials reuse) and append/truncates as needed.
///
/// Returns a fresh, migrated TreeView and pushes modified indices into `modified_out`.
///
/// Caller is responsible for commiting.
pub fn loadValidators(
    allocator: Allocator,
    pool: *Node.Pool,
    seed_view: *Validators.TreeView,
    new_validators_bytes: []const u8,
    seed_validators_bytes_opt: ?[]const u8,
    modified_out: *std.ArrayListUnmanaged(usize),
) !*Validators.TreeView {
    if (new_validators_bytes.len % Validator.fixed_size != 0) return error.InvalidValidatorBytesLength;
    const seed_count = try seed_view.length();
    const new_count = new_validators_bytes.len / Validator.fixed_size;
    const min_count = @min(seed_count, new_count);
    const is_more_validator = new_count >= seed_count;

    // migrated state starts with the same validators to seed state
    var migrated_view: *Validators.TreeView = try seed_view.clone(.{ .transfer_cache = false });
    errdefer migrated_view.deinit();

    // 80% of validators serialization time comes from memory allocation
    // seedStateValidatorsBytes is an optimization at beacon-node side to avoid memory allocation here
    const owned_seed_bytes: ?[]u8 = if (seed_validators_bytes_opt != null) null else blk: {
        const buf = try allocator.alloc(u8, seed_count * Validator.fixed_size);
        errdefer allocator.free(buf);
        _ = try seed_view.serializeIntoBytes(buf);
        break :blk buf;
    };
    defer if (owned_seed_bytes) |b| allocator.free(b);

    const seed_bytes = if (seed_validators_bytes_opt) |sb| blk: {
        if (sb.len != seed_count * Validator.fixed_size) return error.SeedValidatorsBytesLengthMismatch;
        break :blk sb;
    } else owned_seed_bytes.?;

    const a = if (is_more_validator) seed_bytes else seed_bytes[0 .. min_count * Validator.fixed_size];
    const b = if (is_more_validator) new_validators_bytes[0 .. min_count * Validator.fixed_size] else new_validators_bytes;
    try findModifiedValidators(allocator, a, b, modified_out, 0);

    for (modified_out.items) |i| {
        const seed_validator = try seed_view.get(i);
        const seed_validator_bytes = seed_bytes[i * Validator.fixed_size ..][0..Validator.fixed_size];
        const new_validator_bytes = new_validators_bytes[i * Validator.fixed_size ..][0..Validator.fixed_size];
        const node = try loadValidator(pool, seed_validator, seed_validator_bytes, new_validator_bytes);
        const new_view = try Validator.TreeView.init(allocator, pool, node);
        try migrated_view.set(i, new_view);
    }

    if (is_more_validator) {
        // Add new validators,
        for (seed_count..new_count) |i| {
            const new_validator_bytes = new_validators_bytes[i * Validator.fixed_size ..][0..Validator.fixed_size];
            const node = try Validator.tree.deserializeFromBytes(pool, new_validator_bytes);
            const new_view = try Validator.TreeView.init(allocator, pool, node);
            try migrated_view.push(new_view);
            try modified_out.append(allocator, i);
        }
    } else if (new_count < seed_count) {
        const truncated = if (new_count == 0)
            try Validators.TreeView.fromValue(allocator, pool, &Validators.default_value)
        else
            try migrated_view.sliceTo(new_count - 1);
        migrated_view.deinit();
        migrated_view = truncated;
    }

    return migrated_view;
}

/// Tree-reuse-optimized inactivity scores load. Clones the seed scores tree, patches
/// differing entries, and append/truncates as needed.
pub fn loadInactivityScores(
    allocator: Allocator,
    pool: *Node.Pool,
    seed_view: *InactivityScores.TreeView,
    new_bytes: []const u8,
) !*InactivityScores.TreeView {
    if (new_bytes.len % INACTIVITY_SCORE_SIZE != 0) return error.InvalidInactivityScoresBytesLength;
    const seed_count = try seed_view.length();
    const new_count = new_bytes.len / INACTIVITY_SCORE_SIZE;
    const min_count = @min(seed_count, new_count);
    const is_more_validator = new_count >= seed_count;

    var migrated_view: *InactivityScores.TreeView = try seed_view.clone(.{ .transfer_cache = false });
    errdefer migrated_view.deinit();

    const seed_bytes = try allocator.alloc(u8, seed_count * INACTIVITY_SCORE_SIZE);
    defer allocator.free(seed_bytes);
    _ = try seed_view.serializeIntoBytes(seed_bytes);

    var modified: std.ArrayListUnmanaged(usize) = .empty;
    defer modified.deinit(allocator);

    const a = if (is_more_validator) seed_bytes else seed_bytes[0 .. min_count * INACTIVITY_SCORE_SIZE];
    const b = if (is_more_validator) new_bytes[0 .. min_count * INACTIVITY_SCORE_SIZE] else new_bytes;
    try findModifiedInactivityScores(allocator, a, b, &modified, 0);

    for (modified.items) |i| {
        const v = std.mem.readInt(u64, new_bytes[i * INACTIVITY_SCORE_SIZE ..][0..INACTIVITY_SCORE_SIZE], .little);
        try migrated_view.set(i, v);
    }

    if (is_more_validator) {
        for (seed_count..new_count) |i| {
            const v = std.mem.readInt(u64, new_bytes[i * INACTIVITY_SCORE_SIZE ..][0..INACTIVITY_SCORE_SIZE], .little);
            try migrated_view.push(v);
        }
    } else if (new_count < seed_count) {
        const truncated = if (new_count == 0)
            try InactivityScores.TreeView.fromValue(allocator, pool, &InactivityScores.default_value)
        else
            try migrated_view.sliceTo(new_count - 1);
        migrated_view.deinit();
        migrated_view = truncated;
    }

    return migrated_view;
}

/// Partial-deserialize a fork-specific BeaconState from bytes. Skips `validators` and
/// `inactivity_scores` (uses default placeholder nodes for those) — callers replace
/// them with reused/spliced trees afterward.
fn deserializeStateSkipValidatorsAndInactivityScores(
    comptime f: ForkSeq,
    allocator: Allocator,
    pool: *Node.Pool,
    state_bytes: []const u8,
) !*ForkTypes(f).BeaconState.TreeView {
    const ST = ForkTypes(f).BeaconState;
    if (state_bytes.len > ST.max_size or state_bytes.len < ST.min_size) {
        return error.InvalidSize;
    }
    const ranges = try ST.readFieldRanges(state_bytes);

    var nodes: [ST.chunk_count]Node.Id = undefined;
    inline for (ST.fields, 0..) |field, i| {
        const skip = comptime std.mem.eql(u8, field.name, "validators") or
            std.mem.eql(u8, field.name, "inactivity_scores");
        if (skip) {
            nodes[i] = try field.type.tree.default(pool);
        } else {
            const start = ranges[i][0];
            const end = ranges[i][1];
            nodes[i] = try field.type.tree.deserializeFromBytes(pool, state_bytes[start..end]);
        }
    }
    const root = try Node.fillWithContents(pool, &nodes, ST.chunk_depth);
    return try ST.TreeView.init(allocator, pool, root);
}

pub const LoadStateResult = struct {
    state: *AnyBeaconState,
    modified_validators: std.ArrayListUnmanaged(usize),

    pub fn deinit(self: *LoadStateResult, allocator: Allocator) void {
        self.modified_validators.deinit(allocator);
        self.state.deinit();
        allocator.destroy(self.state);
    }
};

/// Load state from bytes given a seed state so that we share the same base tree. This gives some benefits:
///  - Have single base tree across the application
///  - Faster to load state
///  - Less memory usage
///  - Utilize the cached HashObjects in seed state due to a lot of validators are not changed, also the inactivity scores.
///
/// `seed_state` provides the base validators / inactivity_scores trees for reuse.
/// `seed_validators_bytes_opt` is the pre-serialized seed validators (skip serialization
/// when supplied; otherwise serialized internally).
///
/// Caller is responsible for calling deinit on the returned `LoadStateResult`.
pub fn loadState(
    allocator: Allocator,
    pool: *Node.Pool,
    config: *const BeaconConfig,
    seed_state: *AnyBeaconState,
    state_bytes: []const u8,
    seed_validators_bytes_opt: ?[]const u8,
) !LoadStateResult {
    const slot = readSlotFromAnyBeaconStateBytes(state_bytes);
    const new_fork = config.forkSeq(slot);
    const seed_fork = seed_state.forkSeq();

    var modified: std.ArrayListUnmanaged(usize) = .empty;
    errdefer modified.deinit(allocator);

    const any_state = try allocator.create(AnyBeaconState);
    errdefer allocator.destroy(any_state);

    switch (new_fork) {
        inline else => |f| {
            const ST = ForkTypes(f).BeaconState;
            const v_idx = comptime ST.getFieldIndex("validators");
            const ranges = try ST.readFieldRanges(state_bytes);
            const v_range = ranges[v_idx];

            var migrated_inner = try deserializeStateSkipValidatorsAndInactivityScores(f, allocator, pool, state_bytes);
            errdefer migrated_inner.deinit();

            // Validators (always present from phase0)
            {
                const seed_validators = try seed_state.validators();
                var new_validators_view = try loadValidators(
                    allocator,
                    pool,
                    seed_validators,
                    state_bytes[v_range[0]..v_range[1]],
                    seed_validators_bytes_opt,
                    &modified,
                );
                errdefer new_validators_view.deinit();
                try migrated_inner.set("validators", new_validators_view);
            }

            // Inactivity scores (altair+)
            if (comptime f.gte(.altair)) {
                if (seed_fork.gte(.altair)) {
                    const i_idx = comptime ST.getFieldIndex("inactivity_scores");
                    const i_range = ranges[i_idx];

                    const seed_scores = try seed_state.inactivityScores();
                    var new_scores_view = try loadInactivityScores(
                        allocator,
                        pool,
                        seed_scores,
                        state_bytes[i_range[0]..i_range[1]],
                    );
                    errdefer new_scores_view.deinit();
                    try migrated_inner.set("inactivity_scores", new_scores_view);
                }
            }

            try migrated_inner.commit();
            any_state.* = @unionInit(AnyBeaconState, @tagName(f), migrated_inner);
        },
    }

    return .{
        .state = any_state,
        .modified_validators = modified,
    };
}

test findModifiedValidators {
    const allocator = std.testing.allocator;

    var a: [4 * Validator.fixed_size]u8 = undefined;
    var b: [4 * Validator.fixed_size]u8 = undefined;
    var modified: std.ArrayListUnmanaged(usize) = .empty;
    defer modified.deinit(allocator);
    { // no diff returns empty
        defer {
            modified.clearRetainingCapacity();
            a = undefined;
            b = undefined;
        }
        @memset(&a, 0xab);
        @memset(&b, 0xab);

        try findModifiedValidators(allocator, &a, &b, &modified, 0);
        try std.testing.expectEqual(@as(usize, 0), modified.items.len);
    }

    { // one modified slot
        defer {
            modified.clearRetainingCapacity();
            a = undefined;
            b = undefined;
        }
        b[2 * Validator.fixed_size] = 0xff;
        try findModifiedValidators(allocator, &a, &b, &modified, 0);
        try std.testing.expectEqual(@as(usize, 1), modified.items.len);
        try std.testing.expectEqual(@as(usize, 2), modified.items[0]);
    }
}

fn buildSeedValidator(i: usize) Validator.Type {
    return .{
        .pubkey = [_]u8{0xaa} ** 48,
        .withdrawal_credentials = [_]u8{0xbb} ** 32,
        .effective_balance = @as(u64, 32_000_000_000) + i,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = std.math.maxInt(u64),
        .withdrawable_epoch = std.math.maxInt(u64),
    };
}

const LoadValidatorsTest = struct {
    pool: *Node.Pool,
    seed: Validators.Type,
    seed_view: *Validators.TreeView,
    modified: *std.ArrayListUnmanaged(usize),
};

test "loadValidators - parity: modify one validator" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 8192);
    defer pool.deinit();

    var seed_value: Validators.Type = .empty;
    defer seed_value.deinit(allocator);
    for (0..4) |i| try seed_value.append(allocator, buildSeedValidator(i));

    var seed_view = try Validators.TreeView.fromValue(allocator, &pool, &seed_value);
    defer seed_view.deinit();

    var new_value: Validators.Type = .empty;
    defer new_value.deinit(allocator);
    try Validators.clone(allocator, &seed_value, &new_value);
    new_value.items[2].effective_balance = 30_000_000_000;

    const new_size = Validators.serializedSize(&new_value);
    const new_bytes = try allocator.alloc(u8, new_size);
    defer allocator.free(new_bytes);
    _ = Validators.serializeIntoBytes(&new_value, new_bytes);

    var modified: std.ArrayListUnmanaged(usize) = .empty;
    defer modified.deinit(allocator);
    var migrated_view = try loadValidators(allocator, &pool, seed_view, new_bytes, null, &modified);
    defer migrated_view.deinit();

    try std.testing.expectEqual(@as(usize, 1), modified.items.len);
    try std.testing.expectEqual(@as(usize, 2), modified.items[0]);

    var fresh_view = try Validators.TreeView.fromValue(allocator, &pool, &new_value);
    defer fresh_view.deinit();

    var migrated_root: [32]u8 = undefined;
    var fresh_root: [32]u8 = undefined;
    try migrated_view.hashTreeRootInto(&migrated_root);
    try fresh_view.hashTreeRootInto(&fresh_root);
    try std.testing.expectEqualSlices(u8, &fresh_root, &migrated_root);
}

test "loadValidators - parity: add more validators" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 8192);
    defer pool.deinit();

    var seed_value: Validators.Type = .empty;
    defer seed_value.deinit(allocator);
    for (0..3) |i| try seed_value.append(allocator, buildSeedValidator(i));

    var seed_view = try Validators.TreeView.fromValue(allocator, &pool, &seed_value);
    defer seed_view.deinit();

    var new_value: Validators.Type = .empty;
    defer new_value.deinit(allocator);
    try Validators.clone(allocator, &seed_value, &new_value);
    try new_value.append(allocator, buildSeedValidator(3));
    try new_value.append(allocator, buildSeedValidator(4));

    const new_size = Validators.serializedSize(&new_value);
    const new_bytes = try allocator.alloc(u8, new_size);
    defer allocator.free(new_bytes);
    _ = Validators.serializeIntoBytes(&new_value, new_bytes);

    var modified: std.ArrayListUnmanaged(usize) = .empty;
    defer modified.deinit(allocator);
    var migrated_view = try loadValidators(allocator, &pool, seed_view, new_bytes, null, &modified);
    defer migrated_view.deinit();

    try std.testing.expectEqual(@as(usize, 2), modified.items.len);
    try std.testing.expectEqual(@as(usize, 3), modified.items[0]);
    try std.testing.expectEqual(@as(usize, 4), modified.items[1]);

    var fresh_view = try Validators.TreeView.fromValue(allocator, &pool, &new_value);
    defer fresh_view.deinit();

    var migrated_root: [32]u8 = undefined;
    var fresh_root: [32]u8 = undefined;
    try migrated_view.hashTreeRootInto(&migrated_root);
    try fresh_view.hashTreeRootInto(&fresh_root);
    try std.testing.expectEqualSlices(u8, &fresh_root, &migrated_root);
}

test "loadValidators - parity: truncate validators" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 8192);
    defer pool.deinit();

    var seed_value: Validators.Type = .empty;
    defer seed_value.deinit(allocator);
    for (0..4) |i| try seed_value.append(allocator, buildSeedValidator(i));

    var seed_view = try Validators.TreeView.fromValue(allocator, &pool, &seed_value);
    defer seed_view.deinit();

    var new_value: Validators.Type = .empty;
    defer new_value.deinit(allocator);
    try Validators.clone(allocator, &seed_value, &new_value);
    new_value.shrinkRetainingCapacity(2);

    const new_size = Validators.serializedSize(&new_value);
    const new_bytes = try allocator.alloc(u8, new_size);
    defer allocator.free(new_bytes);
    _ = Validators.serializeIntoBytes(&new_value, new_bytes);

    var modified: std.ArrayListUnmanaged(usize) = .empty;
    defer modified.deinit(allocator);
    var migrated_view = try loadValidators(allocator, &pool, seed_view, new_bytes, null, &modified);
    defer migrated_view.deinit();
    try std.testing.expectEqual(@as(usize, 0), modified.items.len);

    var fresh_view = try Validators.TreeView.fromValue(allocator, &pool, &new_value);
    defer fresh_view.deinit();

    var migrated_root: [32]u8 = undefined;
    var fresh_root: [32]u8 = undefined;
    try migrated_view.hashTreeRootInto(&migrated_root);
    try fresh_view.hashTreeRootInto(&fresh_root);
    try std.testing.expectEqualSlices(u8, &fresh_root, &migrated_root);
}

test "loadInactivityScores - parity: modify scores" {
    const allocator = std.testing.allocator;
    var pool = try Node.Pool.init(allocator, 4096);
    defer pool.deinit();

    var seed_value: InactivityScores.Type = .empty;
    defer seed_value.deinit(allocator);
    for (0..8) |_| try seed_value.append(allocator, 0);

    // 1) Generate new seeded view
    var seed_view = try InactivityScores.TreeView.fromValue(allocator, &pool, &seed_value);
    defer seed_view.deinit();

    // 2) clone and alter some values of the new value
    var new_value: InactivityScores.Type = .empty;
    defer new_value.deinit(allocator);
    try InactivityScores.clone(allocator, &seed_value, &new_value);
    new_value.items[3] = 7;
    new_value.items[5] = 9;

    // 3) serialize
    const new_size = InactivityScores.serializedSize(&new_value);
    const new_bytes = try allocator.alloc(u8, new_size);
    defer allocator.free(new_bytes);
    _ = InactivityScores.serializeIntoBytes(&new_value, new_bytes);

    // 4) load scores and ensure migrated view has same root
    var migrated_view = try loadInactivityScores(allocator, &pool, seed_view, new_bytes);
    defer migrated_view.deinit();

    var fresh_view = try InactivityScores.TreeView.fromValue(allocator, &pool, &new_value);
    defer fresh_view.deinit();

    var migrated_root: [32]u8 = undefined;
    var fresh_root: [32]u8 = undefined;
    try migrated_view.hashTreeRootInto(&migrated_root);
    try fresh_view.hashTreeRootInto(&fresh_root);
    try std.testing.expectEqualSlices(u8, &fresh_root, &migrated_root);
}
