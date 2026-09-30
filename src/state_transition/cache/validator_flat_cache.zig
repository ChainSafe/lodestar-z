//! Flat, index-addressed copy of the validator fields the epoch transition reads.validator_flat_cac
//!
//! The cache is derived from the validators tree and should never be written directly.
//! Use `sync` to do that. `sync` diffs the tree it was last synced to against
//! the target tree and patches only the leaves whose node id differs,
//! so the cost is proportional to the number of changed validators.
//!
//! Owner decides the lifetime and must `deinit` it before the pool it
//! serves is torn down, because of the ref it holds.

const std = @import("std");
const Allocator = std.mem.Allocator;
const BoundedArray = @import("bounded_array").BoundedArray;
const types = @import("consensus_types");
const preset = @import("preset").preset;
const Node = @import("persistent_merkle_tree").Node;
const max_depth = @import("persistent_merkle_tree").max_depth;
const hasCompoundingWithdrawalCredential = @import("../utils/electra.zig").hasCompoundingWithdrawalCredential;

const Validator = types.phase0.Validator;

const flag_slashed: u8 = 1;
const flag_compounding: u8 = 2;

/// Fields that EpochTransitionCache.init needs to know about one validator.
pub const ValidatorFields = struct {
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
    effective_balance: u64,
    slashed: bool,
    compounding: bool,

    pub inline fn fromValidator(v: *const Validator.Type) ValidatorFields {
        return .{
            .activation_eligibility_epoch = v.activation_eligibility_epoch,
            .activation_epoch = v.activation_epoch,
            .exit_epoch = v.exit_epoch,
            .withdrawable_epoch = v.withdrawable_epoch,
            .effective_balance = v.effective_balance,
            .slashed = v.slashed,
            .compounding = hasCompoundingWithdrawalCredential(&v.withdrawal_credentials),
        };
    }
};

pub const ValidatorFlatCache = struct {
    allocator: Allocator,
    pool: *Node.Pool,
    synced_root: ?Node.Id = null,
    activation_eligibility_epoch: std.ArrayList(u64) = .empty,
    activation_epoch: std.ArrayList(u64) = .empty,
    exit_epoch: std.ArrayList(u64) = .empty,
    withdrawable_epoch: std.ArrayList(u64) = .empty,
    effective_balance_increments: std.ArrayList(u16) = .empty,
    flags: std.ArrayList(u8) = .empty,
    /// Leaves rewritten by the last `sync`.
    last_patched: usize = 0,

    pub fn init(allocator: Allocator, pool: *Node.Pool) ValidatorFlatCache {
        return .{ .allocator = allocator, .pool = pool };
    }

    pub fn deinit(self: *ValidatorFlatCache) void {
        self.invalidate();
        self.activation_eligibility_epoch.deinit(self.allocator);
        self.activation_epoch.deinit(self.allocator);
        self.exit_epoch.deinit(self.allocator);
        self.withdrawable_epoch.deinit(self.allocator);
        self.effective_balance_increments.deinit(self.allocator);
        self.flags.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const ValidatorFlatCache) usize {
        return self.flags.items.len;
    }

    pub fn byteSize(self: *const ValidatorFlatCache) usize {
        return self.len() * (4 * @sizeOf(u64) + @sizeOf(u16) + @sizeOf(u8));
    }

    pub inline fn fields(self: *const ValidatorFlatCache, i: usize) ValidatorFields {
        const f = self.flags.items[i];
        return .{
            .activation_eligibility_epoch = self.activation_eligibility_epoch.items[i],
            .activation_epoch = self.activation_epoch.items[i],
            .exit_epoch = self.exit_epoch.items[i],
            .withdrawable_epoch = self.withdrawable_epoch.items[i],
            .effective_balance = @as(u64, self.effective_balance_increments.items[i]) * preset.EFFECTIVE_BALANCE_INCREMENT,
            .slashed = (f & flag_slashed) != 0,
            .compounding = (f & flag_compounding) != 0,
        };
    }

    /// Bring the cache in line with the validators list rooted at `root`, whose elements sit
    /// `depth` levels below it. On error the cache is left empty and the next call refills it.
    pub fn sync(self: *ValidatorFlatCache, root: Node.Id, depth: usize, new_len: usize) !void {
        self.last_patched = 0;
        if (self.synced_root) |old| {
            if (old == root and self.len() == new_len) return;
        }
        errdefer self.invalidate();

        try self.activation_eligibility_epoch.resize(self.allocator, new_len);
        try self.activation_epoch.resize(self.allocator, new_len);
        try self.exit_epoch.resize(self.allocator, new_len);
        try self.withdrawable_epoch.resize(self.allocator, new_len);
        try self.effective_balance_increments.resize(self.allocator, new_len);
        try self.flags.resize(self.allocator, new_len);

        try self.pool.ref(root);
        errdefer self.pool.unref(root);

        if (self.synced_root) |old| {
            try self.diffAndPatch(old, root, depth, new_len);
        } else {
            var it = Node.DepthIterator.init(self.pool, root, @intCast(depth), 0);
            for (0..new_len) |i| try self.patch(i, try it.next());
        }

        if (self.synced_root) |old| self.pool.unref(old);
        self.synced_root = root;
    }

    pub fn invalidate(self: *ValidatorFlatCache) void {
        if (self.synced_root) |old| self.pool.unref(old);
        self.synced_root = null;
        self.activation_eligibility_epoch.clearRetainingCapacity();
        self.activation_epoch.clearRetainingCapacity();
        self.exit_epoch.clearRetainingCapacity();
        self.withdrawable_epoch.clearRetainingCapacity();
        self.effective_balance_increments.clearRetainingCapacity();
        self.flags.clearRetainingCapacity();
    }

    /// Compares `new` and `old` validator trees, patching only validators inside changed subtrees.
    ///
    /// This does a depth-first traversal through the tree using a LIFO stack,
    /// checking if nodes changed, and patching the flat cache if so.
    fn diffAndPatch(
        self: *ValidatorFlatCache,
        old_root: Node.Id,
        new_root: Node.Id,
        depth: usize,
        new_len: usize,
    ) !void {
        const Frame = struct {
            old: Node.Id,
            new: Node.Id,
            depth: usize,
            /// Index of the first leaf position covered by this subtree.
            /// If the subtree is the leaf itself, then this is the validator index.
            base: usize,
        };

        var stack: BoundedArray(Frame, max_depth + 1) = .{};

        // Start: base of the tree
        stack.push(.{ .old = old_root, .new = new_root, .depth = depth, .base = 0 });

        while (stack.pop()) |f| {
            if (
            // Nodes are unchanged
            f.old == f.new or
                // Subtrees starting at new_len or later contain no live validators
                f.base >= new_len) continue;

            if (f.depth == 0) {
                // At a leaf, base is the validator index to patch
                try self.patch(f.base, f.new);
                continue;
            }

            // Each child covers half of the current subtree's validator indexes
            const half = @as(usize, 1) << @intCast(f.depth - 1);

            // Push right first so the LIFO stack processes left first.
            stack.push(.{
                .old = try f.old.getRight(self.pool),
                .new = try f.new.getRight(self.pool),
                .depth = f.depth - 1,
                .base = f.base + half,
            });
            stack.push(.{
                .old = try f.old.getLeft(self.pool),
                .new = try f.new.getLeft(self.pool),
                .depth = f.depth - 1,
                .base = f.base,
            });
        }
    }

    /// Patches the cache at index `i` with validator values from the tree at `leaf`.
    fn patch(self: *ValidatorFlatCache, i: usize, leaf: Node.Id) !void {
        const v = try Validator.tree.getValuePtr(leaf, self.pool);
        self.activation_eligibility_epoch.items[i] = v.activation_eligibility_epoch;
        self.activation_epoch.items[i] = v.activation_epoch;
        self.exit_epoch.items[i] = v.exit_epoch;
        self.withdrawable_epoch.items[i] = v.withdrawable_epoch;
        self.effective_balance_increments.items[i] = @intCast(@divFloor(v.effective_balance, preset.EFFECTIVE_BALANCE_INCREMENT));
        self.flags.items[i] = (if (v.slashed) flag_slashed else 0) |
            (if (hasCompoundingWithdrawalCredential(&v.withdrawal_credentials)) flag_compounding else 0);
        self.last_patched += 1;
    }

    /// Number of validators whose cached fields differ from the tree. For tests and benchmarks.
    pub fn countMismatches(self: *const ValidatorFlatCache, root: Node.Id, depth: usize, list_len: usize) !usize {
        if (self.len() != list_len) return std.math.maxInt(usize);
        var mismatches: usize = 0;
        var it = Node.DepthIterator.init(self.pool, root, @intCast(depth), 0);
        for (0..list_len) |i| {
            const v = try Validator.tree.getValuePtr(try it.next(), self.pool);
            const expected = ValidatorFields.fromValidator(v);
            const actual = self.fields(i);
            if (expected.activation_eligibility_epoch != actual.activation_eligibility_epoch or
                expected.activation_epoch != actual.activation_epoch or
                expected.exit_epoch != actual.exit_epoch or
                expected.withdrawable_epoch != actual.withdrawable_epoch or
                expected.effective_balance != actual.effective_balance or
                expected.slashed != actual.slashed or
                expected.compounding != actual.compounding)
            {
                mismatches += 1;
            }
        }
        return mismatches;
    }
};

test {
    _ = @import("validator_flat_cache_test.zig");
}
