//! Flat, index-addressed copy of the validator fields the epoch transition reads.
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
const Node = @import("persistent_merkle_tree").Node;
const max_depth = @import("persistent_merkle_tree").max_depth;
const hasCompoundingWithdrawalCredential = @import("../utils/electra.zig").hasCompoundingWithdrawalCredential;

const Validator = types.phase0.Validator;

/// Levels from a validators list root down to its elements: the chunks tree plus the length mix-in.
pub const validators_depth: usize = @as(usize, types.phase0.Validators.chunk_depth) + 1;

/// Fields that EpochTransitionCache.init needs to know about one validator.
pub const ValidatorFields = struct {
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
    effective_balance: u64,
    bits: Bits,

    pub const Bits = packed struct(u8) {
        slashed: bool,
        compounding: bool,
        _: u6 = 0,
    };

    pub inline fn fromValidator(v: *const Validator.Type) ValidatorFields {
        return .{
            .activation_eligibility_epoch = v.activation_eligibility_epoch,
            .activation_epoch = v.activation_epoch,
            .exit_epoch = v.exit_epoch,
            .withdrawable_epoch = v.withdrawable_epoch,
            .effective_balance = v.effective_balance,
            .bits = .{
                .slashed = v.slashed,
                .compounding = hasCompoundingWithdrawalCredential(&v.withdrawal_credentials),
            },
        };
    }
};

pub const ValidatorFlatCache = struct {
    allocator: Allocator,
    pool: *Node.Pool,
    synced_root: ?Node.Id = null,
    fields: std.MultiArrayList(ValidatorFields) = .empty,
    /// Leaves rewritten by the last `sync`.
    last_patched: usize = 0,

    pub fn init(allocator: Allocator, pool: *Node.Pool) ValidatorFlatCache {
        return .{ .allocator = allocator, .pool = pool };
    }

    pub fn deinit(self: *ValidatorFlatCache) void {
        self.invalidate();
        self.fields.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const ValidatorFlatCache) usize {
        return self.fields.len;
    }

    pub fn byteSize(self: *const ValidatorFlatCache) usize {
        return self.len() * (5 * @sizeOf(u64) + @sizeOf(ValidatorFields.Bits));
    }

    /// Bring the cache in line with the validators list rooted at `root`.
    /// On error the cache is left empty and the next call refills it.
    pub fn sync(self: *ValidatorFlatCache, root: Node.Id, new_len: usize) !void {
        self.last_patched = 0;
        if (self.synced_root) |old| {
            if (old == root and self.len() == new_len) return;
        }
        errdefer self.invalidate();

        const old_len = self.len();
        try self.fields.resize(self.allocator, new_len);

        try self.pool.ref(root);
        errdefer self.pool.unref(root);

        if (self.synced_root) |old| {
            try self.diffAndPatch(old, root, old_len, new_len);
        } else {
            var it = Node.DepthIterator.init(self.pool, root, @intCast(validators_depth), 0);
            for (0..new_len) |i| try self.patch(i, try it.next());
        }

        if (self.synced_root) |old| self.pool.unref(old);
        self.synced_root = root;
    }

    pub fn invalidate(self: *ValidatorFlatCache) void {
        if (self.synced_root) |old| self.pool.unref(old);
        self.synced_root = null;
        self.fields.clearRetainingCapacity();
    }

    /// Compares `new` and `old` validator trees, patching only validators inside changed subtrees.
    ///
    /// This does a depth-first traversal through the tree using a LIFO stack,
    /// checking if nodes changed, and patching the flat cache if so.
    fn diffAndPatch(
        self: *ValidatorFlatCache,
        old_root: Node.Id,
        new_root: Node.Id,
        old_len: usize,
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
        stack.push(.{ .old = old_root, .new = new_root, .depth = validators_depth, .base = 0 });

        while (stack.pop()) |f| {
            // Subtrees starting at new_len or later contain no live validators
            if (f.base >= new_len) continue;

            // index just past the last validator this subtree covers
            const end = f.base + (@as(usize, 1) << @intCast(f.depth));
            if (
            // old tree and new tree shares same node
            f.old == f.new and
                // every index before under old_len was already cached
                end <= old_len) continue;

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
        self.fields.set(i, .fromValidator(v));
        self.last_patched += 1;
    }
};

test {
    _ = @import("validator_flat_cache_test.zig");
}
