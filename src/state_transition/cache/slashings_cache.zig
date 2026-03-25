const std = @import("std");
const Allocator = std.mem.Allocator;
const DynamicBitSet = std.DynamicBitSet;
const types = @import("consensus_types");
const Slot = types.primitive.Slot.Type;
const ValidatorIndex = types.primitive.ValidatorIndex.Type;
const Validator = types.phase0.Validator.Type;

/// Cache of slashed validator indices with an initialization slot.
pub const SlashingsCache = struct {
    latest_block_slot: ?Slot,
    slashed_validators: DynamicBitSet,

    pub fn initEmpty(allocator: Allocator) !SlashingsCache {
        return .{
            .latest_block_slot = null,
            .slashed_validators = try DynamicBitSet.initEmpty(allocator, 0),
        };
    }

    pub fn initFromValidators(
        allocator: Allocator,
        latest_block_slot: Slot,
        validators: []const Validator,
    ) !SlashingsCache {
        var slashed_validators = try DynamicBitSet.initEmpty(allocator, validators.len);
        errdefer slashed_validators.deinit();
        for (validators, 0..) |validator, i| {
            if (validator.slashed) {
                slashed_validators.set(i);
            }
        }

        return .{
            .latest_block_slot = latest_block_slot,
            .slashed_validators = slashed_validators,
        };
    }

    pub fn clone(self: *const SlashingsCache, allocator: Allocator) !SlashingsCache {
        var slashed_validators = try self.slashed_validators.clone(allocator);
        errdefer slashed_validators.deinit();

        return .{
            .latest_block_slot = self.latest_block_slot,
            .slashed_validators = slashed_validators,
        };
    }

    pub fn deinit(self: *SlashingsCache) void {
        self.slashed_validators.deinit();
        self.* = undefined;
    }

    pub fn isInitialized(self: *const SlashingsCache, latest_block_slot: Slot) bool {
        return self.latest_block_slot != null and self.latest_block_slot.? == latest_block_slot;
    }

    pub fn checkInitialized(self: *const SlashingsCache, latest_block_slot: Slot) !void {
        if (self.isInitialized(latest_block_slot)) return;
        return error.SlashingsCacheUninitialized;
    }

    pub fn recordValidatorSlashing(self: *SlashingsCache, block_slot: Slot, validator_index: ValidatorIndex) !void {
        try self.checkInitialized(block_slot);
        const idx: usize = @intCast(validator_index);
        if (idx >= self.slashed_validators.capacity()) {
            try self.slashed_validators.resize(idx + 1, false);
        }
        self.slashed_validators.set(idx);
    }

    pub fn isSlashed(self: *const SlashingsCache, validator_index: ValidatorIndex) bool {
        const idx: usize = @intCast(validator_index);
        if (idx >= self.slashed_validators.capacity()) return false;
        return self.slashed_validators.isSet(idx);
    }

    pub fn updateLatestBlockSlot(self: *SlashingsCache, latest_block_slot: Slot) void {
        self.latest_block_slot = latest_block_slot;
    }
};

/// Rebuilds the cache if it's not initialized for the state's latest block slot.
pub fn buildFromStateIfNeeded(
    allocator: Allocator,
    state: anytype,
    slashings_cache: *SlashingsCache,
) !void {
    var latest_block_header = try state.latestBlockHeader();
    const latest_block_slot = try latest_block_header.get("slot");
    if (slashings_cache.isInitialized(latest_block_slot)) return;

    var validators_view = try state.validators();
    try validators_view.commit();
    const validators = try validators_view.getAllReadonlyValues(allocator);
    defer allocator.free(validators);
    var new_cache = try SlashingsCache.initFromValidators(allocator, latest_block_slot, validators);
    errdefer new_cache.deinit();
    slashings_cache.deinit();
    slashings_cache.* = new_cache;
}

test "SlashingsCache - initEmpty creates empty cache" {
    const allocator = std.testing.allocator;
    var cache = try SlashingsCache.initEmpty(allocator);
    defer cache.deinit();

    try std.testing.expect(cache.latest_block_slot == null);
    try std.testing.expect(!cache.isSlashed(0));
    try std.testing.expect(!cache.isSlashed(100));
}

test "SlashingsCache - initFromValidators populates slashed bits" {
    const allocator = std.testing.allocator;
    var validators: [5]Validator = undefined;
    @memset(std.mem.asBytes(&validators), 0);

    // Mark validators 1 and 3 as slashed
    validators[1].slashed = true;
    validators[3].slashed = true;

    var cache = try SlashingsCache.initFromValidators(allocator, 42, &validators);
    defer cache.deinit();

    try std.testing.expectEqual(@as(?Slot, 42), cache.latest_block_slot);
    try std.testing.expect(!cache.isSlashed(0));
    try std.testing.expect(cache.isSlashed(1));
    try std.testing.expect(!cache.isSlashed(2));
    try std.testing.expect(cache.isSlashed(3));
    try std.testing.expect(!cache.isSlashed(4));
}

test "SlashingsCache - isInitialized checks slot" {
    const allocator = std.testing.allocator;
    var cache = try SlashingsCache.initEmpty(allocator);
    defer cache.deinit();

    try std.testing.expect(!cache.isInitialized(0));
    try std.testing.expect(!cache.isInitialized(42));

    cache.updateLatestBlockSlot(42);
    try std.testing.expect(cache.isInitialized(42));
    try std.testing.expect(!cache.isInitialized(43));
}

test "SlashingsCache - recordValidatorSlashing requires initialization" {
    const allocator = std.testing.allocator;
    var cache = try SlashingsCache.initEmpty(allocator);
    defer cache.deinit();

    // Should fail when not initialized
    try std.testing.expectError(error.SlashingsCacheUninitialized, cache.recordValidatorSlashing(10, 5));

    // Initialize and try again
    cache.updateLatestBlockSlot(10);
    try cache.recordValidatorSlashing(10, 5);
    try std.testing.expect(cache.isSlashed(5));

    // Wrong slot should fail
    try std.testing.expectError(error.SlashingsCacheUninitialized, cache.recordValidatorSlashing(11, 6));
}

test "SlashingsCache - recordValidatorSlashing grows capacity" {
    const allocator = std.testing.allocator;
    var cache = try SlashingsCache.initEmpty(allocator);
    defer cache.deinit();

    cache.updateLatestBlockSlot(0);

    // Record slashing for a high index — should grow the bitset
    try cache.recordValidatorSlashing(0, 1000);
    try std.testing.expect(cache.isSlashed(1000));
    try std.testing.expect(!cache.isSlashed(999));
}

test "SlashingsCache - clone creates independent copy" {
    const allocator = std.testing.allocator;
    var validators: [3]Validator = undefined;
    @memset(std.mem.asBytes(&validators), 0);
    validators[1].slashed = true;

    var original = try SlashingsCache.initFromValidators(allocator, 10, &validators);
    defer original.deinit();

    var cloned = try original.clone(allocator);
    defer cloned.deinit();

    // Both should see validator 1 as slashed
    try std.testing.expect(cloned.isSlashed(1));
    try std.testing.expectEqual(@as(?Slot, 10), cloned.latest_block_slot);

    // Modify original — clone should be unaffected
    original.updateLatestBlockSlot(20);
    try original.recordValidatorSlashing(20, 2);

    try std.testing.expectEqual(@as(?Slot, 10), cloned.latest_block_slot);
    try std.testing.expect(!cloned.isSlashed(2));
}
