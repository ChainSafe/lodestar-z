const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;
const ValidatorIndex = primitives.ValidatorIndex.Type;

const store_mod = @import("../store.zig");
const Checkpoint = store_mod.Checkpoint;

// =========================================================================
// 1. Errors
// =========================================================================

pub const Error = error{
    StateMissing,
    InvalidByzantineThreshold,
} || Allocator.Error;

// =========================================================================
// 2. SlotAssignments — placeholder (rebuild added in Phase B)
// =========================================================================

pub const SlotAssignments = struct {
    pub fn init() SlotAssignments {
        return .{};
    }
    pub fn deinit(self: *SlotAssignments, allocator: Allocator) void {
        _ = self;
        _ = allocator;
    }
};

// =========================================================================
// 3. BalanceSourceData — placeholder (rebuild added in Phase B)
// =========================================================================

pub const BalanceSourceData = struct {
    checkpoint: Checkpoint,
    effective_balances: std.ArrayListUnmanaged(u16) = .empty,

    pub fn init() BalanceSourceData {
        return .{ .checkpoint = .{ .epoch = 0, .root = [_]u8{0} ** 32 } };
    }

    pub fn deinit(self: *BalanceSourceData, allocator: Allocator) void {
        self.effective_balances.deinit(allocator);
    }
};

// =========================================================================
// 4. FastConfirmation struct
// =========================================================================

pub const FastConfirmation = struct {
    confirmed_root: Root,

    previous_epoch_observed_justified_checkpoint: Checkpoint,
    current_epoch_observed_justified_checkpoint: Checkpoint,
    previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    previous_slot_head: Root,
    current_slot_head: Root,

    previous_balance_source: BalanceSourceData,
    current_balance_source: BalanceSourceData,
    head_balance_source: BalanceSourceData,

    head_assignments: SlotAssignments,

    byzantine_threshold: u8,
    proposer_score_boost: u8,

    last_update_slot: ?Slot = null,
    spec_test_mode: bool = false,

    /// Initialize FCR from anchor (finalized) checkpoint.
    /// `byzantine_threshold` is clamped to [0, 25] per spec.
    pub fn init(
        finalized_cp: Checkpoint,
        byzantine_threshold: u8,
        proposer_score_boost: u8,
    ) FastConfirmation {
        const clamped: u8 = @min(byzantine_threshold, 25);
        return .{
            .confirmed_root = finalized_cp.root,
            .previous_epoch_observed_justified_checkpoint = finalized_cp,
            .current_epoch_observed_justified_checkpoint = finalized_cp,
            .previous_epoch_greatest_unrealized_checkpoint = finalized_cp,
            .previous_slot_head = finalized_cp.root,
            .current_slot_head = finalized_cp.root,
            .previous_balance_source = BalanceSourceData.init(),
            .current_balance_source = BalanceSourceData.init(),
            .head_balance_source = BalanceSourceData.init(),
            .head_assignments = SlotAssignments.init(),
            .byzantine_threshold = clamped,
            .proposer_score_boost = proposer_score_boost,
        };
    }

    pub fn deinit(self: *FastConfirmation, allocator: Allocator) void {
        self.previous_balance_source.deinit(allocator);
        self.current_balance_source.deinit(allocator);
        self.head_balance_source.deinit(allocator);
        self.head_assignments.deinit(allocator);
    }

    pub fn getConfirmedRoot(self: *const FastConfirmation) Root {
        return self.confirmed_root;
    }

    pub fn setSpecTestMode(self: *FastConfirmation, enabled: bool) void {
        self.spec_test_mode = enabled;
    }
};

// =========================================================================
// Tests — Phase A bootstrap
// =========================================================================

const ZERO_ROOT: Root = [_]u8{0} ** 32;

fn rootFromByte(b: u8) Root {
    var r: Root = ZERO_ROOT;
    r[0] = b;
    return r;
}

test "FastConfirmation init/deinit smoke" {
    const cp: Checkpoint = .{ .epoch = 0, .root = rootFromByte(0xAA) };
    var fcr = FastConfirmation.init(cp, 25, 40);
    defer fcr.deinit(testing.allocator);

    try testing.expectEqual(rootFromByte(0xAA), fcr.confirmed_root);
    try testing.expectEqual(@as(u8, 25), fcr.byzantine_threshold);
    try testing.expectEqual(@as(u8, 40), fcr.proposer_score_boost);
    try testing.expect(!fcr.spec_test_mode);
}

test "FastConfirmation byzantine_threshold clamps to 25" {
    const cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };
    var fcr = FastConfirmation.init(cp, 99, 40);
    defer fcr.deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 25), fcr.byzantine_threshold);
}

test "FastConfirmation setSpecTestMode" {
    const cp: Checkpoint = .{ .epoch = 0, .root = ZERO_ROOT };
    var fcr = FastConfirmation.init(cp, 25, 40);
    defer fcr.deinit(testing.allocator);
    fcr.setSpecTestMode(true);
    try testing.expect(fcr.spec_test_mode);
}
