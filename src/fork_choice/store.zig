const std = @import("std");
const Allocator = std.mem.Allocator;

const consensus_types = @import("consensus_types");
const primitives = consensus_types.primitive;
const state_transition = @import("state_transition");

const CachedBeaconState = state_transition.CachedBeaconState;

const proto_array_mod = @import("proto_array.zig");
const PayloadStatus = proto_array_mod.PayloadStatus;

const Slot = primitives.Slot.Type;
const Epoch = primitives.Epoch.Type;
const Root = primitives.Root.Type;

const compute_deltas_mod = @import("compute_deltas.zig");
const EquivocatingIndices = compute_deltas_mod.EquivocatingIndices;

/// Checkpoint with root.
pub const Checkpoint = struct {
    epoch: Epoch,
    root: Root,

    /// Compare checkpoint identity (epoch + root).
    pub fn eql(a: Checkpoint, b: Checkpoint) bool {
        return a.epoch == b.epoch and
            std.mem.eql(u8, &a.root, &b.root);
    }
};

/// Checkpoint extended with Gloas payload status.
///
/// Pre-Gloas: payload_status is always .full.
/// Gloas: determined by state.execution_payload_availability.
pub const CheckpointWithPayloadStatus = struct {
    epoch: Epoch,
    root: Root,
    payload_status: PayloadStatus = .full,

    pub fn fromCheckpoint(cp: Checkpoint, payload_status: PayloadStatus) CheckpointWithPayloadStatus {
        return .{
            .epoch = cp.epoch,
            .root = cp.root,
            .payload_status = payload_status,
        };
    }
};

/// Reference-counted effective balance increments.
pub const JustifiedBalancesRc = state_transition.EffectiveBalanceIncrementsRc;

/// Effective balance increments (1 increment = 1 ETH effective balance).
pub const JustifiedBalances = state_transition.EffectiveBalanceIncrements;

/// Sum all effective balance increments.
pub fn computeTotalBalance(balances: []const u16) u64 {
    var total: u64 = 0;
    for (balances) |b| {
        total += b;
    }
    return total;
}

/// Returns the justified balances of checkpoint.
/// MUST not throw an error in any case, related to cache miss. Either trigger regen
/// or approximate from a close state.
pub const JustifiedBalancesGetter = struct {
    context: ?*anyopaque = null,
    getFn: *const fn (context: ?*anyopaque, checkpoint: CheckpointWithPayloadStatus, state: *CachedBeaconState) JustifiedBalances,

    pub fn get(self: JustifiedBalancesGetter, checkpoint: CheckpointWithPayloadStatus, state: *CachedBeaconState) JustifiedBalances {
        return self.getFn(self.context, checkpoint, state);
    }
};

/// Event callback: context + fn pointer pair.
pub const EventCallback = struct {
    context: ?*anyopaque = null,
    callFn: *const fn (context: ?*anyopaque, cp: CheckpointWithPayloadStatus) void,

    pub fn call(self: EventCallback, cp: CheckpointWithPayloadStatus) void {
        self.callFn(self.context, cp);
    }
};

/// Event callbacks for checkpoint updates.
pub const ForkChoiceStoreEvents = struct {
    on_justified: ?EventCallback = null,
    on_finalized: ?EventCallback = null,
};

/// Approximates the `Store` in "Ethereum Consensus -- Beacon Chain Fork Choice":
/// https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/phase0/fork-choice.md#store
///
/// This is only an approximation for two reasons:
/// - The actual block DAG in `ProtoArray`.
/// - `time` is represented using `Slot` instead of UNIX epoch `u64`.
///
/// Emits forkChoice events on updated justified and finalized checkpoints.
pub const ForkChoiceStore = struct {
    /// Current slot (updated via onTick).
    current_slot: Slot,

    /// Realized justified checkpoint with balances (from epoch boundary processing).
    justified: JustifiedState,
    /// Unrealized justified checkpoint with balances from pull-up FFG.
    unrealized_justified: JustifiedState,
    /// Realized finalized checkpoint.
    finalized_checkpoint: CheckpointWithPayloadStatus,
    /// Unrealized finalized checkpoint from pull-up FFG.
    unrealized_finalized_checkpoint: CheckpointWithPayloadStatus,

    /// Set of equivocating validator indices (from attester slashings).
    equivocating_indices: EquivocatingIndices,

    /// Callback for retrieving justified balances on demand.
    justified_balances_getter: JustifiedBalancesGetter,

    /// Event callbacks for checkpoint updates.
    events: ForkChoiceStoreEvents,

    /// Justified checkpoint + balances + totalBalance bundled together.
    /// Balances are reference-counted: justified and unrealized_justified may share
    pub const JustifiedState = struct {
        checkpoint: CheckpointWithPayloadStatus,
        balances: *JustifiedBalancesRc,
        total_balance: u64,
    };

    pub fn init(
        self: *ForkChoiceStore,
        allocator: Allocator,
        current_slot: Slot,
        justified_checkpoint: CheckpointWithPayloadStatus,
        finalized_checkpoint: CheckpointWithPayloadStatus,
        justified_balances: []const u16,
        justified_balances_getter: JustifiedBalancesGetter,
        events: ForkChoiceStoreEvents,
    ) !void {
        var balances_list = JustifiedBalances.init(allocator);
        errdefer balances_list.deinit();

        try balances_list.appendSlice(justified_balances);

        const balances_rc = try JustifiedBalancesRc.init(allocator, balances_list);
        errdefer balances_rc.release();

        const total = computeTotalBalance(justified_balances);

        // referenced by `unrealized_justified`
        _ = balances_rc.acquire();

        self.* = .{
            .current_slot = current_slot,
            .justified = .{
                .checkpoint = justified_checkpoint,
                .balances = balances_rc,
                .total_balance = total,
            },
            .unrealized_justified = .{
                .checkpoint = justified_checkpoint,
                .balances = balances_rc,
                .total_balance = total,
            },
            .finalized_checkpoint = finalized_checkpoint,
            .unrealized_finalized_checkpoint = finalized_checkpoint,
            .equivocating_indices = .empty,
            .justified_balances_getter = justified_balances_getter,
            .events = events,
        };
    }

    /// Set the justified checkpoint and balances, recomputing totalBalance.
    /// Receives raw balances slice, internally creates a new Rc (matching state_transition pattern).
    /// Fires onJustified event if configured.
    pub fn setJustified(self: *ForkChoiceStore, allocator: Allocator, checkpoint: CheckpointWithPayloadStatus, balances: []const u16) !void {
        var balances_list = JustifiedBalances.init(allocator);
        errdefer balances_list.deinit();

        try balances_list.appendSlice(balances);

        const balances_rc = try JustifiedBalancesRc.init(allocator, balances_list);

        self.justified.balances.release();
        self.justified = .{
            .checkpoint = checkpoint,
            .balances = balances_rc,
            .total_balance = computeTotalBalance(balances),
        };
        if (self.events.on_justified) |cb| cb.call(checkpoint);
    }

    /// Set the finalized checkpoint.
    /// Fires onFinalized event if configured.
    pub fn setFinalizedCheckpoint(self: *ForkChoiceStore, checkpoint: CheckpointWithPayloadStatus) void {
        self.finalized_checkpoint = checkpoint;
        if (self.events.on_finalized) |cb| cb.call(checkpoint);
    }

    pub fn deinit(self: *ForkChoiceStore, allocator: Allocator) void {
        self.equivocating_indices.deinit(allocator);
        self.justified.balances.release();
        self.unrealized_justified.balances.release();
    }
};

// ── Tests ──

const testing = std.testing;
const constants = @import("constants");
const ZERO_HASH = constants.ZERO_HASH;

fn hashFromByte(byte: u8) Root {
    var root: Root = ZERO_HASH;
    root[0] = byte;
    return root;
}

fn makeCheckpoint(epoch: Epoch, root: Root) CheckpointWithPayloadStatus {
    return .{ .epoch = epoch, .root = root };
}

fn dummyBalancesGetter(_: ?*anyopaque, _: CheckpointWithPayloadStatus, _: *CachedBeaconState) JustifiedBalances {
    return JustifiedBalances.init(testing.allocator);
}

const test_getter: JustifiedBalancesGetter = .{ .getFn = dummyBalancesGetter };

fn initTestStore(balances: []const u16) !ForkChoiceStore {
    var store: ForkChoiceStore = undefined;
    try store.init(
        testing.allocator,
        0,
        makeCheckpoint(0, hashFromByte(0x01)),
        makeCheckpoint(0, hashFromByte(0x01)),
        balances,
        test_getter,
        .{},
    );
    return store;
}

test "computeTotalBalance" {
    try testing.expectEqual(@as(u64, 0), computeTotalBalance(&.{}));
    try testing.expectEqual(@as(u64, 10), computeTotalBalance(&.{10}));
    try testing.expectEqual(@as(u64, 6), computeTotalBalance(&.{ 1, 2, 3 }));
    try testing.expectEqual(@as(u64, 130), computeTotalBalance(&.{ 65, 65 }));
}

test "Checkpoint.eql" {
    const root_a = hashFromByte(0x01);
    const root_b = hashFromByte(0x02);

    const cp_a: Checkpoint = .{ .epoch = 1, .root = root_a };
    const cp_b: Checkpoint = .{ .epoch = 1, .root = root_a };
    const cp_c: Checkpoint = .{ .epoch = 2, .root = root_a };
    const cp_d: Checkpoint = .{ .epoch = 1, .root = root_b };

    try testing.expect(cp_a.eql(cp_b));
    try testing.expect(!cp_a.eql(cp_c));
    try testing.expect(!cp_a.eql(cp_d));
}

test "CheckpointWithPayloadStatus.fromCheckpoint" {
    const cp: Checkpoint = .{ .epoch = 5, .root = hashFromByte(0xAA) };
    const cwp = CheckpointWithPayloadStatus.fromCheckpoint(cp, .empty);

    try testing.expectEqual(@as(Epoch, 5), cwp.epoch);
    try testing.expectEqual(cp.root, cwp.root);
    try testing.expectEqual(PayloadStatus.empty, cwp.payload_status);
}

test "init shares Rc between justified and unrealized_justified" {
    var store = try initTestStore(&.{ 10, 20, 30 });
    defer store.deinit(testing.allocator);

    // Both point to the same Rc (ref_count = 2).
    try testing.expectEqual(store.justified.balances, store.unrealized_justified.balances);
    try testing.expectEqual(@as(u64, 60), store.justified.total_balance);
    try testing.expectEqual(@as(u64, 60), store.unrealized_justified.total_balance);

    // Underlying data is the same.
    try testing.expectEqualSlices(u16, store.justified.balances.get().items, store.unrealized_justified.balances.get().items);
}

test "setJustified separates Rc from unrealized_justified" {
    var store = try initTestStore(&.{ 10, 20 });
    defer store.deinit(testing.allocator);

    const old_rc = store.justified.balances;
    const new_cp = makeCheckpoint(1, hashFromByte(0x02));

    try store.setJustified(testing.allocator, new_cp, &.{ 5, 5, 5 });

    // justified now has new Rc, unrealized_justified keeps old Rc.
    try testing.expect(store.justified.balances != old_rc);
    try testing.expectEqual(store.unrealized_justified.balances, old_rc);

    // Values updated correctly.
    try testing.expectEqual(@as(u64, 15), store.justified.total_balance);
    try testing.expectEqual(@as(u64, 30), store.unrealized_justified.total_balance);
    try testing.expectEqual(@as(Epoch, 1), store.justified.checkpoint.epoch);
}

test "setFinalizedCheckpoint updates and fires event" {
    const Tracker = struct {
        called: bool = false,
        last_epoch: Epoch = 0,

        fn onFinalized(ctx: ?*anyopaque, cp: CheckpointWithPayloadStatus) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.called = true;
            self.last_epoch = cp.epoch;
        }
    };

    var tracker: Tracker = .{};
    var store: ForkChoiceStore = undefined;
    try store.init(
        testing.allocator,
        0,
        makeCheckpoint(0, hashFromByte(0x01)),
        makeCheckpoint(0, hashFromByte(0x01)),
        &.{},
        test_getter,
        .{ .on_finalized = .{ .context = @ptrCast(&tracker), .callFn = Tracker.onFinalized } },
    );
    defer store.deinit(testing.allocator);

    const new_cp = makeCheckpoint(3, hashFromByte(0x0F));
    store.setFinalizedCheckpoint(new_cp);

    try testing.expect(tracker.called);
    try testing.expectEqual(@as(Epoch, 3), tracker.last_epoch);
    try testing.expectEqual(@as(Epoch, 3), store.finalized_checkpoint.epoch);
}

test "setJustified fires onJustified event" {
    const Tracker = struct {
        called: bool = false,
        last_epoch: Epoch = 0,

        fn onJustified(ctx: ?*anyopaque, cp: CheckpointWithPayloadStatus) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.called = true;
            self.last_epoch = cp.epoch;
        }
    };

    var tracker: Tracker = .{};
    var store: ForkChoiceStore = undefined;
    try store.init(
        testing.allocator,
        0,
        makeCheckpoint(0, hashFromByte(0x01)),
        makeCheckpoint(0, hashFromByte(0x01)),
        &.{},
        test_getter,
        .{ .on_justified = .{ .context = @ptrCast(&tracker), .callFn = Tracker.onJustified } },
    );
    defer store.deinit(testing.allocator);

    try store.setJustified(testing.allocator, makeCheckpoint(2, hashFromByte(0x0A)), &.{ 7, 8 });

    try testing.expect(tracker.called);
    try testing.expectEqual(@as(Epoch, 2), tracker.last_epoch);
}

test "deinit releases all Rc without leak" {
    // If deinit leaks, testing.allocator will report it.
    var store = try initTestStore(&.{ 1, 2, 3 });
    store.deinit(testing.allocator);
}
