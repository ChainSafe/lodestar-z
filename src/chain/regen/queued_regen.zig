//! QueuedStateRegen — wraps StateRegen with request queuing and deduplication.
//!
//! When multiple callers request the same state simultaneously (common during
//! reorgs when many attestations need the same historical state), only one
//! regeneration runs. All callers receive the same result.
//!
//! Requests are prioritized: block import > fork choice > API > background.
//! Low-priority requests can be dropped under load.
//!
//! Design mirrors Lodestar's QueuedStateRegenerator in chain/regen/queued.ts.

const std = @import("std");
const Allocator = std.mem.Allocator;

const state_transition = @import("state_transition");
const CachedBeaconState = state_transition.CachedBeaconState;
const computeEpochAtSlot = state_transition.computeEpochAtSlot;
const StateRegen = @import("state_regen.zig").StateRegen;
const CheckpointKey = @import("datastore.zig").CheckpointKey;

/// Priority for state regen requests (lower numeric value = higher priority).
pub const RegenPriority = enum(u2) {
    /// Block import — highest priority, must not be delayed.
    block_import = 0,
    /// Fork choice updates — high priority.
    fork_choice = 1,
    /// REST API queries — normal priority.
    api = 2,
    /// Background tasks (cache warming, etc.) — lowest priority.
    background = 3,

    pub fn isHigherOrEqual(self: RegenPriority, other: RegenPriority) bool {
        return @intFromEnum(self) <= @intFromEnum(other);
    }
};

/// Identifies the kind of regen request.
pub const RegenRequestKind = enum {
    /// Get state by block root.
    block_root,
    /// Get checkpoint state by (epoch, root).
    checkpoint,
    /// Get pre-state for a block (by parent root + block slot).
    pre_state,
    /// Get state by state root.
    state_root,
};

/// Key for deduplication — uniquely identifies a regen target.
pub const RegenKey = union(RegenRequestKind) {
    block_root: [32]u8,
    checkpoint: CheckpointKey,
    pre_state: struct {
        parent_block_root: [32]u8,
        parent_state_root: [32]u8,
        block_slot: u64,
    },
    state_root: [32]u8,

    pub fn eql(a: RegenKey, b: RegenKey) bool {
        const tag_a: RegenRequestKind = a;
        const tag_b: RegenRequestKind = b;
        if (tag_a != tag_b) return false;
        return switch (a) {
            .block_root => |ra| std.mem.eql(u8, &ra, &b.block_root),
            .checkpoint => |ca| ca.epoch == b.checkpoint.epoch and std.mem.eql(u8, &ca.root, &b.checkpoint.root),
            .pre_state => |pa| std.mem.eql(u8, &pa.parent_block_root, &b.pre_state.parent_block_root) and
                std.mem.eql(u8, &pa.parent_state_root, &b.pre_state.parent_state_root) and
                pa.block_slot == b.pre_state.block_slot,
            .state_root => |ra| std.mem.eql(u8, &ra, &b.state_root),
        };
    }

    pub fn hash(self: RegenKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&@as(RegenRequestKind, self)));
        switch (self) {
            .block_root => |r| h.update(&r),
            .checkpoint => |cp| {
                h.update(std.mem.asBytes(&cp.epoch));
                h.update(&cp.root);
            },
            .pre_state => |ps| {
                h.update(&ps.parent_block_root);
                h.update(&ps.parent_state_root);
                h.update(std.mem.asBytes(&ps.block_slot));
            },
            .state_root => |r| h.update(&r),
        }
        return h.final();
    }
};

/// A queued regen request.
pub const RegenRequest = struct {
    key: RegenKey,
    priority: RegenPriority,
};

/// Errors specific to the regen subsystem.
pub const RegenError = error{
    NoPreStateAvailable,
    QueueFull,
    RequestDropped,
    StateNotFound,
};

pub const REGEN_QUEUE_MAX_LEN: u32 = 256;
pub const REGEN_CAN_ACCEPT_WORK_THRESHOLD: u32 = 16;

/// QueuedStateRegen — request-queued state regenerator with deduplication.
///
/// Synchronous fast-path: if the state is already cached, return immediately.
/// Async slow-path: queue the request; the worker thread computes a detached
/// transient state, and the caller thread publishes it into shared caches.
///
/// That keeps cache mutation on the chain-owning thread while still moving the
/// expensive replay / deserialize work off-thread.
pub const QueuedStateRegen = struct {
    allocator: Allocator,
    io: std.Io,
    /// The underlying state regenerator (does the actual work).
    regen: *StateRegen,
    /// Maximum queue length before we start dropping low-priority requests.
    max_queue_len: u32,

    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    requests: std.ArrayListUnmanaged(SlowPathRequest) = .empty,
    shutdown_requested: bool = false,
    thread: ?std.Thread = null,

    // -- Metrics --
    /// Total requests served from cache (fast path).
    cache_hits: u64,
    /// Total requests that went through the queue (slow path).
    queue_hits: u64,
    /// Total requests dropped due to queue pressure.
    dropped: u64,

    const SlowPathStage = enum {
        pending,
        running,
        ready_unpublished,
        publishing,
        ready,
    };

    const SlowPathCompletion = union(enum) {
        transient: *CachedBeaconState,
        published: *CachedBeaconState,
        no_state,
        err: anyerror,
    };

    const SlowPathInput = union(enum) {
        none,
        checkpoint: StateRegen.PreparedCheckpointReload,

        fn deinit(self: *SlowPathInput, regen: *StateRegen) void {
            switch (self.*) {
                .none => {},
                .checkpoint => |*prepared| prepared.deinit(regen),
            }
            self.* = .none;
        }
    };

    const SlowPathRequest = struct {
        key: RegenKey,
        priority: RegenPriority,
        waiters: usize,
        stage: SlowPathStage,
        input: SlowPathInput = .none,
        completion: ?SlowPathCompletion = null,

        fn deinit(self: *SlowPathRequest, regen: *StateRegen) void {
            self.input.deinit(regen);
            if (self.completion) |completion| switch (completion) {
                .transient => |state| regen.destroyTransientState(state),
                else => {},
            };
            self.* = undefined;
        }
    };

    pub fn init(allocator: Allocator, io: std.Io, regen: *StateRegen) QueuedStateRegen {
        return initWithConfig(allocator, io, regen, REGEN_QUEUE_MAX_LEN);
    }

    pub fn initWithConfig(
        allocator: Allocator,
        io: std.Io,
        regen: *StateRegen,
        max_queue_len: u32,
    ) QueuedStateRegen {
        return .{
            .allocator = allocator,
            .io = io,
            .regen = regen,
            .max_queue_len = max_queue_len,
            .cache_hits = 0,
            .queue_hits = 0,
            .dropped = 0,
        };
    }

    pub fn start(self: *QueuedStateRegen) !void {
        if (self.thread != null) return;
        self.thread = try std.Thread.spawn(.{}, workerMain, .{self});
    }

    pub fn deinit(self: *QueuedStateRegen) void {
        self.mutex.lockUncancelable(self.io);
        self.shutdown_requested = true;
        self.cond.broadcast(self.io);
        self.mutex.unlock(self.io);

        if (self.thread) |thread| {
            thread.join();
        }

        for (self.requests.items) |*request| {
            request.deinit(self.regen);
        }
        self.requests.deinit(self.allocator);
    }

    // -----------------------------------------------------------------------
    // Public API — synchronous fast path with fallback to regen
    // -----------------------------------------------------------------------

    /// Get the pre-state for processing a block.
    ///
    /// `parent_state_root` MUST be a STATE root (not a block root).
    /// Fast path: exact block-state cache for same-epoch parents, checkpoint
    /// cache for cross-epoch parents.
    /// Slow path: queues an uncached worker regen and publishes the result.
    pub fn getCachedPreState(
        self: *QueuedStateRegen,
        parent_block_root: [32]u8,
        parent_state_root: [32]u8, // Must be state root, not block root
        parent_slot: u64,
        block_slot: u64,
    ) !?*CachedBeaconState {
        if (try self.regen.getCachedPreState(parent_block_root, parent_state_root, parent_slot, block_slot)) |state| {
            self.noteCacheHit();
            return state;
        }

        return null;
    }

    pub fn getPreState(
        self: *QueuedStateRegen,
        parent_block_root: [32]u8,
        parent_state_root: [32]u8,
        parent_slot: u64,
        block_slot: u64,
        priority: RegenPriority,
    ) !*CachedBeaconState {
        const parent_epoch = computeEpochAtSlot(parent_slot);
        const block_epoch = computeEpochAtSlot(block_slot);

        if (try self.getCachedPreState(parent_block_root, parent_state_root, parent_slot, block_slot)) |state| {
            return state;
        }

        if (parent_epoch < block_epoch) {
            if (try self.getCheckpointStateLatest(parent_block_root, block_epoch, priority)) |state| {
                return state;
            }
        }

        return (try self.resolveSlowPath(.{ .pre_state = .{
            .parent_block_root = parent_block_root,
            .parent_state_root = parent_state_root,
            .block_slot = block_slot,
        } }, priority, .none)) orelse error.NoPreStateAvailable;
    }

    /// Get a checkpoint state (epoch boundary state).
    ///
    /// Fast path: check checkpoint cache.
    /// Slow path: queue a detached-seed checkpoint reload and publish it back
    /// into the checkpoint cache on the caller thread.
    pub fn getCheckpointState(
        self: *QueuedStateRegen,
        cp: CheckpointKey,
        priority: RegenPriority,
    ) !?*CachedBeaconState {
        // Fast path.
        if (self.regen.checkpoint_cache.get(cp)) |state| {
            self.noteCacheHit();
            return state;
        }

        const prepared = (try self.regen.prepareCheckpointReload(cp)) orelse return null;
        return self.resolveSlowPath(.{ .checkpoint = cp }, priority, .{ .checkpoint = prepared });
    }

    pub fn getCheckpointStateLatest(
        self: *QueuedStateRegen,
        root: [32]u8,
        max_epoch: u64,
        priority: RegenPriority,
    ) !?*CachedBeaconState {
        const cp = self.regen.checkpoint_cache.findLatestKey(root, max_epoch) orelse return null;

        if (self.regen.checkpoint_cache.get(cp)) |state| {
            self.noteCacheHit();
            return state;
        }

        const prepared = (try self.regen.prepareCheckpointReload(cp)) orelse return null;
        return self.resolveSlowPath(.{ .checkpoint = cp }, priority, .{ .checkpoint = prepared });
    }

    /// Get state by state root.
    ///
    /// Fast path: check block state cache.
    /// Slow path: queue an uncached archive load and publish the result.
    pub fn getStateByRoot(
        self: *QueuedStateRegen,
        state_root: [32]u8,
        priority: RegenPriority,
    ) !?*CachedBeaconState {
        // Fast path.
        if (self.regen.block_cache.get(state_root)) |state| {
            self.noteCacheHit();
            return state;
        }

        return self.resolveSlowPath(.{ .state_root = state_root }, priority, .none);
    }

    /// Drop all pending requests with priority lower than `min_priority`.
    pub fn dropLowPriority(self: *QueuedStateRegen, min_priority: RegenPriority) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.dropLowPriorityLocked(min_priority);
        self.cond.broadcast(self.io);
    }

    /// Whether the queue can accept new work (below threshold).
    pub fn canAcceptWork(self: *const QueuedStateRegen) bool {
        const mutable_self: *QueuedStateRegen = @constCast(self);
        mutable_self.mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.mutex.unlock(mutable_self.io);
        return mutable_self.activeRequestCountLocked() < REGEN_CAN_ACCEPT_WORK_THRESHOLD;
    }

    /// Number of requests currently queued.
    pub fn queueLen(self: *const QueuedStateRegen) usize {
        const mutable_self: *QueuedStateRegen = @constCast(self);
        mutable_self.mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.mutex.unlock(mutable_self.io);
        return mutable_self.activeRequestCountLocked();
    }

    // -----------------------------------------------------------------------
    // Delegate lifecycle events to underlying StateRegen
    // -----------------------------------------------------------------------

    /// Called after processing a new block — cache the resulting state.
    pub fn onNewBlock(self: *QueuedStateRegen, state: *CachedBeaconState, is_head: bool) ![32]u8 {
        return self.regen.onNewBlock(state, is_head);
    }

    /// Called when a new head is selected.
    pub fn onNewHead(self: *QueuedStateRegen, state: *CachedBeaconState) ![32]u8 {
        return self.regen.onNewHead(state);
    }

    /// Called on epoch boundary — store checkpoint state.
    pub fn onCheckpoint(self: *QueuedStateRegen, cp: CheckpointKey, state: *CachedBeaconState) !void {
        return self.regen.onCheckpoint(cp, state);
    }

    /// Called on finalization — prune stale states and drop low-priority queue items.
    pub fn onFinalized(self: *QueuedStateRegen, finalized_epoch: u64) !void {
        try self.regen.onFinalized(finalized_epoch);
        // Under finalization, drop background requests — they're likely stale.
        self.dropLowPriority(.api);
    }

    // -----------------------------------------------------------------------
    // Metrics / debugging
    // -----------------------------------------------------------------------

    pub const Metrics = struct {
        cache_hits: u64,
        queue_hits: u64,
        dropped: u64,
        queue_len: usize,
    };

    pub fn getMetrics(self: *const QueuedStateRegen) Metrics {
        const mutable_self: *QueuedStateRegen = @constCast(self);
        mutable_self.mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.mutex.unlock(mutable_self.io);
        return .{
            .cache_hits = mutable_self.cache_hits,
            .queue_hits = mutable_self.queue_hits,
            .dropped = mutable_self.dropped,
            .queue_len = mutable_self.activeRequestCountLocked(),
        };
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn noteCacheHit(self: *QueuedStateRegen) void {
        self.mutex.lockUncancelable(self.io);
        self.cache_hits += 1;
        self.mutex.unlock(self.io);
    }

    fn resolveSlowPath(
        self: *QueuedStateRegen,
        key: RegenKey,
        priority: RegenPriority,
        prepared_input: SlowPathInput,
    ) !?*CachedBeaconState {
        var owned_input = prepared_input;
        errdefer owned_input.deinit(self.regen);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        try self.getOrCreateRequestLocked(key, priority, &owned_input);
        owned_input = .none;

        while (true) {
            const idx = self.findRequestIndexLocked(key) orelse return error.RequestDropped;
            const request = &self.requests.items[idx];

            switch (request.stage) {
                .pending, .running, .publishing => {
                    self.cond.waitUncancelable(self.io, &self.mutex);
                },
                .ready_unpublished => {
                    const transient = switch (request.completion.?) {
                        .transient => |state| state,
                        else => unreachable,
                    };
                    request.stage = .publishing;
                    request.completion = null;
                    self.mutex.unlock(self.io);

                    const published_completion: SlowPathCompletion = blk: {
                        const published = self.publishSlowPathResult(key, transient) catch |err| {
                            self.regen.destroyTransientState(transient);
                            break :blk .{ .err = err };
                        };
                        break :blk if (published) |state| .{ .published = state } else .no_state;
                    };

                    self.mutex.lockUncancelable(self.io);
                    const publish_idx = self.findRequestIndexLocked(key) orelse return error.RequestDropped;
                    const publish_request = &self.requests.items[publish_idx];
                    publish_request.stage = .ready;
                    publish_request.completion = published_completion;
                    self.cond.broadcast(self.io);
                },
                .ready => {
                    const completion = request.completion.?;
                    request.waiters -= 1;
                    if (request.waiters == 0) {
                        var removed = self.requests.orderedRemove(idx);
                        removed.deinit(self.regen);
                    }

                    switch (completion) {
                        .published => |state| return state,
                        .no_state => return null,
                        .err => |err| return err,
                        .transient => unreachable,
                    }
                },
            }
        }
    }

    fn getOrCreateRequestLocked(
        self: *QueuedStateRegen,
        key: RegenKey,
        priority: RegenPriority,
        input: *SlowPathInput,
    ) !void {
        if (self.findRequestIndexLocked(key)) |idx| {
            const request = &self.requests.items[idx];
            request.waiters += 1;
            if (priority.isHigherOrEqual(request.priority)) {
                request.priority = priority;
            }
            input.deinit(self.regen);
            return;
        }

        if (self.activeRequestCountLocked() >= self.max_queue_len) {
            if (!self.dropLowestPriorityLocked(priority)) {
                return error.QueueFull;
            }
        }

        try self.requests.append(self.allocator, .{
            .key = key,
            .priority = priority,
            .waiters = 1,
            .stage = .pending,
            .input = input.*,
        });
        input.* = .none;
        self.queue_hits += 1;
        self.cond.signal(self.io);
    }

    fn publishSlowPathResult(
        self: *QueuedStateRegen,
        key: RegenKey,
        transient: *CachedBeaconState,
    ) !?*CachedBeaconState {
        return switch (key) {
            .checkpoint => |cp| try self.regen.publishCheckpointReloadedState(cp, transient),
            .pre_state, .state_root => try self.regen.publishLoadedState(transient),
            else => unreachable,
        };
    }

    fn findRequestIndexLocked(self: *QueuedStateRegen, key: RegenKey) ?usize {
        for (self.requests.items, 0..) |request, idx| {
            if (request.key.eql(key)) return idx;
        }
        return null;
    }

    fn activeRequestCountLocked(self: *QueuedStateRegen) usize {
        return self.requests.items.len;
    }

    fn workerMain(self: *QueuedStateRegen) void {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            while (true) {
                if (self.shutdown_requested and self.findHighestPriorityPendingLocked() == null) {
                    self.mutex.unlock(self.io);
                    return;
                }

                if (self.findHighestPriorityPendingLocked()) |idx| {
                    const request = &self.requests.items[idx];
                    request.stage = .running;
                    const key = request.key;
                    var input = request.input;
                    request.input = .none;
                    self.mutex.unlock(self.io);
                    defer input.deinit(self.regen);

                    const completion = self.computeSlowPathResult(key, &input);

                    self.mutex.lockUncancelable(self.io);
                    if (self.findRequestIndexLocked(key)) |complete_idx| {
                        const complete_request = &self.requests.items[complete_idx];
                        complete_request.completion = completion;
                        complete_request.stage = switch (completion) {
                            .transient => .ready_unpublished,
                            else => .ready,
                        };
                        self.cond.broadcast(self.io);
                    } else switch (completion) {
                        .transient => |state| self.regen.destroyTransientState(state),
                        else => {},
                    }
                    break;
                }

                self.cond.waitUncancelable(self.io, &self.mutex);
            }
            self.mutex.unlock(self.io);
        }
    }

    fn computeSlowPathResult(
        self: *QueuedStateRegen,
        key: RegenKey,
        input: *SlowPathInput,
    ) SlowPathCompletion {
        return switch (key) {
            .checkpoint => blk: {
                const prepared = switch (input.*) {
                    .checkpoint => |*prepared| prepared,
                    .none => break :blk .{ .err = error.RequestDropped },
                };
                const transient = self.regen.loadCheckpointStateUncached(prepared) catch |err| {
                    break :blk .{ .err = err };
                };
                break :blk if (transient) |state| .{ .transient = state } else .no_state;
            },
            .pre_state => |ps| blk: {
                const transient = self.regen.loadPreStateUncached(
                    ps.parent_block_root,
                    ps.parent_state_root,
                    ps.block_slot,
                ) catch |err| switch (err) {
                    error.NoPreStateAvailable => break :blk .no_state,
                    else => break :blk .{ .err = err },
                };
                break :blk .{ .transient = transient };
            },
            .state_root => |state_root| blk: {
                const transient = self.regen.loadStateByRootUncached(state_root) catch |err| {
                    break :blk .{ .err = err };
                };
                break :blk if (transient) |state| .{ .transient = state } else .no_state;
            },
            else => .{ .err = error.RequestDropped },
        };
    }

    fn findHighestPriorityPendingLocked(self: *QueuedStateRegen) ?usize {
        var best_idx: ?usize = null;
        var best_priority: RegenPriority = .background;

        for (self.requests.items, 0..) |request, idx| {
            if (request.stage != .pending) continue;
            if (best_idx == null or request.priority.isHigherOrEqual(best_priority)) {
                best_idx = idx;
                best_priority = request.priority;
            }
        }

        return best_idx;
    }

    fn dropLowPriorityLocked(self: *QueuedStateRegen, min_priority: RegenPriority) void {
        var i: usize = 0;
        while (i < self.requests.items.len) {
            const request = &self.requests.items[i];
            if (request.stage == .pending and !request.priority.isHigherOrEqual(min_priority)) {
                request.stage = .ready;
                request.completion = .{ .err = error.RequestDropped };
                self.dropped += 1;
            }
            i += 1;
        }
    }

    /// Drop the single lowest-priority request that has priority strictly
    /// lower than `min_priority`. Returns true if something was dropped.
    fn dropLowestPriority(self: *QueuedStateRegen, min_priority: RegenPriority) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.dropLowestPriorityLocked(min_priority);
    }

    fn dropLowestPriorityLocked(self: *QueuedStateRegen, min_priority: RegenPriority) bool {
        var worst_idx: ?usize = null;
        var worst_priority: RegenPriority = min_priority;

        for (self.requests.items, 0..) |request, idx| {
            if (request.stage != .pending) continue;
            if (!request.priority.isHigherOrEqual(worst_priority)) {
                worst_priority = request.priority;
                worst_idx = idx;
            }
        }

        if (worst_idx) |idx| {
            const request = &self.requests.items[idx];
            request.stage = .ready;
            request.completion = .{ .err = error.RequestDropped };
            self.dropped += 1;
            self.cond.broadcast(self.io);
            return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const RegenRuntimeFixture = @import("test_fixture.zig").RegenRuntimeFixture;

test "QueuedStateRegen: init and deinit" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var queued = QueuedStateRegen.init(allocator, std.testing.io, fixture.regen);
    try queued.start();
    defer queued.deinit();

    try std.testing.expectEqual(@as(usize, 0), queued.queueLen());
    try std.testing.expect(queued.canAcceptWork());
}

test "QueuedStateRegen: getPreState cache hit" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var queued = QueuedStateRegen.init(allocator, std.testing.io, fixture.regen);
    try queued.start();
    defer queued.deinit();

    // Add a state to block cache.
    const state = try fixture.clonePublishedState();
    const root = try fixture.regen.onNewBlock(state, true);
    const parent_slot = try state.state.slot();
    const block_slot = parent_slot;

    // getPreState should find it via cache.
    const result = try queued.getPreState(root, root, parent_slot, block_slot, .block_import);
    try std.testing.expectEqual(state, result);
    try std.testing.expectEqual(@as(u64, 1), queued.cache_hits);
}

test "QueuedStateRegen: getStateByRoot slow path publishes loaded state" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var queued = QueuedStateRegen.init(allocator, std.testing.io, fixture.regen);
    try queued.start();
    defer queued.deinit();

    const archived = try fixture.clonePublishedState();
    defer {
        archived.deinit();
        allocator.destroy(archived);
    }
    try archived.state.commit();
    const archived_state_root = (try archived.state.hashTreeRoot()).*;
    const archived_slot = try archived.state.slot();
    const archived_bytes = try archived.state.serialize(allocator);
    defer allocator.free(archived_bytes);
    try fixture.db.putStateArchive(archived_slot, archived_state_root, archived_bytes);

    const loaded = (try queued.getStateByRoot(archived_state_root, .api)).?;

    try std.testing.expectEqual(archived_slot, try loaded.state.slot());
    try std.testing.expectEqual(loaded, fixture.block_cache.get(archived_state_root).?);
    try std.testing.expectEqual(@as(u64, 1), queued.queue_hits);
}

test "QueuedStateRegen: getPreState slow path publishes loaded state" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var queued = QueuedStateRegen.init(allocator, std.testing.io, fixture.regen);
    try queued.start();
    defer queued.deinit();

    const archived = try fixture.clonePublishedState();
    defer {
        archived.deinit();
        allocator.destroy(archived);
    }
    try archived.state.commit();
    const archived_state_root = (try archived.state.hashTreeRoot()).*;
    const archived_slot = try archived.state.slot();
    const archived_bytes = try archived.state.serialize(allocator);
    defer allocator.free(archived_bytes);
    try fixture.db.putStateArchive(archived_slot, archived_state_root, archived_bytes);

    const loaded = try queued.getPreState(
        [_]u8{0x11} ** 32,
        archived_state_root,
        archived_slot,
        archived_slot + 1,
        .block_import,
    );

    try std.testing.expectEqual(archived_slot, try loaded.state.slot());
    try std.testing.expectEqual(loaded, fixture.block_cache.get(archived_state_root).?);
    try std.testing.expectEqual(@as(u64, 1), queued.queue_hits);
}

test "QueuedStateRegen: getCheckpointState slow path publishes reloaded state" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var queued = QueuedStateRegen.init(allocator, std.testing.io, fixture.regen);
    try queued.start();
    defer queued.deinit();

    const seed = try fixture.clonePublishedState();
    _ = try fixture.regen.onNewBlock(seed, true);
    fixture.cp_cache.max_epochs_in_memory = 1;

    const cp1 = CheckpointKey{ .epoch = 1, .root = [_]u8{0x11} ** 32 };
    const cp2 = CheckpointKey{ .epoch = 2, .root = [_]u8{0x22} ** 32 };
    try fixture.regen.onCheckpoint(cp1, try fixture.clonePublishedState());
    try fixture.regen.onCheckpoint(cp2, try fixture.clonePublishedState());

    _ = try fixture.cp_cache.processState([_]u8{0xff} ** 32, fixture.published_state);
    try std.testing.expect(fixture.cp_cache.get(cp1) == null);
    try std.testing.expectEqual(@as(usize, 1), fixture.cp_datastore.count());

    const loaded = (try queued.getCheckpointState(cp1, .api)).?;
    try std.testing.expectEqual(loaded, fixture.cp_cache.get(cp1));
    try std.testing.expectEqual(@as(u64, 1), queued.queue_hits);
    try std.testing.expectEqual(@as(usize, 1), fixture.cp_datastore.count());
}

test "QueuedStateRegen: onNewBlock delegates to regen" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var queued = QueuedStateRegen.init(allocator, std.testing.io, fixture.regen);
    try queued.start();
    defer queued.deinit();

    // onNewBlock should delegate to regen.
    const state = try fixture.clonePublishedState();
    const root = try queued.onNewBlock(state, true);
    try std.testing.expect(fixture.block_cache.get(root) != null);
}

test "QueuedStateRegen: metrics tracking" {
    const allocator = std.testing.allocator;
    var fixture = try RegenRuntimeFixture.init(allocator, 16);
    defer fixture.deinit();

    var queued = QueuedStateRegen.init(allocator, std.testing.io, fixture.regen);
    try queued.start();
    defer queued.deinit();

    // Add a state.
    const state = try fixture.clonePublishedState();
    const root = try fixture.regen.onNewBlock(state, true);
    const parent_slot = try state.state.slot();
    const block_slot = parent_slot;

    // Cache hit.
    _ = try queued.getPreState(root, root, parent_slot, block_slot, .block_import);

    const m = queued.getMetrics();
    try std.testing.expectEqual(@as(u64, 1), m.cache_hits);
    try std.testing.expectEqual(@as(u64, 0), m.queue_hits);
    try std.testing.expectEqual(@as(u64, 0), m.dropped);
}
