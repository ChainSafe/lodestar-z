const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const types = @import("consensus_types");
const state_transition = @import("state_transition");
const BeaconConfig = @import("config").BeaconConfig;
const time = @import("time");
const SlotClock = @import("clock").SlotClock;

const CheckpointContext = @import("key.zig").CheckpointContext;
const DatastoreKey = @import("key.zig").DatastoreKey;
const datastoreKey = @import("key.zig").datastoreKey;

const cp_datastore = @import("cp_datastore.zig");
const CPStateDatastore = cp_datastore.CPStateDatastore;

const metrics = @import("metrics.zig");

const BlockStateCache = @import("block_state_cache.zig").BlockStateCache;
const StateCacheItem = @import("block_state_cache.zig").StateCacheItem;
const buffer_pool = @import("../../util/buffer_pool.zig");
const BufferPool = buffer_pool.BufferPool;

const CachedBeaconState = state_transition.CachedBeaconState;
const computeStartSlotAtEpoch = state_transition.computeStartSlotAtEpoch;
const Root = types.primitive.Root.Type;
const Epoch = types.primitive.Epoch.Type;

const log = std.log.scoped(.checkpoint_state_cache);

// Basis points into a slot (66.67%) at which to persist checkpoint states: the most idle part of the
// slot, so the disk-heavy persist doesn't contend with block processing at slot start.
const PROCESS_CHECKPOINT_STATES_BPS = 6667;

//
// A checkpoint is `(epoch, root)` with `root = get_block_root_at_slot(epoch * SLOTS_PER_EPOCH)` —
// the block at (or before) the epoch's first slot ("slot 0", the boundary slot
// `epoch * SLOTS_PER_EPOCH`).
//
// Per epoch there are two KINDS, by where that root sits relative to slot 0:
//   - CRCS (Current Root Checkpoint State):  root IS the block AT slot 0; only when that slot has a
//     block.
//   - PRCS (Previous Root Checkpoint State): root is an EARLIER block (the previous epoch's last
//     block), used when slot 0 is skipped / not yet processed.
//
// Recent epochs live in memory; older ones spill to disk (db/fs), regen'd/reloaded on demand:
//
// ╔══════════════════════════════════════╦══════════════════════════╗
// ║  persisted to disk (older epochs)    ║ in memory (recent epochs)║
// ║  reload on demand                    ║                          ║
// ╠══════════════════════════════════════╬══════════════════════════╣
// ║  epoch:    (n-2)       (n-1)         ║    n          (n+1)      ║
// ║            1 cp        1 cp          ║    PRCS+CRCS  PRCS+CRCS  ║
// ╚══════════════════════════════════════╩══════════════════════════╝
//
// IN MEMORY keeps BOTH kinds per epoch (PRCS and CRCS), as the old all-in-memory cache did.
//
// ON DISK keeps only the boundary cp (the one that could be justified/finalized later based on the
// view of the state). With NO reorg, exactly 1 per epoch:
//   slot 0 has a block → persist CRCS, prune the same-chain PRCS (it's regen'able)
//   slot 0 is skipped  → persist PRCS (no CRCS exists)
//
// With a REORG, competing forks give the epoch DIFFERENT boundary roots; disk keeps ≥2 distinct
// roots per epoch (including any unknown to the processed state) as reorg-survival insurance, each
// independently PRCS- or CRCS-kind. The goal is to always be able to regen any state and to hold the
// checkpoint state that could be justified/finalized later.
//
// By default we don't prune any persistent checkpoint states as it's not safe to delete them during
// long non-finality as we don't know the state of the chain and there could be a deep (hundreds of
// epochs) reorg if there are two competing chains with similar weight but we wouldn't have a close
// enough state to pivot to and instead require a resync from last finalized checkpoint state which
// could be very far in the past. pruneFinalized clears epochs below finality once it advances.

/// Store the 3 most recent checkpoint states in memory and the rest on disk. The finalized state may
/// not be available in memory, and stay on disk instead.
pub const DEFAULT_MAX_EPOCHS_IN_MEMORY: usize = 3;

pub const Checkpoint = @import("key.zig").Checkpoint;

const CacheItem = union(enum) {
    in_memory: InMemory,
    persisted: DatastoreKey,
};

/// A cache value plus read-tracking counters (feed the `reads` / `seconds_since_last_read` gauges via
/// `scanCpReadStats`).
const Entry = struct {
    item: CacheItem,
    read_count: u64 = 0,
    last_read: ?std.Io.Timestamp = null,
};

const InMemory = struct {
    /// OWNED by the cache.
    state: *CachedBeaconState,
    /// Present if a disk copy also exists, so the state need not be re-persisted and can be
    /// removed from disk later.
    persisted_key: ?DatastoreKey,
};

const StateOrBytes = union(enum) {
    /// Borrowed in-memory state (caller must NOT deinit).
    state: *CachedBeaconState,
    /// Owned bytes read from disk (caller frees with the cache allocator).
    bytes: []u8,
};

const LoadResult = union(enum) {
    state: *CachedBeaconState,
    /// A disk hit: the persisted key and the owned bytes (caller frees with the cache allocator).
    loaded: struct { persisted_key: DatastoreKey, state_bytes: []u8 },
};

const ScratchBytes = union(enum) {
    leased: buffer_pool.BufferLease,
    owned: []u8,

    fn bytes(self: ScratchBytes) []u8 {
        return switch (self) {
            .leased => |l| l.bytes,
            .owned => |o| o,
        };
    }

    fn deinit(self: ScratchBytes, allocator: Allocator) void {
        switch (self) {
            .leased => |l| l.release(),
            .owned => |o| allocator.free(o),
        }
    }
};

/// An implementation of CheckpointStateCache that keep up to n epoch checkpoint states in memory and
/// persist the rest to disk.
/// - If it's more than `max_epochs_in_memory` epochs old, it will persist n last epochs to disk based
///   on the view of the block.
/// - Once a chain gets finalized we'll prune all states from memory and disk for epochs <
///   finalized_epoch.
/// - In get*() apis if shouldReload is true, it will reload from disk. The reload() api is expensive
///   and should only be called in some important flows: get state for block processing, updateHeadState.
/// - Each time we process a state, we only persist exactly 1 checkpoint state per epoch based on the
///   view of block and prune all others. The persisted checkpoint state could be finalized and used
///   later in archive task, it's also used to regen states.
/// - When we process multiple states in the same epoch, we could persist different checkpoint states
///   of the same epoch because each block could have its own view.
///
pub const PersistentCheckpointStateCache = struct {
    const CacheMap = std.HashMapUnmanaged(
        Checkpoint,
        Entry,
        CheckpointContext,
        std.hash_map.default_max_load_percentage,
    );
    const EpochIndex = std.AutoArrayHashMapUnmanaged(Epoch, std.ArrayListUnmanaged(Root));

    allocator: Allocator,
    config: *const BeaconConfig,
    cache: CacheMap,
    epoch_index: EpochIndex,
    datastore: CPStateDatastore,
    block_state_cache: *BlockStateCache,
    max_epochs_in_memory: usize,
    max_epochs_on_disk: ?usize,
    pre_computed_checkpoint: ?Checkpoint,
    pre_computed_checkpoint_hits: ?u64,
    slot_clock: ?*const SlotClock,
    buffer_pool: ?*BufferPool,

    pub const Opts = struct {
        /// Keep max n state epochs in memory, persist the rest to disk. 0 = persist-everything: every
        /// checkpoint is written to disk and pruned from memory by `processState`; reloads then seed
        /// from the block-state cache.
        max_epochs_in_memory: usize = DEFAULT_MAX_EPOCHS_IN_MEMORY,
        /// Keep max n state epochs on disk; null (the default) = unbounded, never prunes (see the
        /// file-level note on non-finality). A finite value prunes the oldest persisted epochs.
        max_epochs_on_disk: ?usize = null,
        /// Borrowed slot clock for slot-relative timing. Null (the default) disables the persist
        /// throttle and reports the slot-relative metrics as 0.
        slot_clock: ?*const SlotClock = null,
        /// Borrowed reusable serialization buffer. Null (the default) always allocates fresh.
        buffer_pool: ?*BufferPool = null,
    };

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        config: *const BeaconConfig,
        datastore: CPStateDatastore,
        block_state_cache: *BlockStateCache,
        opts: Opts,
    ) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .cache = .empty,
            .epoch_index = .empty,
            .datastore = datastore,
            .block_state_cache = block_state_cache,
            .max_epochs_in_memory = opts.max_epochs_in_memory,
            .max_epochs_on_disk = opts.max_epochs_on_disk,
            .pre_computed_checkpoint = null,
            .pre_computed_checkpoint_hits = null,
            .slot_clock = opts.slot_clock,
            .buffer_pool = opts.buffer_pool,
        };
    }

    /// Deinit every in-memory state and the cache structures (not the borrowed datastore / block-state
    /// cache / config).
    pub fn deinit(self: *Self) void {
        // clear() frees every in-memory state and every epoch list, leaving both containers empty (but
        // capacity-retaining); deinit then releases that retained capacity.
        self.clear();
        self.cache.deinit(self.allocator);
        self.epoch_index.deinit(self.allocator);
    }

    /// Reload checkpoint state keys from the last run.
    pub fn initFromDisk(self: *Self, io: std.Io) !void {
        try self.datastore.initStore(io);
        const keys = try self.datastore.readKeys(io, self.allocator);
        defer self.allocator.free(keys);

        // all checkpoint states from the last run are not trusted, remove them; otherwise if we have a
        // bad checkpoint state from the last run, the node get stucked.
        try self.datastore.removeMany(io, self.allocator, keys);
    }

    /// Similar to `getOrReload()` api without reloading from disk. Returns a borrowed in-memory state the
    /// cache owns (do NOT deinit; `.clone()` to retain past the next mutation); a persisted-only entry
    /// returns null.
    pub fn get(self: *Self, io: std.Io, cp: Checkpoint) ?*CachedBeaconState {
        metrics.checkpoint().lookups.incr();
        const entry = self.cache.getPtr(cp) orelse return null;
        metrics.checkpoint().hits.incr();

        if (self.pre_computed_checkpoint) |pre| {
            if (CheckpointContext.eql(.{}, pre, cp)) {
                if (self.pre_computed_checkpoint_hits) |*h| h.* += 1;
            }
        }

        recordRead(io, entry);

        switch (entry.item) {
            .in_memory => |im| {
                metrics.checkpoint().state_cloned_count.observe(im.state.cloned_count);
                return im.state;
            },
            .persisted => return null,
        }
    }

    /// Record one logical read of a cache item: bump `read_count` and stamp `last_read`. Both public
    /// gets and internal housekeeping reads are recorded, so the gauges reflect all logical reads.
    fn recordRead(io: std.Io, entry: *Entry) void {
        entry.read_count += 1;
        entry.last_read = time.start(io);
    }

    /// Add a state of a checkpoint to this cache, prune from memory if necessary. Takes ownership of
    /// `state` only on success (the caller frees it on a failed insert). A persisted entry keeps its
    /// disk key, so the state is set back to memory without re-persisting.
    pub fn add(self: *Self, io: std.Io, cp: Checkpoint, state: *CachedBeaconState) !void {
        metrics.checkpoint().adds.incr();

        // Carry an existing entry's disk key forward so the state need not be re-persisted; the read
        // also bumps that entry's tracking. insertEntry destroys any displaced resident (last writer
        // wins); a same-pointer re-add is a no-op there.
        const persisted_key: ?DatastoreKey = blk: {
            const entry = self.cache.getPtr(cp) orelse break :blk null;
            recordRead(io, entry);
            break :blk switch (entry.item) {
                .in_memory => |im| im.persisted_key,
                .persisted => |dk| dk,
            };
        };

        try self.insertEntry(cp, .{ .in_memory = .{ .state = state, .persisted_key = persisted_key } });

        // Post-commit: the cache already owns `state`, so propagating would misreport ownership to a
        // caller that frees on failure. The next pre-commit allocation surfaces the OOM cleanly.
        self.prunePersistedStates(io) catch |err| {
            log.err("add: prune-persisted failed: {s}", .{@errorName(err)});
        };
    }

    fn rootListContains(list: *const std.ArrayListUnmanaged(Root), root: Root) bool {
        for (list.items) |r| {
            if (std.mem.eql(u8, &r, &root)) return true;
        }
        return false;
    }

    /// Searches in-memory state for the latest cached state with a `root` without reload, considering
    /// only epochs <= `max_epoch` and descending, returning the first in-memory hit — a borrowed pointer
    /// the cache owns (do NOT deinit; `.clone()` to retain past the next mutation).
    pub fn getLatest(self: *Self, io: std.Io, root: Root, max_epoch: Epoch) ?*CachedBeaconState {
        // Tracked epochs + roots-per-epoch are both small, so a descending linear scan should be enough
        // and stays alloc-free, keeping this read infallible.
        var tried_below: ?Epoch = null;
        while (true) {
            var best: ?Epoch = null;
            for (self.epoch_index.keys(), self.epoch_index.values()) |candidate, *roots| {
                if (candidate > max_epoch) continue;
                if (tried_below) |tried| if (candidate >= tried) continue;
                if (!rootListContains(roots, root)) continue;
                if (best == null or candidate > best.?) best = candidate;
            }
            const epoch = best orelse return null;
            if (self.get(io, .{ .root = root, .epoch = epoch })) |state| return state;
            tried_below = epoch;
        }
    }

    /// Get the latest cached state for `root`, reloading from disk if needed. Considers only epochs
    /// <= `max_epoch`, descending. Returns a borrowed pointer the cache owns (do NOT deinit; `.clone()`
    /// to retain past the next mutation), or null on a miss.
    ///
    /// Expensive — only for important flows:
    /// - validate a gossip block
    /// - get block for processing
    /// - regen head state
    ///
    /// Per-candidate `getOrReload` faults follow the same rule as `getOrReload`:
    /// - OOM propagates (regen can't recover from memory exhaustion)
    /// - any other fault (corrupt blob, IO) is logged and treated as a miss; the scan moves on (safe
    ///   because `getOrReload` leaves no half-state on failure)
    pub fn getOrReloadLatest(self: *Self, io: std.Io, root: Root, max_epoch: Epoch) !?*CachedBeaconState {
        // Same small-scan rationale as `getLatest`, reloading each candidate.
        var tried_below: ?Epoch = null;
        while (true) {
            var best: ?Epoch = null;
            for (self.epoch_index.keys(), self.epoch_index.values()) |candidate, *roots| {
                if (candidate > max_epoch) continue;
                if (tried_below) |tried| if (candidate >= tried) continue;
                if (!rootListContains(roots, root)) continue;
                if (best == null or candidate > best.?) best = candidate;
            }
            const epoch = best orelse return null;
            const cp = Checkpoint{ .root = root, .epoch = epoch };
            const reloaded = self.getOrReload(io, cp) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    log.debug("get-or-reload-latest: epoch {d}: {s}", .{ epoch, @errorName(err) });
                    tried_below = epoch;
                    continue;
                },
            };
            if (reloaded) |s| return s;
            tried_below = epoch;
        }
    }

    fn secFromCurrentSlot(self: *const Self) f64 {
        const clock = self.slot_clock orelse return 0;
        return @as(f64, @floatFromInt(clock.msFromSlot(clock.currentSlotOrGenesis(), null))) / 1000.0;
    }

    /// Get a state from cache, it may reload from disk.
    /// This is an expensive api, should only be called in some important flows:
    /// - Validate a gossip block
    /// - Get block for processing
    /// - Regen head state
    ///
    /// Returns a borrowed pointer the cache owns (do NOT deinit; `.clone()` to retain past the next
    /// mutation), or null in two cases:
    /// - a genuine miss: not in memory or on disk, or on disk but with no seed state to reload from
    /// - a reload fault (e.g. a corrupt persisted blob) swallowed to a miss so regen can recover
    ///
    /// Only reload faults degrade to null; OOM and datastore/seed-lookup read errors propagate.
    pub fn getOrReload(self: *Self, io: std.Io, cp: Checkpoint) !?*CachedBeaconState {
        const load = (try self.getStateOrLoadDb(io, cp)) orelse return null;
        switch (load) {
            .state => |s| return s,
            .loaded => {},
        }
        const persisted_key = load.loaded.persisted_key;
        const state_bytes = load.loaded.state_bytes;
        defer self.allocator.free(state_bytes);

        metrics.checkpoint().state_reload_sec_from_slot.observe(self.secFromCurrentSlot());

        const seed = (try self.findSeedStateToReload(io, cp)) orelse return null;

        const seed_epoch = state_transition.computeEpochAtSlot(try seed.state.slot());
        const diff = if (seed_epoch > cp.epoch) seed_epoch - cp.epoch else cp.epoch - seed_epoch;
        metrics.checkpoint().state_reload_epoch_diff.observe(diff);

        return self.reloadFromSeed(io, seed, cp, state_bytes, persisted_key) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return null,
        };
    }

    fn reloadFromSeed(self: *Self, io: std.Io, seed: *CachedBeaconState, cp: Checkpoint, state_bytes: []const u8, persisted_key: DatastoreKey) !*CachedBeaconState {
        const serialize_start = time.start(io);
        const validators_size = try seed.state.validatorsSerializedSize();
        const validators_scratch = try self.acquireScratch(
            validators_size,
            .persistent_checkpoints_cache_validators,
        );
        defer validators_scratch.deinit(self.allocator);
        const seed_validators_bytes = validators_scratch.bytes();
        _ = try seed.state.serializeValidatorsIntoBytes(seed_validators_bytes);

        metrics.checkpoint().state_reload_validators_serialize_duration.observe(time.secondsSince(io, serialize_start));

        if (validators_scratch == .owned) {
            metrics.checkpoint().state_reload_validators_serialize_alloc_count.incr();
        }

        const reload_start = time.start(io);
        const new_cached = try seed.loadOtherState(self.allocator, self.config, state_bytes, seed_validators_bytes, .{ .preload_validators_and_balances = true });

        var owned_cached: ?*CachedBeaconState = new_cached;
        errdefer if (owned_cached) |s| destroyState(s);

        _ = try new_cached.state.hashTreeRoot();
        metrics.checkpoint().state_reload_duration.observe(time.secondsSince(io, reload_start));

        // only remove persisted state once we reload successfully, so keep `persisted_key`. A resident
        // added for this cp during the earlier datastore-read suspension is displaced here — insertEntry
        // destroys it (last writer wins) once the insert commits.
        try self.insertEntry(cp, .{ .in_memory = .{ .state = new_cached, .persisted_key = persisted_key } });
        owned_cached = null;
        return new_cached;
    }

    /// Return either state or state bytes loaded from db. When bytes are returned the caller OWNS them
    /// (frees with the cache allocator).
    pub fn getStateOrBytes(self: *Self, io: std.Io, cp: Checkpoint) !?StateOrBytes {
        const load = (try self.getStateOrLoadDb(io, cp)) orelse return null;
        return switch (load) {
            .state => |s| .{ .state = s },
            .loaded => |l| .{ .bytes = l.state_bytes },
        };
    }

    /// Return either state or state bytes with persisted key loaded from db (persisted bytes owned by
    /// the caller). A missing entry returns null.
    pub fn getStateOrLoadDb(self: *Self, io: std.Io, cp: Checkpoint) !?LoadResult {
        if (self.get(io, cp)) |state| return .{ .state = state };

        const entry = self.cache.getPtr(cp) orelse return null;
        recordRead(io, entry);
        switch (entry.item) {
            // `get` above returns for every in-memory entry, so a remaining entry is always persisted.
            .in_memory => unreachable,
            .persisted => |dk| {
                const read_start = time.start(io);
                const bytes = (try self.datastore.read(io, self.allocator, dk)) orelse return null;
                metrics.checkpoint().state_reload_db_read_time.observe(time.secondsSince(io, read_start));
                return .{ .loaded = .{ .persisted_key = dk, .state_bytes = bytes } };
            },
        }
    }

    /// Update the precomputed checkpoint and return the number of hits for the previous one (if any).
    pub fn updatePreComputedCheckpoint(self: *Self, root: Root, epoch: Epoch) ?u64 {
        const prev = self.pre_computed_checkpoint_hits;
        self.pre_computed_checkpoint = .{ .root = root, .epoch = epoch };
        self.pre_computed_checkpoint_hits = 0;
        return prev;
    }

    /// No-op: real pruning is `pruneFinalized` (driven from `processState`) + `prunePersistedStates`
    /// (driven from `add`).
    pub fn prune(self: *Self) void {
        _ = self;
    }

    /// Prune all checkpoint states (memory AND disk) before the provided finalized epoch. A per-epoch
    /// `deleteAllEpochItems` failure is logged + skipped, retried on the next finalization; only OOM
    /// propagates. Walks backwards: a successful delete swapRemoves the epoch key, moving an
    /// already-visited tail key into the slot, so `i` always just decrements.
    fn pruneFinalized(self: *Self, io: std.Io, finalized_epoch: Epoch) error{OutOfMemory}!void {
        var i: usize = self.epoch_index.count();
        while (i > 0) {
            i -= 1;
            const epoch = self.epoch_index.keys()[i];
            if (epoch >= finalized_epoch) continue;
            self.deleteAllEpochItems(io, epoch) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => log.debug("prune-finalized: delete epoch {d} failed: {s}", .{ epoch, @errorName(err) }),
            };
        }
    }

    /// After processing a block, prune from memory based on the view of that block, persisting the
    /// excess (oldest) epochs to disk. Returns the count of states freshly serialized+written.
    /// Likely persists 1 state per epoch. Given block `b` was processed with `b2`, `b1`, `b0` its
    /// ancestors in epochs (n-2), (n-1), n respectively:
    ///
    ///   epoch:          (n-2)       (n-1)         n         (n+1)
    ///         |-----------|-----------|-----------|-----------|
    ///                    ^            ^           ^    ^
    ///                    |            |           |    |
    ///   chain:          b2---------->b1--------->b0-->b
    ///
    /// After processing `b`, if `max_epochs_in_memory` is:
    ///   - 2: persist {root: b2, epoch: n-2}
    ///   - 1: persist {root: b2, epoch: n-2} and {root: b1, epoch: n-1}
    ///   - 0: persist all of {root: b2, epoch: n-2}, {root: b1, epoch: n-1}, {root: b0, epoch: n}
    ///        (any already-persisted epoch is skipped, not re-written)
    ///
    /// Note that for each epoch there could be multiple checkpoint states, usually 2, one for Previous
    /// Root Checkpoint State and one for Current Root Checkpoint State. We normally only persist 1
    /// checkpoint state per epoch, the one that could potentially be justified/finalized later based on
    /// the view of the block. Other checkpoint states are pruned from memory.
    ///
    /// This design also covers the reorg scenario. Given block `c` in epoch n with `c.slot > b.slot`,
    /// `c` not a descendant of `b`, built on `c0` (epoch n) instead of `b0`:
    ///
    ///   epoch:          (n-2)       (n-1)         n         (n+1)
    ///         |-----------|-----------|-----------|-----------|
    ///                    ^            ^       ^   ^    ^   ^
    ///                    |            |       |   |    |   |
    ///   chain:          b2---------->b1----->c0->b0-->b   |
    ///                                        ║            |
    ///                                        ╚═══════════►c (reorg)
    ///
    /// After processing `c`, if `max_epochs_in_memory` is:
    ///   - 0: persist {root: c0, epoch: n} (regen should have populated it first). Reload regenerates
    ///        `c`'s state from disk through the seed chain:
    ///
    ///     ╔════════╗   reload    ┌──────────────────────┐   ┌─────────────┐   ┌─────────────────────┐   ┌─────────────┐
    ///     ║   db   ║ ==========► │ {root: b1, epoch n-1}│=► │ c0 block    │=► │ {root: c0, epoch n} │=► │ c block     │
    ///     ║        ║             │ cp state             │   │ state       │   │ cp state            │   │ state       │
    ///     ╚════════╝             └──────────────────────┘   └─────────────┘   └─────────────────────┘   └─────────────┘
    ///
    ///   - 1: persist {root: b1, epoch: n-1}; epoch n keeps both {root: b0, epoch: n} and
    ///        {root: c0, epoch: n} in memory.
    ///   - 2: persist {root: b2, epoch: n-2}; epoch n keeps both states in memory (as in the =1 case).
    ///
    /// A per-epoch fault (view error, datastore IO) is logged + skipped; only OOM propagates.
    /// Idempotent — it re-runs each slot — so a missed epoch is re-attempted later.
    pub fn processState(self: *Self, io: std.Io, block_root: Root, state: *CachedBeaconState) !usize {
        // Prune finalized-below checkpoints first, in this same flow, so a finalized cp state is pruned
        // and never persisted.
        var finalized: types.phase0.Checkpoint.Type = undefined;
        try state.state.finalizedCheckpoint(&finalized);
        try self.pruneFinalized(io, finalized.epoch);

        if (self.epoch_index.count() <= self.max_epochs_in_memory) return 0;

        // Snapshot + ascending sort: in case of big reorg we always want to keep the most recent
        // checkpoint states.
        const epochs = try self.allocator.dupe(Epoch, self.epoch_index.keys());
        defer self.allocator.free(epochs);
        std.mem.sort(Epoch, epochs, {}, std.sort.asc(Epoch));

        const state_slot = try state.state.slot();

        // Defer the disk-heavy persist below to ~67% of the slot — the most idle part — so it doesn't
        // contend with block processing at slot start. At syncing time blocks arrive late, so we're
        // usually already past that point and persist immediately (critical to avoid OOM during
        // unfinality). With no clock (e.g. tests) there is no wait.
        if (self.slot_clock) |clock| {
            const process_cp_states_ms: i64 = @intCast(self.config.getSlotComponentDurationMs(PROCESS_CHECKPOINT_STATES_BPS));
            const ms_to_wait = process_cp_states_ms - clock.msFromSlot(state_slot, null);
            if (ms_to_wait > 0) {
                // Best-effort: a cancelled/failed sleep (e.g. shutdown) falls through to persist now.
                std.Io.sleep(io, std.Io.Duration.fromMilliseconds(ms_to_wait), .awake) catch {};
            }
        }

        var persist_count: usize = 0;
        for (epochs[0 .. epochs.len - self.max_epochs_in_memory]) |lowest_epoch| {
            // there is no checkpoint states of epochs newer than this state.
            if (state_slot < computeStartSlotAtEpoch(lowest_epoch)) break;
            // usually there is only 0 or 1 epoch to persist in this loop. Any per-epoch fault is
            // skip-and-continue (retried next slot); only OOM propagates.
            persist_count += self.processPastEpoch(io, block_root, state, lowest_epoch) catch |err| switch (err) {
                error.OutOfMemory => return err,
                error.SlotTooBig, error.SlotTooSmall => {
                    log.debug("process-state: skip epoch {d}: {s}", .{ lowest_epoch, @errorName(err) });
                    continue;
                },
                else => {
                    log.warn("process-state: persist epoch {d} failed: {s}", .{ lowest_epoch, @errorName(err) });
                    continue;
                },
            };
        }
        return persist_count;
    }

    /// Find a seed state to reload the state of provided checkpoint. We always reload an epoch in the
    /// past. We'll start with epoch n then (n+1) prioritizing ones with the same view of `cp`. Use seed
    /// state from the block cache if cannot find any seed states within this cache. Returns
    /// null when no seed exists at all (in-memory band empty AND block cache empty) — a cold-start /
    /// post-prune condition, not an error.
    fn findSeedStateToReload(self: *Self, io: std.Io, cp: Checkpoint) !?*CachedBeaconState {
        var max_epoch: ?Epoch = null;
        for (self.epoch_index.keys()) |epoch| {
            if (max_epoch == null or epoch > max_epoch.?) max_epoch = epoch;
        }

        if (max_epoch) |max_e| {
            const reloaded_cp_slot = computeStartSlotAtEpoch(cp.epoch);
            // no need to check epochs before `max_epoch - max_epochs_in_memory + 1` before they are all
            // persisted.
            const band_start = if (max_e + 1 > self.max_epochs_in_memory)
                max_e + 1 - self.max_epochs_in_memory
            else
                0;

            // `first_state` persists across iterations and is returned at the TOP of the NEXT one,
            // so the final band epoch (epoch == max_e) never returns its first state — it falls
            // through to the block-cache seed. The loop body never mutates `epoch_index`, so the
            // slice stays valid.
            var first_state: ?*CachedBeaconState = null;
            var epoch = band_start;
            while (epoch <= max_e) : (epoch += 1) {
                // if there's at least 1 state in memory in an earlier epoch, just return the 1st one.
                if (first_state) |fs| return fs;

                // An untracked epoch has no list, skipping the inner loop.
                const roots = if (self.epoch_index.getPtr(epoch)) |l| l.items else &[_]Root{};
                for (roots) |root| {
                    const entry = self.cache.getPtr(.{ .root = root, .epoch = epoch }) orelse continue;
                    recordRead(io, entry);
                    const im = switch (entry.item) {
                        .in_memory => |x| x,
                        .persisted => continue,
                    };
                    if (first_state == null) first_state = im.state;
                    const state_slot = try im.state.state.slot();
                    if (reloaded_cp_slot < state_slot) {
                        // amongst states of the same epoch, choose the one with the same view of cp.
                        // getBlockRootAtSlot may throw error (slot predates this candidate's block-roots
                        // window); skip on SlotTooBig/SlotTooSmall, propagate any other error.
                        const at_slot = im.state.getBlockRootAtSlot(reloaded_cp_slot) catch |e| switch (e) {
                            error.SlotTooBig, error.SlotTooSmall => {
                                log.debug("find-seed: epoch {d}: {s}", .{ epoch, @errorName(e) });
                                continue;
                            },
                            else => return e,
                        };
                        if (std.mem.eql(u8, at_slot, &cp.root)) return im.state;
                    }
                }
            }
        }

        // fallback to the block state cache's seed; null if it's empty too (cold-start, e.g. max=0
        // before any block is resident).
        return self.block_state_cache.getSeedState();
    }

    /// Deinit every in-memory state and clear both structures. Does NOT touch disk.
    pub fn clear(self: *Self) void {
        var it = self.cache.valueIterator();
        while (it.next()) |entry| {
            if (entry.item == .in_memory) destroyState(entry.item.in_memory.state);
        }
        self.cache.clearRetainingCapacity();
        for (self.epoch_index.values()) |*l| l.deinit(self.allocator);
        self.epoch_index.clearRetainingCapacity();
    }

    /// ONLY FOR DEBUGGING PURPOSES. For the debug API. Per-key summary across BOTH tiers; caller
    /// frees the slice. Reads the per-entry counters directly (no read bump). `slot` is the epoch's
    /// start slot and `root` the raw checkpoint root (hexing belongs to the route layer).
    pub fn dumpSummary(self: *Self, allocator: Allocator) ![]StateCacheItem {
        const out = try allocator.alloc(StateCacheItem, self.cache.count());
        errdefer allocator.free(out);

        var i: usize = 0;
        var it = self.cache.iterator();
        while (it.next()) |kv| {
            out[i] = .{
                .slot = computeStartSlotAtEpoch(kv.key_ptr.epoch),
                .root = kv.key_ptr.root,
                .reads = kv.value_ptr.read_count,
                .last_read = kv.value_ptr.last_read,
                .checkpoint_state = true,
            };
            i += 1;
        }
        return out;
    }

    /// ONLY FOR DEBUGGING PURPOSES. For the debug API. In-memory states only (BORROWED — the cache
    /// owns them, do NOT deinit; valid until the next cache mutation); caller frees the returned slice.
    pub fn getStates(self: *Self, allocator: Allocator) ![]*CachedBeaconState {
        var out: std.ArrayListUnmanaged(*CachedBeaconState) = .empty;
        errdefer out.deinit(allocator);
        var it = self.cache.valueIterator();
        while (it.next()) |entry| {
            switch (entry.item) {
                .in_memory => |im| try out.append(allocator, im.state),
                .persisted => {},
            }
        }
        return out.toOwnedSlice(allocator);
    }

    /// ONLY FOR DEBUGGING PURPOSES. For spec tests on error. All cache keys across BOTH tiers; caller
    /// frees the slice.
    pub fn dumpCheckpointKeys(self: *Self, allocator: Allocator) ![]Checkpoint {
        const out = try allocator.alloc(Checkpoint, self.cache.count());
        errdefer allocator.free(out);

        var i: usize = 0;
        var it = self.cache.keyIterator();
        while (it.next()) |key| {
            out[i] = key.*;
            i += 1;
        }
        return out;
    }

    /// Scan `cache` once, bucketing into `{in_memory, persisted}` for the `size` gauge. Refreshed at
    /// write() time when the gauge is pulled.
    pub fn collectSizeCounts(self: *Self) metrics.SizeCounts {
        var counts = metrics.SizeCounts{ .in_memory = 0, .persisted = 0 };
        var it = self.cache.valueIterator();
        while (it.next()) |entry| {
            switch (entry.item) {
                .in_memory => counts.in_memory += 1,
                .persisted => counts.persisted += 1,
            }
        }
        return counts;
    }

    /// Distinct in-memory vs. persisted epoch counts for the `epochSize` gauge. An epoch holding both
    /// an in-memory and a persisted entry counts toward both tiers.
    pub fn collectEpochSizeCounts(self: *Self) metrics.SizeCounts {
        var counts = metrics.SizeCounts{ .in_memory = 0, .persisted = 0 };
        for (self.epoch_index.keys(), self.epoch_index.values()) |epoch, *roots| {
            var has_in_memory = false;
            var has_persisted = false;
            for (roots.items) |root| {
                switch ((self.cache.get(.{ .root = root, .epoch = epoch }) orelse continue).item) {
                    .in_memory => has_in_memory = true,
                    .persisted => has_persisted = true,
                }
            }
            if (has_in_memory) counts.in_memory += 1;
            if (has_persisted) counts.persisted += 1;
        }
        return counts;
    }

    pub fn size(self: *const Self) usize {
        return self.cache.count();
    }

    /// Snapshot reads / seconds-since-last-read over the resident set across BOTH tiers (empty set →
    /// all-zero). Never-read entries are excluded from `reads`; entries with no `last_read` from
    /// `secs`. Takes `*Self` only because `valueIterator` is non-const; it does not mutate.
    pub fn scanCpReadStats(self: *Self, io: std.Io) struct {
        reads: metrics.AvgMinMax,
        secs: metrics.AvgMinMax,
    } {
        var reads: metrics.AvgMinMaxAccumulator = .{};
        var rit = self.cache.valueIterator();
        while (rit.next()) |entry| {
            if (entry.read_count == 0) continue;
            reads.add(@floatFromInt(entry.read_count));
        }

        var secs: metrics.AvgMinMaxAccumulator = .{};
        const now = time.start(io);
        var sit = self.cache.valueIterator();
        while (sit.next()) |entry| {
            const last_read = entry.last_read orelse continue;
            const value = time.durationSeconds(last_read.durationTo(now));
            secs.add(value);
        }

        return .{ .reads = reads.result(), .secs = secs.result() };
    }

    /// Insert/overwrite a cache entry AND track its root in the spine. With `removeEntry`, the ONLY
    /// writers of `cache` + `epoch_index`, kept coherent.
    ///
    /// Last-writer-wins ownership: a successful overwrite of an `.in_memory` entry destroys the
    /// displaced state, so the map holds exactly one owned state per key. The same-pointer case (the
    /// incoming item re-installs the state already resident here) skips the destroy and only updates
    /// metadata. On any failure the incoming state is untouched (caller retains — Model B) and the
    /// existing entry stays intact and tracked. No raw state borrow may cross a suspension: callers
    /// re-lookup by key after suspending before inserting here.
    fn insertEntry(self: *Self, cp_key: Checkpoint, item: CacheItem) !void {
        // Carry the existing entry's per-key read tracking forward across a value overwrite; a new key
        // starts at zero (counters reset only on removal).
        var read_count: u64 = 0;
        var last_read: ?std.Io.Timestamp = null;
        if (self.cache.get(cp_key)) |existing| {
            read_count = existing.read_count;
            last_read = existing.last_read;
        }

        // Reserve the cache slot before tracking so the trailing putAssumeCapacity cannot OOM — index
        // and cache never diverge on a half-completed insert (the index track below is atomic, so a
        // failed track leaves only an unused reservation behind).
        try self.cache.ensureUnusedCapacity(self.allocator, 1);

        // Track the root in the epoch's list. Atomic under OOM: a fresh epoch entry is rolled back if
        // the append fails, and an idempotent re-track of a present (epoch, root) is a no-op.
        const gop = try self.epoch_index.getOrPut(self.allocator, cp_key.epoch);
        const fresh = !gop.found_existing;
        if (fresh) gop.value_ptr.* = .empty;
        errdefer if (fresh) {
            gop.value_ptr.deinit(self.allocator);
            _ = self.epoch_index.swapRemove(cp_key.epoch);
        };
        if (!rootListContains(gop.value_ptr, cp_key.root)) {
            try gop.value_ptr.append(self.allocator, cp_key.root);
        }

        // All fallible steps have succeeded; capture the displaced in_memory state (if any) so it dies
        // AFTER the overwrite commits. A same-pointer re-add just updates metadata (do not free it).
        const displaced: ?*CachedBeaconState = blk: {
            const existing = self.cache.getPtr(cp_key) orelse break :blk null;
            const old_state = switch (existing.item) {
                .in_memory => |im| im.state,
                .persisted => break :blk null,
            };
            const same = item == .in_memory and item.in_memory.state == old_state;
            break :blk if (same) null else old_state;
        };

        self.cache.putAssumeCapacity(cp_key, .{ .item = item, .read_count = read_count, .last_read = last_read });
        if (displaced) |old| destroyState(old);

        const roots = self.epoch_index.getPtr(cp_key.epoch).?;
        assert(rootListContains(roots, cp_key.root));
        assert(self.cache.contains(cp_key));
        for (roots.items) |r| assert(self.cache.contains(.{ .root = r, .epoch = cp_key.epoch }));
    }

    /// Remove a cache entry AND untrack its root from the spine. With `insertEntry`, the ONLY writers
    /// of `cache` + `epoch_index`, kept coherent. Frees the in-memory state if any.
    fn removeEntry(self: *Self, cp_key: Checkpoint) void {
        if (self.cache.fetchRemove(cp_key)) |kv| {
            if (kv.value.item == .in_memory) destroyState(kv.value.item.in_memory.state);
        }

        if (self.epoch_index.getPtr(cp_key.epoch)) |list| {
            for (list.items, 0..) |r, i| {
                if (std.mem.eql(u8, &r, &cp_key.root)) {
                    _ = list.orderedRemove(i);
                    break;
                }
            }
            if (list.items.len == 0) {
                list.deinit(self.allocator);
                _ = self.epoch_index.swapRemove(cp_key.epoch);
            }
        }

        assert(!self.cache.contains(cp_key));
        if (self.epoch_index.getPtr(cp_key.epoch)) |roots| {
            assert(!rootListContains(roots, cp_key.root));
            for (roots.items) |r| assert(self.cache.contains(.{ .root = r, .epoch = cp_key.epoch }));
        }
    }

    /// Prune or persist checkpoint states in an epoch. Returns the count of states freshly
    /// serialized+written.
    ///
    /// 1) If there is 1 checkpoint state with known root, persist it. This is when there is skipped slot
    ///    at block 0 of epoch:
    ///       slot:                          n
    ///             |-----------------------|-----------------------|
    ///       PRCS root - persist           |
    ///
    /// 2) If there are 2 checkpoint states, PRCS and CRCS and both roots are known to this state,
    ///    persist CRCS. If the block is reorged, PRCS is regen and populated to this cache again:
    ///       slot:                          n
    ///             |-----------------------|-----------------------|
    ///       PRCS root - prune             |
    ///       CRCS root - persist           |
    ///
    /// 3) If there are any roots that unknown to this state, persist their cp state. This is to handle
    ///    the current block is reorged later.
    ///
    /// 4) (derived from above) If there are 2 checkpoint states, PRCS and an unknown root, persist both.
    ///    If block slot (n+1) reorged n, then if we process state n+1 its CRCS is unknown to it; we need
    ///    to also store CRCS to handle the case (n+2) switches to n again:
    ///                       PRCS - persist
    ///                         |  processState()
    ///                         |       |
    ///                   -------------n+1
    ///                 /       |
    ///               n-1 ------n------------n+2
    ///                         |
    ///                       CRCS - persist
    ///
    ///   - PRCS is the checkpoint state that could be justified/finalized later based on the view of the
    ///     state
    ///   - unknown root checkpoint state is persisted to handle the reorg back to that branch later
    ///
    /// Performance note: in normal condition we persist 1 checkpoint state per epoch; in reorged
    /// condition we may persist multiple (most likely 2) checkpoint states per epoch.
    fn processPastEpoch(self: *Self, io: std.Io, block_root: Root, state: *CachedBeaconState, epoch: Epoch) !usize {
        const epoch_boundary_slot = computeStartSlotAtEpoch(epoch);
        const state_slot = try state.state.slot();

        var epoch_boundary_root: Root = undefined;
        if (epoch_boundary_slot == state_slot) {
            epoch_boundary_root = block_root;
        } else {
            epoch_boundary_root = (try state.getBlockRootAtSlot(epoch_boundary_slot)).*;
        }

        const prev_epoch_root: ?Root = if (epoch_boundary_slot == 0)
            null
        else
            (try state.getBlockRootAtSlot(epoch_boundary_slot - 1)).*;

        const list = self.epoch_index.getPtr(epoch) orelse return 0;
        const snapshot = try self.allocator.dupe(Root, list.items);
        defer self.allocator.free(snapshot);

        var persist_count: usize = 0;
        for (snapshot) |cp_root| {
            const cp_key = Checkpoint{ .root = cp_root, .epoch = epoch };
            const entry = self.cache.getPtr(cp_key) orelse continue;
            recordRead(io, entry);
            // Copy `im` by value; the `.persisted` overwrite below clobbers the union payload.
            const im = switch (entry.item) {
                .in_memory => |x| x,
                .persisted => continue,
            };

            // 1)/2) always persist the epoch-boundary root: if block 0 of epoch is skipped this is the
            // PRCS (prev_epoch_root === epoch_boundary_root), else it is the CRCS. 3) also persist any
            // root unknown to this state (neither the boundary nor the previous-epoch root).
            const is_boundary = std.mem.eql(u8, &cp_root, &epoch_boundary_root);
            const is_prev = if (prev_epoch_root) |pr| std.mem.eql(u8, &cp_root, &pr) else false;
            // `is_boundary` is NOT redundant: when slot 0 is skipped the boundary root IS the
            // previous-epoch root, so dropping the term would prune the potentially-finalized cp.
            const should_persist = is_boundary or !is_prev;

            if (should_persist) {
                // A re-added entry keeps its disk key, so its blob is already on disk: drop the
                // memory tier without re-serializing. The entry stays tracked in cache + epoch_index
                // — untracking would orphan the blob from prune/reload, which walk the index.
                if (im.persisted_key) |dk| {
                    entry.item = .{ .persisted = dk };
                    destroyState(im.state);
                    continue;
                }

                metrics.checkpoint().state_persist_sec_from_slot.observe(self.secFromCurrentSlot());
                const serialize_start = time.start(io);
                // Serialize THIS checkpoint's cached state under `cp_key`, NOT the driver `state` at
                // `state_slot` — they are different states.
                const state_size = try im.state.state.serializedSize();
                const state_scratch = try self.acquireScratch(
                    state_size,
                    .persistent_checkpoints_cache_state,
                );
                defer state_scratch.deinit(self.allocator);
                const bytes = state_scratch.bytes();
                _ = try im.state.state.serializeIntoBytes(bytes);
                metrics.checkpoint().state_serialize_duration.observe(time.secondsSince(io, serialize_start));
                const key = try self.datastore.write(io, cp_key, bytes);
                persist_count += 1;

                // The write can suspend; on resume the entry may have been pruned, replaced, or
                // persisted by another task. Re-lookup by key and let the last writer win: whoever is
                // resident now is map-owned and downgrades to persisted here, its state freed. Our
                // pre-write `im.state` is either that occupant or was already destroyed by the
                // displacing insertEntry — exactly one destroy either way.
                const cur = self.cache.getPtr(cp_key) orelse {
                    self.datastore.remove(io, key) catch |err| {
                        log.warn("persist: remove untracked blob epoch {d}: {s}", .{
                            epoch, @errorName(err),
                        });
                    };
                    continue;
                };
                switch (cur.item) {
                    .in_memory => |cur_im| {
                        cur.item = .{ .persisted = key };
                        destroyState(cur_im.state);
                    },
                    .persisted => {},
                }
            } else {
                if (im.persisted_key) |dk| {
                    // persisted file will be eventually deleted by the archive task; this also means the
                    // state is deleted from memory. Do not update epoch_index (entry stays tracked).
                    entry.item = .{ .persisted = dk };
                    destroyState(im.state);
                } else {
                    // delete the state from memory. The ONLY branch that untracks.
                    self.removeEntry(cp_key);
                }
                metrics.checkpoint().state_prune_from_memory_count.incr();
            }
        }
        return persist_count;
    }

    /// Delete all items of an epoch from disk and memory.
    fn deleteAllEpochItems(self: *Self, io: std.Io, epoch: Epoch) !void {
        const list = self.epoch_index.getPtr(epoch) orelse return;
        const snapshot = try self.allocator.dupe(Root, list.items);
        defer self.allocator.free(snapshot);

        for (snapshot) |cp_root| {
            const cp_key = Checkpoint{ .root = cp_root, .epoch = epoch };
            const entry = self.cache.getPtr(cp_key) orelse continue;
            recordRead(io, entry);
            const persisted_key: ?DatastoreKey = switch (entry.item) {
                .in_memory => |im| im.persisted_key,
                .persisted => |dk| dk,
            };
            if (persisted_key) |dk| {
                try self.datastore.remove(io, dk);
                metrics.checkpoint().persisted_state_remove_count.incr();
            }
            self.removeEntry(cp_key);
        }
    }

    /// Prune persisted checkpoint states from disk. The tracked bound is `max_epochs_on_disk +
    /// max_epochs_in_memory`; the oldest excess epochs are deleted.
    fn prunePersistedStates(self: *Self, io: std.Io) error{OutOfMemory}!void {
        const max_epochs_on_disk = self.max_epochs_on_disk orelse return;
        //                epochsOnDisk                                   epochsInMemory
        // |----------------------------------------------------------|----------------------|
        const max_tracked = max_epochs_on_disk + self.max_epochs_in_memory;
        const count = self.epoch_index.count();
        if (count <= max_tracked) return;

        var all: std.ArrayListUnmanaged(Epoch) = .empty;
        defer all.deinit(self.allocator);
        try all.appendSlice(self.allocator, self.epoch_index.keys());
        std.mem.sort(Epoch, all.items, {}, std.sort.asc(Epoch));

        const drop = count - max_tracked;
        for (all.items[0..drop]) |epoch| {
            self.deleteAllEpochItems(io, epoch) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => log.debug("prune-persisted: delete epoch {d} failed: {s}", .{ epoch, @errorName(err) }),
            };
        }
    }

    /// A pool lease when a pool is wired and free, else a fresh allocation. Caller `deinit`s it.
    fn acquireScratch(self: *Self, len: usize, source: buffer_pool.AllocSource) !ScratchBytes {
        if (self.buffer_pool) |pool| {
            if (try pool.alloc(len, source)) |lease| return .{ .leased = lease };
        }
        return .{ .owned = try self.allocator.alloc(u8, len) };
    }

    fn destroyState(state: *CachedBeaconState) void {
        const allocator = state.allocator;
        state.deinit();
        allocator.destroy(state);
    }
};

const testing = std.testing;
const Node = @import("persistent_merkle_tree").Node;
const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;
const InMemoryCPStateDatastore = cp_datastore.InMemoryCPStateDatastore;
const FileCPStateDatastore = cp_datastore.FileCPStateDatastore;
const preset = @import("state_transition").preset;
const zio = @import("zio");

const TestStateFactory = struct {
    allocator: Allocator,
    helper: TestCachedBeaconState,

    fn init(allocator: Allocator, pool: *Node.Pool) !TestStateFactory {
        // ELECTRA_FORK_EPOCH = 0 so the whole slot range resolves to electra: reload tests can persist
        // and fault back low-slot (epoch 20-23) states without the blob's fork mismatching.
        const helper = try TestCachedBeaconState.init(allocator, pool, 8, .{ .fork_epoch = 0 });
        return .{ .allocator = allocator, .helper = helper };
    }

    fn deinit(self: *TestStateFactory) void {
        self.helper.deinit();
    }

    fn config(self: *TestStateFactory) *const BeaconConfig {
        return self.helper.config;
    }

    /// Zero finalized checkpoint stamped onto every produced state. The base state from `generate_state`
    /// carries a non-trivial finalized epoch, so without this `processState` would finality-prune the
    /// low-epoch checkpoints the band/persist tests assert; finalized epoch 0 makes its `pruneFinalized`
    /// a no-op, isolating the band logic. Tests that exercise finality set it explicitly per state.
    const zero_finalized = types.phase0.Checkpoint.Type{ .epoch = 0, .root = @splat(0) };

    /// Produce an owned state at `slot` with `root` written at `slot - 1`'s block-roots position, so
    /// `getBlockRootAtSlot(slot - 1)` returns `root`.
    fn make(self: *TestStateFactory, slot: u64) !*CachedBeaconState {
        const state = try self.helper.cached_state.clone(self.allocator, .{});
        errdefer destroyTestState(self.allocator, state);
        try state.state.setSlot(slot);
        try state.state.setFinalizedCheckpoint(&zero_finalized);
        try state.state.commit();
        return state;
    }

    /// Like `make` but stamps `block_root` at `target_slot % SLOTS_PER_HISTORICAL_ROOT` so the
    /// state's view of `getBlockRootAtSlot(target_slot)` is `block_root`.
    fn makeWithBlockRoot(self: *TestStateFactory, slot: u64, target_slot: u64, block_root: Root) !*CachedBeaconState {
        const state = try self.helper.cached_state.clone(self.allocator, .{});
        errdefer destroyTestState(self.allocator, state);
        try state.state.setSlot(slot);
        try state.state.setFinalizedCheckpoint(&zero_finalized);
        var block_roots = try state.state.blockRoots();
        try block_roots.setValue(target_slot % preset.SLOTS_PER_HISTORICAL_ROOT, &block_root);
        try state.state.commit();
        return state;
    }
};

fn destroyTestState(allocator: Allocator, state: *CachedBeaconState) void {
    state.deinit();
    allocator.destroy(state);
}

fn makeRoot(tag: u8) Root {
    var root: Root = undefined;
    @memset(&root, tag);
    return root;
}

const TestHarness = struct {
    allocator: Allocator,
    io: std.Io,
    pool: Node.Pool,
    factory: TestStateFactory,
    // Null when the caller owns the datastore (`initWithDatastore`); `deinit` skips it then.
    store: ?InMemoryCPStateDatastore,
    block_cache: BlockStateCache,
    cache: PersistentCheckpointStateCache,

    fn init(allocator: Allocator, opts: PersistentCheckpointStateCache.Opts) !*TestHarness {
        const h = try allocator.create(TestHarness);
        errdefer allocator.destroy(h);

        h.allocator = allocator;
        h.io = std.testing.io;
        h.pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 64 });
        errdefer h.pool.deinit();

        h.factory = try TestStateFactory.init(allocator, &h.pool);
        errdefer h.factory.deinit();

        h.store = InMemoryCPStateDatastore.init(allocator);
        errdefer h.store.?.deinit();

        h.block_cache = try BlockStateCache.init(allocator, .{});
        errdefer h.block_cache.deinit();

        h.cache = PersistentCheckpointStateCache.init(
            allocator,
            h.factory.config(),
            h.store.?.datastore(),
            &h.block_cache,
            opts,
        );

        return h;
    }

    // Like `init` but the caller owns and deinits `datastore` (e.g. an erroring/interleaving fake);
    // the harness owns no InMemory store.
    fn initWithDatastore(allocator: Allocator, datastore: CPStateDatastore, opts: PersistentCheckpointStateCache.Opts) !*TestHarness {
        const h = try allocator.create(TestHarness);
        errdefer allocator.destroy(h);

        h.allocator = allocator;
        h.io = std.testing.io;
        h.pool = try Node.Pool.init(.{ .page_allocator = allocator, .allocator = allocator, .pool_size = 256 * 64 });
        errdefer h.pool.deinit();

        h.factory = try TestStateFactory.init(allocator, &h.pool);
        errdefer h.factory.deinit();

        h.store = null;

        h.block_cache = try BlockStateCache.init(allocator, .{});
        errdefer h.block_cache.deinit();

        h.cache = PersistentCheckpointStateCache.init(
            allocator,
            h.factory.config(),
            datastore,
            &h.block_cache,
            opts,
        );

        return h;
    }

    fn deinit(self: *TestHarness) void {
        const allocator = self.allocator;
        self.cache.deinit();
        self.block_cache.deinit();
        if (self.store) |*s| s.deinit();
        self.factory.deinit();
        self.pool.deinit();
        allocator.destroy(self);
    }
};

/// One `setValue(target_slot % SLOTS_PER_HISTORICAL_ROOT, &root)` stamp on a driver's block-roots view.
const RootAt = struct { target_slot: u64, root: Root };

/// Build a committed driver state at `slot` whose block-roots view places each `RootAt`'s root at its
/// target slot. Replaces the `make → blockRoots → setValue×N → commit` dance. The caller owns the
/// returned driver and must `destroyTestState` it.
fn buildDriver(h: *TestHarness, slot: u64, roots: []const RootAt) !*CachedBeaconState {
    const driver = try h.factory.make(slot);
    errdefer destroyTestState(h.allocator, driver);
    var driver_roots = try driver.state.blockRoots();
    for (roots) |r| {
        try driver_roots.setValue(r.target_slot % preset.SLOTS_PER_HISTORICAL_ROOT, &r.root);
    }
    try driver.state.commit();
    return driver;
}

/// Assert `cp` resolves to persisted disk bytes equal to `expected`, freeing the owned bytes.
fn expectPersistedBytes(h: *TestHarness, cp: Checkpoint, expected: []const u8) !void {
    const sob = (try h.cache.getStateOrBytes(h.io, cp)).?;
    try testing.expect(sob == .bytes);
    defer h.allocator.free(sob.bytes);
    try testing.expectEqualSlices(u8, expected, sob.bytes);
}

/// Assert `cp` resolves to persisted disk bytes (without checking content), freeing the owned bytes.
fn expectPersisted(h: *TestHarness, cp: Checkpoint) !void {
    const sob = (try h.cache.getStateOrBytes(h.io, cp)).?;
    try testing.expect(sob == .bytes);
    h.allocator.free(sob.bytes);
}

/// Assert `cp` does not resolve to disk bytes (`getStateOrBytes` returns null).
fn expectNoBytes(h: *TestHarness, cp: Checkpoint) !void {
    try testing.expect((try h.cache.getStateOrBytes(h.io, cp)) == null);
}

/// Persist a state for `cp` to disk by hand and mark its cache entry `.persisted`: build a state at
/// `slot`, serialize+write it, free the state, then insert the persisted entry. Returns the disk key.
fn persistByHand(h: *TestHarness, cp: Checkpoint, slot: u64) !DatastoreKey {
    const s = try h.factory.make(slot);
    const bytes = try s.state.serialize(h.allocator);
    defer h.allocator.free(bytes);
    const dk = try h.store.?.datastore().write(h.io, cp, bytes);
    destroyTestState(h.allocator, s);
    try h.cache.insertEntry(cp, .{ .persisted = dk });
    return dk;
}

/// Number of persisted keys on disk.
fn diskKeyCount(h: *TestHarness) !usize {
    const keys = try h.store.?.datastore().readKeys(h.io, h.allocator);
    defer h.allocator.free(keys);
    return keys.len;
}

/// The serialization of a fresh state at `slot` — the expected on-disk bytes for a cp persisted from a
/// state built at `slot`. Caller frees the returned bytes.
fn serializeFresh(h: *TestHarness, slot: u64) ![]u8 {
    const s = try h.factory.make(slot);
    defer destroyTestState(h.allocator, s);
    return s.state.serialize(h.allocator);
}

// A malformed persisted blob must fault in as a graceful cache MISS (the anti-wedge swallow), not panic
// in the slot read or OOB-slice a torn offset — which holds only if the short-blob path returns a
// catchable error. Adds a resident seed (so the reload reaches loadOtherState), persists a truncated
// blob, and asserts getOrReload is a null miss.
fn expectMalformedBlobMiss(allocator: std.mem.Allocator, truncate: enum { below_slot_offset, sub_min_size }) !void {
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0xC0);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp = Checkpoint{ .root = root, .epoch = seed_epoch - 2 };
    const persisted_slot = computeStartSlotAtEpoch(cp.epoch);

    // Same-view resident seed so findSeedStateToReload yields it and the reload reaches the blob parse.
    const seed = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed);

    const full = try h.factory.helper.cached_state.state.serialize(allocator);
    defer allocator.free(full);
    const blob: []const u8 = switch (truncate) {
        .below_slot_offset => &[_]u8{ 1, 2, 3, 4 },
        .sub_min_size => full[0 .. types.electra.BeaconState.min_size - 1],
    };

    const dk = try h.store.?.datastore().write(h.io, cp, blob);
    try h.cache.insertEntry(cp, .{ .persisted = dk });

    try testing.expect((try h.cache.getOrReload(h.io, cp)) == null);
}

fn reportRow(name: []const u8, err: anyerror) anyerror {
    std.debug.print("scanReadStats row [{s}] failed\n", .{name});
    return err;
}

test "metrics.scrape composes block + cp refresh over both live caches" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0xC1);
    try h.cache.add(h.io, .{ .epoch = 5, .root = root }, try h.factory.make(500));
    _ = h.cache.get(h.io, .{ .epoch = 5, .root = root });
    _ = try h.block_cache.add(h.io, try h.factory.make(700), false);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    // Default (noop) metrics: scrape must compose block+cp refresh + write over both live caches.
    try metrics.scrape(&aw.writer, &h.block_cache, &h.cache, h.io);
}

test "PersistentCheckpointStateCache add/get/getLatest and ownership deinit" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root = makeRoot(0x11);
    const s20 = try h.factory.make(20 * spe);
    try h.cache.add(h.io, .{ .epoch = 20, .root = root }, s20);
    const s22 = try h.factory.make(22 * spe);
    try h.cache.add(h.io, .{ .epoch = 22, .root = root }, s22);

    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 20 }) == s20);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 22 }) == s22);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 21 }) == null);
    try testing.expect(h.cache.get(h.io, .{ .root = makeRoot(0x22), .epoch = 20 }) == null);

    try testing.expect(h.cache.getLatest(h.io, root, 21) == s20);
    try testing.expect(h.cache.getLatest(h.io, root, 100) == s22);
    try testing.expect(h.cache.getLatest(h.io, root, 19) == null);
    try testing.expect(h.cache.getLatest(h.io, makeRoot(0x44), 100) == null);

    // getStateOrBytes on an in-memory entry takes the borrowed .state arm (nothing to free).
    const sob = (try h.cache.getStateOrBytes(h.io, .{ .root = root, .epoch = 20 })).?;
    try testing.expect(sob == .state);
    try testing.expect(sob.state == s20);
}

test "PersistentCheckpointStateCache pruneFinalized deletes below epoch and frees states" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root_a = makeRoot(0x55);
    const root_b = makeRoot(0x66);

    try h.cache.add(h.io, .{ .epoch = 2, .root = root_a }, try h.factory.make(200));
    try h.cache.add(h.io, .{ .epoch = 3, .root = root_b }, try h.factory.make(300));
    try h.cache.add(h.io, .{ .epoch = 4, .root = root_a }, try h.factory.make(400));

    try h.cache.pruneFinalized(h.io, 4);

    try testing.expectEqual(@as(usize, 1), h.cache.size());
    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 2 }) == null);
    try testing.expect(h.cache.get(h.io, .{ .root = root_b, .epoch = 3 }) == null);
    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 4 }) != null);
}

test "PersistentCheckpointStateCache clear frees states and resets spine" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    try h.cache.add(h.io, .{ .epoch = 1, .root = makeRoot(0x88) }, try h.factory.make(100));
    try h.cache.add(h.io, .{ .epoch = 2, .root = makeRoot(0x99) }, try h.factory.make(200));

    h.cache.clear();

    try testing.expectEqual(@as(usize, 0), h.cache.size());
    try testing.expect(h.cache.getLatest(h.io, makeRoot(0x88), 100) == null);
    try testing.expectEqual(@as(usize, 0), h.cache.epoch_index.count());
}

test "PersistentCheckpointStateCache dumpSummary/getStates/dumpCheckpointKeys (debug API)" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const mem_root = makeRoot(0x11);
    const disk_root = makeRoot(0x22);
    const mem_cp = Checkpoint{ .epoch = 5, .root = mem_root };
    const disk_cp = Checkpoint{ .epoch = 7, .root = disk_root };

    const mem_state = try h.factory.make(500);
    try h.cache.add(h.io, mem_cp, mem_state);
    _ = try persistByHand(h, disk_cp, 700);

    // A read on the in-memory entry must surface in the summary's `reads`.
    _ = h.cache.get(h.io, mem_cp);

    // The dump reads counters directly (no bump), so the in-memory entry's read shows as 1.
    const summary = try h.cache.dumpSummary(allocator);
    defer allocator.free(summary);
    try testing.expectEqual(@as(usize, 2), summary.len);
    var saw_mem = false;
    var saw_disk = false;
    for (summary) |item| {
        try testing.expect(item.checkpoint_state);
        if (std.mem.eql(u8, &item.root, &mem_root)) {
            saw_mem = true;
            try testing.expectEqual(computeStartSlotAtEpoch(5), item.slot);
            try testing.expectEqual(@as(u64, 1), item.reads);
        }
        if (std.mem.eql(u8, &item.root, &disk_root)) {
            saw_disk = true;
            try testing.expectEqual(computeStartSlotAtEpoch(7), item.slot);
        }
    }
    try testing.expect(saw_mem and saw_disk);

    // getStates: only the in-memory state comes back (borrowed pointer, still owned by the cache).
    const states = try h.cache.getStates(allocator);
    defer allocator.free(states);
    try testing.expectEqual(@as(usize, 1), states.len);
    try testing.expectEqual(mem_state, states[0]);

    const keys = try h.cache.dumpCheckpointKeys(allocator);
    defer allocator.free(keys);
    try testing.expectEqual(@as(usize, 2), keys.len);
    var saw_mem_key = false;
    var saw_disk_key = false;
    for (keys) |k| {
        if (k.epoch == mem_cp.epoch and std.mem.eql(u8, &k.root, &mem_root)) saw_mem_key = true;
        if (k.epoch == disk_cp.epoch and std.mem.eql(u8, &k.root, &disk_root)) saw_disk_key = true;
    }
    try testing.expect(saw_mem_key and saw_disk_key);
}

test "PersistentCheckpointStateCache getStateOrBytes returns owned bytes for a persisted entry" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const cp = Checkpoint{ .epoch = 20, .root = makeRoot(0xCC) };
    _ = try persistByHand(h, cp, 20 * spe);

    const expected = blk: {
        const s = try h.factory.make(20 * spe);
        defer destroyTestState(allocator, s);
        break :blk try s.state.serialize(allocator);
    };
    defer allocator.free(expected);
    try expectPersistedBytes(h, cp, expected);
}

test "PersistentCheckpointStateCache getOrReload faults a persisted state back into memory" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0xDD);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp_epoch = seed_epoch - 2;
    const cp = Checkpoint{ .epoch = cp_epoch, .root = root };
    const persisted_slot = computeStartSlotAtEpoch(cp_epoch);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^                       ^
    //                    |                       |
    //                    cp                      seed
    //                    persisted               (epoch 22, in memory)
    //         seed VIEWS root at the epoch-20 boundary -> chosen to reload cp

    // Provide an in-memory same-view seed in a later epoch (it views cp.root at the cp slot) so
    // findSeedStateToReload returns it (and its pool) for the reload.
    const seed = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed);

    _ = try persistByHand(h, cp, persisted_slot);

    // get() must NOT touch disk.
    try testing.expect(h.cache.get(h.io, cp) == null);

    const reloaded = (try h.cache.getOrReload(h.io, cp)).?;
    try testing.expectEqual(persisted_slot, try reloaded.state.slot());
    const item = h.cache.cache.get(.{ .root = root, .epoch = cp_epoch }).?.item;
    try testing.expect(item == .in_memory);
    try testing.expect(item.in_memory.persisted_key != null);
}

test "PersistentCheckpointStateCache getOrReload returns null when no seed is available" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const cp = Checkpoint{ .epoch = 5, .root = makeRoot(0xEE) };
    _ = try persistByHand(h, cp, 40);

    try testing.expect((try h.cache.getOrReload(h.io, cp)) == null);
}

test "PersistentCheckpointStateCache processState persists older epochs and prunes from memory" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const root_a = makeRoot(0xA0);
    const root_b = makeRoot(0xB0);

    const spe = preset.SLOTS_PER_EPOCH;

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^           ^           ^     ^
    //                    |           |           |     |
    //                    root_b------root_a------root_a--driver
    //         max_epochs_in_memory=1: epochs 20 and 21 persist, 22 stays resident

    // Boundary roots: epoch 21 boundary (slot 21*spe) = root_a, epoch 20 boundary (slot 20*spe) = root_b.
    try h.cache.add(h.io, .{ .epoch = 20, .root = root_b }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 21, .root = root_a }, try h.factory.make(21 * spe));
    try h.cache.add(h.io, .{ .epoch = 22, .root = root_a }, try h.factory.make(22 * spe));

    // Build a driver state whose view has root_b at the epoch-20 boundary and root_a at the epoch-21
    // boundary, so processState persists the boundary cps of epochs 20 and 21.
    const driver = try buildDriver(h, 22 * spe + 1, &.{
        .{ .target_slot = 20 * spe, .root = root_b },
        .{ .target_slot = 21 * spe, .root = root_a },
    });
    defer destroyTestState(allocator, driver);

    const persisted = try h.cache.processState(h.io, makeRoot(0xFF), driver);

    try testing.expectEqual(@as(usize, 2), persisted);
    try testing.expect(h.cache.get(h.io, .{ .root = root_b, .epoch = 20 }) == null);
    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 21 }) == null);
    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 22 }) != null);

    const item1 = h.cache.cache.get(.{ .root = root_b, .epoch = 20 }).?.item;
    try testing.expect(item1 == .persisted);
}

test "PersistentCheckpointStateCache processState keeps both in-band checkpoint states resident" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_0b = makeRoot(0x0B);
    const root_1 = makeRoot(0x02);
    const root_1a = makeRoot(0x64);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^        ^  ^     ^
    //                    |        |  |     |
    //                    root_0b--|-root_1-driver
    //                             |
    //                        {root_1a, 21}=cp1a

    // Epoch 20 = one below-band boundary cp; epoch 21 holds TWO roots (boundary root_1 + reorg
    // sibling root_1a), both in memory. With max=1 only epoch 20 is below the band, so epoch 21 is
    // never processed.
    try h.cache.add(h.io, .{ .epoch = 20, .root = root_0b }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 21, .root = root_1 }, try h.factory.make(21 * spe));
    try h.cache.add(h.io, .{ .epoch = 21, .root = root_1a }, try h.factory.make(21 * spe));

    // Driver view stamps the epoch-20 and epoch-21 boundaries; only epoch 20 is actually processed.
    const driver = try buildDriver(h, 21 * spe + 3, &.{
        .{ .target_slot = 20 * spe, .root = root_0b },
        .{ .target_slot = 21 * spe, .root = root_1 },
    });
    defer destroyTestState(allocator, driver);

    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, makeRoot(0xFF), driver));

    try testing.expect(h.cache.cache.get(.{ .epoch = 21, .root = root_1 }).?.item == .in_memory);
    try testing.expect(h.cache.cache.get(.{ .epoch = 21, .root = root_1a }).?.item == .in_memory);
    try testing.expect(h.cache.get(h.io, .{ .epoch = 21, .root = root_1 }) != null);
    try testing.expect(h.cache.get(h.io, .{ .epoch = 21, .root = root_1a }) != null);
}

test "PersistentCheckpointStateCache processState at max=2 persists the below-band boundary only" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 2, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_0b = makeRoot(0x0B);
    const root_0a = makeRoot(0x0A);
    const root_1 = makeRoot(0x02);
    const root_2 = makeRoot(0x03);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^           ^           ^         ^
    //                   ||           |           |         |
    //                   |root_0b---root_1------root_2----driver
    //                   |
    //                   root_0a

    // Epoch 20 holds two cps: boundary root_0b + prev-root root_0a. Epochs 21 and 22 hold one
    // in-band cp each. With max=2 only epoch 20 is below the band.
    try h.cache.add(h.io, .{ .epoch = 20, .root = root_0b }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 20, .root = root_0a }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 21, .root = root_1 }, try h.factory.make(21 * spe));
    try h.cache.add(h.io, .{ .epoch = 22, .root = root_2 }, try h.factory.make(22 * spe));

    // Driver view: epoch-20 boundary is root_0b, the slot before it is root_0a.
    const driver = try buildDriver(h, 22 * spe + 3, &.{
        .{ .target_slot = 20 * spe, .root = root_0b },
        .{ .target_slot = 20 * spe - 1, .root = root_0a },
        .{ .target_slot = 21 * spe, .root = root_1 },
        .{ .target_slot = 22 * spe, .root = root_2 },
    });
    defer destroyTestState(allocator, driver);

    // Only the epoch-20 boundary persists; root_0a is the known prev-root, pruned from memory
    // (never written).
    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, root_2, driver));
    try expectNoBytes(h, .{ .epoch = 20, .root = root_0a });
    {
        const expected_bytes = try serializeFresh(h, 20 * spe);
        defer allocator.free(expected_bytes);
        try expectPersistedBytes(h, .{ .epoch = 20, .root = root_0b }, expected_bytes);
    }
    try testing.expect(h.cache.get(h.io, .{ .epoch = 21, .root = root_1 }) != null);
    try testing.expect(h.cache.get(h.io, .{ .epoch = 22, .root = root_2 }) != null);
}

test "PersistentCheckpointStateCache processState over an already-persisted epoch re-persists nothing" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const root_a = makeRoot(0xA0);
    const root_b = makeRoot(0xB0);

    const spe = preset.SLOTS_PER_EPOCH;

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^           ^           ^     ^
    //                    |           |           |     |
    //                    root_b------root_a------root_a--driver
    //         first pass persists 20 and 21; a second pass over the same view re-persists nothing

    try h.cache.add(h.io, .{ .epoch = 20, .root = root_b }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 21, .root = root_a }, try h.factory.make(21 * spe));
    try h.cache.add(h.io, .{ .epoch = 22, .root = root_a }, try h.factory.make(22 * spe));

    const driver = try buildDriver(h, 22 * spe + 1, &.{
        .{ .target_slot = 20 * spe, .root = root_b },
        .{ .target_slot = 21 * spe, .root = root_a },
    });
    defer destroyTestState(allocator, driver);

    try testing.expectEqual(@as(usize, 2), try h.cache.processState(h.io, makeRoot(0xFF), driver));
    const disk_after_first = try diskKeyCount(h);
    try testing.expectEqual(@as(usize, 2), disk_after_first);

    // Second pass over the SAME view: epochs 20 and 21 are already `.persisted`, so nothing is
    // re-serialized — returns 0 and the datastore size is unchanged.
    try testing.expectEqual(@as(usize, 0), try h.cache.processState(h.io, makeRoot(0xFF), driver));
    try testing.expectEqual(disk_after_first, try diskKeyCount(h));
}

test "PersistentCheckpointStateCache processState does not re-write an on-disk pruned entry" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const boundary_root = makeRoot(0xA1);
    const prev_root = makeRoot(0xB1);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^           ^     ^
    //                   ||           |     |
    //                   |boundary_root--boundary_root--driver
    //                   |
    //                   prev_root  (prev-epoch root, dual: in-mem + on disk -> dropped, not re-written)

    // Build the epoch-20 prev-epoch-root cp as a DUAL entry: in-memory AND already on disk. Persist its
    // bytes, then overwrite the cache slot to `.in_memory` carrying that persisted_key.
    {
        const s = try h.factory.make(20 * spe + 1);
        const bytes = try s.state.serialize(allocator);
        defer allocator.free(bytes);
        const dk = try h.store.?.datastore().write(h.io, .{ .root = prev_root, .epoch = 20 }, bytes);
        try h.cache.insertEntry(.{ .root = prev_root, .epoch = 20 }, .{ .in_memory = .{ .state = s, .persisted_key = dk } });
    }
    try h.cache.add(h.io, .{ .epoch = 20, .root = boundary_root }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 21, .root = boundary_root }, try h.factory.make(21 * spe));

    const disk_before = try diskKeyCount(h);
    try testing.expectEqual(@as(usize, 1), disk_before);

    // Driver view: epoch-20 boundary is boundary_root, the slot before it is prev_root (a KNOWN view).
    const driver = try buildDriver(h, 21 * spe + 1, &.{
        .{ .target_slot = 20 * spe, .root = boundary_root },
        .{ .target_slot = 20 * spe - 1, .root = prev_root },
    });
    defer destroyTestState(allocator, driver);

    // The boundary cp is persisted (a fresh write, +1); the prev_root cp is a known view already on
    // disk, so it is dropped from memory WITHOUT a re-write. Persist count counts only the boundary.
    const persisted = try h.cache.processState(h.io, makeRoot(0xFE), driver);
    try testing.expectEqual(@as(usize, 1), persisted);

    // Datastore grew by exactly 1 (the boundary), proving prev_root was not re-written.
    try testing.expectEqual(disk_before + 1, try diskKeyCount(h));
    try testing.expect(h.cache.cache.get(.{ .root = prev_root, .epoch = 20 }).?.item == .persisted);
    try testing.expect(h.cache.cache.get(.{ .root = boundary_root, .epoch = 20 }).?.item == .persisted);
}

test "PersistentCheckpointStateCache processState skips re-writing a re-added on-disk boundary" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const boundary_root = makeRoot(0xA1);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^           ^     ^
    //                    |           |     |
    //                    boundary_root--boundary_root--driver
    //         epoch 20 persists, is re-added carrying its disk key, then skipped on the next pass

    try h.cache.add(h.io, .{ .epoch = 20, .root = boundary_root }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 21, .root = boundary_root }, try h.factory.make(21 * spe));

    // Driver view: epoch-20 boundary slot is boundary_root.
    const driver = try buildDriver(h, 21 * spe + 1, &.{
        .{ .target_slot = 20 * spe, .root = boundary_root },
    });
    defer destroyTestState(allocator, driver);

    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, makeRoot(0xFF), driver));
    try testing.expect(h.cache.cache.get(.{ .root = boundary_root, .epoch = 20 }).?.item == .persisted);
    const disk_after_first = try diskKeyCount(h);
    try testing.expectEqual(@as(usize, 1), disk_after_first);

    // Regen re-adds the SAME boundary cp: add() reads the persisted entry and carries persisted_key
    // into a fresh in_memory entry (the reloaded state).
    try h.cache.add(h.io, .{ .epoch = 20, .root = boundary_root }, try h.factory.make(20 * spe));
    const readded = h.cache.cache.get(.{ .root = boundary_root, .epoch = 20 }).?.item;
    try testing.expect(readded == .in_memory);
    try testing.expect(readded.in_memory.persisted_key != null);

    // Second pass over the same boundary view: the entry is in_memory with persisted_key != null and
    // is the boundary, so it is dropped from memory WITHOUT a re-write. Return 0, disk size unchanged.
    try testing.expectEqual(@as(usize, 0), try h.cache.processState(h.io, makeRoot(0xFF), driver));
    try testing.expect(h.cache.cache.get(.{ .root = boundary_root, .epoch = 20 }).?.item == .persisted);
    try testing.expectEqual(disk_after_first, try diskKeyCount(h));
}

test "PersistentCheckpointStateCache pruneFinalized removes persisted states from disk" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const root_a = makeRoot(0xA0);
    const root_b = makeRoot(0xB0);

    const spe = preset.SLOTS_PER_EPOCH;
    // Boundary roots: epoch 21 boundary (slot 21*spe) = root_a, epoch 20 boundary (slot 20*spe) = root_b.
    try h.cache.add(h.io, .{ .epoch = 20, .root = root_b }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 21, .root = root_a }, try h.factory.make(21 * spe));
    try h.cache.add(h.io, .{ .epoch = 22, .root = root_a }, try h.factory.make(22 * spe));

    const driver = try buildDriver(h, 22 * spe + 1, &.{
        .{ .target_slot = 20 * spe, .root = root_b },
        .{ .target_slot = 21 * spe, .root = root_a },
    });
    defer destroyTestState(allocator, driver);

    try testing.expectEqual(@as(usize, 2), try h.cache.processState(h.io, makeRoot(0xFF), driver));
    try testing.expectEqual(@as(usize, 2), try diskKeyCount(h));

    // Finalize above epoch 20: its persisted state must leave both the cache AND disk.
    try h.cache.pruneFinalized(h.io, 21);

    try testing.expectEqual(@as(usize, 1), try diskKeyCount(h));
    try expectNoBytes(h, .{ .epoch = 20, .root = root_b });
    try expectPersisted(h, .{ .epoch = 21, .root = root_a });

    // Finalize above epoch 22: the last persisted state (epoch 21) is removed from disk too.
    try h.cache.pruneFinalized(h.io, 22);

    try testing.expectEqual(@as(usize, 0), try diskKeyCount(h));
    try expectNoBytes(h, .{ .epoch = 21, .root = root_a });
}

test "PersistentCheckpointStateCache processState finality-prunes below-finalized checkpoints from memory and disk" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const root_a = makeRoot(0xA0);

    const spe = preset.SLOTS_PER_EPOCH;

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^           ^           ^           ^
    //                    |           |           |           |
    //                    root_a      root_a      root_a      root_a
    //                    disk        mem         kept        kept
    //         finalized=22: epochs 20 and 21 (< 22) pruned from disk and memory

    // Epoch 20: a below-finalized cp persisted to disk → proves the finality prune deletes from DISK.
    // Epoch 21: a below-finalized cp in memory → proves it deletes from MEMORY. Epochs 22 and 23 are at/
    // above finalized and must survive (the band keeps them: 2 tracked <= max_epochs_in_memory = 8).
    _ = try persistByHand(h, .{ .epoch = 20, .root = root_a }, 20 * spe);
    try h.cache.add(h.io, .{ .epoch = 21, .root = root_a }, try h.factory.make(21 * spe));
    try h.cache.add(h.io, .{ .epoch = 22, .root = root_a }, try h.factory.make(22 * spe));
    try h.cache.add(h.io, .{ .epoch = 23, .root = root_a }, try h.factory.make(23 * spe));

    try testing.expectEqual(@as(usize, 1), try diskKeyCount(h));

    // Driver finalized at epoch 22: processState must prune epochs 20 and 21 (< 22) and keep 22 and 23.
    const driver = try buildDriver(h, 23 * spe + 1, &.{});
    defer destroyTestState(allocator, driver);
    const finalized = types.phase0.Checkpoint.Type{ .epoch = 22, .root = @splat(0) };
    try driver.state.setFinalizedCheckpoint(&finalized);
    try driver.state.commit();

    // No band persist (the band keeps epochs 22 and 23 in memory), so the only effect is the finality
    // prune: epochs 20 and 21 are gone from memory and disk; epochs 22 and 23 stay resident.
    try testing.expectEqual(@as(usize, 0), try h.cache.processState(h.io, makeRoot(0xFF), driver));

    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 20 }) == null);
    try expectNoBytes(h, .{ .epoch = 20, .root = root_a });
    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 21 }) == null);
    try expectNoBytes(h, .{ .epoch = 21, .root = root_a });
    try testing.expectEqual(@as(usize, 0), try diskKeyCount(h));

    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 22 }) != null);
    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 23 }) != null);
}

test "PersistentCheckpointStateCache processState prunes an unknown-view reorg root from memory" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const boundary_root = makeRoot(0xA1);
    const prev_root = makeRoot(0xB1);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^           ^     ^
    //                   ||           |     |
    //                   |boundary_root--boundary_root--driver
    //                   |
    //                   prev_root  (prev-epoch root, memory-only -> deleted from memory)

    // Epoch 20 has the boundary cp (persisted) and the previous-epoch-root cp (pruned from memory,
    // not on disk → memory delete).
    try h.cache.add(h.io, .{ .epoch = 20, .root = boundary_root }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 20, .root = prev_root }, try h.factory.make(20 * spe + 1));
    try h.cache.add(h.io, .{ .epoch = 21, .root = boundary_root }, try h.factory.make(21 * spe));

    const driver = try buildDriver(h, 21 * spe + 1, &.{
        .{ .target_slot = 20 * spe, .root = boundary_root },
        .{ .target_slot = 20 * spe - 1, .root = prev_root },
    });
    defer destroyTestState(allocator, driver);

    const persisted = try h.cache.processState(h.io, makeRoot(0xFE), driver);

    // Boundary cp of epoch 20 persisted; prev-epoch-root cp pruned from memory (known view, on neither
    // disk).
    try testing.expectEqual(@as(usize, 1), persisted);
    const boundary_item = h.cache.cache.get(.{ .root = boundary_root, .epoch = 20 }).?.item;
    try testing.expect(boundary_item == .persisted);
    try testing.expect(h.cache.cache.get(.{ .root = prev_root, .epoch = 20 }) == null);
}

test "PersistentCheckpointStateCache prunePersistedStates enforces the tracked-epoch bound" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 2, .max_epochs_on_disk = 2 });
    defer h.deinit();

    const root = makeRoot(0x77);
    // maxTrackedEpochs = 4. Add 6 distinct epochs; add() prunes the oldest down to 4.
    var epoch: Epoch = 1;
    while (epoch <= 6) : (epoch += 1) {
        try h.cache.add(h.io, .{ .epoch = epoch, .root = root }, try h.factory.make(epoch * 100));
    }

    try testing.expectEqual(@as(u64, 4), h.cache.epoch_index.count());
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 1 }) == null);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 2 }) == null);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 6 }) != null);
}

test "PersistentCheckpointStateCache initFromDisk removes prior-run persisted states" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const s0 = try h.factory.make(100);
    const b0 = try s0.state.serialize(allocator);
    defer allocator.free(b0);
    destroyTestState(allocator, s0);
    _ = try h.store.?.datastore().write(h.io, .{ .root = makeRoot(0x01), .epoch = 1 }, b0);
    _ = try h.store.?.datastore().write(h.io, .{ .root = makeRoot(0x02), .epoch = 2 }, b0);

    try h.cache.initFromDisk(h.io);

    try testing.expectEqual(@as(usize, 0), try diskKeyCount(h));
}

test "PersistentCheckpointStateCache collectSizeCounts and collectEpochSizeCounts" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0x12);
    try h.cache.add(h.io, .{ .epoch = 1, .root = root }, try h.factory.make(100));
    try h.cache.add(h.io, .{ .epoch = 2, .root = root }, try h.factory.make(200));

    const sizes = h.cache.collectSizeCounts();
    try testing.expectEqual(@as(u64, 2), sizes.in_memory);
    try testing.expectEqual(@as(u64, 0), sizes.persisted);

    const epoch_sizes = h.cache.collectEpochSizeCounts();
    try testing.expectEqual(@as(u64, 2), epoch_sizes.in_memory);
    try testing.expectEqual(@as(u64, 0), epoch_sizes.persisted);
}

test "PersistentCheckpointStateCache updatePreComputedCheckpoint tracks hits" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0x34);
    try h.cache.add(h.io, .{ .epoch = 5, .root = root }, try h.factory.make(500));

    try testing.expect(h.cache.updatePreComputedCheckpoint(root, 5) == null);
    _ = h.cache.get(h.io, .{ .epoch = 5, .root = root });
    _ = h.cache.get(h.io, .{ .epoch = 5, .root = root });

    // Setting again returns the accumulated hit count (2) and resets.
    try testing.expectEqual(@as(?u64, 2), h.cache.updatePreComputedCheckpoint(root, 6));
}

test "PersistentCheckpointStateCache processState persists each checkpoint's own bytes (reload round-trip)" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root = makeRoot(0xC1);

    // Three consecutive checkpoint epochs; the driver sits one epoch above them.
    const driver_epoch: Epoch = 23;
    const e1 = driver_epoch - 3;
    const e2 = driver_epoch - 2;
    const e3 = driver_epoch - 1;

    // Each cp state sits at its own epoch-boundary slot — that boundary slot is what a correct reload
    // must recover (the buggy variant would recover the driver slot instead).
    const e1_slot = computeStartSlotAtEpoch(e1);
    const e2_slot = computeStartSlotAtEpoch(e2);
    try h.cache.add(h.io, .{ .epoch = e1, .root = root }, try h.factory.make(e1_slot));
    try h.cache.add(h.io, .{ .epoch = e2, .root = root }, try h.factory.make(e2_slot));
    // The latest epoch stays resident and serves as the reload seed; it views `root` at the e1 and
    // e2 boundaries so findSeedStateToReload picks it as the same-view seed for both reloads.
    const e3_seed = try buildDriver(h, computeStartSlotAtEpoch(e3), &.{
        .{ .target_slot = e1_slot, .root = root },
        .{ .target_slot = e2_slot, .root = root },
    });
    try h.cache.add(h.io, .{ .epoch = e3, .root = root }, e3_seed);

    // Driver lives at a much later slot; its view places `root` at the e1 and e2 boundaries.
    const driver = try buildDriver(h, driver_epoch * spe + 1, &.{
        .{ .target_slot = e1_slot, .root = root },
        .{ .target_slot = e2_slot, .root = root },
    });
    defer destroyTestState(allocator, driver);

    const persisted = try h.cache.processState(h.io, makeRoot(0xFD), driver);
    try testing.expectEqual(@as(usize, 2), persisted);
    try testing.expect(h.cache.cache.get(.{ .root = root, .epoch = e1 }).?.item == .persisted);
    try testing.expect(h.cache.cache.get(.{ .root = root, .epoch = e2 }).?.item == .persisted);

    // Reload each persisted checkpoint and confirm its slot is the cp state's boundary slot, NOT the
    // driver's slot (which would prove the wrong-bytes-persisted bug).
    const r1 = (try h.cache.getOrReload(h.io, .{ .epoch = e1, .root = root })).?;
    try testing.expectEqual(e1_slot, try r1.state.slot());
    const r2 = (try h.cache.getOrReload(h.io, .{ .epoch = e2, .root = root })).?;
    try testing.expectEqual(e2_slot, try r2.state.slot());
}

test "PersistentCheckpointStateCache processState handles a genesis epoch-0 checkpoint" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root = makeRoot(0xE0);

    // Epoch 0 (boundary slot 0) plus two later epochs, so processState treats epoch 0 as a lowest
    // excess epoch to persist.
    try h.cache.add(h.io, .{ .epoch = 0, .root = root }, try h.factory.make(spe));
    try h.cache.add(h.io, .{ .epoch = 1, .root = root }, try h.factory.make(computeStartSlotAtEpoch(1)));
    try h.cache.add(h.io, .{ .epoch = 2, .root = root }, try h.factory.make(computeStartSlotAtEpoch(2)));

    // Place `root` at the epoch-0 boundary (slot 0) and the epoch-1 boundary so both persist.
    const driver = try buildDriver(h, 2 * spe + 1, &.{
        .{ .target_slot = 0, .root = root },
        .{ .target_slot = 1 * spe, .root = root },
    });
    defer destroyTestState(allocator, driver);

    // No underflow panic; epochs 0 and 1 are the two excess epochs below the kept floor, and each
    // persists its single in-memory boundary checkpoint (count is exactly 2, not a lower bound).
    const persisted = try h.cache.processState(h.io, makeRoot(0xFC), driver);
    try testing.expectEqual(@as(usize, 2), persisted);
    try testing.expect(h.cache.cache.get(.{ .root = root, .epoch = 0 }).?.item == .persisted);
}

test "PersistentCheckpointStateCache processState handles a large max_epochs_in_memory" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 100, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root = makeRoot(0x4B);

    // 101 distinct tracked epochs `[20 .. 120]` exceed the 100-epoch band by one.
    const top_epoch: Epoch = 120;
    const lowest_epoch = top_epoch - 100;

    var e: Epoch = lowest_epoch;
    while (e <= top_epoch) : (e += 1) {
        try h.cache.add(h.io, .{ .epoch = e, .root = root }, try h.factory.make(computeStartSlotAtEpoch(e)));
    }
    try testing.expectEqual(@as(u64, 101), h.cache.epoch_index.count());

    // Driver past the highest epoch; its view places `root` at the lowest epoch's boundary, so the one
    // epoch below the 100-band persists.
    const driver = try buildDriver(h, top_epoch * spe + 1, &.{
        .{ .target_slot = computeStartSlotAtEpoch(lowest_epoch), .root = root },
    });
    defer destroyTestState(allocator, driver);

    // Exactly the lowest epoch is persisted (count is exact, not a lower bound); the highest stays
    // resident and the lowest's entry is now `.persisted`.
    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, makeRoot(0xFA), driver));
    try testing.expect(h.cache.cache.get(.{ .root = root, .epoch = lowest_epoch }).?.item == .persisted);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = top_epoch }) != null);
}

test "PersistentCheckpointStateCache getOrReloadLatest reloads a persisted checkpoint from disk" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0xD0);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp_epoch = seed_epoch - 2;
    const persisted_slot = computeStartSlotAtEpoch(cp_epoch);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^                       ^
    //                    |                       |
    //                    {cp_epoch, root}        seed
    //                    persisted               (epoch 22, in memory)
    //         seed VIEWS root at the epoch-20 boundary -> reloaded by getOrReloadLatest

    // Resident same-view seed in a later epoch (views cp.root at the cp slot), so findSeedStateToReload
    // returns it (and its pool) for the reload.
    const seed = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed);

    _ = try persistByHand(h, .{ .root = root, .epoch = cp_epoch }, persisted_slot);

    // getLatest is disk-blind: the persisted-only checkpoint is invisible to it.
    try testing.expect(h.cache.getLatest(h.io, root, cp_epoch) == null);

    const reloaded = (try h.cache.getOrReloadLatest(h.io, root, cp_epoch)).?;
    try testing.expectEqual(persisted_slot, try reloaded.state.slot());

    // Below the tracked epoch: max_epoch excludes every candidate → null.
    try testing.expect((try h.cache.getOrReloadLatest(h.io, root, cp_epoch - 1)) == null);

    try testing.expect((try h.cache.getOrReloadLatest(h.io, makeRoot(0xD9), cp_epoch)) == null);
}

test "PersistentCheckpointStateCache getOrReload treats a malformed persisted blob as a miss" {
    // Too short to even hold the slot field; the slot read returns a catchable error.
    try expectMalformedBlobMiss(testing.allocator, .below_slot_offset);
    // Slot bytes survive (fork resolves to electra) but the blob is one byte short of the fixed section,
    // so loadState's min_size guard rejects it before readFieldRanges can OOB-slice.
    try expectMalformedBlobMiss(testing.allocator, .sub_min_size);
}

test "PersistentCheckpointStateCache findSeedStateToReload selects the same-view state" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    // findSeedStateToReload never deserializes persisted bytes, so its states are fork-agnostic and
    // use arbitrary absolute epochs: the band epoch is 21, the reloaded cp an epoch below at 20.
    const band_epoch: Epoch = 21;
    const band_slot = computeStartSlotAtEpoch(band_epoch);

    // The checkpoint being reloaded sits an epoch below the band; its boundary slot is what a
    // same-view seed must reference.
    const cp_epoch: Epoch = 20;
    const reloaded_cp_slot = computeStartSlotAtEpoch(cp_epoch);
    const cp_root = makeRoot(0x5A);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^           ^
    //                    |           |
    //                    cp_root     band 21: same_view_root + other_root
    //                    (reload)    same_view VIEWS cp_root at the epoch-20 boundary

    // Two states at the lowest band epoch, different roots. `same_view` references cp_root at the
    // reloaded cp slot; `other` references a different root there.
    const same_view_root = makeRoot(0x51);
    const other_root = makeRoot(0x52);
    const same_view = try h.factory.makeWithBlockRoot(band_slot, reloaded_cp_slot, cp_root);
    try h.cache.add(h.io, .{ .epoch = band_epoch, .root = same_view_root }, same_view);
    const other = try h.factory.makeWithBlockRoot(band_slot, reloaded_cp_slot, makeRoot(0x99));
    try h.cache.add(h.io, .{ .epoch = band_epoch, .root = other_root }, other);

    // Same-view discrimination: the seed must be the state that views cp_root at the cp slot.
    const seed = (try h.cache.findSeedStateToReload(h.io, .{ .epoch = cp_epoch, .root = cp_root })).?;
    try testing.expect(seed == same_view);

    // For a random target root with no same-view match in the max (and only) band epoch, the scan
    // falls through to the block-cache seed rather than returning a band state.
    const block_seed = try h.block_cache.add(h.io, try h.factory.make(band_slot), true);
    const fallback = (try h.cache.findSeedStateToReload(h.io, .{ .epoch = cp_epoch, .root = makeRoot(0x77) })).?;
    try testing.expect(fallback == block_seed);
}

test "PersistentCheckpointStateCache findSeedStateToReload returns a middle band epoch's first state" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    // findSeedStateToReload never deserializes, so its states use arbitrary absolute epochs: two band
    // epochs 21 (`lower`) and 22 (`higher`), with the reloaded cp an epoch below at 20. `lower` sits
    // below the max band epoch `higher`, so the scan reaches it first.
    const higher: Epoch = 22;
    const lower: Epoch = 21;
    const cp_epoch: Epoch = 20;
    const lower_slot = computeStartSlotAtEpoch(lower);
    const higher_slot = computeStartSlotAtEpoch(higher);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^           ^           ^
    //                    |           |           |
    //                    cp_epoch    lower 21:      higher 22:
    //                    (reload)    first + second max_state (unreached)
    //         no same-view in lower -> first returned before higher / block seed

    // Two states in `lower`, neither viewing cp.root at the reloaded cp slot; insertion order makes
    // `first` (root 0x61) the recorded state.
    const first = try h.factory.make(lower_slot);
    const second = try h.factory.make(lower_slot);
    try h.cache.add(h.io, .{ .epoch = lower, .root = makeRoot(0x61) }, first);
    try h.cache.add(h.io, .{ .epoch = lower, .root = makeRoot(0x62) }, second);

    // One state in the max (`higher`) epoch and a block-cache seed — both must be UNREACHED.
    const max_state = try h.factory.make(higher_slot);
    try h.cache.add(h.io, .{ .epoch = higher, .root = makeRoot(0x71) }, max_state);
    _ = try h.block_cache.add(h.io, try h.factory.make(higher_slot), true);

    // A root nothing views: `lower` has no same-view match, so its first state is returned before the
    // max epoch or the block-cache seed is consulted.
    const seed = (try h.cache.findSeedStateToReload(h.io, .{ .epoch = cp_epoch, .root = makeRoot(0x77) })).?;
    try testing.expect(seed == first);
    try testing.expect(seed != second);
    try testing.expect(seed != max_state);
}

test "PersistentCheckpointStateCache processState persists the exact disk key order" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    // root_0b is the epoch-20 boundary root; root_0a is an unknown-view reorg root in epoch 20
    // (persisted as reorg insurance). Both must reach disk; the epoch's root list iterates in
    // insertion order, so (root_0b added first, then root_0a) they hit disk as [root_0b, root_0a].
    const root_0b = makeRoot(0x0B);
    const root_0a = makeRoot(0x0A);
    const root_1 = makeRoot(0x02);

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^           ^        ^
    //                   ||           |        |
    //                   |root_0b---root_1---driver
    //                   |
    //                   root_0a   (unknown to the driver -> persisted second)

    try h.cache.add(h.io, .{ .epoch = 20, .root = root_0b }, try h.factory.make(20 * spe));
    try h.cache.add(h.io, .{ .epoch = 20, .root = root_0a }, try h.factory.make(20 * spe + 1));
    try h.cache.add(h.io, .{ .epoch = 21, .root = root_1 }, try h.factory.make(21 * spe));

    // Epoch-20 boundary is root_0b; root_0a is unknown to this view → both persist.
    const driver = try buildDriver(h, 22 * spe + 1, &.{
        .{ .target_slot = 20 * spe, .root = root_0b },
    });
    defer destroyTestState(allocator, driver);

    _ = try h.cache.processState(h.io, makeRoot(0xFB), driver);

    const keys = try h.store.?.datastore().readKeys(h.io, allocator);
    defer allocator.free(keys);

    // Insertion order (root_0b added before root_0a): a deterministic consequence of the per-epoch
    // root list. `readLatestSafe` sorts on read, so no production consumer depends on this order.
    const expected = [_]DatastoreKey{
        datastoreKey(.{ .root = root_0b, .epoch = 20 }),
        datastoreKey(.{ .root = root_0a, .epoch = 20 }),
    };
    try testing.expectEqual(expected.len, keys.len);
    for (expected, keys) |want, got| {
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "PersistentCheckpointStateCache and BlockStateCache metric hooks increment counters" {
    const allocator = testing.allocator;
    // Restore the process-global metrics after the test so the real `.impl` counters/gauges do not
    // leak into sibling tests sharing this binary.
    const saved_checkpoint = metrics.checkpoint_cache_metrics;
    const saved_block = metrics.block_cache_metrics;
    try metrics.init(allocator, std.testing.io, .{});
    defer {
        metrics.deinit();
        metrics.checkpoint_cache_metrics = saved_checkpoint;
        metrics.block_cache_metrics = saved_block;
    }

    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    // Snapshot the counters so the test is robust to any earlier increments in this process.
    const cp0 = metrics.checkpoint().*;
    const block0 = metrics.block().*;

    const root = makeRoot(0x42);
    try h.cache.add(h.io, .{ .epoch = 5, .root = root }, try h.factory.make(500));
    _ = h.cache.get(h.io, .{ .epoch = 5, .root = root }); // hit
    _ = h.cache.get(h.io, .{ .epoch = 9, .root = root }); // miss (lookup, no hit)

    try testing.expectEqual(@as(u64, 1), metrics.checkpoint().adds.impl.count - cp0.adds.impl.count);
    try testing.expectEqual(@as(u64, 2), metrics.checkpoint().lookups.impl.count - cp0.lookups.impl.count);
    try testing.expectEqual(@as(u64, 1), metrics.checkpoint().hits.impl.count - cp0.hits.impl.count);

    const bs = try h.factory.make(600);
    const bkey = (try bs.state.hashTreeRoot()).*;
    _ = try h.block_cache.add(h.io, bs, true);
    _ = h.block_cache.get(h.io, bkey); // hit
    var miss_key: Root = undefined;
    @memset(&miss_key, 0xFA);
    _ = h.block_cache.get(h.io, miss_key); // miss

    try testing.expectEqual(@as(u64, 1), metrics.block().adds.impl.count - block0.adds.impl.count);
    try testing.expectEqual(@as(u64, 2), metrics.block().lookups.impl.count - block0.lookups.impl.count);
    try testing.expectEqual(@as(u64, 1), metrics.block().hits.impl.count - block0.hits.impl.count);
}

test "PersistentCheckpointStateCache unbounded default never prunes persisted states" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 2 });
    defer h.deinit();

    const root = makeRoot(0x6F);
    const epoch_count: Epoch = 12;
    var epoch: Epoch = 1;
    while (epoch <= epoch_count) : (epoch += 1) {
        try h.cache.add(h.io, .{ .epoch = epoch, .root = root }, try h.factory.make(epoch * 100));
        // The count grows with every distinct epoch — nothing is ever pruned on the unbounded path.
        try testing.expectEqual(@as(u64, epoch), h.cache.epoch_index.count());
    }

    try testing.expectEqual(@as(u64, epoch_count), h.cache.epoch_index.count());
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 1 }) != null);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = epoch_count }) != null);
}

test "PersistentCheckpointStateCache hot scans stay correct past 128 tracked epochs" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 2 });
    defer h.deinit();

    const root = makeRoot(0x7E);

    // Walk forward over enough distinct epochs to exceed 128 tracked entries. At each step the epoch
    // falling out of the 2-epoch in-memory band is persisted while its boundary is still inside the
    // historical-roots window, mirroring steady-state operation.
    const epoch_span: Epoch = 140;
    const first_epoch: Epoch = 20;
    const top_epoch = first_epoch + epoch_span;
    var e: Epoch = first_epoch;
    while (e <= top_epoch) : (e += 1) {
        try h.cache.add(h.io, .{ .epoch = e, .root = root }, try h.factory.make(computeStartSlotAtEpoch(e)));

        // Driver sits just past epoch `e`; its view carries `root` at epoch `(e-2)`'s boundary so the
        // one epoch newly below the band persists this step. The first two steps have no epoch below
        // the band yet, so the driver carries no view root.
        var stamps: [1]RootAt = undefined;
        const driver_roots: []const RootAt = if (e >= first_epoch + 2) blk: {
            stamps[0] = .{ .target_slot = computeStartSlotAtEpoch(e - 2), .root = root };
            break :blk &stamps;
        } else &.{};
        const driver = try buildDriver(h, computeStartSlotAtEpoch(e) + 1, driver_roots);
        defer destroyTestState(allocator, driver);
        _ = try h.cache.processState(h.io, makeRoot(0xAA), driver);
    }

    // The tracked index holds well over 128 distinct epochs — beyond any fixed stack buffer.
    try testing.expect(h.cache.epoch_index.count() > 128);

    // (a) processState evicted the TRUE-oldest epochs: only the highest `max_epochs_in_memory` epochs
    // remain in memory, not a hash-order subset.
    const sizes = h.cache.collectSizeCounts();
    try testing.expectEqual(@as(u64, 2), sizes.in_memory);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = top_epoch }) != null);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = top_epoch - 1 }) != null);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = top_epoch - 2 }) == null);

    // (b) A persisted epoch below the in-memory band is still reloadable — the streaming reload scan
    // works against an `epoch_index` of any size.
    const on_disk_epoch = top_epoch - 2;
    try testing.expect(h.cache.cache.get(.{ .root = root, .epoch = on_disk_epoch }).?.item == .persisted);
    const reloaded = try h.cache.getOrReloadLatest(h.io, root, on_disk_epoch);
    try testing.expect(reloaded != null);
    try testing.expectEqual(computeStartSlotAtEpoch(on_disk_epoch), try reloaded.?.state.slot());
}

test "PersistentCheckpointStateCache tracks unbounded distinct roots per epoch" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const epoch: Epoch = 5;
    const count = 40;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try h.cache.add(h.io, .{ .epoch = epoch, .root = makeRoot(@intCast(i + 1)) }, try h.factory.make(500));
    }

    try testing.expectEqual(@as(usize, count), h.cache.epoch_index.getPtr(epoch).?.items.len);
    try testing.expectEqual(@as(usize, count), h.cache.size());
    try testing.expect(h.cache.get(h.io, .{ .root = makeRoot(1), .epoch = epoch }) != null);
    try testing.expect(h.cache.get(h.io, .{ .root = makeRoot(@intCast(count)), .epoch = epoch }) != null);
}

test "PersistentCheckpointStateCache scanCpReadStats reads arithmetic over read-count vectors" {
    const allocator = testing.allocator;

    const Row = struct {
        name: []const u8,
        read_counts: []const u64,
        sum: f64,
        avg: f64,
        min: f64,
        max: f64,
    };
    inline for (.{
        Row{ .name = "excludes never-read", .read_counts = &.{ 3, 1, 0 }, .sum = 4, .avg = 2, .min = 1, .max = 3 },
        Row{ .name = "single read entry", .read_counts = &.{ 0, 0, 5 }, .sum = 5, .avg = 5, .min = 5, .max = 5 },
        Row{ .name = "uniform reads", .read_counts = &.{ 2, 2, 2 }, .sum = 6, .avg = 2, .min = 2, .max = 2 },
        Row{ .name = "spread reads", .read_counts = &.{ 1, 4, 7 }, .sum = 12, .avg = 4, .min = 1, .max = 7 },
    }) |row| {
        const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
        defer h.deinit();

        const root = makeRoot(0x11);
        for (row.read_counts, 0..) |reads, i| {
            const cp = Checkpoint{ .epoch = @intCast(i + 1), .root = root };
            try h.cache.add(h.io, cp, try h.factory.make((i + 1) * 100));
            for (0..reads) |_| _ = h.cache.get(h.io, cp);
        }

        const stats = h.cache.scanCpReadStats(h.io);
        testing.expectEqual(row.sum, stats.reads.sum) catch |e| return reportRow(row.name, e);
        testing.expectEqual(row.avg, stats.reads.avg) catch |e| return reportRow(row.name, e);
        testing.expectEqual(row.min, stats.reads.min) catch |e| return reportRow(row.name, e);
        testing.expectEqual(row.max, stats.reads.max) catch |e| return reportRow(row.name, e);
    }
}

test "PersistentCheckpointStateCache scanCpReadStats seconds computed" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0x22);
    const c0 = Checkpoint{ .epoch = 1, .root = root };
    try h.cache.add(h.io, c0, try h.factory.make(100));
    try h.cache.add(h.io, .{ .epoch = 2, .root = root }, try h.factory.make(200));

    // Stamp only c0; the other entry stays unread so it must not contribute to the seconds stats.
    _ = h.cache.get(h.io, c0);

    // Exact seconds are timing-dependent; assert only the bounds and that the single stamped entry
    // counts (min == max for one sample).
    const stats = h.cache.scanCpReadStats(h.io);
    try testing.expect(stats.secs.max >= 0);
    try testing.expect(stats.secs.min >= 0);
    try testing.expectEqual(stats.secs.min, stats.secs.max);
    try testing.expectEqual(stats.secs.sum, stats.secs.max);
    try testing.expectEqual(@as(f64, 1), stats.reads.sum);
}

test "PersistentCheckpointStateCache scanCpReadStats empty cache is all-zero" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const stats = h.cache.scanCpReadStats(h.io);
    try testing.expectEqual(metrics.AvgMinMax{}, stats.reads);
    try testing.expectEqual(metrics.AvgMinMax{}, stats.secs);
}

test "PersistentCheckpointStateCache read_count is per-key and survives value overwrite" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0x44);
    const cp = Checkpoint{ .epoch = 5, .root = root };
    try h.cache.add(h.io, cp, try h.factory.make(500));

    _ = h.cache.get(h.io, cp);
    _ = h.cache.get(h.io, cp);
    try testing.expectEqual(@as(u64, 2), h.cache.cache.getPtr(cp).?.read_count);

    // Overwrite the SAME key with a new state. The counters are per-key and the overwrite carries them
    // forward (never reset), AND `add` reads the prior entry — that read is itself a logical hit that
    // bumps the count once (2 → 3) before carrying it onto the new value.
    try h.cache.add(h.io, cp, try h.factory.make(501));
    try testing.expectEqual(@as(u64, 3), h.cache.cache.getPtr(cp).?.read_count);

    // A drive of the in_memory→persisted tier transition (via insertEntry) carries the count forward
    // unchanged: insertEntry is the low-level writer and does NOT bump reads (only logical lookups do).
    const dk = blk: {
        const s = try h.factory.make(502);
        const bytes = try s.state.serialize(allocator);
        defer allocator.free(bytes);
        const key = try h.store.?.datastore().write(h.io, cp, bytes);
        destroyTestState(allocator, s);
        break :blk key;
    };
    // insertEntry owns the tier transition: overwriting the in_memory entry with `.persisted` destroys
    // the displaced resident (last writer wins), so no manual free here.
    try h.cache.insertEntry(cp, .{ .persisted = dk });
    try testing.expect(h.cache.cache.getPtr(cp).?.item == .persisted);
    try testing.expectEqual(@as(u64, 3), h.cache.cache.getPtr(cp).?.read_count);
}

test "PersistentCheckpointStateCache scanCpReadStats counts a persisted entry's reads" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const cp = Checkpoint{ .epoch = 5, .root = makeRoot(0x55) };
    _ = try persistByHand(h, cp, 500);

    // get() returns null for a persisted entry but is still a hit → bumps read_count.
    for (0..3) |_| try testing.expect(h.cache.get(h.io, cp) == null);

    const stats = h.cache.scanCpReadStats(h.io);
    try testing.expectEqual(@as(f64, 3), stats.reads.sum);
    try testing.expectEqual(@as(f64, 3), stats.reads.min);
    try testing.expectEqual(@as(f64, 3), stats.reads.max);
}

test "PersistentCheckpointStateCache getLatest bumps every probed candidate" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0x66);
    const lo = Checkpoint{ .epoch = 5, .root = root };
    const hi = Checkpoint{ .epoch = 7, .root = root };

    try h.cache.add(h.io, lo, try h.factory.make(500));
    const winner = h.cache.cache.getPtr(lo).?.item.in_memory.state;

    // Higher epoch: a persisted-only entry built by hand, so getLatest probes it first (DESC) and
    // bumps it before reaching the in-memory winner.
    _ = try persistByHand(h, hi, 700);

    // getLatest returns the in-memory winner (epoch 5), not the higher persisted candidate.
    try testing.expectEqual(winner, h.cache.getLatest(h.io, root, 100).?);

    // The higher persisted candidate was probed+bumped on the way down; the winner bumped exactly once.
    try testing.expectEqual(@as(u64, 1), h.cache.cache.getPtr(hi).?.read_count);
    try testing.expectEqual(@as(u64, 1), h.cache.cache.getPtr(lo).?.read_count);
}

test "PersistentCheckpointStateCache scanCpReadStats reflects only survivors after prune and clear" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0x77);
    const c1 = Checkpoint{ .epoch = 1, .root = root };
    const c2 = Checkpoint{ .epoch = 2, .root = root };
    try h.cache.add(h.io, c1, try h.factory.make(100));
    try h.cache.add(h.io, c2, try h.factory.make(200));

    for (0..2) |_| _ = h.cache.get(h.io, c1);
    for (0..2) |_| _ = h.cache.get(h.io, c2);
    try h.cache.pruneFinalized(h.io, 2);

    // c1 was removed; only c2's reads (2) remain. The miss-probe of pruned epoch 1 returns null before
    // bumping (get bails on `getPtr orelse return null` before touching counters), so c2 stays at 2.
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 1 }) == null);
    const after_prune = h.cache.scanCpReadStats(h.io);
    try testing.expectEqual(@as(f64, 2), after_prune.reads.sum);
    try testing.expectEqual(@as(f64, 2), after_prune.reads.min);
    try testing.expectEqual(@as(f64, 2), after_prune.reads.max);

    h.cache.clear();
    const after_clear = h.cache.scanCpReadStats(h.io);
    try testing.expectEqual(metrics.AvgMinMax{}, after_clear.reads);
}

test "PersistentCheckpointStateCache getStateOrBytes double-bumps a persisted lookup" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const cp = Checkpoint{ .epoch = 5, .root = makeRoot(0x32) };
    _ = try persistByHand(h, cp, 500);

    try expectPersisted(h, cp);

    // One persisted lookup bumped twice: the in-memory `get` probe + the persisted branch.
    try testing.expectEqual(@as(u64, 2), h.cache.cache.getPtr(cp).?.read_count);
}

test "PersistentCheckpointStateCache findSeedStateToReload bumps scanned in-memory candidates" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const band_epoch = seed_epoch - 1;
    const band_slot = computeStartSlotAtEpoch(band_epoch);
    const cp_epoch = band_epoch - 1;

    const scanned = Checkpoint{ .epoch = band_epoch, .root = makeRoot(0x5C) };
    try h.cache.add(h.io, scanned, try h.factory.make(band_slot));
    try testing.expectEqual(@as(u64, 0), h.cache.cache.getPtr(scanned).?.read_count);

    // A block-cache seed backs the fall-through: the scanned candidate is the max band epoch, which
    // has no same-view match and so routes to the block cache seed rather than returning itself.
    _ = try h.block_cache.add(h.io, try h.factory.make(seed_slot), true);

    // Reload a cp an epoch below the band: the scan visits the band candidate and bumps it. The
    // `.?` asserts a seed was found; we care that the scan bumped the candidate it visited.
    _ = (try h.cache.findSeedStateToReload(h.io, .{ .epoch = cp_epoch, .root = makeRoot(0x77) })).?;
    try testing.expect(h.cache.cache.getPtr(scanned).?.read_count >= 1);
}

test "PersistentCheckpointStateCache processState at max=0 persists every checkpoint" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const r1 = makeRoot(0xB1);
    const r2 = makeRoot(0xB2);
    const r3 = makeRoot(0xB3);

    // One boundary cp per epoch (1, 2, 3); the driver's view places each root at its epoch boundary.
    try h.cache.add(h.io, .{ .epoch = 1, .root = r1 }, try h.factory.make(1 * spe));
    try h.cache.add(h.io, .{ .epoch = 2, .root = r2 }, try h.factory.make(2 * spe));
    try h.cache.add(h.io, .{ .epoch = 3, .root = r3 }, try h.factory.make(3 * spe));

    const driver = try buildDriver(h, 3 * spe + 1, &.{
        .{ .target_slot = 1 * spe, .root = r1 },
        .{ .target_slot = 2 * spe, .root = r2 },
        .{ .target_slot = 3 * spe, .root = r3 },
    });
    defer destroyTestState(allocator, driver);

    try testing.expectEqual(@as(usize, 3), try h.cache.processState(h.io, makeRoot(0xFF), driver));

    inline for (.{ .{ @as(Epoch, 1), r1 }, .{ @as(Epoch, 2), r2 }, .{ @as(Epoch, 3), r3 } }) |pair| {
        const cp = Checkpoint{ .epoch = pair[0], .root = pair[1] };
        try testing.expect(h.cache.get(h.io, cp) == null);
        // The persisted bytes are THIS cp's own serialization (the epoch-boundary state added for it),
        // not some other state's.
        const expected_bytes = try serializeFresh(h, pair[0] * spe);
        defer allocator.free(expected_bytes);
        try expectPersistedBytes(h, cp, expected_bytes);
        try testing.expect(h.cache.cache.get(cp).?.item == .persisted);
    }
    try testing.expectEqual(@as(u64, 0), h.cache.collectSizeCounts().in_memory);
}

test "PersistentCheckpointStateCache processState at max=0 persists a single tracked epoch without OOB" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root = makeRoot(0xC7);

    // A single tracked epoch — the minimal trigger for the zero-length-top_k floor read.
    try h.cache.add(h.io, .{ .epoch = 1, .root = root }, try h.factory.make(1 * spe));
    try testing.expectEqual(@as(u64, 1), h.cache.epoch_index.count());

    const driver = try buildDriver(h, 2 * spe + 1, &.{
        .{ .target_slot = 1 * spe, .root = root },
    });
    defer destroyTestState(allocator, driver);

    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, makeRoot(0xFE), driver));
    try testing.expect(h.cache.cache.get(.{ .epoch = 1, .root = root }).?.item == .persisted);
    try testing.expectEqual(@as(u64, 0), h.cache.collectSizeCounts().in_memory);
}

test "PersistentCheckpointStateCache processState at max=0 no reorg persists the boundary only" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_0a = makeRoot(0x0A);
    const root_0b = makeRoot(0x0B);
    const root_1a = makeRoot(0x64);
    const e: Epoch = 20;
    const b = e * spe;

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^     ^
    //                   ||     |
    //                   |root_0b --root_1a
    //                   |
    //                   root_0a

    try h.cache.add(h.io, .{ .epoch = e, .root = root_0a }, try h.factory.make(b));
    try h.cache.add(h.io, .{ .epoch = e, .root = root_0b }, try h.factory.make(b));

    // Driver view: epoch-20 boundary is root_0b, the slot before it is root_0a.
    const driver = try buildDriver(h, b + 3, &.{
        .{ .target_slot = b, .root = root_0b },
        .{ .target_slot = b - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver);

    // Only root_0b persists; root_0a is a known prev-root pruned from memory (never written).
    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, root_0b, driver));
    try expectNoBytes(h, .{ .epoch = e, .root = root_0a });
    {
        // root_0b's disk bytes are its own epoch-boundary serialization, byte-for-byte.
        const expected_bytes = try serializeFresh(h, b);
        defer allocator.free(expected_bytes);
        try expectPersistedBytes(h, .{ .epoch = e, .root = root_0b }, expected_bytes);
    }

    // A later same-fork state (root_1a in epoch 21) changes nothing: no new excess checkpoint.
    const driver1a = try buildDriver(h, b + spe + 3, &.{
        .{ .target_slot = b, .root = root_0b },
        .{ .target_slot = b - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver1a);
    try testing.expectEqual(@as(usize, 0), try h.cache.processState(h.io, root_1a, driver1a));
    try expectNoBytes(h, .{ .epoch = e, .root = root_0a });
    try expectPersisted(h, .{ .epoch = e, .root = root_0b });
}

test "PersistentCheckpointStateCache processState at max=0 reorg in same epoch persists nothing new" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_0a = makeRoot(0x0A);
    const root_0b = makeRoot(0x0B);
    const root_1a = makeRoot(0x64);
    const root_1b = makeRoot(0x65);
    const e: Epoch = 20;
    const b = e * spe;

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^     ^    ^
    //                   ||     |    |
    //                   |root_0b --root_1a
    //                   |      \    |
    //                   root_0a \--root_1b

    try h.cache.add(h.io, .{ .epoch = e, .root = root_0a }, try h.factory.make(b));
    try h.cache.add(h.io, .{ .epoch = e, .root = root_0b }, try h.factory.make(b));

    // Driver view: only root_0b persists (boundary); root_0a is the known prev-root. Count 1.
    const driver = try buildDriver(h, b + 3, &.{
        .{ .target_slot = b, .root = root_0b },
        .{ .target_slot = b - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver);
    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, root_0b, driver));
    try expectNoBytes(h, .{ .epoch = e, .root = root_0a });
    try expectPersisted(h, .{ .epoch = e, .root = root_0b });

    // A next-epoch sibling (root_1a) still views root_0b at the epoch-20 boundary: root_0b is
    // already on disk → no re-write. Count 0.
    const driver1a = try buildDriver(h, b + spe + 3, &.{
        .{ .target_slot = b, .root = root_0b },
    });
    defer destroyTestState(allocator, driver1a);
    try testing.expectEqual(@as(usize, 0), try h.cache.processState(h.io, root_1a, driver1a));

    // Regen re-seeds root_0b into memory (a state transition adds the regen'd boundary state back).
    try h.cache.add(h.io, .{ .epoch = e, .root = root_0b }, try h.factory.make(b));

    // A second same-epoch sibling (root_1b): root_0b is its boundary AND already persisted, so
    // this re-added boundary is not re-written. Count 0.
    const driver1b = try buildDriver(h, b + spe + 4, &.{
        .{ .target_slot = b, .root = root_0b },
    });
    defer destroyTestState(allocator, driver1b);
    try testing.expectEqual(@as(usize, 0), try h.cache.processState(h.io, root_1b, driver1b));

    try expectPersisted(h, .{ .epoch = e, .root = root_0b });
    try expectNoBytes(h, .{ .epoch = e, .root = root_0a });
}

test "PersistentCheckpointStateCache processState at max=0 reorg one epoch persists both checkpoints" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_0a = makeRoot(0x0A);
    const root_0b = makeRoot(0x0B);
    const root_1b = makeRoot(0x65);
    const e: Epoch = 20;
    const b = e * spe;

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^     ^    ^
    //                   ||     |    |
    //                   |root_0b --root_1a
    //                   |           |
    //                   root_0a----root_1b

    // Both roots are added fresh: a state transition adds each regen'd boundary state back to the cache.
    try h.cache.add(h.io, .{ .epoch = e, .root = root_0b }, try h.factory.make(b));
    try h.cache.add(h.io, .{ .epoch = e, .root = root_0a }, try h.factory.make(b));

    // Driver = root_1b (the reorged-back fork): the boundary AND its prev slot are both root_0a.
    const driver1b = try buildDriver(h, b + spe + 4, &.{
        .{ .target_slot = b, .root = root_0a },
        .{ .target_slot = b - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver1b);

    // Mainnet shape: root_1a is late and never processed alone, so the surviving root_1b persists
    // BOTH boundary cps — root_0a as its own view, root_0b as unknown-root reorg insurance.
    try testing.expectEqual(@as(usize, 2), try h.cache.processState(h.io, root_1b, driver1b));
    {
        // Each cp's disk bytes are its own epoch-boundary serialization (both added at slot `b`).
        const expected_bytes = try serializeFresh(h, b);
        defer allocator.free(expected_bytes);
        try expectPersistedBytes(h, .{ .epoch = e, .root = root_0a }, expected_bytes);
        try expectPersistedBytes(h, .{ .epoch = e, .root = root_0b }, expected_bytes);
    }
    try testing.expectEqual(@as(u64, 0), h.cache.collectSizeCounts().in_memory);
}

test "PersistentCheckpointStateCache processState at max=0 reorg one epoch twice persists both" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_0a = makeRoot(0x0A);
    const root_0b = makeRoot(0x0B);
    const root_1a = makeRoot(0x64);
    const root_1b = makeRoot(0x65);
    const e: Epoch = 20;
    const b = e * spe;

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^     ^    ^
    //                   ||     |    |
    //                   |root_0b --root_1a  (pass 1: persist root_0b)
    //                   |           |
    //                   root_0a----root_1b  (pass 2: persist root_0a)

    try h.cache.add(h.io, .{ .epoch = e, .root = root_0a }, try h.factory.make(b));
    try h.cache.add(h.io, .{ .epoch = e, .root = root_0b }, try h.factory.make(b));

    // Pass 1: root_1a's view → root_0b persists (boundary), root_0a drops (prev-root). Count 1.
    const driver1a = try buildDriver(h, b + spe + 3, &.{
        .{ .target_slot = b, .root = root_0b },
        .{ .target_slot = b - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver1a);
    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, root_1a, driver1a));
    try expectNoBytes(h, .{ .epoch = e, .root = root_0a });
    try expectPersisted(h, .{ .epoch = e, .root = root_0b });

    // Regen re-adds root_0a, then drive root_1b's view: root_0a persists (a fresh write +1),
    // root_0b is unknown to this view but already on disk → not re-written. Count 1.
    try h.cache.add(h.io, .{ .epoch = e, .root = root_0a }, try h.factory.make(b));
    const driver1b = try buildDriver(h, b + spe + 4, &.{
        .{ .target_slot = b, .root = root_0a },
        .{ .target_slot = b - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver1b);
    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, root_1b, driver1b));
    try expectPersisted(h, .{ .epoch = e, .root = root_0a });
    try expectPersisted(h, .{ .epoch = e, .root = root_0b });
}

test "PersistentCheckpointStateCache processState at max=0 reorg two epochs persists four checkpoints" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_0a = makeRoot(0x0A);
    const root_0b = makeRoot(0x0B);
    const root_1 = makeRoot(0x02);
    const root_2 = makeRoot(0x64);
    const e0: Epoch = 20;
    const e1: Epoch = 21;
    const b0 = e0 * spe;
    const b1 = e1 * spe;

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                   ^^           ^       ^
    //                   ||           |       |
    //                   |root_0b---root_1    |
    //                   |                    |
    //                   root_0a------------root_2
    //                                ^
    //                              {root_0a, 21}=cp1a

    try h.cache.add(h.io, .{ .epoch = e0, .root = root_0a }, try h.factory.make(b0));
    try h.cache.add(h.io, .{ .epoch = e0, .root = root_0b }, try h.factory.make(b0));

    // Pass 1 — root_0b's view: root_0b@20 persists (boundary), root_0a drops. Count 1.
    const driver0 = try buildDriver(h, b0 + spe + 3, &.{
        .{ .target_slot = b0, .root = root_0b },
        .{ .target_slot = b0 - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver0);
    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, root_0b, driver0));

    // Pass 2 — add cp1@21 and drive its boundary: root_1 persists. Count 1.
    try h.cache.add(h.io, .{ .epoch = e1, .root = root_1 }, try h.factory.make(b1));
    const driver1 = try buildDriver(h, b1 + 3, &.{
        .{ .target_slot = b1, .root = root_1 },
        .{ .target_slot = b0, .root = root_0b },
        .{ .target_slot = b0 - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver1);
    try testing.expectEqual(@as(usize, 1), try h.cache.processState(h.io, root_1, driver1));

    // Regen populates cp0a@20 and cp1a@21 (both the reorged-back root_0a fork).
    try h.cache.add(h.io, .{ .epoch = e0, .root = root_0a }, try h.factory.make(b0));
    try h.cache.add(h.io, .{ .epoch = e1, .root = root_0a }, try h.factory.make(b1));

    // Pass 3 — root_2, two epochs deep, views root_0a at BOTH the 20 and 21 boundaries. cp0a@20 and
    // cp1a@21 persist (each its boundary); root_0b@20 and root_1@21 are unknown-but-already-on-disk
    // (no re-write). Count 2.
    const driver2 = try buildDriver(h, b1 + spe + 3, &.{
        .{ .target_slot = b0, .root = root_0a },
        .{ .target_slot = b0 - 1, .root = root_0a },
        .{ .target_slot = b1, .root = root_0a },
        .{ .target_slot = b1 - 1, .root = root_0a },
    });
    defer destroyTestState(allocator, driver2);
    try testing.expectEqual(@as(usize, 2), try h.cache.processState(h.io, root_2, driver2));

    inline for (.{
        .{ e0, root_0b }, .{ e1, root_1 }, .{ e0, root_0a }, .{ e1, root_0a },
    }) |pair| {
        try expectPersisted(h, .{ .epoch = pair[0], .root = pair[1] });
    }
    try testing.expectEqual(@as(u64, 0), h.cache.collectSizeCounts().in_memory);
    {
        const keys = try h.store.?.datastore().readKeys(h.io, allocator);
        defer allocator.free(keys);
        try testing.expectEqual(@as(usize, 4), keys.len);

        // Assert the disk holds EXACTLY the four expected cp keys, by membership. Do not assert key
        // ORDER: the datastore's key order is not semantically load-bearing (readLatestSafe sorts by
        // epoch), so an order assertion here would be brittle.
        const expected_keys = [_]DatastoreKey{
            datastoreKey(.{ .epoch = e0, .root = root_0b }),
            datastoreKey(.{ .epoch = e1, .root = root_1 }),
            datastoreKey(.{ .epoch = e0, .root = root_0a }),
            datastoreKey(.{ .epoch = e1, .root = root_0a }),
        };
        for (expected_keys) |want| {
            var found = false;
            for (keys) |got| {
                if (std.mem.eql(u8, &want, &got)) {
                    found = true;
                    break;
                }
            }
            try testing.expect(found);
        }
    }
}

test "PersistentCheckpointStateCache getOrReload at max=0 seeds from the block state cache" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const root = makeRoot(0xD0);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp_epoch = seed_epoch - 2;
    const persisted_slot = computeStartSlotAtEpoch(cp_epoch);
    const cp = Checkpoint{ .epoch = cp_epoch, .root = root };

    // epoch: 19         20           21         22          23
    //        |-----------|-----------|-----------|-----------|
    //                    ^                       ^
    //                    |                       |
    //                    cp                      block-cache seed
    //                    persisted               (epoch 22, getSeedState)
    //         max=0: findSeedStateToReload falls through to the block-cache seed

    // Seed the BLOCK cache (not the cp cache): findSeedStateToReload at max=0 falls straight through
    // to getSeedState.
    _ = try h.block_cache.add(h.io, try h.factory.make(seed_slot), true);

    _ = try persistByHand(h, cp, persisted_slot);

    // get is memory-blind; getOrReload faults it in via the block-cache seed.
    try testing.expect(h.cache.get(h.io, cp) == null);
    const reloaded = (try h.cache.getOrReload(h.io, cp)).?;
    try testing.expectEqual(persisted_slot, try reloaded.state.slot());
    try testing.expect(h.cache.cache.get(cp).?.item == .in_memory);
}

test "PersistentCheckpointStateCache getOrReload at max=0 with empty block cache misses gracefully" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const cp = Checkpoint{ .epoch = 5, .root = makeRoot(0xE0) };
    _ = try persistByHand(h, cp, 40);

    // No in-memory band (max=0) AND empty block cache → no seed → null, no panic.
    try testing.expect((try h.cache.getOrReload(h.io, cp)) == null);
}

test "PersistentCheckpointStateCache prunePersistedStates bound holds at max=0" {
    const allocator = testing.allocator;

    {
        // Finite disk: ceiling = 2 + 0 = 2; adding 4 distinct epochs prunes the oldest 2.
        const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0, .max_epochs_on_disk = 2 });
        defer h.deinit();

        const root = makeRoot(0x70);
        var epoch: Epoch = 1;
        while (epoch <= 4) : (epoch += 1) {
            try h.cache.add(h.io, .{ .epoch = epoch, .root = root }, try h.factory.make(epoch * 100));
        }
        try testing.expectEqual(@as(u64, 2), h.cache.epoch_index.count());
        try testing.expect(h.cache.get(h.io, .{ .epoch = 1, .root = root }) == null);
        try testing.expect(h.cache.get(h.io, .{ .epoch = 2, .root = root }) == null);
        try testing.expect(h.cache.get(h.io, .{ .epoch = 4, .root = root }) != null);
    }

    {
        // Default (unbounded) disk at max=0: never prunes.
        const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 0 });
        defer h.deinit();

        const root = makeRoot(0x71);
        var epoch: Epoch = 1;
        while (epoch <= 6) : (epoch += 1) {
            try h.cache.add(h.io, .{ .epoch = epoch, .root = root }, try h.factory.make(epoch * 100));
            try testing.expectEqual(@as(u64, epoch), h.cache.epoch_index.count());
        }
        try testing.expect(h.cache.get(h.io, .{ .epoch = 1, .root = root }) != null);
    }
}

test "PersistentCheckpointStateCache getOrReload with a buffer pool matches the null-pool reload" {
    const allocator = testing.allocator;
    var pool = try BufferPool.init(allocator, 1);
    defer pool.deinit();
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8, .buffer_pool = &pool });
    defer h.deinit();

    const root = makeRoot(0xDA);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp_epoch = seed_epoch - 2;
    const cp = Checkpoint{ .epoch = cp_epoch, .root = root };
    const persisted_slot = computeStartSlotAtEpoch(cp_epoch);

    const seed = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed);
    _ = try persistByHand(h, cp, persisted_slot);

    try testing.expect(h.cache.get(h.io, cp) == null);
    const reloaded = (try h.cache.getOrReload(h.io, cp)).?;
    try testing.expectEqual(persisted_slot, try reloaded.state.slot());
    const item = h.cache.cache.get(cp).?.item;
    try testing.expect(item == .in_memory);
    try testing.expect(item.in_memory.persisted_key != null);
    // The reload leased validators bytes from the pool (growing it from the tiny init) and released them.
    try testing.expect(!pool.busy());
    try testing.expect(pool.capacity() > 1);
}

test "PersistentCheckpointStateCache processState persist with a buffer pool matches serializeFresh" {
    const allocator = testing.allocator;
    var pool = try BufferPool.init(allocator, 1);
    defer pool.deinit();
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8, .buffer_pool = &pool });
    defer h.deinit();

    const root_a = makeRoot(0xA0);
    const root_b = makeRoot(0xB0);
    const spe = preset.SLOTS_PER_EPOCH;

    try h.cache.add(h.io, .{ .epoch = 1, .root = root_b }, try h.factory.make(100));
    try h.cache.add(h.io, .{ .epoch = 2, .root = root_a }, try h.factory.make(200));
    try h.cache.add(h.io, .{ .epoch = 3, .root = root_a }, try h.factory.make(300));

    const driver = try buildDriver(h, 3 * spe + 1, &.{
        .{ .target_slot = 1 * spe, .root = root_b },
        .{ .target_slot = 2 * spe, .root = root_a },
    });
    defer destroyTestState(allocator, driver);

    try testing.expectEqual(@as(usize, 2), try h.cache.processState(h.io, makeRoot(0xFF), driver));

    // Pool-serialized disk bytes are byte-identical to a fresh serialization of the same state.
    const expected1 = try serializeFresh(h, 100);
    defer allocator.free(expected1);
    try expectPersistedBytes(h, .{ .epoch = 1, .root = root_b }, expected1);
    const expected2 = try serializeFresh(h, 200);
    defer allocator.free(expected2);
    try expectPersistedBytes(h, .{ .epoch = 2, .root = root_a }, expected2);

    try testing.expect(h.cache.get(h.io, .{ .root = root_a, .epoch = 3 }) != null);
    try testing.expect(!pool.busy());
}

test "PersistentCheckpointStateCache buffer pool reuses its buffer across sequential reloads" {
    const allocator = testing.allocator;
    var pool = try BufferPool.init(allocator, 1);
    defer pool.deinit();
    const cap_initial = pool.capacity();

    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8, .buffer_pool = &pool });
    defer h.deinit();

    const root = makeRoot(0xAB);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp_epoch = seed_epoch - 2;
    const cp = Checkpoint{ .epoch = cp_epoch, .root = root };
    const persisted_slot = computeStartSlotAtEpoch(cp_epoch);

    const seed = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed);
    _ = try persistByHand(h, cp, persisted_slot);
    const r1 = (try h.cache.getOrReload(h.io, cp)).?;
    try testing.expectEqual(persisted_slot, try r1.state.slot());
    const cap_after_1 = pool.capacity();
    try testing.expect(cap_after_1 > cap_initial);

    h.cache.clear();

    // Same-size second reload: the pool reuses the grown buffer — no second grow.
    const seed2 = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed2);
    _ = try persistByHand(h, cp, persisted_slot);
    const r2 = (try h.cache.getOrReload(h.io, cp)).?;
    try testing.expectEqual(persisted_slot, try r2.state.slot());
    try testing.expectEqual(cap_after_1, pool.capacity());
}

const DoubleFreeDetectAllocator = @import("testing_allocators").DoubleFreeDetectAllocator;

test "PersistentCheckpointStateCache getOrReload owns the reloaded state and frees it exactly once" {
    const allocator = testing.allocator;
    const h = try TestHarness.init(allocator, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0xAA);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp_epoch = seed_epoch - 2;
    const cp = Checkpoint{ .epoch = cp_epoch, .root = root };
    const persisted_slot = computeStartSlotAtEpoch(cp_epoch);

    // Resident same-view seed (views cp.root at the cp slot) so findSeedStateToReload yields it.
    const seed = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed);

    _ = try persistByHand(h, cp, persisted_slot);

    // First reload faults the state in and the cache takes ownership of it.
    const reloaded = (try h.cache.getOrReload(h.io, cp)).?;
    try testing.expectEqual(persisted_slot, try reloaded.state.slot());
    try testing.expect(h.cache.cache.get(.{ .root = root, .epoch = cp_epoch }).?.item == .in_memory);

    // clear() must free the reloaded state exactly once (a double-armed transfer errdefer would
    // double-free the underlying AnyBeaconState here).
    h.cache.clear();
    try testing.expectEqual(@as(usize, 0), h.cache.size());

    // Second cycle: re-seed, re-persist, fault the same cp in again, then clear again — pinning the
    // own-then-free path a second time.
    const seed2 = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed2);
    _ = try persistByHand(h, cp, persisted_slot);
    const reloaded2 = (try h.cache.getOrReload(h.io, cp)).?;
    try testing.expectEqual(persisted_slot, try reloaded2.state.slot());
    try testing.expect(h.cache.cache.get(.{ .root = root, .epoch = cp_epoch }).?.item == .in_memory);

    h.cache.clear();
    try testing.expectEqual(@as(usize, 0), h.cache.size());
}

test "PersistentCheckpointStateCache add/processState/prune free in-memory states exactly once" {
    const seed_alloc = testing.allocator;
    const h = try TestHarness.init(seed_alloc, .{ .max_epochs_in_memory = 2, .max_epochs_on_disk = 4 });
    defer h.deinit();

    var track = DoubleFreeDetectAllocator.init(seed_alloc, std.math.maxInt(usize));
    defer track.deinit();
    const state_alloc = track.allocator();

    const root = makeRoot(0xAB);
    var epoch: Epoch = 1;
    while (epoch <= 10) : (epoch += 1) {
        const s = try h.factory.helper.cached_state.clone(state_alloc, .{});
        try h.cache.add(h.io, .{ .epoch = epoch, .root = root }, s);
        try testing.expect(!track.double_free);
    }

    try h.cache.pruneFinalized(h.io, 9);
    try testing.expect(!track.double_free);
    try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 8 }) == null);

    // Free every remaining `state_alloc`-allocated state WHILE the tracking allocator is still live
    // (the deferred `h.deinit()` would otherwise free them after `track.deinit()`).
    h.cache.clear();
    try testing.expect(!track.double_free);
}

test "PersistentCheckpointStateCache add of the already-resident pointer is idempotent (no double-free)" {
    const seed_alloc = testing.allocator;
    const h = try TestHarness.init(seed_alloc, .{ .max_epochs_in_memory = 2, .max_epochs_on_disk = 4 });
    defer h.deinit();

    var track = DoubleFreeDetectAllocator.init(seed_alloc, std.math.maxInt(usize));
    defer track.deinit();
    const state_alloc = track.allocator();

    const cp = Checkpoint{ .epoch = 1, .root = makeRoot(0xCD) };
    const s = try h.factory.helper.cached_state.clone(state_alloc, .{});
    try h.cache.add(h.io, cp, s);
    // Re-add the SAME resident pointer: insertEntry's same-pointer guard must skip freeing it (still mapped at cp).
    try h.cache.add(h.io, cp, s);
    try testing.expect(!track.double_free);
    try testing.expect(h.cache.get(h.io, cp).? == s);

    // Free `s` WHILE the tracking allocator is still live (the deferred `h.deinit()` would otherwise
    // free it after `track.deinit()`); a guard miss double-frees here too.
    h.cache.clear();
    try testing.expect(!track.double_free);
}

test "PersistentCheckpointStateCache insertEntry overwrite of a different state frees the displaced one exactly once" {
    const seed_alloc = testing.allocator;
    const h = try TestHarness.init(seed_alloc, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    var track = DoubleFreeDetectAllocator.init(seed_alloc, std.math.maxInt(usize));
    defer track.deinit();
    const state_alloc = track.allocator();

    const cp = Checkpoint{ .epoch = 1, .root = makeRoot(0xCE) };

    // Overwrite an in_memory entry with a DIFFERENT state: insertEntry (the sole destroy-on-overwrite
    // owner) frees the displaced state exactly once, with no caller choreography.
    const s1 = try h.factory.helper.cached_state.clone(state_alloc, .{});
    try h.cache.insertEntry(cp, .{ .in_memory = .{ .state = s1, .persisted_key = null } });
    const s2 = try h.factory.helper.cached_state.clone(state_alloc, .{});
    try h.cache.insertEntry(cp, .{ .in_memory = .{ .state = s2, .persisted_key = null } });
    try testing.expect(!track.double_free);
    try testing.expect(h.cache.get(h.io, cp).? == s2);

    // Re-inserting the SAME resident pointer must NOT free it (same-pointer guard); metadata-only.
    try h.cache.insertEntry(cp, .{ .in_memory = .{ .state = s2, .persisted_key = null } });
    try testing.expect(!track.double_free);
    try testing.expect(h.cache.get(h.io, cp).? == s2);

    // Free the surviving resident WHILE the tracking allocator is still live.
    h.cache.clear();
    try testing.expect(!track.double_free);
}

test "PersistentCheckpointStateCache add OOM sweep leaves no garbage entry (dynamic path)" {
    const base_alloc = testing.allocator;

    // Default opts → unbounded disk → single dynamic path, fallible epoch-index track on each fresh epoch.
    const h = try TestHarness.init(base_alloc, .{ .max_epochs_in_memory = 64 });
    defer h.deinit();

    const root = makeRoot(0xE7);

    var epoch: Epoch = 1;
    while (epoch <= 6) : (epoch += 1) {
        var fail_index: usize = 0;
        while (true) : (fail_index += 1) {
            const s = try h.factory.make(@as(u64, epoch) * 100);
            // Model B: `add` takes ownership of `s` only on success. Arm a free via `base_alloc` (the
            // `make` allocator, NOT the swapped failing allocator) so a failing `add` cannot leak `s`;
            // disarm once the cache owns it. This catches BOTH a leak (forgotten free) and a double-free
            // (if `add` wrongly freed `s` AND the test frees) via testing.allocator.
            var s_owned = true;
            errdefer if (s_owned) destroyTestState(base_alloc, s);

            var failing = std.testing.FailingAllocator.init(base_alloc, .{ .fail_index = fail_index });
            // `add` allocates through `cache.allocator`; point it at the failing allocator for this
            // attempt only. Frees route through the same wrapper to `base_alloc`, so the restore before
            // deinit is sound (states are freed via their own captured allocator, not this one).
            h.cache.allocator = failing.allocator();
            const result = h.cache.add(h.io, .{ .epoch = epoch, .root = root }, s);
            h.cache.allocator = base_alloc;

            if (result) |_| {
                s_owned = false;
                break;
            } else |err| {
                try testing.expectEqual(error.OutOfMemory, err);
                // On OOM the index must NOT hold a half-inserted epoch, and `add` left `s` untouched so
                // the test frees it.
                try testing.expect(!h.cache.epoch_index.contains(epoch));
                destroyTestState(base_alloc, s);
                s_owned = false;
            }
        }

        try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = epoch }) != null);
    }

    // Every epoch ended up coherently tracked; full deinit must not OOB or double-free.
    try testing.expectEqual(@as(u64, 6), h.cache.epoch_index.count());

    // A FAILED re-add of an EXISTING (epoch,root) must leave the pre-existing entry intact: the spine
    // put's OOM rollback only undoes the edge it was adding, so it must NOT remove epoch 6's entry
    // here. (A too-broad rollback would make these assertions fail.)
    {
        const s = try h.factory.make(600);
        var s_owned = true;
        errdefer if (s_owned) destroyTestState(base_alloc, s);

        var failing = std.testing.FailingAllocator.init(base_alloc, .{ .fail_index = 0 });
        h.cache.allocator = failing.allocator();
        const result = h.cache.add(h.io, .{ .epoch = 6, .root = root }, s);
        h.cache.allocator = base_alloc;

        try testing.expectError(error.OutOfMemory, result);
        try testing.expect(h.cache.epoch_index.contains(6));
        try testing.expect(h.cache.get(h.io, .{ .root = root, .epoch = 6 }) != null);
        // Model B: the failed re-add left `s` untouched (the pre-existing resident is the one kept), so
        // the test owns and frees `s`.
        destroyTestState(base_alloc, s);
        s_owned = false;
    }
}

test "PersistentCheckpointStateCache getOrReloadLatest propagates a candidate OOM" {
    const base_alloc = testing.allocator;
    const h = try TestHarness.init(base_alloc, .{ .max_epochs_in_memory = 8 });
    defer h.deinit();

    const root = makeRoot(0xD5);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp_epoch = seed_epoch - 2;
    const persisted_slot = computeStartSlotAtEpoch(cp_epoch);

    // Resident same-view seed (views cp.root at the cp slot) so findSeedStateToReload yields a pool.
    const seed = try h.factory.makeWithBlockRoot(seed_slot, persisted_slot, root);
    try h.cache.add(h.io, .{ .epoch = seed_epoch, .root = root }, seed);

    _ = try persistByHand(h, .{ .root = root, .epoch = cp_epoch }, persisted_slot);

    // Force the reload of the only persisted candidate to OOM: the first allocation in getOrReload's
    // datastore read / rebuild fails. getOrReloadLatest surfaces it instead of returning null.
    var failing = std.testing.FailingAllocator.init(base_alloc, .{ .fail_index = 0 });
    h.cache.allocator = failing.allocator();
    const got = h.cache.getOrReloadLatest(h.io, root, cp_epoch);
    h.cache.allocator = base_alloc;
    try testing.expectError(error.OutOfMemory, got);

    // The cache is intact: a normal reload of the same checkpoint now succeeds (the failed pass wrote
    // nothing).
    const ok = try h.cache.getOrReloadLatest(h.io, root, cp_epoch);
    try testing.expect(ok != null);
    try testing.expectEqual(persisted_slot, try ok.?.state.slot());
}

test "PersistentCheckpointStateCache processState propagates OutOfMemory" {
    const base_alloc = testing.allocator;
    const h = try TestHarness.init(base_alloc, .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_a = makeRoot(0xA0);
    const root_b = makeRoot(0xB0);

    try h.cache.add(h.io, .{ .epoch = 1, .root = root_b }, try h.factory.make(100));
    try h.cache.add(h.io, .{ .epoch = 2, .root = root_a }, try h.factory.make(200));
    try h.cache.add(h.io, .{ .epoch = 3, .root = root_a }, try h.factory.make(300));

    const driver = try buildDriver(h, 3 * spe + 1, &.{
        .{ .target_slot = 1 * spe, .root = root_b },
        .{ .target_slot = 2 * spe, .root = root_a },
    });
    defer destroyTestState(base_alloc, driver);

    // Sweep fail indices: each failure must surface as error.OutOfMemory (proving propagation, not a
    // swallowed 0). Stop at the first fully-successful run.
    var saw_oom = false;
    var fail_index: usize = 0;
    while (fail_index < 64) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(base_alloc, .{ .fail_index = fail_index });
        h.cache.allocator = failing.allocator();
        const result = h.cache.processState(h.io, makeRoot(0xFF), driver);
        h.cache.allocator = base_alloc;

        if (result) |_| {
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            saw_oom = true;
        }
    }
    // At least one swept index actually forced (and propagated) an OOM.
    try testing.expect(saw_oom);
}

// A datastore whose `remove` fails on demand, wrapping the in-memory store so write/read/readKeys
// behave normally. Lets the swallow-and-retry path be exercised: pruneFinalized must survive a
// remove failure (return, keep the epoch tracked) rather than loop forever or leak.
const ErroringCPStateDatastore = struct {
    inner: InMemoryCPStateDatastore,
    fail_remove: bool,
    fail_write: bool,

    fn init(alloc: Allocator) ErroringCPStateDatastore {
        return .{ .inner = InMemoryCPStateDatastore.init(alloc), .fail_remove = false, .fail_write = false };
    }

    fn deinit(self: *ErroringCPStateDatastore) void {
        self.inner.deinit();
    }

    fn datastore(self: *ErroringCPStateDatastore) CPStateDatastore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = CPStateDatastore.VTable{
        .write = writeImpl,
        .remove = removeImpl,
        .removeMany = removeManyImpl,
        .read = readImpl,
        .readPrefix = readPrefixImpl,
        .readKeys = readKeysImpl,
        .init = null,
    };

    fn writeImpl(ctx: *anyopaque, io: std.Io, key: Checkpoint, state_bytes: []const u8) anyerror!DatastoreKey {
        const self: *ErroringCPStateDatastore = @ptrCast(@alignCast(ctx));
        if (self.fail_write) return error.DiskWriteFailed;
        return self.inner.datastore().write(io, key, state_bytes);
    }

    fn readPrefixImpl(ctx: *anyopaque, io: std.Io, dk: DatastoreKey, buf: []u8) anyerror!?usize {
        const self: *ErroringCPStateDatastore = @ptrCast(@alignCast(ctx));
        return self.inner.datastore().readPrefix(io, dk, buf);
    }

    fn removeImpl(ctx: *anyopaque, io: std.Io, dk: DatastoreKey) anyerror!void {
        const self: *ErroringCPStateDatastore = @ptrCast(@alignCast(ctx));
        if (self.fail_remove) return error.DiskRemoveFailed;
        return self.inner.datastore().remove(io, dk);
    }

    fn removeManyImpl(ctx: *anyopaque, io: std.Io, alloc: Allocator, keys: []const DatastoreKey) anyerror!void {
        const self: *ErroringCPStateDatastore = @ptrCast(@alignCast(ctx));
        _ = alloc;
        // Sequential, honoring `fail_remove` per key so the swallow-and-retry path is exercised.
        for (keys) |dk| {
            if (self.fail_remove) return error.DiskRemoveFailed;
            try self.inner.datastore().remove(io, dk);
        }
    }

    fn readImpl(ctx: *anyopaque, io: std.Io, alloc: Allocator, dk: DatastoreKey) anyerror!?[]u8 {
        const self: *ErroringCPStateDatastore = @ptrCast(@alignCast(ctx));
        return self.inner.datastore().read(io, alloc, dk);
    }

    fn readKeysImpl(ctx: *anyopaque, io: std.Io, alloc: Allocator) anyerror![]DatastoreKey {
        const self: *ErroringCPStateDatastore = @ptrCast(@alignCast(ctx));
        return self.inner.datastore().readKeys(io, alloc);
    }
};

test "PersistentCheckpointStateCache pruneFinalized survives a remove failure without looping or leaking" {
    const allocator = testing.allocator;

    var store = ErroringCPStateDatastore.init(allocator);
    defer store.deinit();
    const h = try TestHarness.initWithDatastore(allocator, store.datastore(), .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_a = makeRoot(0xA0);
    const root_b = makeRoot(0xB0);

    // Persist the epoch-1 and epoch-2 boundary cps onto disk (≥2 below-finalized epochs).
    try h.cache.add(h.io, .{ .epoch = 1, .root = root_b }, try h.factory.make(100));
    try h.cache.add(h.io, .{ .epoch = 2, .root = root_a }, try h.factory.make(200));
    try h.cache.add(h.io, .{ .epoch = 3, .root = root_a }, try h.factory.make(300));

    const driver = try h.factory.make(3 * spe + 1);
    defer destroyTestState(allocator, driver);
    var driver_roots = try driver.state.blockRoots();
    try driver_roots.setValue((1 * spe) % preset.SLOTS_PER_HISTORICAL_ROOT, &root_b);
    try driver_roots.setValue((2 * spe) % preset.SLOTS_PER_HISTORICAL_ROOT, &root_a);
    try driver.state.commit();
    try testing.expectEqual(@as(usize, 2), try h.cache.processState(h.io, makeRoot(0xFF), driver));

    // Arm the remove failure, then prune below epoch 3. It must return (not hang) despite every
    // persisted remove failing.
    store.fail_remove = true;
    try h.cache.pruneFinalized(h.io, 3);

    // Retain-on-failure: the below-finalized epochs are still tracked and their persisted states are
    // still reloadable (the failed remove left them in place).
    try testing.expect(h.cache.epoch_index.contains(1));
    try testing.expect(h.cache.epoch_index.contains(2));
    {
        const b1 = (try h.cache.getStateOrBytes(h.io, .{ .epoch = 1, .root = root_b })).?;
        try testing.expect(b1 == .bytes);
        allocator.free(b1.bytes);
    }

    // With removes allowed again a retry drains them cleanly (no leak/double-free at deinit).
    store.fail_remove = false;
    try h.cache.pruneFinalized(h.io, 3);
    try testing.expect(!h.cache.epoch_index.contains(1));
    try testing.expect(!h.cache.epoch_index.contains(2));
}

test "PersistentCheckpointStateCache processState swallows a persist write failure and retries next run" {
    const allocator = testing.allocator;

    var store = ErroringCPStateDatastore.init(allocator);
    defer store.deinit();
    const h = try TestHarness.initWithDatastore(allocator, store.datastore(), .{ .max_epochs_in_memory = 1, .max_epochs_on_disk = 8 });
    defer h.deinit();

    const spe = preset.SLOTS_PER_EPOCH;
    const root_a = makeRoot(0xA0);
    const root_b = makeRoot(0xB0);

    try h.cache.add(h.io, .{ .epoch = 1, .root = root_b }, try h.factory.make(100));
    try h.cache.add(h.io, .{ .epoch = 2, .root = root_a }, try h.factory.make(200));
    try h.cache.add(h.io, .{ .epoch = 3, .root = root_a }, try h.factory.make(300));

    const driver = try h.factory.make(3 * spe + 1);
    defer destroyTestState(allocator, driver);
    var driver_roots = try driver.state.blockRoots();
    try driver_roots.setValue((1 * spe) % preset.SLOTS_PER_HISTORICAL_ROOT, &root_b);
    try driver_roots.setValue((2 * spe) % preset.SLOTS_PER_HISTORICAL_ROOT, &root_a);
    try driver.state.commit();

    // Every persist write fails: swallowed, 0 persisted, both epochs stay tracked in memory.
    store.fail_write = true;
    try testing.expectEqual(@as(usize, 0), try h.cache.processState(h.io, makeRoot(0xFF), driver));
    try testing.expect(h.cache.cache.getPtr(.{ .epoch = 1, .root = root_b }).?.item == .in_memory);
    try testing.expect(h.cache.cache.getPtr(.{ .epoch = 2, .root = root_a }).?.item == .in_memory);

    // The next run (writes healthy again) retries and persists both.
    store.fail_write = false;
    try testing.expectEqual(@as(usize, 2), try h.cache.processState(h.io, makeRoot(0xFF), driver));
    try testing.expect(h.cache.cache.getPtr(.{ .epoch = 1, .root = root_b }).?.item == .persisted);
    try testing.expect(h.cache.cache.getPtr(.{ .epoch = 2, .root = root_a }).?.item == .persisted);
}

// Handshake + ordering witness shared by the two zio fibers of an interleave test. `seq` is a
// cooperative logical clock (single executor ⇒ no data race); `stamp` returns and advances it so a
// test can prove fiber B's op landed strictly between fiber A parking and resuming.
const Rendezvous = struct {
    parked: std.Io.Event = .unset,
    gate: std.Io.Event = .unset,
    seq: u32 = 0,
    parked_at: ?u32 = null,
    b_done_at: ?u32 = null,
    resumed_at: ?u32 = null,
    /// The state fiber B added (add-interleave tests); doubles as the fired flag.
    added: ?*CachedBeaconState = null,
    /// Whether the buffer pool was observed busy at fiber B's reload (busy-pool test).
    pool_busy: bool = false,

    fn stamp(self: *Rendezvous) u32 {
        const s = self.seq;
        self.seq += 1;
        return s;
    }
};

// A datastore that parks fiber A in a REAL zio suspension at its `write` OR its `read` (per `gate_on`):
// it runs the inner op, signals `parked`, then WAITS on `gate` (yielding the fiber) before returning.
// A second fiber runs during that gap, so the cache path under test is crossed by genuine cooperative
// concurrency. The inner op completes BEFORE the park, so its durable effect (blob written / bytes
// read) is already in place when the second fiber runs. Non-gated ops delegate straight through.
const GatedCPStateDatastore = struct {
    inner: InMemoryCPStateDatastore,
    rv: *Rendezvous,
    gate_on: GateOn = .write,

    const GateOn = enum { write, read };

    fn init(alloc: Allocator, rv: *Rendezvous) GatedCPStateDatastore {
        return .{ .inner = InMemoryCPStateDatastore.init(alloc), .rv = rv };
    }

    fn deinit(self: *GatedCPStateDatastore) void {
        self.inner.deinit();
    }

    fn datastore(self: *GatedCPStateDatastore) CPStateDatastore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn park(self: *GatedCPStateDatastore, io: std.Io) void {
        self.rv.parked_at = self.rv.stamp();
        self.rv.parked.set(io);
        self.rv.gate.wait(io) catch {};
        self.rv.resumed_at = self.rv.stamp();
    }

    const vtable = CPStateDatastore.VTable{
        .write = writeImpl,
        .remove = removeImpl,
        .removeMany = removeManyImpl,
        .read = readImpl,
        .readPrefix = readPrefixImpl,
        .readKeys = readKeysImpl,
        .init = null,
    };

    fn writeImpl(ctx: *anyopaque, io: std.Io, key: Checkpoint, state_bytes: []const u8) anyerror!DatastoreKey {
        const self: *GatedCPStateDatastore = @ptrCast(@alignCast(ctx));
        const dk = try self.inner.datastore().write(io, key, state_bytes);
        if (self.gate_on == .write) self.park(io);
        return dk;
    }

    fn readImpl(ctx: *anyopaque, io: std.Io, alloc: Allocator, dk: DatastoreKey) anyerror!?[]u8 {
        const self: *GatedCPStateDatastore = @ptrCast(@alignCast(ctx));
        const bytes = try self.inner.datastore().read(io, alloc, dk);
        if (self.gate_on == .read) self.park(io);
        return bytes;
    }

    fn readPrefixImpl(ctx: *anyopaque, io: std.Io, dk: DatastoreKey, buf: []u8) anyerror!?usize {
        const self: *GatedCPStateDatastore = @ptrCast(@alignCast(ctx));
        return self.inner.datastore().readPrefix(io, dk, buf);
    }

    fn removeImpl(ctx: *anyopaque, io: std.Io, dk: DatastoreKey) anyerror!void {
        const self: *GatedCPStateDatastore = @ptrCast(@alignCast(ctx));
        return self.inner.datastore().remove(io, dk);
    }

    fn removeManyImpl(ctx: *anyopaque, io: std.Io, alloc: Allocator, keys: []const DatastoreKey) anyerror!void {
        const self: *GatedCPStateDatastore = @ptrCast(@alignCast(ctx));
        return self.inner.datastore().removeMany(io, alloc, keys);
    }

    fn readKeysImpl(ctx: *anyopaque, io: std.Io, alloc: Allocator) anyerror![]DatastoreKey {
        const self: *GatedCPStateDatastore = @ptrCast(@alignCast(ctx));
        return self.inner.datastore().readKeys(io, alloc);
    }
};

// Fiber A: the seed → driver → processState sequence, entirely on the zio io. It suspends inside the
// gated write; the driver is freed once processState returns.
fn gatedProcessStateTask(h: *TestHarness, io: std.Io, cp: Checkpoint, root_a: Root) anyerror!usize {
    const spe = preset.SLOTS_PER_EPOCH;
    try h.cache.add(io, cp, try h.factory.make(100));
    try h.cache.add(io, .{ .epoch = 2, .root = root_a }, try h.factory.make(200));

    const driver = try h.factory.makeWithBlockRoot(2 * spe + 1, 1 * spe, root_a);
    defer destroyTestState(h.allocator, driver);
    return h.cache.processState(io, makeRoot(0xFF), driver);
}

// Fiber B: wait until A has parked, add a fresh state at `slot` for `cp`, then release the gate.
// Records the fresh state as `rv.added` (fired flag) and stamps the interleave witness.
fn gatedAddTask(rv: *Rendezvous, h: *TestHarness, io: std.Io, cp: Checkpoint, slot: u64) anyerror!void {
    rv.parked.wait(io) catch {};
    const state = try h.factory.make(slot);
    rv.added = state;
    h.cache.add(io, cp, state) catch |err| {
        rv.added = null;
        destroyTestState(h.allocator, state);
        return err;
    };
    rv.b_done_at = rv.stamp();
    rv.gate.set(io);
}

// Fiber A (read-gated): seed the band + persist `cp` by hand (straight to the inner store, bypassing the
// gate), then getOrReload it. It parks inside the gated read; a resident added during the park is
// displaced by the reload's insertEntry.
fn gatedReloadTask(h: *TestHarness, io: std.Io, store: *GatedCPStateDatastore, cp: Checkpoint, seed_cp: Checkpoint, seed_slot: u64, persisted_slot: u64) anyerror!?*CachedBeaconState {
    try h.cache.add(io, seed_cp, try h.factory.make(seed_slot));
    {
        const s = try h.factory.make(persisted_slot);
        const bytes = try s.state.serialize(h.allocator);
        defer h.allocator.free(bytes);
        const dk = try store.inner.datastore().write(io, cp, bytes);
        destroyTestState(h.allocator, s);
        try h.cache.insertEntry(cp, .{ .persisted = dk });
    }
    return h.cache.getOrReload(io, cp);
}

// Fiber B: wait until A parks, then pruneFinalized removes A's in-flight entry (and frees its state), so
// A's post-write re-resolve hits the vanished-entry arm and removes the now-orphan blob.
fn gatedPruneTask(rv: *Rendezvous, h: *TestHarness, io: std.Io, finalized_epoch: Epoch) anyerror!void {
    rv.parked.wait(io) catch {};
    try h.cache.pruneFinalized(io, finalized_epoch);
    rv.b_done_at = rv.stamp();
    rv.gate.set(io);
}

// Fiber A (write-gated, buffer pool): add + persist `rcp` by hand + a block-cache seed, then
// processState persists `cp` — holding the pool lease across the parked write.
fn gatedBusyPoolProcessTask(h: *TestHarness, io: std.Io, store: *GatedCPStateDatastore, cp: Checkpoint, rcp: Checkpoint, root_a: Root, seed_slot: u64) anyerror!usize {
    const spe = preset.SLOTS_PER_EPOCH;
    try h.cache.add(io, cp, try h.factory.make(100));
    try h.cache.add(io, .{ .epoch = 2, .root = root_a }, try h.factory.make(200));
    {
        const s = try h.factory.make(seed_slot);
        const bytes = try s.state.serialize(h.allocator);
        defer h.allocator.free(bytes);
        const dk = try store.inner.datastore().write(io, rcp, bytes);
        destroyTestState(h.allocator, s);
        try h.cache.insertEntry(rcp, .{ .persisted = dk });
    }
    _ = try h.block_cache.add(io, try h.factory.make(seed_slot), true);

    const driver = try h.factory.makeWithBlockRoot(2 * spe + 1, 1 * spe, root_a);
    defer destroyTestState(h.allocator, driver);
    return h.cache.processState(io, makeRoot(0xFF), driver);
}

// Fiber B: wait until A parks (holding the pool lease), record that the pool is busy, then getOrReload
// `rcp` — forcing the fresh-alloc fallback — before releasing the gate.
fn gatedBusyPoolReloadTask(rv: *Rendezvous, h: *TestHarness, io: std.Io, pool: *BufferPool, rcp: Checkpoint) anyerror!?*CachedBeaconState {
    rv.parked.wait(io) catch {};
    rv.pool_busy = pool.busy();
    const reloaded = try h.cache.getOrReload(io, rcp);
    rv.b_done_at = rv.stamp();
    rv.gate.set(io);
    return reloaded;
}

test "PersistentCheckpointStateCache processState survives an add during the persist write" {
    const allocator = testing.allocator;

    // Single executor = the calling thread, zero worker threads: cooperative, deterministic interleave
    // (the cache is not thread-safe). `rt.io()` is the same std.Io adapter the clock module drives.
    const rt = try zio.Runtime.init(allocator, .{ .executors = .exact(1) });
    defer rt.deinit();
    const io = rt.io();

    var rv: Rendezvous = .{};

    var store = GatedCPStateDatastore.init(allocator, &rv);
    defer store.deinit();

    const h = try TestHarness.initWithDatastore(allocator, store.datastore(), .{ .max_epochs_in_memory = 1 });
    defer h.deinit();
    h.io = io;

    const root_a = makeRoot(0xA7);
    const cp = Checkpoint{ .epoch = 1, .root = root_a };

    // Fiber A persists cp epoch 1; it parks mid-write. Fiber B adds a fresh S1 for cp during that park,
    // then releases A. Await both before asserting so neither coroutine is leaked on a failure.
    var fut_a = try std.Io.concurrent(io, gatedProcessStateTask, .{ h, io, cp, root_a });
    var fut_b = try std.Io.concurrent(io, gatedAddTask, .{ &rv, h, io, cp, @as(u64, 101) });
    const res_a = fut_a.await(io);
    const res_b = fut_b.await(io);
    try res_b;
    try testing.expectEqual(@as(usize, 1), try res_a);

    // Proof the interleave was real: B's add completed strictly between A parking and A resuming.
    try testing.expect(rv.parked_at.? < rv.b_done_at.?);
    try testing.expect(rv.b_done_at.? < rv.resumed_at.?);

    // Last writer wins: fiber B's add resident was downgraded to persisted here and freed; the fresh
    // blob is on disk. `rv.added` (the ordering witness) is now freed — do not dereference it.
    try testing.expect(rv.added != null);
    const item = h.cache.cache.get(cp).?.item;
    try testing.expect(item == .persisted);
    const bytes = (try store.inner.datastore().read(io, allocator, item.persisted)).?;
    allocator.free(bytes);

    const item2 = h.cache.cache.get(.{ .epoch = 2, .root = root_a }).?.item;
    try testing.expect(item2 == .in_memory);
}

test "PersistentCheckpointStateCache getOrReload frees a resident added during the datastore read" {
    const allocator = testing.allocator;

    const rt = try zio.Runtime.init(allocator, .{ .executors = .exact(1) });
    defer rt.deinit();
    const io = rt.io();

    var rv: Rendezvous = .{};
    var store = GatedCPStateDatastore.init(allocator, &rv);
    store.gate_on = .read;
    defer store.deinit();

    const h = try TestHarness.initWithDatastore(allocator, store.datastore(), .{ .max_epochs_in_memory = 8 });
    defer h.deinit();
    h.io = io;

    const root = makeRoot(0xC7);
    const seed_epoch: Epoch = 22;
    const seed_slot = computeStartSlotAtEpoch(seed_epoch);
    const cp_epoch = seed_epoch - 2;
    const cp = Checkpoint{ .epoch = cp_epoch, .root = root };
    const seed_cp = Checkpoint{ .epoch = seed_epoch, .root = root };
    const persisted_slot = computeStartSlotAtEpoch(cp_epoch);

    // Fiber A seeds the band + persists cp, then getOrReload parks in the gated read. Fiber B adds a
    // fresh S1 for the same cp during that park, then releases A.
    var fut_a = try std.Io.concurrent(io, gatedReloadTask, .{ h, io, &store, cp, seed_cp, seed_slot, persisted_slot });
    var fut_b = try std.Io.concurrent(io, gatedAddTask, .{ &rv, h, io, cp, seed_slot });
    const res_a = fut_a.await(io);
    const res_b = fut_b.await(io);
    try res_b;
    const reloaded = (try res_a).?;

    // Proof the interleave was real: B's add completed strictly between A parking and A resuming.
    try testing.expect(rv.parked_at.? < rv.b_done_at.?);
    try testing.expect(rv.b_done_at.? < rv.resumed_at.?);

    // Last writer wins: A's reload insertEntry landed AFTER B's add → the reloaded state wins and the
    // interleaved S1 was destroyed by the overwrite (leak-checked). `rv.added` is now freed — not deref'd.
    try testing.expectEqual(persisted_slot, try reloaded.state.slot());
    try testing.expect(rv.added != null);
    const item = h.cache.cache.get(cp).?.item;
    try testing.expect(item == .in_memory);
    try testing.expect(item.in_memory.state == reloaded);
    try testing.expect(item.in_memory.persisted_key != null);
}

test "PersistentCheckpointStateCache processState removes the orphan blob when the entry vanishes mid-write" {
    const allocator = testing.allocator;

    const rt = try zio.Runtime.init(allocator, .{ .executors = .exact(1) });
    defer rt.deinit();
    const io = rt.io();

    var rv: Rendezvous = .{};
    var store = GatedCPStateDatastore.init(allocator, &rv); // gate_on = .write
    defer store.deinit();

    const h = try TestHarness.initWithDatastore(allocator, store.datastore(), .{ .max_epochs_in_memory = 1 });
    defer h.deinit();
    h.io = io;

    const root_a = makeRoot(0xA7);
    const cp = Checkpoint{ .epoch = 1, .root = root_a };

    // Fiber A persists cp epoch 1; the write parks with the blob already on disk. Fiber B finalizes above
    // epoch 1, whose pruneFinalized removes cp's entry (freeing its state) during the park. A resumes to a
    // vanished entry and must remove the now-orphan blob.
    var fut_a = try std.Io.concurrent(io, gatedProcessStateTask, .{ h, io, cp, root_a });
    var fut_b = try std.Io.concurrent(io, gatedPruneTask, .{ &rv, h, io, @as(Epoch, 2) });
    const res_a = fut_a.await(io);
    try fut_b.await(io);
    // persist_count is bumped before the vanish re-resolve, so its value is not load-bearing here.
    _ = try res_a;

    // Proof the interleave was real: B's prune completed strictly between A parking and A resuming.
    try testing.expect(rv.parked_at.? < rv.b_done_at.?);
    try testing.expect(rv.b_done_at.? < rv.resumed_at.?);

    // The entry vanished mid-write; on resume the getPtr-orelse arm removed the orphan blob. Both the
    // entry AND the blob must be gone (the removal actually ran — read returns null).
    try testing.expect(h.cache.cache.get(cp) == null);
    try testing.expect((try store.inner.datastore().read(io, allocator, datastoreKey(cp))) == null);

    try testing.expect(h.cache.cache.get(.{ .epoch = 2, .root = root_a }).?.item == .in_memory);
}

test "PersistentCheckpointStateCache busy pool falls back to fresh alloc during an interleaved reload" {
    const allocator = testing.allocator;

    const rt = try zio.Runtime.init(allocator, .{ .executors = .exact(1) });
    defer rt.deinit();
    const io = rt.io();

    var pool = try BufferPool.init(allocator, 1);
    defer pool.deinit();

    var rv: Rendezvous = .{};
    var store = GatedCPStateDatastore.init(allocator, &rv); // gate_on = .write
    defer store.deinit();

    const h = try TestHarness.initWithDatastore(allocator, store.datastore(), .{ .max_epochs_in_memory = 1, .buffer_pool = &pool });
    defer h.deinit();
    h.io = io;

    const root_a = makeRoot(0xA7);
    const root_b = makeRoot(0xB7);
    const cp = Checkpoint{ .epoch = 1, .root = root_a };
    const reload_slot = computeStartSlotAtEpoch(22);
    // rcp shares the band (max) epoch, so processState never persists it — it stays a pure reload
    // target — while epoch 1 is the single excess epoch the persist writes.
    const rcp = Checkpoint{ .epoch = 2, .root = root_b };

    // Fiber A persists cp — holding the pool lease across the parked write. Fiber B, during that park,
    // records that the pool is busy and reloads the (different) rcp, forcing the fresh-alloc fallback.
    var fut_a = try std.Io.concurrent(io, gatedBusyPoolProcessTask, .{ h, io, &store, cp, rcp, root_a, reload_slot });
    var fut_b = try std.Io.concurrent(io, gatedBusyPoolReloadTask, .{ &rv, h, io, &pool, rcp });
    const res_a = fut_a.await(io);
    const reloaded = (try fut_b.await(io)).?;
    try testing.expectEqual(@as(usize, 1), try res_a);

    // Proof the interleave was real: B's reload completed strictly between A parking and A resuming.
    try testing.expect(rv.parked_at.? < rv.b_done_at.?);
    try testing.expect(rv.b_done_at.? < rv.resumed_at.?);

    // Non-vacuous guard: the pool WAS busy (A held its lease across the parked write) when B reloaded,
    // forcing the fresh-alloc fallback.
    try testing.expect(rv.pool_busy);

    try testing.expect(h.cache.cache.get(cp).?.item == .persisted);
    try testing.expectEqual(reload_slot, try reloaded.state.slot());
    try testing.expect(h.cache.cache.get(rcp).?.item == .in_memory);
    try testing.expect(!pool.busy());
}
