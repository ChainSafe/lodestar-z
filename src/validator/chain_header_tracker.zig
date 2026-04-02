//! Chain head tracker for the Validator Client.
//!
//! Subscribes to the Beacon Node's SSE event stream and maintains the
//! current head slot, head root, and finalized epoch. Services (attestation,
//! sync committee, block) query this for the current head root without
//! making their own API calls.
//!
//! TS equivalent: packages/validator/src/services/chainHeaderTracker.ts
//!
//! Design:
//!   - Parses "head" and "finalized_checkpoint" SSE events from the BN.
//!   - Stores head info in a simple struct guarded by a Mutex.
//!   - Callbacks are fired synchronously when a new head arrives.
//!   - SSE subscription runs on a background fiber (caller responsibility).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const api_client = @import("api_client.zig");
const BeaconApiClient = api_client.BeaconApiClient;
const SseEvent = api_client.SseEvent;
const SseCallback = api_client.SseCallback;
const mutex_mod = @import("mutex.zig");
const time = @import("time.zig");

const log = std.log.scoped(.chain_header_tracker);

// ---------------------------------------------------------------------------
// HeadInfo
// ---------------------------------------------------------------------------

/// Current head state as known by the chain header tracker.
pub const HeadInfo = struct {
    /// Slot of the current canonical head.
    slot: u64,
    /// Block root of the current head.
    block_root: [32]u8,
    /// Latest known finalized epoch.
    finalized_epoch: u64,
    /// Dependent root for attester duty lookups (previous epoch).
    /// Changes when a reorg affects attester duty assignments.
    previous_duty_dependent_root: [32]u8,
    /// Dependent root for current epoch attester duties.
    current_duty_dependent_root: [32]u8,
};

// ---------------------------------------------------------------------------
// Head callback
// ---------------------------------------------------------------------------

/// Callback called when a new head event is received.
pub const HeadCallback = struct {
    ctx: *anyopaque,
    fn_ptr: *const fn (ctx: *anyopaque, info: HeadInfo) void,

    pub fn call(self: HeadCallback, info: HeadInfo) void {
        self.fn_ptr(self.ctx, info);
    }
};

/// Maximum number of head callbacks supported.
const MAX_HEAD_CALLBACKS: usize = 8;

// ---------------------------------------------------------------------------
// ChainHeaderTracker
// ---------------------------------------------------------------------------

pub const ChainHeaderTracker = struct {
    const reconnect_backoff_initial_ns = std.time.ns_per_s;
    const reconnect_backoff_max_ns = 30 * std.time.ns_per_s;
    const MAX_HEAD_WAITERS: usize = 8;

    const HeadWaiter = struct {
        slot: u64,
        ready: *Io.Event,
    };

    allocator: Allocator,
    io: Io,
    api: *BeaconApiClient,
    shutdown_requested: std.atomic.Value(bool),

    /// Current head info (protected by mutex for concurrent access).
    mu: mutex_mod.Mutex,
    head: HeadInfo,

    /// Registered head callbacks.
    head_callbacks: [MAX_HEAD_CALLBACKS]HeadCallback,
    head_callback_count: usize,
    head_waiters: [MAX_HEAD_WAITERS]HeadWaiter,
    head_waiter_count: usize,

    pub fn init(allocator: Allocator, io: Io, api: *BeaconApiClient) ChainHeaderTracker {
        return .{
            .allocator = allocator,
            .io = io,
            .api = api,
            .shutdown_requested = std.atomic.Value(bool).init(false),
            .mu = .{},
            .head = .{
                .slot = 0,
                .block_root = [_]u8{0} ** 32,
                .finalized_epoch = 0,
                .previous_duty_dependent_root = [_]u8{0} ** 32,
                .current_duty_dependent_root = [_]u8{0} ** 32,
            },
            .head_callbacks = undefined,
            .head_callback_count = 0,
            .head_waiters = undefined,
            .head_waiter_count = 0,
        };
    }

    /// Register a callback to be called on each new head event.
    pub fn onHead(self: *ChainHeaderTracker, cb: HeadCallback) void {
        std.debug.assert(self.head_callback_count < MAX_HEAD_CALLBACKS);
        self.head_callbacks[self.head_callback_count] = cb;
        self.head_callback_count += 1;
    }

    /// Return the current head info (thread-safe snapshot).
    pub fn getHeadInfo(self: *ChainHeaderTracker) HeadInfo {
        self.mu.lock();
        defer self.mu.unlock();
        return self.head;
    }

    pub fn hasHeadForSlot(self: *ChainHeaderTracker, slot: u64) bool {
        return self.getHeadInfo().slot >= slot;
    }

    pub fn waitForHeadSlotOrDeadline(self: *ChainHeaderTracker, slot: u64, deadline_real_ns: u64) void {
        if (self.shutdown_requested.load(.acquire)) return;
        if (time.realNanoseconds(self.io) >= deadline_real_ns) return;

        var ready: Io.Event = .unset;
        if (self.registerHeadWaiter(slot, &ready)) return;
        defer self.unregisterHeadWaiter(&ready);

        var events_buf: [2]HeadWaitEvent = undefined;
        var select = Io.Select(HeadWaitEvent).init(self.io, &events_buf);
        errdefer while (select.cancel()) |_| {};

        select.async(.head, waitHeadEvent, .{ self.io, &ready });
        select.async(.deadline, waitHeadDeadline, .{ self.io, deadline_real_ns });

        _ = select.await() catch return;
        while (select.cancel()) |_| {}
    }

    pub fn requestShutdown(self: *ChainHeaderTracker) void {
        self.shutdown_requested.store(true, .release);

        self.mu.lock();
        defer self.mu.unlock();

        for (self.head_waiters[0..self.head_waiter_count]) |waiter| {
            waiter.ready.set(self.io);
        }
        self.head_waiter_count = 0;
    }

    /// Start subscribing to BN SSE events.
    ///
    /// Blocks until shutdown is requested.
    /// Designed to be run on a background fiber.
    ///
    /// TS: ChainHeaderTracker.start(signal)
    pub fn start(self: *ChainHeaderTracker, io: Io) !void {
        log.info("starting chain header tracker", .{});

        const topics = &[_][]const u8{ "head", "finalized_checkpoint" };
        const cb = SseCallback{
            .ctx = self,
            .fn_ptr = sseEventHandler,
        };

        self.refreshSnapshot(io) catch |err| {
            log.warn("failed to seed chain head snapshot before SSE subscribe: {s}", .{@errorName(err)});
        };

        var reconnect_backoff_ns: u64 = reconnect_backoff_initial_ns;
        while (!self.shutdown_requested.load(.acquire)) {
            const subscribe_result = self.api.subscribeToEvents(io, topics, cb);
            if (self.shutdown_requested.load(.acquire)) break;

            if (subscribe_result) |_| unreachable else |err| {
                switch (err) {
                    error.StreamEnded => {
                        log.warn("chain head SSE stream ended across configured beacon nodes; refreshing snapshot and reconnecting", .{});
                    },
                    error.Canceled => break,
                    else => {
                        log.warn("chain head SSE stream failed across configured beacon nodes: {s}", .{@errorName(err)});
                    },
                }
            }

            self.refreshSnapshot(io) catch |err| {
                log.warn("failed to refresh chain head snapshot after SSE interruption: {s}", .{@errorName(err)});
            };

            const sleep_ns = reconnect_backoff_ns;
            log.info("reconnecting chain head SSE stream in {d}s", .{sleep_ns / std.time.ns_per_s});
            io.sleep(.{ .nanoseconds = sleep_ns }, .real) catch return;
            reconnect_backoff_ns = @min(reconnect_backoff_ns * 2, reconnect_backoff_max_ns);
        }
    }

    // -----------------------------------------------------------------------
    // SSE event processing
    // -----------------------------------------------------------------------

    /// SSE event handler — called for each raw event from the stream.
    fn sseEventHandler(ctx: *anyopaque, event: SseEvent) void {
        const self: *ChainHeaderTracker = @ptrCast(@alignCast(ctx));
        self.processEvent(event) catch |err| {
            log.err("processEvent type={s} error={s}", .{ event.event_type, @errorName(err) });
        };
    }

    fn processEvent(self: *ChainHeaderTracker, event: SseEvent) !void {
        if (std.mem.eql(u8, event.event_type, "head")) {
            try self.processHeadEvent(event.data);
        } else if (std.mem.eql(u8, event.event_type, "finalized_checkpoint")) {
            try self.processFinalizedEvent(event.data);
        }
        // Ignore unknown event types.
    }

    /// Parse and apply a "head" SSE event.
    ///
    /// Expected JSON: {"slot":"123","block":"0x...","state":"0x...","epoch_transition":false,...}
    fn processHeadEvent(self: *ChainHeaderTracker, json_data: []const u8) !void {
        var parsed = std.json.parseFromSlice(HeadEventJson, self.allocator, json_data, .{
            .ignore_unknown_fields = true,
        }) catch |err| {
            log.warn("failed to parse head event: {s}", .{@errorName(err)});
            return;
        };
        defer parsed.deinit();

        const ev = parsed.value;

        // Parse the slot number (string in the JSON).
        const slot = std.fmt.parseInt(u64, ev.slot, 10) catch {
            log.warn("invalid slot in head event: {s}", .{ev.slot});
            return;
        };

        // Parse the block root hex (strip 0x prefix).
        var block_root: [32]u8 = [_]u8{0} ** 32;
        const block_hex = if (std.mem.startsWith(u8, ev.block, "0x")) ev.block[2..] else ev.block;
        if (block_hex.len == 64) {
            _ = std.fmt.hexToBytes(&block_root, block_hex) catch {};
        }

        // Parse dependent roots for reorg detection.
        const current_head = self.getHeadInfo();
        var previous_duty_dependent_root: [32]u8 = current_head.previous_duty_dependent_root;
        var current_duty_dependent_root: [32]u8 = current_head.current_duty_dependent_root;

        if (ev.previous_duty_dependent_root) |pdr| {
            const pdr_hex = if (std.mem.startsWith(u8, pdr, "0x")) pdr[2..] else pdr;
            if (pdr_hex.len == 64) _ = std.fmt.hexToBytes(&previous_duty_dependent_root, pdr_hex) catch {};
        }
        if (ev.current_duty_dependent_root) |cdr| {
            const cdr_hex = if (std.mem.startsWith(u8, cdr, "0x")) cdr[2..] else cdr;
            if (cdr_hex.len == 64) _ = std.fmt.hexToBytes(&current_duty_dependent_root, cdr_hex) catch {};
        }

        const info = HeadInfo{
            .slot = slot,
            .block_root = block_root,
            .finalized_epoch = current_head.finalized_epoch,
            .previous_duty_dependent_root = previous_duty_dependent_root,
            .current_duty_dependent_root = current_duty_dependent_root,
        };

        self.applyHeadInfo(info);
        log.debug("new head slot={d} root={x}", .{ slot, block_root });
    }

    /// Parse and apply a "finalized_checkpoint" SSE event.
    ///
    /// Expected JSON: {"block":"0x...","state":"0x...","epoch":"5","execution_optimistic":false}
    fn processFinalizedEvent(self: *ChainHeaderTracker, json_data: []const u8) !void {
        var parsed = std.json.parseFromSlice(FinalizedEventJson, self.allocator, json_data, .{
            .ignore_unknown_fields = true,
        }) catch |err| {
            log.warn("failed to parse finalized_checkpoint event: {s}", .{@errorName(err)});
            return;
        };
        defer parsed.deinit();

        const ev = parsed.value;
        const epoch = std.fmt.parseInt(u64, ev.epoch, 10) catch {
            log.warn("invalid epoch in finalized_checkpoint event: {s}", .{ev.epoch});
            return;
        };

        self.mu.lock();
        self.head.finalized_epoch = epoch;
        const snapshot = self.head;
        self.mu.unlock();

        self.notifyHeadCallbacks(snapshot);

        log.debug("finalized checkpoint epoch={d}", .{epoch});
    }

    fn refreshSnapshot(self: *ChainHeaderTracker, io: Io) !void {
        const head = try self.api.getHeadHeaderSummary(io);
        const current = self.getHeadInfo();
        const finalized_epoch = self.api.getFinalizedCheckpointEpoch(io) catch current.finalized_epoch;

        self.applyHeadInfo(.{
            .slot = head.slot,
            .block_root = head.block_root,
            .finalized_epoch = finalized_epoch,
            .previous_duty_dependent_root = current.previous_duty_dependent_root,
            .current_duty_dependent_root = current.current_duty_dependent_root,
        });
    }

    fn applyHeadInfo(self: *ChainHeaderTracker, info: HeadInfo) void {
        self.mu.lock();
        self.head = info;
        self.signalSatisfiedWaitersLocked();
        self.mu.unlock();

        self.notifyHeadCallbacks(info);
    }

    fn registerHeadWaiter(self: *ChainHeaderTracker, slot: u64, ready: *Io.Event) bool {
        self.mu.lock();
        defer self.mu.unlock();

        if (self.shutdown_requested.load(.acquire) or self.head.slot >= slot) {
            return true;
        }

        std.debug.assert(self.head_waiter_count < MAX_HEAD_WAITERS);
        self.head_waiters[self.head_waiter_count] = .{
            .slot = slot,
            .ready = ready,
        };
        self.head_waiter_count += 1;
        return false;
    }

    fn unregisterHeadWaiter(self: *ChainHeaderTracker, ready: *Io.Event) void {
        self.mu.lock();
        defer self.mu.unlock();

        var i: usize = 0;
        while (i < self.head_waiter_count) : (i += 1) {
            if (self.head_waiters[i].ready == ready) {
                self.head_waiter_count -= 1;
                self.head_waiters[i] = self.head_waiters[self.head_waiter_count];
                return;
            }
        }
    }

    fn signalSatisfiedWaitersLocked(self: *ChainHeaderTracker) void {
        var i: usize = 0;
        while (i < self.head_waiter_count) {
            const waiter = self.head_waiters[i];
            if (self.head.slot < waiter.slot) {
                i += 1;
                continue;
            }

            waiter.ready.set(self.io);
            self.head_waiter_count -= 1;
            self.head_waiters[i] = self.head_waiters[self.head_waiter_count];
        }
    }

    fn notifyHeadCallbacks(self: *ChainHeaderTracker, info: HeadInfo) void {
        for (self.head_callbacks[0..self.head_callback_count]) |cb| {
            cb.call(info);
        }
    }
};

const HeadWaitEvent = union(enum) {
    head: void,
    deadline: void,
};

fn waitHeadEvent(io: Io, ready: *Io.Event) void {
    ready.wait(io) catch {};
}

fn waitHeadDeadline(io: Io, deadline_real_ns: u64) void {
    const now_ns = time.realNanoseconds(io);
    if (now_ns >= deadline_real_ns) return;
    io.sleep(.{ .nanoseconds = @intCast(deadline_real_ns - now_ns) }, .real) catch {};
}

// ---------------------------------------------------------------------------
// JSON event shapes (minimal fields we care about)
// ---------------------------------------------------------------------------

const HeadEventJson = struct {
    slot: []const u8,
    block: []const u8,
    /// Dependent roots for attester duty reorg detection.
    /// Present in head SSE events per the Beacon API spec.
    previous_duty_dependent_root: ?[]const u8 = null,
    current_duty_dependent_root: ?[]const u8 = null,
    // state, epoch_transition, etc. — ignored
};

const FinalizedEventJson = struct {
    block: []const u8,
    state: []const u8,
    epoch: []const u8,
};
