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
    allocator: Allocator,
    api: *BeaconApiClient,

    /// Current head info (protected by mutex for concurrent access).
    mu: std.Thread.Mutex,
    head: HeadInfo,

    /// Registered head callbacks.
    head_callbacks: [MAX_HEAD_CALLBACKS]HeadCallback,
    head_callback_count: usize,

    pub fn init(allocator: Allocator, api: *BeaconApiClient) ChainHeaderTracker {
        return .{
            .allocator = allocator,
            .api = api,
            .mu = .{},
            .head = .{
                .slot = 0,
                .block_root = [_]u8{0} ** 32,
                .finalized_epoch = 0,
            },
            .head_callbacks = undefined,
            .head_callback_count = 0,
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

    /// Start subscribing to BN SSE events.
    ///
    /// Blocks until the SSE stream ends or an error occurs.
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

        try self.api.subscribeToEvents(io, topics, cb);
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

        const info = HeadInfo{
            .slot = slot,
            .block_root = block_root,
            .finalized_epoch = self.head.finalized_epoch, // preserve existing
        };

        // Update under lock.
        self.mu.lock();
        self.head = info;
        self.mu.unlock();

        log.debug("new head slot={d} root={}", .{ slot, std.fmt.fmtSliceHexLower(&block_root) });

        // Fire callbacks (without holding lock).
        for (self.head_callbacks[0..self.head_callback_count]) |cb| {
            cb.call(info);
        }
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
        self.mu.unlock();

        log.debug("finalized checkpoint epoch={d}", .{epoch});
    }
};

// ---------------------------------------------------------------------------
// JSON event shapes (minimal fields we care about)
// ---------------------------------------------------------------------------

const HeadEventJson = struct {
    slot: []const u8,
    block: []const u8,
    // state, epoch_transition, previous_duty_dependent_root, etc. — ignored
};

const FinalizedEventJson = struct {
    block: []const u8,
    state: []const u8,
    epoch: []const u8,
};
