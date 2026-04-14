//! Node-owned execution runtime.
//!
//! Owns execution-layer and builder clients plus the local payload-build cache.
//! Chain-facing execution semantics stay on the chain port; this runtime owns
//! the mutable transport state that used to live directly on BeaconNode.

const std = @import("std");
const scoped_log = std.log.scoped(.execution_runtime);

const chain_mod = @import("chain");
const execution_mod = @import("execution");

const NodeOptions = @import("options.zig").NodeOptions;

const EngineApi = execution_mod.EngineApi;
const MockEngine = execution_mod.mock_engine.MockEngine;
const HttpEngine = execution_mod.HttpEngine;
const HttpBuilder = execution_mod.HttpBuilder;
const IoHttpTransport = execution_mod.IoHttpTransport;
const BuilderApi = execution_mod.BuilderApi;
const GetPayloadResponse = execution_mod.GetPayloadResponse;
const ForkchoiceUpdatedResponse = execution_mod.ForkchoiceUpdatedResponse;
const ExecutionPayloadStatus = execution_mod.ExecutionPayloadStatus;
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;
const Withdrawal = execution_mod.engine_api_types.Withdrawal;

const ExecutionForkchoiceUpdate = chain_mod.ExecutionForkchoiceUpdate;
const ExecutionPort = chain_mod.ExecutionPort;
const NewPayloadRequest = chain_mod.NewPayloadRequest;
const NewPayloadResult = chain_mod.NewPayloadResult;

pub const DEFAULT_MAX_PENDING_PAYLOAD_VERIFICATIONS: usize = 1;

const PendingPayloadVerification = struct {
    ticket: u64,
    request: NewPayloadRequest,
};

const FailedPayloadPreparation = struct {
    ticket: u64,
    status: enum {
        unavailable,
        failed,
    },
};

const OwnedPayloadAttributes = struct {
    timestamp: u64,
    prev_randao: [32]u8,
    suggested_fee_recipient: [20]u8,
    withdrawals: []Withdrawal,
    parent_beacon_block_root: [32]u8,

    fn init(
        allocator: std.mem.Allocator,
        attrs: PayloadAttributesV3,
    ) !OwnedPayloadAttributes {
        const withdrawals = try allocator.dupe(Withdrawal, attrs.withdrawals);
        errdefer if (withdrawals.len > 0) allocator.free(withdrawals);

        return .{
            .timestamp = attrs.timestamp,
            .prev_randao = attrs.prev_randao,
            .suggested_fee_recipient = attrs.suggested_fee_recipient,
            .withdrawals = withdrawals,
            .parent_beacon_block_root = attrs.parent_beacon_block_root,
        };
    }

    fn deinit(self: *OwnedPayloadAttributes, allocator: std.mem.Allocator) void {
        if (self.withdrawals.len > 0) allocator.free(self.withdrawals);
        self.* = undefined;
    }

    fn borrowed(self: *const OwnedPayloadAttributes) PayloadAttributesV3 {
        return .{
            .timestamp = self.timestamp,
            .prev_randao = self.prev_randao,
            .suggested_fee_recipient = self.suggested_fee_recipient,
            .withdrawals = self.withdrawals,
            .parent_beacon_block_root = self.parent_beacon_block_root,
        };
    }
};

const PendingPayloadPreparation = struct {
    slot: u64,
    attrs: OwnedPayloadAttributes,

    fn deinit(self: *PendingPayloadPreparation, allocator: std.mem.Allocator) void {
        self.attrs.deinit(allocator);
        self.* = undefined;
    }
};

const PendingForkchoiceUpdate = struct {
    priority: enum {
        high,
        normal,
    } = .high,
    ticket: u64,
    update: ExecutionForkchoiceUpdate,
    payload_preparation: ?PendingPayloadPreparation = null,

    fn deinit(self: *PendingForkchoiceUpdate, allocator: std.mem.Allocator) void {
        if (self.payload_preparation) |*payload_preparation| {
            payload_preparation.deinit(allocator);
        }
        self.* = undefined;
    }
};

pub const PayloadPreparationContext = struct {
    slot: u64,
    timestamp: u64,
    prev_randao: [32]u8,
    suggested_fee_recipient: [20]u8,
    parent_beacon_block_root: [32]u8,
};

pub const PayloadPreparationSubmitResult = union(enum) {
    ready,
    queued: u64,
    pending: u64,
    unavailable,
};

pub const PayloadFetchResult = union(enum) {
    pending,
    success: GetPayloadResponse,
    unavailable,
    failure: anyerror,
    canceled,
};

pub const BuilderBidFetchResult = union(enum) {
    pending,
    success: execution_mod.builder.SignedBuilderBid,
    unavailable,
    no_bid,
    failure: anyerror,
    canceled,
};

pub const PayloadFetchTask = struct {
    runtime: *const ExecutionRuntime,
    payload_id: [8]u8,
    result: PayloadFetchResult = .pending,

    pub fn run(self: *PayloadFetchTask) void {
        self.result = self.runtime.fetchPreparedPayloadResult(self.payload_id);
    }
};

pub const BuilderBidFetchTask = struct {
    runtime: *const ExecutionRuntime,
    slot: u64,
    parent_hash: [32]u8,
    proposer_pubkey: [48]u8,
    result: BuilderBidFetchResult = .pending,

    pub fn run(self: *BuilderBidFetchTask) void {
        self.result = self.runtime.fetchBuilderBidResult(
            self.slot,
            self.parent_hash,
            self.proposer_pubkey,
        );
    }
};

pub const PayloadFetchHandle = struct {
    task: PayloadFetchTask,
    thread: ?std.Thread,

    pub fn deinit(self: *PayloadFetchHandle) void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    pub fn finish(self: *PayloadFetchHandle) PayloadFetchResult {
        self.deinit();
        return self.task.result;
    }
};

pub const BuilderBidFetchHandle = struct {
    task: BuilderBidFetchTask,
    thread: ?std.Thread,

    pub fn deinit(self: *BuilderBidFetchHandle) void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    pub fn finish(self: *BuilderBidFetchHandle) BuilderBidFetchResult {
        self.deinit();
        return self.task.result;
    }
};

const ProposalRaceTimerResult = enum {
    fired,
    canceled,
};

const ProposalFetchEvent = union(enum) {
    engine: PayloadFetchResult,
    builder: BuilderBidFetchResult,
    cutoff: ProposalRaceTimerResult,
    timeout: ProposalRaceTimerResult,
};

const ProposalRaceState = struct {
    engine_done: bool = false,
    builder_done: bool = false,
    cutoff_reached: bool = false,
    timeout_reached: bool = false,
    engine_available: bool = false,
    builder_available: bool = false,
    engine_should_override_builder: bool = false,

    fn shouldStop(self: ProposalRaceState, stop_immediately_on_engine_success: bool) bool {
        if (self.engine_available and (self.engine_should_override_builder or stop_immediately_on_engine_success)) {
            return true;
        }
        if (self.engine_done and self.builder_done) return true;
        if (self.timeout_reached) return true;
        if (self.cutoff_reached and (self.engine_available or self.builder_available)) return true;
        return false;
    }
};

fn waitProposalRaceTimer(io: std.Io, timeout: std.Io.Timeout) ProposalRaceTimerResult {
    timeout.sleep(io) catch |err| switch (err) {
        error.Canceled => return .canceled,
    };
    return .fired;
}

pub const ProposalSourceFetchOutcome = struct {
    payload: ?GetPayloadResponse = null,
    builder_bid: ?execution_mod.builder.SignedBuilderBid = null,
    engine_error: ?anyerror = null,
    builder_error: ?anyerror = null,
    builder_no_bid: bool = false,
    timed_out: bool = false,

    pub fn takePayload(self: *ProposalSourceFetchOutcome) ?GetPayloadResponse {
        const payload = self.payload;
        self.payload = null;
        return payload;
    }

    pub fn takeBuilderBid(self: *ProposalSourceFetchOutcome) ?execution_mod.builder.SignedBuilderBid {
        const builder_bid = self.builder_bid;
        self.builder_bid = null;
        return builder_bid;
    }

    pub fn deinit(
        self: *ProposalSourceFetchOutcome,
        runtime: *const ExecutionRuntime,
        allocator: std.mem.Allocator,
    ) void {
        if (self.payload) |payload| runtime.freeGetPayloadResponse(payload);
        if (self.builder_bid) |builder_bid| execution_mod.builder.freeBid(allocator, builder_bid);
        self.* = undefined;
    }
};

pub const CompletedPayloadVerification = struct {
    ticket: u64,
    result: NewPayloadResult,
    had_engine: bool,
    elapsed_s: f64,
};

pub const CompletedForkchoiceUpdate = struct {
    ticket: u64,
    update: ExecutionForkchoiceUpdate,
    request: union(enum) {
        plain,
        payload_preparation: PayloadPreparationContext,
    },
    status: enum {
        success,
        unavailable,
        failed,
    },
    payload_status: ?ExecutionPayloadStatus = null,
    payload_id: ?[8]u8 = null,
    had_engine: bool,
    elapsed_s: f64,
};

pub const MetricsSnapshot = struct {
    has_cached_payload: bool,
    pending_forkchoice_updates: u64,
    pending_payload_verifications: u64,
    completed_forkchoice_updates: u64,
    completed_payload_verifications: u64,
    failed_payload_preparations: u64,
    el_offline: bool,
};

pub const ExecutionRuntime = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    mock_engine: ?*MockEngine = null,
    http_engine: ?*HttpEngine = null,
    io_transport: ?*IoHttpTransport = null,
    execution_url: ?[]u8 = null,
    engine_api: ?EngineApi = null,
    http_builder: ?*HttpBuilder = null,
    builder_transport: ?*IoHttpTransport = null,
    builder_api: ?BuilderApi = null,

    cached_payload_id: ?[8]u8 = null,
    cached_payload_slot: ?u64 = null,
    cached_payload_parent_root: ?[32]u8 = null,
    last_builder_status_slot: ?u64 = null,
    el_offline: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    lane_mutex: std.Io.Mutex = .init,
    queue_mutex: std.Io.Mutex = .init,
    queue_cond: std.Io.Condition = .init,
    pending_forkchoice_updates: std.ArrayListUnmanaged(PendingForkchoiceUpdate) = .empty,
    pending_payload_verifications: std.ArrayListUnmanaged(PendingPayloadVerification) = .empty,
    completed_forkchoice_updates: std.ArrayListUnmanaged(CompletedForkchoiceUpdate) = .empty,
    completed_payload_verifications: std.ArrayListUnmanaged(CompletedPayloadVerification) = .empty,
    failed_payload_preparations: std.ArrayListUnmanaged(FailedPayloadPreparation) = .empty,
    active_forkchoice_updates: usize = 0,
    active_payload_verifications: usize = 0,
    next_forkchoice_ticket: u64 = 1,
    shutdown_requested: bool = false,
    worker_thread: ?std.Thread = null,

    pub const AsyncWaitResult = enum {
        completed,
        idle,
        shutdown,
    };

    fn setElOffline(self: *ExecutionRuntime, el_offline: bool) void {
        self.el_offline.store(el_offline, .release);
    }

    pub fn isElOffline(self: *const ExecutionRuntime) bool {
        return self.el_offline.load(.acquire);
    }

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        opts: NodeOptions,
        jwt_secret: ?[32]u8,
    ) !*ExecutionRuntime {
        const self = try allocator.create(ExecutionRuntime);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .io = io,
        };
        errdefer self.deinit();

        if (opts.engine_mock) {
            const mock = try allocator.create(MockEngine);
            errdefer allocator.destroy(mock);
            mock.* = MockEngine.init(allocator);
            errdefer mock.deinit();

            self.mock_engine = mock;
            self.engine_api = mock.engine();
            scoped_log.info("execution engine: MockEngine (--engine-mock)", .{});
        } else if (opts.execution_urls.len > 0) {
            self.execution_url = try allocator.dupe(u8, opts.execution_urls[0]);
            errdefer {
                allocator.free(self.execution_url.?);
                self.execution_url = null;
            }

            const transport = try allocator.create(IoHttpTransport);
            errdefer allocator.destroy(transport);
            transport.* = IoHttpTransport.init(allocator, io);
            errdefer transport.deinit();
            self.io_transport = transport;

            const http_engine = try allocator.create(HttpEngine);
            errdefer allocator.destroy(http_engine);
            var retry_config = execution_mod.RetryConfig{
                .max_retries = opts.execution_retries,
                .initial_backoff_ms = opts.execution_retry_delay_ms,
            };
            if (opts.execution_timeout_ms) |timeout_ms| {
                retry_config.default_timeout_ms = timeout_ms;
                retry_config.new_payload_timeout_ms = timeout_ms;
            }
            http_engine.* = HttpEngine.initWithRetry(
                allocator,
                io,
                self.execution_url.?,
                jwt_secret,
                transport.transport(),
                retry_config,
            );
            errdefer http_engine.deinit();
            self.http_engine = http_engine;
            self.engine_api = http_engine.engine();

            scoped_log.info("execution engine: HttpEngine configured", .{});
        } else {
            return error.ExecutionEngineNotConfigured;
        }

        if (opts.builder_enabled) {
            const transport = try allocator.create(IoHttpTransport);
            errdefer allocator.destroy(transport);
            transport.* = IoHttpTransport.init(allocator, io);
            errdefer transport.deinit();
            self.builder_transport = transport;

            const http_builder = try allocator.create(HttpBuilder);
            errdefer allocator.destroy(http_builder);
            http_builder.* = HttpBuilder.init(
                allocator,
                opts.builder_url,
                transport.transport(),
                .{
                    .timeout_ms = opts.builder_timeout_ms,
                    .fault_inspection_window = execution_mod.builder.resolveFaultInspectionWindow(
                        io,
                        opts.builder_fault_inspection_window,
                    ),
                    .allowed_faults = opts.builder_allowed_faults,
                },
            );
            errdefer http_builder.deinit();
            self.http_builder = http_builder;
            self.builder_api = http_builder.builder();

            scoped_log.info("execution builder: HttpBuilder configured", .{});
        }

        self.worker_thread = try std.Thread.spawn(.{}, workerMain, .{self});
        return self;
    }

    pub fn deinit(self: *ExecutionRuntime) void {
        const allocator = self.allocator;

        self.queue_mutex.lockUncancelable(self.io);
        self.shutdown_requested = true;
        self.queue_cond.signal(self.io);
        self.queue_mutex.unlock(self.io);

        if (self.worker_thread) |thread| {
            thread.join();
        }

        for (self.pending_payload_verifications.items) |*pending| {
            pending.request.deinit(allocator);
        }
        for (self.pending_forkchoice_updates.items) |*pending| {
            pending.deinit(allocator);
        }
        self.pending_forkchoice_updates.deinit(allocator);
        self.pending_payload_verifications.deinit(allocator);
        self.completed_forkchoice_updates.deinit(allocator);
        self.completed_payload_verifications.deinit(allocator);
        self.failed_payload_preparations.deinit(allocator);

        if (self.mock_engine) |engine| {
            engine.deinit();
            allocator.destroy(engine);
        }
        if (self.http_engine) |engine| {
            engine.deinit();
            allocator.destroy(engine);
        }
        if (self.execution_url) |url| {
            allocator.free(url);
        }
        if (self.http_builder) |builder| {
            builder.deinit();
            allocator.destroy(builder);
        }
        if (self.io_transport) |transport| {
            transport.deinit();
            allocator.destroy(transport);
        }
        if (self.builder_transport) |transport| {
            transport.deinit();
            allocator.destroy(transport);
        }

        allocator.destroy(self);
    }

    pub fn executionPort(self: *ExecutionRuntime) ExecutionPort {
        return .{
            .ptr = @ptrCast(self),
            .submitNewPayloadFn = &submitNewPayloadFn,
        };
    }

    fn submitNewPayloadFn(ptr: *anyopaque, request: NewPayloadRequest) NewPayloadResult {
        const self: *ExecutionRuntime = @ptrCast(@alignCast(ptr));
        return self.submitNewPayload(request);
    }

    pub fn submitNewPayload(self: *ExecutionRuntime, request: NewPayloadRequest) NewPayloadResult {
        return self.submitNewPayloadSerialized(request).result;
    }

    pub fn canAcceptPayloadVerification(self: *ExecutionRuntime) bool {
        self.queue_mutex.lockUncancelable(self.io);
        defer self.queue_mutex.unlock(self.io);
        return !self.shutdown_requested and
            self.pending_payload_verifications.items.len +
                self.completed_payload_verifications.items.len +
                self.active_payload_verifications < DEFAULT_MAX_PENDING_PAYLOAD_VERIFICATIONS;
    }

    pub fn submitForkchoiceUpdateAsync(
        self: *ExecutionRuntime,
        update: ExecutionForkchoiceUpdate,
    ) !void {
        self.queue_mutex.lockUncancelable(self.io);
        defer self.queue_mutex.unlock(self.io);

        if (self.shutdown_requested) return error.ShutdownRequested;

        const ticket = self.next_forkchoice_ticket;
        self.next_forkchoice_ticket += 1;
        try self.pending_forkchoice_updates.append(self.allocator, .{
            .priority = .high,
            .ticket = ticket,
            .update = update,
        });
        self.queue_cond.signal(self.io);
    }

    pub fn seedKnownPayload(
        self: *ExecutionRuntime,
        parent_hash: [32]u8,
        block_hash: [32]u8,
        block_number: u64,
        timestamp: u64,
    ) !void {
        if (self.mock_engine) |mock| {
            try mock.seedPayload(.{
                .parent_hash = parent_hash,
                .block_hash = block_hash,
                .block_number = block_number,
                .timestamp = timestamp,
            });
        }
    }

    pub fn ensurePayloadPreparationAsync(
        self: *ExecutionRuntime,
        slot: u64,
        update: ExecutionForkchoiceUpdate,
        payload_attrs: PayloadAttributesV3,
    ) !PayloadPreparationSubmitResult {
        if (self.cachedPayloadFor(slot, update.beacon_block_root)) {
            return .ready;
        }

        self.queue_mutex.lockUncancelable(self.io);
        defer self.queue_mutex.unlock(self.io);

        if (self.shutdown_requested) return .unavailable;

        var i: usize = 0;
        while (i < self.pending_forkchoice_updates.items.len) {
            const pending = self.pending_forkchoice_updates.items[i];
            const payload_preparation = pending.payload_preparation orelse {
                i += 1;
                continue;
            };
            if (payload_preparation.slot != slot) {
                i += 1;
                continue;
            }
            if (std.mem.eql(u8, &pending.update.beacon_block_root, &update.beacon_block_root)) {
                return .{ .pending = pending.ticket };
            }

            var stale_pending = self.pending_forkchoice_updates.orderedRemove(i);
            stale_pending.deinit(self.allocator);
        }

        const ticket = self.next_forkchoice_ticket;
        self.next_forkchoice_ticket += 1;
        try self.pending_forkchoice_updates.append(self.allocator, .{
            .priority = .normal,
            .ticket = ticket,
            .update = update,
            .payload_preparation = .{
                .slot = slot,
                .attrs = try OwnedPayloadAttributes.init(self.allocator, payload_attrs),
            },
        });
        self.queue_cond.signal(self.io);
        return .{ .queued = ticket };
    }

    pub fn submitPayloadVerification(
        self: *ExecutionRuntime,
        ticket: u64,
        request: NewPayloadRequest,
    ) !bool {
        self.queue_mutex.lockUncancelable(self.io);
        defer self.queue_mutex.unlock(self.io);

        if (self.shutdown_requested) return false;
        if (self.pending_payload_verifications.items.len +
            self.completed_payload_verifications.items.len +
            self.active_payload_verifications >= DEFAULT_MAX_PENDING_PAYLOAD_VERIFICATIONS) return false;

        try self.pending_payload_verifications.append(self.allocator, .{
            .ticket = ticket,
            .request = request,
        });
        self.queue_cond.signal(self.io);
        return true;
    }

    pub fn popCompletedPayloadVerification(self: *ExecutionRuntime) ?CompletedPayloadVerification {
        self.queue_mutex.lockUncancelable(self.io);
        defer self.queue_mutex.unlock(self.io);

        if (self.completed_payload_verifications.items.len == 0) return null;
        return self.completed_payload_verifications.orderedRemove(0);
    }

    pub fn popCompletedForkchoiceUpdate(self: *ExecutionRuntime) ?CompletedForkchoiceUpdate {
        self.queue_mutex.lockUncancelable(self.io);
        defer self.queue_mutex.unlock(self.io);

        if (self.completed_forkchoice_updates.items.len == 0) return null;
        return self.completed_forkchoice_updates.orderedRemove(0);
    }

    pub fn waitForAsyncCompletion(self: *ExecutionRuntime) AsyncWaitResult {
        self.queue_mutex.lockUncancelable(self.io);
        defer self.queue_mutex.unlock(self.io);

        while (!self.shutdown_requested and
            self.completed_payload_verifications.items.len == 0 and
            self.completed_forkchoice_updates.items.len == 0 and
            self.failed_payload_preparations.items.len == 0 and
            (self.pending_payload_verifications.items.len > 0 or
                self.pending_forkchoice_updates.items.len > 0 or
                self.active_payload_verifications > 0 or
                self.active_forkchoice_updates > 0))
        {
            self.queue_cond.waitUncancelable(self.io, &self.queue_mutex);
        }

        if (self.completed_payload_verifications.items.len > 0 or
            self.completed_forkchoice_updates.items.len > 0 or
            self.failed_payload_preparations.items.len > 0)
        {
            return .completed;
        }
        if (self.shutdown_requested) return .shutdown;
        return .idle;
    }

    pub const PayloadPreparationWaitResult = enum {
        ready,
        unavailable,
        failed,
        shutdown,
    };

    pub fn waitForPayloadPreparation(
        self: *ExecutionRuntime,
        ticket: u64,
        slot: u64,
        parent_root: [32]u8,
    ) PayloadPreparationWaitResult {
        while (true) {
            if (self.cachedPayloadFor(slot, parent_root)) return .ready;

            self.queue_mutex.lockUncancelable(self.io);
            while (true) {
                for (self.failed_payload_preparations.items, 0..) |failed, i| {
                    if (failed.ticket != ticket) continue;
                    _ = self.failed_payload_preparations.orderedRemove(i);
                    self.queue_mutex.unlock(self.io);
                    return switch (failed.status) {
                        .unavailable => .unavailable,
                        .failed => .failed,
                    };
                }

                if (self.shutdown_requested) {
                    self.queue_mutex.unlock(self.io);
                    return .shutdown;
                }
                self.queue_cond.waitUncancelable(self.io, &self.queue_mutex);
                if (self.cachedPayloadFor(slot, parent_root)) {
                    self.queue_mutex.unlock(self.io);
                    return .ready;
                }
            }
        }
    }

    fn submitNewPayloadSerialized(
        self: *ExecutionRuntime,
        request: NewPayloadRequest,
    ) CompletedPayloadVerification {
        self.lane_mutex.lockUncancelable(self.io);
        defer self.lane_mutex.unlock(self.io);

        const had_engine = self.engine_api != null;
        const t0 = std.Io.Clock.awake.now(self.io);

        const engine = self.engine_api orelse {
            const t1 = std.Io.Clock.awake.now(self.io);
            return .{
                .ticket = 0,
                .result = .unavailable,
                .had_engine = had_engine,
                .elapsed_s = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9,
            };
        };

        const engine_result = switch (request) {
            .bellatrix => |prepared| engine.newPayloadV1(prepared.payload),
            .capella => |prepared| engine.newPayloadV2(prepared.payload),
            .deneb => |prepared| engine.newPayload(
                prepared.payload,
                prepared.versioned_hashes,
                prepared.parent_beacon_block_root,
            ),
            .electra => |prepared| engine.newPayloadV4(
                prepared.payload,
                prepared.versioned_hashes,
                prepared.parent_beacon_block_root,
            ),
        } catch |err| {
            scoped_log.warn("execution runtime: engine_newPayload failed: {}", .{err});
            self.setElOffline(true);
            const t1 = std.Io.Clock.awake.now(self.io);
            return .{
                .ticket = 0,
                .result = .unavailable,
                .had_engine = had_engine,
                .elapsed_s = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9,
            };
        };
        defer engine_result.deinit(self.allocator);
        const t1 = std.Io.Clock.awake.now(self.io);
        const elapsed_s: f64 = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9;

        self.setElOffline(false);
        const response = switch (engine_result.status) {
            .valid => NewPayloadResult{ .valid = .{
                .latest_valid_hash = engine_result.latest_valid_hash orelse request.blockHash(),
            } },
            .invalid => NewPayloadResult{ .invalid = .{
                .latest_valid_hash = engine_result.latest_valid_hash,
            } },
            .invalid_block_hash => NewPayloadResult{ .invalid_block_hash = .{
                .latest_valid_hash = engine_result.latest_valid_hash,
            } },
            .syncing => NewPayloadResult.syncing,
            .accepted => NewPayloadResult.accepted,
        };
        return .{
            .ticket = 0,
            .result = response,
            .had_engine = had_engine,
            .elapsed_s = elapsed_s,
        };
    }

    fn submitForkchoiceUpdateSerialized(
        self: *ExecutionRuntime,
        pending: PendingForkchoiceUpdate,
    ) CompletedForkchoiceUpdate {
        defer {
            var owned_pending = pending;
            owned_pending.deinit(self.allocator);
        }

        const had_engine = self.engine_api != null;
        const t0 = std.Io.Clock.awake.now(self.io);
        const payload_attrs = if (pending.payload_preparation) |*payload_preparation|
            payload_preparation.attrs.borrowed()
        else
            null;
        const maybe_result = self.submitForkchoiceUpdateOnLane(pending.update, payload_attrs) catch |err| {
            scoped_log.warn("execution runtime: engine_forkchoiceUpdated failed: {}", .{err});
            const t1 = std.Io.Clock.awake.now(self.io);
            return .{
                .ticket = pending.ticket,
                .update = pending.update,
                .request = if (pending.payload_preparation) |payload_preparation|
                    .{ .payload_preparation = .{
                        .slot = payload_preparation.slot,
                        .timestamp = payload_preparation.attrs.timestamp,
                        .prev_randao = payload_preparation.attrs.prev_randao,
                        .suggested_fee_recipient = payload_preparation.attrs.suggested_fee_recipient,
                        .parent_beacon_block_root = payload_preparation.attrs.parent_beacon_block_root,
                    } }
                else
                    .plain,
                .status = .failed,
                .had_engine = had_engine,
                .elapsed_s = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9,
            };
        };
        defer if (maybe_result) |*result| result.deinit(self.allocator);

        if (pending.payload_preparation) |payload_preparation| {
            self.recordPreparedPayloadContext(
                payload_preparation.slot,
                pending.update.beacon_block_root,
            );
        }

        const t1 = std.Io.Clock.awake.now(self.io);
        return .{
            .ticket = pending.ticket,
            .update = pending.update,
            .request = if (pending.payload_preparation) |payload_preparation|
                .{ .payload_preparation = .{
                    .slot = payload_preparation.slot,
                    .timestamp = payload_preparation.attrs.timestamp,
                    .prev_randao = payload_preparation.attrs.prev_randao,
                    .suggested_fee_recipient = payload_preparation.attrs.suggested_fee_recipient,
                    .parent_beacon_block_root = payload_preparation.attrs.parent_beacon_block_root,
                } }
            else
                .plain,
            .status = if (maybe_result == null) .unavailable else .success,
            .payload_status = if (maybe_result) |result| result.payload_status.status else null,
            .payload_id = if (maybe_result) |result| result.payload_id else null,
            .had_engine = had_engine,
            .elapsed_s = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9,
        };
    }

    fn workerMain(self: *ExecutionRuntime) void {
        while (true) {
            self.queue_mutex.lockUncancelable(self.io);
            while (!self.shutdown_requested and
                self.pending_forkchoice_updates.items.len == 0 and
                self.pending_payload_verifications.items.len == 0)
            {
                self.queue_cond.waitUncancelable(self.io, &self.queue_mutex);
            }

            if (self.shutdown_requested and
                self.pending_forkchoice_updates.items.len == 0 and
                self.pending_payload_verifications.items.len == 0)
            {
                self.queue_mutex.unlock(self.io);
                return;
            }

            if (self.pending_forkchoice_updates.items.len > 0) {
                var pending_index: usize = 0;
                for (self.pending_forkchoice_updates.items, 0..) |pending, i| {
                    if (pending.priority == .high) {
                        pending_index = i;
                        break;
                    }
                }
                const pending = self.pending_forkchoice_updates.orderedRemove(pending_index);
                self.active_forkchoice_updates += 1;
                self.queue_mutex.unlock(self.io);

                const completed = self.submitForkchoiceUpdateSerialized(pending);

                self.queue_mutex.lockUncancelable(self.io);
                self.completed_forkchoice_updates.append(self.allocator, completed) catch {
                    self.active_forkchoice_updates -= 1;
                    self.queue_mutex.unlock(self.io);
                    @panic("OOM queueing completed forkchoice update");
                };
                if (completed.request == .payload_preparation and completed.status != .success) {
                    self.failed_payload_preparations.append(self.allocator, .{
                        .ticket = completed.ticket,
                        .status = switch (completed.status) {
                            .success => unreachable,
                            .unavailable => .unavailable,
                            .failed => .failed,
                        },
                    }) catch {
                        self.active_forkchoice_updates -= 1;
                        self.queue_mutex.unlock(self.io);
                        @panic("OOM queueing failed payload preparation");
                    };
                }
                self.active_forkchoice_updates -= 1;
                self.queue_cond.signal(self.io);
                self.queue_mutex.unlock(self.io);
                continue;
            }

            const pending = self.pending_payload_verifications.orderedRemove(0);
            self.active_payload_verifications += 1;
            self.queue_mutex.unlock(self.io);

            defer {
                var owned_pending = pending;
                owned_pending.request.deinit(self.allocator);
            }

            var completed = self.submitNewPayloadSerialized(pending.request);
            completed.ticket = pending.ticket;

            self.queue_mutex.lockUncancelable(self.io);
            self.completed_payload_verifications.append(self.allocator, completed) catch {
                self.active_payload_verifications -= 1;
                self.queue_mutex.unlock(self.io);
                @panic("OOM queueing completed execution verification");
            };
            self.active_payload_verifications -= 1;
            self.queue_cond.signal(self.io);
            self.queue_mutex.unlock(self.io);
        }
    }

    fn submitForkchoiceUpdateOnLane(
        self: *ExecutionRuntime,
        update: ExecutionForkchoiceUpdate,
        payload_attrs: ?PayloadAttributesV3,
    ) !?ForkchoiceUpdatedResponse {
        self.lane_mutex.lockUncancelable(self.io);
        defer self.lane_mutex.unlock(self.io);
        const engine = self.engine_api orelse return null;
        const fc_state = update.state;

        const result = engine.forkchoiceUpdated(.{
            .head_block_hash = fc_state.head_block_hash,
            .safe_block_hash = fc_state.safe_block_hash,
            .finalized_block_hash = fc_state.finalized_block_hash,
        }, payload_attrs) catch |err| {
            self.setElOffline(true);
            return err;
        };

        self.setElOffline(false);
        if (result.payload_id) |payload_id| {
            self.cached_payload_id = payload_id;
            if (payload_attrs != null) self.cached_payload_parent_root = update.beacon_block_root;
        } else if (payload_attrs != null) {
            self.clearCachedPayload();
        }
        return result;
    }

    pub fn getPayload(self: *ExecutionRuntime) !GetPayloadResponse {
        self.lane_mutex.lockUncancelable(self.io);
        defer self.lane_mutex.unlock(self.io);
        const engine = self.engine_api orelse return error.NoEngineApi;
        const payload_id = self.cached_payload_id orelse return error.NoPayloadId;

        const result = engine.getPayload(payload_id) catch |err| {
            self.setElOffline(true);
            return err;
        };

        self.setElOffline(false);
        self.clearCachedPayload();
        return result;
    }

    pub fn fetchPreparedPayloadResult(
        self: *const ExecutionRuntime,
        payload_id: [8]u8,
    ) PayloadFetchResult {
        if (self.http_engine) |http_engine| {
            var request_engine = http_engine.requestClone();
            const api = request_engine.engine();
            const response = api.getPayload(payload_id) catch |err| switch (err) {
                error.Canceled => return .canceled,
                else => {
                    const mutable_self: *ExecutionRuntime = @constCast(self);
                    mutable_self.setElOffline(true);
                    return .{ .failure = err };
                },
            };
            const mutable_self: *ExecutionRuntime = @constCast(self);
            mutable_self.setElOffline(false);
            return .{ .success = response };
        }

        const mutable_self: *ExecutionRuntime = @constCast(self);
        mutable_self.lane_mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.lane_mutex.unlock(mutable_self.io);
        const engine = self.engine_api orelse return .unavailable;
        const response = engine.getPayload(payload_id) catch |err| switch (err) {
            error.Canceled => return .canceled,
            else => {
                mutable_self.setElOffline(true);
                return .{ .failure = err };
            },
        };
        mutable_self.setElOffline(false);
        return .{ .success = response };
    }

    pub fn freePayloadFetchResult(self: *const ExecutionRuntime, result: PayloadFetchResult) void {
        switch (result) {
            .success => |response| self.freeGetPayloadResponse(response),
            else => {},
        }
    }

    pub fn fetchBuilderBidResult(
        self: *const ExecutionRuntime,
        slot: u64,
        parent_hash: [32]u8,
        proposer_pubkey: [48]u8,
    ) BuilderBidFetchResult {
        if (self.http_builder) |http_builder| {
            var request_builder = http_builder.requestClone();
            const api = request_builder.builder();
            const bid = api.getHeader(slot, parent_hash, proposer_pubkey) catch |err| switch (err) {
                error.Canceled => return .canceled,
                else => return .{ .failure = err },
            };
            if (bid) |value| {
                return .{ .success = value };
            }
            return .no_bid;
        }

        const builder = self.builder_api orelse return .unavailable;
        const bid = builder.getHeader(slot, parent_hash, proposer_pubkey) catch |err| switch (err) {
            error.Canceled => return .canceled,
            else => return .{ .failure = err },
        };
        if (bid) |value| {
            return .{ .success = value };
        }
        return .no_bid;
    }

    fn freeProposalFetchEvent(self: *const ExecutionRuntime, allocator: std.mem.Allocator, event: ProposalFetchEvent) void {
        switch (event) {
            .engine => |result| self.freePayloadFetchResult(result),
            .builder => |result| switch (result) {
                .success => |bid| execution_mod.builder.freeBid(allocator, bid),
                else => {},
            },
            .cutoff, .timeout => {},
        }
    }

    pub fn fetchProposalSources(
        self: *const ExecutionRuntime,
        allocator: std.mem.Allocator,
        payload_id: [8]u8,
        slot: u64,
        parent_hash: [32]u8,
        proposer_pubkey: [48]u8,
        cutoff_ns: u64,
        timeout_ms: u64,
        stop_immediately_on_engine_success: bool,
    ) !ProposalSourceFetchOutcome {
        return self.fetchProposalSourcesWithSelect(
            allocator,
            payload_id,
            slot,
            parent_hash,
            proposer_pubkey,
            cutoff_ns,
            timeout_ms,
            stop_immediately_on_engine_success,
        ) catch |err| switch (err) {
            error.ConcurrencyUnavailable => self.fetchProposalSourcesBlocking(
                payload_id,
                slot,
                parent_hash,
                proposer_pubkey,
            ),
            else => err,
        };
    }

    fn fetchProposalSourcesWithSelect(
        self: *const ExecutionRuntime,
        allocator: std.mem.Allocator,
        payload_id: [8]u8,
        slot: u64,
        parent_hash: [32]u8,
        proposer_pubkey: [48]u8,
        cutoff_ns: u64,
        timeout_ms: u64,
        stop_immediately_on_engine_success: bool,
    ) !ProposalSourceFetchOutcome {
        var events_buf: [4]ProposalFetchEvent = undefined;
        var select = std.Io.Select(ProposalFetchEvent).init(self.io, &events_buf);
        errdefer while (select.cancel()) |event| {
            self.freeProposalFetchEvent(allocator, event);
        };

        try select.concurrent(.engine, ExecutionRuntime.fetchPreparedPayloadResult, .{
            self,
            payload_id,
        });
        try select.concurrent(.builder, ExecutionRuntime.fetchBuilderBidResult, .{
            self,
            slot,
            parent_hash,
            proposer_pubkey,
        });

        var race_state = ProposalRaceState{};
        if (cutoff_ns == 0) {
            race_state.cutoff_reached = true;
        } else {
            select.async(.cutoff, waitProposalRaceTimer, .{
                self.io,
                .{ .duration = .{
                    .raw = .{ .nanoseconds = @as(i96, @intCast(cutoff_ns)) },
                    .clock = .real,
                } },
            });
        }
        select.async(.timeout, waitProposalRaceTimer, .{
            self.io,
            .{ .duration = .{
                .raw = .{ .nanoseconds = @as(i96, @intCast(timeout_ms * std.time.ns_per_ms)) },
                .clock = .real,
            } },
        });

        var outcome = ProposalSourceFetchOutcome{};
        while (true) {
            const event = try select.await();
            switch (event) {
                .engine => |result| {
                    race_state.engine_done = true;
                    switch (result) {
                        .success => |payload| {
                            outcome.payload = payload;
                            race_state.engine_available = true;
                            race_state.engine_should_override_builder = payload.should_override_builder;
                        },
                        .unavailable => outcome.engine_error = error.NoEngineApi,
                        .failure => |err| outcome.engine_error = err,
                        .canceled, .pending => {},
                    }
                },
                .builder => |result| {
                    race_state.builder_done = true;
                    switch (result) {
                        .success => |builder_bid| {
                            outcome.builder_bid = builder_bid;
                            race_state.builder_available = true;
                        },
                        .unavailable => outcome.builder_error = error.BuilderNotConfigured,
                        .no_bid => outcome.builder_no_bid = true,
                        .failure => |err| outcome.builder_error = err,
                        .canceled, .pending => {},
                    }
                },
                .cutoff => |result| {
                    if (result == .fired) race_state.cutoff_reached = true;
                },
                .timeout => |result| {
                    if (result == .fired) race_state.timeout_reached = true;
                },
            }

            if (race_state.shouldStop(stop_immediately_on_engine_success)) break;
        }

        while (select.cancel()) |event| {
            self.freeProposalFetchEvent(allocator, event);
        }

        outcome.timed_out = race_state.timeout_reached;
        return outcome;
    }

    fn fetchProposalSourcesBlocking(
        self: *const ExecutionRuntime,
        payload_id: [8]u8,
        slot: u64,
        parent_hash: [32]u8,
        proposer_pubkey: [48]u8,
    ) !ProposalSourceFetchOutcome {
        var payload_fetch = PayloadFetchTask{
            .runtime = self,
            .payload_id = payload_id,
        };
        var builder_bid_fetch = BuilderBidFetchTask{
            .runtime = self,
            .slot = slot,
            .parent_hash = parent_hash,
            .proposer_pubkey = proposer_pubkey,
        };

        var payload_thread = try std.Thread.spawn(.{}, PayloadFetchTask.run, .{&payload_fetch});
        errdefer payload_thread.join();
        var builder_thread = try std.Thread.spawn(.{}, BuilderBidFetchTask.run, .{&builder_bid_fetch});
        errdefer builder_thread.join();

        payload_thread.join();
        builder_thread.join();

        var outcome = ProposalSourceFetchOutcome{};
        switch (payload_fetch.result) {
            .pending => unreachable,
            .success => |payload| outcome.payload = payload,
            .unavailable => outcome.engine_error = error.NoEngineApi,
            .failure => |err| outcome.engine_error = err,
            .canceled => {},
        }
        switch (builder_bid_fetch.result) {
            .pending => unreachable,
            .success => |builder_bid| outcome.builder_bid = builder_bid,
            .unavailable => outcome.builder_error = error.BuilderNotConfigured,
            .no_bid => outcome.builder_no_bid = true,
            .failure => |err| outcome.builder_error = err,
            .canceled => {},
        }
        return outcome;
    }

    pub fn startPreparedPayloadFetch(
        self: *const ExecutionRuntime,
        payload_id: [8]u8,
    ) !PayloadFetchHandle {
        var handle = PayloadFetchHandle{
            .task = .{
                .runtime = self,
                .payload_id = payload_id,
            },
            .thread = null,
        };
        handle.thread = try std.Thread.spawn(.{}, PayloadFetchTask.run, .{&handle.task});
        return handle;
    }

    pub fn startBuilderBidFetch(
        self: *const ExecutionRuntime,
        slot: u64,
        parent_hash: [32]u8,
        proposer_pubkey: [48]u8,
    ) !BuilderBidFetchHandle {
        var handle = BuilderBidFetchHandle{
            .task = .{
                .runtime = self,
                .slot = slot,
                .parent_hash = parent_hash,
                .proposer_pubkey = proposer_pubkey,
            },
            .thread = null,
        };
        handle.thread = try std.Thread.spawn(.{}, BuilderBidFetchTask.run, .{&handle.task});
        return handle;
    }

    pub fn freeGetPayloadResponse(self: *const ExecutionRuntime, response: GetPayloadResponse) void {
        const engine = self.engine_api orelse return;
        engine.freeGetPayloadResponse(response);
    }

    pub fn hasExecutionEngine(self: *const ExecutionRuntime) bool {
        return self.engine_api != null;
    }

    pub fn builderApi(self: *const ExecutionRuntime) ?BuilderApi {
        return self.builder_api;
    }

    pub fn currentBuilderStatus(self: *const ExecutionRuntime) execution_mod.BuilderStatus {
        const mutable_self: *ExecutionRuntime = @constCast(self);
        mutable_self.lane_mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.lane_mutex.unlock(mutable_self.io);
        const http_builder = self.http_builder orelse return .unavailable;
        return http_builder.current_status;
    }

    pub fn updateBuilderStatus(
        self: *ExecutionRuntime,
        status: execution_mod.BuilderStatus,
    ) void {
        self.lane_mutex.lockUncancelable(self.io);
        defer self.lane_mutex.unlock(self.io);
        if (self.http_builder) |http_builder| http_builder.updateStatus(status);
    }

    pub fn getValidatorRegistration(
        self: *const ExecutionRuntime,
        pubkey: [48]u8,
    ) ?execution_mod.builder.CachedValidatorRegistration {
        const http_builder = self.http_builder orelse return null;
        return http_builder.getValidatorRegistration(pubkey);
    }

    pub fn builderFaultInspectionWindow(self: *const ExecutionRuntime) u64 {
        const http_builder = self.http_builder orelse return 0;
        return http_builder.fault_inspection_window;
    }

    pub fn builderAllowedFaults(self: *const ExecutionRuntime) u64 {
        const http_builder = self.http_builder orelse return 0;
        return http_builder.allowed_faults;
    }

    pub fn metricsSnapshot(self: *const ExecutionRuntime) MetricsSnapshot {
        const mutable_self: *ExecutionRuntime = @constCast(self);
        mutable_self.queue_mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.queue_mutex.unlock(mutable_self.io);
        mutable_self.lane_mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.lane_mutex.unlock(mutable_self.io);
        return .{
            .has_cached_payload = self.cached_payload_id != null,
            .pending_forkchoice_updates = @intCast(self.pending_forkchoice_updates.items.len),
            .pending_payload_verifications = @intCast(self.pending_payload_verifications.items.len),
            .completed_forkchoice_updates = @intCast(self.completed_forkchoice_updates.items.len),
            .completed_payload_verifications = @intCast(self.completed_payload_verifications.items.len),
            .failed_payload_preparations = @intCast(self.failed_payload_preparations.items.len),
            .el_offline = self.isElOffline(),
        };
    }

    pub fn lastBuilderStatusSlot(self: *const ExecutionRuntime) ?u64 {
        const mutable_self: *ExecutionRuntime = @constCast(self);
        mutable_self.lane_mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.lane_mutex.unlock(mutable_self.io);
        return self.last_builder_status_slot;
    }

    pub fn setLastBuilderStatusSlot(self: *ExecutionRuntime, slot: ?u64) void {
        self.lane_mutex.lockUncancelable(self.io);
        defer self.lane_mutex.unlock(self.io);
        self.last_builder_status_slot = slot;
    }

    pub fn cachedPayloadId(self: *const ExecutionRuntime) ?[8]u8 {
        const mutable_self: *ExecutionRuntime = @constCast(self);
        mutable_self.lane_mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.lane_mutex.unlock(mutable_self.io);
        return self.cached_payload_id;
    }

    pub fn cachedPayloadFor(
        self: *const ExecutionRuntime,
        slot: u64,
        parent_root: [32]u8,
    ) bool {
        const mutable_self: *ExecutionRuntime = @constCast(self);
        mutable_self.lane_mutex.lockUncancelable(mutable_self.io);
        defer mutable_self.lane_mutex.unlock(mutable_self.io);
        return self.cached_payload_slot == slot and
            self.cached_payload_id != null and
            self.cached_payload_parent_root != null and
            std.mem.eql(u8, &self.cached_payload_parent_root.?, &parent_root);
    }

    fn recordPreparedPayloadContext(
        self: *ExecutionRuntime,
        slot: u64,
        parent_root: [32]u8,
    ) void {
        self.lane_mutex.lockUncancelable(self.io);
        defer self.lane_mutex.unlock(self.io);
        if (self.cached_payload_id != null) {
            self.cached_payload_slot = slot;
            self.cached_payload_parent_root = parent_root;
        } else {
            self.cached_payload_slot = null;
            self.cached_payload_parent_root = null;
        }
    }

    pub fn invalidatePreparedPayloadIfStale(
        self: *ExecutionRuntime,
        slot: u64,
        parent_root: [32]u8,
    ) void {
        self.lane_mutex.lockUncancelable(self.io);
        defer self.lane_mutex.unlock(self.io);
        if (self.cached_payload_slot) |cached_slot| {
            if (cached_slot != slot or
                self.cached_payload_parent_root == null or
                !std.mem.eql(u8, &self.cached_payload_parent_root.?, &parent_root))
            {
                self.clearCachedPayload();
            }
        }
    }

    pub fn clearCachedPayloadIfMatch(
        self: *ExecutionRuntime,
        slot: u64,
        parent_root: [32]u8,
        payload_id: [8]u8,
    ) void {
        self.lane_mutex.lockUncancelable(self.io);
        defer self.lane_mutex.unlock(self.io);
        if (self.cached_payload_slot != slot) return;
        const cached_parent_root = self.cached_payload_parent_root orelse return;
        if (!std.mem.eql(u8, &cached_parent_root, &parent_root)) return;
        const cached_payload_id = self.cached_payload_id orelse return;
        if (!std.mem.eql(u8, &cached_payload_id, &payload_id)) return;
        self.clearCachedPayload();
    }

    fn clearCachedPayload(self: *ExecutionRuntime) void {
        self.cached_payload_id = null;
        self.cached_payload_slot = null;
        self.cached_payload_parent_root = null;
    }
};
