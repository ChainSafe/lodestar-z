//! Beacon API HTTP client for the Validator Client.
//!
//! Wraps HTTP calls to the Beacon Node REST API endpoints consumed by
//! validator clients (duties, block production, attestation, sync committee).
//!
//! TS equivalent: @lodestar/api ApiClient (packages/api/src/client/)
//!
//! Design (Zig 0.16):
//!   - Owns reusable std.http.Client instances for request and SSE traffic.
//!   - GET requests use sendBodiless(); POST uses transfer_encoding + sendBodyComplete().
//!   - SSE stream for events uses a chunked reader over a persistent TCP connection.
//!   - JSON parsing uses std.json.parseFromSlice with ArenaAllocator.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const types = @import("types.zig");
const ProposerDuty = types.ProposerDuty;
const AttesterDuty = types.AttesterDuty;
const SyncCommitteeDuty = types.SyncCommitteeDuty;
const ValidatorMetrics = @import("metrics.zig").ValidatorMetrics;
const time = @import("time.zig");

const log = std.log.scoped(.vc_api);

/// Maximum response body size: 16 MiB.
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
/// SSE line buffer size.
const SSE_LINE_BUF = 4096;

// ---------------------------------------------------------------------------
// SSE event (raw)
// ---------------------------------------------------------------------------

/// A single Server-Sent Event received from the BN.
pub const SseEvent = struct {
    /// Event type string (e.g., "head", "block", "finalized_checkpoint").
    event_type: []const u8,
    /// Raw JSON data payload.
    data: []const u8,
};

pub const HeadHeaderSummary = struct {
    slot: u64,
    block_root: [32]u8,
};

pub const ProposerDutiesResponse = struct {
    duties: []ProposerDuty,
    dependent_root: ?[32]u8,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.duties);
    }
};

pub const AttesterDutiesResponse = struct {
    duties: []AttesterDuty,
    dependent_root: ?[32]u8,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        allocator.free(self.duties);
    }
};

/// Callback type for SSE events.
pub const SseCallback = struct {
    ctx: *anyopaque,
    fn_ptr: *const fn (ctx: *anyopaque, event: SseEvent) void,

    pub fn call(self: SseCallback, event: SseEvent) void {
        self.fn_ptr(self.ctx, event);
    }
};

pub const BeaconCommitteeSubscription = struct {
    validator_index: u64,
    committee_index: u64,
    committees_at_slot: u64,
    slot: u64,
    is_aggregator: bool,
};

pub const SyncCommitteeSubscription = struct {
    validator_index: u64,
    sync_committee_indices: []const u64,
    until_epoch: u64,
};

pub const ProduceBlockOpts = struct {
    fee_recipient: ?[20]u8 = null,
    builder_selection: ?types.BuilderSelection = null,
    builder_boost_factor: ?u64 = null,
    strict_fee_recipient_check: bool = false,
    blinded_local: bool = false,
};

const SszGetResponse = struct {
    body: []const u8,
    fork_name: [32]u8,
    fork_name_len: u8,
    is_blinded: bool,
    execution_payload_source: types.ExecutionPayloadSource,
};

// ---------------------------------------------------------------------------
// BeaconApiClient
// ---------------------------------------------------------------------------

/// Maximum consecutive failures before logging "beacon node unreachable".
const BN_UNREACHABLE_THRESHOLD: u64 = 3;
const URL_SCORE_DELTA_SUCCESS: u8 = 1;
const URL_SCORE_DELTA_ERROR: u8 = 2 * URL_SCORE_DELTA_SUCCESS;
const URL_SCORE_MAX: u8 = 10 * URL_SCORE_DELTA_SUCCESS;
const URL_SCORE_MIN: u8 = 0;

const route_ids = struct {
    const beacon_get_genesis = "beacon.getGenesis";
    const config_get_spec = "config.getSpec";
    const beacon_get_header = "beacon.getHeader";
    const beacon_get_state_finality_checkpoints = "beacon.getStateFinalityCheckpoints";
    const validator_get_proposer_duties = "validator.getProposerDuties";
    const validator_get_attester_duties = "validator.getAttesterDuties";
    const validator_get_sync_committee_duties = "validator.getSyncCommitteeDuties";
    const beacon_get_state_validators = "beacon.getStateValidators";
    const validator_produce_block_v3 = "validator.produceBlockV3";
    const beacon_publish_block_v2 = "beacon.publishBlockV2";
    const validator_produce_attestation_data = "validator.produceAttestationData";
    const beacon_publish_attestations_v2 = "beacon.publishAttestationsV2";
    const beacon_publish_voluntary_exit = "beacon.publishVoluntaryExit";
    const validator_get_aggregate_attestation = "validator.getAggregatedAttestation";
    const validator_publish_aggregate_and_proofs_v2 = "validator.publishAggregateAndProofsV2";
    const beacon_publish_sync_committee_messages = "beacon.publishSyncCommitteeMessages";
    const validator_publish_contribution_and_proofs = "validator.publishContributionAndProofs";
    const validator_produce_sync_committee_contribution = "validator.produceSyncCommitteeContribution";
    const validator_prepare_beacon_committee_subscriptions = "validator.prepareBeaconCommitteeSubscriptions";
    const validator_prepare_sync_committee_subscriptions = "validator.prepareSyncCommitteeSubscriptions";
    const validator_prepare_beacon_proposer = "validator.prepareBeaconProposer";
    const validator_register_validator = "validator.registerValidator";
    const beacon_publish_blinded_block_v2 = "beacon.publishBlindedBlockV2";
    const events_eventstream = "events.eventstream";
    const node_get_syncing_status = "node.getSyncingStatus";
    const validator_get_liveness = "validator.getLiveness";
};

/// HTTP client for the Beacon Node REST API (validator-facing endpoints).
///
/// Supports multiple beacon node URLs with request-scoped fallback attempts.
/// Tracks consecutive failures on the current active URL and promotes the
/// first URL that succeeds for future requests.
pub const BeaconApiClient = struct {
    pub const Options = struct {
        base_url: []const u8,
        fallback_urls: []const []const u8 = &.{},
        request_timeout_ms: u64 = 12_000,
        metrics: ?*ValidatorMetrics = null,
    };

    allocator: Allocator,
    io: Io,
    http_client: std.http.Client,
    sse_client: std.http.Client,
    /// Primary beacon node URL (first in urls list, or beacon_node_url).
    base_url: []const u8,
    /// Additional fallback beacon node URLs (may be empty).
    /// Tried in order when the primary fails.
    fallback_urls: []const []const u8,
    /// Health score per configured beacon URL.
    url_scores: []u8,
    /// Index of the currently active URL (0 = primary).
    active_url_idx: usize,
    /// Consecutive HTTP/transport failures on the current URL.
    consecutive_failures: u64,
    /// Whether the BN was considered unreachable at the last check.
    was_unreachable: bool,
    /// Monotonic ns timestamp when BN first became unreachable.
    unreachable_since_ns: u64,
    /// Default timeout budget for non-streaming BN requests.
    request_timeout_ms: u64,
    metrics: ?*ValidatorMetrics,
    /// Protects the shared failover state used by validator worker threads.
    state_mutex: std.Io.Mutex,

    pub const FailoverStatus = struct {
        configured: bool,
        connected: bool,
    };

    pub fn init(allocator: Allocator, io: Io, base_url: []const u8) !BeaconApiClient {
        return initWithOptions(allocator, io, .{ .base_url = base_url });
    }

    /// Create a client with multiple beacon node URLs (fallback support).
    ///
    /// `urls` must have at least one entry. The first is the primary.
    /// TS: BeaconNodeOpts.urls (array of BN endpoints)
    pub fn initMulti(allocator: Allocator, io: Io, urls: []const []const u8) !BeaconApiClient {
        if (urls.len == 0) return error.InvalidBeaconNodeUrlConfiguration;
        return initWithOptions(allocator, io, .{
            .base_url = urls[0],
            .fallback_urls = urls[1..],
        });
    }

    pub fn initWithFallbacks(
        allocator: Allocator,
        io: Io,
        base_url: []const u8,
        fallback_urls: []const []const u8,
    ) !BeaconApiClient {
        return initWithOptions(allocator, io, .{
            .base_url = base_url,
            .fallback_urls = fallback_urls,
        });
    }

    pub fn initWithOptions(
        allocator: Allocator,
        io: Io,
        options: Options,
    ) !BeaconApiClient {
        const total_urls = 1 + options.fallback_urls.len;
        const url_scores = try allocator.alloc(u8, total_urls);
        @memset(url_scores, URL_SCORE_MAX);

        var client: BeaconApiClient = .{
            .allocator = allocator,
            .io = io,
            .http_client = .{ .allocator = allocator, .io = io },
            .sse_client = .{ .allocator = allocator, .io = io },
            .base_url = options.base_url,
            .fallback_urls = options.fallback_urls,
            .url_scores = url_scores,
            .active_url_idx = 0,
            .consecutive_failures = 0,
            .was_unreachable = false,
            .unreachable_since_ns = 0,
            .request_timeout_ms = options.request_timeout_ms,
            .metrics = options.metrics,
            .state_mutex = .init,
        };
        client.publishAllUrlScores();
        return client;
    }

    pub fn deinit(self: *BeaconApiClient) void {
        self.http_client.deinit();
        self.sse_client.deinit();
        self.allocator.free(self.url_scores);
    }

    /// Return the currently active beacon node URL.
    fn totalUrlCount(self: *const BeaconApiClient) usize {
        return 1 + self.fallback_urls.len;
    }

    fn urlAtIndex(self: *const BeaconApiClient, url_idx: usize) []const u8 {
        if (url_idx == 0) return self.base_url;
        const idx = url_idx - 1;
        if (idx < self.fallback_urls.len) return self.fallback_urls[idx];
        return self.base_url;
    }

    fn activeUrlLocked(self: *const BeaconApiClient) []const u8 {
        return self.urlAtIndex(self.active_url_idx);
    }

    fn activeUrl(self: *BeaconApiClient) []const u8 {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.activeUrlLocked();
    }

    fn activeUrlIndex(self: *BeaconApiClient) usize {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        if (self.url_scores[self.active_url_idx] == URL_SCORE_MIN) {
            self.active_url_idx = self.bestScoredUrlLocked();
        }
        return self.active_url_idx;
    }

    pub fn failoverStatus(self: *BeaconApiClient) FailoverStatus {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return .{
            .configured = self.fallback_urls.len > 0,
            .connected = self.active_url_idx > 0,
        };
    }

    pub fn primaryUrlUnhealthy(self: *BeaconApiClient) bool {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        return self.url_scores[0] == URL_SCORE_MIN;
    }

    fn bestScoredUrlLocked(self: *const BeaconApiClient) usize {
        var best_idx: usize = self.active_url_idx;
        var best_score = self.url_scores[best_idx];
        for (self.url_scores, 0..) |score, idx| {
            if (score > best_score or (score == best_score and idx < best_idx)) {
                best_idx = idx;
                best_score = score;
            }
        }
        return best_idx;
    }

    fn updateUrlScoreMetrics(self: *BeaconApiClient, url_idx: usize) void {
        if (self.metrics) |metrics| {
            metrics.setRestApiUrlScore(url_idx, self.urlAtIndex(url_idx), self.url_scores[url_idx]);
        }
    }

    fn publishAllUrlScores(self: *BeaconApiClient) void {
        if (self.metrics == null) return;
        for (self.url_scores, 0..) |_, idx| {
            self.updateUrlScoreMetrics(idx);
        }
    }

    fn recordRequestErrorMetric(self: *BeaconApiClient, route_id: []const u8, base_url: []const u8) void {
        if (self.metrics) |metrics| {
            metrics.recordRestApiError(route_id, base_url);
        }
    }

    fn recordFallbackMetric(self: *BeaconApiClient, route_id: []const u8, base_url: []const u8) void {
        if (self.metrics) |metrics| {
            metrics.recordRestApiFallback(route_id, base_url);
        }
    }

    /// Record a transport/HTTP failure. Rotates to next BN URL after threshold.
    fn recordFailure(self: *BeaconApiClient, io: Io, failed_url_idx: usize) void {
        const LogState = struct {
            active_url: []const u8,
            consecutive_failures: u64,
            unreachable_secs: ?u64 = null,
        };

        var log_state: ?LogState = null;
        {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);

            self.url_scores[failed_url_idx] = self.url_scores[failed_url_idx] -| URL_SCORE_DELTA_ERROR;
            self.updateUrlScoreMetrics(failed_url_idx);

            if (failed_url_idx != self.active_url_idx) return;

            self.consecutive_failures += 1;
            if (self.consecutive_failures >= BN_UNREACHABLE_THRESHOLD) {
                log_state = .{
                    .active_url = self.activeUrlLocked(),
                    .consecutive_failures = self.consecutive_failures,
                };
                if (!self.was_unreachable) {
                    self.was_unreachable = true;
                    self.unreachable_since_ns = time.awakeNanoseconds(io);
                } else {
                    const now_ns = time.awakeNanoseconds(io);
                    log_state.?.unreachable_secs = (now_ns -| self.unreachable_since_ns) / std.time.ns_per_s;
                }
            }
        }

        if (log_state) |state| {
            if (state.unreachable_secs) |secs| {
                log.warn("beacon node unreachable for {d}s url={s}", .{ secs, state.active_url });
            } else {
                log.warn("beacon node unreachable url={s} (consecutive_failures={d})", .{
                    state.active_url,
                    state.consecutive_failures,
                });
            }
        }
    }

    /// Record a successful HTTP call. Clears failure state.
    fn recordSuccessAt(self: *BeaconApiClient, successful_url_idx: usize) void {
        var reconnected_url: ?[]const u8 = null;
        var switched_url: ?[]const u8 = null;
        {
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);

            self.url_scores[successful_url_idx] = @min(URL_SCORE_MAX, self.url_scores[successful_url_idx] + URL_SCORE_DELTA_SUCCESS);
            self.updateUrlScoreMetrics(successful_url_idx);

            if (self.active_url_idx != successful_url_idx) {
                self.active_url_idx = successful_url_idx;
                switched_url = self.activeUrlLocked();
            }
            if (self.was_unreachable) {
                reconnected_url = self.activeUrlLocked();
                self.was_unreachable = false;
                self.unreachable_since_ns = 0;
            }
            self.consecutive_failures = 0;
        }
        if (switched_url) |url| {
            log.info("switching active beacon node url={s}", .{url});
        }
        if (reconnected_url) |url| {
            log.info("beacon node reconnected url={s}", .{url});
        }
    }

    const TimedTaskResult = union(enum) {
        success: []const u8,
        success_ssz: SszGetResponse,
        success_void,
        failure: anyerror,
        canceled,
    };

    const RequestOp = union(enum) {
        get: struct {
            route_id: []const u8,
            path: []const u8,
        },
        get_ssz: struct {
            route_id: []const u8,
            path: []const u8,
        },
        post: struct {
            route_id: []const u8,
            path: []const u8,
            body: []const u8,
        },
        post_ssz: struct {
            route_id: []const u8,
            path: []const u8,
            body: []const u8,
            fork_name: []const u8,
        },
    };

    const TimerResult = enum {
        fired,
        canceled,
    };

    const RequestRaceCompletion = struct {
        url_idx: usize,
        result: TimedTaskResult,
    };

    const RequestRaceEvent = union(enum) {
        request: RequestRaceCompletion,
        timeout: TimerResult,
    };

    const RequestRaceTaskContext = struct {
        client: *BeaconApiClient,
        io: Io,
        url_idx: usize,
        base_url: []const u8,
        op: RequestOp,

        fn run(ctx: @This()) RequestRaceCompletion {
            return .{
                .url_idx = ctx.url_idx,
                .result = ctx.client.runRequestOp(ctx.io, ctx.base_url, ctx.op),
            };
        }
    };

    const SseConnection = struct {
        url_idx: usize,
        req: std.http.Client.Request,
        response: std.http.Client.Response,
    };

    const SseConnectResult = union(enum) {
        success: SseConnection,
        failure: anyerror,
        canceled,
    };

    const SseConnectCompletion = struct {
        url_idx: usize,
        result: SseConnectResult,
    };

    const SseConnectEvent = union(enum) {
        connect: SseConnectCompletion,
        timeout: TimerResult,
    };

    const SseConnectTaskContext = struct {
        client: *BeaconApiClient,
        io: Io,
        url_idx: usize,
        path: []const u8,

        fn run(ctx: @This()) SseConnectCompletion {
            return .{
                .url_idx = ctx.url_idx,
                .result = ctx.client.connectSseOnUrl(ctx.io, ctx.url_idx, ctx.path),
            };
        }
    };

    fn timeoutFromMs(timeout_ms: u64) Io.Timeout {
        return .{ .duration = .{
            .raw = Io.Duration.fromNanoseconds(@intCast(timeout_ms * std.time.ns_per_ms)),
            .clock = .awake,
        } };
    }

    fn requestDeadlineNs(io: Io, timeout_ms: u64) u64 {
        return time.awakeNanoseconds(io) +| (timeout_ms * std.time.ns_per_ms);
    }

    fn remainingTimeoutMs(io: Io, deadline_ns: u64) !u64 {
        const now_ns = time.awakeNanoseconds(io);
        const remaining_ns = deadline_ns -| now_ns;
        if (remaining_ns == 0) return error.Timeout;
        return @max(1, @as(u64, @intCast((remaining_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms)));
    }

    fn waitTimeout(io: Io, timeout: Io.Timeout) TimerResult {
        timeout.sleep(io) catch |err| switch (err) {
            error.Canceled => return .canceled,
        };
        return .fired;
    }

    fn freeTimedTaskResult(self: *BeaconApiClient, result: TimedTaskResult) void {
        switch (result) {
            .success => |body| self.allocator.free(body),
            .success_ssz => |response| self.allocator.free(response.body),
            else => {},
        }
    }

    fn freeRequestRaceEvent(self: *BeaconApiClient, event: RequestRaceEvent) void {
        switch (event) {
            .request => |completion| self.freeTimedTaskResult(completion.result),
            .timeout => {},
        }
    }

    fn requestOpRouteId(op: RequestOp) []const u8 {
        return switch (op) {
            .get => |request| request.route_id,
            .get_ssz => |request| request.route_id,
            .post => |request| request.route_id,
            .post_ssz => |request| request.route_id,
        };
    }

    fn runRequestOp(
        self: *BeaconApiClient,
        io: Io,
        base_url: []const u8,
        op: RequestOp,
    ) TimedTaskResult {
        return switch (op) {
            .get => |request| blk: {
                const body = self.getBlocking(io, request.route_id, base_url, request.path) catch |err| switch (err) {
                    error.Canceled => break :blk .canceled,
                    else => break :blk .{ .failure = err },
                };
                break :blk .{ .success = body };
            },
            .get_ssz => |request| blk: {
                const response = self.getSszBlocking(io, request.route_id, base_url, request.path) catch |err| switch (err) {
                    error.Canceled => break :blk .canceled,
                    else => break :blk .{ .failure = err },
                };
                break :blk .{ .success_ssz = response };
            },
            .post => |request| blk: {
                const body = self.postBlocking(io, request.route_id, base_url, request.path, request.body) catch |err| switch (err) {
                    error.Canceled => break :blk .canceled,
                    else => break :blk .{ .failure = err },
                };
                break :blk .{ .success = body };
            },
            .post_ssz => |request| blk: {
                self.postSszBlocking(io, request.route_id, base_url, request.path, request.body, request.fork_name) catch |err| switch (err) {
                    error.Canceled => break :blk .canceled,
                    else => break :blk .{ .failure = err },
                };
                break :blk .success_void;
            },
        };
    }

    fn fillRaceGroup(
        self: *BeaconApiClient,
        start_idx: usize,
        start_offset: usize,
        out: []usize,
    ) usize {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);

        const total_urls = self.totalUrlCount();
        std.debug.assert(start_offset < total_urls);
        std.debug.assert(out.len >= total_urls - start_offset);

        var count: usize = 0;
        var offset = start_offset;
        while (offset < total_urls) : (offset += 1) {
            const url_idx = (start_idx + offset) % total_urls;
            out[count] = url_idx;
            count += 1;

            if (self.url_scores[url_idx] >= URL_SCORE_MAX) break;
        }

        return count;
    }

    fn runRequestRaceGroup(
        self: *BeaconApiClient,
        io: Io,
        timeout_ms: u64,
        url_indices: []const usize,
        op: RequestOp,
    ) !RequestRaceCompletion {
        var stack_events: [9]RequestRaceEvent = undefined;
        const needed_events = url_indices.len + 1;
        const using_heap_events = needed_events > stack_events.len;
        const events_buf = if (!using_heap_events)
            stack_events[0..needed_events]
        else
            try self.allocator.alloc(RequestRaceEvent, needed_events);
        defer if (using_heap_events) self.allocator.free(events_buf);

        var stack_observed: [8]bool = undefined;
        const using_heap_observed = url_indices.len > stack_observed.len;
        const observed = if (!using_heap_observed)
            stack_observed[0..url_indices.len]
        else
            try self.allocator.alloc(bool, url_indices.len);
        defer if (using_heap_observed) self.allocator.free(observed);
        @memset(observed, false);

        var select = Io.Select(RequestRaceEvent).init(io, events_buf);
        errdefer while (select.cancel()) |event| {
            self.freeRequestRaceEvent(event);
        };

        for (url_indices) |url_idx| {
            try select.concurrent(.request, RequestRaceTaskContext.run, .{.{
                .client = self,
                .io = io,
                .url_idx = url_idx,
                .base_url = self.urlAtIndex(url_idx),
                .op = op,
            }});
        }
        select.async(.timeout, waitTimeout, .{ io, timeoutFromMs(timeout_ms) });

        var completed_count: usize = 0;
        var last_err: anyerror = error.HttpError;
        while (completed_count < url_indices.len) {
            const event = try select.await();
            switch (event) {
                .request => |completion| {
                    const observed_idx = std.mem.indexOfScalar(usize, url_indices, completion.url_idx) orelse unreachable;
                    observed[observed_idx] = true;
                    switch (completion.result) {
                        .success, .success_ssz, .success_void => {
                            while (select.cancel()) |remaining| {
                                self.freeRequestRaceEvent(remaining);
                            }
                            return completion;
                        },
                        .failure => |err| {
                            self.recordFailure(io, completion.url_idx);
                            last_err = err;
                            completed_count += 1;
                        },
                        .canceled => {
                            while (select.cancel()) |remaining| {
                                self.freeRequestRaceEvent(remaining);
                            }
                            return error.Canceled;
                        },
                    }
                },
                .timeout => |result| {
                    if (result != .fired) continue;

                    for (url_indices, observed) |url_idx, did_finish| {
                        if (!did_finish) self.recordFailure(io, url_idx);
                    }
                    while (select.cancel()) |remaining| {
                        self.freeRequestRaceEvent(remaining);
                    }
                    return error.Timeout;
                },
            }
        }

        while (select.cancel()) |event| {
            self.freeRequestRaceEvent(event);
        }

        return last_err;
    }

    fn executeRequestWithFallbacks(
        self: *BeaconApiClient,
        io: Io,
        timeout_ms: u64,
        op: RequestOp,
    ) !TimedTaskResult {
        const start_idx = self.activeUrlIndex();
        const total_urls = self.totalUrlCount();
        const deadline_ns = requestDeadlineNs(io, timeout_ms);
        var last_err: anyerror = error.HttpError;
        var attempted_any = false;
        var next_offset: usize = 0;

        var stack_group: [8]usize = undefined;
        const using_heap_group = total_urls > stack_group.len;
        const group_buf = if (!using_heap_group)
            stack_group[0..total_urls]
        else
            try self.allocator.alloc(usize, total_urls);
        defer if (using_heap_group) self.allocator.free(group_buf);

        while (next_offset < total_urls) {
            const attempt_timeout_ms = remainingTimeoutMs(io, deadline_ns) catch |err| {
                return if (attempted_any) last_err else err;
            };

            const group_len = self.fillRaceGroup(start_idx, next_offset, group_buf);
            const group = group_buf[0..group_len];
            for (group, 0..) |url_idx, idx| {
                if (next_offset + idx > 0) self.recordFallbackMetric(requestOpRouteId(op), self.urlAtIndex(url_idx));
            }

            const completion = self.runRequestRaceGroup(io, attempt_timeout_ms, group, op) catch |err| {
                if (err == error.Canceled) return err;
                attempted_any = true;
                last_err = err;
                next_offset += group_len;
                continue;
            };

            self.recordSuccessAt(completion.url_idx);
            return completion.result;
        }

        return last_err;
    }

    fn freeSseConnection(stream: *SseConnection) void {
        stream.req.deinit();
        stream.* = undefined;
    }

    fn freeSseConnectEvent(_: *BeaconApiClient, event: SseConnectEvent) void {
        switch (event) {
            .connect => |completion| switch (completion.result) {
                .success => |stream| {
                    var owned_stream = stream;
                    freeSseConnection(&owned_stream);
                },
                else => {},
            },
            .timeout => {},
        }
    }

    fn connectSseOnUrl(
        self: *BeaconApiClient,
        io: Io,
        url_idx: usize,
        path: []const u8,
    ) SseConnectResult {
        const base_url = self.urlAtIndex(url_idx);
        const request_started_ns = time.awakeNanoseconds(io);
        defer self.observeRequestDuration(route_ids.events_eventstream, request_started_ns);

        const url = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base_url, path }) catch |err| {
            self.recordRequestErrorMetric(route_ids.events_eventstream, base_url);
            return .{ .failure = err };
        };
        defer self.allocator.free(url);

        const uri = std.Uri.parse(url) catch |err| {
            self.recordRequestErrorMetric(route_ids.events_eventstream, base_url);
            return .{ .failure = err };
        };

        var req = self.sse_client.request(.GET, uri, .{
            .keep_alive = true,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "text/event-stream" },
                .{ .name = "Cache-Control", .value = "no-cache" },
            },
        }) catch |err| {
            self.recordRequestErrorMetric(route_ids.events_eventstream, base_url);
            return .{ .failure = err };
        };
        errdefer req.deinit();

        req.sendBodiless() catch |err| {
            self.recordRequestErrorMetric(route_ids.events_eventstream, base_url);
            return .{ .failure = err };
        };

        var redirect_buf: [1024]u8 = undefined;
        const response = req.receiveHead(&redirect_buf) catch |err| {
            self.recordRequestErrorMetric(route_ids.events_eventstream, base_url);
            return .{ .failure = err };
        };

        if (response.head.status != .ok) {
            log.err("SSE subscription failed: HTTP {d}", .{@intFromEnum(response.head.status)});
            self.recordRequestErrorMetric(route_ids.events_eventstream, base_url);
            return .{ .failure = error.HttpError };
        }

        return .{ .success = .{
            .url_idx = url_idx,
            .req = req,
            .response = response,
        } };
    }

    fn runSseConnectRaceGroup(
        self: *BeaconApiClient,
        io: Io,
        timeout_ms: u64,
        url_indices: []const usize,
        path: []const u8,
    ) !SseConnection {
        var stack_events: [9]SseConnectEvent = undefined;
        const needed_events = url_indices.len + 1;
        const using_heap_events = needed_events > stack_events.len;
        const events_buf = if (!using_heap_events)
            stack_events[0..needed_events]
        else
            try self.allocator.alloc(SseConnectEvent, needed_events);
        defer if (using_heap_events) self.allocator.free(events_buf);

        var stack_observed: [8]bool = undefined;
        const using_heap_observed = url_indices.len > stack_observed.len;
        const observed = if (!using_heap_observed)
            stack_observed[0..url_indices.len]
        else
            try self.allocator.alloc(bool, url_indices.len);
        defer if (using_heap_observed) self.allocator.free(observed);
        @memset(observed, false);

        var select = Io.Select(SseConnectEvent).init(io, events_buf);
        errdefer while (select.cancel()) |event| {
            self.freeSseConnectEvent(event);
        };

        for (url_indices) |url_idx| {
            try select.concurrent(.connect, SseConnectTaskContext.run, .{.{
                .client = self,
                .io = io,
                .url_idx = url_idx,
                .path = path,
            }});
        }
        select.async(.timeout, waitTimeout, .{ io, timeoutFromMs(timeout_ms) });

        var completed_count: usize = 0;
        var last_err: anyerror = error.StreamEnded;
        while (completed_count < url_indices.len) {
            const event = try select.await();
            switch (event) {
                .connect => |completion| {
                    const observed_idx = std.mem.indexOfScalar(usize, url_indices, completion.url_idx) orelse unreachable;
                    observed[observed_idx] = true;
                    switch (completion.result) {
                        .success => |stream| {
                            while (select.cancel()) |remaining| {
                                self.freeSseConnectEvent(remaining);
                            }
                            return stream;
                        },
                        .failure => |err| {
                            self.recordFailure(io, completion.url_idx);
                            last_err = err;
                            completed_count += 1;
                        },
                        .canceled => {
                            while (select.cancel()) |remaining| {
                                self.freeSseConnectEvent(remaining);
                            }
                            return error.Canceled;
                        },
                    }
                },
                .timeout => |result| {
                    if (result != .fired) continue;

                    for (url_indices, observed) |url_idx, did_finish| {
                        if (!did_finish) self.recordFailure(io, url_idx);
                    }
                    while (select.cancel()) |remaining| {
                        self.freeSseConnectEvent(remaining);
                    }
                    return error.Timeout;
                },
            }
        }

        while (select.cancel()) |event| {
            self.freeSseConnectEvent(event);
        }

        return last_err;
    }

    fn connectSseWithFallbacks(
        self: *BeaconApiClient,
        io: Io,
        path: []const u8,
    ) !SseConnection {
        const start_idx = self.activeUrlIndex();
        const total_urls = self.totalUrlCount();
        const deadline_ns = requestDeadlineNs(io, self.request_timeout_ms);
        var last_err: anyerror = error.StreamEnded;
        var attempted_any = false;
        var next_offset: usize = 0;

        var stack_group: [8]usize = undefined;
        const using_heap_group = total_urls > stack_group.len;
        const group_buf = if (!using_heap_group)
            stack_group[0..total_urls]
        else
            try self.allocator.alloc(usize, total_urls);
        defer if (using_heap_group) self.allocator.free(group_buf);

        while (next_offset < total_urls) {
            const attempt_timeout_ms = remainingTimeoutMs(io, deadline_ns) catch |err| {
                return if (attempted_any) last_err else err;
            };

            const group_len = self.fillRaceGroup(start_idx, next_offset, group_buf);
            const group = group_buf[0..group_len];
            for (group, 0..) |url_idx, idx| {
                if (next_offset + idx > 0) self.recordFallbackMetric(route_ids.events_eventstream, self.urlAtIndex(url_idx));
            }

            const stream = self.runSseConnectRaceGroup(io, attempt_timeout_ms, group, path) catch |err| {
                if (err == error.Canceled) return err;
                attempted_any = true;
                last_err = err;
                next_offset += group_len;
                continue;
            };

            self.recordSuccessAt(stream.url_idx);
            return stream;
        }

        return last_err;
    }

    fn processConnectedSseStream(
        self: *BeaconApiClient,
        io: Io,
        stream: *SseConnection,
        callback: SseCallback,
    ) !void {
        defer freeSseConnection(stream);
        log.info("subscribing to SSE events url={s}", .{self.urlAtIndex(stream.url_idx)});

        const stream_started_ns = time.awakeNanoseconds(io);
        defer self.observeStreamDuration(route_ids.events_eventstream, io, stream_started_ns);

        var event_type_buf: [128]u8 = undefined;
        var event_type: []const u8 = "";
        var data_buf: [SSE_LINE_BUF]u8 = undefined;
        var data_len: usize = 0;

        var transfer_buf: [SSE_LINE_BUF]u8 = undefined;
        const reader = stream.response.reader(&transfer_buf);

        while (true) {
            const line = reader.*.takeDelimiterExclusive('\n') catch |err| switch (err) {
                error.EndOfStream => {
                    self.recordRequestErrorMetric(route_ids.events_eventstream, self.urlAtIndex(stream.url_idx));
                    self.recordFailure(io, stream.url_idx);
                    return error.StreamEnded;
                },
                else => {
                    self.recordRequestErrorMetric(route_ids.events_eventstream, self.urlAtIndex(stream.url_idx));
                    self.recordFailure(io, stream.url_idx);
                    return err;
                },
            };

            const trimmed = if (line.len > 0 and line[line.len - 1] == '\r') line[0 .. line.len - 1] else line;

            if (trimmed.len == 0) {
                if (data_len > 0 and event_type.len > 0) {
                    callback.call(.{
                        .event_type = event_type,
                        .data = data_buf[0..data_len],
                    });
                }
                event_type = "";
                data_len = 0;
                continue;
            }

            if (std.mem.startsWith(u8, trimmed, "event:")) {
                var val = trimmed["event:".len..];
                if (val.len > 0 and val[0] == ' ') val = val[1..];
                const n = @min(val.len, event_type_buf.len);
                @memcpy(event_type_buf[0..n], val[0..n]);
                event_type = event_type_buf[0..n];
            } else if (std.mem.startsWith(u8, trimmed, "data:")) {
                var val = trimmed["data:".len..];
                if (val.len > 0 and val[0] == ' ') val = val[1..];
                if (data_len != 0 and data_len < data_buf.len) {
                    data_buf[data_len] = '\n';
                    data_len += 1;
                }
                const copy_len = @min(val.len, data_buf.len - data_len);
                if (copy_len > 0) {
                    @memcpy(data_buf[data_len .. data_len + copy_len], val[0..copy_len]);
                    data_len += copy_len;
                }
            }
        }
    }

    fn observeRequestDuration(self: *BeaconApiClient, route_id: []const u8, started_ns: u64) void {
        if (self.metrics) |metrics| {
            metrics.observeRestApiRequest(route_id, nsToSeconds(time.awakeNanoseconds(self.http_client.io) -| started_ns));
        }
    }

    fn observeStreamDuration(self: *BeaconApiClient, route_id: []const u8, io: Io, started_ns: u64) void {
        if (self.metrics) |metrics| {
            metrics.observeRestApiStream(route_id, nsToSeconds(time.awakeNanoseconds(io) -| started_ns));
        }
    }

    fn nsToSeconds(ns: u64) f64 {
        return @as(f64, @floatFromInt(ns)) / @as(f64, std.time.ns_per_s);
    }

    // -----------------------------------------------------------------------
    // Internal HTTP helpers
    // -----------------------------------------------------------------------

    /// Perform a GET request and return the response body (caller frees).
    ///
    fn get(self: *BeaconApiClient, io: Io, route_id: []const u8, path: []const u8) ![]const u8 {
        return self.getWithTimeout(io, route_id, path, self.request_timeout_ms);
    }

    fn getWithTimeout(self: *BeaconApiClient, io: Io, route_id: []const u8, path: []const u8, timeout_ms: u64) ![]const u8 {
        const result = try self.executeRequestWithFallbacks(io, timeout_ms, .{ .get = .{
            .route_id = route_id,
            .path = path,
        } });
        return switch (result) {
            .success => |body| body,
            .canceled => error.Canceled,
            .failure => |err| err,
            else => unreachable,
        };
    }

    fn getBlocking(self: *BeaconApiClient, _: Io, route_id: []const u8, base_url: []const u8, path: []const u8) ![]const u8 {
        const started_ns = time.awakeNanoseconds(self.http_client.io);
        defer self.observeRequestDuration(route_id, started_ns);
        errdefer self.recordRequestErrorMetric(route_id, base_url);

        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base_url, path });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = self.http_client.request(.GET, uri, .{
            .keep_alive = true,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
        }) catch |err| {
            return err;
        };
        defer req.deinit();

        req.sendBodiless() catch |err| {
            return err;
        };

        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            return err;
        };

        if (response.head.status != .ok) {
            log.warn("GET {s} → HTTP {d}", .{ path, @intFromEnum(response.head.status) });
            return error.HttpError;
        }
        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        return reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
    }

    /// Perform a GET request with Accept: application/octet-stream.
    /// Returns the raw SSZ bytes and parsed response headers.
    /// Caller must free the returned SszGetResponse.body.
    fn getSsz(self: *BeaconApiClient, io: Io, route_id: []const u8, path: []const u8) !SszGetResponse {
        const result = try self.executeRequestWithFallbacks(io, self.request_timeout_ms, .{ .get_ssz = .{
            .route_id = route_id,
            .path = path,
        } });
        return switch (result) {
            .success_ssz => |response| response,
            .canceled => error.Canceled,
            .failure => |err| err,
            else => unreachable,
        };
    }

    fn getSszBlocking(self: *BeaconApiClient, _: Io, route_id: []const u8, base_url: []const u8, path: []const u8) !SszGetResponse {
        const started_ns = time.awakeNanoseconds(self.http_client.io);
        defer self.observeRequestDuration(route_id, started_ns);
        errdefer self.recordRequestErrorMetric(route_id, base_url);

        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base_url, path });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = self.http_client.request(.GET, uri, .{
            .keep_alive = true,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/octet-stream" },
            },
        }) catch |err| {
            return err;
        };
        defer req.deinit();

        req.sendBodiless() catch |err| {
            return err;
        };

        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            return err;
        };

        if (response.head.status != .ok) {
            log.warn("GET(ssz) {s} → HTTP {d}", .{ path, @intFromEnum(response.head.status) });
            return error.HttpError;
        }

        // Extract Eth-Consensus-Version header before reading body
        // (response.reader() invalidates head string pointers).
        var fork_name_buf: [32]u8 = [_]u8{0} ** 32;
        var fork_name_len: u8 = 0;
        var is_blinded = false;
        var execution_payload_source: types.ExecutionPayloadSource = .engine;
        {
            var it = response.head.iterateHeaders();
            while (it.next()) |hdr| {
                if (std.ascii.eqlIgnoreCase(hdr.name, "Eth-Consensus-Version")) {
                    const len: u8 = @intCast(@min(hdr.value.len, fork_name_buf.len));
                    @memcpy(fork_name_buf[0..len], hdr.value[0..len]);
                    fork_name_len = len;
                } else if (std.ascii.eqlIgnoreCase(hdr.name, "Eth-Execution-Payload-Blinded")) {
                    is_blinded = std.mem.eql(u8, hdr.value, "true");
                } else if (std.ascii.eqlIgnoreCase(hdr.name, "Eth-Execution-Payload-Source")) {
                    execution_payload_source = types.ExecutionPayloadSource.parse(hdr.value) catch return error.InvalidResponse;
                }
            }
        }

        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        const ssz_body = reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };

        return .{
            .body = ssz_body,
            .fork_name = fork_name_buf,
            .fork_name_len = fork_name_len,
            .is_blinded = is_blinded,
            .execution_payload_source = execution_payload_source,
        };
    }

    /// Perform a POST request with JSON body and return the response body (caller frees).
    ///
    /// Pass an empty body (`""`) for POST endpoints that don't require a body.
    fn post(self: *BeaconApiClient, io: Io, route_id: []const u8, path: []const u8, body: []const u8) ![]const u8 {
        const result = try self.executeRequestWithFallbacks(io, self.request_timeout_ms, .{
            .post = .{ .route_id = route_id, .path = path, .body = body },
        });
        return switch (result) {
            .success => |response| response,
            .canceled => error.Canceled,
            .failure => |err| err,
            else => unreachable,
        };
    }

    fn postBlocking(self: *BeaconApiClient, _: Io, route_id: []const u8, base_url: []const u8, path: []const u8, body: []const u8) ![]const u8 {
        const started_ns = time.awakeNanoseconds(self.http_client.io);
        defer self.observeRequestDuration(route_id, started_ns);
        errdefer self.recordRequestErrorMetric(route_id, base_url);

        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base_url, path });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = self.http_client.request(.POST, uri, .{
            .keep_alive = true,
            .extra_headers = &.{
                .{ .name = "Accept", .value = "application/json" },
            },
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
        }) catch |err| {
            return err;
        };
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = body.len };
        req.sendBodyComplete(@constCast(body)) catch |err| {
            return err;
        };

        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            return err;
        };

        const status = response.head.status;
        // 2xx codes are all success; 204 has no body.
        if (@intFromEnum(status) < 200 or @intFromEnum(status) >= 300) {
            log.warn("POST {s} → HTTP {d}", .{ path, @intFromEnum(status) });
            return error.HttpError;
        }
        if (status == .no_content) {
            // 204 No Content — return empty slice.
            return try self.allocator.dupe(u8, "");
        }

        var transfer_buf: [8192]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        return reader.allocRemaining(self.allocator, Io.Limit.limited(MAX_RESPONSE_BYTES)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
    }

    /// Perform a POST with no response body required (fire-and-forget).
    fn postNoResponse(self: *BeaconApiClient, io: Io, route_id: []const u8, path: []const u8, body: []const u8) !void {
        const resp = try self.post(io, route_id, path, body);
        self.allocator.free(resp);
    }

    /// Perform a POST request with SSZ body (Content-Type: application/octet-stream).
    /// The Eth-Consensus-Version header is included for fork context.
    /// Returns void on success; errors on non-2xx status.
    fn postSsz(self: *BeaconApiClient, io: Io, route_id: []const u8, path: []const u8, body: []const u8, fork_name: []const u8) !void {
        const result = try self.executeRequestWithFallbacks(io, self.request_timeout_ms, .{
            .post_ssz = .{
                .route_id = route_id,
                .path = path,
                .body = body,
                .fork_name = fork_name,
            },
        });
        return switch (result) {
            .success_void => {},
            .canceled => error.Canceled,
            .failure => |err| err,
            else => unreachable,
        };
    }

    fn postSszBlocking(self: *BeaconApiClient, _: Io, route_id: []const u8, base_url: []const u8, path: []const u8, body: []const u8, fork_name: []const u8) !void {
        const started_ns = time.awakeNanoseconds(self.http_client.io);
        defer self.observeRequestDuration(route_id, started_ns);
        errdefer self.recordRequestErrorMetric(route_id, base_url);

        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base_url, path });
        defer self.allocator.free(url);

        const uri = try std.Uri.parse(url);
        var req = self.http_client.request(.POST, uri, .{
            .keep_alive = true,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/octet-stream" },
                .{ .name = "Eth-Consensus-Version", .value = fork_name },
            },
        }) catch |err| {
            return err;
        };
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = body.len };
        req.sendBodyComplete(@constCast(body)) catch |err| {
            return err;
        };

        var redirect_buf: [1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| {
            return err;
        };

        const status = response.head.status;
        if (@intFromEnum(status) < 200 or @intFromEnum(status) >= 300) {
            log.warn("POST(ssz) {s} → HTTP {d}", .{ path, @intFromEnum(status) });
            return error.HttpError;
        }
        if (status != .no_content) {
            var transfer_buf: [1024]u8 = undefined;
            const reader = response.reader(&transfer_buf);
            _ = reader.discardRemaining() catch |err| switch (err) {
                error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
                else => |e| return e,
            };
        }
    }

    // -----------------------------------------------------------------------
    // Genesis
    // -----------------------------------------------------------------------

    /// GET /eth/v1/beacon/genesis
    pub fn getGenesis(self: *BeaconApiClient, io: Io) !GenesisResponse {
        const body = try self.get(io, route_ids.beacon_get_genesis, "/eth/v1/beacon/genesis");
        defer self.allocator.free(body);

        const Parsed = struct {
            data: struct {
                genesis_time: []const u8,
                genesis_validators_root: []const u8,
                genesis_fork_version: []const u8,
            },
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const d = parsed.value.data;
        const genesis_time = try std.fmt.parseInt(u64, d.genesis_time, 10);

        var genesis_validators_root: [32]u8 = [_]u8{0} ** 32;
        const gvr_hex = if (std.mem.startsWith(u8, d.genesis_validators_root, "0x")) d.genesis_validators_root[2..] else d.genesis_validators_root;
        _ = std.fmt.hexToBytes(&genesis_validators_root, gvr_hex) catch {};

        var genesis_fork_version: [4]u8 = [_]u8{0} ** 4;
        const gfv_hex = if (std.mem.startsWith(u8, d.genesis_fork_version, "0x")) d.genesis_fork_version[2..] else d.genesis_fork_version;
        _ = std.fmt.hexToBytes(&genesis_fork_version, gfv_hex) catch {};

        return .{
            .genesis_time = genesis_time,
            .genesis_validators_root = genesis_validators_root,
            .genesis_fork_version = genesis_fork_version,
        };
    }

    /// GET /eth/v1/config/spec
    ///
    /// Parses a compatibility subset of the beacon node's config/spec response.
    /// Different clients expose different key casing and may omit fields, so we
    /// accept either snake_case or SCREAMING_SNAKE_CASE and only compare fields
    /// that are present.
    pub fn getConfigSpec(self: *BeaconApiClient, io: Io) !ConfigSpecResponse {
        const body = try self.get(io, route_ids.config_get_spec, "/eth/v1/config/spec");
        defer self.allocator.free(body);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, body, .{});
        defer parsed.deinit();

        const root = switch (parsed.value) {
            .object => |obj| obj,
            else => return error.InvalidResponse,
        };
        const data_val = root.get("data") orelse return error.InvalidResponse;
        const data = switch (data_val) {
            .object => |obj| obj,
            else => return error.InvalidResponse,
        };

        return .{
            .min_genesis_active_validator_count = try parseUintField(data, &.{ "min_genesis_active_validator_count", "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT" }),
            .min_genesis_time = try parseUintField(data, &.{ "min_genesis_time", "MIN_GENESIS_TIME" }),
            .genesis_delay = try parseUintField(data, &.{ "genesis_delay", "GENESIS_DELAY" }),
            .genesis_fork_version = try parseHexField(data, &.{ "genesis_fork_version", "GENESIS_FORK_VERSION" }, 4),
            .altair_fork_version = try parseHexField(data, &.{ "altair_fork_version", "ALTAIR_FORK_VERSION" }, 4),
            .altair_fork_epoch = try parseUintField(data, &.{ "altair_fork_epoch", "ALTAIR_FORK_EPOCH" }),
            .bellatrix_fork_version = try parseHexField(data, &.{ "bellatrix_fork_version", "BELLATRIX_FORK_VERSION" }, 4),
            .bellatrix_fork_epoch = try parseUintField(data, &.{ "bellatrix_fork_epoch", "BELLATRIX_FORK_EPOCH" }),
            .capella_fork_version = try parseHexField(data, &.{ "capella_fork_version", "CAPELLA_FORK_VERSION" }, 4),
            .capella_fork_epoch = try parseUintField(data, &.{ "capella_fork_epoch", "CAPELLA_FORK_EPOCH" }),
            .deneb_fork_version = try parseHexField(data, &.{ "deneb_fork_version", "DENEB_FORK_VERSION" }, 4),
            .deneb_fork_epoch = try parseUintField(data, &.{ "deneb_fork_epoch", "DENEB_FORK_EPOCH" }),
            .electra_fork_version = try parseHexField(data, &.{ "electra_fork_version", "ELECTRA_FORK_VERSION" }, 4),
            .electra_fork_epoch = try parseUintField(data, &.{ "electra_fork_epoch", "ELECTRA_FORK_EPOCH" }),
            .fulu_fork_version = try parseHexField(data, &.{ "fulu_fork_version", "FULU_FORK_VERSION" }, 4),
            .fulu_fork_epoch = try parseUintField(data, &.{ "fulu_fork_epoch", "FULU_FORK_EPOCH" }),
            .gloas_fork_version = try parseHexField(data, &.{ "gloas_fork_version", "GLOAS_FORK_VERSION" }, 4),
            .gloas_fork_epoch = try parseUintField(data, &.{ "gloas_fork_epoch", "GLOAS_FORK_EPOCH" }),
            .seconds_per_slot = try parseUintField(data, &.{ "seconds_per_slot", "SECONDS_PER_SLOT" }),
            .slot_duration_ms = try parseUintField(data, &.{ "slot_duration_ms", "SLOT_DURATION_MS" }),
            .min_validator_withdrawability_delay = try parseUintField(data, &.{ "min_validator_withdrawability_delay", "MIN_VALIDATOR_WITHDRAWABILITY_DELAY" }),
            .shard_committee_period = try parseUintField(data, &.{ "shard_committee_period", "SHARD_COMMITTEE_PERIOD" }),
            .eth1_follow_distance = try parseUintField(data, &.{ "eth1_follow_distance", "ETH1_FOLLOW_DISTANCE" }),
            .inactivity_score_bias = try parseUintField(data, &.{ "inactivity_score_bias", "INACTIVITY_SCORE_BIAS" }),
            .inactivity_score_recovery_rate = try parseUintField(data, &.{ "inactivity_score_recovery_rate", "INACTIVITY_SCORE_RECOVERY_RATE" }),
            .ejection_balance = try parseUintField(data, &.{ "ejection_balance", "EJECTION_BALANCE" }),
            .min_per_epoch_churn_limit = try parseUintField(data, &.{ "min_per_epoch_churn_limit", "MIN_PER_EPOCH_CHURN_LIMIT" }),
            .max_per_epoch_activation_churn_limit = try parseUintField(data, &.{ "max_per_epoch_activation_churn_limit", "MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT" }),
            .churn_limit_quotient = try parseUintField(data, &.{ "churn_limit_quotient", "CHURN_LIMIT_QUOTIENT" }),
            .proposer_reorg_cutoff_bps = try parseUintField(data, &.{ "proposer_reorg_cutoff_bps", "PROPOSER_REORG_CUTOFF_BPS" }),
            .attestation_due_bps = try parseUintField(data, &.{ "attestation_due_bps", "ATTESTATION_DUE_BPS" }),
            .attestation_due_bps_gloas = try parseUintField(data, &.{ "attestation_due_bps_gloas", "ATTESTATION_DUE_BPS_GLOAS" }),
            .aggregate_due_bps = try parseUintField(data, &.{ "aggregate_due_bps", "AGGREGATE_DUE_BPS" }),
            .aggregate_due_bps_gloas = try parseUintField(data, &.{ "aggregate_due_bps_gloas", "AGGREGATE_DUE_BPS_GLOAS" }),
            .sync_message_due_bps = try parseUintField(data, &.{ "sync_message_due_bps", "SYNC_MESSAGE_DUE_BPS" }),
            .sync_message_due_bps_gloas = try parseUintField(data, &.{ "sync_message_due_bps_gloas", "SYNC_MESSAGE_DUE_BPS_GLOAS" }),
            .contribution_due_bps = try parseUintField(data, &.{ "contribution_due_bps", "CONTRIBUTION_DUE_BPS" }),
            .contribution_due_bps_gloas = try parseUintField(data, &.{ "contribution_due_bps_gloas", "CONTRIBUTION_DUE_BPS_GLOAS" }),
            .deposit_contract_address = try parseHexField(data, &.{ "deposit_contract_address", "DEPOSIT_CONTRACT_ADDRESS" }, 20),
            .blob_sidecar_subnet_count = try parseUintField(data, &.{ "blob_sidecar_subnet_count", "BLOB_SIDECAR_SUBNET_COUNT" }),
            .max_committees_per_slot = try parseUintField(data, &.{ "max_committees_per_slot", "MAX_COMMITTEES_PER_SLOT" }),
            .target_committee_size = try parseUintField(data, &.{ "target_committee_size", "TARGET_COMMITTEE_SIZE" }),
            .max_validators_per_committee = try parseUintField(data, &.{ "max_validators_per_committee", "MAX_VALIDATORS_PER_COMMITTEE" }),
            .max_blobs_per_block = try parseUintField(data, &.{ "max_blobs_per_block", "MAX_BLOBS_PER_BLOCK" }),
            .min_deposit_amount = try parseUintField(data, &.{ "min_deposit_amount", "MIN_DEPOSIT_AMOUNT" }),
            .max_effective_balance = try parseUintField(data, &.{ "max_effective_balance", "MAX_EFFECTIVE_BALANCE" }),
            .effective_balance_increment = try parseUintField(data, &.{ "effective_balance_increment", "EFFECTIVE_BALANCE_INCREMENT" }),
            .min_attestation_inclusion_delay = try parseUintField(data, &.{ "min_attestation_inclusion_delay", "MIN_ATTESTATION_INCLUSION_DELAY" }),
            .slots_per_epoch = try parseUintField(data, &.{ "slots_per_epoch", "SLOTS_PER_EPOCH" }),
            .min_seed_lookahead = try parseUintField(data, &.{ "min_seed_lookahead", "MIN_SEED_LOOKAHEAD" }),
            .max_seed_lookahead = try parseUintField(data, &.{ "max_seed_lookahead", "MAX_SEED_LOOKAHEAD" }),
            .epochs_per_eth1_voting_period = try parseUintField(data, &.{ "epochs_per_eth1_voting_period", "EPOCHS_PER_ETH1_VOTING_PERIOD" }),
            .slots_per_historical_root = try parseUintField(data, &.{ "slots_per_historical_root", "SLOTS_PER_HISTORICAL_ROOT" }),
            .min_epochs_to_inactivity_penalty = try parseUintField(data, &.{ "min_epochs_to_inactivity_penalty", "MIN_EPOCHS_TO_INACTIVITY_PENALTY" }),
            .epochs_per_historical_vector = try parseUintField(data, &.{ "epochs_per_historical_vector", "EPOCHS_PER_HISTORICAL_VECTOR" }),
            .epochs_per_slashings_vector = try parseUintField(data, &.{ "epochs_per_slashings_vector", "EPOCHS_PER_SLASHINGS_VECTOR" }),
            .historical_roots_limit = try parseUintField(data, &.{ "historical_roots_limit", "HISTORICAL_ROOTS_LIMIT" }),
            .validator_registry_limit = try parseUintField(data, &.{ "validator_registry_limit", "VALIDATOR_REGISTRY_LIMIT" }),
            .base_reward_factor = try parseUintField(data, &.{ "base_reward_factor", "BASE_REWARD_FACTOR" }),
            .whistleblower_reward_quotient = try parseUintField(data, &.{ "whistleblower_reward_quotient", "WHISTLEBLOWER_REWARD_QUOTIENT" }),
            .proposer_reward_quotient = try parseUintField(data, &.{ "proposer_reward_quotient", "PROPOSER_REWARD_QUOTIENT" }),
            .inactivity_penalty_quotient = try parseUintField(data, &.{ "inactivity_penalty_quotient", "INACTIVITY_PENALTY_QUOTIENT" }),
            .min_slashing_penalty_quotient = try parseUintField(data, &.{ "min_slashing_penalty_quotient", "MIN_SLASHING_PENALTY_QUOTIENT" }),
            .proportional_slashing_multiplier = try parseUintField(data, &.{ "proportional_slashing_multiplier", "PROPORTIONAL_SLASHING_MULTIPLIER" }),
            .max_proposer_slashings = try parseUintField(data, &.{ "max_proposer_slashings", "MAX_PROPOSER_SLASHINGS" }),
            .max_attester_slashings = try parseUintField(data, &.{ "max_attester_slashings", "MAX_ATTESTER_SLASHINGS" }),
            .max_attestations = try parseUintField(data, &.{ "max_attestations", "MAX_ATTESTATIONS" }),
            .max_deposits = try parseUintField(data, &.{ "max_deposits", "MAX_DEPOSITS" }),
            .max_voluntary_exits = try parseUintField(data, &.{ "max_voluntary_exits", "MAX_VOLUNTARY_EXITS" }),
            .sync_committee_size = try parseUintField(data, &.{ "sync_committee_size", "SYNC_COMMITTEE_SIZE" }),
            .epochs_per_sync_committee_period = try parseUintField(data, &.{ "epochs_per_sync_committee_period", "EPOCHS_PER_SYNC_COMMITTEE_PERIOD" }),
            .inactivity_penalty_quotient_altair = try parseUintField(data, &.{ "inactivity_penalty_quotient_altair", "INACTIVITY_PENALTY_QUOTIENT_ALTAIR" }),
            .min_slashing_penalty_quotient_altair = try parseUintField(data, &.{ "min_slashing_penalty_quotient_altair", "MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR" }),
            .proportional_slashing_multiplier_altair = try parseUintField(data, &.{ "proportional_slashing_multiplier_altair", "PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR" }),
            .blob_sidecar_subnet_count_electra = try parseUintField(data, &.{ "blob_sidecar_subnet_count_electra", "BLOB_SIDECAR_SUBNET_COUNT_ELECTRA" }),
            .max_blobs_per_block_electra = try parseUintField(data, &.{ "max_blobs_per_block_electra", "MAX_BLOBS_PER_BLOCK_ELECTRA" }),
            .blob_schedule = try parseBlobScheduleField(self.allocator, data, &.{ "blob_schedule", "BLOB_SCHEDULE" }),
        };
    }

    /// GET /eth/v1/beacon/headers/head
    ///
    /// Returns the current canonical head slot and block root.
    pub fn getHeadHeaderSummary(self: *BeaconApiClient, io: Io) !HeadHeaderSummary {
        const body = try self.get(io, route_ids.beacon_get_header, "/eth/v1/beacon/headers/head");
        defer self.allocator.free(body);

        const Parsed = struct {
            data: struct {
                root: []const u8,
                header: struct {
                    message: struct {
                        slot: []const u8,
                    },
                },
            },
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();

        const d = parsed.value.data;
        var block_root: [32]u8 = [_]u8{0} ** 32;
        const root_hex = if (std.mem.startsWith(u8, d.root, "0x")) d.root[2..] else d.root;
        _ = std.fmt.hexToBytes(&block_root, root_hex) catch {};

        return .{
            .slot = try std.fmt.parseInt(u64, d.header.message.slot, 10),
            .block_root = block_root,
        };
    }

    /// GET /eth/v1/beacon/states/head/finality_checkpoints
    ///
    /// Returns the current finalized checkpoint epoch.
    pub fn getFinalizedCheckpointEpoch(self: *BeaconApiClient, io: Io) !u64 {
        const body = try self.get(io, route_ids.beacon_get_state_finality_checkpoints, "/eth/v1/beacon/states/head/finality_checkpoints");
        defer self.allocator.free(body);

        const Parsed = struct {
            data: struct {
                finalized: struct {
                    epoch: []const u8,
                },
            },
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();

        return try std.fmt.parseInt(u64, parsed.value.data.finalized.epoch, 10);
    }

    // -----------------------------------------------------------------------
    // Duties
    // -----------------------------------------------------------------------

    /// GET /eth/v1/validator/duties/proposer/{epoch}
    pub fn getProposerDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
    ) !ProposerDutiesResponse {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/duties/proposer/{d}", .{epoch});
        defer self.allocator.free(path);

        const body = try self.get(io, route_ids.validator_get_proposer_duties, path);
        defer self.allocator.free(body);

        const ProposerDutyJson = struct {
            pubkey: []const u8,
            validator_index: []const u8,
            slot: []const u8,
        };
        const Parsed = struct {
            data: []const ProposerDutyJson,
            dependent_root: ?[]const u8 = null,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const duties = try self.allocator.alloc(ProposerDuty, parsed.value.data.len);
        for (parsed.value.data, duties) |src, *dst| {
            dst.validator_index = try std.fmt.parseInt(u64, src.validator_index, 10);
            dst.slot = try std.fmt.parseInt(u64, src.slot, 10);
            const pk_hex = if (std.mem.startsWith(u8, src.pubkey, "0x")) src.pubkey[2..] else src.pubkey;
            _ = std.fmt.hexToBytes(&dst.pubkey, pk_hex) catch {};
        }

        return .{
            .duties = duties,
            .dependent_root = if (parsed.value.dependent_root) |root_hex|
                parseOptionalHexRoot(root_hex)
            else
                null,
        };
    }

    /// POST /eth/v1/validator/duties/attester/{epoch}
    pub fn getAttesterDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) !AttesterDutiesResponse {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/duties/attester/{d}", .{epoch});
        defer self.allocator.free(path);

        // Serialize indices as JSON array of strings: ["0","1",...]
        var body_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_buf.deinit();
        try body_buf.writer.writeByte('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.writer.writeByte(',');
            try body_buf.writer.print("\"{d}\"", .{idx});
        }
        try body_buf.writer.writeByte(']');

        const resp = try self.post(io, route_ids.validator_get_attester_duties, path, body_buf.written());
        defer self.allocator.free(resp);

        const AttesterDutyJson = struct {
            pubkey: []const u8,
            validator_index: []const u8,
            committee_index: []const u8,
            committee_length: []const u8,
            committees_at_slot: []const u8,
            validator_committee_index: []const u8,
            slot: []const u8,
        };
        const Parsed = struct {
            data: []const AttesterDutyJson,
            dependent_root: ?[]const u8 = null,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, resp, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const duties = try self.allocator.alloc(AttesterDuty, parsed.value.data.len);
        for (parsed.value.data, duties) |src, *dst| {
            dst.validator_index = try std.fmt.parseInt(u64, src.validator_index, 10);
            dst.committee_index = try std.fmt.parseInt(u64, src.committee_index, 10);
            dst.committee_length = try std.fmt.parseInt(u64, src.committee_length, 10);
            dst.committees_at_slot = try std.fmt.parseInt(u64, src.committees_at_slot, 10);
            dst.validator_committee_index = try std.fmt.parseInt(u64, src.validator_committee_index, 10);
            dst.slot = try std.fmt.parseInt(u64, src.slot, 10);
            const pk_hex = if (std.mem.startsWith(u8, src.pubkey, "0x")) src.pubkey[2..] else src.pubkey;
            _ = std.fmt.hexToBytes(&dst.pubkey, pk_hex) catch {};
        }
        return .{
            .duties = duties,
            .dependent_root = if (parsed.value.dependent_root) |root_hex|
                parseOptionalHexRoot(root_hex)
            else
                null,
        };
    }

    /// POST /eth/v1/validator/duties/sync/{epoch}
    pub fn getSyncCommitteeDuties(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]SyncCommitteeDuty {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/duties/sync/{d}", .{epoch});
        defer self.allocator.free(path);

        var body_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_buf.deinit();
        try body_buf.writer.writeByte('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.writer.writeByte(',');
            try body_buf.writer.print("\"{d}\"", .{idx});
        }
        try body_buf.writer.writeByte(']');

        const resp = try self.post(io, route_ids.validator_get_sync_committee_duties, path, body_buf.written());
        defer self.allocator.free(resp);

        const SyncDutyJson = struct {
            pubkey: []const u8,
            validator_index: []const u8,
            validator_sync_committee_indices: []const []const u8,
        };
        const Parsed = struct {
            data: []const SyncDutyJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, resp, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const duties = try self.allocator.alloc(SyncCommitteeDuty, parsed.value.data.len);
        errdefer self.allocator.free(duties);

        for (parsed.value.data, duties) |src, *dst| {
            dst.validator_index = try std.fmt.parseInt(u64, src.validator_index, 10);
            const pk_hex = if (std.mem.startsWith(u8, src.pubkey, "0x")) src.pubkey[2..] else src.pubkey;
            _ = std.fmt.hexToBytes(&dst.pubkey, pk_hex) catch {};

            const sc_indices = try self.allocator.alloc(u64, src.validator_sync_committee_indices.len);
            for (src.validator_sync_committee_indices, sc_indices) |str, *out_idx| {
                out_idx.* = try std.fmt.parseInt(u64, str, 10);
            }
            dst.validator_sync_committee_indices = sc_indices;
        }
        return duties;
    }

    // -----------------------------------------------------------------------
    // Validator indices
    // -----------------------------------------------------------------------

    /// POST /eth/v1/beacon/states/head/validators
    pub fn getValidatorIndices(
        self: *BeaconApiClient,
        io: Io,
        pubkeys: []const [48]u8,
    ) ![]ValidatorIndexAndStatus {
        // Build JSON array of hex pubkeys.
        var body_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_buf.deinit();
        try body_buf.writer.writeByte('[');
        for (pubkeys, 0..) |pk, i| {
            if (i > 0) try body_buf.writer.writeByte(',');
            try body_buf.writer.print("\"0x{x}\"", .{pk});
        }
        try body_buf.writer.writeByte(']');

        const resp = try self.post(io, route_ids.beacon_get_state_validators, "/eth/v1/beacon/states/head/validators", body_buf.written());
        defer self.allocator.free(resp);

        const ValidatorJson = struct {
            index: []const u8,
            validator: struct {
                pubkey: []const u8,
            },
            status: []const u8,
        };
        const Parsed = struct {
            data: []const ValidatorJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, resp, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const result = try self.allocator.alloc(ValidatorIndexAndStatus, parsed.value.data.len);
        for (parsed.value.data, result) |src, *dst| {
            dst.index = try std.fmt.parseInt(u64, src.index, 10);
            const pk_hex = if (std.mem.startsWith(u8, src.validator.pubkey, "0x")) src.validator.pubkey[2..] else src.validator.pubkey;
            _ = std.fmt.hexToBytes(&dst.pubkey, pk_hex) catch {};
            // COH-3 Fix: copy status string into owned fixed-size buffer
            // to avoid dangling pointer into the freed JSON arena.
            {
                const s = src.status;
                const copy_len: u8 = @intCast(@min(s.len, dst.status.len));
                @memcpy(dst.status[0..copy_len], s[0..copy_len]);
                dst.status_len = copy_len;
            }
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // Block production
    // -----------------------------------------------------------------------

    fn buildProduceBlockPath(
        self: *BeaconApiClient,
        slot: u64,
        randao_reveal: [96]u8,
        graffiti: [32]u8,
        opts: ProduceBlockOpts,
    ) ![]u8 {
        var path = std.Io.Writer.Allocating.init(self.allocator);
        errdefer path.deinit();

        const randao_hex = std.fmt.bytesToHex(&randao_reveal, .lower);
        const graffiti_hex = std.fmt.bytesToHex(&graffiti, .lower);

        try path.writer.print(
            "/eth/v3/validator/blocks/{d}?randao_reveal=0x{s}&graffiti=0x{s}",
            .{ slot, randao_hex, graffiti_hex },
        );

        if (opts.fee_recipient) |fee_recipient| {
            try path.writer.print("&fee_recipient=0x{s}", .{
                std.fmt.bytesToHex(&fee_recipient, .lower),
            });
        }
        if (opts.builder_selection) |builder_selection| {
            try path.writer.print("&builder_selection={s}", .{builder_selection.queryValue()});
        }
        if (opts.builder_boost_factor) |boost_factor| {
            try path.writer.print("&builder_boost_factor={d}", .{boost_factor});
        }
        if (opts.strict_fee_recipient_check) {
            try path.writer.writeAll("&strict_fee_recipient_check=true");
        }
        if (opts.blinded_local) {
            try path.writer.writeAll("&blinded_local=true");
        }

        return path.toOwnedSlice();
    }

    fn buildPublishBlockPath(
        self: *BeaconApiClient,
        base_path: []const u8,
        broadcast_validation: types.BroadcastValidation,
    ) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}?broadcast_validation={s}",
            .{ base_path, broadcast_validation.queryValue() },
        );
    }

    /// GET /eth/v3/validator/blocks/{slot}?randao_reveal=...&graffiti=...
    /// with optional `fee_recipient`, `builder_boost_factor`, and
    /// `strict_fee_recipient_check` query parameters.
    pub fn produceBlock(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        randao_reveal: [96]u8,
        graffiti: [32]u8,
        opts: ProduceBlockOpts,
    ) !ProduceBlockResponse {
        const path = try self.buildProduceBlockPath(slot, randao_reveal, graffiti, opts);
        defer self.allocator.free(path);

        const body = try self.get(io, route_ids.validator_produce_block_v3, path);
        // Return the raw JSON body — callers parse what they need.
        return .{ .block_ssz = body, .blinded = false };
    }

    /// POST /eth/v2/beacon/blocks
    pub fn publishBlock(
        self: *BeaconApiClient,
        io: Io,
        signed_block_ssz: []const u8,
        broadcast_validation: types.BroadcastValidation,
    ) !void {
        const path = try self.buildPublishBlockPath("/eth/v2/beacon/blocks", broadcast_validation);
        defer self.allocator.free(path);
        try self.postNoResponse(io, route_ids.beacon_publish_block_v2, path, signed_block_ssz);
    }

    /// GET /eth/v3/validator/blocks/{slot} with SSZ response.
    ///
    /// Requests the unsigned BeaconBlock as SSZ (Accept: application/octet-stream).
    /// The fork is determined from the Eth-Consensus-Version response header.
    /// Returns raw SSZ bytes of the unsigned BeaconBlock + fork metadata.
    /// The same optional produce-block query parameters are supported as
    /// in `produceBlock()`.
    pub fn produceBlockSsz(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        randao_reveal: [96]u8,
        graffiti: [32]u8,
        opts: ProduceBlockOpts,
    ) !ProduceBlockSszResponse {
        const path = try self.buildProduceBlockPath(slot, randao_reveal, graffiti, opts);
        defer self.allocator.free(path);

        const resp = try self.getSsz(io, route_ids.validator_produce_block_v3, path);
        return .{
            .block_ssz = resp.body,
            .fork_name = resp.fork_name,
            .fork_name_len = resp.fork_name_len,
            .blinded = resp.is_blinded,
            .execution_payload_source = resp.execution_payload_source,
        };
    }

    /// POST /eth/v2/beacon/blocks with SSZ body.
    ///
    /// Publishes a SignedBeaconBlock as SSZ (Content-Type: application/octet-stream).
    /// The Eth-Consensus-Version header is set to the fork name.
    pub fn publishBlockSsz(
        self: *BeaconApiClient,
        io: Io,
        signed_block_ssz: []const u8,
        fork_name: []const u8,
        broadcast_validation: types.BroadcastValidation,
    ) !void {
        const path = try self.buildPublishBlockPath("/eth/v2/beacon/blocks", broadcast_validation);
        defer self.allocator.free(path);
        try self.postSsz(io, route_ids.beacon_publish_block_v2, path, signed_block_ssz, fork_name);
    }

    // -----------------------------------------------------------------------
    // Attestation
    // -----------------------------------------------------------------------

    /// GET /eth/v1/validator/attestation_data?slot=...&committee_index=...
    pub fn produceAttestationData(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        committee_index: u64,
    ) !AttestationDataResponse {
        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/validator/attestation_data?slot={d}&committee_index={d}",
            .{ slot, committee_index },
        );
        defer self.allocator.free(path);

        const body = try self.get(io, route_ids.validator_produce_attestation_data, path);
        defer self.allocator.free(body);

        const AttDataJson = struct {
            slot: []const u8,
            index: []const u8,
            beacon_block_root: []const u8,
            source: struct { epoch: []const u8, root: []const u8 },
            target: struct { epoch: []const u8, root: []const u8 },
        };
        const Parsed = struct {
            data: AttDataJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const d = parsed.value.data;

        var beacon_block_root: [32]u8 = [_]u8{0} ** 32;
        var source_root: [32]u8 = [_]u8{0} ** 32;
        var target_root: [32]u8 = [_]u8{0} ** 32;

        const bbr_hex = if (std.mem.startsWith(u8, d.beacon_block_root, "0x")) d.beacon_block_root[2..] else d.beacon_block_root;
        _ = std.fmt.hexToBytes(&beacon_block_root, bbr_hex) catch {};
        const sr_hex = if (std.mem.startsWith(u8, d.source.root, "0x")) d.source.root[2..] else d.source.root;
        _ = std.fmt.hexToBytes(&source_root, sr_hex) catch {};
        const tr_hex = if (std.mem.startsWith(u8, d.target.root, "0x")) d.target.root[2..] else d.target.root;
        _ = std.fmt.hexToBytes(&target_root, tr_hex) catch {};

        return .{
            .slot = try std.fmt.parseInt(u64, d.slot, 10),
            .index = try std.fmt.parseInt(u64, d.index, 10),
            .beacon_block_root = beacon_block_root,
            .source_epoch = try std.fmt.parseInt(u64, d.source.epoch, 10),
            .source_root = source_root,
            .target_epoch = try std.fmt.parseInt(u64, d.target.epoch, 10),
            .target_root = target_root,
        };
    }

    /// POST /eth/v2/beacon/pool/attestations
    pub fn publishAttestations(
        self: *BeaconApiClient,
        io: Io,
        attestations_json: []const u8,
    ) !void {
        try self.postNoResponse(io, route_ids.beacon_publish_attestations_v2, "/eth/v2/beacon/pool/attestations", attestations_json);
    }

    /// POST /eth/v1/beacon/pool/voluntary_exits
    pub fn publishVoluntaryExit(
        self: *BeaconApiClient,
        io: Io,
        signed_exit_json: []const u8,
    ) !void {
        try self.postNoResponse(io, route_ids.beacon_publish_voluntary_exit, "/eth/v1/beacon/pool/voluntary_exits", signed_exit_json);
    }

    /// GET /eth/v1/validator/aggregate_attestation?slot=...&attestation_data_root=...
    pub fn getAggregatedAttestation(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        attestation_data_root: [32]u8,
    ) !AggregatedAttestationResponse {
        const root_hex = std.fmt.bytesToHex(&attestation_data_root, .lower);
        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/validator/aggregate_attestation?slot={d}&attestation_data_root=0x{s}",
            .{ slot, root_hex },
        );
        defer self.allocator.free(path);

        const body = try self.get(io, route_ids.validator_get_aggregate_attestation, path);
        return .{ .attestation_json = body };
    }

    /// POST /eth/v2/validator/aggregate_and_proofs
    pub fn publishAggregateAndProofs(
        self: *BeaconApiClient,
        io: Io,
        proofs_json: []const u8,
    ) !void {
        try self.postNoResponse(io, route_ids.validator_publish_aggregate_and_proofs_v2, "/eth/v2/validator/aggregate_and_proofs", proofs_json);
    }

    // -----------------------------------------------------------------------
    // Sync committee
    // -----------------------------------------------------------------------

    /// POST /eth/v1/beacon/pool/sync_committees
    pub fn publishSyncCommitteeMessages(
        self: *BeaconApiClient,
        io: Io,
        messages_json: []const u8,
    ) !void {
        try self.postNoResponse(io, route_ids.beacon_publish_sync_committee_messages, "/eth/v1/beacon/pool/sync_committees", messages_json);
    }

    /// POST /eth/v1/validator/contribution_and_proofs
    pub fn publishContributionAndProofs(
        self: *BeaconApiClient,
        io: Io,
        contributions_json: []const u8,
    ) !void {
        try self.postNoResponse(io, route_ids.validator_publish_contribution_and_proofs, "/eth/v1/validator/contribution_and_proofs", contributions_json);
    }

    /// GET /eth/v1/validator/sync_committee_contribution?slot=...&subcommittee_index=...&beacon_block_root=...
    pub fn produceSyncCommitteeContribution(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: [32]u8,
    ) !SyncCommitteeContributionResponse {
        return self.produceSyncCommitteeContributionWithTimeout(
            io,
            slot,
            subcommittee_index,
            beacon_block_root,
            self.request_timeout_ms,
        );
    }

    pub fn produceSyncCommitteeContributionWithTimeout(
        self: *BeaconApiClient,
        io: Io,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: [32]u8,
        timeout_ms: u64,
    ) !SyncCommitteeContributionResponse {
        const root_hex = std.fmt.bytesToHex(&beacon_block_root, .lower);
        const path = try std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/validator/sync_committee_contribution?slot={d}&subcommittee_index={d}&beacon_block_root=0x{s}",
            .{ slot, subcommittee_index, root_hex },
        );
        defer self.allocator.free(path);

        const body = try self.getWithTimeout(io, route_ids.validator_produce_sync_committee_contribution, path, timeout_ms);
        defer self.allocator.free(body);

        const ContribJson = struct {
            slot: []const u8,
            beacon_block_root: []const u8,
            subcommittee_index: []const u8,
            aggregation_bits: []const u8,
            signature: []const u8,
        };
        const Parsed = struct {
            data: ContribJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const d = parsed.value.data;

        var block_root: [32]u8 = [_]u8{0} ** 32;
        const br_hex = if (std.mem.startsWith(u8, d.beacon_block_root, "0x")) d.beacon_block_root[2..] else d.beacon_block_root;
        _ = std.fmt.hexToBytes(&block_root, br_hex) catch {};

        var sig: [96]u8 = [_]u8{0} ** 96;
        const sig_hex = if (std.mem.startsWith(u8, d.signature, "0x")) d.signature[2..] else d.signature;
        _ = std.fmt.hexToBytes(&sig, sig_hex) catch {};

        // aggregation_bits is returned as hex in the API.
        const agg_hex = if (std.mem.startsWith(u8, d.aggregation_bits, "0x")) d.aggregation_bits[2..] else d.aggregation_bits;
        const agg_bits = try self.allocator.alloc(u8, agg_hex.len / 2);
        _ = std.fmt.hexToBytes(agg_bits, agg_hex) catch {};

        return .{
            .slot = try std.fmt.parseInt(u64, d.slot, 10),
            .beacon_block_root = block_root,
            .subcommittee_index = try std.fmt.parseInt(u64, d.subcommittee_index, 10),
            .aggregation_bits = agg_bits,
            .signature = sig,
        };
    }

    // -----------------------------------------------------------------------
    // Proposer preparation
    // -----------------------------------------------------------------------

    /// POST /eth/v1/validator/beacon_committee_subscriptions
    pub fn prepareBeaconCommitteeSubnets(
        self: *BeaconApiClient,
        io: Io,
        subscriptions: []const BeaconCommitteeSubscription,
    ) !void {
        if (subscriptions.len == 0) return;

        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();
        try body.writer.writeByte('[');
        for (subscriptions, 0..) |subscription, i| {
            if (i > 0) try body.writer.writeByte(',');
            try body.writer.print(
                "{{\"validator_index\":\"{d}\",\"committee_index\":\"{d}\",\"committees_at_slot\":\"{d}\",\"slot\":\"{d}\",\"is_aggregator\":{s}}}",
                .{
                    subscription.validator_index,
                    subscription.committee_index,
                    subscription.committees_at_slot,
                    subscription.slot,
                    if (subscription.is_aggregator) "true" else "false",
                },
            );
        }
        try body.writer.writeByte(']');

        try self.postNoResponse(io, route_ids.validator_prepare_beacon_committee_subscriptions, "/eth/v1/validator/beacon_committee_subscriptions", body.written());
    }

    /// POST /eth/v1/validator/sync_committee_subscriptions
    pub fn prepareSyncCommitteeSubnets(
        self: *BeaconApiClient,
        io: Io,
        subscriptions: []const SyncCommitteeSubscription,
    ) !void {
        if (subscriptions.len == 0) return;

        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();
        try body.writer.writeByte('[');
        for (subscriptions, 0..) |subscription, i| {
            if (i > 0) try body.writer.writeByte(',');
            try body.writer.print("{{\"validator_index\":\"{d}\",\"sync_committee_indices\":[", .{subscription.validator_index});
            for (subscription.sync_committee_indices, 0..) |committee_index, committee_i| {
                if (committee_i > 0) try body.writer.writeByte(',');
                try body.writer.print("\"{d}\"", .{committee_index});
            }
            try body.writer.print("],\"until_epoch\":\"{d}\"}}", .{subscription.until_epoch});
        }
        try body.writer.writeByte(']');

        try self.postNoResponse(io, route_ids.validator_prepare_sync_committee_subscriptions, "/eth/v1/validator/sync_committee_subscriptions", body.written());
    }

    /// POST /eth/v1/validator/prepare_beacon_proposer
    pub fn prepareBeaconProposer(
        self: *BeaconApiClient,
        io: Io,
        registrations_json: []const u8,
    ) !void {
        try self.postNoResponse(io, route_ids.validator_prepare_beacon_proposer, "/eth/v1/validator/prepare_beacon_proposer", registrations_json);
    }

    // -----------------------------------------------------------------------
    // Builder API (forwarded through BN)
    // -----------------------------------------------------------------------

    /// POST /eth/v1/validator/register_validator
    ///
    /// Sends signed validator registrations to the BN, which forwards them
    /// to the configured MEV-boost relay.
    pub fn registerValidators(
        self: *BeaconApiClient,
        io: Io,
        registrations_json: []const u8,
    ) !void {
        try self.postNoResponse(io, route_ids.validator_register_validator, "/eth/v1/validator/register_validator", registrations_json);
    }

    /// POST /eth/v2/beacon/blinded_blocks with SSZ body.
    ///
    /// Publishes a SignedBlindedBeaconBlock as SSZ.
    /// The builder relay will unblind the block and broadcast it.
    pub fn publishBlindedBlockSsz(
        self: *BeaconApiClient,
        io: Io,
        signed_block_ssz: []const u8,
        fork_name: []const u8,
        broadcast_validation: types.BroadcastValidation,
    ) !void {
        const path = try self.buildPublishBlockPath("/eth/v2/beacon/blinded_blocks", broadcast_validation);
        defer self.allocator.free(path);
        try self.postSsz(io, route_ids.beacon_publish_blinded_block_v2, path, signed_block_ssz, fork_name);
    }

    // -----------------------------------------------------------------------
    // SSE event stream
    // -----------------------------------------------------------------------

    /// GET /eth/v1/events?topics=head,block,...
    ///
    /// Subscribes to beacon node SSE events and calls `callback` for each.
    /// Runs until stream ends or error.
    ///
    /// SSE format (per https://html.spec.whatwg.org/multipage/server-sent-events.html):
    ///   event: head\n
    ///   data: {...}\n
    ///   \n
    pub fn subscribeToEvents(
        self: *BeaconApiClient,
        io: Io,
        topics: []const []const u8,
        callback: SseCallback,
    ) !void {
        const path = try self.buildEventsPath(topics);
        defer self.allocator.free(path);
        var stream = try self.connectSseWithFallbacks(io, path);
        return self.processConnectedSseStream(io, &stream, callback);
    }

    fn buildEventsPath(self: *BeaconApiClient, topics: []const []const u8) ![]u8 {
        var topics_buf = std.array_list.Managed(u8).init(self.allocator);
        defer topics_buf.deinit();
        for (topics, 0..) |topic, i| {
            if (i > 0) try topics_buf.append(',');
            try topics_buf.appendSlice(topic);
        }

        return std.fmt.allocPrint(
            self.allocator,
            "/eth/v1/events?topics={s}",
            .{topics_buf.items},
        );
    }

    // -----------------------------------------------------------------------
    // Liveness (doppelganger)
    // -----------------------------------------------------------------------

    /// POST /eth/v1/validator/liveness/{epoch}
    /// GET /eth/v1/node/syncing
    ///
    /// Returns sync status of the beacon node.
    /// TS: Api.node.getSyncingStatus()
    pub fn getNodeSyncing(self: *BeaconApiClient, io: Io) !NodeSyncingResponse {
        const body = try self.get(io, route_ids.node_get_syncing_status, "/eth/v1/node/syncing");
        defer self.allocator.free(body);

        const Parsed = struct {
            data: struct {
                head_slot: []const u8,
                sync_distance: []const u8,
                is_syncing: bool,
                is_optimistic: bool = false,
                el_offline: bool = false,
            },
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, body, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const d = parsed.value.data;
        return .{
            .head_slot = try std.fmt.parseInt(u64, d.head_slot, 10),
            .sync_distance = try std.fmt.parseInt(u64, d.sync_distance, 10),
            .is_syncing = d.is_syncing,
            .is_optimistic = d.is_optimistic,
            .el_offline = d.el_offline,
        };
    }

    pub fn getLiveness(
        self: *BeaconApiClient,
        io: Io,
        epoch: u64,
        indices: []const u64,
    ) ![]ValidatorLiveness {
        const path = try std.fmt.allocPrint(self.allocator, "/eth/v1/validator/liveness/{d}", .{epoch});
        defer self.allocator.free(path);

        var body_buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_buf.deinit();
        try body_buf.writer.writeByte('[');
        for (indices, 0..) |idx, i| {
            if (i > 0) try body_buf.writer.writeByte(',');
            try body_buf.writer.print("\"{d}\"", .{idx});
        }
        try body_buf.writer.writeByte(']');

        const resp = try self.post(io, route_ids.validator_get_liveness, path, body_buf.written());
        defer self.allocator.free(resp);

        const LivenessJson = struct {
            index: []const u8,
            is_live: bool,
        };
        const Parsed = struct {
            data: []const LivenessJson,
        };

        var parsed = try std.json.parseFromSlice(Parsed, self.allocator, resp, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const result = try self.allocator.alloc(ValidatorLiveness, parsed.value.data.len);
        for (parsed.value.data, result) |src, *dst| {
            dst.index = try std.fmt.parseInt(u64, src.index, 10);
            dst.is_live = src.is_live;
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

pub const GenesisResponse = struct {
    genesis_time: u64,
    genesis_validators_root: [32]u8,
    genesis_fork_version: [4]u8,
};

pub const ConfigSpecResponse = struct {
    pub const BlobScheduleEntry = struct {
        epoch: u64,
        max_blobs_per_block: u64,
    };

    min_genesis_active_validator_count: ?u64 = null,
    min_genesis_time: ?u64 = null,
    genesis_delay: ?u64 = null,
    genesis_fork_version: ?[4]u8 = null,
    altair_fork_version: ?[4]u8 = null,
    altair_fork_epoch: ?u64 = null,
    bellatrix_fork_version: ?[4]u8 = null,
    bellatrix_fork_epoch: ?u64 = null,
    capella_fork_version: ?[4]u8 = null,
    capella_fork_epoch: ?u64 = null,
    deneb_fork_version: ?[4]u8 = null,
    deneb_fork_epoch: ?u64 = null,
    electra_fork_version: ?[4]u8 = null,
    electra_fork_epoch: ?u64 = null,
    fulu_fork_version: ?[4]u8 = null,
    fulu_fork_epoch: ?u64 = null,
    gloas_fork_version: ?[4]u8 = null,
    gloas_fork_epoch: ?u64 = null,
    seconds_per_slot: ?u64 = null,
    slot_duration_ms: ?u64 = null,
    min_validator_withdrawability_delay: ?u64 = null,
    shard_committee_period: ?u64 = null,
    eth1_follow_distance: ?u64 = null,
    inactivity_score_bias: ?u64 = null,
    inactivity_score_recovery_rate: ?u64 = null,
    ejection_balance: ?u64 = null,
    min_per_epoch_churn_limit: ?u64 = null,
    max_per_epoch_activation_churn_limit: ?u64 = null,
    churn_limit_quotient: ?u64 = null,
    proposer_reorg_cutoff_bps: ?u64 = null,
    attestation_due_bps: ?u64 = null,
    attestation_due_bps_gloas: ?u64 = null,
    aggregate_due_bps: ?u64 = null,
    aggregate_due_bps_gloas: ?u64 = null,
    sync_message_due_bps: ?u64 = null,
    sync_message_due_bps_gloas: ?u64 = null,
    contribution_due_bps: ?u64 = null,
    contribution_due_bps_gloas: ?u64 = null,
    deposit_contract_address: ?[20]u8 = null,
    blob_sidecar_subnet_count: ?u64 = null,
    max_committees_per_slot: ?u64 = null,
    target_committee_size: ?u64 = null,
    max_validators_per_committee: ?u64 = null,
    max_blobs_per_block: ?u64 = null,
    min_deposit_amount: ?u64 = null,
    max_effective_balance: ?u64 = null,
    effective_balance_increment: ?u64 = null,
    min_attestation_inclusion_delay: ?u64 = null,
    slots_per_epoch: ?u64 = null,
    min_seed_lookahead: ?u64 = null,
    max_seed_lookahead: ?u64 = null,
    epochs_per_eth1_voting_period: ?u64 = null,
    slots_per_historical_root: ?u64 = null,
    min_epochs_to_inactivity_penalty: ?u64 = null,
    epochs_per_historical_vector: ?u64 = null,
    epochs_per_slashings_vector: ?u64 = null,
    historical_roots_limit: ?u64 = null,
    validator_registry_limit: ?u64 = null,
    base_reward_factor: ?u64 = null,
    whistleblower_reward_quotient: ?u64 = null,
    proposer_reward_quotient: ?u64 = null,
    inactivity_penalty_quotient: ?u64 = null,
    min_slashing_penalty_quotient: ?u64 = null,
    proportional_slashing_multiplier: ?u64 = null,
    max_proposer_slashings: ?u64 = null,
    max_attester_slashings: ?u64 = null,
    max_attestations: ?u64 = null,
    max_deposits: ?u64 = null,
    max_voluntary_exits: ?u64 = null,
    sync_committee_size: ?u64 = null,
    epochs_per_sync_committee_period: ?u64 = null,
    inactivity_penalty_quotient_altair: ?u64 = null,
    min_slashing_penalty_quotient_altair: ?u64 = null,
    proportional_slashing_multiplier_altair: ?u64 = null,
    blob_sidecar_subnet_count_electra: ?u64 = null,
    max_blobs_per_block_electra: ?u64 = null,
    blob_schedule: []const BlobScheduleEntry = &.{},

    pub fn deinit(self: *ConfigSpecResponse, allocator: Allocator) void {
        if (self.blob_schedule.len > 0) allocator.free(self.blob_schedule);
        self.* = undefined;
    }
};

pub const ValidatorIndexAndStatus = struct {
    pubkey: [48]u8,
    index: u64,
    /// Validator status string (e.g. "active_ongoing", "withdrawal_possible").
    /// COH-3 Fix: stored as fixed-size buffer to avoid dangling pointer into freed arena.
    /// Max known status len is 20 bytes ("withdrawal_possible"); 32 is safe margin.
    status: [32]u8,
    status_len: u8,

    /// Return the status string slice.
    pub fn statusStr(self: *const ValidatorIndexAndStatus) []const u8 {
        return self.status[0..self.status_len];
    }
};

pub const ProduceBlockResponse = struct {
    /// Raw JSON body of the block response (caller must free).
    block_ssz: []const u8,
    /// Whether the block is blinded (MEV relay path).
    blinded: bool,
};

pub const ProduceBlockSszResponse = struct {
    /// Raw SSZ bytes of the unsigned BeaconBlock (caller must free).
    block_ssz: []const u8,
    /// Fork name from Eth-Consensus-Version header (e.g. "electra").
    /// Stored in fixed buffer — does not require freeing.
    fork_name: [32]u8,
    fork_name_len: u8,
    /// Whether the block is blinded (from response headers).
    blinded: bool,
    /// Where the execution payload came from.
    execution_payload_source: types.ExecutionPayloadSource,

    pub fn forkNameStr(self: *const ProduceBlockSszResponse) []const u8 {
        return self.fork_name[0..self.fork_name_len];
    }
};

fn getObjectField(
    object: std.json.ObjectMap,
    comptime names: []const []const u8,
) ?std.json.Value {
    inline for (names) |name| {
        if (object.get(name)) |value| return value;
    }
    return null;
}

fn parseUintField(
    object: std.json.ObjectMap,
    comptime names: []const []const u8,
) !?u64 {
    const value = getObjectField(object, names) orelse return null;
    return switch (value) {
        .string => |s| try std.fmt.parseInt(u64, s, 10),
        .integer => |i| blk: {
            if (i < 0) return error.InvalidResponse;
            break :blk @intCast(i);
        },
        else => error.InvalidResponse,
    };
}

test "buildProduceBlockPath includes extended produceBlock opts" {
    var client = try BeaconApiClient.init(std.testing.allocator, std.testing.io, "http://127.0.0.1:5052");
    defer client.deinit();
    const path = try client.buildProduceBlockPath(
        7,
        [_]u8{0x11} ** 96,
        [_]u8{0x22} ** 32,
        .{
            .fee_recipient = [_]u8{0x33} ** 20,
            .builder_selection = .maxprofit,
            .builder_boost_factor = 150,
            .strict_fee_recipient_check = true,
            .blinded_local = true,
        },
    );
    defer std.testing.allocator.free(path);

    try std.testing.expect(std.mem.indexOf(u8, path, "randao_reveal=0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "graffiti=0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "fee_recipient=0x3333") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "builder_selection=maxprofit") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "builder_boost_factor=150") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "strict_fee_recipient_check=true") != null);
    try std.testing.expect(std.mem.indexOf(u8, path, "blinded_local=true") != null);
}

test "buildPublishBlockPath includes broadcast validation query" {
    var client = try BeaconApiClient.init(std.testing.allocator, std.testing.io, "http://127.0.0.1:5052");
    defer client.deinit();
    const path = try client.buildPublishBlockPath("/eth/v2/beacon/blinded_blocks", .consensus);
    defer std.testing.allocator.free(path);

    try std.testing.expectEqualStrings(
        "/eth/v2/beacon/blinded_blocks?broadcast_validation=consensus",
        path,
    );
}

test "BeaconApiClient promotes successful fallback URL to active" {
    var client = try BeaconApiClient.initWithFallbacks(
        std.testing.allocator,
        std.testing.io,
        "http://127.0.0.1:5052",
        &.{ "http://127.0.0.1:5053", "http://127.0.0.1:5054" },
    );
    defer client.deinit();

    try std.testing.expectEqualStrings("http://127.0.0.1:5052", client.activeUrl());
    try std.testing.expectEqual(@as(usize, 0), client.activeUrlIndex());

    client.recordSuccessAt(2);

    try std.testing.expectEqualStrings("http://127.0.0.1:5054", client.activeUrl());
    try std.testing.expectEqual(@as(usize, 2), client.activeUrlIndex());

    const status = client.failoverStatus();
    try std.testing.expect(status.configured);
    try std.testing.expect(status.connected);
}

test "BeaconApiClient stale failures do not clobber newer active URL" {
    var client = try BeaconApiClient.initWithFallbacks(
        std.testing.allocator,
        std.testing.io,
        "http://127.0.0.1:5052",
        &.{"http://127.0.0.1:5053"},
    );
    defer client.deinit();

    client.recordSuccessAt(1);
    client.recordFailure(std.testing.io, 0);

    try std.testing.expectEqual(@as(usize, 1), client.activeUrlIndex());
    try std.testing.expectEqual(@as(u64, 0), client.consecutive_failures);
}

test "BeaconApiClient falls back to highest-scored URL after primary bottoms out" {
    var client = try BeaconApiClient.initWithFallbacks(
        std.testing.allocator,
        std.testing.io,
        "http://127.0.0.1:5052",
        &.{ "http://127.0.0.1:5053", "http://127.0.0.1:5054" },
    );
    defer client.deinit();

    client.recordFailure(std.testing.io, 0);
    client.recordFailure(std.testing.io, 0);
    client.recordFailure(std.testing.io, 0);
    client.recordFailure(std.testing.io, 0);
    client.recordFailure(std.testing.io, 0);

    try std.testing.expect(client.primaryUrlUnhealthy());
    try std.testing.expectEqual(@as(usize, 1), client.activeUrlIndex());
}

test "BeaconApiClient race group includes degraded URLs through next healthy URL" {
    var client = try BeaconApiClient.initWithFallbacks(
        std.testing.allocator,
        std.testing.io,
        "http://127.0.0.1:5052",
        &.{ "http://127.0.0.1:5053", "http://127.0.0.1:5054" },
    );
    defer client.deinit();

    client.recordFailure(std.testing.io, 0);
    client.recordFailure(std.testing.io, 1);

    var group: [3]usize = undefined;
    const count = client.fillRaceGroup(0, 0, group[0..]);

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2 }, group[0..count]);
}

test "BeaconApiClient initMulti rejects empty URL lists" {
    try std.testing.expectError(
        error.InvalidBeaconNodeUrlConfiguration,
        BeaconApiClient.initMulti(std.testing.allocator, std.testing.io, &.{}),
    );
}

test "parseOptionalHexRoot parses 0x-prefixed roots" {
    const parsed = parseOptionalHexRoot("0x1111111111111111111111111111111111111111111111111111111111111111");
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual([32]u8{0x11} ** 32, parsed.?);
}

test "parseOptionalHexRoot rejects invalid roots" {
    try std.testing.expectEqual(@as(?[32]u8, null), parseOptionalHexRoot("0x1234"));
}

test "BeaconApiClient race group uses only the active healthy URL" {
    var client = try BeaconApiClient.initWithFallbacks(
        std.testing.allocator,
        std.testing.io,
        "http://127.0.0.1:5052",
        &.{ "http://127.0.0.1:5053", "http://127.0.0.1:5054" },
    );
    defer client.deinit();

    client.recordSuccessAt(2);

    var group: [3]usize = undefined;
    const count = client.fillRaceGroup(2, 0, group[0..]);

    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualSlices(usize, &.{2}, group[0..count]);
}

fn parseHexField(
    object: std.json.ObjectMap,
    comptime names: []const []const u8,
    comptime N: usize,
) !?[N]u8 {
    const value = getObjectField(object, names) orelse return null;
    const text = switch (value) {
        .string => |s| s,
        else => return error.InvalidResponse,
    };

    const hex = if (std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X"))
        text[2..]
    else
        text;
    if (hex.len != N * 2) return error.InvalidResponse;

    var out: [N]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

fn parseBlobScheduleField(
    allocator: Allocator,
    object: std.json.ObjectMap,
    comptime names: []const []const u8,
) ![]const ConfigSpecResponse.BlobScheduleEntry {
    const value = getObjectField(object, names) orelse return &.{};
    const array = switch (value) {
        .array => |items| items,
        else => return error.InvalidResponse,
    };
    if (array.items.len == 0) return &.{};

    const entries = try allocator.alloc(ConfigSpecResponse.BlobScheduleEntry, array.items.len);
    errdefer allocator.free(entries);

    for (array.items, entries) |item, *entry| {
        const entry_obj = switch (item) {
            .object => |obj| obj,
            else => return error.InvalidResponse,
        };
        entry.* = .{
            .epoch = try parseUintField(entry_obj, &.{ "epoch", "EPOCH" }) orelse return error.InvalidResponse,
            .max_blobs_per_block = try parseUintField(entry_obj, &.{ "max_blobs_per_block", "MAX_BLOBS_PER_BLOCK" }) orelse return error.InvalidResponse,
        };
    }

    return entries;
}

fn parseOptionalHexRoot(text: []const u8) ?[32]u8 {
    const hex = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    if (hex.len != 64) return null;

    var root: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&root, hex) catch return null;
    return root;
}

pub const AttestationDataResponse = struct {
    slot: u64,
    index: u64,
    beacon_block_root: [32]u8,
    source_epoch: u64,
    source_root: [32]u8,
    target_epoch: u64,
    target_root: [32]u8,
};

pub const AggregatedAttestationResponse = struct {
    /// Raw JSON body of the aggregated attestation (caller must free).
    attestation_json: []const u8,
};

pub const SyncCommitteeContributionResponse = struct {
    slot: u64,
    beacon_block_root: [32]u8,
    subcommittee_index: u64,
    /// Aggregation bits (caller must free).
    aggregation_bits: []const u8,
    /// Aggregate BLS signature.
    signature: [96]u8,
};

pub const ValidatorLiveness = struct {
    index: u64,
    is_live: bool,
};

pub const NodeSyncingResponse = struct {
    head_slot: u64,
    sync_distance: u64,
    is_syncing: bool,
    is_optimistic: bool,
    el_offline: bool,
};
