//! Node-owned execution runtime.
//!
//! Owns execution-layer and builder clients plus the local payload-build cache.
//! Chain-facing execution semantics stay on the chain port; this runtime owns
//! the mutable transport state that used to live directly on BeaconNode.

const std = @import("std");

const chain_mod = @import("chain");
const execution_mod = @import("execution");

const NodeOptions = @import("options.zig").NodeOptions;

const EngineApi = execution_mod.EngineApi;
const MockEngine = execution_mod.MockEngine;
const HttpEngine = execution_mod.HttpEngine;
const HttpBuilder = execution_mod.HttpBuilder;
const IoHttpTransport = execution_mod.IoHttpTransport;
const BuilderApi = execution_mod.BuilderApi;
const GetPayloadResponse = execution_mod.GetPayloadResponse;
const ForkchoiceUpdatedResponse = execution_mod.ForkchoiceUpdatedResponse;
const PayloadAttributesV3 = execution_mod.engine_api_types.PayloadAttributesV3;

const ExecutionForkchoiceUpdate = chain_mod.ExecutionForkchoiceUpdate;
const ExecutionPort = chain_mod.ExecutionPort;
const NewPayloadRequest = chain_mod.NewPayloadRequest;
const NewPayloadResult = chain_mod.NewPayloadResult;

pub const ExecutionRuntime = struct {
    allocator: std.mem.Allocator,
    io: std.Io,

    mock_engine: ?*MockEngine = null,
    http_engine: ?*HttpEngine = null,
    io_transport: ?*IoHttpTransport = null,
    engine_api: ?EngineApi = null,
    http_builder: ?*HttpBuilder = null,
    builder_transport: ?*IoHttpTransport = null,
    builder_api: ?BuilderApi = null,

    cached_payload_id: ?[8]u8 = null,
    cached_payload_slot: ?u64 = null,
    cached_payload_parent_root: ?[32]u8 = null,
    last_builder_status_slot: ?u64 = null,
    el_offline: bool = false,

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
            std.log.info("Execution engine: MockEngine (--engine-mock)", .{});
        } else if (opts.execution_urls.len > 0) {
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
                opts.execution_urls[0],
                jwt_secret,
                transport.transport(),
                retry_config,
            );
            errdefer http_engine.deinit();
            self.http_engine = http_engine;
            self.engine_api = http_engine.engine();

            std.log.info(
                "Execution engine: HttpEngine -> {s} (retries={d} delay_ms={d} timeout_ms={d})",
                .{
                    opts.execution_urls[0],
                    opts.execution_retries,
                    opts.execution_retry_delay_ms,
                    retry_config.default_timeout_ms,
                },
            );
        } else {
            const mock = try allocator.create(MockEngine);
            errdefer allocator.destroy(mock);
            mock.* = MockEngine.init(allocator);
            errdefer mock.deinit();

            self.mock_engine = mock;
            self.engine_api = mock.engine();
            std.log.info("Execution engine: MockEngine (no --execution-url)", .{});
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

            std.log.info(
                "Execution builder: HttpBuilder -> {s} (timeout_ms={d} proposal_timeout_ms={d} fault_window={d} allowed_faults={d})",
                .{
                    opts.builder_url,
                    http_builder.request_timeout_ms,
                    http_builder.proposal_timeout_ms,
                    http_builder.fault_inspection_window,
                    http_builder.allowed_faults,
                },
            );
        }

        return self;
    }

    pub fn deinit(self: *ExecutionRuntime) void {
        const allocator = self.allocator;

        if (self.mock_engine) |engine| {
            engine.deinit();
            allocator.destroy(engine);
        }
        if (self.http_engine) |engine| {
            engine.deinit();
            allocator.destroy(engine);
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
        const engine = self.engine_api orelse return .unavailable;

        const result = switch (request) {
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
            std.log.warn("execution runtime: engine_newPayload failed: {}", .{err});
            self.el_offline = true;
            return .unavailable;
        };
        defer result.deinit(self.allocator);

        self.el_offline = false;
        return switch (result.status) {
            .valid => .{ .valid = .{
                .latest_valid_hash = result.latest_valid_hash orelse request.blockHash(),
            } },
            .invalid => .{ .invalid = .{
                .latest_valid_hash = result.latest_valid_hash,
            } },
            .invalid_block_hash => .{ .invalid_block_hash = .{
                .latest_valid_hash = result.latest_valid_hash,
            } },
            .syncing => .syncing,
            .accepted => .accepted,
        };
    }

    pub fn forkchoiceUpdated(
        self: *ExecutionRuntime,
        update: ExecutionForkchoiceUpdate,
        payload_attrs: ?PayloadAttributesV3,
    ) !?ForkchoiceUpdatedResponse {
        const engine = self.engine_api orelse return null;
        const fc_state = update.state;

        const result = engine.forkchoiceUpdated(.{
            .head_block_hash = fc_state.head_block_hash,
            .safe_block_hash = fc_state.safe_block_hash,
            .finalized_block_hash = fc_state.finalized_block_hash,
        }, payload_attrs) catch |err| {
            self.el_offline = true;
            return err;
        };

        self.el_offline = false;
        if (result.payload_id) |payload_id| {
            self.cached_payload_id = payload_id;
            if (payload_attrs != null) self.cached_payload_parent_root = update.beacon_block_root;
        } else if (payload_attrs != null) {
            self.clearCachedPayload();
        }
        return result;
    }

    pub fn getPayload(self: *ExecutionRuntime) !GetPayloadResponse {
        const engine = self.engine_api orelse return error.NoEngineApi;
        const payload_id = self.cached_payload_id orelse return error.NoPayloadId;

        const result = engine.getPayload(payload_id) catch |err| {
            self.el_offline = true;
            return err;
        };

        self.el_offline = false;
        self.clearCachedPayload();
        return result;
    }

    pub fn freeGetPayloadResponse(self: *const ExecutionRuntime, response: GetPayloadResponse) void {
        const engine = self.engine_api orelse return;
        engine.freeGetPayloadResponse(response);
    }

    pub fn hasExecutionEngine(self: *const ExecutionRuntime) bool {
        return self.engine_api != null;
    }

    pub fn engineApi(self: *const ExecutionRuntime) ?EngineApi {
        return self.engine_api;
    }

    pub fn mockEngine(self: *const ExecutionRuntime) ?*MockEngine {
        return self.mock_engine;
    }

    pub fn builderApi(self: *const ExecutionRuntime) ?BuilderApi {
        return self.builder_api;
    }

    pub fn httpEngineRequestClone(self: *const ExecutionRuntime) ?HttpEngine {
        const http_engine = self.http_engine orelse return null;
        return http_engine.requestClone();
    }

    pub fn httpBuilderRequestClone(self: *const ExecutionRuntime) ?HttpBuilder {
        const http_builder = self.http_builder orelse return null;
        return http_builder.requestClone();
    }

    pub fn currentBuilderStatus(self: *const ExecutionRuntime) execution_mod.BuilderStatus {
        const http_builder = self.http_builder orelse return .unavailable;
        return http_builder.current_status;
    }

    pub fn updateBuilderStatus(
        self: *ExecutionRuntime,
        status: execution_mod.BuilderStatus,
    ) void {
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

    pub fn lastBuilderStatusSlot(self: *const ExecutionRuntime) ?u64 {
        return self.last_builder_status_slot;
    }

    pub fn setLastBuilderStatusSlot(self: *ExecutionRuntime, slot: ?u64) void {
        self.last_builder_status_slot = slot;
    }

    pub fn cachedPayloadId(self: *const ExecutionRuntime) ?[8]u8 {
        return self.cached_payload_id;
    }

    pub fn cachedPayloadFor(
        self: *const ExecutionRuntime,
        slot: u64,
        parent_root: [32]u8,
    ) bool {
        return self.cached_payload_slot == slot and
            self.cached_payload_id != null and
            self.cached_payload_parent_root != null and
            std.mem.eql(u8, &self.cached_payload_parent_root.?, &parent_root);
    }

    pub fn recordPreparedPayloadContext(
        self: *ExecutionRuntime,
        slot: u64,
        parent_root: [32]u8,
    ) void {
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
        if (self.cached_payload_slot != slot) return;
        const cached_parent_root = self.cached_payload_parent_root orelse return;
        if (!std.mem.eql(u8, &cached_parent_root, &parent_root)) return;
        const cached_payload_id = self.cached_payload_id orelse return;
        if (!std.mem.eql(u8, &cached_payload_id, &payload_id)) return;
        self.clearCachedPayload();
    }

    pub fn clearCachedPayload(self: *ExecutionRuntime) void {
        self.cached_payload_id = null;
        self.cached_payload_slot = null;
        self.cached_payload_parent_root = null;
    }
};
