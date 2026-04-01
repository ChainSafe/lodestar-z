const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const api_mod = @import("api");
const config_mod = @import("config");
const validator_mod = @import("validator");

pub const Config = struct {
    address: []const u8,
    port: u16,
    cors_origin: ?[]const u8,
    auth_enabled: bool,
    token_file: []const u8,
    body_limit: usize,
};

pub const Runtime = struct {
    io: Io,
    allocator: Allocator,
    client: *validator_mod.ValidatorClient,
    config: Config,
    keymanager_runtime: validator_mod.KeymanagerRuntime,
    api_context: api_mod.ApiContext,
    server: api_mod.HttpServer,
    node_identity: api_mod.types.NodeIdentity,
    thread_handle: ?std.Thread = null,

    pub fn init(
        io: Io,
        allocator: Allocator,
        client: *validator_mod.ValidatorClient,
        beacon_config: *const config_mod.BeaconConfig,
        config: Config,
    ) !Runtime {
        var auth: ?validator_mod.KeymanagerAuth = null;
        if (config.auth_enabled) {
            auth = try validator_mod.KeymanagerAuth.loadOrGenerate(io, allocator, config.token_file);
        }

        const keymanager_runtime = validator_mod.KeymanagerRuntime.init(io, allocator, client, auth);

        var runtime = Runtime{
            .io = io,
            .allocator = allocator,
            .client = client,
            .config = config,
            .keymanager_runtime = keymanager_runtime,
            .node_identity = .{
                .peer_id = "",
                .enr = "",
                .p2p_addresses = &.{},
                .discovery_addresses = &.{},
                .metadata = .{
                    .seq_number = 0,
                    .attnets = [_]u8{0} ** 8,
                    .syncnets = [_]u8{0},
                },
            },
            .api_context = undefined,
            .server = undefined,
        };

        runtime.api_context = .{
            .node_identity = &runtime.node_identity,
            .beacon_config = beacon_config,
            .allocator = allocator,
            .keymanager = runtime.keymanager_runtime.callback(),
        };
        runtime.server = api_mod.HttpServer.initWithOptions(
            allocator,
            &runtime.api_context,
            config.address,
            config.port,
            .{
                .cors_origin = config.cors_origin,
                .allow_keymanager_cors = true,
                .allowed_operation_ids = &.{
                    "listKeystores",
                    "importKeystores",
                    "deleteKeystores",
                    "listRemoteKeys",
                    "importRemoteKeys",
                    "deleteRemoteKeys",
                    "listFeeRecipient",
                    "setFeeRecipient",
                    "deleteFeeRecipient",
                    "getGraffiti",
                    "setGraffiti",
                    "deleteGraffiti",
                    "getGasLimit",
                    "setGasLimit",
                    "deleteGasLimit",
                    "getBuilderBoostFactor",
                    "setBuilderBoostFactor",
                    "deleteBuilderBoostFactor",
                    "getProposerConfig",
                    "signVoluntaryExit",
                },
                .max_body_bytes = config.body_limit,
                .max_block_body_bytes = config.body_limit,
            },
        );
        return runtime;
    }

    pub fn deinit(self: *Runtime) void {
        self.keymanager_runtime.deinit();
    }

    pub fn start(self: *Runtime) !void {
        self.thread_handle = try std.Thread.spawn(.{}, struct {
            fn run(runtime: *Runtime) void {
                runtime.server.serve(runtime.io) catch |err| {
                    std.log.err("validator keymanager server stopped: {s}", .{@errorName(err)});
                };
            }
        }.run, .{self});

        while (true) {
            switch (self.server.startupStatus()) {
                .idle => try self.io.sleep(.{ .nanoseconds = 10 * std.time.ns_per_ms }, .real),
                .started => break,
                .failed => return error.KeymanagerServerStartFailed,
            }
        }

        std.log.info("validator keymanager API listening on {s}:{d}", .{ self.config.address, self.config.port });
        if (self.config.auth_enabled) {
            std.log.info("validator keymanager bearer token: {s}", .{self.config.token_file});
        } else {
            std.log.warn("validator keymanager started without bearer authentication", .{});
        }
    }

    pub fn stop(self: *Runtime) void {
        self.server.shutdown(self.io);
        if (self.thread_handle) |thread| {
            thread.join();
            self.thread_handle = null;
        }
    }
};
