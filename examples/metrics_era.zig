//! Simple example to show collection of metrics using metrics.zig, with mainnet era files.
//!
//! Metrics are served on `port` on a separate thread, which is visualized through Prometheus,
//! while we continuously run the state transition function using data from 2 consecutive era files.
//! Run a Prometheus instance to see the data visually.
//!
//! To run this example, run `zig build run:metrics_era`.

const download_era_options = @import("download_era_options");
const era = @import("era");
const c = @import("config");
const std = @import("std");
const httpz = @import("httpz");
const state_transition = @import("state_transition");
const types = @import("consensus_types");

const CachedBeaconStateAllForks = state_transition.CachedBeaconStateAllForks;
const SignedBlock = state_transition.SignedBlock;
const active_preset = @import("preset").active_preset;
const mainnet_chain_config = @import("config").mainnet.chain_config;
const minimal_chain_config = @import("config").minimal.chain_config;
const BeaconConfig = @import("config").BeaconConfig;
const ValidatorIndex = @import("consensus_types").primitive.ValidatorIndex.Type;
const Index2PubkeyCache = state_transition.Index2PubkeyCache;
const PubkeyIndexMap = state_transition.PubkeyIndexMap(ValidatorIndex);
const chain_config = if (active_preset == .mainnet) mainnet_chain_config else minimal_chain_config;

const MetricsHandler = struct {
    allocator: std.mem.Allocator,
};

pub fn serveMetrics(
    allocator: std.mem.Allocator,
    port: u16,
) !void {
    var handler = MetricsHandler{
        .allocator = allocator,
    };
    const address = "0.0.0.0";
    var server = try httpz.Server(*MetricsHandler).init(
        allocator,
        .{ .port = port, .address = address, .thread_pool = .{ .count = 1 } },
        &handler,
    );
    defer {
        server.stop();
        server.deinit();
    }
    var router = try server.router(.{});
    router.get("/metrics", getMetrics, .{});

    std.log.info("Listening at {s}/{d}", .{ address, port });
    try server.listen(); // blocks
}

/// Endpoint to write all state transition metrics to the server.
fn getMetrics(_: *MetricsHandler, _: *httpz.Request, res: *httpz.Response) !void {
    res.content_type = .TEXT;
    const writer = res.writer();
    try state_transition.metrics.write(writer);
}

fn eraReader(allocator: std.mem.Allocator, era_path: []const u8) !era.Reader {
    std.debug.print("Reading era file at {s}\n", .{era_path});
    return try era.Reader.open(allocator, c.mainnet.config, era_path);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    _ = try std.Thread.spawn(.{}, serveMetrics, .{ allocator, 8008 });

    try state_transition.metrics.init(allocator, .{});
    defer state_transition.metrics.state_transition.deinit();

    const era_path_pre = try std.fs.path.join(
        allocator,
        &[_][]const u8{ download_era_options.era_out_dir, download_era_options.era_files[0] },
    );
    defer allocator.free(era_path_pre);
    const era_path_post = try std.fs.path.join(
        allocator,
        &[_][]const u8{ download_era_options.era_out_dir, download_era_options.era_files[1] },
    );
    defer allocator.free(era_path_post);

    var reader_pre = try eraReader(allocator, era_path_pre);
    defer reader_pre.close(allocator);
    var reader_post = try eraReader(allocator, era_path_post);
    defer reader_post.close(allocator);

    std.debug.print("Reading state\n", .{});
    var state_ptr = try allocator.create(state_transition.BeaconStateAllForks);
    errdefer allocator.destroy(state_ptr);
    state_ptr.* = try reader_pre.readState(allocator, null);
    const blocks_index = reader_post.group_indices[0].blocks_index orelse return error.NoBlockIndex;
    const index_pubkey_cache = try allocator.create(Index2PubkeyCache);
    errdefer {
        index_pubkey_cache.deinit();
        allocator.destroy(index_pubkey_cache);
    }
    index_pubkey_cache.* = Index2PubkeyCache.init(allocator);
    const pubkey_index_map = try PubkeyIndexMap.init(allocator);
    errdefer pubkey_index_map.deinit();

    const config = try allocator.create(BeaconConfig);
    errdefer allocator.destroy(config);
    config.* = BeaconConfig.init(chain_config, state_ptr.genesisValidatorsRoot());

    const immutable_data = state_transition.EpochCacheImmutableData{
        .config = config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = pubkey_index_map,
    };

    std.debug.print("Creating cached beacon state\n", .{});
    var cached_state = try CachedBeaconStateAllForks.createCachedBeaconState(
        allocator,
        state_ptr,
        immutable_data,
        .{
            .skip_sync_committee_cache = state_ptr.isPhase0(),
            .skip_sync_pubkeys = false,
        },
    );
    std.debug.print("Running state transition\n", .{});
    for (blocks_index.start_slot + 1..blocks_index.start_slot + blocks_index.offsets.len) |slot| {
        const raw_block = try reader_post.readBlock(allocator, slot) orelse continue;
        defer raw_block.deinit(allocator);

        const block: SignedBlock = .{ .regular = raw_block };

        const block_num = switch (block.message().beaconBlockBody()) {
            .regular => |b| b.executionPayload().getBlockNumber(),
            .blinded => |b| b.executionPayloadHeader().getBlockNumber(),
        };
        std.debug.print("state slot = {}, block number = {}\n", .{ cached_state.state.slot(), block_num });

        const next = try state_transition.stateTransition(
            allocator,
            cached_state,
            block,
            .{
                .verify_signatures = false,
                .verify_proposer = false,
                .verify_state_root = false,
            },
        );

        cached_state.deinit();
        allocator.destroy(cached_state);
        cached_state = next;
    }
}
