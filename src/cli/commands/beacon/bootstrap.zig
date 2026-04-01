const std = @import("std");

const Allocator = std.mem.Allocator;

const node_mod = @import("node");
const cli_paths = @import("../../paths.zig");

const BeaconNode = node_mod.BeaconNode;
const NodeIdentity = node_mod.NodeIdentity;
const NodeOptions = node_mod.NodeOptions;
const NetworkName = node_mod.NetworkName;

pub const PreparedRuntime = struct {
    paths: cli_paths.DataPaths,
    node_identity: ?NodeIdentity,
    jwt_secret: ?[32]u8,

    pub fn deinit(self: *PreparedRuntime) void {
        if (self.node_identity) |*node_identity| {
            node_identity.deinit();
        }
        self.paths.deinit();
    }

    pub fn takeInitConfig(self: *PreparedRuntime, options: NodeOptions) BeaconNode.InitConfig {
        const node_identity = self.node_identity.?;
        self.node_identity = null;
        return .{
            .options = options,
            .db_path = self.paths.beacon_db,
            .node_identity = node_identity,
            .jwt_secret = self.jwt_secret,
        };
    }
};

pub fn prepareRuntime(
    allocator: Allocator,
    io: std.Io,
    network: NetworkName,
    data_dir: []const u8,
    db_path_override: ?[]const u8,
    jwt_secret_override: ?[]const u8,
    node_options: NodeOptions,
    needs_execution_auth: bool,
) !PreparedRuntime {
    var paths = try cli_paths.DataPaths.resolve(allocator, .{
        .data_dir = data_dir,
        .network = network,
        .beacon_db = db_path_override,
        .jwt_secret = jwt_secret_override,
    });
    errdefer paths.deinit();

    try paths.ensureDirs(io);

    const node_identity = try node_mod.identity.loadOrCreatePersistentIdentity(
        allocator,
        io,
        .{
            .secret_key = paths.enr_key,
            .enr = paths.enr,
        },
        node_options,
    );
    errdefer {
        var identity = node_identity;
        identity.deinit();
    }

    const jwt_secret = if (needs_execution_auth)
        try node_mod.jwt_mod.loadOrGenerate(io, paths.jwt_secret)
    else
        null;

    return .{
        .paths = paths,
        .node_identity = node_identity,
        .jwt_secret = jwt_secret,
    };
}
