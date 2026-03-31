const cli = @import("zig_cli");

pub const spec = cli.command(.{
    .description = "Run a standalone discv5 bootnode",
    .options = .{
        .listen_address = cli.option([]const u8, .{
            .long = "listenAddress",
            .description = "IPv4 address to listen for discv5 connections",
            .env = "LODESTAR_Z_BOOTNODE_LISTEN_ADDRESS",
        }, "0.0.0.0"),
        .bn_port = cli.option(u16, .{
            .long = "port",
            .description = "UDP port for bootnode discv5",
            .env = "LODESTAR_Z_BOOTNODE_PORT",
        }, 9000),
        .listen_address6 = cli.option(?[]const u8, .{
            .long = "listenAddress6",
            .description = "IPv6 address to listen for discv5 connections",
            .env = "LODESTAR_Z_BOOTNODE_LISTEN_ADDRESS6",
        }, null),
        .port6 = cli.option(?u16, .{
            .long = "port6",
            .description = "IPv6 UDP port for bootnode discv5",
            .env = "LODESTAR_Z_BOOTNODE_PORT6",
        }, null),
        .bootnodes = cli.option(?[]const u8, .{
            .long = "bootnodes",
            .description = "Comma-separated list of bootnode ENRs",
            .env = "LODESTAR_Z_BOOTNODE_BOOTNODES",
        }, null),
        .bootnodes_file = cli.option(?[]const u8, .{
            .long = "bootnodesFile",
            .description = "File path with bootnode ENRs (one per line)",
            .env = "LODESTAR_Z_BOOTNODE_BOOTNODES_FILE",
        }, null),
        .enr_ip = cli.option(?[]const u8, .{
            .long = "enr.ip",
            .description = "Override ENR IP entry",
            .env = "LODESTAR_Z_BOOTNODE_ENR_IP",
        }, null),
        .enr_ip6 = cli.option(?[]const u8, .{
            .long = "enr.ip6",
            .description = "Override ENR IPv6 entry",
            .env = "LODESTAR_Z_BOOTNODE_ENR_IP6",
        }, null),
        .enr_udp = cli.option(?u16, .{
            .long = "enr.udp",
            .description = "Override ENR UDP port entry",
            .env = "LODESTAR_Z_BOOTNODE_ENR_UDP",
        }, null),
        .enr_udp6 = cli.option(?u16, .{
            .long = "enr.udp6",
            .description = "Override ENR IPv6 UDP port entry",
            .env = "LODESTAR_Z_BOOTNODE_ENR_UDP6",
        }, null),
        .persist_network_identity = cli.option(bool, .{
            .long = "persistNetworkIdentity",
            .description = "Persist peer-id and ENR across restarts",
            .env = "LODESTAR_Z_BOOTNODE_PERSIST_IDENTITY",
        }, true),
        .nat = cli.option(bool, .{
            .long = "nat",
            .description = "Allow ENR configuration of non-local addresses",
            .env = "LODESTAR_Z_BOOTNODE_NAT",
        }, false),
    },
});
