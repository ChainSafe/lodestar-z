const std = @import("std");
const testing = std.testing;
pub const BeaconConfig = @import("./beacon_config.zig").BeaconConfig;
pub const ChainConfig = @import("./chain/chain_config.zig").ChainConfig;
pub const ForkSeq = @import("./fork.zig").ForkSeq;
pub const ForkInfo = @import("./fork.zig").ForkInfo;
pub const forkSeqByForkName = @import("./fork.zig").forkSeqByForkName;
pub const mergeChainConfig = @import("./chain/chain_config.zig").mergeChainConfig;
pub const TOTAL_FORKS = @import("./fork.zig").TOTAL_FORKS;
pub const mainnet_chain_config = @import("./chain/networks/mainnet.zig").mainnet_chain_config;
pub const minimal_chain_config = @import("./chain/networks/minimal.zig").minimal_chain_config;
pub const gnosis_chain_config = @import("./chain/networks/gnosis.zig").gnosis_chain_config;
pub const chiado_chain_config = @import("./chain/networks/chiado.zig").chiado_chain_config;
pub const sepolia_chain_config = @import("./chain/networks/sepolia.zig").sepolia_chain_config;
pub const hoodi_chain_config = @import("./chain/networks/hoodi.zig").hoodi_chain_config;

test {
    testing.refAllDecls(@This());
}
