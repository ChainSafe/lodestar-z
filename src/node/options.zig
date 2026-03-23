//! Node configuration options.
//!
//! Runtime configuration for the beacon node. Distinct from BeaconConfig
//! (which is the chain/consensus config derived from the spec) — this covers
//! operational settings: networking, database paths, API binding, etc.

const std = @import("std");

/// Known Ethereum consensus networks.
pub const NetworkName = enum {
    mainnet,
    goerli,
    sepolia,
    holesky,
    hoodi,
    minimal,
};

/// Top-level node configuration.
///
/// These are operational settings — where to listen, how many peers to target,
/// which database directory to use, etc. The actual chain parameters come from
/// `BeaconConfig` (derived from ChainConfig + preset).
pub const NodeOptions = struct {
    // ── Network ──────────────────────────────────────────────────
    listen_addresses: []const []const u8 = &.{"/ip4/0.0.0.0/tcp/9000"},
    bootnodes: []const []const u8 = &.{},
    target_peers: u32 = 50,

    // ── Database ─────────────────────────────────────────────────
    data_dir: []const u8 = "beacon-data",

    // ── Chain ────────────────────────────────────────────────────
    network: NetworkName = .mainnet,

    // ── Execution ────────────────────────────────────────────────
    execution_urls: []const []const u8 = &.{"http://localhost:8551"},
    jwt_secret_path: ?[]const u8 = null,

    // ── API ──────────────────────────────────────────────────────
    rest_address: []const u8 = "127.0.0.1",
    rest_port: u16 = 9596,

    // ── Validator ────────────────────────────────────────────────
    suggested_fee_recipient: ?[20]u8 = null,

    // ── Caches ───────────────────────────────────────────────────
    max_block_states: u32 = 64,
    max_checkpoint_epochs: u32 = 3,
};
