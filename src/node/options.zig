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

    // ── P2P ──────────────────────────────────────────────────────
    /// P2P listen address (IPv4), from --p2p-host.
    p2p_host: []const u8 = "0.0.0.0",
    /// P2P listen port (TCP/UDP), from --p2p-port.
    p2p_port: u16 = 9000,

    // ── Discovery ────────────────────────────────────────────────
    /// Enable discv5 peer discovery (default: true).
    enable_discv5: bool = true,
    /// UDP port for discv5 (default: same as p2p port, set via --discovery-port).
    discovery_port: ?u16 = null,
    /// Direct peers to always connect to (multiaddr strings from --direct-peers).
    direct_peers: []const []const u8 = &.{},
    /// Enable mDNS local discovery.
    enable_mdns: bool = false,
    /// Subscribe to all attestation subnets (--subscribe-all-subnets).
    subscribe_all_subnets: bool = false,

    // ── Database ─────────────────────────────────────────────────
    data_dir: []const u8 = "",

    // ── Chain ────────────────────────────────────────────────────
    network: NetworkName = .mainnet,

    // ── Execution ────────────────────────────────────────────────
    execution_urls: []const []const u8 = &.{"http://localhost:8551"},
    jwt_secret_path: ?[]const u8 = null,
    /// Use mock execution engine instead of real EL (--engine-mock).
    engine_mock: bool = false,

    // ── API ──────────────────────────────────────────────────────
    /// Enable the REST HTTP API (--rest flag).
    rest_enabled: bool = false,
    rest_address: []const u8 = "127.0.0.1",
    rest_port: u16 = 5052,

    // ── Metrics ──────────────────────────────────────────────────
    /// Enable Prometheus metrics HTTP server (--metrics flag).
    metrics_enabled: bool = false,
    metrics_address: []const u8 = "127.0.0.1",
    metrics_port: u16 = 8008,

    // ── Validator ────────────────────────────────────────────────
    suggested_fee_recipient: ?[20]u8 = null,
    /// Custom graffiti string (UTF-8, max 32 bytes, zero-padded).
    /// Set via --graffiti CLI option. When null, defaults to "lodestar-z".
    graffiti: ?[32]u8 = null,

    // ── Validator Client (VC mode) ────────────────────────────────
    /// Path to directory containing EIP-2335 keystore files (--validator-keys).
    validator_keys_dir: ?[]const u8 = null,
    /// Path to directory containing keystore password files (--validator-secrets).
    validator_secrets_dir: ?[]const u8 = null,
    /// Beacon node REST API URL for the VC to connect to (--beacon-node-url).
    beacon_node_url: []const u8 = "http://localhost:5052",
    /// Enable doppelganger protection: wait one epoch before attesting to detect
    /// another instance signing for the same validator (--doppelganger-detection).
    doppelganger_detection: bool = false,
    /// URL of a Web3Signer remote signing service (--web3signer-url).
    /// When set, signing is delegated to the external service instead of local keys.
    web3signer_url: ?[]const u8 = null,

    // ── Sync ─────────────────────────────────────────────────────
    /// URL to fetch checkpoint state from a beacon API (--checkpoint-sync-url).
    checkpoint_sync_url: ?[]const u8 = null,

    // ── Caches ───────────────────────────────────────────────────
    max_block_states: u32 = 64,
    max_checkpoint_epochs: u32 = 3,

    // ── Validation ───────────────────────────────────────────────
    /// When true, BLS signatures are verified during block import.
    /// Defaults to false for performance / test convenience.
    verify_signatures: bool = false,
};
