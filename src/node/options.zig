//! Node configuration options.
//!
//! Runtime configuration for the beacon node. Distinct from BeaconConfig
//! (which is the chain/consensus config derived from the spec) — this covers
//! node behavior and transport policy after launcher/bootstrap preparation.

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
/// These are runtime behavior settings — where to listen, how many peers to
/// target, which sync/discovery features to enable, etc. Filesystem paths,
/// persisted identity, and JWT secret loading are launcher concerns and are
/// prepared before `BeaconNode.init`.
pub const NodeOptions = struct {
    // ── Network ──────────────────────────────────────────────────
    listen_addresses: []const []const u8 = &.{"/ip4/0.0.0.0/tcp/9000"},
    target_peers: u32 = 50,

    // ── P2P ──────────────────────────────────────────────────────
    /// P2P listen address (IPv4), from --p2p-host. Null disables IPv4.
    p2p_host: ?[]const u8 = null,
    /// P2P listen address (IPv6), from --p2p-host6. Null disables IPv6.
    p2p_host6: ?[]const u8 = null,
    /// P2P listen port (TCP/UDP), from --p2p-port.
    p2p_port: u16 = 9000,
    /// P2P listen port (TCP/UDP) for IPv6, from --p2p-port6.
    p2p_port6: ?u16 = null,

    // ── Discovery ────────────────────────────────────────────────
    /// Enable discv5 peer discovery (default: true).
    enable_discv5: bool = true,
    /// UDP port for discv5 (default: same as p2p port, set via --discovery-port).
    discovery_port: ?u16 = null,
    /// UDP port for discv5 IPv6 (default: same as p2p-port6 or p2p-port).
    discovery_port6: ?u16 = null,
    /// Direct peers to always connect to (multiaddr strings from --direct-peers).
    direct_peers: []const []const u8 = &.{},
    /// Enable mDNS local discovery.
    enable_mdns: bool = false,
    /// Subscribe to all attestation subnets (--subscribe-all-subnets).
    subscribe_all_subnets: bool = false,
    /// Override ENR IPv4 address.
    enr_ip: ?[]const u8 = null,
    /// Override ENR TCP port.
    enr_tcp: ?u16 = null,
    /// Override ENR UDP port.
    enr_udp: ?u16 = null,
    /// Override ENR IPv6 address.
    enr_ip6: ?[]const u8 = null,
    /// Override ENR IPv6 TCP port.
    enr_tcp6: ?u16 = null,
    /// Override ENR IPv6 UDP port.
    enr_udp6: ?u16 = null,
    /// Allow non-local ENR addresses without clearing them.
    nat: bool = false,

    // ── Chain ────────────────────────────────────────────────────
    network: NetworkName = .mainnet,

    // ── Execution ────────────────────────────────────────────────
    execution_urls: []const []const u8 = &.{"http://localhost:8551"},
    /// Use mock execution engine instead of real EL (--engine-mock).
    engine_mock: bool = false,
    /// Number of retry attempts for execution-engine HTTP requests.
    execution_retries: u32 = 3,
    /// Initial delay between execution-engine retry attempts in milliseconds.
    execution_retry_delay_ms: u64 = 100,
    /// Per-request execution-engine HTTP timeout in milliseconds.
    execution_timeout_ms: ?u64 = null,
    /// Enable an external builder relay for proposer block production.
    builder_enabled: bool = false,
    /// Builder relay URL used when builder support is enabled.
    builder_url: []const u8 = "http://localhost:8661",
    /// Per-request builder HTTP timeout in milliseconds.
    builder_timeout_ms: ?u64 = null,
    /// Default builder boost factor percentage for local BN produceBlockV3.
    builder_boost_factor: u64 = 100,
    /// Slot window used for builder circuit-breaker health checks.
    builder_fault_inspection_window: ?u64 = null,
    /// Missed slots tolerated within the inspection window before disabling builder use.
    builder_allowed_faults: ?u64 = null,

    // ── API ──────────────────────────────────────────────────────
    /// Enable the REST HTTP API (--rest flag).
    rest_enabled: bool = false,
    rest_address: []const u8 = "127.0.0.1",
    rest_port: u16 = 5052,
    /// CORS origin for the REST API (--api-cors). Null = same-origin only.
    rest_cors_origin: ?[]const u8 = null,

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

    // ── Validator Monitor ─────────────────────────────────────
    /// Validator indices to monitor for on-chain performance tracking.
    /// Set via --validator-monitor-indices (comma-separated).
    validator_monitor_indices: []const u64 = &.{},
};
