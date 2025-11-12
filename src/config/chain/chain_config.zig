const std = @import("std");
const ssz = @import("consensus_types");
const Epoch = ssz.primitive.Epoch.Type;
const Preset = @import("preset").Preset;

/// Run-time chain configuration
/// This starts with ChainConfig, similar to typescript version
pub const ChainConfig = struct {
    PRESET_BASE: Preset,
    CONFIG_NAME: []const u8,

    // Transition
    TERMINAL_TOTAL_DIFFICULTY: u256,
    TERMINAL_BLOCK_HASH: [32]u8,
    TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: u64,

    // Genesis
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: u64,
    MIN_GENESIS_TIME: u64,
    GENESIS_FORK_VERSION: [4]u8,
    GENESIS_DELAY: u64,

    // Altair
    ALTAIR_FORK_VERSION: [4]u8,
    ALTAIR_FORK_EPOCH: u64,
    // Bellatrix
    BELLATRIX_FORK_VERSION: [4]u8,
    BELLATRIX_FORK_EPOCH: u64,
    // Capella
    CAPELLA_FORK_VERSION: [4]u8,
    CAPELLA_FORK_EPOCH: u64,
    // DENEB
    DENEB_FORK_VERSION: [4]u8,
    DENEB_FORK_EPOCH: u64,
    // ELECTRA
    ELECTRA_FORK_VERSION: [4]u8,
    ELECTRA_FORK_EPOCH: u64,
    // FULU (assuming it's a future fork, standard pattern)
    FULU_FORK_VERSION: [4]u8,
    FULU_FORK_EPOCH: u64,

    // Time parameters
    SECONDS_PER_SLOT: u64,
    SECONDS_PER_ETH1_BLOCK: u64,
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64,
    SHARD_COMMITTEE_PERIOD: u64,
    ETH1_FOLLOW_DISTANCE: u64,

    // Validator cycle
    INACTIVITY_SCORE_BIAS: u64,
    INACTIVITY_SCORE_RECOVERY_RATE: u64,
    EJECTION_BALANCE: u64,
    MIN_PER_EPOCH_CHURN_LIMIT: u64,
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: u64,
    CHURN_LIMIT_QUOTIENT: u64,
    MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT: u64,
    MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: u64,

    // Fork choice
    PROPOSER_SCORE_BOOST: u64,
    REORG_HEAD_WEIGHT_THRESHOLD: u64,
    REORG_PARENT_WEIGHT_THRESHOLD: u64,
    REORG_MAX_EPOCHS_SINCE_FINALIZATION: u64,

    // Deposit contract
    DEPOSIT_CHAIN_ID: u64,
    DEPOSIT_NETWORK_ID: u64,
    DEPOSIT_CONTRACT_ADDRESS: [20]u8,

    // Networking
    MIN_EPOCHS_FOR_BLOCK_REQUESTS: u64,
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: u64,
    MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS: u64,
    BLOB_SIDECAR_SUBNET_COUNT: u64,
    MAX_BLOBS_PER_BLOCK: u64,
    MAX_REQUEST_BLOB_SIDECARS: u64,
    BLOB_SIDECAR_SUBNET_COUNT_ELECTRA: u64,
    MAX_BLOBS_PER_BLOCK_ELECTRA: u64,
    MAX_REQUEST_BLOB_SIDECARS_ELECTRA: u64,

    SAMPLES_PER_SLOT: u64,
    CUSTODY_REQUIREMENT: u64,
    NODE_CUSTODY_REQUIREMENT: u64,
    VALIDATOR_CUSTODY_REQUIREMENT: u64,
    BALANCE_PER_ADDITIONAL_CUSTODY_GROUP: u64,

    // Blob Scheduling
    BLOB_SCHEDULE: []BlobScheduleEntry,
};

pub const BlobScheduleEntry = struct {
    EPOCH: Epoch,
    MAX_BLOBS_PER_BLOCK: u64,
};

pub fn mergeChainConfig(config: ChainConfig, fields: anytype) ChainConfig {
    var merged = config;
    inline for (std.meta.fields(@TypeOf(fields))) |field| {
        @field(merged, field.name) = @field(fields, field.name);
    }
    return merged;
}

test mergeChainConfig {
    const mainnet_config = @import("./networks/mainnet.zig").mainnet_chain_config;
    const old_altair_epoch = mainnet_config.ALTAIR_FORK_EPOCH;
    const merged_config = mergeChainConfig(mainnet_config, .{
        .ALTAIR_FORK_EPOCH = old_altair_epoch + 1000,
    });
    try std.testing.expect(merged_config.ALTAIR_FORK_EPOCH == old_altair_epoch + 1000);
}
