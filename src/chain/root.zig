//! Chain module — block import pipeline, operation pools, validator duties,
//! seen caches, block production logic, and the Chain coordinator struct.

const std = @import("std");
const testing = std.testing;

pub const chain = @import("chain.zig");
pub const chain_types = @import("types.zig");
pub const block_import = @import("block_import.zig");
pub const op_pool = @import("op_pool.zig");
pub const seen_cache = @import("seen_cache.zig");
pub const validator_duties = @import("validator_duties.zig");
pub const produce_block = @import("produce_block.zig");
pub const gossip_validation = @import("gossip_validation.zig");

// Chain struct and types
pub const Chain = chain.Chain;
pub const BlockInput = chain_types.BlockInput;
pub const HeadInfo = chain_types.HeadInfo;
pub const SyncStatus = chain_types.SyncStatus;
pub const EventCallback = chain_types.EventCallback;
pub const SseEvent = chain_types.SseEvent;

// Existing re-exports (kept for backward compatibility)
pub const HeadTracker = block_import.HeadTracker;
pub const ImportResult = chain_types.ImportResult;
pub const ImportError = block_import.ImportError;
pub const OpPool = op_pool.OpPool;
pub const SeenCache = seen_cache.SeenCache;
pub const ValidatorDuties = validator_duties.ValidatorDuties;
pub const AttestationDuty = validator_duties.AttestationDuty;
pub const SyncDuty = validator_duties.SyncDuty;
pub const produceBlockBody = produce_block.produceBlockBody;
pub const GossipAction = gossip_validation.GossipAction;
pub const ChainGossipState = gossip_validation.ChainState;
pub const validateGossipBlock = gossip_validation.validateGossipBlock;
pub const validateGossipAttestation = gossip_validation.validateGossipAttestation;
pub const validateGossipAggregate = gossip_validation.validateGossipAggregate;
pub const validateGossipDataColumnSidecar = gossip_validation.validateGossipDataColumnSidecar;
pub const ProducedBlockBody = produce_block.ProducedBlockBody;

test {
    testing.refAllDecls(@This());
}
