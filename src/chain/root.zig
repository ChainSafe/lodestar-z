//! Chain module — operation pools, validator duties, seen caches, and block
//! production logic.

const std = @import("std");
const testing = std.testing;

pub const op_pool = @import("op_pool.zig");
pub const seen_cache = @import("seen_cache.zig");
pub const validator_duties = @import("validator_duties.zig");
pub const produce_block = @import("produce_block.zig");

pub const OpPool = op_pool.OpPool;
pub const SeenCache = seen_cache.SeenCache;
pub const ValidatorDuties = validator_duties.ValidatorDuties;
pub const AttestationDuty = validator_duties.AttestationDuty;
pub const SyncDuty = validator_duties.SyncDuty;
pub const produceBlockBody = produce_block.produceBlockBody;
pub const ProducedBlockBody = produce_block.ProducedBlockBody;

test {
    testing.refAllDecls(@This());
}
