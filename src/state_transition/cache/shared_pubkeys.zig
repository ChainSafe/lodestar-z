const std = @import("std");
const Allocator = std.mem.Allocator;
const BeaconConfig = @import("config").BeaconConfig;
const types = @import("consensus_types");
const Validator = types.phase0.Validator.Type;
const EpochCacheImmutableData = @import("./epoch_cache.zig").EpochCacheImmutableData;
const pubkey_cache = @import("./pubkey_cache.zig");
const PubkeyIndexMap = pubkey_cache.PubkeyIndexMap;
const Index2PubkeyCache = pubkey_cache.Index2PubkeyCache;
const syncPubkeys = pubkey_cache.syncPubkeys;

/// Application-owned append-only validator pubkey caches.
///
/// The cache is shared by all published states in the process. Validator
/// registries only grow, so historical states can safely borrow any prefix of
/// this cache without requiring a per-state copy.
pub const SharedValidatorPubkeys = struct {
    allocator: Allocator,
    pubkey_to_index: PubkeyIndexMap,
    index_to_pubkey: Index2PubkeyCache,

    pub fn init(allocator: Allocator) SharedValidatorPubkeys {
        return .{
            .allocator = allocator,
            .pubkey_to_index = PubkeyIndexMap.init(allocator),
            .index_to_pubkey = Index2PubkeyCache.init(allocator),
        };
    }

    pub fn deinit(self: *SharedValidatorPubkeys) void {
        self.pubkey_to_index.deinit();
        self.index_to_pubkey.deinit();
    }

    pub fn syncFromValidators(self: *SharedValidatorPubkeys, validators: []const Validator) !void {
        try syncPubkeys(validators, &self.pubkey_to_index, &self.index_to_pubkey);
    }

    pub fn immutableData(
        self: *SharedValidatorPubkeys,
        config: *const BeaconConfig,
    ) EpochCacheImmutableData {
        return .{
            .config = config,
            .pubkey_to_index = &self.pubkey_to_index,
            .index_to_pubkey = &self.index_to_pubkey,
        };
    }

    pub fn ownsStateCaches(
        self: *const SharedValidatorPubkeys,
        pubkey_to_index: *PubkeyIndexMap,
        index_to_pubkey: *Index2PubkeyCache,
    ) bool {
        return pubkey_to_index == &self.pubkey_to_index and index_to_pubkey == &self.index_to_pubkey;
    }
};
