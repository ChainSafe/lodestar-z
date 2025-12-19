const std = @import("std");
const types = @import("consensus_types");
const preset = @import("preset").preset;
const ForkData = types.phase0.ForkData.Type;
const Epoch = types.primitive.Epoch.Type;
const Slot = types.primitive.Slot.Type;
const Version = types.primitive.Version.Type;
const Root = types.primitive.Root.Type;
const DomainType = types.primitive.DomainType.Type;
const c = @import("constants");
const DOMAIN_VOLUNTARY_EXIT = c.DOMAIN_VOLUNTARY_EXIT;
const ALL_DOMAINS = c.ALL_DOMAINS;
const forks = @import("./fork.zig");
const ForkSeq = forks.ForkSeq;
const ForkInfo = forks.ForkInfo;
const TOTAL_FORKS = forks.TOTAL_FORKS;
const forkSeqByForkName = forks.forkSeqByForkName;
const mainnet_chain_config = @import("./chain/networks/mainnet.zig").mainnet_chain_config;

pub const ChainConfig = @import("./chain/chain_config.zig").ChainConfig;

pub const BeaconConfig = struct {
    chain: ChainConfig,
    forks_ascending_epoch_order: [TOTAL_FORKS]ForkInfo,
    forks_descending_epoch_order: [TOTAL_FORKS]ForkInfo,
    genesis_validator_root: Root,
    domain_cache: DomainCache,

    pub fn init(self: *BeaconConfig, chain_config: ChainConfig, genesis_validator_root: Root) !void {
        const phase0 = ForkInfo{
            .fork_seq = ForkSeq.phase0,
            .epoch = 0,
            .version = chain_config.GENESIS_FORK_VERSION,
            .prev_version = [4]u8{ 0, 0, 0, 0 },
            .prev_fork_seq = ForkSeq.phase0,
        };

        const altair = ForkInfo{
            .fork_seq = ForkSeq.altair,
            .epoch = chain_config.ALTAIR_FORK_EPOCH,
            .version = chain_config.ALTAIR_FORK_VERSION,
            .prev_version = chain_config.GENESIS_FORK_VERSION,
            .prev_fork_seq = ForkSeq.phase0,
        };

        const bellatrix = ForkInfo{
            .fork_seq = ForkSeq.bellatrix,
            .epoch = chain_config.BELLATRIX_FORK_EPOCH,
            .version = chain_config.BELLATRIX_FORK_VERSION,
            .prev_version = chain_config.ALTAIR_FORK_VERSION,
            .prev_fork_seq = ForkSeq.altair,
        };

        const capella = ForkInfo{
            .fork_seq = ForkSeq.capella,
            .epoch = chain_config.CAPELLA_FORK_EPOCH,
            .version = chain_config.CAPELLA_FORK_VERSION,
            .prev_version = chain_config.BELLATRIX_FORK_VERSION,
            .prev_fork_seq = ForkSeq.bellatrix,
        };

        const deneb = ForkInfo{
            .fork_seq = ForkSeq.deneb,
            .epoch = chain_config.DENEB_FORK_EPOCH,
            .version = chain_config.DENEB_FORK_VERSION,
            .prev_version = chain_config.CAPELLA_FORK_VERSION,
            .prev_fork_seq = ForkSeq.capella,
        };

        const electra = ForkInfo{
            .fork_seq = ForkSeq.electra,
            .epoch = chain_config.ELECTRA_FORK_EPOCH,
            .version = chain_config.ELECTRA_FORK_VERSION,
            .prev_version = chain_config.DENEB_FORK_VERSION,
            .prev_fork_seq = ForkSeq.deneb,
        };

        const fulu = ForkInfo{
            .fork_seq = ForkSeq.fulu,
            .epoch = chain_config.FULU_FORK_EPOCH,
            .version = chain_config.FULU_FORK_VERSION,
            .prev_version = chain_config.ELECTRA_FORK_VERSION,
            .prev_fork_seq = ForkSeq.electra,
        };

        const forks_ascending_epoch_order = [_]ForkInfo{
            phase0,
            altair,
            bellatrix,
            capella,
            deneb,
            electra,
            fulu,
        };
        const forks_descending_epoch_order = [_]ForkInfo{
            fulu,
            electra,
            deneb,
            capella,
            bellatrix,
            altair,
            phase0,
        };

        self.chain = chain_config;
        self.forks_ascending_epoch_order = forks_ascending_epoch_order;
        self.forks_descending_epoch_order = forks_descending_epoch_order;
        self.genesis_validator_root = genesis_validator_root;
        try self.domain_cache.init(
            forks_ascending_epoch_order,
            genesis_validator_root,
        );
    }

    pub fn deinit(self: *BeaconConfig) void {
        for (self.domain_cache.items) |*domain_by_type| {
            domain_by_type.deinit();
        }
        self.domain_cache.deinit();
        self.allocator.destroy(self);
    }

    pub fn forkInfo(self: *const BeaconConfig, slot: Slot) ForkInfo {
        const epoch = @divFloor(slot, preset.SLOTS_PER_EPOCH);
        return self.forkInfoAtEpoch(epoch);
    }

    pub fn forkInfoAtEpoch(self: *const BeaconConfig, epoch: Epoch) ForkInfo {
        // NOTE: forks must be sorted by descending epoch, latest fork first
        for (self.forks_descending_epoch_order) |fork| {
            if (epoch >= fork.epoch) {
                return fork;
            }
        }

        // phase0
        return self.forks_ascending_epoch_order[@intFromEnum(ForkSeq.phase0)];
    }

    pub fn forkSeq(self: *const BeaconConfig, slot: Slot) ForkSeq {
        return self.forkInfo(slot).fork_seq;
    }

    pub fn forkSeqAtEpoch(self: *const BeaconConfig, epoch: Epoch) ForkSeq {
        return self.forkInfoAtEpoch(epoch).fork_seq;
    }

    pub fn forkVersion(self: *const BeaconConfig, slot: Slot) [4]u8 {
        return self.forkInfo(slot).version;
    }

    // TODO: is forkTypes() necessary?
    // TODO: getPostBellatrixForkTypes
    // TODO: getPostAltairForkTypes
    // TODO: getPostDenebForkTypes
    pub fn getMaxBlobsPerBlock(self: *const BeaconConfig, epoch: Epoch) u64 {
        const fork = self.forkInfoAtEpoch(epoch).fork_seq;
        return switch (fork) {
            .deneb => self.chain.MAX_BLOBS_PER_BLOCK,
            .electra, .fulu => self.chain.MAX_BLOBS_PER_BLOCK_ELECTRA,
            else =>
            // For forks before Deneb, we assume no blobs
            0,
        };
    }

    pub fn getMaxRequestBlobSidecars(self: *const BeaconConfig, fork: ForkSeq) u64 {
        return if (fork.isForkPostElectra()) self.chain.MAX_REQUEST_BLOB_SIDECARS_ELECTRA else self.chain.MAX_REQUEST_BLOB_SIDECARS;
    }

    pub fn getDomain(self: *const BeaconConfig, state_slot: Slot, domain_type: DomainType, message_slot: ?Slot) ![32]u8 {
        const slot = if (message_slot) |s| s else state_slot;
        const epoch = @divFloor(slot, preset.SLOTS_PER_EPOCH);
        const state_fork_info = self.forkInfo(state_slot);
        const fork_seq = if (epoch < state_fork_info.epoch) state_fork_info.prev_fork_seq else state_fork_info.fork_seq;

        return self.getDomainByForkSeq(fork_seq, domain_type);
    }

    // TODO: may not need this method
    pub fn getDomainByForkName(self: *const BeaconConfig, fork_name: []const u8, domain_type: DomainType) ![32]u8 {
        const fork_seq = forkSeqByForkName(fork_name);
        return try self.getDomainByForkSeq(fork_seq, domain_type);
    }

    pub fn getDomainByForkSeq(self: *const BeaconConfig, fork_seq: ForkSeq, domain_type: DomainType) ![32]u8 {
        return self.domain_cache.get(fork_seq, domain_type);
    }

    pub fn getDomainForVoluntaryExit(self: *const BeaconConfig, state_slot: Slot, message_slot: ?Slot) ![32]u8 {
        const domain = if (@divFloor(state_slot, preset.SLOTS_PER_EPOCH) < self.chain.DENEB_FORK_EPOCH) {
            return self.getDomain(state_slot, DOMAIN_VOLUNTARY_EXIT, message_slot);
        } else {
            return self.getDomainByForkSeq(ForkSeq.capella, DOMAIN_VOLUNTARY_EXIT);
        };

        return domain;
    }

    // TODO: forkDigest2ForkName, forkDigest2ForkNameOption, forkName2ForkDigest, forkName2ForkDigestHex
    // may not need it for state-transition
};

/// Domain cache with precomputed domain values for all forks and all domain types.
///
/// Implementation note: uses a fixed-size 2D array for simplicity and performance.
pub const DomainCache = struct {
    inner: [TOTAL_FORKS][ALL_DOMAINS.len][32]u8,

    pub fn init(self: *DomainCache, forks_ascending_epoch_order: [TOTAL_FORKS]ForkInfo, genesis_validators_root: [32]u8) !void {
        for (&self.inner, 0..) |*fork_cache, fork_seq| {
            for (fork_cache, 0..) |*domain_entry, domain_index| {
                const domain_type = ALL_DOMAINS[domain_index];
                try computeDomain(
                    domain_type,
                    forks_ascending_epoch_order[fork_seq].version,
                    genesis_validators_root,
                    domain_entry,
                );
            }
        }
    }

    pub fn get(self: *const DomainCache, fork_seq: ForkSeq, domain_type: DomainType) ![32]u8 {
        if (@intFromEnum(fork_seq) >= TOTAL_FORKS) return error.ForkSeqOutOfRange;
        inline for (ALL_DOMAINS, 0..) |d, i| {
            if (std.mem.eql(u8, &d, &domain_type)) {
                return self.inner[@intFromEnum(fork_seq)][i];
            }
        }
        return error.DomainTypeNotFound;
    }
};

fn computeDomain(domain_type: DomainType, fork_version: Version, genesis_validators_root: Root, out: *[32]u8) !void {
    var fork_data_root: [32]u8 = undefined;
    try computeForkDataRoot(fork_version, genesis_validators_root, &fork_data_root);
    // 4 first bytes is domain_type
    @memcpy(out[0..4], domain_type[0..4]);
    // 28 next bytes is first 28 bytes of fork_data_root
    @memcpy(out[4..32], fork_data_root[0..28]);
}

fn computeForkDataRoot(current_version: Version, genesis_validators_root: Root, out: *[32]u8) !void {
    const fork_data: ForkData = .{
        .current_version = current_version,
        .genesis_validators_root = genesis_validators_root,
    };
    try types.phase0.ForkData.hashTreeRoot(&fork_data, out);
}

test "getDomain" {
    const root = [_]u8{0} ** 32;
    var beacon_config: BeaconConfig = undefined;
    try beacon_config.init(mainnet_chain_config, root);

    const domain = try beacon_config.getDomain(100, DOMAIN_VOLUNTARY_EXIT, null);
    const domain2 = try beacon_config.getDomain(100, DOMAIN_VOLUNTARY_EXIT, null);
    try std.testing.expectEqualSlices(u8, &domain, &domain2);
}
