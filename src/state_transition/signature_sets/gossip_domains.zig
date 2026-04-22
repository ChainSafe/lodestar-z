const BeaconConfig = @import("config").BeaconConfig;
const types = @import("consensus_types");

pub const DomainType = types.primitive.DomainType.Type;

pub fn getDomainAtSlot(config: *const BeaconConfig, slot: u64, domain_type: DomainType) !*const [32]u8 {
    return config.domain_cache.get(config.forkSeq(slot), domain_type);
}
