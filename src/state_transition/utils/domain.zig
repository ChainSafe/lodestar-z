const std = @import("std");
const types = @import("consensus_types");
const Domain = types.primitive.Domain.Type;
const Version = types.primitive.Version.Type;
const DomainType = types.primitive.DomainType.Type;
const Root = types.primitive.Root.Type;
const Fork = types.phase0.Fork.Type;
const ForkData = types.phase0.ForkData.Type;
const Epoch = types.primitive.Epoch.Type;

// Only used by processDeposit +  lightclient

/// Return the domain for the [[domainType]] and [[forkVersion]].
pub fn computeDomain(domain_type: DomainType, fork_version: Version, genesis_validator_root: Root, out: *Domain) !void {
    var fork_data_root: Root = undefined;
    try computeForkDataRoot(fork_version, genesis_validator_root, &fork_data_root);
    std.mem.copyForwards(u8, out[0..4], domain_type[0..4]);
    std.mem.copyForwards(u8, out[4..32], fork_data_root[0..28]);
}

/// Return the ForkVersion at an epoch from a Fork type
pub fn forkVersion(fork: Fork, epoch: Epoch) Version {
    return if (epoch < fork.epoch) fork.previous_version else fork.current_version;
}

/// Used primarily in signature domains to avoid collisions across forks/chains.
pub fn computeForkDataRoot(current_version: Version, genesis_validators_root: Root, out: *Root) !void {
    const fork_data: ForkData = .{
        .current_version = current_version,
        .genesis_validators_root = genesis_validators_root,
    };
    try types.phase0.ForkData.hashTreeRoot(&fork_data, out);
}

// ──── Tests ────

const testing = std.testing;

test "computeDomain - domain type is first 4 bytes" {
    const domain_type = [4]u8{ 0x07, 0x00, 0x00, 0x00 }; // DOMAIN_VOLUNTARY_EXIT
    const fork_version = [4]u8{ 0x01, 0x00, 0x00, 0x00 };
    const genesis_root = [_]u8{0} ** 32;
    var domain: Domain = undefined;

    try computeDomain(domain_type, fork_version, genesis_root, &domain);

    // First 4 bytes should be the domain type
    try testing.expectEqualSlices(u8, &domain_type, domain[0..4]);
    // Remaining 28 bytes should be from fork data root (non-zero due to hashing)
    var all_zero = true;
    for (domain[4..32]) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "computeDomain - different domain types produce different domains" {
    const fork_version = [4]u8{ 0x01, 0x00, 0x00, 0x00 };
    const genesis_root = [_]u8{0xAA} ** 32;

    var domain_a: Domain = undefined;
    var domain_b: Domain = undefined;
    const type_a = [4]u8{ 0x00, 0x00, 0x00, 0x00 }; // DOMAIN_BEACON_PROPOSER
    const type_b = [4]u8{ 0x01, 0x00, 0x00, 0x00 }; // DOMAIN_BEACON_ATTESTER

    try computeDomain(type_a, fork_version, genesis_root, &domain_a);
    try computeDomain(type_b, fork_version, genesis_root, &domain_b);

    try testing.expect(!std.mem.eql(u8, &domain_a, &domain_b));
}

test "computeDomain - different fork versions produce different domains" {
    const domain_type = [4]u8{ 0x00, 0x00, 0x00, 0x00 };
    const genesis_root = [_]u8{0xBB} ** 32;

    var domain_a: Domain = undefined;
    var domain_b: Domain = undefined;
    const version_a = [4]u8{ 0x01, 0x00, 0x00, 0x00 };
    const version_b = [4]u8{ 0x02, 0x00, 0x00, 0x00 };

    try computeDomain(domain_type, version_a, genesis_root, &domain_a);
    try computeDomain(domain_type, version_b, genesis_root, &domain_b);

    // First 4 bytes (domain type) are the same
    try testing.expectEqualSlices(u8, domain_a[0..4], domain_b[0..4]);
    // But the fork data root portion differs
    try testing.expect(!std.mem.eql(u8, domain_a[4..32], domain_b[4..32]));
}

test "forkVersion - before fork epoch returns previous version" {
    const fork: Fork = .{
        .previous_version = [4]u8{ 0x01, 0x00, 0x00, 0x00 },
        .current_version = [4]u8{ 0x02, 0x00, 0x00, 0x00 },
        .epoch = 100,
    };
    try testing.expectEqualSlices(u8, &[4]u8{ 0x01, 0x00, 0x00, 0x00 }, &forkVersion(fork, 50));
    try testing.expectEqualSlices(u8, &[4]u8{ 0x01, 0x00, 0x00, 0x00 }, &forkVersion(fork, 99));
}

test "forkVersion - at or after fork epoch returns current version" {
    const fork: Fork = .{
        .previous_version = [4]u8{ 0x01, 0x00, 0x00, 0x00 },
        .current_version = [4]u8{ 0x02, 0x00, 0x00, 0x00 },
        .epoch = 100,
    };
    try testing.expectEqualSlices(u8, &[4]u8{ 0x02, 0x00, 0x00, 0x00 }, &forkVersion(fork, 100));
    try testing.expectEqualSlices(u8, &[4]u8{ 0x02, 0x00, 0x00, 0x00 }, &forkVersion(fork, 200));
}

test "computeForkDataRoot - deterministic" {
    const version = [4]u8{ 0x01, 0x00, 0x00, 0x00 };
    const genesis_root = [_]u8{0xCC} ** 32;
    var root_a: Root = undefined;
    var root_b: Root = undefined;

    try computeForkDataRoot(version, genesis_root, &root_a);
    try computeForkDataRoot(version, genesis_root, &root_b);

    try testing.expectEqualSlices(u8, &root_a, &root_b);
}

test "computeForkDataRoot - different inputs produce different roots" {
    const genesis_root = [_]u8{0xDD} ** 32;
    var root_a: Root = undefined;
    var root_b: Root = undefined;

    try computeForkDataRoot([4]u8{ 0x01, 0x00, 0x00, 0x00 }, genesis_root, &root_a);
    try computeForkDataRoot([4]u8{ 0x02, 0x00, 0x00, 0x00 }, genesis_root, &root_b);

    try testing.expect(!std.mem.eql(u8, &root_a, &root_b));
}
