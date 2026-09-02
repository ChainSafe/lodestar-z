const std = @import("std");
const ct = @import("consensus_types");
const hex = @import("hex");
const BeaconConfig = @import("BeaconConfig.zig");

const Epoch = ct.primitive.Epoch.Type;
const ForkDigest = ct.primitive.ForkDigest.Type;

pub const BlobParameters = struct {
    epoch: Epoch,
    max_blobs_per_block: u64,
};

pub fn getBlobParameters(config: *const BeaconConfig, epoch: Epoch) BlobParameters {
    var best: ?BlobParameters = null;
    for (config.chain.BLOB_SCHEDULE) |entry| {
        if (epoch < entry.EPOCH) continue;
        if (best == null or entry.EPOCH > best.?.epoch) {
            best = .{ .epoch = entry.EPOCH, .max_blobs_per_block = entry.MAX_BLOBS_PER_BLOCK };
        }
    }
    return best orelse .{
        .epoch = config.chain.ELECTRA_FORK_EPOCH,
        .max_blobs_per_block = config.chain.MAX_BLOBS_PER_BLOCK_ELECTRA,
    };
}

pub fn computeForkDigest(config: *const BeaconConfig, epoch: Epoch) ForkDigest {
    const version = config.forkInfoAtEpoch(epoch).version;
    var base: [32]u8 = undefined;
    BeaconConfig.computeForkDataRoot(version, config.genesis_validator_root, &base);
    var digest: ForkDigest = base[0..4].*;
    if (epoch < config.chain.FULU_FORK_EPOCH) return digest;
    const params = getBlobParameters(config, epoch);
    var material: [16]u8 = undefined;
    std.mem.writeInt(u64, material[0..8], params.epoch, .little);
    std.mem.writeInt(u64, material[8..16], params.max_blobs_per_block, .little);
    var mask: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material, &mask, .{});
    for (&digest, mask[0..4]) |*byte, m| byte.* ^= m;
    return digest;
}

const mainnet_genesis_validators_root = hex.hexToBytesComptime(
    32,
    "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
);

test "computeForkDigest reproduces the mainnet digests before Fulu" {
    const mainnet = @import("./networks/mainnet.zig");
    const config = BeaconConfig.init(mainnet.chain_config, mainnet_genesis_validators_root);
    const chain = config.chain;
    try std.testing.expectEqual([4]u8{ 0xb5, 0x30, 0x3f, 0x2a }, computeForkDigest(&config, 0));
    try std.testing.expectEqual(
        [4]u8{ 0xaf, 0xca, 0xab, 0xa0 },
        computeForkDigest(&config, chain.ALTAIR_FORK_EPOCH),
    );
    try std.testing.expectEqual(
        [4]u8{ 0x4a, 0x26, 0xc5, 0x8b },
        computeForkDigest(&config, chain.BELLATRIX_FORK_EPOCH),
    );
    try std.testing.expectEqual(
        [4]u8{ 0xbb, 0xa4, 0xda, 0x96 },
        computeForkDigest(&config, chain.CAPELLA_FORK_EPOCH),
    );
    try std.testing.expectEqual(
        [4]u8{ 0x6a, 0x95, 0xa1, 0xa9 },
        computeForkDigest(&config, chain.DENEB_FORK_EPOCH),
    );
    try std.testing.expectEqual(
        computeForkDigest(&config, chain.DENEB_FORK_EPOCH),
        computeForkDigest(&config, chain.ELECTRA_FORK_EPOCH - 1),
    );
}

test "computeForkDigest masks Fulu digests with the blob schedule" {
    const mainnet = @import("./networks/mainnet.zig");
    const config = BeaconConfig.init(mainnet.chain_config, mainnet_genesis_validators_root);
    const chain = config.chain;
    const fulu_epoch = chain.FULU_FORK_EPOCH;
    const at_fork = computeForkDigest(&config, fulu_epoch);
    const before_fork = computeForkDigest(&config, fulu_epoch - 1);
    try std.testing.expect(!std.mem.eql(u8, &at_fork, &before_fork));

    const params = getBlobParameters(&config, fulu_epoch);
    try std.testing.expectEqual(chain.ELECTRA_FORK_EPOCH, params.epoch);
    try std.testing.expectEqual(chain.MAX_BLOBS_PER_BLOCK_ELECTRA, params.max_blobs_per_block);

    var base: [32]u8 = undefined;
    BeaconConfig.computeForkDataRoot(
        config.forkInfoAtEpoch(fulu_epoch).version,
        config.genesis_validator_root,
        &base,
    );
    var material: [16]u8 = undefined;
    std.mem.writeInt(u64, material[0..8], params.epoch, .little);
    std.mem.writeInt(u64, material[8..16], params.max_blobs_per_block, .little);
    var mask: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material, &mask, .{});
    var expected: [4]u8 = base[0..4].*;
    for (&expected, mask[0..4]) |*byte, m| byte.* ^= m;
    try std.testing.expectEqual(expected, at_fork);

    const first_bpo = chain.BLOB_SCHEDULE[0];
    const at_bpo = computeForkDigest(&config, first_bpo.EPOCH);
    try std.testing.expect(!std.mem.eql(u8, &at_bpo, &at_fork));
    try std.testing.expectEqual(first_bpo.MAX_BLOBS_PER_BLOCK, getBlobParameters(&config, first_bpo.EPOCH).max_blobs_per_block);
    try std.testing.expectEqual(at_bpo, computeForkDigest(&config, first_bpo.EPOCH + 100));
}
