const std = @import("std");
const ct = @import("consensus_types");

const BeaconConfig = @import("BeaconConfig.zig");

const Epoch = ct.primitive.Epoch.Type;
const ForkDigest = ct.primitive.ForkDigest.Type;

pub fn computeForkDigest(config: *const BeaconConfig, epoch: Epoch) ForkDigest {
    const version = config.forkInfoAtEpoch(epoch).version;
    var base: [32]u8 = undefined;
    BeaconConfig.computeForkDataRoot(version, config.genesis_validator_root, &base);
    var digest: ForkDigest = base[0..4].*;
    if (epoch < config.chain.FULU_FORK_EPOCH) return digest;
    const params = config.getBlobParameters(epoch);
    var material: [16]u8 = undefined;
    std.mem.writeInt(u64, material[0..8], params.epoch, .little);
    std.mem.writeInt(u64, material[8..16], params.max_blobs_per_block, .little);
    var mask: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material, &mask, .{});
    for (&digest, mask[0..4]) |*byte, m| byte.* ^= m;
    return digest;
}

test {
    _ = @import("fork_digest_test.zig");
}
