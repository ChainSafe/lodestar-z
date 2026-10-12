const std = @import("std");
const builtin = @import("builtin");
const blst = @import("blst");
const sha256 = @import("sha256.zig");
const StdSha256 = std.crypto.hash.sha2.Sha256;

/// blst reads this on every call to choose between its hardware and portable SHA-256.
extern var __blst_platform_cap: c_int;

/// The bit blst's cpuid.c sets in `__blst_platform_cap` when the CPU has SHA-256 instructions.
const hardware_sha_capability: c_int = switch (builtin.cpu.arch) {
    .x86_64 => 0b10,
    .aarch64 => 0b01,
    else => 0,
};

fn expectDigest(expected_hex: *const [64]u8, message: []const u8) !void {
    var digest: [sha256.digest_length]u8 = undefined;
    sha256.hash(message, &digest);
    try std.testing.expectEqualStrings(expected_hex, &std.fmt.bytesToHex(digest, .lower));
}

fn expectBlstMatchesStdForEveryLength() !void {
    const block_len = StdSha256.block_length;
    var prng = std.Random.DefaultPrng.init(0);
    var message: [5 * block_len]u8 = undefined;
    prng.random().bytes(&message);

    for (0..message.len + 1) |len| {
        var expected: [StdSha256.digest_length]u8 = undefined;
        StdSha256.hash(message[0..len], &expected, .{});
        var actual: [StdSha256.digest_length]u8 = undefined;
        blst.blst_sha256(&actual, &message, len);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
}

test "hash matches known SHA-256 digests" {
    try expectDigest("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "");
    try expectDigest("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
    try expectDigest(
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    );
}

test "blst sha256 matches std for every message length up to five blocks" {
    try expectBlstMatchesStdForEveryLength();
}

test "blst sha256 portable path matches std for every message length up to five blocks" {
    // Hides the detected capability so blst takes its portable path on a CPU that has the
    // instructions.
    const detected = __blst_platform_cap;
    defer __blst_platform_cap = detected;
    __blst_platform_cap = detected & ~hardware_sha_capability;

    try expectBlstMatchesStdForEveryLength();
}
