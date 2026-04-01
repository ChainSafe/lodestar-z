const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const api_client = @import("api_client.zig");
const fs = @import("fs.zig");

const log = std.log.scoped(.validator_metadata);

pub const Error = error{
    GenesisTimeMismatch,
    GenesisValidatorsRootMismatch,
    UnsupportedMetadataVersion,
};

pub const GenesisMetadata = struct {
    genesis_time: u64,
    genesis_validators_root: [32]u8,
};

pub fn ensureGenesis(
    io: Io,
    allocator: Allocator,
    path: []const u8,
    genesis: api_client.GenesisResponse,
) !void {
    const expected: GenesisMetadata = .{
        .genesis_time = genesis.genesis_time,
        .genesis_validators_root = genesis.genesis_validators_root,
    };

    const existing = loadGenesis(io, allocator, path) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };

    if (existing) |metadata| {
        if (metadata.genesis_time != expected.genesis_time) {
            log.err("validator genesis_time mismatch expected={d} actual={d}", .{
                expected.genesis_time,
                metadata.genesis_time,
            });
            return error.GenesisTimeMismatch;
        }
        if (!std.mem.eql(u8, &metadata.genesis_validators_root, &expected.genesis_validators_root)) {
            log.err("validator genesis_validators_root mismatch expected=0x{s} actual=0x{s}", .{
                std.fmt.bytesToHex(&expected.genesis_validators_root, .lower),
                std.fmt.bytesToHex(&metadata.genesis_validators_root, .lower),
            });
            return error.GenesisValidatorsRootMismatch;
        }
        return;
    }

    try writeGenesis(io, allocator, path, expected);
    log.info("persisted validator genesis metadata path={s}", .{path});
}

pub fn loadGenesis(io: Io, allocator: Allocator, path: []const u8) !GenesisMetadata {
    const bytes = try fs.readFileAlloc(io, allocator, path, 4096);
    defer allocator.free(bytes);

    const Raw = struct {
        version: ?u32 = null,
        genesis_time: []const u8,
        genesis_validators_root: []const u8,
    };

    var parsed = try std.json.parseFromSlice(Raw, allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const raw = parsed.value;
    if (raw.version) |version| {
        if (version != 1) return error.UnsupportedMetadataVersion;
    }

    var genesis_validators_root: [32]u8 = [_]u8{0} ** 32;
    const gvr_hex = if (std.mem.startsWith(u8, raw.genesis_validators_root, "0x"))
        raw.genesis_validators_root[2..]
    else
        raw.genesis_validators_root;
    if (gvr_hex.len != genesis_validators_root.len * 2) return error.InvalidGenesisValidatorsRoot;
    _ = try std.fmt.hexToBytes(&genesis_validators_root, gvr_hex);

    return .{
        .genesis_time = try std.fmt.parseInt(u64, raw.genesis_time, 10),
        .genesis_validators_root = genesis_validators_root,
    };
}

pub fn writeGenesis(
    io: Io,
    allocator: Allocator,
    path: []const u8,
    metadata: GenesisMetadata,
) !void {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    defer buf.deinit();

    try buf.writer.print(
        "{{\"version\":1,\"genesis_time\":\"{d}\",\"genesis_validators_root\":\"0x{s}\"}}\n",
        .{
            metadata.genesis_time,
            std.fmt.bytesToHex(&metadata.genesis_validators_root, .lower),
        },
    );

    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);

    try file.writePositionalAll(io, buf.written(), 0);
    try file.sync(io);
}

const testing = std.testing;

test "ensureGenesis persists metadata on first run" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    const path = try std.fs.path.join(testing.allocator, &.{ root, "validator-metadata.json" });
    defer testing.allocator.free(path);

    const genesis: api_client.GenesisResponse = .{
        .genesis_time = 1234,
        .genesis_validators_root = [_]u8{0xab} ** 32,
        .genesis_fork_version = [_]u8{0} ** 4,
    };

    try ensureGenesis(testing.io, testing.allocator, path, genesis);

    const loaded = try loadGenesis(testing.io, testing.allocator, path);
    try testing.expectEqual(genesis.genesis_time, loaded.genesis_time);
    try testing.expectEqualSlices(u8, &genesis.genesis_validators_root, &loaded.genesis_validators_root);
}

test "ensureGenesis rejects mismatched metadata" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);

    const path = try std.fs.path.join(testing.allocator, &.{ root, "validator-metadata.json" });
    defer testing.allocator.free(path);

    try writeGenesis(testing.io, testing.allocator, path, .{
        .genesis_time = 1111,
        .genesis_validators_root = [_]u8{0xcd} ** 32,
    });

    try testing.expectError(error.GenesisTimeMismatch, ensureGenesis(testing.io, testing.allocator, path, .{
        .genesis_time = 2222,
        .genesis_validators_root = [_]u8{0xcd} ** 32,
        .genesis_fork_version = [_]u8{0} ** 4,
    }));
}
