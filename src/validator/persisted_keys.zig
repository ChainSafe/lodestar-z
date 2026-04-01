const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const types = @import("types.zig");
const PersistencePaths = types.PersistencePaths;
const ProposerConfig = types.ProposerConfig;
const ProposerConfigEntry = types.ProposerConfigEntry;
const KeystoreLock = @import("keystore_lock.zig").KeystoreLock;

pub const WriteKeystoreOptions = struct {
    hold_lock: bool = false,
    persist_if_duplicate: bool = false,
};

pub const WriteKeystoreResult = struct {
    lock: ?KeystoreLock = null,
};

pub fn formatPubkeyHex(pubkey: [48]u8) [98]u8 {
    var out: [98]u8 = undefined;
    out[0] = '0';
    out[1] = 'x';
    _ = std.fmt.bufPrint(out[2..], "{x}", .{pubkey}) catch unreachable;
    return out;
}

pub fn writeKeystore(
    io: Io,
    allocator: Allocator,
    paths: PersistencePaths,
    pubkey: [48]u8,
    keystore_json: []const u8,
    password: []const u8,
    options: WriteKeystoreOptions,
) !WriteKeystoreResult {
    const pubkey_hex = formatPubkeyHex(pubkey);

    const keystore_dir = try std.fs.path.join(allocator, &.{ paths.keystores_dir, &pubkey_hex });
    defer allocator.free(keystore_dir);
    try Io.Dir.cwd().createDirPath(io, keystore_dir);
    try Io.Dir.cwd().createDirPath(io, paths.secrets_dir);

    const keystore_path = try std.fs.path.join(allocator, &.{ keystore_dir, "voting-keystore.json" });
    defer allocator.free(keystore_path);
    const secret_path = try std.fs.path.join(allocator, &.{ paths.secrets_dir, &pubkey_hex });
    defer allocator.free(secret_path);

    var file = try Io.Dir.cwd().createFile(io, keystore_path, .{
        .read = options.hold_lock,
        .truncate = true,
        .exclusive = !options.persist_if_duplicate,
        .lock = if (options.hold_lock) .exclusive else .none,
        .lock_nonblocking = options.hold_lock,
    });
    errdefer file.close(io);

    try file.writePositionalAll(io, keystore_json, 0);
    try file.sync(io);

    const secret_file = try Io.Dir.cwd().createFile(io, secret_path, .{ .truncate = true });
    defer secret_file.close(io);
    try secret_file.writePositionalAll(io, password, 0);
    try secret_file.sync(io);

    if (!options.hold_lock) {
        file.close(io);
        return .{};
    }

    return .{
        .lock = try KeystoreLock.fromLockedFile(allocator, keystore_path, pubkey, file),
    };
}

pub fn deleteKeystore(
    io: Io,
    allocator: Allocator,
    paths: PersistencePaths,
    pubkey: [48]u8,
) !bool {
    const pubkey_hex = formatPubkeyHex(pubkey);

    const keystore_dir = try std.fs.path.join(allocator, &.{ paths.keystores_dir, &pubkey_hex });
    defer allocator.free(keystore_dir);
    const keystore_path = try std.fs.path.join(allocator, &.{ keystore_dir, "voting-keystore.json" });
    defer allocator.free(keystore_path);
    const secret_path = try std.fs.path.join(allocator, &.{ paths.secrets_dir, &pubkey_hex });
    defer allocator.free(secret_path);

    var deleted_any = false;

    Io.Dir.cwd().deleteFile(io, keystore_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    pathExists(io, keystore_path) catch {
        deleted_any = true;
    };

    Io.Dir.cwd().deleteFile(io, secret_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    pathExists(io, secret_path) catch {
        deleted_any = true;
    };

    Io.Dir.cwd().deleteDir(io, keystore_dir) catch |err| switch (err) {
        error.FileNotFound => {},
        error.DirNotEmpty => {},
        else => return err,
    };

    return deleted_any;
}

pub fn writeRemoteKey(
    io: Io,
    allocator: Allocator,
    paths: PersistencePaths,
    pubkey: [48]u8,
    url: []const u8,
    persist_if_duplicate: bool,
) !bool {
    const pubkey_hex = formatPubkeyHex(pubkey);
    const definition_path = try std.fs.path.join(allocator, &.{ paths.remote_keys_dir, &pubkey_hex });
    defer allocator.free(definition_path);

    try Io.Dir.cwd().createDirPath(io, paths.remote_keys_dir);

    const file = Io.Dir.cwd().createFile(io, definition_path, .{
        .truncate = true,
        .exclusive = !persist_if_duplicate,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => return false,
        else => return err,
    };
    defer file.close(io);

    const definition = try std.fmt.allocPrint(
        allocator,
        "{{\"pubkey\":\"{s}\",\"url\":\"{s}\",\"readonly\":false}}\n",
        .{ pubkey_hex, url },
    );
    defer allocator.free(definition);

    try file.writePositionalAll(io, definition, 0);
    try file.sync(io);
    return true;
}

pub fn deleteRemoteKey(
    io: Io,
    allocator: Allocator,
    paths: PersistencePaths,
    pubkey: [48]u8,
) !bool {
    const pubkey_hex = formatPubkeyHex(pubkey);
    const definition_path = try std.fs.path.join(allocator, &.{ paths.remote_keys_dir, &pubkey_hex });
    defer allocator.free(definition_path);

    Io.Dir.cwd().deleteFile(io, definition_path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

pub fn writeProposerConfig(
    io: Io,
    allocator: Allocator,
    paths: PersistencePaths,
    pubkey: [48]u8,
    config: ?ProposerConfig,
) !bool {
    const effective = config orelse return deleteProposerConfig(io, allocator, paths, pubkey);
    if (configIsEmpty(effective)) return deleteProposerConfig(io, allocator, paths, pubkey);

    const pubkey_hex = formatPubkeyHex(pubkey);
    const path = try std.fs.path.join(allocator, &.{ paths.proposer_dir, &pubkey_hex });
    defer allocator.free(path);

    try Io.Dir.cwd().createDirPath(io, paths.proposer_dir);

    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);

    const json = try serializeProposerConfig(allocator, effective);
    defer allocator.free(json);

    try file.writePositionalAll(io, json, 0);
    try file.sync(io);
    return true;
}

pub fn deleteProposerConfig(
    io: Io,
    allocator: Allocator,
    paths: PersistencePaths,
    pubkey: [48]u8,
) !bool {
    const pubkey_hex = formatPubkeyHex(pubkey);
    const path = try std.fs.path.join(allocator, &.{ paths.proposer_dir, &pubkey_hex });
    defer allocator.free(path);

    Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

pub fn readProposerConfigs(
    io: Io,
    allocator: Allocator,
    proposer_dir: []const u8,
) ![]ProposerConfigEntry {
    var dir = std.Io.Dir.cwd().openDir(io, proposer_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    defer dir.close(io);

    var entries = std.ArrayListUnmanaged(ProposerConfigEntry).empty;
    errdefer entries.deinit(allocator);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;

        const pubkey_hex = if (std.mem.startsWith(u8, entry.name, "0x")) entry.name[2..] else entry.name;
        if (pubkey_hex.len != 96) return error.InvalidProposerConfig;

        var pubkey: [48]u8 = undefined;
        _ = std.fmt.hexToBytes(&pubkey, pubkey_hex) catch return error.InvalidProposerConfig;

        const path = try std.fs.path.join(allocator, &.{ proposer_dir, entry.name });
        defer allocator.free(path);
        const bytes = try @import("fs.zig").readFileAlloc(io, allocator, path, 16 * 1024);
        defer allocator.free(bytes);

        try entries.append(allocator, .{
            .pubkey = pubkey,
            .config = try parseProposerConfig(allocator, bytes),
        });
    }

    return try entries.toOwnedSlice(allocator);
}

const testing = std.testing;

test "writeRemoteKey persists one signer definition" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const remote_keys_dir = try std.fs.path.join(testing.allocator, &.{ root, "remoteKeys" });
    defer testing.allocator.free(remote_keys_dir);

    const pubkey: [48]u8 = [_]u8{0x42} ** 48;
    try testing.expect(try writeRemoteKey(testing.io, testing.allocator, .{
        .keystores_dir = "",
        .secrets_dir = "",
        .remote_keys_dir = remote_keys_dir,
        .proposer_dir = "",
    }, pubkey, "http://127.0.0.1:9000", false));

    const pubkey_hex = formatPubkeyHex(pubkey);
    const path = try std.fs.path.join(testing.allocator, &.{ remote_keys_dir, &pubkey_hex });
    defer testing.allocator.free(path);
    const contents = try @import("fs.zig").readFileAlloc(testing.io, testing.allocator, path, 1024);
    defer testing.allocator.free(contents);
    try testing.expect(std.mem.indexOf(u8, contents, "\"url\":\"http://127.0.0.1:9000\"") != null);
}

test "writeProposerConfig round-trips persisted proposer settings" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const proposer_dir = try std.fs.path.join(testing.allocator, &.{ root, "proposerConfigs" });
    defer testing.allocator.free(proposer_dir);

    const pubkey: [48]u8 = [_]u8{0x42} ** 48;
    const config = ProposerConfig{
        .fee_recipient = [_]u8{0xaa} ** 20,
        .graffiti = textToGraffiti("lodestar-z"),
        .gas_limit = 60_000_000,
        .builder_selection = .maxprofit,
        .builder_boost_factor = 123,
    };

    try testing.expect(try writeProposerConfig(testing.io, testing.allocator, .{
        .keystores_dir = "",
        .secrets_dir = "",
        .remote_keys_dir = "",
        .proposer_dir = proposer_dir,
    }, pubkey, config));

    const loaded = try readProposerConfigs(testing.io, testing.allocator, proposer_dir);
    defer if (loaded.len > 0) testing.allocator.free(loaded);

    try testing.expectEqual(@as(usize, 1), loaded.len);
    try testing.expectEqualSlices(u8, &pubkey, &loaded[0].pubkey);
    try testing.expectEqualSlices(u8, &config.fee_recipient.?, &loaded[0].config.fee_recipient.?);
    try testing.expectEqualSlices(u8, &config.graffiti.?, &loaded[0].config.graffiti.?);
    try testing.expectEqual(config.gas_limit, loaded[0].config.gas_limit);
    try testing.expectEqual(config.builder_selection, loaded[0].config.builder_selection);
    try testing.expectEqual(config.builder_boost_factor, loaded[0].config.builder_boost_factor);
}

fn pathExists(io: Io, path: []const u8) !void {
    try Io.Dir.cwd().access(io, path, .{});
}

fn configIsEmpty(config: ProposerConfig) bool {
    return config.fee_recipient == null and
        config.graffiti == null and
        config.gas_limit == null and
        config.builder_selection == null and
        config.builder_boost_factor == null and
        config.strict_fee_recipient_check == null;
}

pub fn serializeProposerConfig(allocator: Allocator, config: ProposerConfig) ![]u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    const writer = &buf.writer;

    try writer.writeByte('{');
    var wrote_field = false;

    if (config.graffiti) |graffiti| {
        const graffiti_text = try graffitiToText(allocator, graffiti);
        defer allocator.free(graffiti_text);
        try writer.print("\"graffiti\":{f}", .{std.json.fmt(graffiti_text, .{})});
        wrote_field = true;
    }
    if (config.strict_fee_recipient_check) |strict| {
        if (wrote_field) try writer.writeByte(',');
        try writer.print("\"strictFeeRecipientCheck\":{s}", .{if (strict) "true" else "false"});
        wrote_field = true;
    }
    if (config.fee_recipient) |fee_recipient| {
        if (wrote_field) try writer.writeByte(',');
        var fee_hex: [42]u8 = undefined;
        fee_hex[0] = '0';
        fee_hex[1] = 'x';
        _ = std.fmt.bufPrint(fee_hex[2..], "{x}", .{fee_recipient}) catch unreachable;
        try writer.print("\"feeRecipient\":\"{s}\"", .{fee_hex});
        wrote_field = true;
    }
    if (config.builder_selection != null or config.gas_limit != null or config.builder_boost_factor != null) {
        if (wrote_field) try writer.writeByte(',');
        try writer.writeAll("\"builder\":{");
        var wrote_builder_field = false;
        if (config.builder_selection) |selection| {
            try writer.print("\"selection\":{f}", .{std.json.fmt(selection.queryValue(), .{})});
            wrote_builder_field = true;
        }
        if (config.gas_limit) |gas_limit| {
            if (wrote_builder_field) try writer.writeByte(',');
            try writer.print("\"gasLimit\":{d}", .{gas_limit});
            wrote_builder_field = true;
        }
        if (config.builder_boost_factor) |boost_factor| {
            if (wrote_builder_field) try writer.writeByte(',');
            try writer.print("\"boostFactor\":\"{d}\"", .{boost_factor});
        }
        try writer.writeByte('}');
    }

    try writer.writeByte('}');
    return buf.toOwnedSlice();
}

fn parseProposerConfig(allocator: Allocator, bytes: []const u8) !ProposerConfig {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), bytes, .{});
    const object = switch (parsed.value) {
        .object => |value| value,
        else => return error.InvalidProposerConfig,
    };

    var config = ProposerConfig{};

    if (object.get("graffiti")) |graffiti_value| {
        const graffiti_text = switch (graffiti_value) {
            .string => |value| value,
            else => return error.InvalidProposerConfig,
        };
        if (!std.unicode.utf8ValidateSlice(graffiti_text)) return error.InvalidProposerConfig;
        config.graffiti = textToGraffiti(graffiti_text);
    }
    if (object.get("strictFeeRecipientCheck")) |strict_value| {
        config.strict_fee_recipient_check = switch (strict_value) {
            .bool => |value| value,
            else => return error.InvalidProposerConfig,
        };
    }
    if (object.get("feeRecipient")) |fee_value| {
        const fee_text = switch (fee_value) {
            .string => |value| value,
            else => return error.InvalidProposerConfig,
        };
        config.fee_recipient = try parseFeeRecipient(fee_text);
    }
    if (object.get("builder")) |builder_value| {
        const builder = switch (builder_value) {
            .object => |value| value,
            else => return error.InvalidProposerConfig,
        };
        if (builder.get("selection")) |selection_value| {
            const selection_text = switch (selection_value) {
                .string => |value| value,
                .number_string => |value| value,
                else => return error.InvalidProposerConfig,
            };
            config.builder_selection = try types.BuilderSelection.parse(selection_text);
        }

        if (builder.get("gasLimit")) |gas_limit_value| {
            config.gas_limit = switch (gas_limit_value) {
                .integer => |value| std.math.cast(u64, value) orelse return error.InvalidProposerConfig,
                .number_string => |value| try std.fmt.parseInt(u64, value, 10),
                else => return error.InvalidProposerConfig,
            };
        }
        if (builder.get("boostFactor")) |boost_value| {
            const boost_text = switch (boost_value) {
                .string => |value| value,
                .number_string => |value| value,
                else => return error.InvalidProposerConfig,
            };
            config.builder_boost_factor = try std.fmt.parseInt(u64, boost_text, 10);
        }
    }

    return config;
}

fn textToGraffiti(text: []const u8) [32]u8 {
    var graffiti: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(text.len, graffiti.len);
    @memcpy(graffiti[0..copy_len], text[0..copy_len]);
    return graffiti;
}

fn graffitiToText(allocator: Allocator, graffiti: [32]u8) ![]u8 {
    var end = graffiti.len;
    while (end > 0 and graffiti[end - 1] == 0) {
        end -= 1;
    }
    const text = graffiti[0..end];
    if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidGraffiti;
    return allocator.dupe(u8, text);
}

fn parseFeeRecipient(input: []const u8) ![20]u8 {
    const hex = if (std.mem.startsWith(u8, input, "0x")) input[2..] else input;
    if (hex.len != 40) return error.InvalidFeeRecipient;

    var fee_recipient: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&fee_recipient, hex) catch return error.InvalidFeeRecipient;
    return fee_recipient;
}
