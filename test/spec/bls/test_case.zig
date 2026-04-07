const std = @import("std");
const io = std.testing.io;

fn readFileToEnd(file: std.Io.File, allocator: std.mem.Allocator, limit: usize) ![]u8 {
    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &read_buf);
    return file_reader.interface.allocRemaining(allocator, @enumFromInt(limit));
}
const yaml = @import("yaml");
const bls = @import("bls");

const Allocator = std.mem.Allocator;

pub fn aggregate(gpa: Allocator, path: std.Io.Dir) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const data_file = try path.openFile(io, "data.yaml", .{});
    defer data_file.close(io);
    const data_bytes = try readFileToEnd(data_file, allocator, 100_000_000);

    const AggregateTestData = struct {
        input: [][]const u8,
        output: []const u8,
    };

    var data_yaml = yaml.Yaml{ .source = data_bytes };
    try data_yaml.load(allocator);
    const aggregate_test_data = try data_yaml.parse(allocator, AggregateTestData);

    {
        const signatures = try allocator.alloc(bls.Signature, aggregate_test_data.input.len);
        defer allocator.free(signatures);

        var sig_buf: [bls.Signature.COMPRESS_SIZE]u8 = undefined;

        for (aggregate_test_data.input, 0..) |sig_hex_bytes, i| {
            const sig_bytes = try std.fmt.hexToBytes(
                &sig_buf,
                sig_hex_bytes[2..], // skip "0x" prefix
            );
            signatures[i] = try bls.Signature.deserialize(sig_bytes);
        }

        // yaml library parses `null` as a string
        if (std.mem.eql(u8, aggregate_test_data.output, "null")) {
            // expect failure
            try std.testing.expectError(bls.BlstError.AggrTypeMismatch, bls.AggregateSignature.aggregate(signatures, true));
        } else {
            const expected = try std.fmt.hexToBytes(
                &sig_buf,
                aggregate_test_data.output[2..], // skip "0x" prefix
            );
            const aggregate_sig = try bls.AggregateSignature.aggregate(signatures, false);
            const actual = aggregate_sig.toSignature().compress();
            try std.testing.expectEqualSlices(u8, expected, &actual);
        }
    }
}

pub fn aggregate_verify(gpa: Allocator, path: std.Io.Dir) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const data_file = try path.openFile(io, "data.yaml", .{});
    defer data_file.close(io);
    const data_bytes = try readFileToEnd(data_file, allocator, 100_000_000);

    const AggregateVerifyTestData = struct {
        input: struct {
            pubkeys: [][]const u8,
            messages: [][]const u8,
            signature: []const u8,
        },
        output: bool,
    };

    var data_yaml = yaml.Yaml{ .source = data_bytes };
    try data_yaml.load(allocator);
    const aggregate_verify_test_data = try data_yaml.parse(allocator, AggregateVerifyTestData);

    {
        const num_sigs = aggregate_verify_test_data.input.pubkeys.len;
        try std.testing.expect(num_sigs == aggregate_verify_test_data.input.messages.len);

        const pubkeys = try allocator.alloc(bls.PublicKey, num_sigs);
        defer allocator.free(pubkeys);
        const messages = try allocator.alloc([32]u8, num_sigs);
        defer allocator.free(messages);

        var pk_buf: [bls.PublicKey.COMPRESS_SIZE]u8 = undefined;
        var sig_buf: [bls.Signature.COMPRESS_SIZE]u8 = undefined;
        var pairing_buf: [bls.Pairing.sizeOf()]u8 align(bls.Pairing.buf_align) = undefined;

        for (aggregate_verify_test_data.input.pubkeys, 0..) |pk_hex_bytes, i| {
            const pk_bytes = try std.fmt.hexToBytes(
                &pk_buf,
                pk_hex_bytes[2..], // skip "0x" prefix
            );
            pubkeys[i] = try bls.PublicKey.deserialize(pk_bytes);
        }

        for (aggregate_verify_test_data.input.messages, 0..) |msg_hex_bytes, i| {
            _ = try std.fmt.hexToBytes(
                messages[i][0..],
                msg_hex_bytes[2..], // skip "0x" prefix
            );
        }

        const sig_bytes = try std.fmt.hexToBytes(
            &sig_buf,
            aggregate_verify_test_data.input.signature[2..], // skip "0x" prefix
        );
        const signature = bls.Signature.deserialize(sig_bytes) catch {
            // if signature is invalid, expect false
            try std.testing.expect(!aggregate_verify_test_data.output);
            return;
        };

        const result = signature.aggregateVerify(
            true,
            &pairing_buf,
            messages,
            bls.DST,
            pubkeys,
            true,
        ) catch false;
        try std.testing.expectEqual(aggregate_verify_test_data.output, result);
    }
}

pub fn fast_aggregate_verify(gpa: Allocator, path: std.Io.Dir) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const data_file = try path.openFile(io, "data.yaml", .{});
    defer data_file.close(io);
    const data_bytes = try readFileToEnd(data_file, allocator, 100_000_000);

    const FastAggregateVerifyTestData = struct {
        input: struct {
            pubkeys: [][]const u8,
            message: []const u8,
            signature: []const u8,
        },
        output: bool,
    };

    var data_yaml = yaml.Yaml{ .source = data_bytes };
    try data_yaml.load(allocator);
    const fast_aggregate_verify_test_data = try data_yaml.parse(allocator, FastAggregateVerifyTestData);

    {
        const num_sigs = fast_aggregate_verify_test_data.input.pubkeys.len;

        const pubkeys = try allocator.alloc(bls.PublicKey, num_sigs);
        defer allocator.free(pubkeys);

        var msg_bytes: [32]u8 = undefined;
        var pk_buf: [bls.PublicKey.COMPRESS_SIZE]u8 = undefined;
        var sig_buf: [bls.Signature.COMPRESS_SIZE]u8 = undefined;
        var pairing_buf: [bls.Pairing.sizeOf()]u8 align(bls.Pairing.buf_align) = undefined;

        for (fast_aggregate_verify_test_data.input.pubkeys, 0..) |pk_hex_bytes, i| {
            const pk_bytes = try std.fmt.hexToBytes(
                &pk_buf,
                pk_hex_bytes[2..], // skip "0x" prefix
            );
            pubkeys[i] = try bls.PublicKey.deserialize(pk_bytes);
        }

        _ = try std.fmt.hexToBytes(
            &msg_bytes,
            fast_aggregate_verify_test_data.input.message[2..], // skip "0x" prefix
        );

        const sig_bytes = try std.fmt.hexToBytes(
            &sig_buf,
            fast_aggregate_verify_test_data.input.signature[2..], // skip "0x" prefix
        );
        const signature = bls.Signature.deserialize(sig_bytes) catch {
            // if signature is invalid, expect false
            try std.testing.expect(!fast_aggregate_verify_test_data.output);
            return;
        };

        const result = signature.fastAggregateVerify(
            true,
            &pairing_buf,
            &msg_bytes,
            bls.DST,
            pubkeys,
            true,
        ) catch false;
        try std.testing.expectEqual(fast_aggregate_verify_test_data.output, result);
    }
}

pub fn sign(gpa: Allocator, path: std.Io.Dir) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const data_file = try path.openFile(io, "data.yaml", .{});
    defer data_file.close(io);
    const data_bytes = try readFileToEnd(data_file, allocator, 100_000_000);

    const SignTestData = struct {
        input: struct {
            privkey: []const u8,
            message: []const u8,
        },
        output: []const u8,
    };

    var data_yaml = yaml.Yaml{ .source = data_bytes };
    try data_yaml.load(allocator);
    const sign_test_data = try data_yaml.parse(allocator, SignTestData);

    {
        var privkey: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&privkey, sign_test_data.input.privkey[2..]); // skip "0x" prefix

        var msg: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&msg, sign_test_data.input.message[2..]); // skip "0x" prefix

        const sk = bls.SecretKey.deserialize(&privkey) catch {
            // if secret key is invalid, expect signature to be "null"
            try std.testing.expect(std.mem.eql(u8, sign_test_data.output, "null"));
            return;
        };

        const sig = sk.sign(&msg, bls.DST, null);
        const actual = sig.compress();

        var sig_buf: [bls.Signature.COMPRESS_SIZE]u8 = undefined;
        const expected = try std.fmt.hexToBytes(&sig_buf, sign_test_data.output[2..]); // skip "0x" prefix

        try std.testing.expectEqualSlices(u8, expected, &actual);
    }
}

pub fn verify(gpa: Allocator, path: std.Io.Dir) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const data_file = try path.openFile(io, "data.yaml", .{});
    defer data_file.close(io);
    const data_bytes = try readFileToEnd(data_file, allocator, 100_000_000);

    const VerifyTestData = struct {
        input: struct {
            pubkey: []const u8,
            message: []const u8,
            signature: []const u8,
        },
        output: bool,
    };

    var data_yaml = yaml.Yaml{ .source = data_bytes };
    try data_yaml.load(allocator);
    const verify_test_data = try data_yaml.parse(allocator, VerifyTestData);

    {
        var pk_buf: [bls.PublicKey.COMPRESS_SIZE]u8 = undefined;
        var sig_buf: [bls.Signature.COMPRESS_SIZE]u8 = undefined;
        var msg_bytes: [32]u8 = undefined;

        const pk_bytes = try std.fmt.hexToBytes(&pk_buf, verify_test_data.input.pubkey[2..]); // skip "0x" prefix
        const pk = bls.PublicKey.deserialize(pk_bytes) catch {
            // if public key is invalid, expect false
            try std.testing.expect(!verify_test_data.output);
            return;
        };

        _ = try std.fmt.hexToBytes(&msg_bytes, verify_test_data.input.message[2..]); // skip "0x" prefix

        const sig_bytes = try std.fmt.hexToBytes(&sig_buf, verify_test_data.input.signature[2..]); // skip "0x" prefix
        const signature = bls.Signature.deserialize(sig_bytes) catch {
            // if signature is invalid, expect false
            try std.testing.expectEqual(verify_test_data.output, false);
            return;
        };

        signature.verify(
            true,
            &msg_bytes,
            bls.DST,
            null,
            &pk,
            true,
        ) catch {
            // if verification fails, expect false
            try std.testing.expectEqual(verify_test_data.output, false);
            return;
        };
        try std.testing.expectEqual(verify_test_data.output, true);
    }
}

pub fn eth_aggregate_pubkeys(gpa: Allocator, path: std.Io.Dir) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const data_file = try path.openFile(io, "data.yaml", .{});
    defer data_file.close(io);
    const data_bytes = try readFileToEnd(data_file, allocator, 100_000_000);

    const EthAggregatePubkeysTestData = struct {
        input: [][]const u8,
        output: []const u8,
    };

    var data_yaml = yaml.Yaml{ .source = data_bytes };
    try data_yaml.load(allocator);
    const eth_aggregate_pubkeys_test_data = try data_yaml.parse(allocator, EthAggregatePubkeysTestData);

    {
        const pubkeys = try allocator.alloc(bls.PublicKey, eth_aggregate_pubkeys_test_data.input.len);
        defer allocator.free(pubkeys);

        var pk_buf: [bls.PublicKey.COMPRESS_SIZE]u8 = undefined;

        for (eth_aggregate_pubkeys_test_data.input, 0..) |pk_hex_bytes, i| {
            const pk_bytes = try std.fmt.hexToBytes(
                &pk_buf,
                pk_hex_bytes[2..], // skip "0x" prefix
            );
            pubkeys[i] = bls.PublicKey.deserialize(pk_bytes) catch {
                // if any public key is invalid, expect output to be "null"
                try std.testing.expect(std.mem.eql(u8, eth_aggregate_pubkeys_test_data.output, "null"));
                return;
            };
        }

        // yaml library parses `null` as a string
        if (std.mem.eql(u8, eth_aggregate_pubkeys_test_data.output, "null")) {
            // expect failure
            _ = bls.AggregatePublicKey.aggregate(pubkeys, true) catch {
                return;
            };
            try std.testing.expect(false);
        } else {
            const expected = try std.fmt.hexToBytes(
                &pk_buf,
                eth_aggregate_pubkeys_test_data.output[2..], // skip "0x" prefix
            );
            const aggregate_pk = try bls.AggregatePublicKey.aggregate(pubkeys, false);
            const actual = aggregate_pk.toPublicKey().compress();
            try std.testing.expectEqualSlices(u8, expected, &actual);
        }
    }
}

pub fn eth_fast_aggregate_verify(gpa: Allocator, path: std.Io.Dir) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    const data_file = try path.openFile(io, "data.yaml", .{});
    defer data_file.close(io);
    const data_bytes = try readFileToEnd(data_file, allocator, 100_000_000);

    const EthFastAggregateVerifyTestData = struct {
        input: struct {
            pubkeys: [][]const u8,
            message: []const u8,
            signature: []const u8,
        },
        output: bool,
    };

    var data_yaml = yaml.Yaml{ .source = data_bytes };
    try data_yaml.load(allocator);
    const eth_fast_aggregate_verify_test_data = try data_yaml.parse(allocator, EthFastAggregateVerifyTestData);

    {
        const num_sigs = eth_fast_aggregate_verify_test_data.input.pubkeys.len;

        const pubkeys = try allocator.alloc(bls.PublicKey, num_sigs);
        defer allocator.free(pubkeys);

        var msg_bytes: [32]u8 = undefined;
        var pk_buf: [bls.PublicKey.COMPRESS_SIZE]u8 = undefined;
        var sig_buf: [bls.Signature.COMPRESS_SIZE]u8 = undefined;
        var pairing_buf: [bls.Pairing.sizeOf()]u8 align(bls.Pairing.buf_align) = undefined;

        for (eth_fast_aggregate_verify_test_data.input.pubkeys, 0..) |pk_hex_bytes, i| {
            const pk_bytes = try std.fmt.hexToBytes(
                &pk_buf,
                pk_hex_bytes[2..], // skip "0x" prefix
            );
            pubkeys[i] = bls.PublicKey.deserialize(pk_bytes) catch {
                // if any public key is invalid, expect false
                try std.testing.expect(!eth_fast_aggregate_verify_test_data.output);
                return;
            };
        }

        _ = try std.fmt.hexToBytes(
            &msg_bytes,
            eth_fast_aggregate_verify_test_data.input.message[2..], // skip "0x" prefix
        );

        const sig_bytes = try std.fmt.hexToBytes(
            &sig_buf,
            eth_fast_aggregate_verify_test_data.input.signature[2..], // skip "0x" prefix
        );
        const signature = bls.Signature.deserialize(sig_bytes) catch {
            // if signature is invalid, expect false
            try std.testing.expect(!eth_fast_aggregate_verify_test_data.output);
            return;
        };
        if (pubkeys.len == 0 and signature.isInfinity()) {
            try std.testing.expectEqual(eth_fast_aggregate_verify_test_data.output, true);
            return;
        }
        const result = signature.fastAggregateVerify(
            true,
            &pairing_buf,
            &msg_bytes,
            bls.DST,
            pubkeys,
            true,
        ) catch false;
        try std.testing.expectEqual(eth_fast_aggregate_verify_test_data.output, result);
    }
}
