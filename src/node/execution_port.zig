//! Node-owned execution adapter for the chain execution port.
//!
//! The chain prepares explicit `engine_newPayload` requests and the node is
//! responsible only for submitting them to the configured EL client and
//! translating the response into chain-facing semantics.

const std = @import("std");

const chain_mod = @import("chain");
const execution_mod = @import("execution");

const BeaconNode = @import("beacon_node.zig").BeaconNode;

const ExecutionPort = chain_mod.ExecutionPort;
const NewPayloadRequest = chain_mod.NewPayloadRequest;
const NewPayloadResult = chain_mod.NewPayloadResult;

pub fn make(node: *BeaconNode) ExecutionPort {
    return .{
        .ptr = @ptrCast(node),
        .submitNewPayloadFn = &submitNewPayloadFn,
    };
}

fn submitNewPayloadFn(ptr: *anyopaque, request: NewPayloadRequest) NewPayloadResult {
    const node: *BeaconNode = @ptrCast(@alignCast(ptr));
    return submitNewPayload(node, request);
}

fn submitNewPayload(node: *BeaconNode, request: NewPayloadRequest) NewPayloadResult {
    const t0 = std.Io.Clock.awake.now(node.io);
    const had_engine = node.execution_runtime.hasExecutionEngine();
    const result = node.execution_runtime.submitNewPayload(request);
    const t1 = std.Io.Clock.awake.now(node.io);
    const elapsed_s: f64 = @as(f64, @floatFromInt(t1.nanoseconds - t0.nanoseconds)) / 1e9;
    if (node.metrics) |m| {
        m.execution_new_payload_seconds.observe(elapsed_s);
        switch (result) {
            .valid => m.execution_payload_valid_total.incr(),
            .invalid, .invalid_block_hash => m.execution_payload_invalid_total.incr(),
            .syncing, .accepted => m.execution_payload_syncing_total.incr(),
            .unavailable => if (had_engine) m.execution_errors_total.incr(),
        }
    }
    return result;
}

test "execution adapter maps mock VALID payload to valid" {
    const allocator = std.testing.allocator;
    var mock = execution_mod.mock_engine.MockEngine.init(allocator);
    defer mock.deinit();

    const request = NewPayloadRequest{
        .bellatrix = .{
            .payload = .{
                .parent_hash = [_]u8{0x44} ** 32,
                .fee_recipient = [_]u8{0x55} ** 20,
                .state_root = [_]u8{0x66} ** 32,
                .receipts_root = [_]u8{0x77} ** 32,
                .logs_bloom = [_]u8{0x88} ** 256,
                .prev_randao = [_]u8{0x99} ** 32,
                .block_number = 1,
                .gas_limit = 30_000_000,
                .gas_used = 21_000,
                .timestamp = 1,
                .extra_data = &.{},
                .base_fee_per_gas = 1,
                .block_hash = [_]u8{0x11} ** 32,
                .transactions = &.{},
            },
            .extra_data = &.{},
            .transactions = &.{},
        },
    };
    const result = submitNewPayloadWithEngine(allocator, mock.engine(), request);
    switch (result) {
        .valid => |valid| try std.testing.expectEqual(([_]u8{0x11} ** 32), valid.latest_valid_hash),
        else => return error.UnexpectedExecutionPortResult,
    }
}

test "execution adapter maps mock SYNCING payload to syncing" {
    const allocator = std.testing.allocator;
    var mock = execution_mod.mock_engine.MockEngine.init(allocator);
    defer mock.deinit();

    const block_hash = [_]u8{0x22} ** 32;
    try mock.setPayloadStatus(block_hash, .syncing);

    const request = NewPayloadRequest{
        .bellatrix = .{
            .payload = .{
                .parent_hash = [_]u8{0x44} ** 32,
                .fee_recipient = [_]u8{0x55} ** 20,
                .state_root = [_]u8{0x66} ** 32,
                .receipts_root = [_]u8{0x77} ** 32,
                .logs_bloom = [_]u8{0x88} ** 256,
                .prev_randao = [_]u8{0x99} ** 32,
                .block_number = 1,
                .gas_limit = 30_000_000,
                .gas_used = 21_000,
                .timestamp = 1,
                .extra_data = &.{},
                .base_fee_per_gas = 1,
                .block_hash = block_hash,
                .transactions = &.{},
            },
            .extra_data = &.{},
            .transactions = &.{},
        },
    };
    const result = submitNewPayloadWithEngine(allocator, mock.engine(), request);
    try std.testing.expectEqual(@as(std.meta.Tag(NewPayloadResult), .syncing), std.meta.activeTag(result));
}

fn submitNewPayloadWithEngine(
    allocator: std.mem.Allocator,
    engine: execution_mod.EngineApi,
    request: NewPayloadRequest,
) NewPayloadResult {
    const result = switch (request) {
        .bellatrix => |prepared| engine.newPayloadV1(prepared.payload),
        .capella => |prepared| engine.newPayloadV2(prepared.payload),
        .deneb => |prepared| engine.newPayload(
            prepared.payload,
            prepared.versioned_hashes,
            prepared.parent_beacon_block_root,
        ),
        .electra => |prepared| engine.newPayloadV4(
            prepared.payload,
            prepared.versioned_hashes,
            prepared.parent_beacon_block_root,
        ),
    } catch return .unavailable;
    defer result.deinit(allocator);

    return switch (result.status) {
        .valid => .{ .valid = .{
            .latest_valid_hash = result.latest_valid_hash orelse request.blockHash(),
        } },
        .invalid => .{ .invalid = .{
            .latest_valid_hash = result.latest_valid_hash,
        } },
        .invalid_block_hash => .{ .invalid_block_hash = .{
            .latest_valid_hash = result.latest_valid_hash,
        } },
        .syncing => .syncing,
        .accepted => .accepted,
    };
}
