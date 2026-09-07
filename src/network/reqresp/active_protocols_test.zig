const std = @import("std");
const config = @import("config");
const ct = @import("consensus_types");
const codec = @import("codec.zig");
const protocol = @import("protocol.zig");
const response_bounds = @import("response_bounds.zig");
const reqresp = @import("reqresp.zig");
const harness = @import("reqresp_test.zig");

const first: reqresp.ForkEntry = .{ .digest = .{ 1, 2, 3, 4 }, .fork = .fulu };
const second: reqresp.ForkEntry = .{ .digest = .{ 5, 6, 7, 8 }, .fork = .fulu };
const phase0: reqresp.ForkEntry = .{ .digest = .{ 9, 10, 11, 12 }, .fork = .phase0 };

fn request(setup: *harness.ReqRespPair, which: protocol.Protocol, bytes: []const u8, sink: []u8, options: reqresp.RequestOptions) !reqresp.RequestHandle {
    return setup.client.request(&setup.pair.client, &setup.client_neg, setup.handles.client, which, bytes, sink, options, setup.pair.now);
}

test "reqresp active new methods enforce request ceilings through real exchanges and reuse" {
    const cases = .{
        .{ protocol.Protocol.blocks_by_head_v1, 40, 2, ct.fulu.SignedBeaconBlock.min_size },
        .{ protocol.Protocol.light_client_bootstrap_v1, 32, 1, ct.fulu.LightClientBootstrap.min_size },
        .{ protocol.Protocol.light_client_updates_by_range_v1, 16, 0, ct.fulu.LightClientUpdate.min_size },
        .{ protocol.Protocol.light_client_finality_update_v1, 0, 1, ct.fulu.LightClientFinalityUpdate.min_size },
        .{ protocol.Protocol.light_client_optimistic_update_v1, 0, 1, ct.fulu.LightClientOptimisticUpdate.min_size },
    };
    var setup: harness.ReqRespPair = .{};
    try setup.init(.{ .outbound_max = 1, .forks = &.{ first, second, phase0 } }, .{ .inbound_max = 1, .inbound_per_peer_max = 1, .forks = &.{ first, second, phase0 } });
    defer setup.deinit();
    inline for (cases) |case| {
        for ([_]reqresp.ForkEntry{ first, second }) |context| {
            var bytes = [_]u8{0} ** case[1];
            if (case[0] == .blocks_by_head_v1) std.mem.writeInt(u64, bytes[32..40], 2, .little);
            var payload = [_]u8{0} ** (case[3] + 1);
            const sink = try std.testing.allocator.alloc(u8, case[0].info().response_max);
            defer std.testing.allocator.free(sink);
            try std.testing.expectError(error.InvalidRequestOptions, request(&setup, case[0], &bytes, sink, .{ .expected_chunks = case[2] + 1 }));
            _ = try request(&setup, case[0], &bytes, sink, .{});
            var chunks: u32 = 0;
            var done = false;
            var served = false;
            for (0..60) |_| {
                try setup.pumpOnce();
                for (setup.serverEvents()) |event| switch (event) {
                    .request => |incoming| {
                        try std.testing.expectEqualSlices(u8, &bytes, incoming.bytes);
                        if (case[2] == 0) {
                            try std.testing.expectError(error.TooManyChunks, setup.server.respond(incoming.request, payload[0..case[3]], context, setup.pair.now));
                            try std.testing.expect(setup.server.finish(incoming.request, setup.pair.now));
                        } else {
                            try std.testing.expectError(error.UnknownFork, setup.server.respond(incoming.request, payload[0..case[3]], .{ .digest = context.digest, .fork = .deneb }, setup.pair.now));
                            if (case[0] != .blocks_by_head_v1) try std.testing.expectError(error.InvalidContext, setup.server.respond(incoming.request, payload[0..case[3]], phase0, setup.pair.now));
                            try std.testing.expectError(error.ChunkTooSmall, setup.server.respond(incoming.request, payload[0 .. case[3] - 1], context, setup.pair.now));
                            try setup.server.respond(incoming.request, payload[0..case[3]], context, setup.pair.now);
                        }
                    },
                    .chunk_sent => |sent| {
                        if (sent.chunks == case[2]) {
                            try std.testing.expectError(error.TooManyChunks, setup.server.respond(sent.request, payload[0..case[3]], context, setup.pair.now));
                            try std.testing.expect(setup.server.finish(sent.request, setup.pair.now));
                        } else try setup.server.respond(sent.request, payload[0..case[3]], context, setup.pair.now);
                    },
                    .served => |terminal| {
                        try std.testing.expectEqual(@as(u32, case[2]), terminal.chunks);
                        served = true;
                    },
                    .failed => return error.TestUnexpectedResult,
                    else => {},
                };
                for (setup.clientEvents()) |event| switch (event) {
                    .chunk => |chunk| {
                        chunks += 1;
                        try std.testing.expectEqual(@as(?config.ForkSeq, .fulu), chunk.fork);
                        try std.testing.expectEqualSlices(u8, payload[0..case[3]], chunk.bytes);
                        try std.testing.expect(setup.client.consume(chunk.request, setup.pair.now));
                    },
                    .done => |terminal| {
                        try std.testing.expect(!done);
                        try std.testing.expectEqual(@as(u32, case[2]), terminal.chunks);
                        done = true;
                    },
                    .failed => return error.TestUnexpectedResult,
                    else => {},
                };
                if (done and served) break;
            }
            try std.testing.expect(done and served);
            try std.testing.expectEqual(@as(u32, case[2]), chunks);
            try setup.pumpOnce();
            try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
            try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
        }
    }
}

test "reqresp active light client bounds select each actual fork type before decoding" {
    inline for (.{ .altair, .capella, .deneb, .electra, .fulu, .gloas }) |fork_tag| {
        const fork: config.ForkSeq = fork_tag;
        const types = @field(ct, @tagName(fork));
        const cases = .{
            .{ response_bounds.Family.light_client_bootstrap, types.LightClientBootstrap },
            .{ response_bounds.Family.light_client_update, types.LightClientUpdate },
            .{ response_bounds.Family.light_client_finality_update, types.LightClientFinalityUpdate },
            .{ response_bounds.Family.light_client_optimistic_update, types.LightClientOptimisticUpdate },
        };
        inline for (cases) |case| {
            const T = case[1];
            const min = if (@hasDecl(T, "fixed_size")) T.fixed_size else T.min_size;
            const max = if (@hasDecl(T, "fixed_size")) T.fixed_size else T.max_size;
            const bounds = try response_bounds.forFork(case[0], fork);
            try std.testing.expectEqual(min, bounds.min);
            try std.testing.expectEqual(max, bounds.max);
            try std.testing.expectError(error.InvalidResponseContext, response_bounds.forFork(case[0], .phase0));
            const sink = try std.testing.allocator.alloc(u8, response_bounds.unionFor(case[0]).max);
            defer std.testing.allocator.free(sink);
            const encoded = try std.testing.allocator.alloc(u8, codec.encodedLengthMax(max + 1));
            defer std.testing.allocator.free(encoded);
            const payload = try std.testing.allocator.alloc(u8, max + 1);
            defer std.testing.allocator.free(payload);
            @memset(payload, 0);
            var scratch: [codec.frame_scratch_max]u8 = undefined;
            for ([_]usize{ min - 1, min, max, max + 1 }) |length| {
                @memset(sink, 0xa5);
                const bytes = try codec.encodeChunk(0, first.digest, payload[0..length], encoded);
                var decoder = codec.Decoder.initResponseWithContext(response_bounds.unionFor(case[0]), sink, &scratch);
                try std.testing.expectEqual(@as(usize, 5), (try decoder.feed(bytes)).consumed);
                try decoder.setContextBounds(bounds);
                if (length < min or length > max) {
                    try std.testing.expectError(error.LengthOutOfBounds, decoder.feed(bytes[5..]));
                    try std.testing.expect(std.mem.allEqual(u8, sink, 0xa5));
                } else {
                    try std.testing.expect((try decoder.feed(bytes[5..])).done);
                    try std.testing.expectEqual(length, decoder.payload().len);
                }
            }
        }
    }
    try std.testing.expectError(error.InvalidResponseContext, response_bounds.forFork(.blob, .capella));
    try std.testing.expectError(error.InvalidResponseContext, response_bounds.forFork(.column, .electra));
    try std.testing.expectError(error.InvalidResponseContext, protocol.Protocol.ping_v1.responseBounds(.fulu));
}

test "reqresp active hostile coalesced context rejects before sink writes with one terminal" {
    const cases = .{
        .{ reqresp.ForkEntry{ .digest = .{ 99, 99, 99, 99 }, .fork = .fulu }, reqresp.Failure{ .unknown_context = .{ 99, 99, 99, 99 } } },
        .{ phase0, reqresp.Failure{ .invalid_response = error.InvalidResponseContext } },
        .{ first, reqresp.Failure{ .invalid_response = error.LengthOutOfBounds } },
    };
    inline for (cases) |case| {
        for (0..7) |split| {
            var setup: harness.ReqRespPair = .{};
            try setup.init(.{ .forks = &.{ first, phase0 } }, .{ .forks = &.{ first, phase0 } });
            defer setup.deinit();
            const sink = try std.testing.allocator.alloc(u8, protocol.Protocol.light_client_optimistic_update_v1.info().response_max);
            defer std.testing.allocator.free(sink);
            @memset(sink, 0xaa);
            _ = try request(&setup, .light_client_optimistic_update_v1, "", sink, .{});
            const bytes = [_]u8{0} ++ case[0].digest ++ [_]u8{ 1, 0xff, 6, 0, 0 };
            var stream: ?@import("../quic/engine.zig").StreamHandle = null;
            var sent_suffix = false;
            var failed = false;
            for (0..40) |_| {
                try setup.pumpOnce();
                for (setup.serverEvents()) |event| if (event == .request) {
                    const slot = &setup.server.inbound[event.request.request.index];
                    stream = slot.stream;
                    if (split > 0) try std.testing.expectEqual(split, try setup.pair.server.write(slot.stream, bytes[0..split], false));
                };
                for (setup.clientEvents()) |event| switch (event) {
                    .failed => |failure| {
                        try std.testing.expect(!failed);
                        try std.testing.expectEqualDeep(case[1], failure.reason);
                        failed = true;
                    },
                    .chunk, .done => return error.TestUnexpectedResult,
                    else => {},
                };
                if (failed) break;
                if (stream) |raw| {
                    if (!sent_suffix) {
                        try std.testing.expectEqual(bytes.len - split, try setup.pair.server.write(raw, bytes[split..], true));
                        sent_suffix = true;
                    }
                }
            }
            try std.testing.expect(failed);
            try std.testing.expect(std.mem.allEqual(u8, sink, 0xaa));
            setup.server.shutdown(&setup.pair.server, &setup.server_neg);
            try setup.pumpOnce();
            try setup.pumpOnce();
            try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
            try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
            try std.testing.expectEqual(@as(u64, 1), setup.client.counters.failures);
        }
    }
}

test "reqresp active zero ceiling rejects malicious success and permits remote error" {
    for ([_]u8{ 0, 3 }) |result| {
        var setup: harness.ReqRespPair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const which = protocol.Protocol.light_client_updates_by_range_v1;
        const sink = try std.testing.allocator.alloc(u8, which.info().response_max);
        defer std.testing.allocator.free(sink);
        const bytes = [_]u8{0} ** 16;
        _ = try request(&setup, which, &bytes, sink, .{});
        const payload = [_]u8{0} ** ct.fulu.LightClientUpdate.min_size;
        var encoded: [codec.encodedLengthMax(payload.len)]u8 = undefined;
        const chunk = try codec.encodeChunk(result, if (result == 0) harness.fulu_digest else null, if (result == 0) &payload else "unavailable", &encoded);
        var failed = false;
        for (0..40) |_| {
            try setup.pumpOnce();
            for (setup.serverEvents()) |event| if (event == .request) {
                const slot = &setup.server.inbound[event.request.request.index];
                try std.testing.expectEqual(chunk.len, try setup.pair.server.write(slot.stream, chunk, true));
            };
            for (setup.clientEvents()) |event| switch (event) {
                .failed => |failure| {
                    try std.testing.expect(!failed);
                    if (result == 0) {
                        try std.testing.expect(failure.reason == .too_many_chunks);
                    } else {
                        try std.testing.expectEqual(@as(u8, 3), failure.reason.peer_error.code);
                        try std.testing.expectEqualStrings("unavailable", setup.client.errorMessage(failure.request));
                    }
                    failed = true;
                },
                .chunk, .done => return error.TestUnexpectedResult,
                else => {},
            };
            if (failed) break;
        }
        try std.testing.expect(failed);
        setup.server.shutdown(&setup.pair.server, &setup.server_neg);
        try setup.pumpOnce();
        try setup.pumpOnce();
        try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
        try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
    }
}

test "reqresp active inbound invalid head range and no-body requests never reach application" {
    const cases = .{
        .{ protocol.Protocol.blocks_by_head_v1, &([_]u8{0} ** 40) },
        .{ protocol.Protocol.light_client_updates_by_range_v1, &([_]u8{0xff} ** 16) },
        .{ protocol.Protocol.light_client_finality_update_v1, "\x00" },
        .{ protocol.Protocol.light_client_optimistic_update_v1, "\x00" },
    };
    inline for (cases) |case| {
        var setup: harness.ReqRespPair = .{};
        try setup.init(.{}, .{});
        defer setup.deinit();
        const raw = try setup.client_neg.beginOutbound(&setup.pair.client, setup.handles.client, .{ .reqresp = case[0] }, setup.pair.now);
        for (0..20) |_| {
            try setup.pumpOnce();
            if (setup.unclaimed == 1) break;
        }
        try std.testing.expectEqual(@as(usize, 1), setup.unclaimed);
        var encoded: [256]u8 = undefined;
        const bytes = if (case[0].info().request_max == 0) case[1] else try codec.encodeRequest(case[1], &encoded);
        try std.testing.expectEqual(bytes.len, try setup.pair.client.write(raw, bytes, true));
        var sink: [codec.error_message_max]u8 = undefined;
        var scratch: [codec.frame_scratch_max]u8 = undefined;
        var decoder = codec.Decoder.initResponseWithContext(.{ .min = 0, .max = sink.len }, &sink, &scratch);
        var buffer: [512]u8 = undefined;
        var served = false;
        for (0..30) |_| {
            try setup.pumpOnce();
            for (setup.serverEvents()) |event| switch (event) {
                .request => return error.TestUnexpectedResult,
                .served => served = true,
                else => {},
            };
            if (!decoder.isDone()) {
                const input = try setup.pair.client.read(raw, &buffer);
                _ = try decoder.feed(buffer[0..input.len]);
            }
            if (served and decoder.isDone()) break;
        }
        try std.testing.expect(served and decoder.isDone());
        try std.testing.expectEqual(@as(u8, 1), decoder.result());
        try std.testing.expectEqualStrings("invalid request", decoder.payload());
        try setup.pumpOnce();
        try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
    }
}

test "reqresp active light client traffic preserves control reserve and cancellation reuse" {
    const routing = @import("../router.zig");
    const support = @import("../test_support.zig");
    var pair: support.Pair = .{};
    try pair.init(.{}, .{});
    defer pair.deinit();
    const handles = try support.connectPair(&pair);
    var router = try routing.Router.init(std.testing.allocator, .{});
    defer router.deinit();
    var owner = try reqresp.ReqResp.init(std.testing.allocator, @import("control_capacity_test.zig").reservedOptions());
    defer owner.deinit();
    const which = protocol.Protocol.light_client_finality_update_v1;
    const capacity = protocol.Protocol.light_client_updates_by_range_v1.info().response_max;
    const sink = try std.testing.allocator.alloc(u8, capacity * 2);
    defer {
        owner.shutdown(&pair.client, &router);
        std.testing.allocator.free(sink);
    }
    for (0..2) |_| {
        const a = try owner.request(&pair.client, &router, handles.client, which, "", sink[0..capacity], .{ .expected_chunks = 0 }, pair.now);
        const b = try owner.request(&pair.client, &router, handles.client, .light_client_optimistic_update_v1, "", sink[capacity..], .{}, pair.now);
        try std.testing.expectError(error.SlotsExhausted, owner.request(&pair.client, &router, handles.client, .light_client_updates_by_range_v1, &([_]u8{0} ** 16), sink, .{}, pair.now));
        var ping: [8]u8 = @splat(0);
        const control = try owner.request(&pair.client, &router, handles.client, .ping_v1, &ping, &ping, .{}, pair.now);
        try std.testing.expect(owner.cancel(a));
        try std.testing.expect(owner.cancel(b));
        try std.testing.expect(owner.cancel(control));
        var events: [2]reqresp.Event = undefined;
        const controls = owner.pumpPartitioned(&pair.client, &router, pair.now, &.{}, &events);
        try std.testing.expectEqual(@as(usize, 0), controls.application);
        try std.testing.expectEqual(@as(usize, 1), controls.control);
        try std.testing.expectEqual(control, events[0].failed.request);
        const applications = owner.pumpPartitioned(&pair.client, &router, pair.now, &events, &.{});
        try std.testing.expectEqual(@as(usize, 2), applications.application);
        for (events) |event| try std.testing.expect(event.failed.reason == .cancelled);
        _ = owner.pump(&pair.client, &router, pair.now, &.{});
        try std.testing.expectEqual(@as(u16, 0), owner.active().outbound);
        try std.testing.expectEqual(@as(usize, 0), router.negotiator.active());
    }
}

const policy_fixture = @import("request_policy_test.zig").fixture;
const admission_quotas = @import("admission_test.zig").quotas;

fn emptyExchange(setup: *harness.ReqRespPair, which: protocol.Protocol, bytes: []const u8, allowed: bool, code: u8) !void {
    const sink = try std.testing.allocator.alloc(u8, which.info().response_max);
    defer std.testing.allocator.free(sink);
    _ = try request(setup, which, bytes, sink, .{});
    var received: u32 = 0;
    var terminal = false;
    var served = false;
    for (0..100) |_| {
        try setup.pumpOnce();
        for (setup.serverEvents()) |event| switch (event) {
            .request => |incoming| {
                received += 1;
                try std.testing.expect(allowed);
                try std.testing.expect(setup.server.finish(incoming.request, setup.pair.now));
            },
            .served => served = true,
            .failed => return error.TestUnexpectedResult,
            else => {},
        };
        for (setup.clientEvents()) |event| switch (event) {
            .done => |done| {
                try std.testing.expect(allowed);
                try std.testing.expectEqual(@as(u32, 0), done.chunks);
                terminal = true;
            },
            .failed => |failed| {
                try std.testing.expect(!allowed);
                try std.testing.expectEqual(code, failed.reason.peer_error.code);
                const message = if (code == 2) "rate limited" else "invalid request";
                try std.testing.expectEqualSlices(u8, message, setup.client.errorMessage(failed.request));
                terminal = true;
            },
            else => {},
        };
        if (terminal and served) break;
    }
    try std.testing.expect(terminal and served);
    try std.testing.expectEqual(@as(u32, if (allowed) 1 else 0), received);
    try setup.pumpOnce();
    try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
    try std.testing.expectEqual(@as(u16, 0), setup.server.active().inbound);
}

test "reqresp request admission empty success refusal malformed attempts and control independence" {
    var setup: harness.ReqRespPair = .{};
    try setup.init(.{}, .{
        .request_policy = policy_fixture(),
        .request_fork = .fulu,
        .admission = .{ .identities = 2, .peer = admission_quotas(2, 86_400_000), .global = admission_quotas(100, 86_400_000) },
    });
    defer setup.deinit();
    try emptyExchange(&setup, .blocks_by_root_v2, &.{}, true, 0);
    try emptyExchange(&setup, .blocks_by_root_v2, &.{}, true, 0);
    try emptyExchange(&setup, .blocks_by_root_v2, &.{}, false, 2);
    try emptyExchange(&setup, .blocks_by_root_v2, &.{0}, false, 1);
    var bytes = [_]u8{0} ** 24;
    std.mem.writeInt(u64, bytes[8..16], 3, .little);
    try emptyExchange(&setup, .blocks_by_range_v2, &bytes, false, 2);
    std.mem.writeInt(u64, bytes[8..16], 1, .little);
    try emptyExchange(&setup, .blocks_by_range_v2, &bytes, true, 0);
    try emptyExchange(&setup, .ping_v1, bytes[0..8], true, 0);
    const status = harness.statusBytes(1);
    try emptyExchange(&setup, .status_v1, &status, true, 0);
    try emptyExchange(&setup, .blob_sidecars_by_root_v1, &.{0}, false, 1);
    try emptyExchange(&setup, .blob_sidecars_by_root_v1, &.{}, true, 0);
    try emptyExchange(&setup, .blob_sidecars_by_root_v1, &.{}, false, 2);
    std.mem.writeInt(u32, bytes[16..20], 20, .little);
    try emptyExchange(&setup, .data_column_sidecars_by_range_v1, bytes[0..20], true, 0);
    try emptyExchange(&setup, .data_column_sidecars_by_range_v1, bytes[0..20], true, 0);
    try emptyExchange(&setup, .data_column_sidecars_by_range_v1, bytes[0..20], false, 2);
    try std.testing.expectEqual(@as(u64, 14), setup.server.counters.inspected);
    try std.testing.expectEqual(@as(u64, 8), setup.server.counters.admitted);
    try std.testing.expectEqual(@as(u128, 9), setup.server.counters.charged_work);
    try std.testing.expectEqual(@as(u64, 5), setup.server.counters.peer_refusals);
    try std.testing.expectEqual(@as(u64, 2), setup.server.counters.malformed);
}

test "reqresp request admission outbound validation ceiling and owner fork snapshot" {
    var setup: harness.ReqRespPair = .{};
    const options: harness.Overrides = .{
        .request_policy = policy_fixture(),
        .request_fork = .phase0,
        .admission = .{ .identities = 2, .peer = admission_quotas(2048, 1000), .global = admission_quotas(2048, 1000) },
    };
    try setup.init(options, options);
    defer setup.deinit();
    const sink = try std.testing.allocator.alloc(u8, protocol.Protocol.blocks_by_root_v2.info().response_max);
    defer std.testing.allocator.free(sink);
    var roots = [_]u8{0} ** (129 * 32);
    try std.testing.expectError(error.InvalidRequest, request(&setup, .blocks_by_root_v2, roots[0..1], sink, .{}));
    try std.testing.expectEqual(@as(u16, 0), setup.client.active().outbound);
    try std.testing.expectError(error.InvalidRequestOptions, request(&setup, .blocks_by_root_v2, &roots, sink, .{ .expected_chunks = 130 }));
    const handle = try request(&setup, .blocks_by_root_v2, &roots, sink, .{});
    setup.client.setRequestFork(.fulu);
    try std.testing.expectEqual(@as(u32, 129), setup.client.outbound[handle.index].chunks_max);
    var accepted = false;
    var completed = false;
    for (0..60) |_| {
        try setup.pumpOnce();
        for (setup.server.inbound) |*slot| if (slot.state == .receiving_request) {
            accepted = true;
            try std.testing.expectEqual(config.ForkSeq.phase0, slot.request_fork);
            setup.server.setRequestFork(.fulu);
        };
        for (setup.serverEvents()) |event| if (event == .request) {
            try std.testing.expect(accepted);
            try std.testing.expectEqual(@as(u32, 129), setup.server.inbound[event.request.request.index].chunks_max);
            try std.testing.expect(setup.server.finish(event.request.request, setup.pair.now));
        };
        if (setup.clientEvents().len > 0 and setup.clientEvents()[0] == .done) {
            completed = true;
            break;
        }
    }
    try std.testing.expect(accepted and completed);
    try std.testing.expectError(error.InvalidRequest, request(&setup, .blocks_by_root_v2, &roots, sink, .{}));
    try emptyExchange(&setup, .blocks_by_root_v2, &.{}, true, 0);
}

fn admissionAllocation(allocator: std.mem.Allocator) !void {
    var owner = try reqresp.ReqResp.init(allocator, .{
        .forks = &.{},
        .outbound_max = 1,
        .inbound_max = 1,
        .request_policy = policy_fixture(),
        .admission = .{ .identities = 2, .peer = admission_quotas(2, 1000), .global = admission_quotas(100, 1000) },
    });
    defer owner.deinit();
    try std.testing.expect(owner.options.request_policy == null);
    try std.testing.expectEqual(owner.admission.?.memoryPlan().allocated_bytes, owner.memoryPlan().admission_bytes);
}

test "reqresp request admission owner allocation failure prefixes and paired options" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, admissionAllocation, .{});
    try std.testing.expectError(error.InvalidOptions, reqresp.ReqResp.init(std.testing.allocator, .{ .forks = &.{}, .request_policy = policy_fixture() }));
    try std.testing.expectError(error.InvalidOptions, reqresp.ReqResp.init(std.testing.allocator, .{ .forks = &.{}, .admission = .{ .identities = 2, .peer = admission_quotas(2, 1000), .global = admission_quotas(100, 1000) } }));
}

test "reqresp request admission concurrent connections and reconnect retain full identity debt" {
    const support = @import("../test_support.zig");
    var setup: harness.ReqRespPair = .{};
    try setup.init(.{}, .{
        .request_policy = policy_fixture(),
        .admission = .{ .identities = 2, .peer = admission_quotas(2, 86_400_000), .global = admission_quotas(100, 86_400_000) },
    });
    defer setup.deinit();
    try emptyExchange(&setup, .blocks_by_root_v2, &.{}, true, 0);
    const initial = setup.handles;
    const second_connection = try support.connectPair(&setup.pair);
    setup.handles = .{ .client = second_connection.client, .server = second_connection.server };
    try std.testing.expect(!std.meta.eql(initial.server, setup.handles.server));
    try std.testing.expect(setup.pair.server.peerId(initial.server).?.eql(&setup.pair.server.peerId(setup.handles.server).?));
    try emptyExchange(&setup, .blocks_by_root_v2, &.{}, true, 0);
    try emptyExchange(&setup, .blocks_by_root_v2, &.{}, false, 2);
    try std.testing.expect(setup.pair.client.close(initial.client, 0));
    try std.testing.expect(setup.pair.client.close(setup.handles.client, 0));
    for (0..8) |_| try setup.pumpOnce();
    const reconnected = try support.connectPair(&setup.pair);
    setup.handles = .{ .client = reconnected.client, .server = reconnected.server };
    try emptyExchange(&setup, .blocks_by_root_v2, &.{}, false, 2);
    try std.testing.expectEqual(@as(u64, 2), setup.server.counters.admitted);
    try std.testing.expectEqual(@as(u64, 2), setup.server.counters.peer_refusals);
}

fn changeClientIdentity(setup: *harness.ReqRespPair, seed: u8) !void {
    const support = @import("../test_support.zig");
    const keys = @import("../wire/keys.zig");
    const tls = @import("../tls/context.zig");
    const Engine = @import("../quic/engine.zig").Engine;
    const key = try keys.KeyPair.fromSecretKey(&(.{0} ** 31 ++ .{seed}));
    const ctx = try tls.Context.init(&key, support.now_unix, @splat(seed));
    const replacement = Engine.init(std.testing.allocator, .{
        .tls = ctx,
        .limits = .{},
        .local = support.client_address,
        .seed = seed,
    }) catch |err| {
        var failed_context = ctx;
        failed_context.deinit();
        return err;
    };
    setup.client.shutdown(&setup.pair.client, &setup.client_neg);
    setup.pair.client.deinit();
    setup.pair.client = replacement;
    setup.pair.client_ctx = ctx;
    const connection = try support.connectPair(&setup.pair);
    setup.handles = .{ .client = connection.client, .server = connection.server };
}

test "reqresp request admission distinct identity peer aggregate and retained capacity decisions" {
    for ([_]u16{ 1, 2 }) |identities| {
        var setup: harness.ReqRespPair = .{};
        var global = admission_quotas(100, 86_400_000);
        for (&global) |*table| table[@intFromEnum(protocol.Protocol.blob_sidecars_by_root_v1)].tokens = 1;
        try setup.init(.{}, .{
            .request_policy = policy_fixture(),
            .admission = .{ .identities = identities, .peer = admission_quotas(1, 86_400_000), .global = global },
        });
        defer setup.deinit();
        try emptyExchange(&setup, .blocks_by_root_v2, &.{}, true, 0);
        try emptyExchange(&setup, .blob_sidecars_by_root_v1, &.{}, true, 0);
        try changeClientIdentity(&setup, 3);
        try emptyExchange(&setup, .blocks_by_root_v2, &.{}, identities == 2, 2);
        try emptyExchange(&setup, .blob_sidecars_by_root_v1, &.{}, false, 2);
        try std.testing.expectEqual(@as(u64, 0), setup.server.counters.peer_refusals);
        try std.testing.expectEqual(@as(u64, if (identities == 1) 2 else 0), setup.server.counters.identity_capacity_refusals);
        try std.testing.expectEqual(@as(u64, if (identities == 2) 1 else 0), setup.server.counters.aggregate_refusals);
    }
}
