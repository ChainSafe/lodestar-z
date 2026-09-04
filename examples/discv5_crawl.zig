//! Starts one DiscV5 node, authenticates configured bootnodes, and runs a bounded set of
//! concurrent random lookups.
//!
//! zig build run:discv5_crawl -- 0.0.0.0:9000 203.0.113.10:9000
//!     [--duration-seconds 60] enr:... [enr:...]

const std = @import("std");
const discv5 = @import("discv5");

const net = std.Io.net;
const bootstrap_capacity: usize = discv5.Maintenance.bootstrap_max;
const bootstrap_steps_max: usize = 4_096;
const call_capacity: usize = 64;
const crawl_duration_seconds_default: u16 = 60;
const crawl_duration_seconds_max: u16 = 300;
const driver_steps_max: usize = 12_000;
const key_generation_attempts_max: usize = 16;
const lookup_concurrency: usize = 16;
const lookup_total_max: usize = 64;
const poll_interval_ms: u32 = 25;
const record_capacity: usize = 8_192;

const Bootstrap = struct {
    record: discv5.identity.enr.Record,
    handle: ?discv5.CallTable.Handle = null,
    authenticated: bool = false,
};

const LookupSlot = struct {
    operation: discv5.Lookup = undefined,
    active: bool = false,

    fn cancel(self: *LookupSlot, core: *discv5.Engine) void {
        if (!self.active) return;
        self.operation.cancel(core);
        self.active = false;
    }
};

const RecordSet = struct {
    records: []discv5.identity.enr.Record,
    indices: std.AutoHashMapUnmanaged(discv5.types.NodeId, u16),
    count: u16 = 0,

    fn init(allocator: std.mem.Allocator) !RecordSet {
        const records = try allocator.alloc(discv5.identity.enr.Record, record_capacity);
        errdefer allocator.free(records);

        var indices: std.AutoHashMapUnmanaged(discv5.types.NodeId, u16) = .empty;
        errdefer indices.deinit(allocator);
        try indices.ensureTotalCapacity(allocator, @intCast(record_capacity));

        return .{ .records = records, .indices = indices };
    }

    fn deinit(self: *RecordSet, allocator: std.mem.Allocator) void {
        self.indices.deinit(allocator);
        allocator.free(self.records);
        self.* = undefined;
    }

    fn add(self: *RecordSet, record: *const discv5.identity.enr.Record) bool {
        if (self.indices.get(record.node_id)) |index| {
            const stored = &self.records[index];
            if (record.sequence > stored.sequence) stored.* = record.*;
            return false;
        }
        if (self.count == self.records.len) return false;
        self.records[self.count] = record.*;
        self.indices.putAssumeCapacityNoClobber(record.node_id, self.count);
        self.count += 1;
        return true;
    }
};

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 4) {
        std.debug.print(
            "usage: {s} <bind-ip:port> <advertised-ip:port> " ++
                "[--duration-seconds <1..300>] <boot-enr> [boot-enr...]\n",
            .{args[0]},
        );
        return;
    }
    var duration_seconds = crawl_duration_seconds_default;
    var bootnode_start: usize = 3;
    if (std.mem.eql(u8, args[3], "--duration-seconds")) {
        if (args.len < 6) return error.MissingDurationOrBootnode;
        duration_seconds = try std.fmt.parseInt(u16, args[4], 10);
        if (duration_seconds == 0 or duration_seconds > crawl_duration_seconds_max)
            return error.InvalidDuration;
        bootnode_start = 5;
    }
    if (args.len - bootnode_start > bootstrap_capacity) return error.TooManyBootnodes;
    const started_ms = try discv5.Driver.monotonicMilliseconds(io);
    const duration_ms = @as(u64, duration_seconds) * std.time.ms_per_s;
    const deadline_ms = std.math.add(u64, started_ms, duration_ms) catch
        return error.ClockOutOfRange;

    const bind_address = try net.IpAddress.parseLiteral(args[1]);
    const advertised_address = discv5.Udp.fromNetwork(try net.IpAddress.parseLiteral(args[2]));
    var udp = try discv5.Udp.bind(io, bind_address);
    defer udp.close(io);
    const bound_address = udp.localAddress();
    if (std.meta.activeTag(bound_address) != std.meta.activeTag(advertised_address))
        return error.AdvertisedAddressFamilyMismatch;
    if (bound_address.port() != advertised_address.port())
        return error.AdvertisedPortMismatch;

    var key_pair = try randomKeyPair(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
    const local_record = try discv5.identity.enr.Record.create(
        &key_pair,
        1,
        advertised_address,
    );
    var core: discv5.Engine = undefined;
    try core.initWithConfig(allocator, key_pair, local_record, .{
        .session_capacity = 256,
        .challenge_capacity = 64,
        .call_capacity = call_capacity,
        .request_timeout_ms = 1_000,
        .challenge_timeout_ms = 1_000,
        .session_idle_timeout_ms = 86_400_000,
    });
    defer core.deinit(allocator);
    var transport = try discv5.Driver.initWithConfig(
        &core,
        &udp,
        .{ .poll_interval_ms = poll_interval_ms },
    );

    var bootstraps: [bootstrap_capacity]Bootstrap = undefined;
    const bootstraps_slice = try parseBootstraps(
        args[bootnode_start..],
        std.meta.activeTag(advertised_address),
        &bootstraps,
    );
    var records = try RecordSet.init(allocator);
    defer records.deinit(allocator);
    const authenticated = try authenticateBootstraps(
        io,
        &transport,
        bootstraps_slice,
        &records,
        deadline_ms,
    );
    if (core.peerCount() == 0) return error.NoReachableBootnodes;

    std.debug.print(
        "node bound on {any}, authenticated {d}/{d} bootnodes\n",
        .{ udp.localAddress(), authenticated, bootstraps_slice.len },
    );
    var maintenance_bootstraps: [bootstrap_capacity]discv5.identity.enr.Record = undefined;
    for (bootstraps_slice, maintenance_bootstraps[0..bootstraps_slice.len]) |bootstrap, *record| record.* = bootstrap.record;
    try crawl(io, allocator, &transport, &records, maintenance_bootstraps[0..bootstraps_slice.len], deadline_ms);
    const elapsed_ms = (try discv5.Driver.monotonicMilliseconds(io)) - started_ms;
    std.debug.print(
        "collected {d} validated peer records from {d} routing entries in {d} ms\n",
        .{ records.count, core.peerCount(), elapsed_ms },
    );
    for (records.records[0..records.count]) |*record| printRecord(record);
}

fn parseBootstraps(
    encoded: []const [:0]const u8,
    address_family: std.meta.Tag(discv5.types.Address),
    storage: *[bootstrap_capacity]Bootstrap,
) ![]Bootstrap {
    var count: usize = 0;
    for (encoded) |text| {
        const record = try discv5.identity.enr.Record.initText(text);
        const record_endpoint = record.endpoint() orelse
            return error.BootnodeHasNoUdpEndpoint;
        if (std.meta.activeTag(record_endpoint) != address_family) continue;
        var duplicate = false;
        for (storage[0..count]) |*stored| {
            if (!std.mem.eql(u8, &stored.record.node_id, &record.node_id)) continue;
            duplicate = true;
            break;
        }
        if (duplicate) continue;
        storage[count] = .{ .record = record };
        count += 1;
    }
    if (count == 0) return error.NoBootnodes;
    return storage[0..count];
}

fn authenticateBootstraps(
    io: std.Io,
    transport: *discv5.Driver,
    bootstraps: []Bootstrap,
    records: *RecordSet,
    deadline_ms: u64,
) !usize {
    defer for (bootstraps) |*bootstrap| {
        if (bootstrap.handle) |handle| _ = transport.core.cancelCall(handle);
        bootstrap.handle = null;
    };
    var pending: usize = 0;
    for (bootstraps, 0..) |*bootstrap, index| {
        const request = discv5.wire.message.Message{ .ping = .{
            .request_id = requestId(index + 1),
            .enr_sequence = transport.core.localRecord().sequence,
        } };
        bootstrap.handle = try transport.startCall(
            io,
            endpoint(&bootstrap.record),
            &bootstrap.record,
            &request,
        );
        pending += 1;
    }

    var expired: [call_capacity]discv5.CallTable.Expired = undefined;
    for (0..bootstrap_steps_max) |_| {
        if (pending == 0) break;
        if (try discv5.Driver.monotonicMilliseconds(io) >= deadline_ms) break;
        const result = try transport.stepUntil(io, &expired, deadline_ms);
        for (expired[0..result.calls_expired]) |item| {
            if (findBootstrap(bootstraps, item.handle)) |bootstrap| {
                bootstrap.handle = null;
                pending -= 1;
            }
        }
        switch (result.event) {
            .failed => |failed| {
                if (findBootstrap(bootstraps, failed.handle)) |bootstrap| {
                    bootstrap.handle = null;
                    pending -= 1;
                }
            },
            .response => |response| {
                if (findBootstrap(bootstraps, response.matched.handle)) |bootstrap| {
                    bootstrap.handle = null;
                    pending -= 1;
                    if (transport.core.confirmPeer(&response.peer, &bootstrap.record, result.now_ms)) |_| {
                        bootstrap.authenticated = true;
                        _ = records.add(&bootstrap.record);
                    } else |_| {}
                }
            },
            else => {},
        }
        if (result.failure) |err| return err;
    }

    var authenticated: usize = 0;
    for (bootstraps) |*bootstrap| {
        if (bootstrap.authenticated) authenticated += 1;
        if (bootstrap.handle) |handle| {
            _ = transport.core.cancelCall(handle);
            bootstrap.handle = null;
        }
    }
    return authenticated;
}

fn crawl(
    io: std.Io,
    allocator: std.mem.Allocator,
    transport: *discv5.Driver,
    records: *RecordSet,
    bootstrap_records: []const discv5.identity.enr.Record,
    deadline_ms: u64,
) !void {
    const candidates = try allocator.alloc(discv5.Lookup.Candidates, lookup_concurrency + 1);
    defer allocator.free(candidates);
    var maintenance: discv5.Maintenance = undefined;
    try maintenance.init(&candidates[lookup_concurrency], bootstrap_records, try discv5.Driver.monotonicMilliseconds(io), .{
        .probe_interval_ms = 10_000,
        .stale_after_ms = 15_000,
        .refresh_interval_ms = 15_000,
        .bootstrap_interval_ms = 15_000,
        .discovery_stall_ms = 15_000,
    });
    defer maintenance.cancel(transport.core);
    var cursor: discv5.lookup_driver.Cursor = .{};
    var statistics: CrawlStatistics = .{};
    var slots = [_]LookupSlot{.{}} ** lookup_concurrency;
    defer for (&slots) |*slot| slot.cancel(transport.core);
    var expired: [call_capacity]discv5.CallTable.Expired = undefined;
    var operations: [lookup_concurrency]*discv5.Lookup = undefined;
    var launched: usize = 0;
    var completed: usize = 0;
    var rejections = std.EnumArray(discv5.types.RejectReason, u32).initFill(0);

    for (0..driver_steps_max) |_| {
        if (try discv5.Driver.monotonicMilliseconds(io) >= deadline_ms) break;
        try startMaintenance(io, transport, &maintenance);
        try startLookups(io, transport.core, &slots, candidates[0..lookup_concurrency], &launched);

        const active = activeLookups(&slots, &operations);
        const result = try discv5.lookup_driver.step(transport, io, active, &cursor, &expired);
        switch (result.driver.datagram) {
            .rejected => |reason| rejections.getPtr(reason).* += 1,
            .timeout, .accepted => {},
        }
        for (expired[0..result.driver.calls_expired]) |item| {
            _ = maintenance.onFailure(transport.core, item.handle, result.driver.now_ms, .expired);
        }
        _ = try maintenance.onEvent(transport.core, &result.driver.event, result.driver.now_ms);
        if (result.driver.event == .response) {
            for (result.driver.event.response.node_records) |*record| _ = records.add(record);
        }
        statistics.failures += result.progress.failures;
        completed += finishLookups(transport.core, &slots, &statistics);
        if (result.failure) |err| return err;
        if (completed == lookup_total_max and activeLookups(&slots, &operations).len == 0) break;
        if (records.count == record_capacity) break;
    }

    for (&slots) |*slot| {
        if (slot.active) slot.operation.cancel(transport.core);
    }
    completed += finishLookups(transport.core, &slots, &statistics);

    std.debug.print("lookups launched={d} terminal={d}\n", .{ launched, completed });
    std.debug.print("lookup_queries={d} lookup_failures={d} capacity_drops={d} candidate_bytes={d}\n", .{
        statistics.queries,                                 statistics.failures, statistics.capacity_drops,
        candidates.len * @sizeOf(discv5.Lookup.Candidates),
    });
    for (std.enums.values(discv5.Lookup.FinishReason)) |reason| {
        std.debug.print("  {s}={d}\n", .{ @tagName(reason), statistics.finished.get(reason) });
    }
    printRejections(&rejections);
}

const CrawlStatistics = struct {
    queries: u32 = 0,
    failures: u32 = 0,
    capacity_drops: u64 = 0,
    finished: std.EnumArray(discv5.Lookup.FinishReason, u16) = .initFill(0),
};

fn startMaintenance(io: std.Io, transport: *discv5.Driver, maintenance: *discv5.Maintenance) !void {
    var context = try discv5.Driver.sendContext(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&context.entropy));
    var output: [discv5.wire.constants.packet_size_max]u8 = undefined;
    const started = try maintenance.startNext(transport.core, &output, try discv5.Driver.requestId(io), context.now_ms, &context.entropy) orelse return;
    transport.transmit(io, started.peer.address, output[0..started.call.packet_length]) catch |err| {
        const consumed = maintenance.onFailure(transport.core, started.call.handle, context.now_ms, .local);
        std.debug.assert(consumed);
        if (err != error.DestinationUnreachable) return err;
    };
}

fn printRejections(rejections: *const std.EnumArray(discv5.types.RejectReason, u32)) void {
    var total: u32 = 0;
    for (std.enums.values(discv5.types.RejectReason)) |reason| total += rejections.get(reason);
    std.debug.print("rejected_datagrams={d}\n", .{total});
    for (std.enums.values(discv5.types.RejectReason)) |reason| {
        const count = rejections.get(reason);
        if (count > 0) std.debug.print("  {s}={d}\n", .{ @tagName(reason), count });
    }
}

fn startLookups(
    io: std.Io,
    core: *discv5.Engine,
    slots: *[lookup_concurrency]LookupSlot,
    candidates: []discv5.Lookup.Candidates,
    launched: *usize,
) !void {
    for (slots, candidates) |*slot, *storage| {
        if (slot.active or launched.* == lookup_total_max) continue;
        var target: discv5.types.NodeId = undefined;
        try std.Io.randomSecure(io, &target);
        var seeds_buffer: [discv5.Lookup.result_max]discv5.RoutingTable.Entry = undefined;
        const seeds = core.closestNodes(&target, &seeds_buffer);
        if (seeds.len == 0) return;
        try slot.operation.init(
            storage,
            core.localRecord().node_id,
            target,
            seeds,
        );
        slot.active = true;
        launched.* += 1;
    }
}

fn activeLookups(
    slots: *[lookup_concurrency]LookupSlot,
    out: *[lookup_concurrency]*discv5.Lookup,
) []const *discv5.Lookup {
    var count: usize = 0;
    for (slots) |*slot| {
        if (!slot.active) continue;
        out[count] = &slot.operation;
        count += 1;
    }
    return out[0..count];
}

fn finishLookups(
    core: *discv5.Engine,
    slots: *[lookup_concurrency]LookupSlot,
    statistics: *CrawlStatistics,
) usize {
    var completed: usize = 0;
    for (slots) |*slot| {
        if (!slot.active or !slot.operation.isFinished()) continue;
        const lookup_statistics = slot.operation.statistics();
        statistics.queries += lookup_statistics.queries_started;
        statistics.capacity_drops += lookup_statistics.capacity_drops;
        statistics.finished.getPtr(slot.operation.finishReason().?).* += 1;
        slot.cancel(core);
        completed += 1;
    }
    return completed;
}

fn findBootstrap(
    bootstraps: []Bootstrap,
    handle: discv5.CallTable.Handle,
) ?*Bootstrap {
    for (bootstraps) |*bootstrap| {
        const stored = bootstrap.handle orelse continue;
        if (std.meta.eql(stored, handle)) return bootstrap;
    }
    return null;
}

fn endpoint(record: *const discv5.identity.enr.Record) discv5.types.Endpoint {
    return .{ .node_id = record.node_id, .address = record.endpoint().? };
}

fn requestId(value: usize) discv5.wire.message.RequestId {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .big);
    return discv5.wire.message.RequestId.init(&encoded) catch unreachable;
}

fn randomKeyPair(io: std.Io) !discv5.identity.crypto.KeyPair {
    for (0..key_generation_attempts_max) |_| {
        var secret: [32]u8 = undefined;
        try std.Io.randomSecure(io, &secret);
        const key_pair = discv5.identity.crypto.keyPairFromSecret(&secret) catch {
            std.crypto.secureZero(u8, &secret);
            continue;
        };
        std.crypto.secureZero(u8, &secret);
        return key_pair;
    }
    return error.KeyGenerationFailed;
}

fn printRecord(record: *const discv5.identity.enr.Record) void {
    var encoded_buffer: [512]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(
        &encoded_buffer,
        record.slice(),
    );
    std.debug.print("enr:{s}\n", .{encoded});
}

comptime {
    std.debug.assert(bootstrap_capacity <= call_capacity);
    std.debug.assert(driver_steps_max <= std.math.maxInt(u32));
    std.debug.assert(lookup_concurrency <= discv5.lookup_driver.operations_max);
    std.debug.assert((lookup_concurrency + 1) * discv5.Lookup.parallelism + 1 <= call_capacity);
    std.debug.assert(record_capacity <= std.math.maxInt(u16));
    std.debug.assert(record_capacity >= discv5.RoutingTable.table_capacity);
}
