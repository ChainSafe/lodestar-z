//! Starts one DiscV5 node, authenticates configured bootnodes, and runs a bounded set of
//! concurrent random lookups.
//!
//! zig build run:discv5_crawl -- 0.0.0.0:9000 203.0.113.10:9000
//!     [--duration-seconds 60] enr:... [enr:...]

const std = @import("std");
const discv5 = @import("discv5");

const net = std.Io.net;
const bootstrap_capacity: usize = 32;
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
    handle: ?discv5.calls.Handle = null,
    authenticated: bool = false,
};

const LookupSlot = struct {
    operation: discv5.lookup.Lookup = undefined,
    active: bool = false,

    fn cancel(self: *LookupSlot, core: *discv5.engine.Engine) void {
        if (!self.active) return;
        self.operation.cancel(core);
        self.operation.deinit();
        self.active = false;
    }
};

const RecordSet = struct {
    allocator: std.mem.Allocator,
    records: []discv5.identity.enr.Record,
    indices: std.AutoHashMapUnmanaged(discv5.types.NodeId, u16),
    count: u16 = 0,

    fn init(allocator: std.mem.Allocator) !RecordSet {
        const records = try allocator.alloc(discv5.identity.enr.Record, record_capacity);
        errdefer allocator.free(records);

        var indices: std.AutoHashMapUnmanaged(discv5.types.NodeId, u16) = .empty;
        errdefer indices.deinit(allocator);
        try indices.ensureTotalCapacity(allocator, @intCast(record_capacity));

        return .{ .allocator = allocator, .records = records, .indices = indices };
    }

    fn deinit(self: *RecordSet) void {
        self.indices.deinit(self.allocator);
        self.allocator.free(self.records);
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
    const started_ms = try discv5.driver.monotonicMilliseconds(io);
    const duration_ms = @as(u64, duration_seconds) * std.time.ms_per_s;
    const deadline_ms = std.math.add(u64, started_ms, duration_ms) catch
        return error.ClockOutOfRange;

    const bind_address = try net.IpAddress.parseLiteral(args[1]);
    const advertised_address = discv5.runtime.fromNetwork(try net.IpAddress.parseLiteral(args[2]));
    var udp = try discv5.runtime.Udp.bind(io, bind_address);
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
    var core: discv5.engine.Engine = undefined;
    try core.initWithConfig(allocator, key_pair, local_record, .{
        .session_capacity = 256,
        .challenge_capacity = 64,
        .call_capacity = call_capacity,
        .request_timeout_ms = 1_000,
        .challenge_timeout_ms = 1_000,
        .session_idle_timeout_ms = 86_400_000,
    });
    defer core.deinit();
    var transport = try discv5.driver.Driver.initWithConfig(
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
    defer records.deinit();
    const authenticated = try authenticateBootstraps(
        io,
        &transport,
        bootstraps_slice,
        &records,
        deadline_ms,
    );
    if (core.routing.count() == 0) return error.NoReachableBootnodes;

    std.debug.print(
        "node bound on {any}, authenticated {d}/{d} bootnodes\n",
        .{ udp.localAddress(), authenticated, bootstraps_slice.len },
    );
    try crawl(io, allocator, &transport, &records, deadline_ms);
    const elapsed_ms = (try discv5.driver.monotonicMilliseconds(io)) - started_ms;
    std.debug.print(
        "collected {d} validated peer records from {d} routing entries in {d} ms\n",
        .{ records.count, core.routing.count(), elapsed_ms },
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
    transport: *discv5.driver.Driver,
    bootstraps: []Bootstrap,
    records: *RecordSet,
    deadline_ms: u64,
) !usize {
    var pending: usize = 0;
    for (bootstraps, 0..) |*bootstrap, index| {
        const request = discv5.wire.message.Message{ .ping = .{
            .request_id = requestId(index + 1),
            .enr_sequence = transport.core.channel.local_record.sequence,
        } };
        bootstrap.handle = try transport.startCall(
            io,
            endpoint(&bootstrap.record),
            &bootstrap.record,
            &request,
        );
        pending += 1;
    }

    var expired: [call_capacity]discv5.calls.Expired = undefined;
    for (0..bootstrap_steps_max) |_| {
        if (pending == 0) break;
        if (try discv5.driver.monotonicMilliseconds(io) >= deadline_ms) break;
        const result = try transport.step(io, &expired);
        for (expired[0..result.calls_expired]) |item| {
            if (findBootstrap(bootstraps, item.handle)) |bootstrap| {
                bootstrap.handle = null;
                pending -= 1;
            }
        }
        const response = switch (result.event) {
            .response => |response| response,
            else => continue,
        };
        const bootstrap = findBootstrap(bootstraps, response.matched.handle) orelse continue;
        bootstrap.handle = null;
        pending -= 1;
        _ = transport.core.confirmPeer(
            &response.peer,
            &bootstrap.record,
            result.now_ms,
        ) catch continue;
        bootstrap.authenticated = true;
        _ = records.add(&bootstrap.record);
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
    transport: *discv5.driver.Driver,
    records: *RecordSet,
    deadline_ms: u64,
) !void {
    var slots = [_]LookupSlot{.{}} ** lookup_concurrency;
    defer for (&slots) |*slot| slot.cancel(transport.core);
    var expired: [call_capacity]discv5.calls.Expired = undefined;
    var operations: [lookup_concurrency]*discv5.lookup.Lookup = undefined;
    var launched: usize = 0;
    var completed: usize = 0;
    var rejections = std.EnumArray(discv5.types.RejectReason, u32).initFill(0);

    for (0..driver_steps_max) |_| {
        if (try discv5.driver.monotonicMilliseconds(io) >= deadline_ms) break;
        try startLookups(io, allocator, transport.core, &slots, &launched);

        const active = activeLookups(&slots, &operations);
        const result = try discv5.lookup_driver.step(transport, io, active, &expired);
        switch (result.driver.datagram) {
            .rejected => |reason| rejections.getPtr(reason).* += 1,
            .timeout, .accepted => {},
        }
        if (result.consumed != null) {
            for (result.driver.event.response.node_records) |*record| _ = records.add(record);
        }

        completed += finishLookups(transport.core, &slots);
        if (completed == lookup_total_max and activeLookups(&slots, &operations).len == 0) break;
        if (records.count == record_capacity) break;
    }

    std.debug.print("lookups launched={d} completed={d}\n", .{ launched, completed });
    printRejections(&rejections);
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
    allocator: std.mem.Allocator,
    core: *discv5.engine.Engine,
    slots: *[lookup_concurrency]LookupSlot,
    launched: *usize,
) !void {
    for (slots) |*slot| {
        if (slot.active or launched.* == lookup_total_max) continue;
        var target: discv5.types.NodeId = undefined;
        try std.Io.randomSecure(io, &target);
        var seeds_buffer: [discv5.lookup.result_max]discv5.routing.Entry = undefined;
        const seeds = core.closestNodes(&target, &seeds_buffer);
        if (seeds.len == 0) return;
        try slot.operation.init(
            allocator,
            core.channel.local_record.node_id,
            target,
            seeds,
        );
        slot.active = true;
        launched.* += 1;
    }
}

fn activeLookups(
    slots: *[lookup_concurrency]LookupSlot,
    out: *[lookup_concurrency]*discv5.lookup.Lookup,
) []const *discv5.lookup.Lookup {
    var count: usize = 0;
    for (slots) |*slot| {
        if (!slot.active) continue;
        out[count] = &slot.operation;
        count += 1;
    }
    return out[0..count];
}

fn finishLookups(
    core: *discv5.engine.Engine,
    slots: *[lookup_concurrency]LookupSlot,
) usize {
    var completed: usize = 0;
    for (slots) |*slot| {
        if (!slot.active or !slot.operation.isFinished()) continue;
        slot.cancel(core);
        completed += 1;
    }
    return completed;
}

fn findBootstrap(
    bootstraps: []Bootstrap,
    handle: discv5.calls.Handle,
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
    std.debug.assert(lookup_concurrency * discv5.lookup.parallelism <= call_capacity);
    std.debug.assert(record_capacity <= std.math.maxInt(u16));
    std.debug.assert(record_capacity >= discv5.routing.table_capacity);
}
