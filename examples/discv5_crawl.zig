//! Starts one DiscV5 node, authenticates configured bootnodes, and runs a bounded set of
//! concurrent random lookups.
//!
//! zig build run:discv5_crawl -- 0.0.0.0:9000 203.0.113.10:9000 enr:... [enr:...]

const std = @import("std");
const discv5 = @import("discv5");

const net = std.Io.net;
const bootstrap_capacity: usize = 32;
const bootstrap_steps_max: usize = 4_096;
const call_capacity: usize = 64;
const driver_steps_max: usize = 12_000;
const key_generation_attempts_max: usize = 16;
const lookup_concurrency: usize = 4;
const lookup_total_max: usize = 64;
const poll_interval_ms: u32 = 25;
const record_capacity: usize = discv5.routing.table_capacity;

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
    records: [record_capacity]discv5.identity.enr.Record = undefined,
    count: u16 = 0,

    fn add(self: *RecordSet, record: *const discv5.identity.enr.Record) bool {
        for (self.records[0..self.count]) |*stored| {
            if (!std.mem.eql(u8, &stored.node_id, &record.node_id)) continue;
            if (record.sequence > stored.sequence) stored.* = record.*;
            return false;
        }
        if (self.count == self.records.len) return false;
        self.records[self.count] = record.*;
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
            "usage: {s} <bind-ip:port> <advertised-ip:port> <boot-enr> [boot-enr...]\n",
            .{args[0]},
        );
        return;
    }
    if (args.len - 3 > bootstrap_capacity) return error.TooManyBootnodes;

    const bind_address = try net.IpAddress.parseLiteral(args[1]);
    const advertised_address = toDiscv5Address(try net.IpAddress.parseLiteral(args[2]));
    var udp = try discv5.runtime.Udp.bind(io, bind_address);
    defer udp.close(io);
    const bound_address = udp.localAddress();
    if (std.meta.activeTag(bound_address) != std.meta.activeTag(advertised_address))
        return error.AdvertisedAddressFamilyMismatch;
    if (addressPort(bound_address) != addressPort(advertised_address))
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
        args[3..],
        std.meta.activeTag(advertised_address),
        &bootstraps,
    );
    var records = RecordSet{};
    const authenticated = try authenticateBootstraps(
        io,
        &transport,
        bootstraps_slice,
        &records,
    );
    if (core.routing.count() == 0) return error.NoReachableBootnodes;

    std.debug.print(
        "node bound on {any}, authenticated {d}/{d} bootnodes\n",
        .{ udp.localAddress(), authenticated, bootstraps_slice.len },
    );
    try crawl(io, allocator, &transport, &records);
    std.debug.print(
        "collected {d} authenticated peer records from {d} routing entries\n",
        .{ records.count, core.routing.count() },
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
) !usize {
    var pending: usize = 0;
    for (bootstraps, 0..) |*bootstrap, index| {
        const request = discv5.wire.message.Message{ .ping = .{
            .request_id = requestId(index + 1),
            .enr_sequence = transport.core.local_record.sequence,
        } };
        bootstrap.handle = try transport.startCallKnown(
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
) !void {
    var slots = [_]LookupSlot{.{}} ** lookup_concurrency;
    defer for (&slots) |*slot| slot.cancel(transport.core);
    var expired: [call_capacity]discv5.calls.Expired = undefined;
    var launched: usize = 0;
    var completed: usize = 0;
    var rejected: usize = 0;
    var refill_cursor: usize = 0;

    for (0..driver_steps_max) |_| {
        try startLookups(io, allocator, transport.core, &slots, &launched);
        try refillLookups(io, transport, &slots, refill_cursor);
        refill_cursor = (refill_cursor + 1) % slots.len;
        completed += finishLookups(transport.core, &slots, records);
        if (completed == lookup_total_max and activeLookupCount(&slots) == 0) break;
        if (records.count == record_capacity) break;

        const result = try transport.step(io, &expired);
        if (result.datagram == .rejected) rejected += 1;
        try routeExpiries(transport.core, &slots, expired[0..result.calls_expired]);
        try routeEvent(transport.core, &slots, &result);
    }

    for (&slots) |*slot| {
        if (!slot.active) continue;
        collectLookupResults(&slot.operation, records);
        slot.cancel(transport.core);
    }
    std.debug.print(
        "lookups launched={d} completed={d} rejected_datagrams={d}\n",
        .{ launched, completed, rejected },
    );
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
            core.local_record.node_id,
            target,
            seeds,
        );
        slot.active = true;
        launched.* += 1;
    }
}

fn refillLookups(
    io: std.Io,
    transport: *discv5.driver.Driver,
    slots: *[lookup_concurrency]LookupSlot,
    cursor: usize,
) !void {
    for (0..discv5.lookup.parallelism) |_| {
        for (0..slots.len) |offset| {
            const slot = &slots[(cursor + offset) % slots.len];
            if (!slot.active or slot.operation.isFinished() or
                slot.operation.waitingCount() == discv5.lookup.parallelism) continue;
            const started = transport.startLookupCall(io, &slot.operation) catch |err| switch (err) {
                error.PeerBusy, error.TableFull => continue,
                else => return err,
            };
            if (!started) continue;
        }
    }
}

fn finishLookups(
    core: *discv5.engine.Engine,
    slots: *[lookup_concurrency]LookupSlot,
    records: *RecordSet,
) usize {
    var completed: usize = 0;
    for (slots) |*slot| {
        if (!slot.active or !slot.operation.isFinished()) continue;
        collectLookupResults(&slot.operation, records);
        slot.cancel(core);
        completed += 1;
    }
    return completed;
}

fn collectLookupResults(operation: *const discv5.lookup.Lookup, records: *RecordSet) void {
    var result_buffer: [discv5.lookup.result_max]discv5.identity.enr.Record = undefined;
    for (operation.results(&result_buffer)) |*record| _ = records.add(record);
}

fn routeExpiries(
    core: *discv5.engine.Engine,
    slots: *[lookup_concurrency]LookupSlot,
    expired: []const discv5.calls.Expired,
) !void {
    for (expired) |item| {
        for (slots) |*slot| {
            if (!slot.active or !slot.operation.ownsCall(item.handle)) continue;
            try slot.operation.onFailure(core, item.handle);
            break;
        }
    }
}

fn routeEvent(
    core: *discv5.engine.Engine,
    slots: *[lookup_concurrency]LookupSlot,
    result: *const discv5.driver.StepResult,
) !void {
    const response = switch (result.event) {
        .response => |response| response,
        else => return,
    };
    for (slots) |*slot| {
        if (!slot.active or !slot.operation.ownsCall(response.matched.handle)) continue;
        try slot.operation.onResponse(core, &response, result.now_ms);
        return;
    }
}

fn activeLookupCount(slots: *const [lookup_concurrency]LookupSlot) usize {
    var count: usize = 0;
    for (slots) |slot| if (slot.active) {
        count += 1;
    };
    return count;
}

fn findBootstrap(
    bootstraps: []Bootstrap,
    handle: discv5.calls.Handle,
) ?*Bootstrap {
    for (bootstraps) |*bootstrap| {
        const stored = bootstrap.handle orelse continue;
        if (stored.index == handle.index and stored.generation == handle.generation)
            return bootstrap;
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

fn toDiscv5Address(address: net.IpAddress) discv5.types.Address {
    return switch (address) {
        .ip4 => |value| .{ .ip4 = .{ .octets = value.bytes, .port = value.port } },
        .ip6 => |value| .{ .ip6 = .{
            .octets = value.bytes,
            .port = value.port,
            .interface = value.interface.index,
        } },
    };
}

fn addressPort(address: discv5.types.Address) u16 {
    return switch (address) {
        inline else => |value| value.port,
    };
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
    std.debug.assert(lookup_concurrency * discv5.lookup.parallelism <= call_capacity);
    std.debug.assert(record_capacity <= std.math.maxInt(u16));
}
