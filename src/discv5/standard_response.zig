const std = @import("std");
const enr = @import("identity/enr.zig");
const types = @import("types.zig");
const constants = @import("wire/constants.zig");
const message = @import("wire/message.zig");

pub const Error = message.Error;

const Nodes = struct {
    request_id: message.RequestId,
    packet_count: u8,
};

pub const RawRecords = [types.findnode_result_max][]const u8;

pub const Plan = struct {
    peer: types.Endpoint = undefined,
    records: [types.findnode_result_max]enr.Record = undefined,
    boundaries: [types.findnode_response_packets_max + 1]u8 = undefined,
    sent: u8 = 0,
    body: union(enum) {
        none,
        pong: message.Pong,
        nodes: Nodes,
    } = .none,

    /// The returned NODES message borrows `raw` for its record slices.
    pub fn next(self: *const Plan, raw: *RawRecords) ?message.Message {
        return switch (self.body) {
            .none => null,
            .pong => |value| if (self.sent == 0) .{ .pong = value } else null,
            .nodes => |value| blk: {
                if (self.sent == value.packet_count) break :blk null;
                std.debug.assert(self.sent < value.packet_count);
                const start = self.boundaries[self.sent];
                const end = self.boundaries[self.sent + 1];
                std.debug.assert(start <= end);
                std.debug.assert(end <= self.records.len);
                break :blk .{ .nodes = .{
                    .request_id = value.request_id,
                    .total = value.packet_count,
                    .enrs = sliceRecords(self.records[start..end], raw),
                } };
            },
        };
    }

    pub fn markSent(self: *Plan) void {
        std.debug.assert(!self.complete());
        self.sent += 1;
    }

    pub fn complete(self: *const Plan) bool {
        return switch (self.body) {
            .none => true,
            .pong => self.sent == 1,
            .nodes => |value| self.sent == value.packet_count,
        };
    }
};

pub fn preparePong(
    plan: *Plan,
    peer: types.Endpoint,
    request_id: message.RequestId,
    local_enr_sequence: u64,
) void {
    plan.peer = peer;
    plan.sent = 0;
    plan.body = .{ .pong = switch (peer.address) {
        .ip4 => |address| .{
            .request_id = request_id,
            .enr_sequence = local_enr_sequence,
            .recipient_ip = .{ .ip4 = address.octets },
            .recipient_port = address.port,
        },
        .ip6 => |address| .{
            .request_id = request_id,
            .enr_sequence = local_enr_sequence,
            .recipient_ip = .{ .ip6 = address.octets },
            .recipient_port = address.port,
        },
    } };
}

pub fn prepareNodes(
    plan: *Plan,
    peer: types.Endpoint,
    request_id: message.RequestId,
    record_count: usize,
) Error!void {
    if (record_count > types.findnode_result_max) return Error.InvalidMessage;
    plan.peer = peer;
    plan.sent = 0;
    if (record_count == 0) {
        plan.boundaries[0] = 0;
        plan.boundaries[1] = 0;
        setNodes(plan, request_id, 1);
        return;
    }
    var raw_records: RawRecords = undefined;
    const raw = sliceRecords(plan.records[0..record_count], &raw_records);

    var packet_count: u8 = 0;
    var record_start: usize = 0;
    var encoded: [constants.ordinary_plaintext_size_max]u8 = undefined;
    while (record_start < record_count) {
        std.debug.assert(packet_count < types.findnode_response_packets_max);
        plan.boundaries[packet_count] = @intCast(record_start);
        var record_end = record_start;
        while (record_end < record_count) {
            const candidate = message.Message{
                .nodes = .{
                    .request_id = request_id,
                    // Counts 1 through 16 have the same one-byte RLP width.
                    .total = types.findnode_response_packets_max,
                    .enrs = raw[record_start .. record_end + 1],
                },
            };
            _ = candidate.encode(&encoded) catch |err| switch (err) {
                message.Error.InvalidMessage => break,
                else => return err,
            };
            record_end += 1;
        }
        if (record_end == record_start) return Error.InvalidMessage;
        packet_count += 1;
        record_start = record_end;
    }
    plan.boundaries[packet_count] = @intCast(record_count);
    setNodes(plan, request_id, packet_count);
}

fn sliceRecords(records: []const enr.Record, raw: *RawRecords) []const []const u8 {
    for (records, raw[0..records.len]) |*record, *slice| slice.* = record.slice();
    return raw[0..records.len];
}

fn setNodes(plan: *Plan, request_id: message.RequestId, packet_count: u8) void {
    std.debug.assert(packet_count > 0);
    std.debug.assert(packet_count <= types.findnode_response_packets_max);
    plan.body = .{ .nodes = .{
        .request_id = request_id,
        .packet_count = packet_count,
    } };
}

comptime {
    std.debug.assert(@sizeOf(Plan) <= 8 * 1_024);
}
