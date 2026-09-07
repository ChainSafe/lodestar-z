const std = @import("std");
const ForkSeq = @import("config").ForkSeq;
const constants = @import("constants");
const preset = @import("preset");
const Protocol = @import("protocol.zig").Protocol;
const limiter = @import("limiter.zig");

pub const BlobLimit = struct { start_slot: u64, max_blobs: u32 };
pub const Config = struct {
    deneb_start_slot: ?u64,
    blocks_pre_deneb: u32,
    blocks_deneb: u32,
    blob_identifiers_deneb: u32,
    blob_identifiers_electra: u32,
    number_of_columns: u16,
    column_chunks: u32,
    blob_schedule: []const BlobLimit,
    host_integer_max: ?u64 = null,
};
pub const Range = struct { start: u64, count: u64, end_exclusive: u64 };
pub const Inspection = struct {
    raw_cost: u128,
    charged_cost: u128,
    chunks_max: u32,
    range: ?Range = null,
};
pub const InspectError = error{ MalformedSsz, InvalidRequest, HostIntegerRange, UnsupportedBounds };
pub const schedule_max = 64;

pub const Policy = struct {
    config: Config,
    points: [schedule_max]BlobLimit = undefined,
    point_count: u8,

    pub fn init(config: *const Config) error{InvalidPolicy}!Policy {
        if (config.blocks_pre_deneb == 0 or config.blocks_pre_deneb > constants.MAX_REQUEST_BLOCKS or
            config.blocks_deneb == 0 or config.blocks_deneb > constants.MAX_REQUEST_BLOCKS_DENEB or
            config.blob_identifiers_deneb == 0 or config.blob_identifiers_deneb > constants.MAX_REQUEST_BLOB_SIDECARS_LIMIT or
            config.blob_identifiers_electra == 0 or config.blob_identifiers_electra > constants.MAX_REQUEST_BLOB_SIDECARS_LIMIT or
            config.number_of_columns != preset.NUMBER_OF_COLUMNS or
            config.column_chunks == 0 or config.column_chunks > preset.MAX_REQUEST_DATA_COLUMN_SIDECARS or
            config.blob_schedule.len > schedule_max) return error.InvalidPolicy;
        if (config.deneb_start_slot) |start| {
            if (config.blob_schedule.len == 0 or config.blob_schedule[0].start_slot != start) return error.InvalidPolicy;
        } else if (config.blob_schedule.len != 0) return error.InvalidPolicy;
        for (config.blob_schedule, 0..) |point, i| {
            if (point.max_blobs == 0 or @as(u64, point.max_blobs) * config.blocks_deneb > constants.MAX_REQUEST_BLOB_SIDECARS_LIMIT)
                return error.InvalidPolicy;
            if (i > 0 and point.start_slot <= config.blob_schedule[i - 1].start_slot) return error.InvalidPolicy;
        }
        var result: Policy = .{ .config = config.*, .point_count = @intCast(config.blob_schedule.len) };
        @memcpy(result.points[0..result.point_count], config.blob_schedule);
        result.config.blob_schedule = &.{};
        return result;
    }

    pub fn defaultQuotas(self: *const Policy, fork: ForkSeq) limiter.Quotas {
        var out = limiter.defaultQuotas();
        for ([_]Protocol{ .blocks_by_range_v2, .blocks_by_root_v2 }) |which|
            out[@intFromEnum(which)].tokens = self.blocks(fork);
        out[@intFromEnum(Protocol.blocks_by_head_v1)].tokens = self.config.blocks_deneb;
        for ([_]Protocol{ .blob_sidecars_by_range_v1, .blob_sidecars_by_root_v1 }) |which|
            out[@intFromEnum(which)].tokens = self.blobs(fork);
        for ([_]Protocol{ .data_column_sidecars_by_range_v1, .data_column_sidecars_by_root_v1 }) |which|
            out[@intFromEnum(which)].tokens = self.config.column_chunks;
        return out;
    }

    pub fn inspect(self: *const Policy, which: Protocol, bytes: []const u8, request_fork: ForkSeq) InspectError!Inspection {
        const bounds = which.info();
        if (bytes.len < bounds.request_min or bytes.len > bounds.request_max) return error.MalformedSsz;
        var cost: u128 = 1;
        var ceiling: u128 = bounds.chunks_max;
        var range: ?Range = null;
        switch (which) {
            .blocks_by_range_v2, .blob_sidecars_by_range_v1, .data_column_sidecars_by_range_v1, .light_client_updates_by_range_v1 => {
                const start = scalar(bytes, 0);
                const count = scalar(bytes, 8);
                if (count == 0 and which != .light_client_updates_by_range_v1) return error.InvalidRequest;
                try self.host(start);
                try self.host(count);
                const limit = switch (which) {
                    .blocks_by_range_v2 => if (self.config.deneb_start_slot != null and start >= self.config.deneb_start_slot.?) self.config.blocks_deneb else self.config.blocks_pre_deneb,
                    .light_client_updates_by_range_v1 => constants.MAX_REQUEST_LIGHT_CLIENT_UPDATES,
                    else => self.config.blocks_deneb,
                };
                const effective = @min(count, limit);
                const end = std.math.add(u64, start, effective) catch return error.InvalidRequest;
                try self.host(end);
                range = .{ .start = start, .count = effective, .end_exclusive = end };
                cost = count;
                ceiling = effective;
                if (which == .blob_sidecars_by_range_v1) {
                    ceiling = 0;
                    for (self.points[0..self.point_count], 0..) |point, i| {
                        const next = if (i + 1 < self.point_count) self.points[i + 1].start_slot else end;
                        const left = @max(start, point.start_slot);
                        const right = @min(end, next);
                        if (right > left) ceiling += @as(u128, right - left) * point.max_blobs;
                    }
                } else if (which == .data_column_sidecars_by_range_v1) {
                    if (offset(bytes, 16) != 20) return error.MalformedSsz;
                    const occurrences = try self.columns(bytes[20..]);
                    cost *= occurrences;
                    ceiling *= occurrences;
                }
            },
            .blocks_by_root_v2 => {
                if (bytes.len % 32 != 0 or bytes.len / 32 > self.blocks(request_fork)) return error.MalformedSsz;
                cost = bytes.len / 32;
                ceiling = cost;
            },
            .blob_sidecars_by_root_v1 => {
                if (bytes.len % 40 != 0 or bytes.len / 40 > self.blobs(request_fork)) return error.MalformedSsz;
                const count = bytes.len / 40;
                for (0..count) |i| try self.host(scalar(bytes, i * 40 + 32));
                cost = count;
                ceiling = cost;
            },
            .data_column_sidecars_by_root_v1 => {
                cost = 0;
                if (bytes.len != 0) {
                    if (bytes.len < 4) return error.MalformedSsz;
                    const first: usize = offset(bytes, 0);
                    if (first == 0 or first % 4 != 0 or first > bytes.len or first / 4 > self.config.blocks_deneb) return error.MalformedSsz;
                    const count = first / 4;
                    for (0..count) |i| {
                        const start: usize = offset(bytes, i * 4);
                        const end: usize = if (i + 1 < count) offset(bytes, (i + 1) * 4) else bytes.len;
                        if (start < first or end > bytes.len or start > end or end - start < 36) return error.MalformedSsz;
                        const element = bytes[start..end];
                        if (offset(element, 32) != 36) return error.MalformedSsz;
                        cost += try self.columns(element[36..]);
                    }
                }
                ceiling = cost;
            },
            .blocks_by_head_v1 => {
                const count = scalar(bytes, 32);
                if (count == 0) return error.InvalidRequest;
                try self.host(count);
                cost = count;
                ceiling = @min(count, self.config.blocks_deneb);
            },
            .status_v1, .status_v2 => {
                try self.host(scalar(bytes, 36));
                try self.host(scalar(bytes, 76));
                if (which == .status_v2) try self.host(scalar(bytes, 84));
            },
            .ping_v1, .goodbye_v1 => try self.host(scalar(bytes, 0)),
            .metadata_v1, .metadata_v2, .metadata_v3, .light_client_bootstrap_v1, .light_client_finality_update_v1, .light_client_optimistic_update_v1 => {},
        }
        const supported = if (which == .data_column_sidecars_by_range_v1 or which == .data_column_sidecars_by_root_v1)
            self.config.column_chunks
        else
            bounds.chunks_max;
        if (ceiling > supported) return error.UnsupportedBounds;
        return .{ .raw_cost = cost, .charged_cost = @max(1, cost), .chunks_max = @intCast(ceiling), .range = range };
    }

    fn columns(self: *const Policy, bytes: []const u8) InspectError!u64 {
        if (bytes.len % 8 != 0 or bytes.len / 8 > self.config.number_of_columns) return error.MalformedSsz;
        const count = bytes.len / 8;
        for (0..count) |i| try self.host(scalar(bytes, i * 8));
        return @intCast(count);
    }
    fn host(self: *const Policy, value: u64) InspectError!void {
        if (self.config.host_integer_max) |limit| if (value > limit) return error.HostIntegerRange;
    }
    fn blocks(self: *const Policy, fork: ForkSeq) u32 {
        return if (fork.gte(.deneb)) self.config.blocks_deneb else self.config.blocks_pre_deneb;
    }
    fn blobs(self: *const Policy, fork: ForkSeq) u32 {
        return if (fork.gte(.electra)) self.config.blob_identifiers_electra else self.config.blob_identifiers_deneb;
    }
};

fn scalar(bytes: []const u8, at: usize) u64 {
    std.debug.assert(at <= bytes.len and bytes.len - at >= 8);
    return std.mem.readInt(u64, bytes[at..][0..8], .little);
}
fn offset(bytes: []const u8, at: usize) u32 {
    std.debug.assert(at <= bytes.len and bytes.len - at >= 4);
    return std.mem.readInt(u32, bytes[at..][0..4], .little);
}
