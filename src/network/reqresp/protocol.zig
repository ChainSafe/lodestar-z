const std = @import("std");
const constants = @import("constants.zig");
const consensus = @import("constants");
const ct = @import("consensus_types");
const preset = @import("preset");
const config = @import("config");
const codec = @import("codec.zig");
const response_bounds = @import("response_bounds.zig");

const assert = std.debug.assert;

pub const prefix = "/eth2/beacon_chain/req/";
pub const suffix = "/ssz_snappy";

pub const Protocol = enum(u8) {
    status_v1,
    status_v2,
    goodbye_v1,
    ping_v1,
    metadata_v1,
    metadata_v2,
    metadata_v3,
    blocks_by_range_v2,
    blocks_by_root_v2,
    blob_sidecars_by_range_v1,
    blob_sidecars_by_root_v1,
    data_column_sidecars_by_range_v1,
    data_column_sidecars_by_root_v1,

    blocks_by_head_v1,
    light_client_bootstrap_v1,
    light_client_updates_by_range_v1,
    light_client_finality_update_v1,
    light_client_optimistic_update_v1,

    pub const count: u8 = @intCast(@typeInfo(Protocol).@"enum".fields.len);

    pub fn id(self: Protocol) []const u8 {
        return ids[@intFromEnum(self)];
    }

    pub fn fromId(candidate: []const u8) ?Protocol {
        assert(ids.len == count);
        if (candidate.len > id_length_max) return null;
        for (ids, 0..) |known, index| {
            if (std.mem.eql(u8, known, candidate)) return @enumFromInt(index);
        }
        return null;
    }

    pub fn isControl(self: Protocol) bool {
        return switch (self) {
            .status_v1, .status_v2, .goodbye_v1, .ping_v1, .metadata_v1, .metadata_v2, .metadata_v3 => true,
            .blocks_by_range_v2, .blocks_by_root_v2, .blob_sidecars_by_range_v1, .blob_sidecars_by_root_v1, .data_column_sidecars_by_range_v1, .data_column_sidecars_by_root_v1, .blocks_by_head_v1, .light_client_bootstrap_v1, .light_client_updates_by_range_v1, .light_client_finality_update_v1, .light_client_optimistic_update_v1 => false,
        };
    }

    pub fn responseFamily(self: Protocol) ?response_bounds.Family {
        return switch (self) {
            .blocks_by_range_v2, .blocks_by_root_v2, .blocks_by_head_v1 => .block,
            .blob_sidecars_by_range_v1, .blob_sidecars_by_root_v1 => .blob,
            .data_column_sidecars_by_range_v1, .data_column_sidecars_by_root_v1 => .column,
            .light_client_bootstrap_v1 => .light_client_bootstrap,
            .light_client_updates_by_range_v1 => .light_client_update,
            .light_client_finality_update_v1 => .light_client_finality_update,
            .light_client_optimistic_update_v1 => .light_client_optimistic_update,
            .status_v1, .status_v2, .goodbye_v1, .ping_v1, .metadata_v1, .metadata_v2, .metadata_v3 => null,
        };
    }

    pub fn responseBounds(self: Protocol, fork: config.ForkSeq) error{InvalidResponseContext}!codec.Bounds {
        return response_bounds.forFork(self.responseFamily() orelse return error.InvalidResponseContext, fork);
    }

    pub fn info(self: Protocol) Info {
        return table[@intFromEnum(self)];
    }
};

pub const Info = struct {
    request_min: usize,
    request_max: usize,
    response_min: usize,
    response_max: usize,
    context_bytes: bool,
    chunks_max: u32,
    quota_tokens: u32,
    quota_period_ms: u64,
};

fn name(comptime protocol: Protocol) []const u8 {
    return switch (protocol) {
        .status_v1, .status_v2 => "status",
        .goodbye_v1 => "goodbye",
        .ping_v1 => "ping",
        .metadata_v1, .metadata_v2, .metadata_v3 => "metadata",
        .blocks_by_range_v2 => "beacon_blocks_by_range",
        .blocks_by_root_v2 => "beacon_blocks_by_root",
        .blob_sidecars_by_range_v1 => "blob_sidecars_by_range",
        .blob_sidecars_by_root_v1 => "blob_sidecars_by_root",
        .data_column_sidecars_by_range_v1 => "data_column_sidecars_by_range",
        .data_column_sidecars_by_root_v1 => "data_column_sidecars_by_root",
        .blocks_by_head_v1 => "beacon_blocks_by_head",
        .light_client_bootstrap_v1 => "light_client_bootstrap",
        .light_client_updates_by_range_v1 => "light_client_updates_by_range",
        .light_client_finality_update_v1 => "light_client_finality_update",
        .light_client_optimistic_update_v1 => "light_client_optimistic_update",
    };
}

fn version(comptime protocol: Protocol) []const u8 {
    return switch (protocol) {
        .status_v2, .metadata_v2, .blocks_by_range_v2, .blocks_by_root_v2 => "2",
        .metadata_v3 => "3",
        else => "1",
    };
}

pub const ids: [Protocol.count][]const u8 = blk: {
    var out: [Protocol.count][]const u8 = undefined;
    for (@typeInfo(Protocol).@"enum".fields, 0..) |field, index| {
        const protocol: Protocol = @enumFromInt(field.value);
        out[index] = prefix ++ name(protocol) ++ "/" ++ version(protocol) ++ suffix;
    }
    break :blk out;
};

pub const id_length_max: usize = blk: {
    var longest: usize = 0;
    for (ids) |candidate| longest = @max(longest, candidate.len);
    break :blk longest;
};

const ten_seconds_ms: u64 = 10_000;

fn entry(comptime protocol: Protocol) Info {
    return switch (protocol) {
        .blocks_by_head_v1 => chunked(40, 40, consensus.MAX_REQUEST_BLOCKS_DENEB, 128),
        .light_client_bootstrap_v1 => contextualSingle(32, 5, 15_000),
        .light_client_updates_by_range_v1 => chunked(16, 16, consensus.MAX_REQUEST_LIGHT_CLIENT_UPDATES, 128),
        .light_client_finality_update_v1, .light_client_optimistic_update_v1 => contextualSingle(0, 2, 12_000),
        .status_v1 => single(ct.phase0.Status.fixed_size, ct.phase0.Status.fixed_size, 5, 15_000),
        .status_v2 => single(ct.fulu.StatusV2.fixed_size, ct.fulu.StatusV2.fixed_size, 5, 15_000),
        .goodbye_v1 => single(
            ct.phase0.Goodbye.fixed_size,
            ct.phase0.Goodbye.fixed_size,
            1,
            ten_seconds_ms,
        ),
        .ping_v1 => single(ct.phase0.Ping.fixed_size, ct.phase0.Ping.fixed_size, 2, ten_seconds_ms),
        .metadata_v1 => single(0, ct.phase0.MetaDataV1.fixed_size, 2, 5_000),
        .metadata_v2 => single(0, ct.altair.MetaDataV2.fixed_size, 2, 5_000),
        .metadata_v3 => single(0, ct.fulu.MetaDataV3.fixed_size, 2, 5_000),
        .blocks_by_range_v2 => chunked(
            ct.phase0.BeaconBlocksByRangeRequest.fixed_size,
            ct.phase0.BeaconBlocksByRangeRequest.fixed_size,
            consensus.MAX_REQUEST_BLOCKS_DENEB,
            128,
        ),
        .blocks_by_root_v2 => chunked(
            0,
            ct.deneb.BeaconBlockRootsDeneb.max_size,
            consensus.MAX_REQUEST_BLOCKS_DENEB,
            128,
        ),
        .blob_sidecars_by_range_v1 => chunked(
            ct.deneb.BlobSidecarsByRangeRequest.fixed_size,
            ct.deneb.BlobSidecarsByRangeRequest.fixed_size,
            consensus.MAX_REQUEST_BLOB_SIDECARS_LIMIT,
            768,
        ),
        .blob_sidecars_by_root_v1 => chunked(
            0,
            ct.deneb.BlobIdentifiers.max_size,
            consensus.MAX_REQUEST_BLOB_SIDECARS_LIMIT,
            768,
        ),
        .data_column_sidecars_by_range_v1 => chunked(
            ct.fulu.DataColumnSidecarsByRangeRequest.min_size,
            ct.fulu.DataColumnSidecarsByRangeRequest.max_size,
            preset.MAX_REQUEST_DATA_COLUMN_SIDECARS,
            16_384,
        ),
        .data_column_sidecars_by_root_v1 => chunked(
            0,
            ct.fulu.DataColumnsByRootIdentifiers.max_size,
            preset.MAX_REQUEST_DATA_COLUMN_SIDECARS,
            16_384,
        ),
    };
}

fn contextualSingle(request: usize, tokens: u32, period_ms: u64) Info {
    var info = single(request, 0, tokens, period_ms);
    info.context_bytes = true;
    return info;
}

fn single(request: usize, response: usize, tokens: u32, period_ms: u64) Info {
    return .{
        .request_min = request,
        .request_max = request,
        .response_min = response,
        .response_max = response,
        .context_bytes = false,
        .chunks_max = 1,
        .quota_tokens = tokens,
        .quota_period_ms = period_ms,
    };
}

fn chunked(
    request_min: usize,
    request_max: usize,
    chunks: usize,
    tokens: u32,
) Info {
    return .{
        .request_min = request_min,
        .request_max = request_max,
        .response_min = 0,
        .response_max = 0,
        .context_bytes = true,
        .chunks_max = @intCast(chunks),
        .quota_tokens = tokens,
        .quota_period_ms = ten_seconds_ms,
    };
}

const table: [Protocol.count]Info = blk: {
    var out: [Protocol.count]Info = undefined;
    for (@typeInfo(Protocol).@"enum".fields, 0..) |field, index| {
        const which: Protocol = @enumFromInt(field.value);
        out[index] = entry(which);
        if (which.responseFamily()) |family| {
            const bounds = response_bounds.unionFor(family);
            out[index].response_min = bounds.min;
            out[index].response_max = bounds.max;
        }
    }
    break :blk out;
};

pub fn requestMaxAll() usize {
    comptime var longest: usize = 0;
    inline for (table) |bounds| longest = @max(longest, bounds.request_max);
    return longest;
}

pub fn requestMaxControl() usize {
    comptime var longest: usize = 0;
    inline for (table, 0..) |bounds, index| {
        if (comptime @as(Protocol, @enumFromInt(index)).isControl()) longest = @max(longest, bounds.request_max);
    }
    return longest;
}

pub fn responseMaxAll() usize {
    comptime var longest: usize = 0;
    inline for (table) |bounds| longest = @max(longest, bounds.response_max);
    return longest;
}

comptime {
    assert(Protocol.count == 18);
    for (table) |bounds| {
        assert(bounds.request_min <= bounds.request_max);
        assert(bounds.response_min <= bounds.response_max);
        assert(bounds.response_max <= constants.MAX_PAYLOAD_SIZE);
        assert(bounds.chunks_max >= 1);
        assert(bounds.quota_tokens >= 1);
        assert(bounds.quota_period_ms >= 1);
    }
    for (ids, 0..) |candidate, index| {
        for (ids[0..index]) |earlier| assert(!std.mem.eql(u8, candidate, earlier));
        assert(candidate.len <= id_length_max);
    }
    assert(requestMaxAll() >= ct.deneb.BlobIdentifiers.max_size);
}

pub fn requestChunkLimit(which: Protocol, bytes: []const u8) error{InvalidRequest}!u32 {
    const info = which.info();
    if (bytes.len < info.request_min or bytes.len > info.request_max) return error.InvalidRequest;
    switch (which) {
        .blocks_by_head_v1 => {
            const raw_count = std.mem.readInt(u64, bytes[32..40], .little);
            if (raw_count == 0) return error.InvalidRequest;
            return @intCast(@min(raw_count, consensus.MAX_REQUEST_BLOCKS_DENEB));
        },
        .light_client_updates_by_range_v1 => {
            const start = std.mem.readInt(u64, bytes[0..8], .little);
            const raw_count = std.mem.readInt(u64, bytes[8..16], .little);
            const effective = @min(raw_count, consensus.MAX_REQUEST_LIGHT_CLIENT_UPDATES);
            _ = std.math.add(u64, start, effective) catch return error.InvalidRequest;
            return @intCast(effective);
        },
        else => return info.chunks_max,
    }
}
