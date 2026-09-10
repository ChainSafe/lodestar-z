const std = @import("std");
const routing = @import("router.zig");
const reqresp = @import("reqresp/protocol.zig");
const ForkSeq = @import("config").ForkSeq;
const Version = @import("gossipsub/sessions.zig").Version;

pub const protocol_count = reqresp.Protocol.count + 4;
const Bits = std.meta.Int(.unsigned, protocol_count);

pub const Set = struct {
    bits: Bits = 0,

    pub fn initEmpty() Set {
        return .{};
    }

    pub fn insert(self: *Set, protocol: routing.Protocol) void {
        self.bits |= bit(protocol);
    }

    pub fn contains(self: Set, protocol: routing.Protocol) bool {
        return self.bits & bit(protocol) != 0;
    }

    pub fn count(self: Set) u8 {
        return @popCount(self.bits);
    }

    fn bit(protocol: routing.Protocol) Bits {
        const index: std.math.Log2Int(Bits) = @intCast(switch (protocol) {
            .identify => reqresp.Protocol.count + 3,
            .reqresp => |which| @as(u8, @intFromEnum(which)),
            .meshsub => |version| reqresp.Protocol.count + @intFromEnum(version),
        });
        return @as(Bits, 1) << index;
    }
};

pub const Directional = struct { receive: Set, request: Set };

/// Produces the implemented host subset. Phase0 block v1 is not implemented.
/// Metadata3 serving requires a real configured local custody count even before Fulu.
/// Gloas requires payload protocols that are not yet implemented.
pub fn forFork(fork: ForkSeq, serve_light_clients: bool, meshsub_versions: []const Version) error{InvalidCapabilities}!Directional {
    if (fork.gte(.gloas)) return error.InvalidCapabilities;
    if (meshsub_versions.len == 0 or meshsub_versions.len > 3) return error.InvalidCapabilities;
    var common: Set = .initEmpty();
    for (meshsub_versions) |version| {
        const protocol: routing.Protocol = .{ .meshsub = version };
        if (common.contains(protocol)) return error.InvalidCapabilities;
        common.insert(protocol);
    }
    for ([_]reqresp.Protocol{ .ping_v1, .goodbye_v1, .metadata_v3, .blocks_by_range_v2, .blocks_by_root_v2 }) |protocol| common.insert(.{ .reqresp = protocol });
    if (fork.lt(.altair)) common.insert(.{ .reqresp = .metadata_v1 });
    if (fork.lt(.fulu)) {
        common.insert(.{ .reqresp = .status_v1 });
        common.insert(.{ .reqresp = .metadata_v2 });
    } else {
        for ([_]reqresp.Protocol{ .status_v2, .blocks_by_head_v1, .data_column_sidecars_by_range_v1, .data_column_sidecars_by_root_v1 }) |protocol| common.insert(.{ .reqresp = protocol });
    }
    if (fork.gte(.deneb)) {
        common.insert(.{ .reqresp = .blob_sidecars_by_range_v1 });
        common.insert(.{ .reqresp = .blob_sidecars_by_root_v1 });
    }
    var active: Directional = .{ .receive = common, .request = common };
    if (fork.gte(.altair)) for ([_]reqresp.Protocol{ .light_client_bootstrap_v1, .light_client_updates_by_range_v1, .light_client_finality_update_v1, .light_client_optimistic_update_v1 }) |protocol| {
        active.request.insert(.{ .reqresp = protocol });
        if (serve_light_clients) active.receive.insert(.{ .reqresp = protocol });
    };
    return active;
}

/// Compose with forFork for full-host startup and local updates when Identify is configured.
pub fn withIdentify(active: Directional) Directional {
    var result = active;
    result.receive.insert(.identify);
    result.request.insert(.identify);
    return result;
}
