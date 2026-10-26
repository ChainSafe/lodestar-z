const std = @import("std");

pub const Resource = enum { bridge_slots, bridge_bytes, requests, negotiations };
pub const count = @typeInfo(Resource).@"enum".fields.len;
pub const token_max = 64;
pub const Token = struct {
    instance: u64,
    resource: Resource,
    revision: u64,

    pub fn format(self: Token, buffer: *[token_max]u8) []const u8 {
        return std.fmt.bufPrint(buffer, "{x}:{d}:{x}", .{ self.instance, @intFromEnum(self.resource), self.revision }) catch unreachable;
    }

    pub fn parse(text: []const u8) error{InvalidRequestCapacityToken}!Token {
        if (text.len == 0 or text.len > token_max) return error.InvalidRequestCapacityToken;
        var parts = std.mem.splitScalar(u8, text, ':');
        const instance = std.fmt.parseInt(u64, parts.next() orelse return error.InvalidRequestCapacityToken, 16) catch return error.InvalidRequestCapacityToken;
        const resource = std.fmt.parseInt(u8, parts.next() orelse return error.InvalidRequestCapacityToken, 10) catch return error.InvalidRequestCapacityToken;
        const revision = std.fmt.parseInt(u64, parts.next() orelse return error.InvalidRequestCapacityToken, 16) catch return error.InvalidRequestCapacityToken;
        if (parts.next() != null or resource >= count) return error.InvalidRequestCapacityToken;
        return .{ .instance = instance, .resource = @enumFromInt(resource), .revision = revision };
    }
};

/// The bridge mutex protects revisions, subscriptions and delivery. No request storage is retained by a watch.
pub const Tracker = struct {
    instance: u64 = 0,
    revisions: [count]u64 = @splat(0),
    armed: std.StaticBitSet(count) = .empty,
    pending: bool = false,

    pub fn token(self: *const Tracker, resource: Resource) Token {
        return .{ .instance = self.instance, .resource = resource, .revision = self.revisions[@intFromEnum(resource)] };
    }

    pub fn update(self: *Tracker, resource: Resource, revision: u64) void {
        const index = @intFromEnum(resource);
        std.debug.assert(revision >= self.revisions[index]);
        if (revision == self.revisions[index]) return;
        self.revisions[index] = revision;
        if (self.armed.isSet(index)) {
            self.armed.unset(index);
            self.pending = true;
        }
    }

    pub fn watch(self: *Tracker, since: Token) error{InvalidRequestCapacityToken}!bool {
        if (since.instance != self.instance) return error.InvalidRequestCapacityToken;
        const index = @intFromEnum(since.resource);
        if (since.revision > self.revisions[index]) return error.InvalidRequestCapacityToken;
        if (since.revision != self.revisions[index]) return true;
        self.armed.set(index);
        return false;
    }
};

test {
    _ = @import("network_request_capacity_test.zig");
}
