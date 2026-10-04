//! Which host work an exchange would deliver now, and when the host must hear of it. Each delivery kind sits in none, the
//! control list, the payload list, or parked (work whose host capacity is zero); a delivery kind an exchange pinned sits in
//! none until it is unpinned. Only `pin`, `unpin`, `recompute` and `forget` change membership, under the runtime
//! mutex.
//!
//! An exchange arms when both lists are empty. The next move of a delivery kind into a list from outside them, or from none
//! to parked, disarms and notifies, so while disarmed another exchange is guaranteed: scheduled, queued or running.
const std = @import("std");
const lists = @import("network").index_list;

pub const DeliveryKind = enum(u8) { completions, peers, checks, serving, gossip };
pub const Place = enum { none, control, payload, parked };
pub const delivery_kind_count = @typeInfo(DeliveryKind).@"enum".fields.len;

const Entry = struct { link: lists.Link = .{}, place: Place = .none, pinned: bool = false };

pub const Readiness = struct {
    entries: [delivery_kind_count]Entry = @splat(.{}),
    control: lists.List = .{},
    payload: lists.List = .{},
    armed: bool = true,

    pub fn place(self: *const Readiness, kind: DeliveryKind) Place {
        return self.entries[@intFromEnum(kind)].place;
    }

    fn list(self: *Readiness, where: Place) ?*lists.List {
        return switch (where) {
            .control => &self.control,
            .payload => &self.payload,
            .none, .parked => null,
        };
    }

    /// Moves an unpinned `kind` to `want`; an entry that stays queued keeps its position. Returns whether the move
    /// disarmed, so the caller must notify the host.
    pub fn recompute(self: *Readiness, kind: DeliveryKind, want: Place) bool {
        const entry = &self.entries[@intFromEnum(kind)];
        if (entry.pinned or entry.place == want) return false;
        const previous = entry.place;
        if (self.list(previous)) |from| from.remove(&self.entries, "link", @intFromEnum(kind));
        if (self.list(want)) |to| to.append(&self.entries, "link", @intFromEnum(kind));
        entry.place = want;
        const wake = (queued(want) and !queued(previous)) or (previous == .none and want == .parked);
        if (!wake or !self.armed) return false;
        self.armed = false;
        return true;
    }

    /// Takes a queued `kind` out of its list for one delivery.
    pub fn pin(self: *Readiness, kind: DeliveryKind) void {
        const entry = &self.entries[@intFromEnum(kind)];
        std.debug.assert(!entry.pinned and queued(entry.place));
        self.list(entry.place).?.remove(&self.entries, "link", @intFromEnum(kind));
        entry.* = .{ .pinned = true };
    }

    /// Ends a delivery while disarmed: the delivery kind moves to `want`, at the back of a list.
    pub fn unpin(self: *Readiness, kind: DeliveryKind, want: Place) void {
        std.debug.assert(!self.armed);
        const entry = &self.entries[@intFromEnum(kind)];
        std.debug.assert(entry.pinned);
        entry.pinned = false;
        _ = self.recompute(kind, want);
    }

    /// Takes every delivery kind out of the lists and arms, so owner activity that recomputes an entry with work can notify
    /// again. For a host that threw on a notification, outside any exchange; the next exchange refreshes every delivery kind.
    pub fn forget(self: *Readiness) void {
        for (&self.entries, 0..) |*entry, i| {
            std.debug.assert(!entry.pinned);
            if (self.list(entry.place)) |from| from.remove(&self.entries, "link", @intCast(i));
            entry.place = .none;
        }
        self.armed = true;
    }

    pub fn arm(self: *Readiness) bool {
        self.armed = self.control.len == 0 and self.payload.len == 0;
        return self.armed;
    }
};

fn queued(where: Place) bool {
    return where == .control or where == .payload;
}

test {
    _ = @import("network_readiness_test.zig");
}
