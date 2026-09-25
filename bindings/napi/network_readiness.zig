//! Which host work an exchange would deliver now, and when the host must hear of it. Each row sits in none, the
//! control list, the payload list, or parked (work whose host capacity is zero); a row an exchange pinned sits in
//! none until it is unpinned. Only `pin`, `unpin` and `recompute` change membership, under the runtime mutex.
//!
//! An exchange arms when both lists are empty. The next move of a row into a list from outside them, or from none
//! to parked, disarms and notifies, so while disarmed another exchange is guaranteed: scheduled, queued or running.
const std = @import("std");
const lists = @import("network").index_list;

pub const Row = enum(u8) { legacy, peers, checks, serving, gossip };
pub const Place = enum { none, control, payload, parked };
pub const row_count = @typeInfo(Row).@"enum".fields.len;

const Entry = struct { link: lists.Link = .{}, place: Place = .none, pinned: bool = false };

pub const Readiness = struct {
    rows: [row_count]Entry = @splat(.{}),
    control: lists.List = .{},
    payload: lists.List = .{},
    armed: bool = true,

    pub fn place(self: *const Readiness, row: Row) Place {
        return self.rows[@intFromEnum(row)].place;
    }

    fn list(self: *Readiness, where: Place) ?*lists.List {
        return switch (where) {
            .control => &self.control,
            .payload => &self.payload,
            .none, .parked => null,
        };
    }

    /// Moves an unpinned `row` to `want`; a row that stays queued keeps its position. Returns whether the move
    /// disarmed, so the caller must notify the host.
    pub fn recompute(self: *Readiness, row: Row, want: Place) bool {
        const entry = &self.rows[@intFromEnum(row)];
        if (entry.pinned or entry.place == want) return false;
        const previous = entry.place;
        if (self.list(previous)) |from| from.remove(&self.rows, "link", @intFromEnum(row));
        if (self.list(want)) |to| to.append(&self.rows, "link", @intFromEnum(row));
        entry.place = want;
        const wake = (queued(want) and !queued(previous)) or (previous == .none and want == .parked);
        if (!wake or !self.armed) return false;
        self.armed = false;
        return true;
    }

    /// Takes a queued `row` out of its list for one delivery. Returns the list it came from.
    pub fn pin(self: *Readiness, row: Row) Place {
        const entry = &self.rows[@intFromEnum(row)];
        std.debug.assert(!entry.pinned and queued(entry.place));
        const from = entry.place;
        self.list(from).?.remove(&self.rows, "link", @intFromEnum(row));
        entry.* = .{ .pinned = true };
        return from;
    }

    /// Ends a delivery while disarmed. A rolled-back row that still wants its list returns to the head, so unpinning
    /// in reverse selection order keeps the order; otherwise it moves to `want`.
    pub fn unpin(self: *Readiness, row: Row, from: Place, want: Place, rollback: bool) void {
        std.debug.assert(!self.armed);
        const entry = &self.rows[@intFromEnum(row)];
        std.debug.assert(entry.pinned);
        entry.pinned = false;
        if (rollback and want == from) {
            self.list(from).?.prepend(&self.rows, "link", @intFromEnum(row));
            entry.place = from;
            return;
        }
        _ = self.recompute(row, want);
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
