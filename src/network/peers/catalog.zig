const std = @import("std");
const t = @import("types.zig");
const reputation = @import("reputation.zig");

pub const Row = struct {
    generation: u64 = 0,
    occupied: bool = false,
    identity: t.PeerId = undefined,
    connection: ?t.Handle = null,
    closing_reason: ?t.DisconnectReason = null,
    direction: t.Direction = .inbound,
    endpoint: t.Address = .unspecified,
    status: ?t.Status = null,
    metadata: ?t.Metadata = null,
    status_at_ms: u64 = 0,
    metadata_at_ms: u64 = 0,
    connected_at_ms: u64 = 0,
    direct: bool = false,
    reputation: reputation.State = .{},
    published: bool = false,
    pending_update: bool = false,
    pending_close: ?struct { connection: t.Handle, reason: t.DisconnectReason } = null,
};

pub const Catalog = struct {
    rows: []Row,
    options: t.Options,
    event_cursor: usize = 0,

    pub fn init(a: std.mem.Allocator, options: t.Options) !Catalog {
        try options.validate();
        const rows = try a.alloc(Row, options.capacity);
        @memset(rows, .{});
        return .{ .rows = rows, .options = options };
    }

    pub fn deinit(self: *Catalog, a: std.mem.Allocator) void {
        a.free(self.rows);
        self.* = undefined;
    }

    pub fn memoryPlan(self: *const Catalog) t.MemoryPlan {
        return .{
            .inline_bytes = @sizeOf(Catalog),
            .allocated_bytes = self.rows.len * @sizeOf(Row),
            .rows = self.options.capacity,
            .notification_slots = self.options.capacity,
        };
    }

    pub fn find(self: *const Catalog, identity: *const t.PeerId) ?t.PeerRef {
        for (self.rows, 0..) |*row, index| {
            if (row.occupied and row.identity.eql(identity))
                return .{ .index = @intCast(index), .generation = row.generation };
        }
        return null;
    }

    fn rowFor(self: *const Catalog, ref: t.PeerRef) ?*Row {
        if (ref.index >= self.rows.len) return null;
        const row = &self.rows[ref.index];
        return if (row.occupied and row.generation == ref.generation) row else null;
    }

    fn connectedRow(self: *Catalog, ref: t.PeerRef, conn: t.Handle) ?*Row {
        const row = self.rowFor(ref) orelse return null;
        const current = row.connection orelse return null;
        return if (std.meta.eql(current, conn)) row else null;
    }

    pub fn get(self: *const Catalog, ref: t.PeerRef) ?t.Snapshot {
        const row = self.rowFor(ref) orelse return null;
        return .{
            .peer = ref,
            .identity = row.identity,
            .connection = row.connection,
            .direction = row.direction,
            .endpoint = row.endpoint,
            .relevant = row.connection != null and row.status != null,
            .disconnect_reason = row.closing_reason,
            .status = row.status,
            .metadata = row.metadata,
            .status_at_ms = row.status_at_ms,
            .metadata_at_ms = row.metadata_at_ms,
            .connected_at_ms = row.connected_at_ms,
            .direct = row.direct,
            .score = row.reputation.score,
            .ban_until_ms = row.reputation.ban_until_ms,
            .goodbye_until_ms = row.reputation.goodbye_until_ms,
        };
    }

    pub fn snapshots(self: *const Catalog, out: []t.Snapshot) usize {
        var count: usize = 0;
        for (self.rows, 0..) |row, index| {
            if (count == out.len) break;
            if (!row.occupied) continue;
            out[count] = self.get(.{ .index = @intCast(index), .generation = row.generation }).?;
            count += 1;
        }
        return count;
    }

    /// Identity and connection metadata must come from authenticated transport state.
    pub fn admit(
        self: *Catalog,
        identity: *const t.PeerId,
        local: *const t.PeerId,
        conn: t.Handle,
        options: *const t.AdmissionOptions,
    ) t.Admission {
        if (identity.eql(local)) return .duplicate;
        if (self.find(identity)) |ref| {
            const row = self.rowFor(ref).?;
            var current_reputation = row.reputation;
            current_reputation.decay(options.now_ms);
            if (current_reputation.banned(options.now_ms)) return .banned;
            if (options.now_ms < current_reputation.goodbye_until_ms) return .cooldown;
            if (row.pending_close != null) return .capacity;
            var displaced: ?t.Handle = null;
            if (row.connection) |current| {
                const local_smaller = std.mem.order(u8, &local.bytes, &identity.bytes) == .lt;
                const preferred: t.Direction = if (local_smaller)
                    .outbound
                else
                    .inbound;
                if (std.meta.eql(current, conn) or row.direction == options.direction or
                    options.direction != preferred) return .duplicate;
                displaced = current;
            } else if (self.connectedCount() >= self.options.max_peers) return .capacity;
            row.reputation = current_reputation;
            connect(row, conn, options);
            return .{ .admitted = .{ .peer = ref, .displaced = displaced, .fresh = false } };
        }
        if (self.connectedCount() >= self.options.max_peers) return .capacity;
        const limit = self.rows.len - if (options.direction == .inbound)
            @as(usize, self.options.outbound_reserve)
        else
            0;
        for (self.rows[0..limit], 0..) |*row, index| {
            if (row.connection != null or row.direct or row.pending_close != null or
                row.pending_update or row.generation == std.math.maxInt(u64)) continue;
            var current_reputation = row.reputation;
            current_reputation.decay(options.now_ms);
            if (row.occupied and current_reputation.retained(options.now_ms)) continue;
            row.* = .{ .occupied = true, .generation = row.generation + 1, .identity = identity.* };
            connect(row, conn, options);
            return .{ .admitted = .{
                .peer = .{ .index = @intCast(index), .generation = row.generation },
                .fresh = true,
            } };
        }
        return .capacity;
    }

    fn connect(row: *Row, conn: t.Handle, options: *const t.AdmissionOptions) void {
        row.connection = conn;
        row.closing_reason = null;
        row.direction = options.direction;
        row.endpoint = options.endpoint;
        row.connected_at_ms = options.now_ms;
        row.status = null;
        row.metadata = null;
        row.status_at_ms = 0;
        row.metadata_at_ms = 0;
        row.pending_update = row.published;
    }

    pub fn relevantCount(self: *const Catalog) u16 {
        var count: u16 = 0;
        for (self.rows) |row| if (row.connection != null and row.status != null) {
            count += 1;
        };
        return count;
    }

    pub fn eventsPending(self: *const Catalog) bool {
        for (self.rows) |row| if (row.pending_close != null or row.pending_update) return true;
        return false;
    }

    pub fn connectedCount(self: *const Catalog) u16 {
        var count: u16 = 0;
        for (self.rows) |row| if (row.connection != null) {
            count += 1;
        };
        return count;
    }

    pub fn disconnect(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        reason: t.DisconnectReason,
        now_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        row.connection = null;
        row.status = null;
        row.metadata = null;
        row.pending_update = false;
        row.pending_close = .{ .connection = conn, .reason = reason };
        row.reputation.decay(now_ms);
        return true;
    }

    pub fn markUnavailable(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        reason: t.DisconnectReason,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return true;
        row.closing_reason = reason;
        row.status = null;
        row.pending_update = row.published;
        return true;
    }

    /// Only a decoded Status accepted by the relevance check may establish relevance.
    pub fn updateStatus(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        status: *const t.Status,
        now_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return false;
        row.status = status.*;
        row.status_at_ms = now_ms;
        row.pending_update = true;
        return true;
    }

    pub fn updateMetadata(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        metadata: *const t.Metadata,
        now_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        if (row.closing_reason != null) return false;
        if (row.metadata) |current| if (metadata.seq_number < current.seq_number) return false;
        row.metadata = metadata.*;
        row.metadata_at_ms = now_ms;
        if (row.published or row.status != null) row.pending_update = true;
        return true;
    }

    pub fn setDirect(self: *Catalog, ref: t.PeerRef, direct: bool) bool {
        const row = self.rowFor(ref) orelse return false;
        row.direct = direct;
        return true;
    }

    pub fn report(
        self: *Catalog,
        ref: t.PeerRef,
        action: t.PeerAction,
        now_ms: u64,
    ) ?t.ReputationDecision {
        const row = self.rowFor(ref) orelse return null;
        return row.reputation.apply(action, now_ms);
    }

    pub fn remoteGoodbye(
        self: *Catalog,
        ref: t.PeerRef,
        conn: t.Handle,
        now_ms: u64,
        duration_ms: u64,
    ) bool {
        const row = self.connectedRow(ref, conn) orelse return false;
        row.reputation.remoteGoodbye(now_ms, duration_ms);
        return true;
    }

    pub fn refresh(self: *Catalog, now_ms: u64) void {
        for (self.rows) |*row| {
            if (row.occupied) row.reputation.decay(now_ms);
        }
    }

    pub fn nextDeadline(self: *const Catalog, now_ms: u64) ?u64 {
        var deadline: ?u64 = null;
        for (self.rows) |*row| {
            if (!row.occupied) continue;
            if (row.reputation.nextDeadline(now_ms)) |next| {
                deadline = @min(deadline orelse next, next);
            }
        }
        return deadline;
    }

    pub fn pollEvents(self: *Catalog, out: []t.Event) usize {
        var count: usize = 0;
        for (0..self.rows.len) |_| {
            if (count == out.len) break;
            const index = self.event_cursor;
            self.event_cursor = (index + 1) % self.rows.len;
            const row = &self.rows[index];
            if (!row.occupied) continue;
            const ref: t.PeerRef = .{ .index = @intCast(index), .generation = row.generation };
            if (row.pending_close) |closed| {
                out[count] = .{ .closed = .{
                    .peer = ref,
                    .identity = row.identity,
                    .connection = closed.connection,
                    .reason = closed.reason,
                } };
                row.pending_close = null;
                row.published = false;
            } else if (row.pending_update) {
                const snapshot = self.get(ref).?;
                out[count] = if (row.published)
                    .{ .updated = snapshot }
                else
                    .{ .ready = snapshot };
                row.pending_update = false;
                row.published = true;
            } else continue;
            count += 1;
        }
        return count;
    }
};
