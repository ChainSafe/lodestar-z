const std = @import("std");
const consensus_types = @import("consensus_types");
const fork_types = @import("fork_types");

const Slot = consensus_types.primitive.Slot.Type;

pub const PeerProvenance = struct {
    peer_id_buf: [128]u8 = undefined,
    peer_id_len: u8 = 0,

    pub fn fromPeerId(peer_id: ?[]const u8) PeerProvenance {
        var peer: PeerProvenance = .{};
        peer.setPeerId(peer_id);
        return peer;
    }

    pub fn peerId(self: *const PeerProvenance) ?[]const u8 {
        if (self.peer_id_len == 0) return null;
        return self.peer_id_buf[0..self.peer_id_len];
    }

    pub fn setPeerId(self: *PeerProvenance, peer_id: ?[]const u8) void {
        self.peer_id_len = 0;
        const bytes = peer_id orelse return;
        self.peer_id_len = @intCast(@min(bytes.len, self.peer_id_buf.len));
        @memcpy(self.peer_id_buf[0..self.peer_id_len], bytes[0..self.peer_id_len]);
    }
};

pub const PreparedBlockSource = enum {
    gossip,
    range_sync,
    unknown_block_sync,
    api,
    checkpoint_sync,
    regen,
};

pub const PreparedBlockInput = struct {
    block: fork_types.AnySignedBeaconBlock,
    source: PreparedBlockSource,
    block_root: [32]u8,
    seen_timestamp_sec: u64 = 0,
    peer: PeerProvenance = .{},

    pub fn slot(self: *const PreparedBlockInput) Slot {
        return self.block.beaconBlock().slot();
    }

    pub fn peerId(self: *const PreparedBlockInput) ?[]const u8 {
        return self.peer.peerId();
    }

    pub fn setPeerId(self: *PreparedBlockInput, peer_id: ?[]const u8) void {
        self.peer.setPeerId(peer_id);
    }

    pub fn deinit(self: *PreparedBlockInput, allocator: std.mem.Allocator) void {
        self.block.deinit(allocator);
        self.* = undefined;
    }
};
