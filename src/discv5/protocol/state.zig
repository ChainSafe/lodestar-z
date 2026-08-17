const std = @import("std");
const Io = std.Io;
const Address = Io.net.IpAddress;

const enr_mod = @import("../enr.zig");
const packet = @import("packet.zig");

pub const NodeId = enr_mod.NodeId;
pub const CHALLENGE_DATA_SIZE = packet.WHOAREYOU_CHALLENGE_DATA_SIZE;

/// Bounded ring buffer of recently seen nonces per session.
/// Provides replay protection without heap allocation (CL-2020-nonce).
/// Capacity of 32 is sufficient for typical burst rates; older entries are
/// evicted silently.
pub const SEEN_NONCES_CAP: usize = 32;

pub const SeenNonces = struct {
    buf: [SEEN_NONCES_CAP][12]u8,
    len: usize,
    head: usize,

    pub fn init() SeenNonces {
        return .{ .buf = undefined, .len = 0, .head = 0 };
    }

    /// Returns true if nonce was already seen.
    pub fn contains(self: *const SeenNonces, nonce: *const [12]u8) bool {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const idx = (self.head + SEEN_NONCES_CAP - self.len + i) % SEEN_NONCES_CAP;
            if (std.mem.eql(u8, &self.buf[idx], nonce)) return true;
        }
        return false;
    }

    /// Record a nonce. Evicts the oldest entry when the buffer is full.
    pub fn insert(self: *SeenNonces, nonce: *const [12]u8) void {
        self.buf[self.head] = nonce.*;
        self.head = (self.head + 1) % SEEN_NONCES_CAP;
        if (self.len < SEEN_NONCES_CAP) self.len += 1;
    }
};

pub const PendingSessionKeys = struct {
    initiator_key: [16]u8,
    recipient_key: [16]u8,
};

pub const SessionRecord = struct {
    node_id: NodeId,
    initiator_key: [16]u8,
    recipient_key: [16]u8,
    /// New keys learned during rekey. Kept pending until a packet decrypts with them.
    awaiting_initiator_key: ?[16]u8 = null,
    awaiting_recipient_key: ?[16]u8 = null,
    seen_nonces: SeenNonces,
};

pub const ActiveChallenge = struct {
    challenge_data: [CHALLENGE_DATA_SIZE]u8,
    remote_enr: ?[enr_mod.MAX_ENR_SIZE]u8 = null,
    remote_enr_len: u16 = 0,
};

pub const AddressKey = struct {
    family: Address.Family,
    bytes: [16]u8,

    pub fn fromAddress(addr: Address) AddressKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes },
        };
    }
};

pub const WhoareyouRateEntry = struct {
    count: u32,
    window_start_ns: i64,
};

pub const Contact = struct {
    pubkey: [33]u8,
    addr: Address,
};
