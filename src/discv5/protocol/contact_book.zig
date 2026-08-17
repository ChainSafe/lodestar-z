//! Fallback directory of peers we have identity + address for, but whose ENR is
//! not verified enough for the routing table. It is consulted when resolving a
//! peer's static pubkey/address for handshakes and request sending; an entry is
//! dropped once the peer earns a routing-table slot.

const std = @import("std");
const scoped_log = std.log.scoped(.discv5_protocol);
const Allocator = std.mem.Allocator;

const enr_mod = @import("../enr.zig");
const protocol_state = @import("state.zig");

const Io = std.Io;
const Address = Io.net.IpAddress;
const NodeId = enr_mod.NodeId;
const Contact = protocol_state.Contact;

pub const ContactBook = struct {
    contacts: std.AutoHashMap(NodeId, Contact),
    local_node_id: NodeId,
    max_contacts: usize,

    pub fn init(alloc: Allocator, local_node_id: NodeId, max_contacts: usize) ContactBook {
        return .{
            .contacts = std.AutoHashMap(NodeId, Contact).init(alloc),
            .local_node_id = local_node_id,
            .max_contacts = max_contacts,
        };
    }

    pub fn deinit(self: *ContactBook) void {
        self.contacts.deinit();
    }

    pub fn get(self: *const ContactBook, node_id: NodeId) ?Contact {
        return self.contacts.get(node_id);
    }

    /// Record a peer's static key + address. No-ops for our own node id or when
    /// no pubkey is supplied; a full table silently drops the entry.
    pub fn remember(self: *ContactBook, node_id: NodeId, pubkey: ?*const [33]u8, addr: Address) void {
        if (std.mem.eql(u8, &node_id, &self.local_node_id)) return;
        const pk = pubkey orelse return;
        if (!self.contacts.contains(node_id) and self.contacts.count() >= self.max_contacts) return;
        self.contacts.put(node_id, .{ .pubkey = pk.*, .addr = addr }) catch return;
        const short = std.fmt.bytesToHex(node_id[0..4].*, .lower);
        scoped_log.debug("remembered contact node={s} addr={any}", .{ &short, addr });
    }

    /// Drop a contact, e.g. once it has earned a routing-table entry.
    pub fn forget(self: *ContactBook, node_id: NodeId) void {
        _ = self.contacts.remove(node_id);
    }
};

test "contact book bounds distinct peers while allowing updates" {
    const alloc = std.testing.allocator;
    const local = [_]u8{0} ** 32;
    var book = ContactBook.init(alloc, local, 2);
    defer book.deinit();

    const pubkey = [_]u8{2} ** 33;
    const first = [_]u8{1} ** 32;
    const second = [_]u8{2} ** 32;
    const overflow = [_]u8{3} ** 32;
    const addr_a = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    const addr_b = Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9001 } };

    book.remember(first, &pubkey, addr_a);
    book.remember(second, &pubkey, addr_a);
    book.remember(overflow, &pubkey, addr_a);
    try std.testing.expectEqual(@as(usize, 2), book.contacts.count());
    try std.testing.expect(book.get(overflow) == null);

    book.remember(first, &pubkey, addr_b);
    try std.testing.expect(book.get(first).?.addr.eql(&addr_b));
}
