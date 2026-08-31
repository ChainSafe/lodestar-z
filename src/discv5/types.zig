pub const NodeId = [32]u8;

pub const Address = union(enum) {
    ip4: struct {
        octets: [4]u8,
        port: u16,
    },
    ip6: struct {
        octets: [16]u8,
        port: u16,
    },
};

pub const Endpoint = struct {
    node_id: NodeId,
    address: Address,
};
