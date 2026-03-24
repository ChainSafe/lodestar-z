//! Default bootnode ENR records for Ethereum mainnet.
//!
//! These are well-known bootnodes operated by client teams.
//! Used to seed the discv5 routing table on first startup.

pub const BootnodeInfo = struct {
    /// Base64url-encoded ENR string (with "enr:" prefix)
    enr: []const u8,
    /// Human-readable label
    label: []const u8,
};

/// Ethereum mainnet consensus layer bootnodes.
pub const mainnet = [_]BootnodeInfo{
    .{
        .enr = "enr:-KG4QNTx85fjxABbSq_Rta9wy56nQ1fHK0PewJbGjLm1M4bMGx5-3Qq4ZX2-iFJ0pys_O90sVXNNOxp2E7afBsGsBrgDhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQEnfA2iXNlY3AyNTZrMaECGXWQ-rQ2KZKRH1aOW4IlPDBkY4XDphxg9pxKytFCkayDdGNwgiMog3VkcIIjKA",
        .label = "Teku (azure-us-east)",
    },
    .{
        .enr = "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
        .label = "Prysm (aws-us-east-2)",
    },
    .{
        .enr = "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
        .label = "Lighthouse (linode-au-sydney)",
    },
};

test "mainnet bootnodes count" {
    const std = @import("std");
    try std.testing.expectEqual(@as(usize, 3), mainnet.len);
}
