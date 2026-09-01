const crypto = @import("identity/crypto.zig");
const enr = @import("identity/enr.zig");
const types = @import("types.zig");

pub fn buildRecord(
    key_pair: *const crypto.KeyPair,
    sequence: u64,
    endpoint: types.Address,
) !enr.Record {
    return enr.Record.create(key_pair, sequence, endpoint);
}
