const std = @import("std");

pub const Budget = struct {
    limit: usize = 0,
    used: usize = 0,

    pub fn reserve(self: *Budget, amount: usize) !void {
        std.debug.assert(self.used <= self.limit);
        if (amount > self.limit - self.used) return error.NetworkBridgeFull;
        self.used += amount;
    }
    pub fn release(self: *Budget, amount: usize) void {
        std.debug.assert(amount <= self.used);
        self.used -= amount;
    }
};
