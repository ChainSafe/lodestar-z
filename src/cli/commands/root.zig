pub const beacon = struct {
    pub const spec = @import("beacon/spec.zig");
    pub const command = @import("beacon/command.zig");
};

pub const bootnode = struct {
    pub const spec = @import("bootnode/spec.zig");
    pub const command = @import("bootnode/command.zig");
};

pub const dev = struct {
    pub const spec = @import("dev/spec.zig");
    pub const command = @import("dev/command.zig");
};

pub const validator = struct {
    pub const spec = @import("validator/spec.zig");
    pub const command = @import("validator/command.zig");
};
