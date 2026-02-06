pub const Clock = @import("./clock.zig").Clock;
pub const slot = @import("./slot.zig");
pub const runner = @import("./runner.zig");

// Execute tests when running `zig build test:clock`
test {
    @import("std").testing.refAllDecls(@import("./clock_test.zig"));
}
