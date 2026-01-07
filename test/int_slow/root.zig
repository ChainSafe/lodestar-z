const testing = @import("std").testing;

test {
    testing.refAllDecls(@import("./era/root.zig"));
}
