pub const binding = @import("binding.zig");

test {
    _ = binding;
    _ = @import("binding_test.zig");
}
