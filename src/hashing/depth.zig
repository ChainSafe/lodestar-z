const std = @import("std");
const build_options = @import("build_options");

// VALIDATOR_REGISTRY_LIMIT is only 2**40 (= 1,099,511,627,776)
/// This should not be changed without careful consideration,
/// as it affects the maximum depth of _everything_ in this library
const default_max_depth = 64;

// Allow overriding via `build.zig`
pub const user_max_depth: u8 = if (@hasDecl(build_options, "max_depth"))
    if (@typeInfo(@TypeOf(build_options.max_depth)) == .optional)
        build_options.max_depth orelse default_max_depth
    else
        build_options.max_depth
else
    default_max_depth;

pub const GindexUint = std.meta.Int(.unsigned, @intCast(user_max_depth));
pub const Depth = std.math.Log2Int(GindexUint);
pub const max_depth = std.math.maxInt(Depth);
