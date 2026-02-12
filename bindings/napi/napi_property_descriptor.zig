const std = @import("std");
const napi = @import("zapi:napi");

/// Extracts a function name, without prefix, from a napi binding function.
///
/// Example: `BeaconStateView_getXYZ` => "getXYZ"
pub fn fnName(comptime func: anytype) [:0]const u8 {
    const fq_name = @typeName(@TypeOf(func));
    const start_index = comptime std.mem.indexOf(u8, fq_name, "@typeInfo") orelse @compileError("Expected a @typeInfo");
    const underscore_index = comptime std.mem.indexOfScalar(u8, fq_name[start_index..], '_') orelse @compileError("Expected an underscore");
    const next_paren_index = comptime std.mem.indexOfScalar(u8, fq_name[start_index..], ')') orelse @compileError("Expected a paren");
    return @ptrCast(fq_name[(start_index + underscore_index + 1) .. start_index + next_paren_index] ++ [_]u8{0});
}

/// Creates a `napi.c.napi_property_descriptor` getter from a binding function.
///
/// This is a way to extract a `utf8name` from a given `func`, at compile time,
/// so that we do not need to run into runtime errors due to naming typos.
pub fn getter(
    comptime func: anytype,
) napi.c.napi_property_descriptor {
    const name = comptime fnName(func);
    return .{ .utf8name = name.ptr, .getter = napi.wrapCallback(0, func) };
}

/// Creates a `napi.c.napi_property_descriptor` method from a binding function.
///
/// This is a way to extract a `utf8name` from a given `func`, at compile time,
/// so that we do not need to run into runtime errors due to naming typos.
pub fn method(
    comptime argc_cap: usize,
    comptime func: anytype,
) napi.c.napi_property_descriptor {
    const name = comptime fnName(func);
    return .{ .utf8name = name.ptr, .method = napi.wrapCallback(argc_cap, func) };
}
