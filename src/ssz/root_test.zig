//! Tests for `root.zig`.

const std = @import("std");
const testing = std.testing;
const ssz = @import("root.zig");
const types = ssz.types;
const HasherData = ssz.HasherData;

test "redundant SSZ helper APIs are not exposed" {
    try testing.expect(!@hasDecl(types, "isProgressiveListType"));
    try testing.expect(!@hasDecl(types, "isCompatibleUnionType"));
    try testing.expect(!@hasDecl(HasherData, "getAllocator"));
}
