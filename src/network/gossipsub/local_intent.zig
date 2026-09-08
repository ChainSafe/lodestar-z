const std = @import("std");
const constants = @import("constants.zig");
const topic = @import("topic.zig");
const score = @import("score.zig");

pub const Subscription = struct {
    name: []const u8,
    params: score.TopicParams,
};
pub const TopicSet = std.StaticBitSet(constants.topics_cap);
pub const Pins = struct {
    validation: TopicSet = .initEmpty(),
    announcements: TopicSet = .initEmpty(),
};
pub const Assignment = struct {
    bytes: [topic.topic_max_len]u8,
    len: u8,
    params: score.TopicParams,
    row: ?u16,
    generation: u64,
    existing: bool,

    pub fn name(self: *const Assignment) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Private scratch between preparation and commit in one serialized owner call.
pub const Workspace = struct {
    entries: [constants.topics_cap]Assignment = undefined,
    len: u16 = 0,
    reserved: TopicSet = .initEmpty(),
    pins: Pins = .{},
    now_ms: u64 = 0,
    prepared: bool = false,
};

pub const Error = error{ TopicCapacity, DuplicateTopic, InvalidTopic, InvalidLimits, TopicPolicyRequired };
