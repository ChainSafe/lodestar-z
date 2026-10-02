const gossip = @import("../gossipsub/root.zig");
const limits_mod = @import("../gossip_limits.zig");
const storage = @import("../gossipsub/message_store.zig");
const validation = @import("../gossipsub/validation.zig");

/// Check the compressed source share before considering victims. Replacing one's
/// own work must not renew a source's full share.
pub fn sourceRoom(candidate: *gossip.Gossipsub.MessageAdmission) bool {
    const usage = candidate.sourceUsage();
    if (candidate.context.options.payload_limits) |limits| {
        const limit = limits[@intFromEnum(candidate.canonical.?.name.kind)];
        const bytes = limits_mod.sourceBytes(limit, usage.maximum_bytes, storage.inline_bytes);
        if (usage.kind_items >= limits_mod.sourceItems(limit) or validation.Validation.chargedBytes(candidate.compressed.len) > bytes -| usage.kind_bytes) return candidate.refuse(.peer_validations);
    } else if (usage.items >= @max(1, usage.validation_capacity / 2)) return candidate.refuse(.peer_validations);
    return true;
}

/// The protocol supplies physical costs; the processor decides which pending
/// compressed and validation allowances may be used by the incoming kind.
pub fn feasible(candidate: *gossip.Gossipsub.MessageAdmission, victims: []const gossip.Gossipsub.ValidationHandle) bool {
    // Constant-time admission is covered by receipt work; replacement adds
    // bounded repeated preflight work beyond that existing atomic allowance.
    if (!candidate.charge(victims.len * @sizeOf(gossip.Gossipsub.MessageAdmission.Usage))) return false;
    const usage = candidate.usage(victims);
    if (candidate.context.options.payload_limits) |limits| {
        const limit = limits[@intFromEnum(candidate.canonical.?.name.kind)];
        if (usage.kind_pending >= limit.items) return candidate.refuse(.kind_validations);
        if (usage.kind_entries >= limit.items or storage.Store.pagesFor(candidate.compressed.len) > limit.bytes / storage.page_bytes -| usage.kind_pages) return candidate.refuse(.kind_payload);
    }
    return candidate.feasible(&usage);
}
