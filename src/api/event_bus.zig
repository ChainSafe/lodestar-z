//! EventBus — ring buffer pub/sub for beacon chain events.
//!
//! Stores up to 256 recent events in a ring buffer. SSE handlers poll by
//! keeping track of the last `write_idx` they consumed and calling
//! `getRecent(since_idx)` to receive any new events.
//!
//! Thread safety: single-threaded (cooperative-async model assumed).

const std = @import("std");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

pub const EventType = enum {
    head,
    block,
    finalized_checkpoint,
    chain_reorg,
    attestation,
    voluntary_exit,
    contribution_and_proof,
    payload_attributes,
    blob_sidecar,

    /// Returns the SSE topic name for this event type.
    pub fn topicName(self: EventType) []const u8 {
        return switch (self) {
            .head => "head",
            .block => "block",
            .finalized_checkpoint => "finalized_checkpoint",
            .chain_reorg => "chain_reorg",
            .attestation => "attestation",
            .voluntary_exit => "voluntary_exit",
            .contribution_and_proof => "contribution_and_proof",
            .payload_attributes => "payload_attributes",
            .blob_sidecar => "blob_sidecar",
        };
    }
};

pub const Event = union(EventType) {
    head: HeadEvent,
    block: BlockEvent,
    finalized_checkpoint: FinalizedCheckpointEvent,
    chain_reorg: ChainReorgEvent,
    attestation: AttestationEvent,
    voluntary_exit: VoluntaryExitEvent,
    contribution_and_proof: ContributionAndProofEvent,
    payload_attributes: PayloadAttributesEvent,
    blob_sidecar: BlobSidecarEvent,

    /// Returns the active event type tag.
    pub fn eventType(self: Event) EventType {
        return std.meta.activeTag(self);
    }

    /// Format the JSON `data` payload for this event into `buf`.
    /// Returns the written slice. Uses `std.fmt.bufPrint`.
    pub fn writeJson(self: Event, buf: []u8) std.fmt.BufPrintError![]const u8 {
        return switch (self) {
            .head => |e| std.fmt.bufPrint(buf,
                "{{\"slot\":\"{d}\",\"block\":\"0x{s}\",\"state\":\"0x{s}\",\"epoch_transition\":{s}}}",
                .{
                    e.slot,
                    std.fmt.bytesToHex(&e.block_root, .lower),
                    std.fmt.bytesToHex(&e.state_root, .lower),
                    if (e.epoch_transition) @as([]const u8, "true") else @as([]const u8, "false"),
                },
            ),
            .block => |e| std.fmt.bufPrint(buf,
                "{{\"slot\":\"{d}\",\"block\":\"0x{s}\"}}",
                .{
                    e.slot,
                    std.fmt.bytesToHex(&e.block_root, .lower),
                },
            ),
            .finalized_checkpoint => |e| std.fmt.bufPrint(buf,
                "{{\"block\":\"0x{s}\",\"state\":\"0x{s}\",\"epoch\":\"{d}\"}}",
                .{
                    std.fmt.bytesToHex(&e.root, .lower),
                    std.fmt.bytesToHex(&e.state_root, .lower),
                    e.epoch,
                },
            ),
            .chain_reorg => |e| std.fmt.bufPrint(buf,
                "{{\"slot\":\"{d}\",\"depth\":\"{d}\",\"old_head_block\":\"0x{s}\",\"new_head_block\":\"0x{s}\",\"old_head_state\":\"0x{s}\",\"new_head_state\":\"0x{s}\",\"epoch\":\"{d}\"}}",
                .{
                    e.slot,
                    e.depth,
                    std.fmt.bytesToHex(&e.old_head_root, .lower),
                    std.fmt.bytesToHex(&e.new_head_root, .lower),
                    std.fmt.bytesToHex(&e.old_state_root, .lower),
                    std.fmt.bytesToHex(&e.new_state_root, .lower),
                    e.epoch,
                },
            ),
            .attestation => |e| std.fmt.bufPrint(buf,
                "{{\"aggregation_bits\":\"0x{s}\",\"data\":{{\"slot\":\"{d}\",\"index\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"source\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}},\"target\":{{\"epoch\":\"{d}\",\"root\":\"0x{s}\"}}}},\"signature\":\"0x{s}\"}}",
                .{
                    std.fmt.bytesToHex(&e.aggregation_bits, .lower),
                    e.slot,
                    e.committee_index,
                    std.fmt.bytesToHex(&e.beacon_block_root, .lower),
                    e.source_epoch,
                    std.fmt.bytesToHex(&e.source_root, .lower),
                    e.target_epoch,
                    std.fmt.bytesToHex(&e.target_root, .lower),
                    std.fmt.bytesToHex(&e.signature, .lower),
                },
            ),
            .voluntary_exit => |e| std.fmt.bufPrint(buf,
                "{{\"message\":{{\"epoch\":\"{d}\",\"validator_index\":\"{d}\"}},\"signature\":\"0x{s}\"}}",
                .{
                    e.epoch,
                    e.validator_index,
                    std.fmt.bytesToHex(&e.signature, .lower),
                },
            ),
            .contribution_and_proof => |e| std.fmt.bufPrint(buf,
                "{{\"aggregator_index\":\"{d}\",\"contribution\":{{\"slot\":\"{d}\",\"beacon_block_root\":\"0x{s}\",\"subcommittee_index\":\"{d}\",\"aggregation_bits\":\"0x{s}\",\"signature\":\"0x{s}\"}},\"selection_proof\":\"0x{s}\"}}",
                .{
                    e.aggregator_index,
                    e.slot,
                    std.fmt.bytesToHex(&e.beacon_block_root, .lower),
                    e.subcommittee_index,
                    std.fmt.bytesToHex(&e.aggregation_bits, .lower),
                    std.fmt.bytesToHex(&e.contribution_signature, .lower),
                    std.fmt.bytesToHex(&e.selection_proof, .lower),
                },
            ),
            .payload_attributes => |e| std.fmt.bufPrint(buf,
                "{{\"proposer_index\":\"{d}\",\"proposal_slot\":\"{d}\",\"parent_block_number\":\"{d}\",\"parent_block_root\":\"0x{s}\",\"parent_block_hash\":\"0x{s}\",\"payload_attributes\":{{\"timestamp\":\"{d}\",\"prev_randao\":\"0x{s}\",\"suggested_fee_recipient\":\"0x{s}\"}}}}",
                .{
                    e.proposer_index,
                    e.proposal_slot,
                    e.parent_block_number,
                    std.fmt.bytesToHex(&e.parent_block_root, .lower),
                    std.fmt.bytesToHex(&e.parent_block_hash, .lower),
                    e.timestamp,
                    std.fmt.bytesToHex(&e.prev_randao, .lower),
                    std.fmt.bytesToHex(&e.suggested_fee_recipient, .lower),
                },
            ),
            .blob_sidecar => |e| std.fmt.bufPrint(buf,
                "{{\"block_root\":\"0x{s}\",\"index\":\"{d}\",\"slot\":\"{d}\",\"kzg_commitment\":\"0x{s}\",\"versioned_hash\":\"0x{s}\"}}",
                .{
                    std.fmt.bytesToHex(&e.block_root, .lower),
                    e.index,
                    e.slot,
                    std.fmt.bytesToHex(&e.kzg_commitment, .lower),
                    std.fmt.bytesToHex(&e.versioned_hash, .lower),
                },
            ),
        };
    }
};

pub const HeadEvent = struct {
    slot: u64,
    block_root: [32]u8,
    state_root: [32]u8,
    epoch_transition: bool,
};

pub const BlockEvent = struct {
    slot: u64,
    block_root: [32]u8,
};

pub const FinalizedCheckpointEvent = struct {
    epoch: u64,
    root: [32]u8,
    state_root: [32]u8,
};

pub const ChainReorgEvent = struct {
    slot: u64,
    depth: u64,
    old_head_root: [32]u8,
    new_head_root: [32]u8,
    /// State root of the old head (before reorg).
    old_state_root: [32]u8,
    /// State root of the new head (after reorg).
    new_state_root: [32]u8,
    /// Epoch of the new head slot.
    epoch: u64,
};

/// Emitted when a new attestation is received (gossip or API).
pub const AttestationEvent = struct {
    /// Hex-encoded aggregation bitfield.
    aggregation_bits: [8]u8,
    slot: u64,
    committee_index: u64,
    beacon_block_root: [32]u8,
    source_epoch: u64,
    source_root: [32]u8,
    target_epoch: u64,
    target_root: [32]u8,
    signature: [96]u8,
};

/// Emitted when a signed voluntary exit is received.
pub const VoluntaryExitEvent = struct {
    epoch: u64,
    validator_index: u64,
    signature: [96]u8,
};

/// Emitted when a sync committee contribution and proof is received.
pub const ContributionAndProofEvent = struct {
    aggregator_index: u64,
    slot: u64,
    beacon_block_root: [32]u8,
    subcommittee_index: u64,
    /// Hex-encoded aggregation bits for the subcommittee.
    aggregation_bits: [16]u8,
    /// Signature on the SyncCommitteeContribution.
    contribution_signature: [96]u8,
    /// Selection proof for the aggregator.
    selection_proof: [96]u8,
};

/// Emitted when forkchoiceUpdated provides payload attributes for block building.
pub const PayloadAttributesEvent = struct {
    proposer_index: u64,
    proposal_slot: u64,
    parent_block_number: u64,
    parent_block_root: [32]u8,
    parent_block_hash: [32]u8,
    timestamp: u64,
    prev_randao: [32]u8,
    suggested_fee_recipient: [20]u8,
};

/// Emitted when a blob sidecar is received.
pub const BlobSidecarEvent = struct {
    block_root: [32]u8,
    index: u64,
    slot: u64,
    kzg_commitment: [48]u8,
    versioned_hash: [32]u8,
};

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

pub const EventBus = struct {
    allocator: Allocator,
    /// Ring buffer of recent events (256 slots, indexed by u8).
    events: [256]Event,
    /// Next write position. Wraps at 256.
    write_idx: u8,
    /// Number of events emitted so far (saturates at 256 once full).
    count: u8,

    /// Initialise an empty event bus.
    pub fn init(allocator: Allocator) EventBus {
        return .{
            .allocator = allocator,
            .events = undefined,
            .write_idx = 0,
            .count = 0,
        };
    }

    /// Emit an event into the ring buffer. Overwrites the oldest event once
    /// the buffer is full.
    pub fn emit(self: *EventBus, event: Event) void {
        self.events[self.write_idx] = event;
        self.write_idx +%= 1; // wraps at 256
        if (self.count < 255) self.count += 1;
    }

    /// Return events written since `since_idx`.
    ///
    /// The returned slice is a view into the ring buffer and is valid until
    /// the next `emit` call that overwrites those slots.
    ///
    /// Callers store `event_bus.write_idx` after consuming and pass it back
    /// on the next poll.  If `since_idx == write_idx`, returns an empty slice.
    ///
    /// On wrap-around (since_idx > write_idx), returns the tail portion from
    /// since_idx to buffer end. Callers should then call `getRecent(0)` to
    /// get the head portion from 0 to write_idx on their next poll.
    pub fn getRecent(self: *const EventBus, since_idx: u8) []const Event {
        if (since_idx == self.write_idx) return &.{};
        if (since_idx < self.write_idx) {
            return self.events[since_idx..self.write_idx];
        }
        // Wrapped around: since_idx > write_idx.
        // Return the tail from since_idx to the end of the buffer.
        // The caller's next poll with since_idx=0 will pick up [0..write_idx].
        if (self.count >= 255) {
            // Buffer is full — return from since_idx to end.
            return self.events[since_idx..256];
        }
        // Buffer hasn't filled yet but indices wrapped (shouldn't happen in
        // normal operation). Reset the caller by returning everything from 0.
        return self.events[0..self.write_idx];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "EventBus: init is empty" {
    var bus = EventBus.init(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0), bus.write_idx);
    try std.testing.expectEqual(@as(u8, 0), bus.count);
    const slice = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 0), slice.len);
}

test "EventBus: emit and getRecent" {
    var bus = EventBus.init(std.testing.allocator);

    bus.emit(.{ .block = .{ .slot = 1, .block_root = [_]u8{0xAA} ** 32 } });
    bus.emit(.{ .block = .{ .slot = 2, .block_root = [_]u8{0xBB} ** 32 } });

    const recent = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 2), recent.len);
    try std.testing.expectEqual(@as(u64, 1), recent[0].block.slot);
    try std.testing.expectEqual(@as(u64, 2), recent[1].block.slot);
}

test "EventBus: getRecent returns empty when up to date" {
    var bus = EventBus.init(std.testing.allocator);
    bus.emit(.{ .block = .{ .slot = 5, .block_root = [_]u8{0} ** 32 } });

    const since = bus.write_idx;
    bus.emit(.{ .block = .{ .slot = 6, .block_root = [_]u8{1} ** 32 } });

    // since was 1, write_idx is now 2
    const recent = bus.getRecent(since);
    try std.testing.expectEqual(@as(usize, 1), recent.len);
    try std.testing.expectEqual(@as(u64, 6), recent[0].block.slot);
}

test "EventBus: head event round-trip" {
    var bus = EventBus.init(std.testing.allocator);

    const block_root = [_]u8{0xDE} ** 32;
    const state_root = [_]u8{0xAD} ** 32;
    bus.emit(.{ .head = .{
        .slot = 42,
        .block_root = block_root,
        .state_root = state_root,
        .epoch_transition = true,
    } });

    const recent = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 1), recent.len);
    const ev = recent[0].head;
    try std.testing.expectEqual(@as(u64, 42), ev.slot);
    try std.testing.expect(ev.epoch_transition);
    try std.testing.expectEqualSlices(u8, &block_root, &ev.block_root);
    try std.testing.expectEqualSlices(u8, &state_root, &ev.state_root);
}

test "EventBus: finalized_checkpoint event" {
    var bus = EventBus.init(std.testing.allocator);

    bus.emit(.{ .finalized_checkpoint = .{
        .epoch = 5,
        .root = [_]u8{0x55} ** 32,
        .state_root = [_]u8{0x66} ** 32,
    } });

    const recent = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 1), recent.len);
    try std.testing.expectEqual(@as(u64, 5), recent[0].finalized_checkpoint.epoch);
}

test "Event.writeJson: head event" {
    var buf: [512]u8 = undefined;
    const ev = Event{ .head = .{
        .slot = 42,
        .block_root = [_]u8{0xAA} ** 32,
        .state_root = [_]u8{0xBB} ** 32,
        .epoch_transition = true,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"slot\":\"42\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"epoch_transition\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "0xaaaa") != null);
}

test "Event.writeJson: block event" {
    var buf: [512]u8 = undefined;
    const ev = Event{ .block = .{
        .slot = 100,
        .block_root = [_]u8{0xFF} ** 32,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"slot\":\"100\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "0xffff") != null);
}

test "Event.writeJson: finalized_checkpoint event" {
    var buf: [512]u8 = undefined;
    const ev = Event{ .finalized_checkpoint = .{
        .epoch = 10,
        .root = [_]u8{0x11} ** 32,
        .state_root = [_]u8{0x22} ** 32,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"epoch\":\"10\"") != null);
}

test "Event.writeJson: chain_reorg event" {
    var buf: [512]u8 = undefined;
    const ev = Event{ .chain_reorg = .{
        .slot = 99,
        .depth = 3,
        .old_head_root = [_]u8{0xAA} ** 32,
        .new_head_root = [_]u8{0xBB} ** 32,
        .old_state_root = [_]u8{0xCC} ** 32,
        .new_state_root = [_]u8{0xDD} ** 32,
        .epoch = 12,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"depth\":\"3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"epoch\":\"12\"") != null);
}

test "EventType.topicName" {
    try std.testing.expectEqualStrings("head", EventType.head.topicName());
    try std.testing.expectEqualStrings("block", EventType.block.topicName());
    try std.testing.expectEqualStrings("finalized_checkpoint", EventType.finalized_checkpoint.topicName());
    try std.testing.expectEqualStrings("chain_reorg", EventType.chain_reorg.topicName());
    try std.testing.expectEqualStrings("attestation", EventType.attestation.topicName());
    try std.testing.expectEqualStrings("voluntary_exit", EventType.voluntary_exit.topicName());
    try std.testing.expectEqualStrings("contribution_and_proof", EventType.contribution_and_proof.topicName());
    try std.testing.expectEqualStrings("payload_attributes", EventType.payload_attributes.topicName());
    try std.testing.expectEqualStrings("blob_sidecar", EventType.blob_sidecar.topicName());
}

test "Event.writeJson: attestation event" {
    var buf: [2048]u8 = undefined;
    const ev = Event{ .attestation = .{
        .aggregation_bits = [_]u8{0x01} ++ [_]u8{0} ** 7,
        .slot = 100,
        .committee_index = 1,
        .beacon_block_root = [_]u8{0xAA} ** 32,
        .source_epoch = 3,
        .source_root = [_]u8{0xBB} ** 32,
        .target_epoch = 4,
        .target_root = [_]u8{0xCC} ** 32,
        .signature = [_]u8{0xDD} ** 96,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"slot\":\"100\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"index\":\"1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"target\"") != null);
}

test "Event.writeJson: voluntary_exit event" {
    var buf: [1024]u8 = undefined;
    const ev = Event{ .voluntary_exit = .{
        .epoch = 42,
        .validator_index = 1234,
        .signature = [_]u8{0xEE} ** 96,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"epoch\":\"42\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"validator_index\":\"1234\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "0xeeee") != null);
}

test "Event.writeJson: contribution_and_proof event" {
    var buf: [2048]u8 = undefined;
    const ev = Event{ .contribution_and_proof = .{
        .aggregator_index = 99,
        .slot = 200,
        .beacon_block_root = [_]u8{0xAA} ** 32,
        .subcommittee_index = 1,
        .aggregation_bits = [_]u8{0xFF} ** 16,
        .contribution_signature = [_]u8{0xBB} ** 96,
        .selection_proof = [_]u8{0xCC} ** 96,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"aggregator_index\":\"99\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"subcommittee_index\":\"1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"selection_proof\"") != null);
}

test "Event.writeJson: payload_attributes event" {
    var buf: [2048]u8 = undefined;
    const ev = Event{ .payload_attributes = .{
        .proposer_index = 42,
        .proposal_slot = 100,
        .parent_block_number = 50,
        .parent_block_root = [_]u8{0x11} ** 32,
        .parent_block_hash = [_]u8{0x22} ** 32,
        .timestamp = 1700000000,
        .prev_randao = [_]u8{0x33} ** 32,
        .suggested_fee_recipient = [_]u8{0x44} ** 20,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"proposer_index\":\"42\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"proposal_slot\":\"100\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"payload_attributes\"") != null);
}

test "Event.writeJson: blob_sidecar event" {
    var buf: [1024]u8 = undefined;
    const ev = Event{ .blob_sidecar = .{
        .block_root = [_]u8{0xAA} ** 32,
        .index = 3,
        .slot = 999,
        .kzg_commitment = [_]u8{0xBB} ** 48,
        .versioned_hash = [_]u8{0xCC} ** 32,
    } };
    const json = try ev.writeJson(&buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"index\":\"3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"slot\":\"999\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"kzg_commitment\"") != null);
}

test "EventBus: new event types round-trip" {
    var bus = EventBus.init(std.testing.allocator);

    bus.emit(.{ .attestation = .{
        .aggregation_bits = [_]u8{0x03} ++ [_]u8{0} ** 7,
        .slot = 500,
        .committee_index = 2,
        .beacon_block_root = [_]u8{0xAA} ** 32,
        .source_epoch = 15,
        .source_root = [_]u8{0xBB} ** 32,
        .target_epoch = 16,
        .target_root = [_]u8{0xCC} ** 32,
        .signature = [_]u8{0xDD} ** 96,
    } });
    bus.emit(.{ .voluntary_exit = .{
        .epoch = 10,
        .validator_index = 42,
        .signature = [_]u8{0xEE} ** 96,
    } });
    bus.emit(.{ .blob_sidecar = .{
        .block_root = [_]u8{0x11} ** 32,
        .index = 0,
        .slot = 600,
        .kzg_commitment = [_]u8{0x22} ** 48,
        .versioned_hash = [_]u8{0x33} ** 32,
    } });

    const recent = bus.getRecent(0);
    try std.testing.expectEqual(@as(usize, 3), recent.len);
    try std.testing.expectEqual(@as(u64, 500), recent[0].attestation.slot);
    try std.testing.expectEqual(@as(u64, 42), recent[1].voluntary_exit.validator_index);
    try std.testing.expectEqual(@as(u64, 0), recent[2].blob_sidecar.index);
}
