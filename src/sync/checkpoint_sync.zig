//! Checkpoint sync: bootstrap from a trusted finalized state.
//!
//! Instead of syncing from genesis, a node can start from a recent
//! finalized checkpoint state + the corresponding block. This drastically
//! reduces initial sync time (minutes instead of hours/days).
//!
//! The trusted root must be verified out-of-band (from a block explorer,
//! a trusted friend's node, etc.).
//!
//! Reference: Lodestar `packages/beacon-node/src/chain/initState.ts`

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const db_mod = @import("db");
const BeaconDB = db_mod.BeaconDB;

pub const CheckpointSyncResult = struct {
    state_slot: u64,
    state_root: [32]u8,
    block_root: [32]u8,
};

pub const CheckpointSyncError = error{
    /// The computed state root does not match the trusted root.
    StateRootMismatch,
    /// The checkpoint state bytes are empty.
    EmptyState,
    /// The checkpoint block bytes are empty.
    EmptyBlock,
};

pub const CheckpointSync = struct {
    allocator: Allocator,
    db: *BeaconDB,

    pub fn init(allocator: Allocator, db: *BeaconDB) CheckpointSync {
        return .{
            .allocator = allocator,
            .db = db,
        };
    }

    /// Bootstrap from a checkpoint: validate, persist state + block.
    ///
    /// `checkpoint_state_bytes`: SSZ-encoded BeaconState at the finalized slot.
    /// `checkpoint_block_bytes`: SSZ-encoded SignedBeaconBlock at the same slot.
    /// `trusted_root`: the expected SHA-256 hash of `checkpoint_state_bytes`.
    ///
    /// The caller is responsible for obtaining these from a trusted source
    /// (e.g. a `/eth/v2/debug/beacon/states/finalized` endpoint).
    pub fn syncFromCheckpoint(
        self: *CheckpointSync,
        checkpoint_state_bytes: []const u8,
        checkpoint_block_bytes: []const u8,
        trusted_root: [32]u8,
    ) !CheckpointSyncResult {
        if (checkpoint_state_bytes.len == 0) return CheckpointSyncError.EmptyState;
        if (checkpoint_block_bytes.len == 0) return CheckpointSyncError.EmptyBlock;

        // Compute the SHA-256 hash of the state bytes as a simple
        // integrity check. In production this would be an SSZ hash-tree-root,
        // but at this layer we operate on opaque bytes and use the hash
        // the caller provides.
        var state_hash: [32]u8 = undefined;
        Sha256.hash(checkpoint_state_bytes, &state_hash, .{});

        if (!std.mem.eql(u8, &state_hash, &trusted_root)) {
            return CheckpointSyncError.StateRootMismatch;
        }

        // Compute block root similarly.
        var block_root: [32]u8 = undefined;
        Sha256.hash(checkpoint_block_bytes, &block_root, .{});

        // Extract slot from the state bytes. In SSZ-encoded BeaconState,
        // the slot is at offset 40 (after genesis_time:u64 = offset 0..8,
        // genesis_validators_root:Bytes32 = offset 8..40, slot:u64 = 40..48).
        //
        // Note: this is a minimal extraction. A full implementation would
        // use the SSZ type to deserialize.
        const state_slot = extractSlotFromState(checkpoint_state_bytes) orelse 0;

        // Persist the checkpoint state and block.
        try self.db.putStateArchive(state_slot, state_hash, checkpoint_state_bytes);
        try self.db.putBlockArchive(state_slot, block_root, checkpoint_block_bytes);

        return .{
            .state_slot = state_slot,
            .state_root = state_hash,
            .block_root = block_root,
        };
    }

    /// Extract the slot field from SSZ-encoded BeaconState bytes.
    /// Returns null if the bytes are too short.
    pub fn extractSlotFromState(state_bytes: []const u8) ?u64 {
        // BeaconState layout: genesis_time(8) + genesis_validators_root(32) + slot(8)
        const slot_offset = 8 + 32; // 40
        if (state_bytes.len < slot_offset + 8) return null;
        return std.mem.readInt(u64, state_bytes[slot_offset..][0..8], .little);
    }
};

// ── Tests ────────────────────────────────────────────────────────────

test "CheckpointSync: successful checkpoint import" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var cs = CheckpointSync.init(allocator, &db);

    // Build a fake state blob with a slot embedded at offset 40.
    var state_bytes: [128]u8 = [_]u8{0} ** 128;
    const slot: u64 = 12345;
    @memcpy(state_bytes[40..48], std.mem.asBytes(&std.mem.nativeToLittle(u64, slot)));

    // Compute expected hash.
    var expected_root: [32]u8 = undefined;
    Sha256.hash(&state_bytes, &expected_root, .{});

    var block_bytes: [64]u8 = [_]u8{0xBB} ** 64;

    const result = try cs.syncFromCheckpoint(&state_bytes, &block_bytes, expected_root);

    try std.testing.expectEqual(slot, result.state_slot);
    try std.testing.expectEqual(expected_root, result.state_root);

    // Verify block was persisted.
    const stored_block = try db.getBlockArchive(slot);
    defer if (stored_block) |b| allocator.free(b);
    try std.testing.expect(stored_block != null);

    // Verify state was persisted.
    const stored_state = try db.getStateArchive(slot);
    defer if (stored_state) |s| allocator.free(s);
    try std.testing.expect(stored_state != null);
}

test "CheckpointSync: rejects mismatched state root" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var cs = CheckpointSync.init(allocator, &db);

    const state_bytes = [_]u8{0xAA} ** 64;
    const block_bytes = [_]u8{0xBB} ** 64;
    const wrong_root = [_]u8{0xFF} ** 32;

    const result = cs.syncFromCheckpoint(&state_bytes, &block_bytes, wrong_root);
    try std.testing.expectError(CheckpointSyncError.StateRootMismatch, result);
}

test "CheckpointSync: rejects empty state" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var cs = CheckpointSync.init(allocator, &db);

    const result = cs.syncFromCheckpoint("", "block", [_]u8{0} ** 32);
    try std.testing.expectError(CheckpointSyncError.EmptyState, result);
}

test "CheckpointSync: rejects empty block" {
    const allocator = std.testing.allocator;
    var kv = db_mod.MemoryKVStore.init(allocator);
    defer kv.deinit();
    var db = BeaconDB.init(allocator, kv.kvStore());

    var cs = CheckpointSync.init(allocator, &db);

    const result = cs.syncFromCheckpoint("state", "", [_]u8{0} ** 32);
    try std.testing.expectError(CheckpointSyncError.EmptyBlock, result);
}

test "CheckpointSync: extractSlotFromState parses correctly" {
    var buf: [64]u8 = [_]u8{0} ** 64;
    const slot: u64 = 98765;
    @memcpy(buf[40..48], std.mem.asBytes(&std.mem.nativeToLittle(u64, slot)));

    const extracted = CheckpointSync.extractSlotFromState(&buf);
    try std.testing.expectEqual(@as(?u64, slot), extracted);
}

test "CheckpointSync: extractSlotFromState returns null for short input" {
    const buf = [_]u8{0} ** 20;
    try std.testing.expect(CheckpointSync.extractSlotFromState(&buf) == null);
}

// ── Weak subjectivity checkpoint parsing ─────────────────────────────

pub const WeakSubjectivityCheckpoint = struct {
    root: [32]u8,
    epoch: u64,
};

pub const WsCheckpointParseError = error{
    /// Missing ':' separator between root and epoch.
    MissingSeparator,
    /// Root must be 0x-prefixed 32-byte hex (66 chars).
    InvalidRoot,
    /// Epoch portion is not a valid integer.
    InvalidEpoch,
};

/// Parse a weak subjectivity checkpoint string in "0xROOT:EPOCH" format.
///
/// Example: "0xabcdef...64hex...:12345"
pub fn parseWeakSubjectivityCheckpoint(input: []const u8) WsCheckpointParseError!WeakSubjectivityCheckpoint {
    const sep_idx = std.mem.indexOfScalar(u8, input, ':') orelse
        return WsCheckpointParseError.MissingSeparator;

    const root_hex = input[0..sep_idx];
    const epoch_str = input[sep_idx + 1 ..];

    // Strip 0x prefix if present.
    const hex_str = if (root_hex.len >= 2 and root_hex[0] == '0' and root_hex[1] == 'x')
        root_hex[2..]
    else
        root_hex;

    if (hex_str.len != 64) return WsCheckpointParseError.InvalidRoot;

    var root: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&root, hex_str) catch return WsCheckpointParseError.InvalidRoot;

    const epoch = std.fmt.parseInt(u64, epoch_str, 10) catch
        return WsCheckpointParseError.InvalidEpoch;

    return .{ .root = root, .epoch = epoch };
}

/// Validate that a checkpoint state matches a weak subjectivity checkpoint.
///
/// Checks that the state's epoch (derived from slot) matches the expected
/// epoch. Root validation requires hash-tree-root which is done at a
/// higher layer.
pub fn validateWeakSubjectivityCheckpoint(
    ws: WeakSubjectivityCheckpoint,
    state_slot: u64,
    slots_per_epoch: u64,
) !void {
    const state_epoch = state_slot / slots_per_epoch;
    if (state_epoch != ws.epoch) {
        return error.WeakSubjectivityViolation;
    }
}

// ── HTTP checkpoint sync (Beacon API) ────────────────────────────────

pub const FetchError = error{
    UrlUnreachable,
    HttpError,
    EmptyResponse,
    InvalidForkVersion,
    OutOfMemory,
    IoNotAvailable,
    UriParseError,
    ConnectionFailed,
    RequestFailed,
    InvalidContentLength,
};

pub const FetchedState = struct {
    state_bytes: []u8,
    fork_name: []const u8,
};

pub const FetchedBlock = struct {
    block_bytes: []u8,
    fork_name: []const u8,
};

/// Fetch the finalized beacon state from a remote beacon node via HTTP.
///
/// Calls GET /eth/v2/debug/beacon/states/finalized with Accept: application/octet-stream
/// to receive the SSZ-encoded state. The fork version is read from the
/// Eth-Consensus-Version response header.
pub fn fetchFinalizedState(
    allocator: Allocator,
    io: std.Io,
    base_url: []const u8,
) !FetchedState {
    return fetchBeaconEndpoint(
        allocator,
        io,
        base_url,
        "/eth/v2/debug/beacon/states/finalized",
        "finalized state",
    );
}

/// Fetch the finalized beacon block from a remote beacon node via HTTP.
///
/// Calls GET /eth/v2/beacon/blocks/finalized with Accept: application/octet-stream.
pub fn fetchFinalizedBlock(
    allocator: Allocator,
    io: std.Io,
    base_url: []const u8,
) !FetchedBlock {
    const result = try fetchBeaconEndpoint(
        allocator,
        io,
        base_url,
        "/eth/v2/beacon/blocks/finalized",
        "finalized block",
    );
    return .{
        .block_bytes = result.state_bytes,
        .fork_name = result.fork_name,
    };
}

/// Generic fetch for a beacon API endpoint returning SSZ bytes.
fn fetchBeaconEndpoint(
    allocator: Allocator,
    io: std.Io,
    base_url: []const u8,
    path: []const u8,
    label: []const u8,
) !FetchedState {
    // Build full URL: base_url + path.
    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base_url, path });
    defer allocator.free(url);

    std.log.info("Fetching {s} from {s}", .{ label, url });

    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
    };
    defer client.deinit();

    const uri = std.Uri.parse(url) catch return FetchError.UriParseError;

    var req = client.request(.GET, uri, .{
        .keep_alive = false,
        .extra_headers = &.{
            .{ .name = "Accept", .value = "application/octet-stream" },
        },
    }) catch return FetchError.ConnectionFailed;
    defer req.deinit();

    // Send the request (GET has no body).
    req.sendBodiless() catch return FetchError.RequestFailed;

    // Receive response head.
    var redirect_buf: [2048]u8 = undefined;
    var response = req.receiveHead(&redirect_buf) catch return FetchError.RequestFailed;

    // Check HTTP status.
    if (response.head.status != .ok) {
        std.log.err("HTTP {d} fetching {s}", .{ @intFromEnum(response.head.status), label });
        return FetchError.HttpError;
    }

    // Extract Eth-Consensus-Version header for fork detection.
    // IMPORTANT: response.reader() invalidates head string pointers,
    // so we must copy the fork name before reading the body.
    var fork_name_buf: [32]u8 = undefined;
    var fork_name: []const u8 = "unknown";
    {
        var it = response.head.iterateHeaders();
        while (it.next()) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, "Eth-Consensus-Version")) {
                const len = @min(hdr.value.len, fork_name_buf.len);
                @memcpy(fork_name_buf[0..len], hdr.value[0..len]);
                fork_name = fork_name_buf[0..len];
                break;
            }
        }
    }

    // Log content length if known.
    if (response.head.content_length) |total| {
        std.log.info("Downloading {s}: {d} bytes (fork={s})", .{ label, total, fork_name });
    } else {
        std.log.info("Downloading {s}: chunked (fork={s})", .{ label, fork_name });
    }

    // Read the entire response body.
    // State responses can be very large (hundreds of MB), so allow up to 1 GB.
    var transfer_buf: [65536]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    const body = reader.allocRemaining(allocator, std.Io.Limit.limited(1024 * 1024 * 1024)) catch |err| switch (err) {
        error.ReadFailed => {
            std.log.err("Read failed fetching {s}: {?}", .{ label, response.bodyErr() });
            return FetchError.RequestFailed;
        },
        else => |e| return e,
    };

    if (body.len == 0) {
        allocator.free(body);
        return FetchError.EmptyResponse;
    }

    std.log.info("Downloaded {s}: {d} bytes", .{ label, body.len });
    return .{ .state_bytes = body, .fork_name = fork_name };
}

// ── Additional tests ─────────────────────────────────────────────────

test "parseWeakSubjectivityCheckpoint: valid input" {
    const input = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:12345";
    const result = try parseWeakSubjectivityCheckpoint(input);
    try std.testing.expectEqual(@as(u64, 12345), result.epoch);
    // Verify first byte of root.
    try std.testing.expectEqual(@as(u8, 0xab), result.root[0]);
    try std.testing.expectEqual(@as(u8, 0xcd), result.root[1]);
}

test "parseWeakSubjectivityCheckpoint: no 0x prefix" {
    const input = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:99";
    const result = try parseWeakSubjectivityCheckpoint(input);
    try std.testing.expectEqual(@as(u64, 99), result.epoch);
    try std.testing.expectEqual(@as(u8, 0xab), result.root[0]);
}

test "parseWeakSubjectivityCheckpoint: missing separator" {
    const result = parseWeakSubjectivityCheckpoint("0xabcdef");
    try std.testing.expectError(WsCheckpointParseError.MissingSeparator, result);
}

test "parseWeakSubjectivityCheckpoint: short root" {
    const result = parseWeakSubjectivityCheckpoint("0xabcdef:123");
    try std.testing.expectError(WsCheckpointParseError.InvalidRoot, result);
}

test "parseWeakSubjectivityCheckpoint: invalid epoch" {
    const input = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:notanumber";
    const result = parseWeakSubjectivityCheckpoint(input);
    try std.testing.expectError(WsCheckpointParseError.InvalidEpoch, result);
}

test "validateWeakSubjectivityCheckpoint: matching epoch" {
    const ws = WeakSubjectivityCheckpoint{
        .root = [_]u8{0} ** 32,
        .epoch = 10,
    };
    // Slot 320 at 32 slots/epoch = epoch 10.
    try validateWeakSubjectivityCheckpoint(ws, 320, 32);
}

test "validateWeakSubjectivityCheckpoint: mismatched epoch" {
    const ws = WeakSubjectivityCheckpoint{
        .root = [_]u8{0} ** 32,
        .epoch = 10,
    };
    const result = validateWeakSubjectivityCheckpoint(ws, 100, 32);
    try std.testing.expectError(error.WeakSubjectivityViolation, result);
}

