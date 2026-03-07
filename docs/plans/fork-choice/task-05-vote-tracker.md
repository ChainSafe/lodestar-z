# Task 5: VoteTracker + Votes (SoA Storage)

**Status:** Done
**Source:** `src/fork_choice/vote_tracker.zig`

## Goal

Implement per-validator vote tracking with cache-efficient SoA (Struct-of-Arrays) storage for the `computeDeltas` hot path. Aligned with Gloas spec `LatestMessage`.

## Data Structures

### VoteTracker

Matches Gloas spec `LatestMessage { slot, root, payload_present }`:

```zig
pub const VoteTracker = struct {
    /// Index of the block this validator currently votes for (after last computeDeltas).
    current_index: u32,
    /// Index of the block this validator will vote for (on next computeDeltas).
    next_index: u32,
    /// Slot of the validator's latest vote. Used by onAttestation to reject stale votes.
    next_slot: Slot,
    /// Whether the validator's vote supports the payload (Gloas ePBS).
    /// Determines EMPTY vs FULL variant in is_supporting_vote.
    payload_present: bool,

    pub const DEFAULT: VoteTracker = .{
        .current_index = NULL_VOTE_INDEX,
        .next_index = NULL_VOTE_INDEX,
        .next_slot = 0,
        .payload_present = false,
    };
};
```

**Size:** 24 bytes per validator (4 + 4 + 8 + 1 + padding).

### Votes

SoA wrapper around `std.MultiArrayList(VoteTracker)`:

```zig
pub const Votes = struct {
    multi_list: std.MultiArrayList(VoteTracker),

    pub fn init() Votes;
    pub fn deinit(self: *Votes, allocator: Allocator) void;
    pub fn len(self: *const Votes) u32;
    pub fn ensureValidatorCount(self: *Votes, allocator: Allocator, validator_count: u32) Allocator.Error!void;
    pub fn fields(self: *Votes) struct {
        current_indices: []u32,
        next_indices: []u32,
        next_slots: []Slot,
        payload_presents: []bool,
    };
};
```

## Why Slot instead of Epoch?

Phase0 spec uses `LatestMessage { epoch, root }`. Gloas spec changes to `LatestMessage { slot, root, payload_present }`.

The reason: ePBS introduces 3 variant nodes per block (PENDING, EMPTY, FULL). The `is_supporting_vote` function needs to distinguish:

- **`message.slot <= block.slot`** (same-slot vote): supports PENDING only (payload hasn't arrived yet)
- **`message.slot > block.slot`** (cross-slot vote): supports EMPTY or FULL based on `payload_present`

Epoch granularity cannot make this distinction. We target unstable/Gloas directly.

Reference: Lighthouse `gloas-fork-choice` branch also uses `next_slot: Slot` + `next_payload_present: bool`.

## Why SoA Storage?

`computeDeltas` is the hottest loop -- called every time `getHead` runs. It iterates all validators (~600K-2.1M) and only reads `current_index` and `next_index`.

| Layout | Cache Lines per 16 Validators | Fields Loaded |
|--------|-------------------------------|---------------|
| AoS (`[]VoteTracker`) | 6 lines (24B x 16 = 384B) | All 4 fields per entry |
| **SoA (`MultiArrayList`)** | **2 lines** (4B x 16 = 64B per array) | **Only `current_index` + `next_index`** |

SoA reduces cache pressure in the hot path. `next_slot` and `payload_present` are only
touched in `onAttestation` (cold path, random access).

## API Design

### `ensureValidatorCount(allocator, count)`

Grows storage when new validators join:
- **Grow-only:** Calling with a smaller count is a no-op.
- **DEFAULT-initialized:** New slots get `NULL_VOTE_INDEX`, slot 0, `payload_present = false`.
- **Preserves existing:** Existing votes are never touched during growth.

### `fields()`

Returns raw SoA arrays for direct iteration. Used by `computeDeltas` to avoid
per-element method call overhead.

## Tests (7 tests)

| Test | Validates |
|------|-----------|
| "VoteTracker DEFAULT is null votes" | Default sentinel values + payload_present = false |
| "VoteTracker size" | Compile-time size assertion (24 bytes) |
| "Votes init and deinit" | Zero-length after init, clean deinit |
| "Votes ensureValidatorCount initializes defaults" | New slots get DEFAULT values (all 4 fields) |
| "Votes ensureValidatorCount grows preserving existing" | Existing votes + payload_present survive growth |
| "Votes ensureValidatorCount no-op when already large enough" | No shrink on smaller count |
| "Votes fields returns empty arrays when no validators" | Empty state is safe (all 4 arrays) |
