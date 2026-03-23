# Fork Choice Rewrite — TS-Aligned Design

**Date:** 2026-03-23
**Branch:** `gr/feature/forkchoice-z`
**Reference:** `lodestar/packages/fork-choice/src/forkChoice/forkChoice.ts` (unstable branch)

## Goal

Rewrite `src/fork_choice/fork_choice.zig` to align with the TypeScript `ForkChoice` class. The current Zig implementation covers ~30% of the TS surface. This spec covers the full port.

## Struct Fields

```zig
pub const ForkChoice = struct {
    // ── Config & options ──
    config: *const BeaconConfig,
    opts: ForkChoiceOpts,

    // ── Core components ──
    proto_array: ProtoArray,
    votes: Votes,
    fcStore: ForkChoiceStore,
    deltas_cache: DeltasCache,

    // ── Head tracking ──
    head: ProtoBlock,

    // ── Proposer boost ──
    proposer_boost_root: ?Root,
    justified_proposer_boost_score: ?u64,

    // ── Balance tracking ──
    balances: *EffectiveBalanceIncrementsRc,

    // ── Attestation queue ──
    queued_attestations: QueuedAttestationMap,
    queued_attestations_previous_slot: u32,

    // ── Caches ──
    validated_attestation_datas: RootSet,

    // ── Error state ──
    irrecoverable_error: bool,
};
```

### Removed fields (vs current Zig)

| Field | Reason |
|---|---|
| `synced: bool` | TS notes 100% of calls have synced=false. Removed. |
| `best_justified_checkpoint` | Not in TS; logic is in `updateCheckpoints`. |
| `head: HeadResult` | Changed to `ProtoBlock` to match TS. `HeadResult` removed. |

### New types needed

```zig
/// Queued attestation for deferred processing.
const QueuedAttestation = struct {
    validator_index: ValidatorIndex,
    payload_status: PayloadStatus,
};

/// Slot -> BlockRoot -> []QueuedAttestation
const QueuedAttestationMap = std.AutoArrayHashMap(Slot, BlockAttestationMap);
const BlockAttestationMap = std.AutoHashMap(Root, std.ArrayListUnmanaged(QueuedAttestation));

/// Set of validated attestation data roots.
const RootSet = std.HashMapUnmanaged(Root, void, RootContext, 80);
```

## InitOpts

```zig
pub const InitOpts = struct {
    config: *const BeaconConfig,
    opts: ForkChoiceOpts,
    justified_checkpoint: CheckpointWithPayloadStatus,
    finalized_checkpoint: CheckpointWithPayloadStatus,
    justified_balances: []const u16,
    justified_balances_getter: JustifiedBalancesGetter,
    events: ForkChoiceStoreEvents = .{},
    prune_threshold: u32 = DEFAULT_PRUNE_THRESHOLD,
};
```

## Public API — TS Method Mapping

### Block Processing

#### `onBlock`

**TS signature:**
```ts
onBlock(block: BeaconBlock, state: CachedBeaconStateAllForks, blockDelaySec: number,
        currentSlot: Slot, executionStatus: MaybeValidExecutionStatus,
        dataAvailabilityStatus: DataAvailabilityStatus): ProtoBlock
```

**Zig signature:**
```zig
pub fn onBlock(
    self: *ForkChoice,
    allocator: Allocator,
    block: *const AnyBeaconBlock,
    state: *CachedBeaconState,
    block_delay_sec: u32,
    current_slot: Slot,
    execution_status: ExecutionStatus,
    data_availability_status: DataAvailabilityStatus,
) !ProtoBlock
```

**Logic (matches TS order):**
1. Extract `parentRoot`, `slot` from block
2. Look up parent block in proto_array — error `UNKNOWN_PARENT` if missing
3. Reject future slot — error `FUTURE_SLOT`
4. Reject finalized slot — error `FINALIZED_SLOT`
5. Check finalized descendant — error `NOT_FINALIZED_DESCENDANT`
6. Compute timeliness via `isBlockTimely`; assign `proposer_boost_root` if timely + first
7. Extract justified/finalized checkpoints from state
8. Compute or inherit unrealized checkpoints (use `computeUnrealizedCheckpoints` from state_transition when `opts.compute_unrealized` is set)
9. Call `updateCheckpoints(justified, finalized)`
10. Call `updateUnrealizedCheckpoints(unrealized_justified, unrealized_finalized)`
11. If block from past epoch: `updateCheckpoints` again with unrealized
12. Construct `ProtoBlock` from block+state fields (fork-aware: pre-merge / post-merge / Gloas)
13. `proto_array.onBlock(protoBlock, current_slot, proposer_boost_root)`
14. Return `ProtoBlock`

#### `onAttestation`

**TS signature:**
```ts
onAttestation(attestation: IndexedAttestation, attDataRoot: string, forceImport?: boolean): void
```

**Zig signature:**
```zig
pub fn onAttestation(
    self: *ForkChoice,
    allocator: Allocator,
    attestation: *const AnyIndexedAttestation,
    att_data_root: Root,
    force_import: bool,
) !void
```

**Requires:** `AnyIndexedAttestation` union type in `fork_types` (new, follows `AnyAttestations` pattern).

**Logic (matches TS):**
1. Ignore zero hash beacon_block_root
2. `validateOnAttestation` (full validation chain)
3. Determine `PayloadStatus` for Gloas (PENDING/EMPTY/FULL based on slot + data_index)
4. If `slot < currentSlot`: `addLatestMessage` for each non-equivocating validator
5. If `slot >= currentSlot`: queue in `queued_attestations`

#### `onAttesterSlashing`

**TS signature:**
```ts
onAttesterSlashing(slashing: AttesterSlashing): void
```

**Zig signature:**
```zig
pub fn onAttesterSlashing(
    self: *ForkChoice,
    allocator: Allocator,
    slashing: *const AnyAttesterSlashing,
) !void
```

**Logic:** Call `findAttesterSlashableIndices` from state_transition, add results to `fcStore.equivocating_indices`.

**Requires:** `AnyAttesterSlashing` type — either create new or use existing `AnyAttesterSlashingItems` with a single item.

### Head Selection

#### `updateHead` (private)

Matches TS `updateHead()`:
1. `computeDeltas` with old/new balances + equivocating indices
2. Compute proposer boost score if enabled (lazy `justified_proposer_boost_score`)
3. `applyScoreChanges`
4. `findHead`
5. Update `self.head` and `self.balances`

#### `updateAndGetHead`

```zig
pub fn updateAndGetHead(self: *ForkChoice, allocator: Allocator, opt: UpdateAndGetHeadOpt) !UpdateAndGetHeadResult
```

Multiplexer matching TS:
- `get_canonical_head`: `updateHead()`
- `get_proposer_head`: `updateHead()` then `getProposerHead()`
- `get_predicted_proposer_head`: `getHead()` then `predictProposerHead()`

### Proposer Boost Reorg

All match TS logic exactly:

```zig
pub fn shouldOverrideForkChoiceUpdate(self: *ForkChoice, head_block: ProtoBlock, sec_from_slot: u32, current_slot: Slot) ShouldOverrideForkChoiceUpdateResult;
fn getProposerHead(self: *ForkChoice, head_block: ProtoBlock, sec_from_slot: u32, slot: Slot) ProposerHeadResult;
fn predictProposerHead(self: *ForkChoice, head_block: ProtoBlock, sec_from_slot: u32, current_slot: Slot) ProtoBlock;
fn getPreliminaryProposerHead(self: *const ForkChoice, head_block: ProtoBlock, parent_block: ProtoBlock, slot: Slot) PreliminaryResult;
fn isProposingOnTime(self: *const ForkChoice, sec_from_slot: u32, slot: Slot) bool;
fn isBlockTimely(self: *const ForkChoice, block_slot: Slot, block_delay_sec: u32) bool;
```

Helper:
```zig
pub fn getCommitteeFraction(total_balance: u64, committee_percent: u64) u64;
```

### Time Management

#### `updateTime`

```zig
pub fn updateTime(self: *ForkChoice, allocator: Allocator, current_slot: Slot) !void
```

Matches TS: loop `onTick` per slot, then `processAttestationQueue`, then reset `validated_attestation_datas`.

#### `onTick` (private)

```zig
fn onTick(self: *ForkChoice, time: Slot) !void
```

1. Validate `time == previousSlot + 1`
2. Update `fcStore.currentSlot`
3. Reset `proposer_boost_root`
4. At epoch boundary: `updateCheckpoints` with unrealized

#### `processAttestationQueue` (private)

```zig
fn processAttestationQueue(self: *ForkChoice) void
```

Process queued attestations for slots < currentSlot via `addLatestMessage`.

### Checkpoint Management (private)

```zig
fn updateCheckpoints(self: *ForkChoice, justified: CheckpointWithPayloadStatus, finalized: CheckpointWithPayloadStatus) void;
fn updateUnrealizedCheckpoints(self: *ForkChoice, justified: CheckpointWithPayloadStatus, finalized: CheckpointWithPayloadStatus) void;
```

Both use epoch-monotonic updates matching TS. Call `justified_balances_getter` lazily when justified checkpoint advances.

### Query Methods

All match TS IForkChoice interface:

```zig
// Getters
pub fn getHeadRoot(self: *const ForkChoice) Root;
pub fn getHead(self: *const ForkChoice) ProtoBlock;
pub fn getTime(self: *const ForkChoice) Slot;
pub fn getJustifiedCheckpoint(self: *const ForkChoice) CheckpointWithPayloadStatus;
pub fn getFinalizedCheckpoint(self: *const ForkChoice) CheckpointWithPayloadStatus;
pub fn getProposerBoostRoot(self: *const ForkChoice) Root;

// Block queries (with finalized descendant check)
pub fn hasBlock(self: *const ForkChoice, block_root: Root) bool;
pub fn hasBlockUnsafe(self: *const ForkChoice, block_root: Root) bool;
pub fn getBlock(self: *const ForkChoice, block_root: Root, payload_status: PayloadStatus) ?ProtoBlock;
pub fn getBlockDefaultStatus(self: *const ForkChoice, block_root: Root) ?ProtoBlock;
pub fn getBlockAndBlockHash(self: *const ForkChoice, block_root: Root, block_hash: Root) ?ProtoBlock;
pub fn getJustifiedBlock(self: *const ForkChoice) !ProtoBlock;
pub fn getFinalizedBlock(self: *const ForkChoice) !ProtoBlock;
pub fn getFinalizedCheckpointSlot(self: *const ForkChoice) Slot;

// Traversal
pub fn getAncestor(self: *const ForkChoice, block_root: Root, ancestor_slot: Slot) !ProtoNode;
pub fn isDescendant(self: *const ForkChoice, ancestor_root: Root, ancestor_status: PayloadStatus, desc_root: Root, desc_status: PayloadStatus) !bool;
pub fn getCanonicalBlockByRoot(self: *const ForkChoice, block_root: Root) ?ProtoBlock;
pub fn getCanonicalBlockAtSlot(self: *const ForkChoice, slot: Slot) ?ProtoBlock;
pub fn getCanonicalBlockClosestLteSlot(self: *const ForkChoice, slot: Slot) ?ProtoBlock;
pub fn getAllAncestorBlocks(self: *const ForkChoice, allocator: Allocator, block_root: Root, status: PayloadStatus) ![]ProtoBlock;
pub fn getAllNonAncestorBlocks(self: *const ForkChoice, allocator: Allocator, block_root: Root, status: PayloadStatus) ![]ProtoBlock;
pub fn getAllAncestorAndNonAncestorBlocks(self: *const ForkChoice, allocator: Allocator, block_root: Root, status: PayloadStatus) !struct { ancestors: []ProtoBlock, non_ancestors: []ProtoBlock };
pub fn getCommonAncestorDepth(self: *const ForkChoice, prev: ProtoBlock, new_block: ProtoBlock) AncestorResult;
pub fn getDependentRoot(self: *const ForkChoice, block: ProtoBlock, epoch_diff: EpochDifference) !Root;

// Debug / metrics
pub fn getHeads(self: *const ForkChoice, allocator: Allocator) ![]ProtoBlock;
pub fn getAllNodes(self: *const ForkChoice) []ProtoNode;
pub fn getSlotsPresent(self: *const ForkChoice, window_start: Slot) u32;
pub fn getBlockSummariesByParentRoot(self: *const ForkChoice, allocator: Allocator, parent_root: Root) ![]ProtoBlock;
pub fn getBlockSummariesAtSlot(self: *const ForkChoice, allocator: Allocator, slot: Slot) ![]ProtoBlock;

// Pruning (with vote index adjustment)
pub fn prune(self: *ForkChoice, allocator: Allocator, finalized_root: Root) ![]ProtoBlock;
pub fn setPruneThreshold(self: *ForkChoice, threshold: u32) void;

// Execution validation
pub fn validateLatestHash(self: *ForkChoice, allocator: Allocator, response: LVHExecResponse, current_slot: Slot) void;

// Gloas (ePBS)
pub fn onExecutionPayload(self: *ForkChoice, allocator: Allocator, block_root: Root, exec_hash: Root, exec_number: u64, exec_state_root: Root) !void;
pub fn notifyPtcMessages(self: *ForkChoice, block_root: Root, ptc_indices: []const u32, payload_present: bool) void;
```

### Attestation Validation (private)

Match TS validation chain:

```zig
fn validateOnAttestation(self: *ForkChoice, attestation: *const AnyIndexedAttestation, att_data_root: Root, force_import: bool) !void;
fn validateAttestationData(self: *ForkChoice, attestation: *const AnyIndexedAttestation, att_data_root: Root, force_import: bool) !void;
fn addLatestMessage(self: *ForkChoice, validator_index: ValidatorIndex, next_slot: Slot, next_root: Root, next_payload_status: PayloadStatus) void;
```

### Critical Bug Fix: `prune` Vote Index Adjustment

Current Zig `prune` just delegates to `proto_array.maybePrune`. TS adjusts all vote indices:

```zig
pub fn prune(self: *ForkChoice, allocator: Allocator, finalized_root: Root) ![]ProtoBlock {
    const pruned = try self.proto_array.maybePrune(allocator, finalized_root);
    const pruned_count: u32 = @intCast(pruned.len);

    // Adjust all vote indices — critical for correctness
    const fields = self.votes.fields();
    for (0..self.votes.len()) |i| {
        if (fields.current_indices[i] != NULL_VOTE_INDEX) {
            if (fields.current_indices[i] >= pruned_count) {
                fields.current_indices[i] -= pruned_count;
            } else {
                fields.current_indices[i] = NULL_VOTE_INDEX;
            }
        }
        if (fields.next_indices[i] != NULL_VOTE_INDEX) {
            if (fields.next_indices[i] >= pruned_count) {
                fields.next_indices[i] -= pruned_count;
            } else {
                fields.next_indices[i] = NULL_VOTE_INDEX;
            }
        }
    }
    return pruned;
}
```

## New Files Required

| File | Purpose |
|---|---|
| `src/fork_types/any_indexed_attestation.zig` | `AnyIndexedAttestation` union (phase0/electra) |
| Update `src/fork_types/root.zig` | Export `AnyIndexedAttestation` |

## Dependencies

- `config.BeaconConfig` — fork detection, ChainConfig constants
- `state_transition.CachedBeaconState` — checkpoint extraction, `computeUnrealizedCheckpoints`
- `state_transition.computeEpochAtSlot`, `computeStartSlotAtEpoch`
- `fork_types.AnyBeaconBlock` — block field extraction
- `fork_types.AnyIndexedAttestation` — attestation processing (NEW)
- `preset.SLOTS_PER_EPOCH` — epoch boundary, committee fraction

## Implementation Phases

**Phase 1: Infrastructure**
- Create `AnyIndexedAttestation` in fork_types
- Add new fields to `ForkChoice` struct
- Update `InitOpts` with `config`, `opts`
- Update `init` / `deinit`

**Phase 2: Core Logic**
- `updateCheckpoints` / `updateUnrealizedCheckpoints` (private)
- `onTick` / `updateTime` / `processAttestationQueue`
- `addLatestMessage` (private)
- Fix `prune` with vote index adjustment
- Rewrite `updateHead` (was `getHead`)

**Phase 3: Block & Attestation Processing**
- Rewrite `onBlock` with full TS logic
- Rewrite `onAttestation` with full validation + queuing
- Rewrite `onAttesterSlashing` to use `AnyAttesterSlashing`
- Attestation validation chain

**Phase 4: Query Methods**
- Block queries with finalized descendant check
- Traversal methods
- `getDependentRoot`, `getCommonAncestorDepth`
- Debug/metrics methods

**Phase 5: Proposer Boost Reorg**
- `updateAndGetHead`
- `shouldOverrideForkChoiceUpdate`
- `getProposerHead` / `predictProposerHead`
- `getPreliminaryProposerHead`
- `getCommitteeFraction`

**Phase 6: Gloas + Cleanup**
- `onExecutionPayload` / `notifyPtcMessages` (update signatures)
- `validateLatestHash` with `irrecoverable_error`
- Remove `HeadResult` type
- Update `root.zig` exports
- Tests for all new methods
