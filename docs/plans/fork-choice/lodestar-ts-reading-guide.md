# Lodestar TS Fork Choice Source Code Reading Guide

Lodestar fork choice source code:
`packages/fork-choice/src/` (branch: `unstable`)

## File Map

```
packages/fork-choice/src/
  index.ts                       # re-exports
  metrics.ts                     # Prometheus metrics

  protoArray/
    interface.ts                 # ProtoBlock, ProtoNode, ExecutionStatus, PayloadStatus
    errors.ts                    # ProtoArrayError, ProtoArrayErrorCode
    computeDeltas.ts             # vote weight calculation
    protoArray.ts                # ProtoArray class (~1700 lines, DAG engine)

  forkChoice/
    interface.ts                 # IForkChoice API contract
    store.ts                     # IForkChoiceStore, CheckpointWithPayload
    errors.ts                    # ForkChoiceError, InvalidBlockCode, InvalidAttestationCode
    forkChoice.ts                # ForkChoice class (~1860 lines, main orchestrator)
    safeBlocks.ts                # getSafeBeaconBlockRoot, getSafeExecutionBlockHash
```

## Recommended Reading Order

bottom-up, from types to orchestrator:

1. `protoArray/interface.ts` -- core types
2. `protoArray/errors.ts` -- error codes
3. `protoArray/computeDeltas.ts` -- vote weight algorithm
4. `protoArray/protoArray.ts` -- DAG operations
5. `forkChoice/store.ts` -- store types
6. `forkChoice/errors.ts` -- high-level error codes
7. `forkChoice/interface.ts` -- public API contract
8. `forkChoice/forkChoice.ts` -- main orchestrator

---

## 1. protoArray/interface.ts -- Core Types

### ExecutionStatus

```typescript
export enum ExecutionStatus {
  Valid = "Valid",
  Syncing = "Syncing",
  PreMerge = "PreMerge",
  Invalid = "Invalid",
  PayloadSeparated = "PayloadSeparated",  // Gloas (ePBS)
}
```

Zig: `ExecutionStatus = enum(u3)` in `proto_node.zig`.

### PayloadStatus (Gloas)

```typescript
export enum PayloadStatus {
  PENDING = 0,   // block without payload resolution
  EMPTY = 1,     // payload absent
  FULL = 2,      // payload arrived (pre-Gloas: always FULL)
}
```

Zig: not yet implemented. Gloas-specific feature for ePBS where each block can
have up to 3 variant nodes (PENDING, EMPTY, FULL).

### BlockExtraMeta

```typescript
// discriminated union on executionStatus
export type BlockExtraMeta =
  | { executionPayloadBlockHash: RootHex;
      executionPayloadNumber: UintNum64;
      executionStatus: Exclude<ExecutionStatus, ExecutionStatus.PreMerge>;
      dataAvailabilityStatus: DataAvailabilityStatus; }
  | { executionPayloadBlockHash: null;
      executionStatus: ExecutionStatus.PreMerge;
      dataAvailabilityStatus: DataAvailabilityStatus.PreData; };
```

Zig: `BlockExtraMeta = union(enum) { post_merge: PostMergeMeta, pre_merge: void }`.
`Exclude<>` enforced by `PostMergeMeta.init()` assert.

### ProtoBlock

```typescript
export type ProtoBlock = BlockExtraMeta & {
  slot: Slot;
  blockRoot: RootHex;
  parentRoot: RootHex;
  stateRoot: RootHex;
  targetRoot: RootHex;

  justifiedEpoch: Epoch;
  justifiedRoot: RootHex;
  finalizedEpoch: Epoch;
  finalizedRoot: RootHex;

  unrealizedJustifiedEpoch: Epoch;
  unrealizedJustifiedRoot: RootHex;
  unrealizedFinalizedEpoch: Epoch;
  unrealizedFinalizedRoot: RootHex;

  timeliness: boolean;

  // Gloas fields:
  payloadStatus: PayloadStatus;
  builderIndex: ValidatorIndex | null;
  blockHashFromBid: RootHex | null;
  parentBlockHash: RootHex | null;
};
```

Zig: `ProtoBlock` in `proto_node.zig`. Missing Gloas fields: `payloadStatus`,
`parentBlockHash`. Has `builder_index` and `block_hash` (partial).

Note: TS uses `RootHex` (hex string) for all roots. Zig uses `[32]u8`.

### ProtoNode

```typescript
// flat extension of ProtoBlock (TS uses intersection type)
export type ProtoNode = ProtoBlock & {
  parent?: number;
  weight: number;
  bestChild?: number;
  bestDescendant?: number;
};
```

Zig: `ProtoNode` uses composition (`block: ProtoBlock` + DAG fields).

### VoteTracker

```typescript
export const NULL_VOTE_INDEX = 0xffffffff;

// In ForkChoice class (not a separate type):
private voteCurrentIndices: VoteIndex[];
private voteNextIndices: VoteIndex[];
private voteNextSlots: Slot[];  // note: TS uses Slot, Zig uses Epoch
```

Zig: `VoteTracker` struct + `Votes` wrapper in `vote_tracker.zig`.
SoA via `MultiArrayList(VoteTracker)` with `fields()` accessor.

### VariantIndices (Gloas)

```typescript
// Pre-Gloas: single index (number)
// Gloas: [PENDING, EMPTY, FULL?] tuple
export type VariantIndices = number | [number, number] | [number, number, number];
```

Not yet in Zig. Needed for Gloas (ePBS) support.

---

## 2. protoArray/computeDeltas.ts -- Vote Weight Algorithm

The core LMD-GHOST weight calculation.

```typescript
export function computeDeltas(
  numProtoNodes: number,
  voteCurrentIndices: VoteIndex[],
  voteNextIndices: VoteIndex[],
  oldBalances: EffectiveBalanceIncrements,
  newBalances: EffectiveBalanceIncrements,
  equivocatingIndices: Set<ValidatorIndex>
): DeltasResult
```

### Algorithm

```
deltas = new Array(numProtoNodes).fill(0)

for each validator vIndex:
    currentIndex = voteCurrentIndices[vIndex]
    nextIndex    = voteNextIndices[vIndex]

    // skip inactive validators
    if currentIndex == NULL && nextIndex == NULL: continue

    // handle equivocating validators
    if vIndex is equivocating:
        if currentIndex != NULL:
            deltas[currentIndex] -= oldBalances[vIndex]
        voteCurrentIndices[vIndex] = NULL
        voteNextIndices[vIndex] = NULL
        continue

    // skip if nothing changed
    if currentIndex == nextIndex && oldBalances[vIndex] == newBalances[vIndex]:
        continue

    // apply delta
    if currentIndex != NULL:
        deltas[currentIndex] -= oldBalances[vIndex]
    if nextIndex != NULL:
        deltas[nextIndex] += newBalances[vIndex]

    // rotate vote
    voteCurrentIndices[vIndex] = nextIndex

return deltas
```

Key points:
- balance units = `EffectiveBalanceIncrements` (effective balance / EFFECTIVE_BALANCE_INCREMENT)
- equivocating validators: sorted set, iterated with a single pointer to avoid
  `Set.has()` lookups in the hot loop
- SoA layout enables cache-efficient iteration

Zig mapping: Task 6 (not yet implemented).

---

## 3. protoArray/protoArray.ts -- DAG Engine

~1700 lines. The `ProtoArray` class manages the block tree.

### State

```typescript
class ProtoArray {
  pruneThreshold: number;
  justifiedEpoch: Epoch;
  justifiedRoot: RootHex;
  finalizedEpoch: Epoch;
  finalizedRoot: RootHex;
  nodes: ProtoNode[] = [];
  indices: Map<RootHex, VariantIndices>;  // blockRoot -> node index(es)
  ptcVotes: Map<RootHex, boolean[]>;       // PTC votes (Gloas)
}
```

### onBlock(block, currentSlot, proposerBoostRoot)

Add a new block to the DAG.

Pre-Gloas flow:
1. look up parent index via `indices.get(block.parentRoot)`
2. create ProtoNode with parent set to parent index
3. push to `nodes[]`, store index in `indices`
4. call `maybeUpdateBestChildAndDescendant(parentIndex, nodeIndex)`
5. propagate valid execution status upward

Gloas flow:
1. create PENDING node (parent = parent's EMPTY or FULL variant based on parentBlockHash)
2. create EMPTY node (parent = own PENDING node)
3. store `[pendingIdx, emptyIdx]` in `indices`
4. call `maybeUpdateBestChildAndDescendant` for both pairs

### applyScoreChanges({deltas, proposerBoost, ...})

Update weights after `computeDeltas`.

```
// Pass 1: apply deltas, propagate to parents (backward iteration)
for i in (nodes.length-1 .. 0):
    node = nodes[i]
    if node is Invalid:
        delta = -node.weight  // zero out
    else:
        delta = deltas[i]
    // apply proposer boost to the boosted node
    if node.blockRoot == proposerBoost.root:
        if is_boosting: delta += boostScore
        else: delta -= boostScore
    node.weight += delta
    if node.parent != null:
        deltas[node.parent] += delta  // propagate

// Pass 2: update bestChild/bestDescendant (backward iteration)
for i in (nodes.length-1 .. 0):
    node = nodes[i]
    if node.parent != null:
        maybeUpdateBestChildAndDescendant(node.parent, i)
```

### findHead(justifiedRoot, currentSlot)

```
justifiedIndex = indices.get(justifiedRoot)
justifiedNode = nodes[justifiedIndex]
bestDescendantIndex = justifiedNode.bestDescendant ?? justifiedIndex
bestNode = nodes[bestDescendantIndex]

// validate: bestNode must be viable for head
if not nodeIsViableForHead(bestNode, currentSlot):
    error INVALID_BEST_NODE

return bestNode
```

O(1) after `applyScoreChanges` has set up the bestDescendant pointers.

### maybeUpdateBestChildAndDescendant(parentIndex, childIndex)

4 cases:

```
parent = nodes[parentIndex]
child  = nodes[childIndex]

case 1: child IS bestChild, no longer viable
    -> parent.bestChild = null, parent.bestDescendant = null

case 2: child IS bestChild, still viable
    -> parent.bestDescendant = child.bestDescendant ?? childIndex

case 3: child is NOT bestChild, compare with current bestChild
    -> pick by: viable > non-viable; higher weight wins; higher root wins
    -> Gloas tiebreaker: prefer FULL > EMPTY

case 4: no bestChild exists
    -> if child is viable: parent.bestChild = childIndex
       parent.bestDescendant = child.bestDescendant ?? childIndex
```

### nodeIsViableForHead(node, currentSlot)

```
currentEpoch = computeEpochAtSlot(currentSlot)

correctJustified =
    justifiedEpoch == GENESIS_EPOCH
    OR node.justifiedEpoch == this.justifiedEpoch
    OR node.justifiedEpoch + 2 >= currentEpoch   // pull-up FFG

correctFinalized =
    finalizedEpoch == GENESIS_EPOCH
    OR isFinalizedRootOrDescendant(node)

return correctJustified AND correctFinalized
```

### maybePrune(finalizedRoot)

```
finalizedIndex = indices.get(finalizedRoot)
if finalizedIndex < pruneThreshold: return  // not worth pruning yet

// remove pruned nodes from indices map
for i in 0..finalizedIndex:
    indices.delete(nodes[i].blockRoot)

// slice off prefix
nodes = nodes[finalizedIndex..]

// adjust all indices
for each node in nodes:
    if node.parent != null:
        if node.parent < finalizedIndex: node.parent = null
        else: node.parent -= finalizedIndex
    // same for bestChild, bestDescendant
```

---

## 4. forkChoice/store.ts -- Fork Choice Store

```typescript
export type CheckpointWithHex = phase0.Checkpoint & { rootHex: RootHex };
export type CheckpointWithPayload = CheckpointWithHex & {
  payloadStatus: PayloadStatus;
};

export interface IForkChoiceStore {
  currentSlot: Slot;
  justified: CheckpointWithPayloadAndTotalBalance;
  unrealizedJustified: CheckpointWithPayloadAndBalance;
  finalizedCheckpoint: CheckpointWithPayload;
  unrealizedFinalizedCheckpoint: CheckpointWithPayload;
  justifiedBalancesGetter: JustifiedBalancesGetter;
  equivocatingIndices: Set<ValidatorIndex>;
}
```

Not yet in Zig. Will be needed for Task 12.

---

## 5. forkChoice/forkChoice.ts -- Main Orchestrator

~1860 lines. Wires everything together.

### State

```typescript
class ForkChoice implements IForkChoice {
  private protoArray: ProtoArray;
  private fcStore: IForkChoiceStore;

  // SoA votes
  private voteCurrentIndices: VoteIndex[];
  private voteNextIndices: VoteIndex[];
  private voteNextSlots: Slot[];

  // attestation queue
  private queuedAttestations: MapDef<Slot, MapDef<RootHex, Map<ValidatorIndex, PayloadStatus>>>;

  // cached head + proposer boost
  private head: ProtoBlock;
  private proposerBoostRoot: RootHex | null;
  private justifiedProposerBoostScore: number | null;
  private balances: EffectiveBalanceIncrements;
}
```

### updateHead() -- hot path

```
1. deltas = computeDeltas(nodes.len, voteCurrentIndices, voteNextIndices,
                           oldBalances, newBalances, equivocatingIndices)
2. boostScore = getCommitteeFraction(totalBalance, config)
3. protoArray.applyScoreChanges({ deltas, proposerBoost, ... })
4. head = protoArray.findHead(justifiedRoot, currentSlot)
5. cache head
```

### onBlock(block, state, ...) -- block import

```
1. validate: parent exists, slot not future, slot after finalized
2. getAncestor to check finalized descendant
3. set proposer boost if timely
4. compute justified/finalized checkpoints with payload status
5. build ProtoBlock (different paths for pre-merge / post-merge / Gloas)
6. protoArray.onBlock(protoBlock, currentSlot, proposerBoostRoot)
```

### onAttestation(attestation, ...) -- attestation processing

```
1. skip zero hash
2. validateOnAttestation() checks
3. determine PayloadStatus:
   - pre-Gloas: FULL
   - Gloas same-slot: PENDING
   - Gloas cross-slot: use indices[0]=EMPTY, indices[1]=FULL
4. if attestation.slot < currentSlot: addLatestMessage() immediately
5. if attestation.slot >= currentSlot: queue for later
```

### addLatestMessage(validatorIndex, nextSlot, nextRoot, payloadStatus)

```
nodeIndex = protoArray.getNodeIndexByRootAndStatus(nextRoot, payloadStatus)
grow vote arrays if needed
if nextSlot is from newer epoch than existing vote:
    voteNextIndices[validatorIndex] = nodeIndex
    voteNextSlots[validatorIndex] = nextSlot
```

### onTick(time) -- per-slot processing

```
1. fcStore.currentSlot = time
2. reset proposerBoostRoot (boost lasts one slot only)
3. on epoch boundary: pull up unrealized justified/finalized to actual
```

### prune(finalizedRoot) -- after finalization

```
1. prunedCount = protoArray.maybePrune(finalizedRoot)
2. adjust all vote indices:
   for each validator:
       if index < prunedCount: set to NULL_VOTE_INDEX
       else: index -= prunedCount
```

---

## 6. Data Flow

### Block Import

```
BeaconBlock
  -> ForkChoice.onBlock()
    -> validate (parent, slot, finalized descendant)
    -> compute checkpoints
    -> build ProtoBlock
    -> ProtoArray.onBlock()
      -> create ProtoNode(s)
      -> maybeUpdateBestChildAndDescendant()
```

### Attestation

```
IndexedAttestation
  -> ForkChoice.onAttestation()
    -> validate
    -> if current slot: addLatestMessage() -> update voteNextIndices
    -> if future slot: queue
```

### Head Calculation

```
ForkChoice.updateHead()
  -> computeDeltas()        -- per-validator weight diffs
  -> applyScoreChanges()    -- propagate weights, update bestChild/bestDescendant
  -> findHead()             -- justified -> bestDescendant in O(1)
```

### Pruning

```
ForkChoice.prune(finalizedRoot)
  -> ProtoArray.maybePrune()  -- slice nodes[], adjust indices
  -> adjust vote arrays       -- subtract prunedCount or set NULL
```

---

## 7. TS -> Zig Mapping Status

| TS File | Zig File | Task | Status |
|---------|----------|------|--------|
| `protoArray/interface.ts` | `proto_node.zig` | 2,4 | Done (missing Gloas fields) |
| `protoArray/errors.ts` | `proto_node.zig` | 3 | Done (co-located) |
| `protoArray/computeDeltas.ts` | -- | 6 | Not started |
| `protoArray/protoArray.ts` | -- | 7,8,9,10,11 | Not started |
| `forkChoice/store.ts` | -- | 12 | Not started |
| `forkChoice/errors.ts` | `proto_node.zig` | 3 | Done (co-located) |
| `forkChoice/interface.ts` | -- | 12 | Not started |
| `forkChoice/forkChoice.ts` | -- | 12,13 | Not started |
| `forkChoice/safeBlocks.ts` | -- | 15 | Not started |
| -- | `vote_tracker.zig` | 5 | Done |
| -- | `root.zig` | 1,15 | Done (re-exports) |

## 8. Key Architectural Differences

| Aspect | TS | Zig |
|--------|----|----|
| Root representation | `RootHex` (hex string) | `[32]u8` (byte array) |
| Root -> index lookup | `Map<string, number>` | `std.AutoHashMap([32]u8, u32)` |
| Node storage | `ProtoNode[]` (JS array) | `ArrayList(ProtoNode)` or similar |
| Vote storage | 3 parallel arrays (manual SoA) | `MultiArrayList(VoteTracker)` |
| Weight type | `number` (f64) | `i64` |
| Error handling | throw `LodestarError` | error union |
| Memory | GC | explicit allocator |
| Gloas variant | `VariantIndices` polymorphic | TBD |
