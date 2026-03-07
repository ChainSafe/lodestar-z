# Task 4: ProtoNode + ProtoBlock Structs

**Status:** Done
**Source:** `src/fork_choice/proto_node.zig`

## Goal

Define the core data structures for the fork choice DAG: `ProtoBlock` (input data), `ProtoNode` (flat: block fields + DAG metadata), and related response types.

## Data Structures

### ProtoBlock

The block data as it enters fork choice.

```zig
pub const ProtoBlock = struct {
    slot: Slot,
    block_root: Root,
    parent_root: Root,
    state_root: Root,
    target_root: Root,

    justified_epoch: Epoch,
    justified_root: Root,
    finalized_epoch: Epoch,
    finalized_root: Root,

    unrealized_justified_epoch: Epoch,
    unrealized_justified_root: Root,
    unrealized_finalized_epoch: Epoch,
    unrealized_finalized_root: Root,

    extra_meta: BlockExtraMeta,
    timeliness: bool,

    builder_index: ?ValidatorIndex = null,
    block_hash: ?Root = null,
};
```

### ProtoNode

Flat layout: all ProtoBlock fields + DAG metadata. Uses comptime `inline for` + `@field`
for conversion between ProtoBlock and ProtoNode.

```zig
pub const ProtoNode = struct {
    // ── All ProtoBlock fields (duplicated for flat access) ──
    slot: Slot,
    block_root: Root,
    // ... (same fields as ProtoBlock) ...

    // ── DAG metadata ──
    parent: ?u32 = null,
    weight: i64 = 0,
    best_child: ?u32 = null,
    best_descendant: ?u32 = null,

    pub fn fromBlock(block: ProtoBlock) ProtoNode {
        var node: ProtoNode = undefined;
        inline for (std.meta.fields(ProtoBlock)) |field| {
            @field(node, field.name) = @field(block, field.name);
        }
        node.parent = null;
        node.weight = 0;
        node.best_child = null;
        node.best_descendant = null;
        return node;
    }

    pub fn toBlock(self: ProtoNode) ProtoBlock {
        var block: ProtoBlock = undefined;
        inline for (std.meta.fields(ProtoBlock)) |field| {
            @field(block, field.name) = @field(self, field.name);
        }
        return block;
    }
};
```

### BlockExtraMeta

Two-variant tagged union separating pre-merge/post-merge concerns.
`PostMergeMeta.init()` rejects `ExecutionStatus.pre_merge` via assert.

```zig
pub const BlockExtraMeta = union(enum) {
    post_merge: PostMergeMeta,
    pre_merge: void,

    pub const PostMergeMeta = struct {
        execution_payload_block_hash: Root,
        execution_payload_number: u64,
        execution_status: ExecutionStatus,
        data_availability_status: DataAvailabilityStatus,

        pub fn init(...) PostMergeMeta {
            assert(status != .pre_merge);
            return .{ ... };
        }
    };

    pub fn executionPayloadBlockHash(self: BlockExtraMeta) ?Root { ... }
    pub fn executionStatus(self: BlockExtraMeta) ExecutionStatus { ... }
    pub fn dataAvailabilityStatus(self: BlockExtraMeta) DataAvailabilityStatus { ... }
};
```

Accessor behavior:

| Accessor | `.post_merge` | `.pre_merge` |
|---|---|---|
| `executionPayloadBlockHash()` | the hash | `null` |
| `executionStatus()` | from field | `.pre_merge` |
| `dataAvailabilityStatus()` | from field | `.pre_data` |

### LVH Response Types

```zig
pub const LVHExecResponse = union(enum) {
    valid: LVHValidResponse,
    invalid: LVHInvalidResponse,
};

pub const LVHValidResponse = struct {
    latest_valid_exec_hash: Root,
};

pub const LVHInvalidResponse = struct {
    latest_valid_exec_hash: ?Root,        // null -> irrecoverable error
    invalidate_from_parent_block_root: Root,
};
```

## Key Design Decisions

### Why flat ProtoNode?

TS uses `ProtoNode = ProtoBlock & { parent, weight, ... }` (intersection type, flat access).
We match this: `node.slot` instead of `node.block.slot`. The TS team had both flat and
composition available and chose flat — the fork choice algorithm intermixes block field
and DAG field access frequently (`applyScoreChanges`, `nodeIsViableForHead`).

`fromBlock()` / `toBlock()` use comptime `inline for` + `@field` to copy matching fields.
Zero runtime overhead (unrolled at compile time).

### Why `?u32` for DAG indices?

Zig's `?u32` optional type is more idiomatic than sentinel values:
- Compiler enforces null checks
- `orelse` and `if (opt) |val|` patterns

`NULL_VOTE_INDEX` sentinel is still used in VoteTracker where SoA storage
makes optionals impractical (cache efficiency).

### Why `BlockExtraMeta` assert over `union(ExecutionStatus)`?

- 2 variants (`post_merge`/`pre_merge`) is clearer than 5
- `PostMergeMeta.init()` assert catches misuse during development
- TigerStyle: assertions are the idiomatic invariant enforcement mechanism

## Tests

| Test | Validates |
|------|-----------|
| "ExecutionStatus enum values" | Wire-compatible ordinal values |
| "DataAvailabilityStatus enum values" | Wire-compatible ordinal values |
| "BlockExtraMeta pre_merge accessors" | Null/default returns for pre-merge |
| "BlockExtraMeta post_merge accessors" | Field delegation for post-merge |
| "PostMergeMeta.init rejects pre_merge status" | Valid construction of non-pre_merge statuses |
| "ProtoNode default values" | `fromBlock()` sets DAG fields to null/0, copies block fields |
| "ProtoNode.toBlock round-trip" | `fromBlock()` -> modify DAG fields -> `toBlock()` preserves block data |
