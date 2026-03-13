# lodestar-z
Zig consensus modules for Lodestar

## Installation
`zig fetch git+https://github.com/ChainSafe/lodestar-z`

## Usage

This project provides several modules:
- `hashing`
- `persistent_merkle_tree`
- `ssz`
- `consensus_types`

### Ssz

A Zig implementation of Ethereum’s [SSZ (Simple Serialize)](https://github.com/ethereum/consensus-specs/tree/dev/ssz) serialization format, Merkleization, and consensus‐type definitions. Provides:

- Hashing utilities (SHA‑256, zero‐hash tree, Merkleization)
- Merkle tree memory pool, structural sharing and lazy hashing
- A SSZ library for defining SSZ types
  - Core spec operations, to/from byte array<->structs<->merkle tree
  - Typed views on merkle tree and byte array
  - TODO: merkle proofs, multiproofs
- A full set of Ethereum consensus types (phase0, altair, bellatrix, capella, deneb, electra) defined as SSZ containers


```zig
const std = @import("std");
const ssz = @import("ssz");

// All types defined by the spec are available (except union)
// An ssz type definition returns a namespace of related decls used to operate on the datatype

const uint64 = ssz.UintType(64);

test "uint64" {
    try std.testing.expectEqual(u64, uint64.Type);
    try std.testing.expectEqual(8, uint64.fixed_size);
    try std.testing.expectEqual(0, uint64.default_value);

    const i: uint64.Type = 42;
    var i_buf: [uint64.fixed_size] = undefined;

    const bytes_written = uint64.serializeToBytes(&i, &i_buf);
    try std.testing.expectEqual(uint64.fixed_size, bytes_written);

    var j: uint64.Type = undefined;
    try uint64.deserializeToBytes(&i_buf, &j);

    var root: [32]u8 = undefined;
    try uint64.hashTreeRoot(&i, &root);
    try uint64.serialized.hashTreeRoot(&i_buf, &root);
}

// Composite types are broken into fixed and variably-sized variants
const checkpoint = ssz.FixedContainerType(struct {
    epoch: ssz.UintType(64),
    root: ssz.ByteVectorType(32),
});

const beacon_state = ssz.VariableContainerType(struct {
    ...
});

// variably-sized variants require an allocator for most operations
// TODO more examples

// Using merkle trees
test TreeView {
    const Node = @import("persistent_merkle_tree").Node;
    var pool = try Node.Pool.init(std.testing.allocator, 100_000);
    defer pool.deinit();
    const root_node = try checkpoint.tree.fromValue(&pool, .{
        .epoch = 42,
        .root = [_]u8{0} ** 32,
    });

    var view = try checkpoint.TreeView.init(std.testing.allocator, &pool, root_node);
    try std.testing.expectEqual(
        u64,
        42,
        // get field by field name
        // returns
        //     if (comptime isBasicType(field.type)) field.type.Value
        //     else TreeView(field.type)
        try view.getField("epoch"),
    );

    // set field by field name
    try view.setField("epoch", 100);
    
    // commit changes, updating the stored root node
    view.commit();

    // htr now works as expected
    var htr_from_value: [32]u8 = undefined;
    try checkpoint.hashTreeRoot(.{
        .epoch = 100,
        .root = [_]u8{0} ** 32,
    }, &htr_from_value);

    var htr_from_tree: [32]u8 = undefined;
    view.hashTreeRoot(&htr_from_tree);
    
    try std.testing.expectEqualSlices(
        u8,
        &htr_from_value,
        &htr_from_tree,
    );
}


```

### Consensus types

```zig
const consensus_types = @import("consensus_types");

const Checkpoint = consensus_types.phase0.Checkpoint;

pub fn main() !void {
    var c: Checkpoint.Type = Checkpoint.default_value;
    c.epoch = 42;
}
```

## Developer usage

Clone the repository:

```bash
git clone https://github.com/ChainSafe/lodestar-z.git
```

After cloning:

```bash
# Build the project
zig build

# Run all unit tests
zig build test
```

To run Ethereum consensus spec tests (recommended for contributors):

1. Download and generate spec test vectors (one-time or when updating spec version):
   ```bash
   zig build run:download_spec_tests
   zig build run:write_spec_tests
   zig build run:write_ssz_generic_spec_tests
   zig build run:write_ssz_static_spec_tests
   ```
2. Run spec tests (use `-Dpreset=minimal` for faster runs):
   ```bash
   zig build test:int
   zig build test:spec_tests -Dpreset=minimal
   zig build test:ssz_generic_spec_tests -Dpreset=minimal
   zig build test:ssz_static_spec_tests -Dpreset=minimal
   ```
   For mainnet preset: replace `-Dpreset=minimal` with `-Dpreset=mainnet`.

Alternatively use the [Makefile](Makefile) for common tasks: `make help`.

## Contributing

- **Style:** Follow [.gemini/styleguide.md](.gemini/styleguide.md) (TigerStyle-based).
- **Testing:** Run `zig build test` before submitting; run spec tests when changing consensus or SSZ behavior.
- **First steps:** See the [Makefile](Makefile) (`make help`) for build, test, spec, and benchmark targets.

# License

Apache-2.0
