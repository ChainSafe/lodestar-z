# lodestar-z

Zig consensus modules for [Lodestar](https://github.com/chainsafe/lodestar), the TypeScript Ethereum consensus client.
Modules are implemented in Zig and exposed to Node.js through NAPI bindings.

This is heavily WIP.

## Installation

```sh
zig fetch git+https://github.com/ChainSafe/lodestar-z
```

### Spec Tests

`lodestar-z` is compliant against the spec tests version specified in `build.zig.zon` under `options_modules.spec_test_options`.

To run all tests:

```sh
zig build test:spec_tests
```

To run on a preset:

```sh
zig build test:spec_tests -Dpreset=minimal
```

## Developer Usage

We currently use Zig 0.16.0 and pnpm 10.x.

We follow a modified version of [TIGERSTYLE](./.gemini/styleguide.md) loosely.

Before opening a PR, please make sure all tests pass.

To do that, we need to download spec tests and era files used in testing:

```sh
# Download vectors pinned by build.zig.zon
zig build run:download_spec_tests

# Download era files
zig build run:download_era_files

# Generate test sources
zig build run:write_spec_tests
zig build run:write_ssz_generic_spec_tests
zig build run:write_ssz_static_spec_tests
zig build run:write_bls_spec_tests
```

If you created new unit tests, you can run them individually.
For example, if you made a new `ssz` unit test:

```sh
zig build test:ssz -Dtest:ssz.filters="my full test name"
```

If you made changes that affect spec relevant behavior, run:

```sh
zig build test:spec_tests -Dpreset={mainnet,minimal}
```

And run all other tests:

```sh
zig build test
```

And format all files:

```sh
zig fmt .
```

If you made a change to the bindings layer, make sure the bindings tests pass:

```sh
pnpm install

# Build bindings
zig build build-lib:bindings

# Build for a specific preset through package scripts
pnpm prepare-mainnet
pnpm prepare-minimal

# Run binding tests
pnpm test

# Run Biome
pnpm lint
pnpm exec biome check --write .
```

# License

Apache-2.0
