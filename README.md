# lodestar-z

Zig consensus modules for [Lodestar](https://github.com/chainsafe/lodestar), the TypeScript Ethereum consensus client.
Modules are implemented in Zig and exposed to Node.js through NAPI bindings.

## Installation

You can use **lodestar-z** natively in Zig:

```sh
zig fetch --save git+https://github.com/ChainSafe/lodestar-z
```

Or in TypeScript, via napi bindings:

```sh
pnpm install @chainsafe/lodestar-z
```

The [`@chainsafe/lodestar-z/leveldb` API](./docs/leveldb.md) provides asynchronous
binary storage with bounded result copying, atomic batches, and snapshot cursors.
Its Zig module lives in `src/leveldb`; run its tests with `zig build test:leveldb`.
The root build links the C library artifact from the pinned ChainSafe `leveldb_c`
dependency; `src/leveldb/raw.zig` provides the local handles through `@cImport`.

### Spec Test Compliance

`lodestar-z` is compliant against the spec tests version specified in `build.zig.zon`
under `options_modules.spec_test_options`.

## Contributing to Lodestar-z

We welcome all contributions, but are strict about quality.
Before contributing, please read [CONTRIBUTING](./CONTRIBUTING.md) and the
relevant links inside.

We may deprioritize or close low-effort issues and pull requests at our discretion.

## License

Apache-2.0

The adapted ChainSafe LevelDB handles retain their
[MIT license](./src/leveldb/LICENSE). See the [LevelDB documentation](./docs/leveldb.md#native-dependencies-and-attribution)
for dependency attribution.

## Zig UDP API migration

The network transport owns `udp.Sockets` directly. `network.Udp` and
`network.udp.Udp` are removed; `network.udp` now names the shared UDP module.
QUIC counters and send drops live on `network.Transport`, while role-specific
`SocketBuffers` configuration lives in `network.configuration`.

`Sockets.sendMany(io, outgoing, payload_max, scratch)` borrows payload-only
`Outgoing` records and a caller-owned `BatchScratch`. It preserves input order
across families and returns the accepted prefix plus the first unsent error.
Valid entries before an oversized payload may be sent. The previous mutable
`std.Io.net.OutgoingMessage` interface, including ancillary control data, is no
longer supported. External Zig callers must migrate before adopting this API;
JavaScript bindings and metric names/values are unchanged.

Socket owners must not be copied while live. Close is mutable and clears socket
state. Operation-time send/receive overrides remain supported; Threaded operations
on handles bound by another provider return `IncompatibleProvider`. Kernel drop
observation is independent of buffer sizing and remains optional. Buffer gauges
report raw kernel values.

Owner-driven discovery uses one family readiness mask through
a drain while still advancing timers and coordinator work when no family is ready.
Standalone timed receives retain their cancellable wait contract.
