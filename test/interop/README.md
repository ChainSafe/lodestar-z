# Network binding lifecycle fixtures

Run the CI lifecycle suite from a clean checkout with pinned installed peers:

```sh
pnpm install --frozen-lockfile --ignore-scripts
node --test test/interop/*.test.mjs
zig build test:network_runtime -Doptimize=ReleaseSafe -Dpreset=mainnet
zig build build-lib:bindings -Doptimize=ReleaseSafe -Dpreset=mainnet -Dnetwork_runtime_options.network_runtime_test_failures=true
zig build build-exe:network_interop_peer -Doptimize=ReleaseSafe -Dpreset=mainnet
NODE_OPTIONS=--expose-gc LODESTAR_Z_NETWORK_TEST_FAILURES=1 LODESTAR_Z_NETWORK_STOCK_HOST=installed LODESTAR_Z_NETWORK_NATIVE_PEER="$PWD/zig-out/bin/network_interop_peer" pnpm exec vitest run bindings/test/network*.test.ts --reporter=default --reporter=json --outputFile=network-binding-results.json
node test/interop/check_network_binding_results.mjs network-binding-results.json
```

Repeat the build and suite with `-Dpreset=minimal` for the other CI preset. Instrumented addons
expose fault hooks and must never be packaged or published.

`LODESTAR_Z_NETWORK_STOCK_HOST=installed` uses this repository's pinned libp2p, QUIC, gossip,
Snappy, and `@lodestar/reqresp` dev dependencies. The incoming-response fixture imports
`@lodestar/reqresp` 1.46.0's packaged `lib/encoders/responseDecode.js` internal module because the
package does not export its wire decoder. The fixture import test checks that contract.
The existing ERA dependency retains its separate reqresp version.

To test an independently built Lodestar checkout, set `LODESTAR_Z_NETWORK_STOCK_HOST` to its
absolute path. That mode loads peers from `packages/beacon-node/node_modules` and the decoder
from `packages/reqresp/lib`. Missing dependencies fail the suite.

CI requires every collected network binding test to run except the two named retained Hoodi
sample tests. Set `LODESTAR_Z_NETWORK_HOODI_FIXTURE` to the retained sample file to include those
tests locally. The installed fixture runs the synthetic loopback cases without external services
or a host checkout.
