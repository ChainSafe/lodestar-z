import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";

const GOSSIP_SHA256_BACKENDS = ["zig_std", "x86_sha_avx2", "aarch64_sha2"];

/** Fails unless the addon selected the backend a qualification run names in LODESTAR_Z_EXPECT_GOSSIP_SHA256. */
export function assertExpectedGossipSha256(backend) {
  const expected = process.env.LODESTAR_Z_EXPECT_GOSSIP_SHA256;
  if (!expected) return;
  assert(GOSSIP_SHA256_BACKENDS.includes(expected), `unknown expected gossip SHA-256 backend ${expected}`);
  assert.equal(backend, expected, "unexpected gossip SHA-256 backend");
}

export function inspectNetworkAddon(path) {
  const addon = createRequire(import.meta.url)(resolve(path));
  const names = Object.getOwnPropertyNames(addon).sort();
  assert(names.length <= 256, "native export bound exceeded");
  assert.equal(typeof addon.NativeNetworkRuntime, "function", "native network runtime is missing");
  const actual = names.filter((name) => /^networkTest/i.test(name));
  assert.deepEqual(actual, [], "unexpected native network test exports");
  const gossipSha256Backend = addon.NativeNetworkRuntime.gossipSha256Backend();
  assert(GOSSIP_SHA256_BACKENDS.includes(gossipSha256Backend), "unknown gossip SHA-256 backend");
  assertExpectedGossipSha256(gossipSha256Backend);
  return {exports: names, gossipSha256Backend, instrumented: false};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [path, mode = "normal"] = process.argv.slice(2);
  assert(path && mode === "normal", "usage: check_network_addon.mjs ADDON [normal]");
  process.stdout.write(`${JSON.stringify(inspectNetworkAddon(path))}\n`);
}
