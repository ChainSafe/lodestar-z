import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";

const testExports = [
  "networkTestFail",
  "networkTestGossip",
  "networkTestGossipRelease",
  "networkTestIncoming",
  "networkTestIncomingPhase",
  "networkTestIncomingRelease",
  "networkTestRequest",
  "networkTestScenario",
  "networkTestStage",
  "networkTestStats",
];

export function inspectNetworkAddon(path, instrumented = false) {
  const addon = createRequire(import.meta.url)(resolve(path));
  const names = Object.getOwnPropertyNames(addon).sort();
  assert(names.length <= 256, "native export bound exceeded");
  assert.equal(typeof addon.NativeNetworkRuntime, "function", "native network runtime is missing");
  const actual = names.filter((name) => /^networkTest/i.test(name));
  assert.deepEqual(actual, instrumented ? testExports : [], "unexpected native network test exports");
  for (const name of actual) assert.equal(typeof addon[name], "function", `invalid native export ${name}`);
  return {exports: names, instrumented};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [path, mode = "normal"] = process.argv.slice(2);
  assert(
    path && ["normal", "instrumented"].includes(mode),
    "usage: check_network_addon.mjs ADDON [normal|instrumented]"
  );
  process.stdout.write(`${JSON.stringify(inspectNetworkAddon(path, mode === "instrumented"))}\n`);
}
