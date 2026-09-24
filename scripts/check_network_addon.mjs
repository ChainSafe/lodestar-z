import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";

export function inspectNetworkAddon(path) {
  const addon = createRequire(import.meta.url)(resolve(path));
  const names = Object.getOwnPropertyNames(addon).sort();
  assert(names.length <= 256, "native export bound exceeded");
  assert.equal(typeof addon.NativeNetworkRuntime, "function", "native network runtime is missing");
  const actual = names.filter((name) => /^networkTest/i.test(name));
  assert.deepEqual(actual, [], "unexpected native network test exports");
  return {exports: names, instrumented: false};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [path, mode = "normal"] = process.argv.slice(2);
  assert(path && mode === "normal", "usage: check_network_addon.mjs ADDON [normal]");
  process.stdout.write(`${JSON.stringify(inspectNetworkAddon(path))}\n`);
}
