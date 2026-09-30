import {realpathSync} from "node:fs";
import {createRequire} from "node:module";
import {pathToFileURL} from "node:url";

// Resolves and loads package exports in a consumer, then reports the native addons the process loaded.
// The consumer must run with --experimental-import-meta-resolve.

export async function probeExports(parents, specifiers) {
  const result = {exports: {}, loadedAddons: [], resolutions: []};
  for (const parent of parents) {
    for (const specifier of specifiers) {
      try {
        result.resolutions.push({parent, resolved: import.meta.resolve(specifier, pathToFileURL(parent)), specifier});
      } catch (error) {
        result.resolutions.push({error: {code: error.code, message: error.message}, parent, specifier});
      }
    }
  }
  for (const specifier of specifiers) {
    const resolved = result.resolutions.find((row) => row.specifier === specifier && row.error === undefined)?.resolved;
    if (!resolved) continue;
    result.exports[specifier] = Object.keys(await import(resolved)).sort();
  }
  result.loadedAddons = Object.keys(createRequire(import.meta.url).cache)
    .filter((path) => path.endsWith(".node"))
    .map((path) => realpathSync(path));
  return result;
}
