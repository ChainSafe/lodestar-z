import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";

export function stockPackages(hostRoot) {
  async function packageInfo(name) {
    const directory = resolve(hostRoot, "packages/beacon-node/node_modules", name);
    return {directory, pkg: JSON.parse(await readFile(resolve(directory, "package.json"), "utf8"))};
  }
  return {
    async load(name) {
      const parts = name.split("/");
      const packageName = parts.slice(0, name.startsWith("@") ? 2 : 1).join("/");
      const subpath = name.slice(packageName.length);
      const {directory, pkg} = await packageInfo(packageName);
      const entry = pkg.exports?.[subpath ? `.${subpath}` : "."];
      const target = typeof entry === "string" ? entry : (entry?.import ?? entry?.default ?? pkg.main);
      assert(typeof target === "string", `missing ESM export: ${name}`);
      return import(pathToFileURL(resolve(directory, target)).href);
    },
    async version(name) {
      return (await packageInfo(name)).pkg.version;
    },
  };
}
