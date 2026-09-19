import assert from "node:assert/strict";
import {copyFile, cp, mkdir, mkdtemp, readFile, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {getTarget} from "@chainsafe/zapi";
import {runBoundedCommand} from "./bounded_child.mjs";
import {inspectNetworkAddon} from "./check_network_addon.mjs";

const source = fileURLToPath(new URL("../", import.meta.url));
const target = getTarget(process.platform, process.arch);
const addon = resolve(process.argv[2] ?? join(source, "artifacts", target, "bindings.node"));
inspectNetworkAddon(addon);
const root = await mkdtemp(join(tmpdir(), "lodestar-network-package-"));

async function run(program, args, cwd) {
  return runBoundedCommand(program, args, cwd, {
    env: {...process.env, NODE_PATH: ""},
    maxOutputBytes: 1024 * 1024,
    timeoutMs: 120_000,
  });
}

try {
  const staging = join(root, "package");
  const artifacts = join(root, "artifacts");
  const npm = join(root, "npm");
  await mkdir(staging);
  await mkdir(join(artifacts, target), {recursive: true});
  await copyFile(addon, join(artifacts, target, "bindings.node"));
  await cp(join(source, "bindings/src"), join(staging, "bindings/src"), {recursive: true});
  const pkg = JSON.parse(await readFile(join(source, "package.json"), "utf8"));
  pkg.zapi.targets = [target];
  await writeFile(join(staging, "package.json"), JSON.stringify(pkg));
  const cli = join(dirname(fileURLToPath(import.meta.resolve("@chainsafe/zapi"))), "cli.js");
  await run(process.execPath, [cli, "prepublish", "--artifacts-dir", artifacts, "--npm-dir", npm], staging);
  const mainArchive = join(root, "main.tgz");
  const platformArchive = join(root, "platform.tgz");
  await run("pnpm", ["--config.ignore-scripts=true", "pack", "--out", mainArchive], staging);
  await run("pnpm", ["--config.ignore-scripts=true", "pack", "--out", platformArchive], join(npm, target));
  const installed = join(root, "installed");
  await mkdir(installed);
  const platformPackage = `${pkg.name}-${target}`;
  await writeFile(
    join(installed, "package.json"),
    JSON.stringify({
      dependencies: {[pkg.name]: `file:${mainArchive}`, [platformPackage]: `file:${platformArchive}`},
      packageManager: pkg.packageManager,
      pnpm: {overrides: {[platformPackage]: `file:${platformArchive}`}},
      private: true,
      type: "module",
    })
  );
  await run("pnpm", ["--config.ignore-scripts=true", "install", "--no-frozen-lockfile"], installed);
  await rm(staging, {recursive: true});
  await rm(npm, {recursive: true});
  const probe = await run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `
    import assert from "node:assert/strict";
    import {createRequire} from "node:module";
    import {existsSync, realpathSync} from "node:fs";
    import {dirname, join, relative} from "node:path";
    import {fileURLToPath} from "node:url";
    const require = createRequire(join(process.cwd(), "probe.cjs"));
    const network = await import(${JSON.stringify(`${pkg.name}/network`)});
    assert.equal(typeof network.createNativeNetworkApplicationRuntime, "function");
    const nativePath = realpathSync(require.resolve(${JSON.stringify(platformPackage)}));
    assert(!relative(process.cwd(), nativePath).startsWith(".."));
    const native = require(nativePath);
    assert.equal(typeof native.NativeNetworkRuntime, "function");
    assert(!Object.getOwnPropertyNames(native).some(name => /^networkTest/i.test(name)));
    const packageRoot = join(dirname(fileURLToPath(import.meta.resolve(${JSON.stringify(`${pkg.name}/network`)}))), "../..");
    assert(!existsSync(join(packageRoot, "zig-out/lib/bindings.node")));
    assert.deepEqual(Object.keys(require.cache).filter(path => path.endsWith(".node")), [nativePath]);
    console.log(JSON.stringify({target: ${JSON.stringify(target)}, platformPackage: ${JSON.stringify(platformPackage)}, loaded: true}));
  `,
    ],
    installed
  );
  const result = JSON.parse(probe.stdout);
  assert.equal(result.loaded, true);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} finally {
  await rm(root, {force: true, recursive: true});
}
