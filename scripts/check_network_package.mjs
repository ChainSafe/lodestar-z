// Usage: node scripts/check_network_package.mjs [ADDON] [--lifecycle] [--target TARGET] [--consumer DIR] [--prepare]
//
// Packs the main package and TARGET's platform package around ADDON (default artifacts/TARGET/bindings.node) and
// installs both into a consumer that runs bindings/test/fixtures/network-package.mjs: the load probe and, with
// --lifecycle, the lifecycle and worker fixtures with their dependencies. TARGET defaults to this host's, where the
// checks then run. With --consumer the consumer stays in DIR, its lockfile and qualification.json as evidence. With
// --prepare it is only installed, for TARGET's platform to run `node bindings/test/fixtures/network-package.mjs
// [--lifecycle]` from it.
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {copyFile, cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {parseArgs} from "node:util";
import {getTarget, validateTarget} from "@chainsafe/zapi";
import {runBoundedCommand} from "./bounded_child.mjs";
import {inspectNetworkAddon} from "./check_network_addon.mjs";

const source = fileURLToPath(new URL("../", import.meta.url));
const {values, positionals} = parseArgs({
  allowPositionals: true,
  options: {
    consumer: {type: "string"},
    lifecycle: {type: "boolean"},
    prepare: {type: "boolean"},
    target: {type: "string"},
  },
});
assert(positionals.length <= 1, "usage: check_network_package.mjs [ADDON] [--lifecycle] [--target T] [--consumer DIR]");
const target = validateTarget(values.target ?? getTarget(process.platform, process.arch));
assert(
  values.prepare || target === getTarget(process.platform, process.arch),
  "another target's checks need --prepare"
);
assert(!values.prepare || values.consumer !== undefined, "--prepare needs --consumer DIR");
const addon = resolve(positionals[0] ?? join(source, "artifacts", target, "bindings.node"));
if (!values.prepare) inspectNetworkAddon(addon);
const root =
  values.consumer === undefined ? await mkdtemp(join(tmpdir(), "lodestar-network-package-")) : resolve(values.consumer);
const work = await mkdtemp(join(tmpdir(), "lodestar-network-pack-"));
// The lifecycle fixtures' own dependencies, at the versions this checkout tests them with.
const fixtureDependencies = ["tsx", "@lodestar/config", "@libp2p/crypto", "@libp2p/peer-id"];
const command = ["bindings/test/fixtures/network-package.mjs", ...(values.lifecycle ? ["--lifecycle"] : [])];

async function run(program, args, cwd, timeoutMs = 120_000) {
  return runBoundedCommand(program, args, cwd, {
    env: {...process.env, NODE_PATH: ""},
    maxOutputBytes: 4 * 1024 * 1024,
    timeoutMs,
  });
}

async function installedVersion(name) {
  return JSON.parse(await readFile(join(source, "node_modules", name, "package.json"), "utf8")).version;
}

try {
  const staging = join(work, "package");
  const artifacts = join(work, "artifacts");
  const npm = join(work, "npm");
  await mkdir(staging);
  await mkdir(join(artifacts, target), {recursive: true});
  await copyFile(addon, join(artifacts, target, "bindings.node"));
  await cp(join(source, "bindings/src"), join(staging, "bindings/src"), {recursive: true});
  const pkg = JSON.parse(await readFile(join(source, "package.json"), "utf8"));
  pkg.zapi.targets = [target];
  await writeFile(join(staging, "package.json"), JSON.stringify(pkg));
  const cli = join(dirname(fileURLToPath(import.meta.resolve("@chainsafe/zapi"))), "cli.js");
  await run(process.execPath, [cli, "prepublish", "--artifacts-dir", artifacts, "--npm-dir", npm], staging);
  await mkdir(join(root, "packages"), {recursive: true});
  await run("pnpm", ["--config.ignore-scripts=true", "pack", "--out", join(root, "packages/main.tgz")], staging);
  await run(
    "pnpm",
    ["--config.ignore-scripts=true", "pack", "--out", join(root, "packages/platform.tgz")],
    join(npm, target)
  );

  const platformPackage = `${pkg.name}-${target}`;
  const [arch, , os, abi] = target.split("-");
  const dependencies = {[pkg.name]: "file:packages/main.tgz", [platformPackage]: "file:packages/platform.tgz"};
  if (values.lifecycle) for (const name of fixtureDependencies) dependencies[name] = await installedVersion(name);
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      dependencies,
      packageManager: pkg.packageManager,
      pnpm: {
        overrides: {[platformPackage]: "file:packages/platform.tgz"},
        supportedArchitectures: {
          cpu: [arch === "aarch64" ? "arm64" : "x64"],
          libc: abi === undefined ? [] : [{gnu: "glibc", musl: "musl"}[abi]],
          os: [os],
        },
      },
      private: true,
      type: "module",
    })
  );
  await run("pnpm", ["--config.ignore-scripts=true", "install", "--no-frozen-lockfile"], root, 600_000);
  // The fixtures import the package's JavaScript through bindings/src, as they do in this checkout.
  await mkdir(join(root, "bindings/test"), {recursive: true});
  await symlink(`../node_modules/${pkg.name}/bindings/src`, join(root, "bindings/src"));
  for (const path of [
    "bindings/test/fixtures",
    "bindings/test/utils",
    "test/interop/network_chain.mjs",
    "scripts/bounded_child.mjs",
  ])
    await cp(join(source, path), join(root, path), {recursive: true});

  if (values.prepare) {
    process.stdout.write(`${JSON.stringify({consumer: root, run: ["node", ...command], target})}\n`);
  } else {
    const checks = spawnSync(process.execPath, command, {
      cwd: root,
      env: {...process.env, NODE_OPTIONS: "", NODE_PATH: ""},
      stdio: "inherit",
      timeout: 1_800_000,
    });
    assert.equal(checks.status, 0, "packaged consumer checks failed");
  }
} finally {
  await rm(work, {force: true, recursive: true});
  if (values.consumer === undefined) await rm(root, {force: true, recursive: true});
}
