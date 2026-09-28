import assert from "node:assert/strict";
import {mkdir, mkdtemp, rm, stat, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath} from "node:url";
import {getTarget} from "@chainsafe/zapi";
import {runBoundedCommand} from "./bounded_child.mjs";
import {inspectNetworkAddon} from "./check_network_addon.mjs";
import {installHook, pack, verifyInstalled} from "./lodestar_package.mjs";
import {verifyManifestArchive} from "./lodestar_package_archive.mjs";
import {readJson, sha256} from "./lodestar_package_io.mjs";

// Packs the release layout from this checkout's zapi artifact for the host target, as the publish workflow does,
// installs the main and platform archives into a bare consumer and runs the package probe there, native lifecycle
// included.

const source = fileURLToPath(new URL("../", import.meta.url));
const target = getTarget(process.platform, process.arch);
const artifact = `artifacts/${target}/bindings.node`;
inspectNetworkAddon(join(source, artifact));
const root = await mkdtemp(join(tmpdir(), "lodestar-network-package-"));

async function run(program, args, cwd, {allowFailure = false} = {}) {
  return runBoundedCommand(program, args, cwd, {
    allowFailure,
    env: {...process.env, NODE_PATH: ""},
    maxOutputBytes: 16 * 1024 * 1024,
    timeoutMs: 300_000,
  });
}

try {
  const pkg = await readJson(join(source, "package.json"), "package.json");
  const version = async (program, args) => (await run(program, args, source)).stdout.trim();
  const buildRecord = join(root, "build-record.json");
  await writeFile(
    buildRecord,
    JSON.stringify({
      buildCommand: "pnpm zapi build-artifacts --optimize ReleaseSafe",
      files: [
        {
          bytes: (await stat(join(source, artifact))).size,
          path: artifact,
          sha256: await sha256(join(source, artifact)),
        },
      ],
      instrumented: false,
      optimize: "ReleaseSafe",
      preset: "mainnet",
      sourceCommit: await version("git", ["rev-parse", "HEAD"]),
      targetPolicy: `zapi ${target}: the default CPU and libc of its Zig target`,
      toolchain: {
        arch: process.arch,
        node: process.version.slice(1),
        pnpm: await version("pnpm", ["--version"]),
        zig: await version("zig", ["version"]),
      },
    })
  );
  const manifestPath = join(root, "archives", "lodestar-z.tgz.json");
  await pack(source, join(root, "archives", "lodestar-z.tgz"), buildRecord);
  const archiveState = await verifyManifestArchive(manifestPath, run);
  const consumer = join(root, "consumer");
  await mkdir(consumer);
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({
      dependencies: {[pkg.name]: `file:${archiveState.archive}`},
      packageManager: pkg.packageManager,
      private: true,
      type: "module",
    })
  );
  const hook = join(root, "hook.cjs");
  await writeFile(hook, installHook(archiveState).source);
  await run("pnpm", ["install", "--ignore-scripts", "--no-frozen-lockfile", "--pnpmfile", hook], consumer);
  const verification = await verifyInstalled(consumer, manifestPath, archiveState);
  assert.equal(verification.installed.platform.files.length, archiveState.manifest.platform.files.length);
  assert.equal(verification.runtime.cycles.length, 2);
  process.stdout.write(
    `${JSON.stringify({
      addon: verification.installed.addon,
      platformPackage: archiveState.manifest.platform.name,
      runtime: verification.runtime,
      target,
    })}\n`
  );
} finally {
  await rm(root, {force: true, recursive: true});
}
