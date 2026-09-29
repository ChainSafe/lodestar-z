// Usage: node scripts/check_network_package.mjs [--target TARGET | --manifest MANIFEST] [--lifecycle]
//          [--consumer DIR [--prepare]] [--lockfile LOCKFILE]
//
// Installs packed packages into a consumer that runs bindings/test/fixtures/network-package.mjs: the load probe and,
// with --lifecycle, the lifecycle and worker fixtures with their dependencies. Without --manifest it packs TARGET's
// release packages (default this host's) as publishing prepares them, from artifacts/build.json and TARGET's addon:
// zapi prepublish, then the legal files, then the archives and their verification (scripts/lodestar_package.mjs pack).
// MANIFEST names archives `pack` made before, in either layout. The consumer resolves its lockfile, or takes LOCKFILE
// to replay, installs frozen from it, and its installed files must be the archives'. The checks then run here, for this
// host's target; with --prepare the consumer is only installed, for TARGET's platform to run
// `node bindings/test/fixtures/network-package.mjs [--lifecycle]` from it. With --consumer the consumer stays in DIR,
// which must not exist yet, as evidence: the archives with their manifest and build record, the lockfile and
// qualification.json.
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {copyFile, cp, mkdir, mkdtemp, realpath, rm, symlink, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {basename, dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {parseArgs} from "node:util";
import {getTarget, validateTarget} from "@chainsafe/zapi";
import {runBoundedCommand} from "./bounded_child.mjs";
import {pack} from "./lodestar_package.mjs";
import {verifyManifestArchive} from "./lodestar_package_archive.mjs";
import {collectFiles, readJson} from "./lodestar_package_io.mjs";
import {packageBuildRecord} from "./release_artifacts.mjs";

const source = fileURLToPath(new URL("../", import.meta.url));
const host = getTarget(process.platform, process.arch);
const {values} = parseArgs({
  options: {
    consumer: {type: "string"},
    lifecycle: {type: "boolean"},
    lockfile: {type: "string"},
    manifest: {type: "string"},
    prepare: {type: "boolean"},
    target: {type: "string"},
  },
});
assert(values.target === undefined || values.manifest === undefined, "--target and --manifest exclude each other");
assert(!values.prepare || values.consumer !== undefined, "--prepare needs --consumer DIR");
// The lifecycle fixtures' own dependencies, at the versions this checkout tests them with.
const fixtureDependencies = ["tsx", "@lodestar/config", "@libp2p/crypto", "@libp2p/peer-id"];
const command = ["bindings/test/fixtures/network-package.mjs", ...(values.lifecycle ? ["--lifecycle"] : [])];

async function run(program, args, cwd, {allowFailure = false, timeoutMs = 300_000} = {}) {
  return runBoundedCommand(program, args, cwd, {
    allowFailure,
    env: {...process.env, NODE_PATH: ""},
    maxOutputBytes: 16 * 1024 * 1024,
    timeoutMs,
  });
}

async function installedVersion(name) {
  return (await readJson(join(source, "node_modules", name, "package.json"), name)).version;
}

/** The archives' manifest in `packages`: TARGET's release packages packed now, or the copied MANIFEST's. */
async function packages(directory) {
  if (values.manifest === undefined) {
    const target = validateTarget(values.target ?? host);
    const build = await readJson(join(source, "artifacts/build.json"), "build record");
    const buildRecord = join(directory, "build-record.json");
    await writeFile(buildRecord, `${JSON.stringify(packageBuildRecord(build, target), null, 2)}\n`);
    await pack(source, join(directory, "lodestar-z.tgz"), buildRecord);
    return join(directory, "lodestar-z.tgz.json");
  }
  const manifestPath = resolve(values.manifest);
  const manifest = await readJson(manifestPath, "package manifest");
  for (const file of [basename(manifestPath), manifest.archive?.file, manifest.platform?.archive?.file]) {
    if (file !== undefined) await copyFile(join(dirname(manifestPath), file), join(directory, file));
  }
  return join(directory, basename(manifestPath));
}

const root =
  values.consumer === undefined ? await mkdtemp(join(tmpdir(), "lodestar-network-package-")) : resolve(values.consumer);
if (values.consumer !== undefined) {
  await mkdir(dirname(root), {recursive: true});
  await mkdir(root);
}
try {
  await mkdir(join(root, "packages"));
  const {inspected, manifest} = await verifyManifestArchive(await packages(join(root, "packages")), run);
  const main = inspected.packageJson;
  const target = manifest.platform?.target ?? host;
  assert(values.prepare || target === host, "another target's checks need --prepare");

  // The consumer installs the main archive and, in the platform layout, the target's platform archive in place of
  // every platform package the main package names.
  const dependencies = {[main.name]: `file:packages/${manifest.archive.file}`};
  const overrides = Object.fromEntries(Object.keys(main.optionalDependencies ?? {}).map((name) => [name, "-"]));
  if (manifest.platform !== null) {
    dependencies[manifest.platform.name] = `file:packages/${manifest.platform.archive.file}`;
    overrides[manifest.platform.name] = dependencies[manifest.platform.name];
  }
  if (values.lifecycle) for (const name of fixtureDependencies) dependencies[name] = await installedVersion(name);
  const [arch, , os, abi] = target.split("-");
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      dependencies,
      packageManager: (await readJson(join(source, "package.json"), "package.json")).packageManager,
      pnpm: {
        overrides,
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
  // The qualification runs from the lockfile it keeps: resolved here, or replayed, and installed frozen.
  if (values.lockfile === undefined) {
    const resolveOnly = ["--config.ignore-scripts=true", "install", "--lockfile-only", "--no-frozen-lockfile"];
    await run("pnpm", resolveOnly, root, {timeoutMs: 600_000});
  } else await copyFile(resolve(values.lockfile), join(root, "pnpm-lock.yaml"));
  await run("pnpm", ["--config.ignore-scripts=true", "install", "--frozen-lockfile"], root, {timeoutMs: 600_000});
  const installed = await collectFiles(await realpath(join(root, "node_modules", main.name)));
  assert.deepEqual(installed, manifest.files, "the installed main package is not the archived one");
  if (manifest.platform !== null) {
    const platform = await collectFiles(await realpath(join(root, "node_modules", manifest.platform.name)));
    assert.deepEqual(platform, manifest.platform.files, "the installed platform package is not the archived one");
  }

  // The fixtures import the package's JavaScript through bindings/src, as they do in this checkout.
  await mkdir(join(root, "bindings/test"), {recursive: true});
  await symlink(`../node_modules/${main.name}/bindings/src`, join(root, "bindings/src"));
  for (const path of [
    "bindings/test/fixtures",
    "bindings/test/utils",
    "test/interop/network_chain.mjs",
    "scripts/bounded_child.mjs",
    "scripts/lodestar_package_probe.mjs",
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
  if (values.consumer === undefined) await rm(root, {force: true, recursive: true});
}
