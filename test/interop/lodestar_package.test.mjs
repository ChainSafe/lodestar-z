import assert from "node:assert/strict";
import {execFile} from "node:child_process";
import {createHash} from "node:crypto";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {afterEach, test} from "node:test";
import {promisify} from "node:util";
import {runBoundedCommand} from "./bounded_child.mjs";
import {collectFiles, sha256} from "./lodestar_package_io.mjs";

const exec = promisify(execFile);
const tool = new URL("lodestar_package.mjs", import.meta.url);
const temporaryDirectories = [];

function fixtureCommand(program, args, cwd) {
  return exec(program, args, {cwd, encoding: "utf8", timeout: 20_000});
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, {force: true, recursive: true})));
});

async function command(program, args, cwd, options = {}) {
  try {
    return await runBoundedCommand(program, args, cwd, {
      allowFailure: true,
      env: options.env,
      maxOutputBytes: 16 * 1024 * 1024,
      timeoutMs: 20_000,
    });
  } catch (error) {
    return error.commandRecord ?? {exitCode: error.code, stderr: "", stdout: ""};
  }
}

async function missing(path) {
  await assert.rejects(access(path), {code: "ENOENT"});
}

async function waitForProcessExit(pid) {
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      process.kill(pid, 0);
      const status = await readFile(`/proc/${pid}/stat`, "utf8").catch((error) => {
        if (error.code === "ENOENT") return null;
        throw error;
      });
      if (status === null || status.split(" ")[2] === "Z") return;
    } catch (error) {
      if (error.code === "ESRCH") return;
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.fail(`process ${pid} remained alive`);
}

function killProcessIfAlive(pid) {
  try {
    process.kill(pid, "SIGKILL");
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

async function fixture({extraFiles = {}, networkSource} = {}) {
  const root = await mkdtemp(join(tmpdir(), "lodestar-package-test-"));
  temporaryDirectories.push(root);
  const nativeDir = join(root, "native");
  const out = join(root, "lodestar-z.tgz");
  await mkdir(join(nativeDir, "bindings", "src"), {recursive: true});
  await mkdir(join(nativeDir, "zig-out", "lib"), {recursive: true});
  await writeFile(join(nativeDir, "bindings", "src", "index.js"), "export const fixture = true;\n");
  await writeFile(join(nativeDir, "bindings", "src", "index.d.ts"), "export declare const fixture: true;\n");
  await writeFile(
    join(nativeDir, "bindings", "src", "network.js"),
    networkSource ??
      "export const createNativeNetworkApplicationRuntime = () => {};\nexport const createNativeNetworkRuntime = () => {};\n"
  );
  for (const [path, source] of Object.entries(extraFiles)) {
    await writeFile(join(nativeDir, path), source);
  }
  await writeFile(join(nativeDir, "zig-out", "lib", "bindings.node"), "fixture-addon\n");
  await writeFile(
    join(nativeDir, "prepare.cjs"),
    'require("node:fs").writeFileSync("prepare-ran", "yes"); process.exit(23);\n'
  );
  await writeFile(
    join(nativeDir, "package.json"),
    `${JSON.stringify(
      {
        exports: Object.fromEntries(
          [
            ".",
            "./bls-verifier",
            "./blst",
            "./metrics",
            "./network",
            "./pubkeys",
            "./shuffle",
            "./state-transition",
          ].map((subpath) => [
            subpath,
            {
              import: subpath === "./network" ? "./bindings/src/network.js" : "./bindings/src/index.js",
              types: "./bindings/src/index.d.ts",
            },
          ])
        ),
        files: ["bindings/src/", "zig-out/lib/"],
        name: "@chainsafe/lodestar-z",
        packageManager: "pnpm@10.24.0",
        scripts: {prepare: "node prepare.cjs"},
        type: "module",
        version: "1.0.0",
      },
      null,
      2
    )}\n`
  );
  await fixtureCommand("git", ["init", "-q"], nativeDir);
  await fixtureCommand("git", ["config", "user.email", "fixture@example.invalid"], nativeDir);
  await fixtureCommand("git", ["config", "user.name", "fixture"], nativeDir);
  await fixtureCommand("git", ["config", "commit.gpgSign", "false"], nativeDir);
  await fixtureCommand("git", ["add", "."], nativeDir);
  await fixtureCommand("git", ["commit", "-qm", "fixture"], nativeDir);
  const {stdout: sourceCommit} = await fixtureCommand("git", ["rev-parse", "HEAD"], nativeDir);
  const addon = await readFile(join(nativeDir, "zig-out", "lib", "bindings.node"));
  const buildRecord = join(root, "build-record.json");
  await writeFile(
    buildRecord,
    `${JSON.stringify(
      {
        buildCommand: "fixture build",
        files: [
          {
            bytes: addon.byteLength,
            path: "zig-out/lib/bindings.node",
            sha256: createHash("sha256").update(addon).digest("hex"),
          },
        ],
        instrumented: false,
        optimize: "ReleaseSafe",
        preset: "mainnet",
        sourceCommit: sourceCommit.trim(),
        targetPolicy: "fixture target policy",
        toolchain: {arch: process.arch, node: process.version, pnpm: "10.24.0", zig: "fixture"},
      },
      null,
      2
    )}\n`
  );
  return {buildRecord, nativeDir, out, root};
}

test("pack suppresses prepare and verifies the archived addon", async () => {
  const {nativeDir, out, buildRecord} = await fixture();

  const normal = await command("corepack", ["pnpm", "pack", "--json", "--out", `${out}.control`], nativeDir);
  assert.equal(normal.exitCode, 23);
  assert.equal(await readFile(join(nativeDir, "prepare-ran"), "utf8"), "yes");
  await rm(join(nativeDir, "prepare-ran"));

  const packed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir
  );
  assert.equal(packed.exitCode, 0, JSON.stringify(packed));
  assert.equal(await stat(out).then((value) => value.isFile()), true);
  assert.equal(await stat(`${out}.json`).then((value) => value.isFile()), true);
  await assert.rejects(readFile(join(nativeDir, "prepare-ran")), {code: "ENOENT"});
  const manifest = JSON.parse(await readFile(`${out}.json`, "utf8"));
  assert.equal(manifest.build.preset, "mainnet");
  assert.equal(manifest.addon.path, "zig-out/lib/bindings.node");
  assert.equal(manifest.archive.sha256.length, 64);
  assert(manifest.files.some((file) => file.path === "bindings/src/index.js"));
});

test("install and verify use a relocated archive without the native checkout", async () => {
  const {root, nativeDir, out, buildRecord} = await fixture();
  const packed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir
  );
  assert.equal(packed.exitCode, 0, JSON.stringify(packed));
  const hostDir = join(root, "host");
  await mkdir(hostDir);
  await writeFile(
    join(hostDir, "package.json"),
    `${JSON.stringify(
      {
        dependencies: {"@chainsafe/lodestar-z": `file:${out}`},
        name: "host-fixture",
        packageManager: "pnpm@10.24.0",
        private: true,
        type: "module",
      },
      null,
      2
    )}\n`
  );
  await writeFile(join(hostDir, "pnpm-workspace.yaml"), 'packages:\n  - "."\n');
  await writeFile(join(hostDir, ".npmrc"), `store-dir=${join(root, "store")}\n`);
  const baseline = await command(
    "corepack",
    ["pnpm", "install", "--offline", "--ignore-scripts", "--lockfile=false"],
    hostDir
  );
  assert.equal(baseline.exitCode, 0, JSON.stringify(baseline));
  const deployed = join(root, "deployed");
  await mkdir(deployed);
  const deployedArchive = join(deployed, "lodestar-z.tgz");
  await rename(out, deployedArchive);
  await rename(`${out}.json`, `${deployedArchive}.json`);
  await rm(nativeDir, {recursive: true});
  const evidenceDir = join(root, "evidence");

  const installed = await command(
    process.execPath,
    [
      tool.pathname,
      "install",
      "--host-dir",
      hostDir,
      "--manifest",
      `${deployedArchive}.json`,
      "--evidence-dir",
      evidenceDir,
    ],
    root
  );
  assert.equal(installed.exitCode, 0, JSON.stringify(installed));
  const verified = await command(
    process.execPath,
    [tool.pathname, "verify", "--host-dir", hostDir, "--manifest", `${deployedArchive}.json`],
    root
  );
  assert.equal(verified.exitCode, 0, JSON.stringify(verified));
  const result = JSON.parse(await readFile(join(evidenceDir, "install-evidence.json"), "utf8")).verification;
  assert.equal(result.archive.sha256.length, 64);
  assert.equal(result.resolutions.packageRoots.length, 1);
  assert.equal(result.installed.addon.sha256, result.manifest.addon.sha256);
  assert.equal(await stat(join(evidenceDir, "install-evidence.json")).then((value) => value.isFile()), true);

  await writeFile(join(result.installed.packageRoot, "bindings", "src", "index.js"), "export const changed = true;\n");
  const divergent = await command(
    process.execPath,
    [tool.pathname, "verify", "--host-dir", hostDir, "--manifest", `${deployedArchive}.json`],
    root
  );
  assert.equal(divergent.exitCode, 1);
  assert.equal(JSON.parse(divergent.stderr).error.code, "InstalledPackageMismatch");
});

test("install persists and emits a structured pnpm failure record", async () => {
  const {root, nativeDir, out, buildRecord} = await fixture();
  const packed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir
  );
  assert.equal(packed.exitCode, 0, JSON.stringify(packed));
  const hostDir = join(root, "host");
  await mkdir(hostDir);
  await writeFile(
    join(hostDir, "package.json"),
    `${JSON.stringify(
      {
        dependencies: {"@chainsafe/lodestar-z": `file:${out}`},
        name: "host-fixture",
        packageManager: "pnpm@10.24.0",
        private: true,
        type: "module",
      },
      null,
      2
    )}\n`
  );
  await writeFile(join(hostDir, "pnpm-workspace.yaml"), 'packages:\n  - "."\n');
  await writeFile(join(hostDir, ".npmrc"), `store-dir=${join(root, "store")}\n`);
  const baseline = await command(
    "corepack",
    ["pnpm", "install", "--offline", "--ignore-scripts", "--lockfile=false"],
    hostDir
  );
  assert.equal(baseline.exitCode, 0, JSON.stringify(baseline));
  const bin = join(root, "bin");
  await mkdir(bin);
  const pnpm = join(bin, "pnpm");
  await writeFile(
    pnpm,
    '#!/bin/sh\nif [ "$1" = "--version" ]; then printf "10.24.0\\n"; exit 0; fi\nprintf "install-out"\nprintf "install-err" >&2\nexit 23\n'
  );
  await chmod(pnpm, 0o755);
  const evidenceDir = join(root, "failed-install");

  const installed = await command(
    process.execPath,
    [tool.pathname, "install", "--host-dir", hostDir, "--manifest", `${out}.json`, "--evidence-dir", evidenceDir],
    root,
    {env: {...process.env, PATH: `${bin}:${process.env.PATH}`}}
  );
  assert.equal(installed.exitCode, 1);
  const cliFailure = JSON.parse(installed.stderr).error;
  assert.equal(cliFailure.code, "PackageInstallFailed");
  assert.equal(cliFailure.commandRecord.cwd, hostDir);
  assert.equal(cliFailure.commandRecord.exitCode, 23);
  assert.equal(cliFailure.commandRecord.stdout, "install-out");
  assert.equal(cliFailure.commandRecord.stderr, "install-err");
  const saved = JSON.parse(await readFile(join(evidenceDir, "install-failure.json"), "utf8"));
  assert.deepEqual(saved.attempts[0].command.argv, [
    "pnpm",
    "install",
    "--offline",
    "--ignore-scripts",
    "--lockfile=false",
    "--pnpmfile",
    join(evidenceDir, "lodestar-package-hook.cjs"),
  ]);
  assert.equal(saved.attempts[0].command.cwd, hostDir);
  assert.equal(saved.attempts[0].command.exitCode, 23);
  assert.equal(saved.attempts[0].command.signal, null);
  assert.equal(saved.attempts[0].command.stderr, "install-err");
  assert.equal(saved.attempts[0].command.stdout, "install-out");
});

test("install rejects a named re-exported network test hook before host mutation", async () => {
  const {root, nativeDir, out, buildRecord} = await fixture();
  const packed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir
  );
  assert.equal(packed.exitCode, 0, JSON.stringify(packed));
  const hostDir = join(root, "host");
  await mkdir(hostDir);
  await writeFile(
    join(hostDir, "package.json"),
    `${JSON.stringify(
      {
        dependencies: {"@chainsafe/lodestar-z": `file:${out}`},
        name: "host-fixture",
        packageManager: "pnpm@10.24.0",
        private: true,
        type: "module",
      },
      null,
      2
    )}\n`
  );
  await writeFile(join(hostDir, "pnpm-workspace.yaml"), 'packages:\n  - "."\n');
  await writeFile(join(hostDir, ".npmrc"), `store-dir=${join(root, "store")}\n`);
  const baseline = await command(
    "corepack",
    ["pnpm", "install", "--offline", "--ignore-scripts", "--lockfile=false"],
    hostDir
  );
  assert.equal(baseline.exitCode, 0, JSON.stringify(baseline));
  const installedRoot = await realpath(join(hostDir, "node_modules", "@chainsafe", "lodestar-z"));
  const beforeInstalled = await collectFiles(installedRoot);
  const internalLock = join(hostDir, "node_modules", ".pnpm", "lock.yaml");
  const beforeLock = await sha256(internalLock);

  await writeFile(join(nativeDir, "bindings", "src", "hooks.js"), "export const networkTestHook = true;\n");
  await writeFile(
    join(nativeDir, "bindings", "src", "network.js"),
    "export const createNativeNetworkApplicationRuntime = () => {};\n" +
      "export const createNativeNetworkRuntime = () => {};\n" +
      'export {networkTestHook} from "./hooks.js";\n'
  );
  const badArchive = join(root, "lodestar-z-reexport.tgz");
  const repacked = await command(
    "corepack",
    ["pnpm", "--config.ignore-scripts=true", "pack", "--json", "--out", badArchive],
    nativeDir
  );
  assert.equal(repacked.exitCode, 0, JSON.stringify(repacked));
  const extracted = join(root, "reexport-package");
  await mkdir(extracted);
  const extractedArchive = await command("tar", ["-xzf", badArchive, "-C", extracted], root);
  assert.equal(extractedArchive.exitCode, 0, JSON.stringify(extractedArchive));
  const manifest = JSON.parse(await readFile(`${out}.json`, "utf8"));
  const archiveInfo = await stat(badArchive);
  manifest.archive = {bytes: archiveInfo.size, file: "lodestar-z-reexport.tgz", sha256: await sha256(badArchive)};
  manifest.files = await collectFiles(join(extracted, "package"));
  const badManifest = `${badArchive}.json`;
  await writeFile(badManifest, `${JSON.stringify(manifest, null, 2)}\n`);

  const evidenceDir = join(root, "rejected-install");
  const installed = await command(
    process.execPath,
    [tool.pathname, "install", "--host-dir", hostDir, "--manifest", badManifest, "--evidence-dir", evidenceDir],
    root
  );
  assert.equal(installed.exitCode, 1);
  assert.equal(JSON.parse(installed.stderr).error.code, "NetworkTestExport", JSON.stringify(installed));
  assert.equal(
    JSON.parse(await readFile(join(evidenceDir, "install-failure.json"), "utf8")).failure.code,
    "NetworkTestExport"
  );
  assert.equal(await realpath(join(hostDir, "node_modules", "@chainsafe", "lodestar-z")), installedRoot);
  assert.deepEqual(await collectFiles(installedRoot), beforeInstalled);
  assert.equal(await sha256(internalLock), beforeLock);
});

test("pack rejects addon hash mismatch without publishing either output", async () => {
  const {nativeDir, out, buildRecord} = await fixture();
  const record = JSON.parse(await readFile(buildRecord, "utf8"));
  record.files[0].sha256 = "0".repeat(64);
  await writeFile(buildRecord, `${JSON.stringify(record, null, 2)}\n`);

  const packed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir
  );
  assert.equal(packed.exitCode, 1);
  assert.equal(JSON.parse(packed.stderr).error.code, "AddonMismatch");
  await missing(out);
  await missing(`${out}.json`);
});

test("pack rejects tracked source drift before creating temporary output", async () => {
  const {nativeDir, out, buildRecord} = await fixture();
  await writeFile(join(nativeDir, "bindings", "src", "index.js"), "export const drifted = true;\n");

  const packed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir
  );
  assert.equal(packed.exitCode, 1);
  assert.equal(JSON.parse(packed.stderr).error.code, "SourceDrift");
  await missing(out);
  await missing(`${out}.json`);
});

test("pack emits structured child failure evidence across the CLI boundary", async () => {
  const {root, nativeDir, out, buildRecord} = await fixture();
  const bin = join(root, "bin");
  await mkdir(bin);
  const pnpm = join(bin, "pnpm");
  await writeFile(pnpm, '#!/bin/sh\nprintf "captured-out"\nprintf "captured-err" >&2\nexit 23\n');
  await chmod(pnpm, 0o755);

  const failed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir,
    {env: {...process.env, PATH: `${bin}:${process.env.PATH}`}}
  );
  assert.equal(failed.exitCode, 1);
  const evidence = JSON.parse(failed.stderr);
  assert(evidence.error.commandRecord, JSON.stringify(failed));
  assert.deepEqual(evidence.error.commandRecord.argv, [
    "pnpm",
    "--config.ignore-scripts=true",
    "pack",
    "--json",
    "--out",
    evidence.error.commandRecord.argv[5],
  ]);
  assert.equal(evidence.error.commandRecord.cwd, nativeDir);
  assert.equal(evidence.error.commandRecord.exitCode, 23);
  assert.equal(evidence.error.commandRecord.signal, null);
  assert.equal(evidence.error.commandRecord.stdout, "captured-out");
  assert.equal(evidence.error.commandRecord.stderr, "captured-err");
  await missing(out);
  await missing(`${out}.json`);
});

test("pack rejects a named re-exported network test hook", async () => {
  const {nativeDir, out, buildRecord} = await fixture({
    extraFiles: {"bindings/src/hooks.js": "export const networkTestHook = true;\n"},
    networkSource:
      'export const createNativeNetworkApplicationRuntime = () => {};\nexport const createNativeNetworkRuntime = () => {};\nexport {networkTestHook} from "./hooks.js";\n',
  });
  const packed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir
  );
  assert.equal(packed.exitCode, 1);
  assert.equal(JSON.parse(packed.stderr).error.code, "NetworkTestExport", JSON.stringify(packed));
  await missing(out);
  await missing(`${out}.json`);
});

test("pack rejects an export-star test hook without evaluating archived modules", async () => {
  const {root, nativeDir, out, buildRecord} = await fixture();
  const marker = join(root, "archive-module-evaluated");
  await writeFile(join(nativeDir, "bindings", "src", "hooks.js"), "export const networkTestHook = true;\n");
  await writeFile(
    join(nativeDir, "bindings", "src", "network.js"),
    `process.getBuiltinModule("node:fs").writeFileSync(${JSON.stringify(marker)}, "yes");\n` +
      "export const createNativeNetworkApplicationRuntime = () => {};\n" +
      "export const createNativeNetworkRuntime = () => {};\n" +
      'export * from "./hooks.js";\n'
  );
  await fixtureCommand("git", ["add", "."], nativeDir);
  await fixtureCommand("git", ["commit", "-qm", "add export star"], nativeDir);
  const {stdout: sourceCommit} = await fixtureCommand("git", ["rev-parse", "HEAD"], nativeDir);
  const record = JSON.parse(await readFile(buildRecord, "utf8"));
  record.sourceCommit = sourceCommit.trim();
  await writeFile(buildRecord, `${JSON.stringify(record, null, 2)}\n`);

  const packed = await command(
    process.execPath,
    [tool.pathname, "pack", "--native-dir", nativeDir, "--out", out, "--build-record", buildRecord],
    nativeDir
  );
  assert.equal(packed.exitCode, 1);
  assert.equal(JSON.parse(packed.stderr).error.code, "NetworkTestExport", JSON.stringify(packed));
  await missing(marker);
  await missing(out);
  await missing(`${out}.json`);
});

test("bounded inventory rejects a file by size before opening it for hashing", async () => {
  const root = await mkdtemp(join(tmpdir(), "lodestar-package-inventory-"));
  temporaryDirectories.push(root);
  const path = join(root, "over-limit");
  await writeFile(path, "xx");
  await chmod(path, 0);
  const {collectFiles} = await import("./lodestar_package_io.mjs");
  await assert.rejects(collectFiles(root, {maxBytes: 1, maxDirectories: 2, maxFiles: 2}), {
    code: "PackageSourceByteBound",
  });
});

test("archive headers reject uncompressed bytes before extraction", async () => {
  const root = await mkdtemp(join(tmpdir(), "lodestar-package-archive-bound-"));
  temporaryDirectories.push(root);
  const source = join(root, "source");
  await mkdir(join(source, "package"), {recursive: true});
  await writeFile(join(source, "package", "over-limit"), "xx");
  const archive = join(root, "package.tgz");
  const archived = await command("tar", ["-czf", archive, "-C", source, "package/over-limit"], root);
  assert.equal(archived.exitCode, 0, JSON.stringify(archived));
  const {inspectArchive} = await import("./lodestar_package_archive.mjs");
  const {runBoundedCommand} = await import("./bounded_child.mjs");
  const runCommand = (program, args, cwd, {allowFailure = false} = {}) =>
    runBoundedCommand(program, args, cwd, {allowFailure, maxOutputBytes: 1024 * 1024, timeoutMs: 5000});
  await assert.rejects(
    inspectArchive(archive, {bytes: 1, path: "zig-out/lib/bindings.node", sha256: "0".repeat(64)}, runCommand, {
      maxSourceBytes: 1,
    }),
    {code: "PackageSourceByteBound"}
  );
});

test("bounded child capture retains final stdout and stderr before close", async () => {
  const {runBoundedCommand} = await import("./bounded_child.mjs");
  const result = await runBoundedCommand(
    process.execPath,
    ["--eval", 'process.stdout.write("stdout-final"); process.stderr.write("stderr-final");'],
    process.cwd(),
    {maxOutputBytes: 1024, timeoutMs: 1000}
  );
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "stdout-final");
  assert.equal(result.stderr, "stderr-final");
});

test("bounded child capture kills a descendant after its leader exits with inherited output", async () => {
  const {runBoundedCommand} = await import("./bounded_child.mjs");
  let descendantPid;
  try {
    await assert.rejects(
      runBoundedCommand(
        process.execPath,
        [
          "--eval",
          'const {spawn} = require("node:child_process"); const child = spawn(process.execPath, ["--eval", "setInterval(() => {}, 1000)"], {stdio: ["ignore", 1, 2]}); process.stdout.write(String(child.pid)); child.unref();',
        ],
        process.cwd(),
        {maxOutputBytes: 1024, timeoutMs: 5000}
      ),
      (error) => {
        descendantPid = Number(error.commandRecord.stdout);
        assert.equal(error.code, "CommandOutputDrainTimeout");
        assert.equal(error.commandRecord.exitCode, 0);
        return true;
      }
    );
    assert(Number.isSafeInteger(descendantPid));
    await waitForProcessExit(descendantPid);
  } finally {
    if (Number.isSafeInteger(descendantPid)) killProcessIfAlive(descendantPid);
  }
});

test("bounded child capture kills a descendant that closes inherited output", async () => {
  const {runBoundedCommand} = await import("./bounded_child.mjs");
  let descendantPid;
  try {
    const result = await runBoundedCommand(
      process.execPath,
      [
        "--eval",
        'const {spawn} = require("node:child_process"); const child = spawn(process.execPath, ["--eval", "setInterval(() => {}, 1000)"], {stdio: "ignore"}); process.stdout.write(String(child.pid)); child.unref();',
      ],
      process.cwd(),
      {maxOutputBytes: 1024, timeoutMs: 5000}
    );
    descendantPid = Number(result.stdout);
    assert(Number.isSafeInteger(descendantPid));
    await waitForProcessExit(descendantPid);
  } finally {
    if (Number.isSafeInteger(descendantPid)) killProcessIfAlive(descendantPid);
  }
});

test("bounded child capture handles a reader error and cleans the owned child", async () => {
  const root = await mkdtemp(join(tmpdir(), "lodestar-package-reader-error-"));
  temporaryDirectories.push(root);
  const preload = join(root, "reader-fault.cjs");
  const runner = join(root, "runner.mjs");
  const pidPath = join(root, "pid");
  await writeFile(
    preload,
    'const fs = require("node:fs");\n' +
      "const original = fs.createReadStream;\n" +
      "fs.createReadStream = (path, options) => {\n" +
      "  const stream = original(path, options);\n" +
      '  if (String(path).includes("lodestar-package-command-")) {\n' +
      "    const originalOn = stream.on;\n" +
      "    stream.on = function(event, listener) {\n" +
      "      const result = originalOn.call(this, event, listener);\n" +
      '      if (event === "data") setTimeout(() => { stream.emit("error", Object.assign(new Error("reader failed"), {code: "EIO"})); stream.destroy(); }, 100);\n' +
      "      return result;\n" +
      "    };\n" +
      "  }\n" +
      "  return stream;\n" +
      "};\n" +
      'require("node:module").syncBuiltinESMExports();\n'
  );
  await writeFile(
    runner,
    `import {runBoundedCommand} from ${JSON.stringify(new URL("./bounded_child.mjs", import.meta.url).href)};\n` +
      "let failure;\n" +
      "try {\n" +
      `  await runBoundedCommand(process.execPath, ["--eval", ${JSON.stringify(
        `require("node:fs").writeFileSync(${JSON.stringify(pidPath)}, String(process.pid)); setInterval(() => {}, 1000);`
      )}], process.cwd(), {maxOutputBytes: 1024, timeoutMs: 5000});\n` +
      "} catch (error) { failure = error; }\n" +
      "process.stdout.write(JSON.stringify({code: failure?.code, record: failure?.commandRecord ?? null}));\n"
  );
  const before = new Set((await readdir(tmpdir())).filter((name) => name.startsWith("lodestar-package-command-")));
  let pid;
  try {
    const result = await command(process.execPath, ["--require", preload, runner], root);
    assert.equal(result.exitCode, 0, JSON.stringify(result));
    const failure = JSON.parse(result.stdout);
    assert.equal(failure.code, "EIO");
    assert.equal(failure.record.cwd, root);
    pid = Number(await readFile(pidPath, "utf8"));
    await waitForProcessExit(pid);
    const after = (await readdir(tmpdir())).filter(
      (name) => name.startsWith("lodestar-package-command-") && !before.has(name)
    );
    assert.deepEqual(after, []);
  } finally {
    if (
      !Number.isSafeInteger(pid) &&
      (await access(pidPath).then(
        () => true,
        () => false
      ))
    ) {
      pid = Number(await readFile(pidPath, "utf8"));
    }
    if (Number.isSafeInteger(pid)) killProcessIfAlive(pid);
  }
});

test("bounded child capture rejects combined output beyond the byte limit", async () => {
  const {runBoundedCommand} = await import("./bounded_child.mjs");
  let failure;
  try {
    await runBoundedCommand(
      process.execPath,
      ["--eval", 'process.stdout.write("a".repeat(700)); process.stderr.write("b".repeat(700));'],
      process.cwd(),
      {maxOutputBytes: 1024, timeoutMs: 1000}
    );
  } catch (error) {
    failure = error;
  }
  assert.match(failure.message, /CommandOutputBound/);
  assert.deepEqual(failure.commandRecord.argv.slice(0, 2), [process.execPath, "--eval"]);
  assert.equal(failure.commandRecord.cwd, process.cwd());
  assert(Buffer.byteLength(failure.commandRecord.stdout) + Buffer.byteLength(failure.commandRecord.stderr) <= 1024);
});

test("bounded child capture retains failed command output and status", async () => {
  const {runBoundedCommand} = await import("./bounded_child.mjs");
  let failure;
  try {
    await runBoundedCommand(
      process.execPath,
      ["--eval", 'process.stdout.write("failed-out"); process.stderr.write("failed-err"); process.exitCode = 23;'],
      process.cwd(),
      {maxOutputBytes: 1024, timeoutMs: 1000}
    );
  } catch (error) {
    failure = error;
  }
  assert.match(failure.message, /CommandFailed/);
  assert.equal(failure.commandRecord.exitCode, 23);
  assert.equal(failure.commandRecord.signal, null);
  assert.equal(failure.commandRecord.stdout, "failed-out");
  assert.equal(failure.commandRecord.stderr, "failed-err");
});

test("bounded child capture times out, kills the process, and removes FIFO storage", async () => {
  const {runBoundedCommand} = await import("./bounded_child.mjs");
  const root = await mkdtemp(join(tmpdir(), "lodestar-package-timeout-"));
  temporaryDirectories.push(root);
  const pidPath = join(root, "pid");
  const before = new Set((await readdir(tmpdir())).filter((name) => name.startsWith("lodestar-package-command-")));
  let failure;
  try {
    await runBoundedCommand(
      process.execPath,
      [
        "--eval",
        `require("node:fs").writeFileSync(${JSON.stringify(pidPath)}, String(process.pid)); setInterval(() => {}, 1000);`,
      ],
      process.cwd(),
      {maxOutputBytes: 1024, timeoutMs: 100}
    );
  } catch (error) {
    failure = error;
  }
  assert.match(failure.message, /CommandTimeout/);
  assert.equal(failure.commandRecord.cwd, process.cwd());
  assert.equal(failure.commandRecord.signal, "SIGKILL");
  const pid = Number(await readFile(pidPath, "utf8"));
  assert.throws(() => process.kill(pid, 0), {code: "ESRCH"});
  const after = (await readdir(tmpdir())).filter(
    (name) => name.startsWith("lodestar-package-command-") && !before.has(name)
  );
  assert.deepEqual(after, []);
});

test("bounded child capture cleans FIFO storage when the child cannot spawn", async () => {
  const {runBoundedCommand} = await import("./bounded_child.mjs");
  const before = new Set((await readdir(tmpdir())).filter((name) => name.startsWith("lodestar-package-command-")));
  let failure;
  try {
    await runBoundedCommand("lodestar-package-command-that-does-not-exist", [], process.cwd(), {
      maxOutputBytes: 1024,
      timeoutMs: 1000,
    });
  } catch (error) {
    failure = error;
  }
  assert.equal(failure.code, "ENOENT");
  assert.deepEqual(failure.commandRecord.argv, ["lodestar-package-command-that-does-not-exist"]);
  assert.equal(failure.commandRecord.cwd, process.cwd());
  const after = (await readdir(tmpdir())).filter(
    (name) => name.startsWith("lodestar-package-command-") && !before.has(name)
  );
  assert.deepEqual(after, []);
});
