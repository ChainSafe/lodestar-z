import assert from "node:assert/strict";
import {execFile} from "node:child_process";
import {createHash} from "node:crypto";
import {access, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {afterEach, test} from "node:test";
import {promisify} from "node:util";

const exec = promisify(execFile);
const tool = new URL("lodestar_package.mjs", import.meta.url);
const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, {force: true, recursive: true})));
});

async function command(program, args, cwd) {
  try {
    const result = await exec(program, args, {cwd, encoding: "utf8"});
    return {...result, exitCode: 0};
  } catch (error) {
    return {exitCode: error.code, stderr: error.stderr ?? "", stdout: error.stdout ?? ""};
  }
}

async function missing(path) {
  await assert.rejects(access(path), {code: "ENOENT"});
}

async function fixture() {
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
    "export const createNativeNetworkApplicationRuntime = () => {};\nexport const createNativeNetworkRuntime = () => {};\n"
  );
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
  await exec("git", ["init", "-q"], {cwd: nativeDir});
  await exec("git", ["config", "user.email", "fixture@example.invalid"], {cwd: nativeDir});
  await exec("git", ["config", "user.name", "fixture"], {cwd: nativeDir});
  await exec("git", ["config", "commit.gpgSign", "false"], {cwd: nativeDir});
  await exec("git", ["add", "."], {cwd: nativeDir});
  await exec("git", ["commit", "-qm", "fixture"], {cwd: nativeDir});
  const {stdout: sourceCommit} = await exec("git", ["rev-parse", "HEAD"], {cwd: nativeDir});
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
  assert.notEqual(divergent.exitCode, 0);
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
  assert.notEqual(packed.exitCode, 0);
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
  assert.notEqual(packed.exitCode, 0);
  await missing(out);
  await missing(`${out}.json`);
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
  assert.notEqual(failure.commandRecord.exitCode, 0);
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
