// Usage:
//   node scripts/release_artifacts.mjs record [--artifacts-dir artifacts]
//   node scripts/release_artifacts.mjs verify --qualification DIR [--artifacts-dir artifacts] [--npm-dir npm]
//
// `record`, after `zapi build-artifacts`, writes build.json beside the addons: each advertised zapi target's addon hash
// and the toolchain that built them. `verify`, after `zapi prepublish`, fails unless the main package depends on
// exactly the advertised platform packages, and each is complete and holds the recorded addon, which DIR's
// qualification-TARGET/qualification.json shows ran each lifecycle scenario exactly once and passed on its platform.
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFile, readdir, realpath, writeFile} from "node:fs/promises";
import {join, resolve} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {parseArgs} from "node:util";
import {packageScenarios} from "../bindings/test/fixtures/network-package-scenarios.mjs";
import {runBoundedCommand} from "./bounded_child.mjs";

const ADDON = "bindings.node";
const LIFECYCLE_SCENARIOS = packageScenarios(true).map((scenario) => scenario.name);
// ELF e_machine and Mach-O cputype of each target's addon.
const MACHINES = {
  "aarch64-apple-darwin": 0x0100000c,
  "aarch64-unknown-linux-gnu": 183,
  "aarch64-unknown-linux-musl": 183,
  "x86_64-apple-darwin": 0x01000007,
  "x86_64-unknown-linux-gnu": 62,
  "x86_64-unknown-linux-musl": 62,
};

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function subdirectories(path) {
  const entries = await readdir(path, {withFileTypes: true});
  return entries.filter((entry) => entry.isDirectory() && !entry.name.startsWith(".")).map((entry) => entry.name);
}

/** Whether ACTUAL is a reordering of EXPECTED: nothing missing, added or repeated. */
function sameSet(actual, expected) {
  return actual.length === expected.length && [...actual].sort().every((name, i) => name === [...expected].sort()[i]);
}

/** The target a 64-bit little-endian shared library was built for, or null. */
function machineOf(bytes) {
  if (bytes.length < 20) return null;
  if (bytes.readUInt32BE(0) === 0x7f454c46 && bytes[4] === 2 && bytes[5] === 1 && bytes.readUInt16LE(16) === 3)
    return bytes.readUInt16LE(18);
  if (bytes.readUInt32LE(0) === 0xfeedfacf && bytes.readUInt32LE(12) === 6) return bytes.readUInt32LE(4);
  return null;
}

async function version(program, args) {
  try {
    const record = await runBoundedCommand(program, args, process.cwd(), {
      allowFailure: true,
      maxOutputBytes: 64 * 1024,
      timeoutMs: 30_000,
    });
    return `${record.stdout}${record.stderr}`.trim().split("\n")[0] || null;
  } catch {
    return null;
  }
}

/** The commit checked out at `packageDir`, which must be the top of its own git checkout. */
async function sourceCommit(packageDir) {
  const git = async (args) =>
    (await runBoundedCommand("git", args, packageDir, {maxOutputBytes: 64 * 1024, timeoutMs: 30_000})).stdout.trim();
  const top = await git(["rev-parse", "--show-toplevel"]);
  assert.equal(await realpath(top), await realpath(packageDir), "the package is not the top of its git checkout");
  const commit = await git(["rev-parse", "--verify", "HEAD^{commit}"]);
  assert.match(commit, /^[0-9a-f]{40}$/, "HEAD is not a commit");
  return commit;
}

export async function record(packageDir, artifactsDir) {
  const {zapi} = await readJson(join(packageDir, "package.json"));
  assert(sameSet(await subdirectories(artifactsDir), zapi.targets), "artifacts are not the advertised targets");
  const targets = {};
  for (const target of zapi.targets) {
    const bytes = await readFile(join(artifactsDir, target, ADDON));
    assert.equal(machineOf(bytes), MACHINES[target], `${target} addon is built for another target`);
    targets[target] = {bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex")};
  }
  const osRelease = await readFile("/etc/os-release", "utf8").catch(() => "");
  const build = {
    sourceCommit: await sourceCommit(packageDir),
    targets,
    toolchain: {
      assembler: await version("as", ["--version"]),
      cargo: await version("cargo", ["--version"]),
      cmake: await version("cmake", ["--version"]),
      image: process.env.ImageOS ? `${process.env.ImageOS} ${process.env.ImageVersion}` : null,
      node: process.version,
      os: /^PRETTY_NAME="?([^"\n]*)"?$/m.exec(osRelease)?.[1] ?? process.platform,
      pnpm: await version("pnpm", ["--version"]),
      rustc: await version("rustc", ["--version"]),
      zig: await version("zig", ["version"]),
    },
  };
  await writeFile(join(artifactsDir, "build.json"), `${JSON.stringify(build, null, 2)}\n`);
  return build;
}

/** Every reason the prepared packages must not be published. */
export async function verify(packageDir, artifactsDir, npmDir, qualificationDir) {
  const problems = [];
  const pkg = await readJson(join(packageDir, "package.json"));
  const targets = pkg.zapi.targets;
  const build = await readJson(join(artifactsDir, "build.json"));
  const names = targets.map((target) => `${pkg.name}-${target}`);
  if (!sameSet(Object.keys(build.targets), targets)) problems.push("build.json does not record the advertised targets");
  if (!sameSet(await subdirectories(npmDir), targets))
    problems.push("platform packages are not the advertised targets");
  const dependencies = pkg.optionalDependencies ?? {};
  if (!sameSet(Object.keys(dependencies), names) || Object.values(dependencies).some((value) => value !== pkg.version))
    problems.push("the main package does not depend on exactly the advertised platform packages at its version");
  for (const target of targets) {
    const name = `${pkg.name}-${target}`;
    const expected = build.targets[target]?.sha256;
    const platform = await readJson(join(npmDir, target, "package.json")).catch(() => null);
    const [arch, , os, abi] = target.split("-");
    const complete =
      platform?.name === name &&
      platform.version === pkg.version &&
      platform.main === ADDON &&
      platform.files?.includes(ADDON) &&
      platform.os?.join() === os &&
      platform.cpu?.join() === (arch === "aarch64" ? "arm64" : "x64") &&
      platform.libc?.join() === (abi === undefined ? undefined : abi === "gnu" ? "glibc" : "musl");
    if (!complete) problems.push(`${name} package.json is incomplete`);
    const addon = await readFile(join(npmDir, target, ADDON)).catch(() => null);
    if (addon === null || createHash("sha256").update(addon).digest("hex") !== expected)
      problems.push(`${name} does not hold the recorded addon`);
    const qualification = join(qualificationDir, `qualification-${target}`);
    const evidence = await readJson(join(qualification, "qualification.json")).catch(() => null);
    const qualified =
      evidence?.platformPackage === name &&
      evidence.addon?.sha256 === expected &&
      evidence.lifecycle === true &&
      evidence.failed === 0 &&
      sameSet(evidence.results?.map((result) => result.name) ?? [], LIFECYCLE_SCENARIOS) &&
      evidence.results.every((result) => result.passed);
    if (!qualified) problems.push(`${name} has no passing lifecycle qualification of the recorded addon`);
    const lockfile = await readFile(join(qualification, "pnpm-lock.yaml")).catch(() => null);
    if (lockfile === null) problems.push(`${name} qualification has no consumer lockfile`);
  }
  return problems;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const {positionals, values} = parseArgs({
    allowPositionals: true,
    options: {
      "artifacts-dir": {default: "artifacts", type: "string"},
      "npm-dir": {default: "npm", type: "string"},
      qualification: {type: "string"},
    },
  });
  const packageDir = fileURLToPath(new URL("../", import.meta.url));
  if (positionals[0] === "record" && positionals.length === 1) {
    process.stdout.write(`${JSON.stringify(await record(packageDir, values["artifacts-dir"]), null, 2)}\n`);
  } else if (positionals[0] === "verify" && positionals.length === 1 && values.qualification !== undefined) {
    const problems = await verify(packageDir, values["artifacts-dir"], values["npm-dir"], values.qualification);
    for (const problem of problems) process.stderr.write(`${problem}\n`);
    assert.deepEqual(problems, [], "the prepared packages must not be published");
    process.stdout.write("every advertised target is packaged with its qualified addon\n");
  } else {
    throw Error("usage: release_artifacts.mjs record | verify --qualification DIR");
  }
}
