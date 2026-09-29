import assert from "node:assert/strict";
import {mkdir, mkdtemp, readFile, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {afterEach, test} from "node:test";
import {packageScenarios} from "../../bindings/test/fixtures/network-package-scenarios.mjs";
import {record, verify} from "../../scripts/release_artifacts.mjs";

const NAME = "@chainsafe/lodestar-z";
const VERSION = "1.2.3";
const TARGETS = ["aarch64-apple-darwin", "x86_64-unknown-linux-musl"];
const temporaryDirectories = [];

afterEach(async () => {
  for (const dir of temporaryDirectories.splice(0)) await rm(dir, {force: true, recursive: true});
});

function addon(target, seed) {
  const bytes = Buffer.alloc(64, seed);
  if (target.endsWith("darwin")) {
    bytes.writeUInt32LE(0xfeedfacf, 0);
    bytes.writeUInt32LE(target.startsWith("aarch64") ? 0x0100000c : 0x01000007, 4);
    bytes.writeUInt32LE(6, 12);
  } else {
    bytes.writeUInt32BE(0x7f454c46, 0);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes.writeUInt16LE(3, 16);
    bytes.writeUInt16LE(target.startsWith("aarch64") ? 183 : 62, 18);
  }
  return bytes;
}

/** A release after build, qualification and `zapi prepublish`, as the publishing job holds it. */
async function release() {
  const root = await mkdtemp(join(tmpdir(), "release-artifacts-"));
  temporaryDirectories.push(root);
  const pkg = {name: NAME, version: VERSION, zapi: {binaryName: "bindings", targets: TARGETS}};
  await writeFile(join(root, "package.json"), JSON.stringify(pkg));
  for (const target of TARGETS) {
    await mkdir(join(root, "artifacts", target), {recursive: true});
    await writeFile(join(root, "artifacts", target, "bindings.node"), addon(target, TARGETS.indexOf(target)));
  }
  const build = await record(root, join(root, "artifacts"));
  pkg.optionalDependencies = Object.fromEntries(TARGETS.map((target) => [`${NAME}-${target}`, VERSION]));
  await writeFile(join(root, "package.json"), JSON.stringify(pkg));
  for (const target of TARGETS) {
    const [arch, , os, abi] = target.split("-");
    await mkdir(join(root, "npm", target), {recursive: true});
    await writeFile(join(root, "npm", target, "bindings.node"), addon(target, TARGETS.indexOf(target)));
    await writeFile(
      join(root, "npm", target, "package.json"),
      JSON.stringify({
        cpu: [arch === "aarch64" ? "arm64" : "x64"],
        files: ["bindings.node"],
        main: "bindings.node",
        name: `${NAME}-${target}`,
        os: [os],
        version: VERSION,
        ...(abi === undefined ? {} : {libc: [abi === "gnu" ? "glibc" : "musl"]}),
      })
    );
    const evidence = join(root, "qualification", `qualification-${target}`);
    await mkdir(evidence, {recursive: true});
    await writeFile(join(evidence, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    await writeFile(
      join(evidence, "qualification.json"),
      JSON.stringify({
        addon: {sha256: build.targets[target].sha256},
        failed: 0,
        lifecycle: true,
        platformPackage: `${NAME}-${target}`,
        results: packageScenarios(true).map(({name}) => ({name, passed: true})),
      })
    );
  }
  const check = () => verify(root, join(root, "artifacts"), join(root, "npm"), join(root, "qualification"));
  return {build, check, root};
}

async function edit(path, change) {
  const value = JSON.parse(await readFile(path, "utf8"));
  change(value);
  await writeFile(path, JSON.stringify(value));
}

test("a complete release of qualified addons verifies", async () => {
  const {build, check} = await release();
  assert.deepEqual(Object.keys(build.targets), TARGETS);
  assert.equal(build.targets[TARGETS[0]].bytes, 64);
  assert.deepEqual(await check(), []);
});

test("recording refuses a missing target and an addon built for another target", async () => {
  const {root} = await release();
  await rm(join(root, "artifacts", TARGETS[1]), {recursive: true});
  await assert.rejects(record(root, join(root, "artifacts")), /artifacts are not the advertised targets/);
  await mkdir(join(root, "artifacts", TARGETS[1]));
  await writeFile(join(root, "artifacts", TARGETS[1], "bindings.node"), addon("aarch64-unknown-linux-musl", 1));
  await assert.rejects(record(root, join(root, "artifacts")), /x86_64-unknown-linux-musl addon is built for another/);
});

test("verification refuses every incomplete, unrecorded or unqualified package", async () => {
  const musl = `${NAME}-${TARGETS[1]}`;
  const cases = [
    [
      async (root) => rm(join(root, "npm", TARGETS[1]), {recursive: true}),
      [
        "platform packages are not the advertised targets",
        `${musl} package.json is incomplete`,
        `${musl} does not hold the recorded addon`,
      ],
    ],
    [
      async (root) => edit(join(root, "package.json"), (pkg) => delete pkg.optionalDependencies[musl]),
      ["the main package does not depend on exactly the advertised platform packages at its version"],
    ],
    [
      async (root) =>
        edit(join(root, "npm", TARGETS[1], "package.json"), (pkg) => {
          pkg.libc = ["glibc"];
        }),
      [`${musl} package.json is incomplete`],
    ],
    [
      async (root) => writeFile(join(root, "npm", TARGETS[1], "bindings.node"), addon(TARGETS[1], 9)),
      [`${musl} does not hold the recorded addon`],
    ],
    [
      async (root) =>
        edit(join(root, "qualification", `qualification-${TARGETS[1]}`, "qualification.json"), (evidence) => {
          evidence.failed = 1;
          evidence.results[0].passed = false;
        }),
      [`${musl} has no passing lifecycle qualification of the recorded addon`],
    ],
    [
      async (root) => rm(join(root, "qualification", `qualification-${TARGETS[1]}`), {recursive: true}),
      [
        `${musl} has no passing lifecycle qualification of the recorded addon`,
        `${musl} qualification has no consumer lockfile`,
      ],
    ],
  ];
  for (const [change, problems] of cases) {
    const {check, root} = await release();
    await change(root);
    assert.deepEqual(await check(), problems);
  }
});

test("verification refuses a qualification that did not run each lifecycle scenario once and pass", async () => {
  const cases = {
    failing: (results) => results.with(-1, {...results.at(-1), passed: false}),
    "load only": (results) => results.slice(0, 1),
    missing: (results) => results.slice(0, -1),
    "repeated in addition": (results) => [...results, results.at(-1)],
    "repeated in place of another": (results) => results.with(-1, results[0]),
    substituted: (results) => results.with(-1, {...results.at(-1), name: "unrelated check"}),
  };
  for (const [label, change] of Object.entries(cases)) {
    const {check, root} = await release();
    await edit(join(root, "qualification", `qualification-${TARGETS[1]}`, "qualification.json"), (evidence) => {
      evidence.results = change(evidence.results);
    });
    assert.deepEqual(
      await check(),
      [`${NAME}-${TARGETS[1]} has no passing lifecycle qualification of the recorded addon`],
      label
    );
  }
});
