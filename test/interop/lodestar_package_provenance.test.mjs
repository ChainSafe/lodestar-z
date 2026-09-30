import assert from "node:assert/strict";
import {copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {dirname, join} from "node:path";
import {test} from "node:test";
import {fileURLToPath} from "node:url";
import {
  checkProvenance,
  compareCargo,
  expectedNotices,
  linkedDependencies,
  parseCargoTree,
  parseNotices,
  parseZon,
} from "../../scripts/lodestar_package_provenance.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const record = JSON.parse(await readFile(new URL("../../scripts/lodestar_package_provenance.json", import.meta.url)));
const fetched = (await checkProvenance(root, record)).summary.cargo === "resolved";

const PLATFORMS = ".github/workflows/bindings-platforms.yml";
const PUBLISH = ".github/workflows/publish-bindings.yml";

function codes(result) {
  return result.errors.map((error) => error.code);
}

async function drifted(mutate, options) {
  const copy = structuredClone(record);
  mutate(copy);
  return codes(await checkProvenance(root, copy, options));
}

async function provenanceFixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "lodestar-build-provenance-"));
  t.after(() => rm(directory, {force: true, recursive: true}));
  for (const path of [
    "package.json",
    "build.zig.zon",
    "build.zig",
    "README.md",
    "rust-toolchain.toml",
    "pnpm-lock.yaml",
    ".github/workflows/CI.yml",
    ...Object.keys(record.install.platform.workflows),
    record.notices,
    "src/leveldb/LICENSE",
  ]) {
    await mkdir(dirname(join(directory, path)), {recursive: true});
    await copyFile(join(root, path), join(directory, path));
  }
  return {copy: structuredClone(record), directory};
}

test("ZON parser reads the manifest subset and rejects malformed containers", () => {
  const zon = parseZon(`.{
    // a comment with "quotes" and .{ braces
    .name = .example,
    .@"quoted field" = "a \\"b\\"",
    .dependencies = .{ .dep = .{ .url = "u", .hash = "h", .args = .{ .optimize = .ReleaseFast } } },
    .list = .{ .one, "two:three", 0x1f },
    .empty = .{},
  }`);
  assert.equal(zon.name, "example");
  assert.equal(zon["quoted field"], 'a "b"');
  assert.deepEqual(zon.dependencies.dep, {args: {optimize: "ReleaseFast"}, hash: "h", url: "u"});
  assert.deepEqual(zon.list, ["one", "two:three", "0x1f"]);
  assert.deepEqual(zon.empty, {});
  assert.throws(() => parseZon(".{ .a = .{ }"), /incomplete/);
  assert.throws(() => parseZon(".{ .a = 1, .b }"), /mixed/);
});

test("linked dependencies follow the bindings imports through modules, not other targets", () => {
  const manifest = (networkImports) =>
    parseZon(`.{
      .dependencies = .{ .bench = .{}, .dep = .{}, .quiche = .{}, .unused = .{} },
      .options_modules = .{ .options = .{} },
      .modules = .{ .network = .{ .imports = .{ ${networkImports} } }, .tool = .{ .imports = .{ .bench } } },
      .libraries = .{ .bindings = .{ .root_module = .{ .imports = .{ .network, .options, "quiche:quiche" } } } },
    }`);
  assert.deepEqual([...linkedDependencies(manifest(".dep, .network"))].sort(), ["dep", "quiche"]);
  assert.deepEqual([...linkedDependencies(manifest(".dep, .tool"))].sort(), ["bench", "dep", "quiche"]);
  assert.throws(() => linkedDependencies(manifest(".missing")), /missing names no module or dependency/);
});

test("cargo tree listings parse into crates by name and version", () => {
  const crates = parseCargoTree(
    [
      "quiche v0.28.0 (/pkg/quiche)|BSD-2-Clause",
      "enum_dispatch v0.3.13 (proc-macro)|MIT OR Apache-2.0",
      "quote v1.0.45|MIT OR Apache-2.0 (*)",
      "",
    ].join("\n")
  );
  assert.deepEqual(
    [...crates.values()],
    [
      {license: "BSD-2-Clause", name: "quiche", version: "0.28.0"},
      {license: "MIT OR Apache-2.0", name: "enum_dispatch", version: "0.3.13"},
      {license: "MIT OR Apache-2.0", name: "quote", version: "1.0.45"},
    ]
  );
});

test("the crate inventory must equal the resolved closure", () => {
  const resolved = [
    {license: "BSD-2-Clause", name: "quiche", use: "linked", version: "0.28.0"},
    {license: "MIT", name: "bytes", use: "linked", version: "1.11.1"},
    {license: "MIT OR Apache-2.0", name: "syn", use: "build", version: "2.0.117"},
  ];
  assert.deepEqual(compareCargo(resolved, resolved), []);
  const details = (recorded) => compareCargo(recorded, resolved).map((error) => `${error.code} ${error.detail}`);
  assert.deepEqual(details(resolved.filter((crate) => crate.name !== "bytes")), [
    "CargoInventory unrecorded linked: bytes@1.11.1",
  ]);
  assert.deepEqual(details(resolved.map((crate) => (crate.name === "bytes" ? {...crate, version: "1.10.0"} : crate))), [
    "CargoInventory not resolved: bytes@1.10.0",
    "CargoInventory unrecorded linked: bytes@1.11.1",
  ]);
  assert.deepEqual(details(resolved.map((crate) => (crate.name === "syn" ? {...crate, use: "linked"} : crate))), [
    "CargoInventory syn@2.0.117 is build",
  ]);
  assert.deepEqual(
    details(resolved.map((crate) => (crate.name === "bytes" ? {...crate, license: "Apache-2.0"} : crate))),
    ["CargoLicense bytes@1.11.1 declares MIT"]
  );
  assert.deepEqual(details([...resolved, {license: "MIT", name: "extra", use: "linked", version: "1.0.0"}]), [
    "CargoInventory not resolved: extra@1.0.0",
  ]);
  assert.deepEqual(details([...resolved, resolved[1]]), ["CargoInventory duplicate bytes@1.11.1"]);
});

test("notice sections are keyed by their header and required for every distributed component", () => {
  const parsed = parseNotices("preamble\n=== a: first\n\ntext  \n\n=== b: second\nmore\n=== a: again\n");
  assert.deepEqual(
    [...parsed.sections],
    [
      ["a", ""],
      ["b", "more"],
    ]
  );
  assert.deepEqual(parsed.duplicates, ["a"]);
  const ids = expectedNotices(record).map((notice) => notice.id);
  for (const id of [
    "zig:blst/blst",
    "copied:leveldb-wrapper",
    "zig:leveldb_c/leveldb",
    "zig:leveldb_c/snappy/snappy",
    "zig:snappy",
    "zig:snappy/snappy",
    "vendored:boringssl",
    "crate:bytes@1.11.1",
    "runtime:rust-std",
    "runtime:libcxx",
  ]) {
    assert(ids.includes(id), id);
  }
  for (const id of [
    "zig:leveldb_c",
    "zig:leveldb_c/snappy",
    "zig:blst",
    "zig:quiche_zig",
    "zig:zapi/zbuild",
    "zig:zbuild",
    "crate:quiche@0.28.0",
  ]) {
    assert(!ids.includes(id), id);
  }
  assert(!ids.some((id) => id.startsWith("crate:once_cell") || id.startsWith("crate:syn")));
});

test("the checked-in record matches the tree", async () => {
  const result = await checkProvenance(root, record);
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.direct, 11);
  assert.equal(result.summary.npm, 1);
  const {comparedWordForWord, reviewedWithoutSource, sections, sourceUnavailable} = result.summary.notices;
  assert.equal(sections, expectedNotices(record).length);
  assert.equal(comparedWordForWord + reviewedWithoutSource.length + sourceUnavailable.length, sections);
});

test("the LevelDB artifact follows manifest library links without importing its upstream wrapper", async (t) => {
  const {directory, copy} = await provenanceFixture(t);
  const manifest = await readFile(join(directory, "build.zig.zon"), "utf8");
  assert(linkedDependencies(parseZon(manifest)).has("leveldb_c"));
  const detached = manifest.replace('.link_libraries = .{"leveldb_c:leveldb"}', ".link_libraries = .{}");
  assert.notEqual(detached, manifest);
  await writeFile(join(directory, "build.zig.zon"), detached);
  assert(codes(await checkProvenance(directory, copy)).includes("ZigDependencyUse"));
});

test("copied wrapper licenses are mandatory and reproduced without fetched packages", async (t) => {
  const {directory, copy} = await provenanceFixture(t);
  const result = await checkProvenance(directory, copy);
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.transitive.verified, 0);
  assert.equal(result.summary.notices.comparedWordForWord, 1);
  assert(!result.summary.notices.sourceUnavailable.includes("copied:leveldb-wrapper"));
  const path = join(directory, "src/leveldb/LICENSE");
  await writeFile(path, "changed wrapper license");
  assert.deepEqual(codes(await checkProvenance(directory, copy)), ["NoticeText"]);
  await rm(path);
  assert.deepEqual(codes(await checkProvenance(directory, copy)), ["NoticeSourceUnavailable"]);
});

test("copied licenses reject paths outside the repository", async (t) => {
  const {directory, copy} = await provenanceFixture(t);
  const copied = copy.copiedSources[0];
  await symlink(join(root, "src/leveldb/LICENSE"), join(directory, "outside-license"));
  for (const path of [
    "",
    ".",
    "../LICENSE",
    "src/../LICENSE",
    "/tmp/LICENSE",
    "C:/LICENSE",
    "src\\LICENSE",
    "outside-license",
  ]) {
    copied.reviewed.licenseFile = path;
    assert.deepEqual(codes(await checkProvenance(directory, copy)), ["NoticeSourcePath"], path);
  }
});

test("record drift from the tree fails with the disagreeing fact", async () => {
  const cases = [
    ["ZigDirectPins", (r) => r.zig.dependencies.pop()],
    [
      "ZigDependencyUse",
      (r) =>
        Object.assign(
          r.zig.dependencies.find((d) => d.name === "zio"),
          {use: "addon"}
        ),
    ],
    [
      "ZigDependencyUse",
      (r) =>
        Object.assign(
          r.zig.dependencies.find((d) => d.name === "zapi"),
          {use: "build"}
        ),
    ],
    ["ZigToolchain", (r) => Object.assign(r.zig, {toolchain: "0.15.2"})],
    ["RustToolchain", (r) => Object.assign(r.rust, {toolchain: "1.90.0"})],
    ["NpmIntegrity", (r) => Object.assign(r.npm.runtime[0], {integrity: "sha512-drift"})],
    ["NpmRuntimePins", (r) => Object.assign(r.npm.runtime[0], {version: "4.0.1"})],
    ["PackageFiles", (r) => r.install.files.splice(r.install.files.indexOf("docs/leveldb.md"), 1)],
    ["PackageFiles", (r) => r.install.files.splice(r.install.files.indexOf("src/leveldb/LICENSE"), 1)],
    ["PackageFiles", (r) => r.install.files.push("unexpected.txt")],
    ["PlatformTargets", (r) => r.install.platform.targets.pop()],
    ["ReleaseStep", (r) => r.install.platform.workflows[PUBLISH].push("pnpm zapi publish --dry-run")],
    // The legal files must be in place before verification and publishing.
    [
      "ReleaseStep",
      (r) => {
        const steps = r.install.platform.workflows[PUBLISH];
        [steps[2], steps[3]] = [steps[3], steps[2]];
      },
    ],
    [
      "ReleaseBuild",
      (r) => r.install.platform.workflows[PLATFORMS].splice(1, 1, "pnpm zapi build-artifacts --optimize ReleaseSafe"),
    ],
    ["ReleaseRunner", (r) => Object.assign(r.install.platform, {runner: "ubuntu-latest"})],
    ["EmbeddedAddonPath", (r) => Object.assign(r.install.embedded, {addon: "zig-out/bindings.node"})],
    ["PackageLicenseFile", (r) => Object.assign(r.package, {licenseFile: "LICENSE"})],
    ["PackageLicense", (r) => Object.assign(r.package.declaredLicenses, {"README.md": "MIT"})],
    ["LegalFiles", (r) => r.install.legal.push("LICENSE")],
    ["NoticeMissing", (r) => r.runtime.push({id: "extra", reviewed: {}, toolchain: "rust"})],
    ["NoticeUnexpected", (r) => r.runtime.pop()],
    [
      "NoticeMissing",
      (r) =>
        Object.assign(r.zig.dependencies.find((d) => d.name === "zapi").dependencies[0].reviewed, {
          contributes: "code",
        }),
    ],
  ];
  for (const [code, mutate] of cases) assert((await drifted(mutate)).includes(code), code);
});

test("fetched packages verify transitive pins, the resolved crate closure and reproduced license texts", async (t) => {
  if (!fetched) {
    assert((await drifted(() => {}, {requireFetched: true})).includes("ZigPackageUnfetched"));
    t.skip("zig-pkg is not fetched or cargo cannot resolve offline; a Zig build fetches both");
    return;
  }
  const result = await checkProvenance(root, record, {requireFetched: true});
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.summary.transitive, {unfetched: 0, verified: 19});
  const {comparedWordForWord, reviewedWithoutSource} = result.summary.notices;
  assert(comparedWordForWord > 0);
  const unnamed = expectedNotices(record).filter((notice) => notice.file === null);
  assert.deepEqual(
    reviewedWithoutSource,
    unnamed.map((notice) => notice.id)
  );
  // A source the record names but the checker cannot read is listed as unavailable, not compared or reviewed, and
  // fails the check when sources are required.
  const missing = structuredClone(record);
  Object.assign(missing.cargo.crates.find((c) => c.name === "bytes").reviewed, {notice: "MISSING"});
  const unavailable = await checkProvenance(root, missing);
  assert.deepEqual(unavailable.errors, []);
  assert(unavailable.summary.notices.sourceUnavailable.includes("crate:bytes@1.11.1"));
  assert.equal(unavailable.summary.notices.comparedWordForWord, comparedWordForWord - 1);
  assert.deepEqual((await checkProvenance(root, missing, {requireFetched: true})).errors, [
    {code: "NoticeSourceUnavailable", detail: "crate:bytes@1.11.1"},
  ]);
  const cases = [
    ["CargoLockfile", (r) => Object.assign(r.cargo, {lockfileSha256: "0".repeat(64)})],
    [
      "CargoInventory",
      (r) =>
        r.cargo.crates.splice(
          r.cargo.crates.findIndex((c) => c.name === "bytes"),
          1
        ),
    ],
    [
      "CargoInventory",
      (r) =>
        Object.assign(
          r.cargo.crates.find((c) => c.name === "bytes"),
          {version: "1.11.0"}
        ),
    ],
    [
      "CargoInventory",
      (r) =>
        Object.assign(
          r.cargo.crates.find((c) => c.name === "once_cell"),
          {use: "linked"}
        ),
    ],
    [
      "CargoLicense",
      (r) =>
        Object.assign(
          r.cargo.crates.find((c) => c.name === "libm"),
          {license: "Apache-2.0"}
        ),
    ],
    ["CargoRootCrate", (r) => Object.assign(r.cargo.crates[0], {version: "0.27.0"})],
    ["CargoLocked", (r) => Object.assign(r.cargo, {locked: true})],
    ["CargoFeatures", (r) => r.cargo.features.push("qlog")],
    ["CargoDefaultFeatures", (r) => Object.assign(r.cargo, {defaultFeatures: false})],
    [
      "ZigTransitivePins",
      (r) => Object.assign(r.zig.dependencies.find((d) => d.name === "snappy").dependencies[0], {url: "x"}),
    ],
    ["ZigPackageFiles", (r) => r.zig.dependencies.find((d) => d.name === "blst").files.pop()],
    ["RustInstalled", (r) => Object.assign(r.rust, {toolchain: "1.90.0"})],
    [
      "RustLibraryCrate",
      (r) =>
        Object.assign(
          r.runtime.find((entry) => entry.id === "rust-std/object@0.37.3"),
          {id: "rust-std/object@0.37.2"}
        ),
    ],
  ];
  for (const [code, mutate] of cases) assert((await drifted(mutate, {requireFetched: true})).includes(code), code);
  const directory = await mkdtemp(join(tmpdir(), "lodestar-notices-"));
  try {
    const notices = await readFile(join(root, record.notices), "utf8");
    const altered = join(directory, "notices.txt");
    await writeFile(altered, notices.replace("Copyright (c) 2018 Carl Lerche", "Copyright (c) 2018"));
    assert((await drifted((r) => Object.assign(r, {notices: altered}))).includes("NoticeText"));
  } finally {
    await rm(directory, {force: true, recursive: true});
  }
});
