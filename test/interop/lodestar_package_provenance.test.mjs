import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {test} from "node:test";
import {fileURLToPath} from "node:url";
import {
  checkProvenance,
  compareCargo,
  linkedDependencies,
  parseCargoTree,
  parseZon,
} from "../../scripts/lodestar_package_provenance.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const record = JSON.parse(await readFile(new URL("../../scripts/lodestar_package_provenance.json", import.meta.url)));
const fetched = (await checkProvenance(root, record)).summary.cargo === "resolved";

function codes(result) {
  return result.errors.map((error) => error.code);
}

async function drifted(mutate, options) {
  const copy = structuredClone(record);
  mutate(copy);
  return codes(await checkProvenance(root, copy, options));
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

test("the checked-in record matches the tree", async () => {
  const result = await checkProvenance(root, record);
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.direct, 10);
  assert.equal(result.summary.npm, 1);
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
    ["NpmIntegrity", (r) => Object.assign(r.npm.runtime[0], {integrity: "sha512-drift"})],
    ["NpmRuntimePins", (r) => Object.assign(r.npm.runtime[0], {version: "4.0.1"})],
    ["PlatformTargets", (r) => r.install.platform.targets.pop()],
    ["ReleaseStep", (r) => r.install.platform.steps.push("pnpm zapi publish --dry-run")],
    ["ReleaseRunner", (r) => Object.assign(r.install.platform, {runner: "ubuntu-latest"})],
    ["EmbeddedAddonPath", (r) => Object.assign(r.install.embedded, {addon: "zig-out/bindings.node"})],
    ["PackageLicenseFile", (r) => Object.assign(r.package, {licenseFile: "LICENSE"})],
  ];
  for (const [code, mutate] of cases) assert((await drifted(mutate)).includes(code), code);
});

test("fetched packages verify transitive pins and the resolved crate closure", async (t) => {
  if (!fetched) {
    assert((await drifted(() => {}, {requireFetched: true})).includes("ZigPackageUnfetched"));
    t.skip("zig-pkg is not fetched or cargo cannot resolve offline; a Zig build fetches both");
    return;
  }
  const result = await checkProvenance(root, record, {requireFetched: true});
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.summary.transitive, {unfetched: 0, verified: 15});
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
  ];
  for (const [code, mutate] of cases) assert((await drifted(mutate, {requireFetched: true})).includes(code), code);
});
