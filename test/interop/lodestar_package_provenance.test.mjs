import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {test} from "node:test";
import {fileURLToPath} from "node:url";
import {checkProvenance, linkedDependencies, parseZon} from "../../scripts/lodestar_package_provenance.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const record = JSON.parse(await readFile(new URL("../../scripts/lodestar_package_provenance.json", import.meta.url)));

function codes(result) {
  return result.errors.map((error) => error.code);
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

test("the checked-in record matches the tree", async () => {
  const result = await checkProvenance(root, record);
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.direct, 10);
  assert.equal(result.summary.npm, 1);
});

test("record drift from the tree fails with the disagreeing fact", async () => {
  const cases = [
    [
      (r) => {
        r.zig.dependencies.find((d) => d.name === "blst").hash = "blst-0.0.0-drift";
      },
      "ZigDirectPins",
    ],
    [
      (r) => {
        r.zig.dependencies.pop();
      },
      "ZigDirectPins",
    ],
    [
      (r) => {
        r.zig.dependencies.find((d) => d.name === "zio").use = "addon";
      },
      "ZigDependencyUse",
    ],
    [
      (r) => {
        r.zig.dependencies.find((d) => d.name === "zapi").use = "build";
      },
      "ZigDependencyUse",
    ],
    [
      (r) => {
        r.zig.toolchain = "0.15.2";
      },
      "ZigToolchain",
    ],
    [
      (r) => {
        r.npm.runtime[0].integrity = "sha512-drift";
      },
      "NpmIntegrity",
    ],
    [
      (r) => {
        r.npm.runtime[0].version = "4.0.1";
      },
      "NpmRuntimePins",
    ],
    [
      (r) => {
        r.install.platform.targets.pop();
      },
      "PlatformTargets",
    ],
    [
      (r) => {
        r.install.platform.steps.push("pnpm zapi publish --dry-run");
      },
      "ReleaseStep",
    ],
    [
      (r) => {
        r.install.platform.runner = "ubuntu-latest";
      },
      "ReleaseRunner",
    ],
    [
      (r) => {
        r.install.embedded.addon = "zig-out/bindings.node";
      },
      "EmbeddedAddonPath",
    ],
    [
      (r) => {
        r.package.licenseFile = "LICENSE";
      },
      "PackageLicenseFile",
    ],
  ];
  for (const [mutate, code] of cases) {
    const drifted = structuredClone(record);
    mutate(drifted);
    assert(codes(await checkProvenance(root, drifted)).includes(code), code);
  }
});

test("fetched packages verify transitive pins and the quiche lockfile", async (t) => {
  const result = await checkProvenance(root, record);
  if (result.summary.cargo !== "verified") {
    assert(codes(await checkProvenance(root, record, {requireFetched: true})).includes("ZigPackageUnfetched"));
    t.skip("zig-pkg is not fetched; a Zig build fetches it");
    return;
  }
  assert.deepEqual(result.summary.transitive, {unfetched: 0, verified: 15});
  const cases = [
    [
      (r) => {
        r.cargo.lockfileSha256 = "0".repeat(64);
      },
      "CargoLockfile",
    ],
    [
      (r) => {
        r.cargo.crates.find((c) => c.name === "bytes").version = "1.0.0";
      },
      "CargoCrate",
    ],
    [
      (r) => {
        r.cargo.crates[0].license = "MIT";
      },
      "CargoRootCrate",
    ],
    [
      (r) => {
        r.cargo.locked = true;
      },
      "CargoLocked",
    ],
    [
      (r) => {
        r.zig.dependencies.find((d) => d.name === "snappy").dependencies[0].url = "drift";
      },
      "ZigTransitivePins",
    ],
  ];
  for (const [mutate, code] of cases) {
    const drifted = structuredClone(record);
    mutate(drifted);
    assert(codes(await checkProvenance(root, drifted)).includes(code), code);
  }
});
