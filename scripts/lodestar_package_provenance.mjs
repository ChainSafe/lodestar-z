import {createHash} from "node:crypto";
import {readFile, readdir} from "node:fs/promises";
import {join, resolve} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {runBoundedCommand} from "./bounded_child.mjs";
import {EMBEDDED_ADDON_PATH} from "./lodestar_package_archive.mjs";
import {exists} from "./lodestar_package_io.mjs";

// Checks the dependency and install provenance record against the tree: Zig pins and their use, the npm runtime pins
// and the two install paths. When zig-pkg holds the packages it also checks transitive Zig pins and cargo's offline
// resolution of the quiche lockfile. Needs no build and no network.

const RECORD = "scripts/lodestar_package_provenance.json";
const MAX_ZON_TOKENS = 64 * 1024;
const MAX_ZON_DEPTH = 32;
const MAX_ZIG_PACKAGES = 256;
const MAX_MODULES = 1024;
const MAX_PACKAGE_FILES = 4096;
const MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 60_000;

/** Parses the ZON subset build manifests use: containers, strings, enum literals, numbers and comments. */
export function parseZon(source) {
  const tokens = [];
  const word = /[A-Za-z0-9_+-]/;
  for (let i = 0; i < source.length; ) {
    if (tokens.length >= MAX_ZON_TOKENS) throw Error("ZON token bound");
    const c = source[i];
    if (/\s|,/.test(c)) i++;
    else if (source.startsWith("//", i)) i = source.includes("\n", i) ? source.indexOf("\n", i) : source.length;
    else if (source.startsWith(".{", i)) {
      tokens.push({type: "open"});
      i += 2;
    } else if (c === "}" || c === "=") {
      tokens.push({type: c === "}" ? "close" : "equals"});
      i++;
    } else if (c === '"' || source.startsWith('.@"', i)) {
      const dotted = c === ".";
      let j = i + (dotted ? 3 : 1);
      let value = "";
      while (source[j] !== '"') {
        if (j >= source.length) throw Error("unterminated ZON string");
        if (source[j] === "\\") {
          const escaped = source[j + 1];
          value += escaped === "n" ? "\n" : escaped === "t" ? "\t" : escaped;
          j += 2;
        } else value += source[j++];
      }
      tokens.push(dotted ? {name: value, type: "dot"} : {type: "value", value});
      i = j + 1;
    } else if (c === ".") {
      let j = i + 1;
      while (j < source.length && word.test(source[j])) j++;
      tokens.push({name: source.slice(i + 1, j), type: "dot"});
      i = j;
    } else if (word.test(c)) {
      let j = i;
      while (j < source.length && word.test(source[j])) j++;
      tokens.push({type: "value", value: source.slice(i, j)});
      i = j;
    } else throw Error(`unexpected ZON character ${JSON.stringify(c)}`);
  }
  const stack = [];
  let root;
  const place = (value) => {
    const frame = stack.at(-1);
    if (frame === undefined) root = value;
    else if (frame.key !== null) {
      frame.fields[frame.key] = value;
      frame.key = null;
    } else frame.items.push(value);
  };
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    if (token.type === "open") {
      if (stack.length >= MAX_ZON_DEPTH) throw Error("ZON depth bound");
      stack.push({fields: {}, items: [], key: null});
    } else if (token.type === "close") {
      const frame = stack.pop();
      if (frame === undefined || frame.key !== null) throw Error("unbalanced ZON container");
      if (frame.items.length > 0 && Object.keys(frame.fields).length > 0) throw Error("mixed ZON container");
      place(frame.items.length > 0 ? frame.items : frame.fields);
    } else if (token.type === "dot" && tokens[index + 1]?.type === "equals") {
      stack.at(-1).key = token.name;
      index++;
    } else place(token.type === "dot" ? token.name : token.value);
  }
  if (stack.length !== 0 || root === undefined) throw Error("incomplete ZON document");
  return root;
}

const list = (value) => (Array.isArray(value) ? value : []);

/** Dependencies whose code the bindings library links: reached through its imports and the modules they import. */
export function linkedDependencies(zon) {
  const modules = zon.modules ?? {};
  const dependencies = zon.dependencies ?? {};
  const options = zon.options_modules ?? {};
  const bindings = zon.libraries?.bindings?.root_module;
  if (bindings === undefined) throw Error("build.zig.zon declares no bindings library");
  const queue = [...list(bindings.imports), ...list(bindings.link_libraries)];
  const visited = new Set();
  const linked = new Set();
  for (let index = 0; index < queue.length; index++) {
    if (index >= MAX_MODULES) throw Error("module graph bound");
    const name = queue[index];
    if (name.includes(":")) linked.add(name.slice(0, name.indexOf(":")));
    else if (modules[name] !== undefined) {
      if (visited.has(name)) continue;
      visited.add(name);
      queue.push(...list(modules[name].imports), ...list(modules[name].link_libraries));
    } else if (dependencies[name] !== undefined) linked.add(name);
    else if (options[name] === undefined) throw Error(`bindings import ${name} names no module or dependency`);
  }
  return linked;
}

function pins(dependencies) {
  return Object.entries(dependencies ?? {})
    .map(([name, pin]) => ({hash: pin.hash, name, url: pin.url}))
    .sort((left, right) => left.name.localeCompare(right.name));
}

const recordPins = (entries) =>
  entries.map(({hash, name, url}) => ({hash, name, url})).sort((left, right) => left.name.localeCompare(right.name));

async function readOptional(path) {
  return readFile(path, "utf8").catch((error) => (error.code === "ENOENT" ? null : Promise.reject(error)));
}

function cargoCrate(record) {
  const [parentName, crateName] = record.cargo.crate.split("/");
  const parent = record.zig.dependencies.find((entry) => entry.name === parentName);
  const crate = parent?.dependencies.find((entry) => entry.name === crateName);
  return crate === undefined ? undefined : {hash: crate.hash, parent};
}

/** Crates of one `cargo tree --format {p}|{l}` listing, by name and version. */
export function parseCargoTree(stdout) {
  const crates = new Map();
  for (const line of stdout.split("\n")) {
    const match = /^(\S+) v(\S+)(?: \([^)]*\))?\|(.*?)(?: \(\*\))?$/.exec(line.trim());
    if (match !== null) crates.set(`${match[1]}@${match[2]}`, {license: match[3], name: match[1], version: match[2]});
  }
  return crates;
}

async function command(program, args, cwd) {
  const result = await runBoundedCommand(program, args, cwd, {
    allowFailure: true,
    maxOutputBytes: MAX_COMMAND_OUTPUT_BYTES,
    timeoutMs: COMMAND_TIMEOUT_MS,
  }).catch((error) => ({exitCode: null, stderr: error.message, stdout: ""}));
  return result.exitCode === 0 ? {stdout: result.stdout} : {error: `${program} ${args.join(" ")}: ${result.stderr}`};
}

/**
 * The crates quiche's pinned lockfile resolves for the recorded features, defaults included, on every release target,
 * offline. Linked crates are the normal dependencies without procedural macros; the rest serve only the build.
 */
export async function resolveCargo(crateDirectory, record) {
  const key = JSON.stringify([
    crateDirectory,
    record.cargo.features,
    record.cargo.defaultFeatures,
    record.install.platform.targets,
  ]);
  if (!resolutions.has(key)) resolutions.set(key, await resolveCargoTrees(crateDirectory, record));
  return resolutions.get(key);
}

const resolutions = new Map();

async function resolveCargoTrees(crateDirectory, record) {
  const linked = new Map();
  const all = new Map();
  for (const target of record.install.platform.targets) {
    const base = ["tree", "--frozen", "--target", target, "--prefix", "none", "--format", "{p}|{l}"];
    if (record.cargo.features.length > 0) base.push("--features", record.cargo.features.join(","));
    if (!record.cargo.defaultFeatures) base.push("--no-default-features");
    for (const [edges, into] of [
      ["normal,no-proc-macro", linked],
      ["normal,build", all],
    ]) {
      const tree = await command("cargo", [...base, "-e", edges], crateDirectory);
      if (tree.error !== undefined) return {error: tree.error};
      for (const [key, crate] of parseCargoTree(tree.stdout)) into.set(key, crate);
    }
  }
  const crates = [...all].map(([key, crate]) => ({...crate, use: linked.has(key) ? "linked" : "build"}));
  return {crates: crates.sort((left, right) => left.name.localeCompare(right.name))};
}

/** Differences between the recorded crate inventory and cargo's resolution. */
export function compareCargo(recorded, resolved) {
  const errors = [];
  const key = (crate) => `${crate.name}@${crate.version}`;
  const byKey = new Map(resolved.map((crate) => [key(crate), crate]));
  const seen = new Set();
  for (const crate of recorded) {
    if (seen.has(key(crate))) errors.push({code: "CargoInventory", detail: `duplicate ${key(crate)}`});
    seen.add(key(crate));
    const actual = byKey.get(key(crate));
    if (actual === undefined) errors.push({code: "CargoInventory", detail: `not resolved: ${key(crate)}`});
    else if (actual.use !== crate.use) errors.push({code: "CargoInventory", detail: `${key(crate)} is ${actual.use}`});
    else if (actual.license !== crate.license) {
      errors.push({code: "CargoLicense", detail: `${key(crate)} declares ${actual.license}`});
    }
  }
  for (const crate of resolved) {
    if (!seen.has(key(crate))) errors.push({code: "CargoInventory", detail: `unrecorded ${crate.use}: ${key(crate)}`});
  }
  return errors;
}

async function packageFiles(directory) {
  const files = [];
  const queue = [""];
  for (let index = 0; index < queue.length; index++) {
    for (const entry of await readdir(join(directory, queue[index]), {withFileTypes: true})) {
      const path = queue[index] === "" ? entry.name : `${queue[index]}/${entry.name}`;
      if (entry.isDirectory()) queue.push(path);
      else files.push(path);
      if (files.length + queue.length > MAX_PACKAGE_FILES) throw Error("package file bound");
    }
  }
  return files.sort();
}

/** Returns every disagreement between `record` and the tree at `root`, and what it could verify. */
export async function checkProvenance(root, record, {requireFetched = false} = {}) {
  const errors = [];
  const report = (code, detail) => errors.push({code, detail});
  const summary = {cargo: "unfetched", direct: 0, npm: 0, transitive: {unfetched: 0, verified: 0}};
  const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const zon = parseZon(await readFile(join(root, "build.zig.zon"), "utf8"));

  if (packageJson.name !== record.package.name || packageJson.license !== record.package.license) {
    report("PackageIdentity", `${packageJson.name} ${packageJson.license}`);
  }
  const licenseFile = (await readdir(root)).find((name) => /^licen[cs]e(?:\..*)?$/i.test(name)) ?? null;
  if (licenseFile !== record.package.licenseFile) report("PackageLicenseFile", String(licenseFile));

  if (zon.minimum_zig_version !== record.zig.toolchain) report("ZigToolchain", zon.minimum_zig_version);
  const workflows = new Map();
  for (const name of ["CI.yml", ...record.install.platform.workflows.map((path) => path.split("/").at(-1))]) {
    const source = await readFile(join(root, ".github/workflows", name), "utf8");
    workflows.set(name, source);
    for (const [, version] of source.matchAll(/ZIG_VERSION: "([^"]+)"/g)) {
      if (version !== record.zig.toolchain) report("WorkflowZigToolchain", `${name}: ${version}`);
    }
  }

  if (!isDeepStrictEqual(pins(zon.dependencies), recordPins(record.zig.dependencies))) {
    report("ZigDirectPins", JSON.stringify(pins(zon.dependencies)));
  }
  summary.direct = record.zig.dependencies.length;
  const linked = linkedDependencies(zon);
  const buildImports = new Set(
    [...(await readFile(join(root, "build.zig"), "utf8")).matchAll(/@import\("([^"]+)"\)/g)].map((match) => match[1])
  );
  for (const dependency of record.zig.dependencies) {
    const use = linked.has(dependency.name) ? "addon" : buildImports.has(dependency.name) ? "build" : "development";
    if (dependency.use !== use) report("ZigDependencyUse", `${dependency.name}: ${use}`);
  }

  const queue = record.zig.dependencies.map((entry) => ({entry, path: entry.name}));
  for (let index = 0; index < queue.length; index++) {
    if (index >= MAX_ZIG_PACKAGES) throw Error("Zig package bound");
    const {entry, path} = queue[index];
    const directory = join(root, "zig-pkg", entry.hash);
    if (!(await exists(directory))) {
      summary.transitive.unfetched++;
      if (requireFetched) report("ZigPackageUnfetched", path);
      continue;
    }
    const manifest = await readOptional(join(directory, "build.zig.zon"));
    const children = manifest === null ? [] : pins(parseZon(manifest).dependencies);
    if (!isDeepStrictEqual(children, recordPins(entry.dependencies ?? []))) {
      report("ZigTransitivePins", `${path}: ${JSON.stringify(children)}`);
    }
    // A package recorded as build input only must hold no sources beyond the files reviewed as such.
    if (entry.files !== undefined && !isDeepStrictEqual(await packageFiles(directory), entry.files)) {
      report("ZigPackageFiles", path);
    }
    summary.transitive.verified++;
    for (const child of entry.dependencies ?? []) queue.push({entry: child, path: `${path}/${child.name}`});
  }

  const crate = cargoCrate(record);
  if (crate === undefined) report("CargoCrateSource", record.cargo.crate);
  const crateDirectory = crate === undefined ? null : join(root, "zig-pkg", crate.hash);
  const lockfile = crateDirectory === null ? null : await readOptional(join(crateDirectory, "Cargo.lock"));
  if (lockfile !== null) {
    const lockfileSha256 = createHash("sha256").update(lockfile).digest("hex");
    if (lockfileSha256 !== record.cargo.lockfileSha256) report("CargoLockfile", lockfileSha256);
    const resolved = await resolveCargo(crateDirectory, record);
    if (resolved.error !== undefined) {
      summary.cargo = "unresolved";
      if (requireFetched) report("CargoResolution", resolved.error);
    } else {
      summary.cargo = "resolved";
      errors.push(...compareCargo(record.cargo.crates, resolved.crates));
    }
    const manifest = await readFile(join(crateDirectory, "Cargo.toml"), "utf8");
    const packageSection = manifest.slice(manifest.indexOf("[package]"));
    const field = (key) => new RegExp(`^${key} = "([^"]+)"$`, "m").exec(packageSection)?.[1];
    const rootCrate = record.cargo.crates[0];
    if (field("name") !== rootCrate.name || field("version") !== rootCrate.version) {
      report("CargoRootCrate", `${field("name")}@${field("version")}`);
    }
    const buildScript = await readFile(join(root, "zig-pkg", crate.parent.hash, "build.zig"), "utf8");
    const flags = [...buildScript.matchAll(/"(--[a-z-]+)"/g)].map((match) => match[1]);
    const features = /"--features",\s*"([^"]*)"/.exec(buildScript)?.[1].split(",") ?? [];
    if (!isDeepStrictEqual(features, record.cargo.features)) report("CargoFeatures", features.join(","));
    if (flags.includes("--no-default-features") === record.cargo.defaultFeatures) report("CargoDefaultFeatures", "");
    if (flags.includes("--locked") !== record.cargo.locked) report("CargoLocked", String(!record.cargo.locked));
  } else if (requireFetched) report("CargoLockfileUnfetched", record.cargo.crate);

  const runtime = Object.fromEntries(record.npm.runtime.map(({name, version}) => [name, version]));
  if (!isDeepStrictEqual(packageJson.dependencies ?? {}, runtime)) {
    report("NpmRuntimePins", JSON.stringify(packageJson.dependencies));
  }
  const pnpmLock = await readFile(join(root, "pnpm-lock.yaml"), "utf8");
  for (const dependency of record.npm.runtime) {
    const entry = `\n  '${dependency.name}@${dependency.version}':\n    resolution: {integrity: ${dependency.integrity}}`;
    if (!pnpmLock.includes(entry)) report("NpmIntegrity", `${dependency.name}@${dependency.version}`);
    const installed = await readOptional(join(root, "node_modules", dependency.name, "package.json"));
    if (installed !== null) {
      const {license, version} = JSON.parse(installed);
      if (license !== dependency.license || version !== dependency.version) {
        report("NpmInstalled", `${dependency.name}@${version} ${license}`);
      }
    }
    summary.npm++;
  }

  if (!isDeepStrictEqual(packageJson.files, record.install.files)) {
    report("PackageFiles", JSON.stringify(packageJson.files));
  }
  if (!isDeepStrictEqual(packageJson.zapi?.targets, record.install.platform.targets)) {
    report("PlatformTargets", JSON.stringify(packageJson.zapi?.targets));
  }
  if (EMBEDDED_ADDON_PATH !== record.install.embedded.addon) report("EmbeddedAddonPath", EMBEDDED_ADDON_PATH);
  for (const path of record.install.platform.workflows) {
    const source = workflows.get(path.split("/").at(-1));
    for (const step of record.install.platform.steps) {
      if (!source.includes(step)) report("ReleaseStep", `${path}: ${step}`);
    }
    if (!source.includes(`runs-on: ${record.install.platform.runner}`)) report("ReleaseRunner", path);
  }
  return {errors, summary};
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const flags = process.argv.slice(2);
  if (flags.some((flag) => flag !== "--require-fetched"))
    throw Error("usage: lodestar_package_provenance.mjs [--require-fetched]");
  const root = fileURLToPath(new URL("../", import.meta.url));
  const record = JSON.parse(await readFile(join(root, RECORD), "utf8"));
  const result = await checkProvenance(root, record, {requireFetched: flags.includes("--require-fetched")});
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.errors.length !== 0) process.exitCode = 1;
}
