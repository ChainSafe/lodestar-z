import {randomBytes} from "node:crypto";
import {lstat, mkdtemp, readFile, rm, stat} from "node:fs/promises";
import {tmpdir} from "node:os";
import * as nodePathNamespace from "node:path";
import {basename, dirname, isAbsolute, join, relative, resolve} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import vm from "node:vm";
import * as zapiNamespace from "@chainsafe/zapi";
import {
  MAX_ARCHIVE_ENTRIES,
  MAX_FILES,
  MAX_SOURCE_BYTES,
  collectFiles,
  fail,
  failCommand,
  readDirectoryEntries,
  readJson,
  sha256,
} from "./lodestar_package_io.mjs";

export const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
export const MAX_PACKAGE_EXPORTS = 64;
export const MAX_WRAPPER_BYTES = 1024 * 1024;
const MAX_MODULES = 64;
const MAX_MODULE_SOURCE_BYTES = 16 * 1024 * 1024;
const MAX_IMPORT_EDGES = 256;
const TOOL_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const HASH_PATTERN = /^[0-9a-f]{64}$/;
export const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
export const EXPECTED_PACKAGE_EXPORTS = [
  ".",
  "./bls-verifier",
  "./blst",
  "./metrics",
  "./network",
  "./pubkeys",
  "./shuffle",
  "./state-transition",
];
export const EXPECTED_NETWORK_EXPORTS = ["createNativeNetwork"];

export const EMBEDDED_ADDON_PATH = "zig-out/lib/bindings.node";
export const PLATFORM_ADDON_FILE = "bindings.node";
const PLATFORM_ADDON_PATTERN = /^artifacts\/([a-z0-9_-]+)\/bindings\.node$/;

/**
 * Where a build put the addon selects the package layout: a local zig-out build embeds it in the package, and a zapi
 * artifact for one target ships in that target's platform package, as the release workflow publishes it.
 */
export function addonLayout(addonPath) {
  if (addonPath === EMBEDDED_ADDON_PATH) return {layout: "embedded", target: null};
  const target = PLATFORM_ADDON_PATTERN.exec(addonPath)?.[1];
  if (target === undefined) fail("InvalidBuildRecord", `unsupported addon path ${addonPath}`);
  return {layout: "platform", target};
}

export function validateBuildRecord(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) fail("InvalidBuildRecord");
  if (!COMMIT_PATTERN.test(record.sourceCommit)) fail("InvalidBuildRecord", "sourceCommit");
  if (record.preset !== "mainnet" && record.preset !== "minimal") fail("InvalidBuildRecord", "preset");
  if (record.optimize !== "ReleaseSafe") fail("InvalidBuildRecord", "optimize");
  if (record.instrumented !== false) fail("InvalidBuildRecord", "instrumented");
  if (typeof record.targetPolicy !== "string" || record.targetPolicy === "") fail("InvalidBuildRecord", "targetPolicy");
  if (typeof record.buildCommand !== "string" || record.buildCommand === "") fail("InvalidBuildRecord", "buildCommand");
  if (!record.toolchain || typeof record.toolchain !== "object" || Array.isArray(record.toolchain)) {
    fail("InvalidBuildRecord", "toolchain");
  }
  for (const field of ["zig", "node", "pnpm", "arch"]) {
    if (typeof record.toolchain[field] !== "string" || record.toolchain[field] === "") {
      fail("InvalidBuildRecord", `toolchain.${field}`);
    }
  }
  if (!Array.isArray(record.files) || record.files.length > MAX_FILES) fail("InvalidBuildRecord", "files");
  const paths = new Set();
  for (const file of record.files) {
    if (!file || typeof file.path !== "string" || !Number.isSafeInteger(file.bytes) || file.bytes < 0) {
      fail("InvalidBuildRecord", "file entry");
    }
    if (!HASH_PATTERN.test(file.sha256)) fail("MalformedHash", file.path);
    if (paths.has(file.path)) fail("DuplicateBuildFile", file.path);
    paths.add(file.path);
  }
  const addons = record.files.filter((file) => file.path.endsWith(".node"));
  if (addons.length !== 1) fail("InvalidBuildRecord", "exact addon entry required");
  addonLayout(addons[0].path);
  return addons[0];
}

export function validateArchivePath(path) {
  if (isAbsolute(path) || path.includes("\\") || path.split("/").some((part) => part === ".." || part === "")) {
    fail("UnsafeArchivePath", path);
  }
  if (!path.startsWith("package/")) fail("UnexpectedArchiveRoot", path);
  if (!/^[A-Za-z0-9@_./-]+$/.test(path)) fail("UnsupportedArchivePath", path);
}

function parseVerboseEntry(line) {
  const fields = line.trim().split(/\s+/);
  if (fields.length < 6 || !fields[1].includes("/") || !/^\d+$/.test(fields[2])) fail("InvalidArchiveListing", line);
  const bytes = Number(fields[2]);
  if (!Number.isSafeInteger(bytes)) fail("InvalidArchiveListing", line);
  return {bytes, type: fields[0][0]};
}

export function assertNetworkExports(names) {
  if (names.length > MAX_PACKAGE_EXPORTS) fail("PackageExportBound");
  if (names.some((name) => name.toLowerCase().includes("test"))) fail("NetworkTestExport", names.join(","));
  if (JSON.stringify(names) !== JSON.stringify(EXPECTED_NETWORK_EXPORTS)) {
    fail("UnexpectedNetworkExports", names.join(","));
  }
  return names;
}

function namespaceNames(namespace) {
  const names = Reflect.ownKeys(namespace)
    .filter((name) => typeof name === "string")
    .sort();
  if (names.length > MAX_PACKAGE_EXPORTS) fail("PackageExportBound");
  return names;
}

async function trustedExternalNamespaces(packageRoot) {
  const toolPackage = await readJson(join(TOOL_ROOT, "package.json"), "tool package.json");
  const zapiPin = toolPackage.dependencies?.["@chainsafe/zapi"];
  if (typeof zapiPin !== "string" || !/^\d+\.\d+\.\d+$/.test(zapiPin)) fail("UnsupportedToolZapiPin");
  const zapiEntry = fileURLToPath(import.meta.resolve("@chainsafe/zapi"));
  const zapiPackage = await readJson(resolve(dirname(zapiEntry), "..", "package.json"), "tool zapi package.json");
  if (zapiPackage.name !== "@chainsafe/zapi" || zapiPackage.version !== zapiPin) {
    fail("ToolZapiVersionMismatch", JSON.stringify({actual: zapiPackage.version, expected: zapiPin}));
  }
  const archivePackage = await readJson(join(packageRoot, "package.json"), "archived package.json");
  return new Map([
    [
      "@chainsafe/zapi",
      {
        assertArchiveDependency() {
          if (archivePackage.dependencies?.["@chainsafe/zapi"] !== zapiPin) {
            fail(
              "ArchiveZapiVersionMismatch",
              JSON.stringify({actual: archivePackage.dependencies?.["@chainsafe/zapi"] ?? null, expected: zapiPin})
            );
          }
        },
        exports: namespaceNames(zapiNamespace),
        identity: {kind: "pinned-tool-dependency", specifier: "@chainsafe/zapi", version: zapiPin},
      },
    ],
    [
      "node:path",
      {
        assertArchiveDependency() {},
        exports: namespaceNames(nodePathNamespace),
        identity: {kind: "trusted-node-builtin", node: process.version, specifier: "node:path"},
      },
    ],
  ]);
}

async function analyzeModuleExports(packageRoot, entryPath) {
  if (typeof vm.SourceTextModule !== "function" || typeof vm.SyntheticModule !== "function") {
    fail("UnsupportedVmModuleApi");
  }
  const supportedExternalNamespaces = await trustedExternalNamespaces(packageRoot);
  const modules = new Map();
  const dependencies = new Map();
  const usedExternalNamespaces = new Map();
  const queue = [];
  let importEdges = 0;
  let sourceBytes = 0;

  async function admitLocal(path) {
    const normalized = resolve(path);
    const inside = relative(packageRoot, normalized);
    if (inside.startsWith("..") || isAbsolute(inside)) fail("ArchiveModuleOutsidePackage", normalized);
    const existing = modules.get(normalized);
    if (existing !== undefined) return existing;
    if (modules.size >= MAX_MODULES) fail("ArchiveModuleBound");
    const info = await stat(normalized);
    if (!info.isFile() || info.size > MAX_WRAPPER_BYTES) fail("NetworkWrapperByteBound", inside);
    if (info.size > MAX_MODULE_SOURCE_BYTES - sourceBytes) fail("ArchiveModuleSourceBound");
    sourceBytes += info.size;
    const module = new vm.SourceTextModule(await readFile(normalized, "utf8"), {
      identifier: pathToFileURL(normalized).href,
    });
    modules.set(normalized, module);
    queue.push({module, path: normalized});
    return module;
  }

  const root = await admitLocal(join(packageRoot, entryPath));
  for (let index = 0; index < queue.length; index++) {
    const current = queue[index];
    const requested = [];
    for (const request of current.module.moduleRequests) {
      if (importEdges >= MAX_IMPORT_EDGES) fail("ArchiveModuleImportBound");
      importEdges += 1;
      if (request.specifier.startsWith("./") || request.specifier.startsWith("../")) {
        requested.push(await admitLocal(fileURLToPath(new URL(request.specifier, current.module.identifier))));
        continue;
      }
      const externalNamespace = supportedExternalNamespaces.get(request.specifier);
      if (externalNamespace === undefined) fail("UnsupportedArchiveExternalImport", request.specifier);
      externalNamespace.assertArchiveDependency();
      usedExternalNamespaces.set(request.specifier, externalNamespace);
      let external = modules.get(request.specifier);
      if (external === undefined) {
        external = new vm.SyntheticModule(externalNamespace.exports, () => {}, {
          identifier: `external:${request.specifier}`,
        });
        modules.set(request.specifier, external);
      }
      requested.push(external);
    }
    dependencies.set(current.module, requested);
  }
  for (const {module} of queue) module.linkRequests(dependencies.get(module));
  root.instantiate();
  return {
    exports: namespaceNames(root.namespace),
    externalNamespaces: [...usedExternalNamespaces.values()]
      .map(({exports, identity}) => ({...identity, exports}))
      .sort((left, right) => left.specifier.localeCompare(right.specifier)),
  };
}

async function inspectNetworkExports(packageRoot, packageJson, runCommand) {
  const networkPath = packageJson.exports?.["./network"]?.import;
  if (typeof networkPath !== "string" || !networkPath.startsWith("./")) fail("InvalidNetworkExport");
  const command = await runCommand(
    process.execPath,
    ["--experimental-vm-modules", fileURLToPath(import.meta.url), "exports", packageRoot, networkPath.slice(2)],
    packageRoot,
    {allowFailure: true}
  );
  if (command.exitCode !== 0) failCommand("ArchiveExportInspectionFailed", command);
  let result;
  try {
    result = JSON.parse(command.stdout);
  } catch (error) {
    fail("InvalidArchiveExportOutput", error.message);
  }
  if (
    !result ||
    !Array.isArray(result.exports) ||
    result.exports.some((name) => typeof name !== "string") ||
    !Array.isArray(result.externalNamespaces)
  ) {
    fail("InvalidArchiveExportOutput");
  }
  return {...result, exports: assertNetworkExports(result.exports)};
}

export async function inspectNativeExports(addonPath, runCommand) {
  const command = await runCommand(
    process.execPath,
    [fileURLToPath(new URL("./check_network_addon.mjs", import.meta.url)), addonPath],
    dirname(addonPath),
    {allowFailure: true}
  );
  if (command.exitCode !== 0) failCommand("NativeAddonInspectionFailed", command);
  return JSON.parse(command.stdout);
}

async function listArchive(archive, runCommand, maxSourceBytes) {
  const info = await stat(archive);
  if (!info.isFile()) fail("InvalidArchive", "not a regular file");
  if (info.size > MAX_ARCHIVE_BYTES) fail("ArchiveByteBound", `more than ${MAX_ARCHIVE_BYTES} bytes`);
  const listed = await runCommand("tar", ["-tzf", archive], dirname(archive));
  const paths = listed.stdout.split("\n").filter(Boolean);
  if (paths.length > MAX_ARCHIVE_ENTRIES) fail("ArchiveEntryBound", `more than ${MAX_ARCHIVE_ENTRIES} entries`);
  const verbose = await runCommand("tar", ["-tvzf", archive], dirname(archive));
  const details = verbose.stdout.split("\n").filter(Boolean).map(parseVerboseEntry);
  if (details.length !== paths.length) fail("ArchiveListMismatch");
  const seen = new Set();
  const regularPaths = [];
  let regularBytes = 0;
  for (let index = 0; index < paths.length; index++) {
    const path = paths[index];
    const normalized = path.endsWith("/") ? path.slice(0, -1) : path;
    validateArchivePath(normalized);
    if (seen.has(normalized)) fail("DuplicateArchivePath", normalized);
    seen.add(normalized);
    const detail = details[index];
    if (detail.type !== "-" && detail.type !== "d") fail("ArchiveLinkOrSpecialFile", detail.type);
    if (detail.type === "-") {
      if (regularPaths.length >= MAX_FILES) fail("PackageFileBound", `more than ${MAX_FILES} regular files`);
      if (detail.bytes > maxSourceBytes - regularBytes) {
        fail("PackageSourceByteBound", `more than ${maxSourceBytes} bytes`);
      }
      regularBytes += detail.bytes;
      regularPaths.push(path);
    }
  }
  return regularPaths;
}

/** Lists and extracts `archive`, requiring exactly `nativeLibraries` among its files, then runs `inspect` on it. */
async function withExtractedArchive(archive, nativeLibraries, runCommand, maxSourceBytes, inspect) {
  const regularPaths = await listArchive(archive, runCommand, maxSourceBytes);
  const actualLibraries = regularPaths.filter((path) => /\.(?:node|so|dll|dylib|a)$/i.test(path));
  if (!isDeepStrictEqual(actualLibraries, nativeLibraries)) fail("UnexpectedNativeLibrary", actualLibraries.join(","));
  const extractDir = await mkdtemp(join(tmpdir(), `lodestar-package-extract-${randomBytes(4).toString("hex")}-`));
  try {
    await runCommand(
      "tar",
      ["-xzf", archive, "-C", extractDir, "--no-same-owner", "--no-same-permissions", "--", ...regularPaths],
      dirname(archive)
    );
    const packageRoot = join(extractDir, "package");
    return await inspect(packageRoot, await collectFiles(packageRoot, {maxBytes: maxSourceBytes}));
  } finally {
    await rm(extractDir, {force: true, recursive: true});
  }
}

function assertAddon(files, path, expectedAddon) {
  const addon = files.find((file) => file.path === path);
  if (!addon || addon.bytes !== expectedAddon.bytes || addon.sha256 !== expectedAddon.sha256) {
    fail("AddonMismatch", JSON.stringify({actual: addon ?? null, expected: expectedAddon}));
  }
  return addon;
}

/** Inspects the main package archive. The addon is embedded unless `expectedAddon` is null for the platform layout. */
export async function inspectArchive(archive, expectedAddon, runCommand, {maxSourceBytes = MAX_SOURCE_BYTES} = {}) {
  const nativeLibraries = expectedAddon === null ? [] : [`package/${EMBEDDED_ADDON_PATH}`];
  return withExtractedArchive(archive, nativeLibraries, runCommand, maxSourceBytes, async (packageRoot, files) => {
    const packageJson = await readJson(join(packageRoot, "package.json"), "archived package.json");
    assertPackageExports(packageJson);
    const network = await inspectNetworkExports(packageRoot, packageJson, runCommand);
    let native = null;
    if (expectedAddon !== null) {
      assertAddon(files, EMBEDDED_ADDON_PATH, expectedAddon);
      native = await inspectNativeExports(join(packageRoot, EMBEDDED_ADDON_PATH), runCommand);
    }
    return {
      externalNamespaces: network.externalNamespaces,
      files,
      native,
      networkExports: network.exports,
      packageJson,
    };
  });
}

/** Inspects the archive of the platform package zapi prepublish generates for `target`. */
export async function inspectPlatformArchive(archive, expectedAddon, target, mainPackage, runCommand) {
  const nativeLibraries = [`package/${PLATFORM_ADDON_FILE}`];
  return withExtractedArchive(archive, nativeLibraries, runCommand, MAX_SOURCE_BYTES, async (packageRoot, files) => {
    const packageJson = await readJson(join(packageRoot, "package.json"), "archived platform package.json");
    const expectedName = platformPackageName(mainPackage.name, target);
    if (
      packageJson.name !== expectedName ||
      packageJson.version !== mainPackage.version ||
      packageJson.main !== PLATFORM_ADDON_FILE ||
      !isDeepStrictEqual(packageJson.files, [PLATFORM_ADDON_FILE])
    ) {
      fail("PlatformPackageMismatch", JSON.stringify(packageJson));
    }
    const paths = files.map((file) => file.path).sort();
    if (!isDeepStrictEqual(paths, ["README.md", PLATFORM_ADDON_FILE, "package.json"].sort())) {
      fail("PlatformPackageInventory", paths.join(","));
    }
    assertAddon(files, PLATFORM_ADDON_FILE, expectedAddon);
    const native = await inspectNativeExports(join(packageRoot, PLATFORM_ADDON_FILE), runCommand);
    return {files, name: expectedName, native, packageJson, target};
  });
}

export function platformPackageName(name, target) {
  return `${name}-${target}`;
}

/**
 * pnpm pack drops package-manager fields and lifecycle scripts from the embedded layout's package.json. For the platform
 * layout, zapi prepublish adds one optional dependency per target and npm pack, which the release publishes with, keeps
 * the rest.
 */
export function assertPackedPackageJson(source, packed, layout = "embedded") {
  let expected;
  if (layout === "platform") {
    const targets = Array.isArray(source.zapi?.targets) ? source.zapi.targets : [];
    expected = {
      ...source,
      optionalDependencies: Object.fromEntries(
        targets.map((target) => [platformPackageName(source.name, target), source.version])
      ),
    };
  } else {
    expected = Object.fromEntries(Object.entries(source).filter(([key]) => !["packageManager", "pnpm"].includes(key)));
    if (expected.scripts) {
      const omitted = ["prepublishOnly", "prepack", "prepare", "postpack", "publish", "postpublish"];
      expected.scripts = Object.fromEntries(Object.entries(expected.scripts).filter(([key]) => !omitted.includes(key)));
    }
  }
  if (!isDeepStrictEqual(expected, packed)) fail("PackedPackageJsonMismatch");
}

export async function verifyArchiveSources(nativeDir, archivedFiles, packageJson, layout) {
  assertPackedPackageJson(await readJson(join(nativeDir, "package.json"), "source package.json"), packageJson, layout);
  const before = [];
  for (const file of archivedFiles) {
    if (file.path === "package.json") continue;
    const source = join(nativeDir, file.path);
    const sourceInfo = await lstat(source).catch((error) => (error.code === "ENOENT" ? null : Promise.reject(error)));
    if (sourceInfo === null || !sourceInfo.isFile() || sourceInfo.isSymbolicLink()) {
      fail("ArchiveSourceMissing", file.path);
    }
    const sourceFile = {bytes: sourceInfo.size, path: file.path, sha256: await sha256(source)};
    if (sourceFile.bytes !== file.bytes || sourceFile.sha256 !== file.sha256) fail("ArchiveSourceMismatch", file.path);
    before.push(sourceFile);
  }
  return before;
}

export async function collectPackSources(nativeDir, packageJson) {
  if (!Array.isArray(packageJson.files) || packageJson.files.length > MAX_FILES) fail("InvalidPackageFiles");
  const selected = new Set(["package.json"]);
  for (const entry of packageJson.files) {
    if (typeof entry !== "string") fail("InvalidPackageFiles");
    const normalized = entry.replace(/\/+$/, "");
    if (normalized === "" || isAbsolute(normalized) || normalized.split("/").includes("..")) {
      fail("InvalidPackageFiles", entry);
    }
    const path = join(nativeDir, normalized);
    const info = await lstat(path);
    if (info.isSymbolicLink()) fail("PackageLink", normalized);
    if (info.isFile()) selected.add(normalized);
    else if (info.isDirectory()) {
      for (const file of await collectFiles(path)) selected.add(`${normalized}/${file.path}`);
    } else fail("PackageFileType", normalized);
  }
  for (const entry of await readDirectoryEntries(nativeDir, MAX_ARCHIVE_ENTRIES, "PackageDirectoryEntryBound")) {
    if (entry.isFile() && /^(?:readme|license|licence|changelog)(?:\..*)?$/i.test(entry.name)) selected.add(entry.name);
  }
  const files = [];
  let bytes = 0;
  for (const path of [...selected].sort()) {
    if (files.length >= MAX_FILES) fail("PackageFileBound", `more than ${MAX_FILES} regular files`);
    const info = await stat(join(nativeDir, path));
    if (info.size > MAX_SOURCE_BYTES - bytes) fail("PackageSourceByteBound", `more than ${MAX_SOURCE_BYTES} bytes`);
    bytes += info.size;
    files.push({bytes: info.size, path, sha256: await sha256(join(nativeDir, path))});
  }
  return files;
}

export function assertPackageExports(packageJson) {
  if (!packageJson.exports || typeof packageJson.exports !== "object" || Array.isArray(packageJson.exports)) {
    fail("InvalidPackageExports");
  }
  const subpaths = Object.keys(packageJson.exports).sort();
  if (subpaths.length > MAX_PACKAGE_EXPORTS) fail("PackageExportBound");
  if (JSON.stringify(subpaths) !== JSON.stringify(EXPECTED_PACKAGE_EXPORTS)) {
    fail("UnexpectedPackageExports", subpaths.join(","));
  }
}

function validateManifestArchive(archive, label) {
  if (
    !archive ||
    typeof archive.file !== "string" ||
    basename(archive.file) !== archive.file ||
    !Number.isSafeInteger(archive.bytes) ||
    archive.bytes < 0 ||
    archive.bytes > MAX_ARCHIVE_BYTES ||
    !HASH_PATTERN.test(archive.sha256)
  ) {
    fail("InvalidPackageManifest", label);
  }
}

function validateManifestFiles(files, required) {
  if (!Array.isArray(files) || files.length > MAX_FILES) fail("InvalidPackageManifest", "files");
  const paths = new Set();
  let bytes = 0;
  for (const file of files) {
    if (
      !file ||
      typeof file.path !== "string" ||
      !Number.isSafeInteger(file.bytes) ||
      file.bytes < 0 ||
      !HASH_PATTERN.test(file.sha256)
    ) {
      fail("InvalidPackageManifest", "file entry");
    }
    validateArchivePath(`package/${file.path}`);
    if (paths.has(file.path)) fail("DuplicatePackageFile", file.path);
    paths.add(file.path);
    if (file.bytes > MAX_SOURCE_BYTES - bytes) fail("PackageSourceByteBound", `more than ${MAX_SOURCE_BYTES} bytes`);
    bytes += file.bytes;
  }
  for (const path of required) if (!paths.has(path)) fail("InvalidPackageManifest", `missing ${path}`);
}

export function validatePackageManifest(manifest) {
  if (!manifest || manifest.schemaVersion !== 2) fail("InvalidPackageManifest");
  if (manifest.package?.name !== "@chainsafe/lodestar-z" || typeof manifest.package.version !== "string") {
    fail("InvalidPackageManifest", "package");
  }
  validateManifestArchive(manifest.archive, "archive");
  if (
    !manifest.addon ||
    typeof manifest.addon.path !== "string" ||
    !Number.isSafeInteger(manifest.addon.bytes) ||
    manifest.addon.bytes < 0 ||
    !HASH_PATTERN.test(manifest.addon.sha256)
  ) {
    fail("InvalidPackageManifest", "addon");
  }
  validateBuildRecord({...manifest.build, files: [manifest.addon]});
  const {layout, target} = addonLayout(manifest.addon.path);
  if (manifest.layout !== layout) fail("InvalidPackageManifest", "layout");
  if (layout === "embedded") {
    validateManifestFiles(manifest.files, ["package.json", EMBEDDED_ADDON_PATH]);
    if (manifest.platform !== null) fail("InvalidPackageManifest", "platform");
    return;
  }
  validateManifestFiles(manifest.files, ["package.json"]);
  if (manifest.files.some((file) => file.path.endsWith(".node"))) fail("InvalidPackageManifest", "embedded addon");
  const platform = manifest.platform;
  if (platform?.target !== target || platform.name !== platformPackageName(manifest.package.name, target)) {
    fail("InvalidPackageManifest", "platform");
  }
  validateManifestArchive(platform.archive, "platform archive");
  if (platform.archive.file === manifest.archive.file) fail("InvalidPackageManifest", "platform archive");
  validateManifestFiles(platform.files, ["package.json", PLATFORM_ADDON_FILE]);
}

async function verifyArchiveFile(manifestPath, expected) {
  const archive = join(dirname(manifestPath), expected.file);
  const archiveInfo = await stat(archive);
  const archiveHash = await sha256(archive);
  if (archiveInfo.size !== expected.bytes || archiveHash !== expected.sha256) {
    fail("ArchiveMismatch", JSON.stringify({actual: {bytes: archiveInfo.size, sha256: archiveHash}, expected}));
  }
  return archive;
}

export async function verifyManifestArchive(manifestPath, runCommand) {
  const manifest = await readJson(manifestPath, "package manifest");
  validatePackageManifest(manifest);
  const archive = await verifyArchiveFile(manifestPath, manifest.archive);
  const embedded = manifest.layout === "embedded";
  const inspected = await inspectArchive(archive, embedded ? manifest.addon : null, runCommand);
  if (!isDeepStrictEqual(manifest.files, inspected.files)) fail("ArchiveInventoryMismatch");
  if (
    inspected.packageJson.name !== "@chainsafe/lodestar-z" ||
    inspected.packageJson.version !== manifest.package.version
  ) {
    fail("ArchivePackageMismatch");
  }
  if (JSON.stringify(manifest.ordinaryExports?.network) !== JSON.stringify(inspected.networkExports)) {
    fail("ArchiveNetworkExportsMismatch");
  }
  let platformArchive = null;
  if (!embedded) {
    platformArchive = await verifyArchiveFile(manifestPath, manifest.platform.archive);
    const platform = await inspectPlatformArchive(
      platformArchive,
      manifest.addon,
      manifest.platform.target,
      inspected.packageJson,
      runCommand
    );
    if (!isDeepStrictEqual(manifest.platform.files, platform.files)) fail("PlatformArchiveInventoryMismatch");
    inspected.platform = platform;
  }
  return {archive, inspected, manifest, manifestSha256: await sha256(manifestPath), platformArchive};
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [command, packageRoot, entryPath] = process.argv.slice(2);
  if (command !== "exports" || packageRoot === undefined || entryPath === undefined)
    fail("InvalidArchiveHelperCommand");
  process.stdout.write(`${JSON.stringify(await analyzeModuleExports(packageRoot, entryPath))}\n`);
}
