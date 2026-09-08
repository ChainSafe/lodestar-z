import {createHash, randomBytes} from "node:crypto";
import {createReadStream} from "node:fs";
import {
  access,
  copyFile,
  lstat,
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
import {basename, dirname, isAbsolute, join, relative, resolve, sep} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {runBoundedCommand} from "./bounded_child.mjs";

const MAX_FILES = 256;
const MAX_SOURCE_BYTES = 512 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 20 * 60 * 1000;
const MAX_ARCHIVE_ENTRIES = 512;
const MAX_PACKAGE_EXPORTS = 64;
const MAX_RESOLUTION_RECORDS = 16 * 1024;
const MAX_GRAPH_NODES = 8192;
const MAX_GRAPH_EDGES = 64 * 1024;
const MAX_WRAPPER_BYTES = 1024 * 1024;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const EXPECTED_PACKAGE_EXPORTS = [
  ".",
  "./bls-verifier",
  "./blst",
  "./metrics",
  "./network",
  "./pubkeys",
  "./shuffle",
  "./state-transition",
];
const EXPECTED_NETWORK_EXPORTS = ["createNativeNetworkApplicationRuntime", "createNativeNetworkRuntime"];
const SOURCE_PATHS = [
  "src",
  "bindings/napi",
  "bindings/src",
  "build.zig",
  "build.zig.zon",
  "package.json",
  "pnpm-lock.yaml",
];

function fail(code, detail = "") {
  throw new Error(detail === "" ? code : `${code}: ${detail}`);
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

async function readJson(path, label) {
  const info = await stat(path);
  if (!info.isFile()) fail("InvalidPath", `${label} is not a regular file`);
  if (info.size > MAX_OUTPUT_BYTES) fail("CommandOutputBound", `${label} exceeds ${MAX_OUTPUT_BYTES} bytes`);
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    fail("InvalidJson", `${label}: ${error.message}`);
  }
}

async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function runCommand(program, args, cwd, {allowFailure = false} = {}) {
  return runBoundedCommand(program, args, cwd, {
    allowFailure,
    maxOutputBytes: MAX_OUTPUT_BYTES,
    timeoutMs: COMMAND_TIMEOUT_MS,
  });
}

function parseOptions(argv) {
  const command = argv[0];
  const allowed = {
    install: new Set(["--host-dir", "--manifest", "--evidence-dir"]),
    pack: new Set(["--native-dir", "--out", "--build-record"]),
    verify: new Set(["--host-dir", "--manifest"]),
  }[command];
  if (allowed === undefined) fail("InvalidCommand", command ?? "missing command");
  const options = {};
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(key)) fail("UnknownOption", key ?? "missing option");
    if (options[key] !== undefined) fail("DuplicateOption", key);
    if (value === undefined || value.startsWith("--")) fail("MissingOptionValue", key);
    options[key] = resolve(value);
  }
  for (const key of allowed) if (options[key] === undefined) fail("MissingOption", key);
  return {command, options};
}

function validateBuildRecord(record) {
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
  const addons = record.files.filter((file) => file.path === "zig-out/lib/bindings.node");
  if (addons.length !== 1) fail("InvalidBuildRecord", "exact addon entry required");
  return addons[0];
}

async function verifySource(nativeDir, sourceCommit) {
  const commit = await runCommand("git", ["cat-file", "-e", `${sourceCommit}^{commit}`], nativeDir, {
    allowFailure: true,
  });
  if (commit.exitCode !== 0) fail("UnknownSourceCommit", sourceCommit);
  const diff = await runCommand(
    "git",
    ["diff", "--no-ext-diff", "--quiet", sourceCommit, "--", ...SOURCE_PATHS],
    nativeDir,
    {
      allowFailure: true,
    }
  );
  if (diff.exitCode !== 0) fail("SourceDrift", `tracked build/package inputs differ from ${sourceCommit}`);
  const status = await runCommand(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all", "--", ...SOURCE_PATHS],
    nativeDir
  );
  if (status.stdout !== "") fail("SourceDrift", status.stdout.trim());
  const head = await runCommand("git", ["rev-parse", "HEAD"], nativeDir);
  const wholeStatus = await runCommand("git", ["status", "--porcelain=v1", "--untracked-files=all"], nativeDir);
  return {
    comparedPaths: SOURCE_PATHS,
    currentCheckoutDirty: wholeStatus.stdout !== "",
    currentCheckoutHead: head.stdout.trim(),
    sourceCommit,
    trackedDiff: false,
    untrackedInputs: [],
  };
}

async function collectFiles(root) {
  const directories = [root];
  const files = [];
  let bytes = 0;
  let visitedDirectories = 0;
  while (directories.length > 0) {
    const current = directories.pop();
    visitedDirectories += 1;
    if (visitedDirectories > MAX_ARCHIVE_ENTRIES) fail("PackageDirectoryBound");
    const entries = await readdir(current, {withFileTypes: true});
    for (const entry of entries) {
      if (current === root && entry.name === "node_modules") continue;
      const path = join(current, entry.name);
      if (entry.isSymbolicLink()) fail("PackageLink", relative(root, path));
      if (entry.isDirectory()) {
        directories.push(path);
        continue;
      }
      if (!entry.isFile()) fail("PackageFileType", relative(root, path));
      const info = await stat(path);
      files.push({bytes: info.size, path: relative(root, path).split(sep).join("/"), sha256: await sha256(path)});
      bytes += info.size;
      if (files.length > MAX_FILES) fail("PackageFileBound", `more than ${MAX_FILES} regular files`);
      if (bytes > MAX_SOURCE_BYTES) fail("PackageSourceByteBound", `more than ${MAX_SOURCE_BYTES} bytes`);
    }
  }
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function validateArchivePath(path) {
  if (isAbsolute(path) || path.includes("\\") || path.split("/").some((part) => part === ".." || part === "")) {
    fail("UnsafeArchivePath", path);
  }
  if (!path.startsWith("package/")) fail("UnexpectedArchiveRoot", path);
  if (!/^[A-Za-z0-9@_./-]+$/.test(path)) fail("UnsupportedArchivePath", path);
}

async function inspectArchive(archive, expectedAddon) {
  const info = await stat(archive);
  if (!info.isFile()) fail("InvalidArchive", "not a regular file");
  if (info.size > MAX_ARCHIVE_BYTES) fail("ArchiveByteBound", `more than ${MAX_ARCHIVE_BYTES} bytes`);
  const listed = await runCommand("tar", ["-tzf", archive], dirname(archive));
  const paths = listed.stdout.split("\n").filter(Boolean);
  if (paths.length > MAX_ARCHIVE_ENTRIES) fail("ArchiveEntryBound", `more than ${MAX_ARCHIVE_ENTRIES} entries`);
  const seen = new Set();
  for (const path of paths) {
    const normalized = path.endsWith("/") ? path.slice(0, -1) : path;
    validateArchivePath(normalized);
    if (seen.has(normalized)) fail("DuplicateArchivePath", normalized);
    seen.add(normalized);
  }
  const verbose = await runCommand("tar", ["-tvzf", archive], dirname(archive));
  const types = verbose.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => line[0]);
  if (types.length !== paths.length) fail("ArchiveListMismatch");
  for (const type of types) if (type !== "-" && type !== "d") fail("ArchiveLinkOrSpecialFile", type);
  const regularPaths = paths.filter((_, index) => types[index] === "-");
  if (regularPaths.length > MAX_FILES) fail("PackageFileBound", `more than ${MAX_FILES} regular files`);
  const nativeLibraries = regularPaths.filter((path) => /\.(?:node|so|dll|dylib|a)$/i.test(path));
  if (nativeLibraries.length !== 1 || nativeLibraries[0] !== "package/zig-out/lib/bindings.node") {
    fail("UnexpectedNativeLibrary", nativeLibraries.join(","));
  }
  const extractDir = await mkdtemp(join(tmpdir(), "lodestar-package-extract-"));
  try {
    await runCommand(
      "tar",
      ["-xzf", archive, "-C", extractDir, "--no-same-owner", "--no-same-permissions", "--", ...regularPaths],
      dirname(archive)
    );
    const packageRoot = join(extractDir, "package");
    const files = await collectFiles(packageRoot);
    const addon = files.find((file) => file.path === expectedAddon.path);
    if (!addon || addon.bytes !== expectedAddon.bytes || addon.sha256 !== expectedAddon.sha256) {
      fail("AddonMismatch", JSON.stringify({actual: addon ?? null, expected: expectedAddon}));
    }
    return {files, packageJson: await readJson(join(packageRoot, "package.json"), "archived package.json")};
  } finally {
    await rm(extractDir, {force: true, recursive: true});
  }
}

async function verifyArchiveSources(nativeDir, archivedFiles) {
  const before = [];
  for (const file of archivedFiles) {
    if (file.path === "package.json") continue;
    const source = join(nativeDir, file.path);
    const sourceInfo = await lstat(source).catch((error) => (error.code === "ENOENT" ? null : Promise.reject(error)));
    if (sourceInfo === null || !sourceInfo.isFile() || sourceInfo.isSymbolicLink())
      fail("ArchiveSourceMissing", file.path);
    const sourceFile = {bytes: sourceInfo.size, path: file.path, sha256: await sha256(source)};
    if (sourceFile.bytes !== file.bytes || sourceFile.sha256 !== file.sha256) {
      fail("ArchiveSourceMismatch", file.path);
    }
    before.push(sourceFile);
  }
  return before;
}

async function collectPackSources(nativeDir, packageJson) {
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
  for (const entry of await readdir(nativeDir, {withFileTypes: true})) {
    if (entry.isFile() && /^(?:readme|license|licence|changelog)(?:\..*)?$/i.test(entry.name)) selected.add(entry.name);
  }
  const files = [];
  let bytes = 0;
  for (const path of [...selected].sort()) {
    const info = await stat(join(nativeDir, path));
    const file = {bytes: info.size, path, sha256: await sha256(join(nativeDir, path))};
    files.push(file);
    bytes += file.bytes;
    if (files.length > MAX_FILES) fail("PackageFileBound", `more than ${MAX_FILES} regular files`);
    if (bytes > MAX_SOURCE_BYTES) fail("PackageSourceByteBound", `more than ${MAX_SOURCE_BYTES} bytes`);
  }
  return files;
}

function ordinaryNetworkExports(source) {
  const names = [];
  const pattern = /\bexport\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)/g;
  for (const match of source.matchAll(pattern)) {
    names.push(match[1]);
    if (names.length > MAX_PACKAGE_EXPORTS) fail("PackageExportBound");
  }
  names.sort();
  if (names.some((name) => name.toLowerCase().includes("test"))) fail("NetworkTestExport", names.join(","));
  if (JSON.stringify(names) !== JSON.stringify(EXPECTED_NETWORK_EXPORTS))
    fail("UnexpectedNetworkExports", names.join(","));
  return names;
}

function assertPackageExports(packageJson) {
  if (!packageJson.exports || typeof packageJson.exports !== "object" || Array.isArray(packageJson.exports)) {
    fail("InvalidPackageExports");
  }
  const subpaths = Object.keys(packageJson.exports).sort();
  if (subpaths.length > MAX_PACKAGE_EXPORTS) fail("PackageExportBound");
  if (JSON.stringify(subpaths) !== JSON.stringify(EXPECTED_PACKAGE_EXPORTS)) {
    fail("UnexpectedPackageExports", subpaths.join(","));
  }
}

async function pack(nativeDir, out, buildRecordPath) {
  for (const path of [nativeDir, buildRecordPath]) if (!(await exists(path))) fail("MissingPath", path);
  if ((await exists(out)) || (await exists(`${out}.json`))) fail("OutputExists", out);
  await mkdir(dirname(out), {recursive: true});
  const buildRecord = await readJson(buildRecordPath, "build record");
  const expectedAddon = validateBuildRecord(buildRecord);
  const sourceCheck = await verifySource(nativeDir, buildRecord.sourceCommit);
  const addonPath = join(nativeDir, expectedAddon.path);
  const addonInfo = await stat(addonPath);
  const actualAddon = {bytes: addonInfo.size, path: expectedAddon.path, sha256: await sha256(addonPath)};
  if (actualAddon.bytes !== expectedAddon.bytes || actualAddon.sha256 !== expectedAddon.sha256) {
    fail("AddonMismatch", JSON.stringify({actual: actualAddon, expected: expectedAddon}));
  }
  const temporaryArchive = join(dirname(out), `.${basename(out)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
  const packArgs = ["--config.ignore-scripts=true", "pack", "--json", "--out", temporaryArchive];
  let command;
  try {
    const packageJson = await readJson(join(nativeDir, "package.json"), "source package.json");
    assertPackageExports(packageJson);
    const sourceFilesBefore = await collectPackSources(nativeDir, packageJson);
    command = await runCommand("pnpm", packArgs, nativeDir);
    const inspected = await inspectArchive(temporaryArchive, expectedAddon);
    await verifyArchiveSources(nativeDir, inspected.files);
    const sourceFilesAfter = await collectPackSources(nativeDir, packageJson);
    assertSameInventory(sourceFilesBefore, sourceFilesAfter, "SourceChangedDuringPack");
    if (JSON.stringify(packageJson.exports) !== JSON.stringify(inspected.packageJson.exports)) {
      fail("PackageExportsMismatch");
    }
    const networkPath = packageJson.exports?.["./network"]?.import;
    if (typeof networkPath !== "string") fail("InvalidNetworkExport");
    const networkSourcePath = join(nativeDir, networkPath.replace(/^\.\//, ""));
    if ((await stat(networkSourcePath)).size > MAX_WRAPPER_BYTES) fail("NetworkWrapperByteBound");
    const networkExports = ordinaryNetworkExports(await readFile(networkSourcePath, "utf8"));
    const archiveInfo = await stat(temporaryArchive);
    const manifest = {
      addon: actualAddon,
      archive: {bytes: archiveInfo.size, file: basename(out), sha256: await sha256(temporaryArchive)},
      build: {
        buildCommand: buildRecord.buildCommand,
        instrumented: buildRecord.instrumented,
        optimize: buildRecord.optimize,
        preset: buildRecord.preset,
        recordFile: basename(buildRecordPath),
        recordSha256: await sha256(buildRecordPath),
        sourceCommit: buildRecord.sourceCommit,
        targetPolicy: buildRecord.targetPolicy,
        toolchain: buildRecord.toolchain,
      },
      command,
      files: inspected.files,
      ordinaryExports: {network: networkExports},
      package: {name: inspected.packageJson.name, version: inspected.packageJson.version},
      schemaVersion: 1,
      sourceCheck: {...sourceCheck, packageFiles: sourceFilesBefore},
    };
    const temporaryManifest = `${temporaryArchive}.json`;
    await writeFile(temporaryManifest, `${JSON.stringify(manifest, null, 2)}\n`, {flag: "wx"});
    await rename(temporaryArchive, out);
    await rename(temporaryManifest, `${out}.json`);
    return manifest;
  } catch (error) {
    await rm(temporaryArchive, {force: true});
    await rm(`${temporaryArchive}.json`, {force: true});
    throw error;
  }
}

function assertSameInventory(expected, actual, code) {
  if (!isDeepStrictEqual(expected, actual)) fail(code);
}

function validatePackageManifest(manifest) {
  if (!manifest || manifest.schemaVersion !== 1) fail("InvalidPackageManifest");
  if (manifest.package?.name !== "@chainsafe/lodestar-z" || typeof manifest.package.version !== "string") {
    fail("InvalidPackageManifest", "package");
  }
  if (
    !manifest.archive ||
    basename(manifest.archive.file) !== manifest.archive.file ||
    !Number.isSafeInteger(manifest.archive.bytes) ||
    manifest.archive.bytes < 0 ||
    manifest.archive.bytes > MAX_ARCHIVE_BYTES ||
    !HASH_PATTERN.test(manifest.archive.sha256)
  ) {
    fail("InvalidPackageManifest", "archive");
  }
  if (
    !manifest.addon ||
    manifest.addon.path !== "zig-out/lib/bindings.node" ||
    !Number.isSafeInteger(manifest.addon.bytes) ||
    manifest.addon.bytes < 0 ||
    !HASH_PATTERN.test(manifest.addon.sha256)
  ) {
    fail("InvalidPackageManifest", "addon");
  }
  validateBuildRecord({...manifest.build, files: [manifest.addon]});
  if (!Array.isArray(manifest.files) || manifest.files.length > MAX_FILES) fail("InvalidPackageManifest", "files");
  const paths = new Set();
  let bytes = 0;
  for (const file of manifest.files) {
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
    bytes += file.bytes;
    if (bytes > MAX_SOURCE_BYTES) fail("PackageSourceByteBound", `more than ${MAX_SOURCE_BYTES} bytes`);
  }
  for (const required of ["package.json", "zig-out/lib/bindings.node"]) {
    if (!paths.has(required)) fail("InvalidPackageManifest", `missing ${required}`);
  }
}

async function verifyManifestArchive(manifestPath) {
  const manifest = await readJson(manifestPath, "package manifest");
  validatePackageManifest(manifest);
  const archive = join(dirname(manifestPath), manifest.archive.file);
  const archiveInfo = await stat(archive);
  const archiveHash = await sha256(archive);
  if (archiveInfo.size !== manifest.archive.bytes || archiveHash !== manifest.archive.sha256) {
    fail(
      "ArchiveMismatch",
      JSON.stringify({actual: {bytes: archiveInfo.size, sha256: archiveHash}, expected: manifest.archive})
    );
  }
  const inspected = await inspectArchive(archive, manifest.addon);
  assertSameInventory(manifest.files, inspected.files, "ArchiveInventoryMismatch");
  if (
    inspected.packageJson.name !== "@chainsafe/lodestar-z" ||
    inspected.packageJson.version !== manifest.package.version
  ) {
    fail("ArchivePackageMismatch");
  }
  assertPackageExports(inspected.packageJson);
  return {archive, inspected, manifest, manifestSha256: await sha256(manifestPath)};
}

async function hostManifestPaths(hostDir) {
  const tracked = await runCommand("git", ["ls-files", "package.json", "packages/*/package.json"], hostDir, {
    allowFailure: true,
  });
  if (tracked.exitCode === 0 && tracked.stdout.trim() !== "") {
    const paths = tracked.stdout
      .trim()
      .split("\n")
      .map((path) => join(hostDir, path));
    if (paths.length > MAX_FILES) fail("HostManifestBound");
    return paths;
  }
  return [join(hostDir, "package.json")];
}

async function snapshotPaths(paths) {
  const snapshot = [];
  for (const path of paths) {
    if (!(await exists(path))) {
      snapshot.push({path, present: false});
      continue;
    }
    const info = await stat(path);
    if (!info.isFile()) fail("InvalidHostSnapshotPath", path);
    snapshot.push({bytes: info.size, path, present: true, sha256: await sha256(path)});
  }
  return snapshot;
}

function declaresPackage(packageJson) {
  return ["dependencies", "devDependencies", "optionalDependencies"].some(
    (kind) => packageJson[kind]?.["@chainsafe/lodestar-z"] !== undefined
  );
}

async function resolutionParents(hostDir, manifests) {
  const parents = [];
  for (const manifest of manifests) {
    if (declaresPackage(await readJson(manifest, manifest))) parents.push(manifest);
  }
  const compiled = [
    join(hostDir, "packages/beacon-node/lib/chain/bls/multithread/worker.js"),
    join(hostDir, "packages/state-transition/lib/cache/epochCache.js"),
  ];
  const actualHost = await exists(join(hostDir, "packages/beacon-node/package.json"));
  for (const path of compiled) {
    if (await exists(path)) parents.push(path);
    else if (actualHost) fail("MissingCompiledHostConsumer", path);
  }
  return [...new Set(parents)];
}

async function packageRootForResolved(resolvedUrl) {
  let current = dirname(fileURLToPath(resolvedUrl));
  for (let step = 0; step < 16; step++) {
    const manifestPath = join(current, "package.json");
    if (await exists(manifestPath)) {
      const packageJson = await readJson(manifestPath, manifestPath);
      if (packageJson.name === "@chainsafe/lodestar-z") return realpath(current);
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  fail("ResolvedPackageRootMissing", resolvedUrl);
}

async function resolveFromParents(hostDir, parents, exports, {load}) {
  const scriptPath = join(hostDir, `.lodestar-package-resolve-${process.pid}-${randomBytes(8).toString("hex")}.mjs`);
  const specifiers = Object.keys(exports).map((subpath) =>
    subpath === "." ? "@chainsafe/lodestar-z" : `@chainsafe/lodestar-z/${subpath.slice(2)}`
  );
  if (specifiers.length > MAX_PACKAGE_EXPORTS || parents.length * specifiers.length > MAX_RESOLUTION_RECORDS) {
    fail("ResolutionBound");
  }
  const source = `
import {pathToFileURL} from "node:url";
const parents = ${JSON.stringify(parents)};
const specifiers = ${JSON.stringify(specifiers)};
const result = {resolutions: [], exports: {}};
for (const parent of parents) {
  for (const specifier of specifiers) {
    try {
      result.resolutions.push({parent, specifier, resolved: import.meta.resolve(specifier, pathToFileURL(parent))});
    } catch (error) {
      result.resolutions.push({parent, specifier, error: {code: error.code, message: error.message}});
    }
  }
}
if (${JSON.stringify(load)}) {
  for (const specifier of specifiers) {
    const module = await import(specifier);
    result.exports[specifier] = Object.keys(module).sort();
  }
}
process.stdout.write(JSON.stringify(result));
`;
  await writeFile(scriptPath, source, {flag: "wx"});
  try {
    const command = await runCommand(process.execPath, ["--experimental-import-meta-resolve", scriptPath], hostDir, {
      allowFailure: true,
    });
    if (command.exitCode !== 0) fail("HostModuleEvaluationFailed", JSON.stringify(command));
    let result;
    try {
      result = JSON.parse(command.stdout);
    } catch (error) {
      fail("InvalidResolverOutput", `${error.message}: ${JSON.stringify(command)}`);
    }
    return {command, ...result};
  } finally {
    await rm(scriptPath, {force: true});
  }
}

async function verifyInstalled(hostDir, manifestPath) {
  const archiveState = await verifyManifestArchive(manifestPath);
  const manifests = await hostManifestPaths(hostDir);
  const parents = await resolutionParents(hostDir, manifests);
  if (parents.length === 0) fail("NoHostPackageConsumers");
  const resolved = await resolveFromParents(hostDir, parents, archiveState.inspected.packageJson.exports, {load: true});
  const failures = resolved.resolutions.filter((row) => row.error !== undefined);
  if (failures.length !== 0) fail("HostResolutionFailed", JSON.stringify(failures));
  const roots = [];
  for (const row of resolved.resolutions) roots.push(await packageRootForResolved(row.resolved));
  const packageRoots = [...new Set(roots)];
  if (packageRoots.length !== 1) fail("SplitPackageIdentity", JSON.stringify(packageRoots));
  const packageRoot = packageRoots[0];
  const installedFiles = await collectFiles(packageRoot);
  assertSameInventory(archiveState.manifest.files, installedFiles, "InstalledPackageMismatch");
  const addonPath = join(packageRoot, archiveState.manifest.addon.path);
  const addonInfo = await stat(addonPath);
  const addon = {bytes: addonInfo.size, path: addonPath, sha256: await sha256(addonPath)};
  if (addon.bytes !== archiveState.manifest.addon.bytes || addon.sha256 !== archiveState.manifest.addon.sha256) {
    fail("InstalledAddonMismatch", JSON.stringify(addon));
  }
  const networkExports = resolved.exports["@chainsafe/lodestar-z/network"] ?? [];
  if (networkExports.some((name) => name.toLowerCase().includes("test"))) {
    fail("NetworkTestExport", networkExports.join(","));
  }
  const head = await runCommand("git", ["rev-parse", "HEAD"], hostDir, {allowFailure: true});
  return {
    archive: archiveState.manifest.archive,
    host: {head: head.exitCode === 0 ? head.stdout.trim() : null},
    installed: {addon, files: installedFiles, packageRoot},
    manifest: archiveState.manifest,
    manifestSha256: archiveState.manifestSha256,
    ordinaryExports: resolved.exports,
    resolutions: {command: resolved.command, packageRoots, parents, records: resolved.resolutions},
  };
}

function packageNameFromEntry(entry, scope) {
  return scope === undefined ? entry : `${scope}/${entry}`;
}

async function nodeModulesEdges(nodeModulesDir, graphRoot) {
  if (!(await exists(nodeModulesDir))) return [];
  const edges = [];
  const entries = await readdir(nodeModulesDir, {withFileTypes: true});
  entries.sort((left, right) => left.name.localeCompare(right.name));
  if (entries.length > MAX_GRAPH_NODES) fail("InstalledGraphBound", nodeModulesDir);
  for (const entry of entries) {
    if (entry.name === ".bin" || entry.name === ".pnpm") continue;
    const path = join(nodeModulesDir, entry.name);
    if (entry.name.startsWith("@") && entry.isDirectory() && !entry.isSymbolicLink()) {
      const scoped = await readdir(path, {withFileTypes: true});
      if (scoped.length > MAX_GRAPH_NODES) fail("InstalledGraphBound", path);
      for (const child of scoped.sort((left, right) => left.name.localeCompare(right.name))) {
        const childPath = join(path, child.name);
        edges.push({
          name: packageNameFromEntry(child.name, entry.name),
          target: relative(graphRoot, await realpath(childPath)),
        });
        if (edges.length > MAX_GRAPH_EDGES) fail("InstalledGraphBound", nodeModulesDir);
      }
      continue;
    }
    edges.push({name: entry.name, target: relative(graphRoot, await realpath(path))});
    if (edges.length > MAX_GRAPH_EDGES) fail("InstalledGraphBound", nodeModulesDir);
  }
  return edges;
}

async function installedGraph(hostDir, manifests) {
  const graphRoot = join(hostDir, "node_modules/.pnpm");
  const storeEntries = await readdir(graphRoot, {withFileTypes: true});
  if (storeEntries.length > MAX_GRAPH_NODES) fail("InstalledGraphBound", graphRoot);
  const nodes = [];
  let edgeCount = 0;
  for (const entry of storeEntries.sort((left, right) => left.name.localeCompare(right.name))) {
    if (!entry.isDirectory() || entry.name === "node_modules") continue;
    const edges = await nodeModulesEdges(join(graphRoot, entry.name, "node_modules"), graphRoot);
    edgeCount += edges.length;
    if (edgeCount > MAX_GRAPH_EDGES) fail("InstalledGraphBound", graphRoot);
    nodes.push({
      edges,
      location: `.pnpm/${entry.name}`,
    });
    if (nodes.length > MAX_GRAPH_NODES) fail("InstalledGraphBound", graphRoot);
  }
  for (const manifest of manifests) {
    const workspace = relative(hostDir, dirname(manifest)) || ".";
    const edges = await nodeModulesEdges(join(dirname(manifest), "node_modules"), graphRoot);
    edgeCount += edges.length;
    if (edgeCount > MAX_GRAPH_EDGES) fail("InstalledGraphBound", graphRoot);
    nodes.push({
      edges,
      location: workspace,
    });
    if (nodes.length > MAX_GRAPH_NODES) fail("InstalledGraphBound", graphRoot);
  }
  const replacementPattern = /(?:^|\/)@chainsafe[+/]lodestar-z(?:-|@|\/|$)/;
  const normalized = nodes
    .filter((node) => !replacementPattern.test(node.location))
    .map((node) => ({
      edges: node.edges
        .filter((edge) => edge.name !== "@chainsafe/lodestar-z" && !edge.name.startsWith("@chainsafe/lodestar-z-"))
        .map((edge) => ({...edge, target: replacementPattern.test(edge.target) ? "PACKAGE_REPLACEMENT" : edge.target})),
      location: node.location,
    }));
  return {nodes, normalized};
}

function currentTarget() {
  if (process.platform === "linux" && process.arch === "x64") {
    const report = process.report?.getReport?.();
    return `x86_64-unknown-linux-${report?.header?.glibcVersionRuntime ? "gnu" : "musl"}`;
  }
  if (process.platform === "linux" && process.arch === "arm64") {
    const report = process.report?.getReport?.();
    return `aarch64-unknown-linux-${report?.header?.glibcVersionRuntime ? "gnu" : "musl"}`;
  }
  if (process.platform === "darwin" && process.arch === "x64") return "x86_64-apple-darwin";
  if (process.platform === "darwin" && process.arch === "arm64") return "aarch64-apple-darwin";
  fail("UnsupportedBaselineTarget", `${process.platform}/${process.arch}`);
}

async function copyInventory(root, destination) {
  const files = await collectFiles(root);
  for (const file of files) {
    const target = join(destination, file.path);
    await mkdir(dirname(target), {recursive: true});
    await copyFile(join(root, file.path), target);
  }
  return files;
}

async function capturePriorInstallation(hostDir, manifests, evidenceDir) {
  const parents = await resolutionParents(hostDir, manifests);
  const rootResolved = await resolveFromParents(hostDir, parents, {".": {}}, {load: false});
  const rootSuccessful = rootResolved.resolutions.filter((row) => row.resolved !== undefined);
  if (rootSuccessful.length === 0) fail("PriorPackageResolutionFailed", JSON.stringify(rootResolved.resolutions));
  const initialRoot = await packageRootForResolved(rootSuccessful[0].resolved);
  const installedManifest = await readJson(join(initialRoot, "package.json"), "installed baseline package.json");
  const baselineExports = installedManifest.exports?.["./pubkeys"] === undefined ? {".": {}} : {"./pubkeys": {}};
  const resolved = await resolveFromParents(hostDir, parents, baselineExports, {load: false});
  const successful = resolved.resolutions.filter((row) => row.resolved !== undefined);
  if (successful.length === 0) fail("PriorPackageResolutionFailed", JSON.stringify(resolved.resolutions));
  const roots = [];
  for (const row of successful) roots.push(await packageRootForResolved(row.resolved));
  const packageRoots = [...new Set(roots)];
  if (packageRoots.length !== 1) fail("SplitPriorPackageIdentity", JSON.stringify(packageRoots));
  const packageRoot = packageRoots[0];
  const wrapperDestination = join(evidenceDir, "prior-installation", "wrapper");
  const wrapperFiles = await copyInventory(packageRoot, wrapperDestination);
  const localAddon = join(packageRoot, "zig-out/lib/bindings.node");
  let selectedAddon;
  let platformFiles = [];
  if (await exists(localAddon)) {
    const info = await stat(localAddon);
    selectedAddon = {bytes: info.size, path: localAddon, sha256: await sha256(localAddon), target: "local"};
  } else {
    const target = currentTarget();
    const packageName = `@chainsafe/lodestar-z-${target}`;
    const resolverPath = join(packageRoot, "bindings/src/bindings.js");
    const resolution = await runCommand(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `import {createRequire} from "node:module"; process.stdout.write(createRequire(${JSON.stringify(
          resolverPath
        )}).resolve(${JSON.stringify(packageName)}));`,
      ],
      hostDir
    );
    const addonPath = resolution.stdout;
    const info = await stat(addonPath);
    selectedAddon = {
      bytes: info.size,
      packageName,
      path: addonPath,
      resolution,
      sha256: await sha256(addonPath),
      target,
    };
    const platformRoot = dirname(addonPath);
    platformFiles = await copyInventory(platformRoot, join(evidenceDir, "prior-installation", "platform"));
  }
  return {packageRoot, parents, platformFiles, resolutions: resolved, selectedAddon, wrapperFiles};
}

async function install(hostDir, manifestPath, evidenceDir) {
  if (!(await exists(hostDir))) fail("MissingPath", hostDir);
  if (await exists(evidenceDir)) fail("EvidenceDirectoryExists", evidenceDir);
  await mkdir(evidenceDir, {recursive: true});
  const archiveState = await verifyManifestArchive(manifestPath);
  const manifests = await hostManifestPaths(hostDir);
  const immutablePaths = [...manifests, join(hostDir, "pnpm-workspace.yaml"), join(hostDir, "pnpm-lock.yaml")];
  const internalLock = join(hostDir, "node_modules/.pnpm/lock.yaml");
  if (!(await exists(internalLock))) fail("MissingInternalLockBaseline", internalLock);
  const beforeFiles = await snapshotPaths([...immutablePaths, internalLock]);
  const beforeGraph = await installedGraph(hostDir, manifests);
  const priorInstallation = await capturePriorInstallation(hostDir, manifests, evidenceDir);
  const version = await runCommand("pnpm", ["--version"], hostDir);
  const hostPackage = await readJson(join(hostDir, "package.json"), "host package.json");
  const selectedVersion = /^pnpm@([^+]+)(?:\+.*)?$/.exec(hostPackage.packageManager ?? "")?.[1];
  if (selectedVersion === undefined) fail("MissingPackageManagerPin");
  if (version.stdout.trim() !== selectedVersion) {
    fail("PackageManagerVersionMismatch", JSON.stringify({actual: version.stdout.trim(), selectedVersion}));
  }
  const explicitArchiveDependency = `file:${archiveState.archive}`;
  const hookPath = join(evidenceDir, "lodestar-package-hook.cjs");
  const hook = `const explicitArchiveDependency = ${JSON.stringify(explicitArchiveDependency)};
module.exports = {hooks: {readPackage(pkg) {
  for (const kind of ["dependencies", "devDependencies", "optionalDependencies"]) {
    if (pkg[kind]?.["@chainsafe/lodestar-z"] !== undefined) {
      pkg[kind]["@chainsafe/lodestar-z"] = explicitArchiveDependency;
    }
  }
  return pkg;
}}};
`;
  await writeFile(hookPath, hook, {flag: "wx"});
  const majorVersion = Number.parseInt(selectedVersion.split(".")[0], 10);
  const installArgs = ["install", "--offline", "--ignore-scripts", "--lockfile=false"];
  if (majorVersion >= 11) installArgs.push("--no-optimistic-repeat-install", "--no-prefer-frozen-lockfile");
  installArgs.push("--pnpmfile", hookPath);
  const command = await runCommand("pnpm", installArgs, hostDir, {allowFailure: true});
  let attemptGraph;
  try {
    attemptGraph = await installedGraph(hostDir, manifests);
  } catch (error) {
    await writeFile(
      join(evidenceDir, "install-failure.json"),
      `${JSON.stringify({archive: archiveState.manifest.archive, command, graphError: error.message, version}, null, 2)}\n`
    );
    throw error;
  }
  const attempts = [
    {
      command,
      graph: attemptGraph,
      kind: majorVersion >= 11 ? "pnpm11-resolved-install" : "standard-install",
    },
  ];
  if (command.exitCode !== 0) {
    await writeFile(
      join(evidenceDir, "install-failure.json"),
      `${JSON.stringify({archive: archiveState.manifest.archive, attempts, version}, null, 2)}\n`
    );
    fail("PackageInstallFailed", JSON.stringify(command));
  }
  let afterFiles;
  let afterGraph;
  let verification;
  try {
    verification = await verifyInstalled(hostDir, manifestPath);
    afterFiles = await snapshotPaths([...immutablePaths, internalLock]);
    assertSameInventory(
      beforeFiles.slice(0, immutablePaths.length),
      afterFiles.slice(0, immutablePaths.length),
      "HostSourceChanged"
    );
    afterGraph = await installedGraph(hostDir, manifests);
    assertSameInventory(beforeGraph.normalized, afterGraph.normalized, "UnrelatedInstalledGraphChanged");
  } catch (error) {
    attempts[0].verificationError = error.message;
    await writeFile(
      join(evidenceDir, "install-failure.json"),
      `${JSON.stringify(
        {afterFiles, afterGraph, archive: archiveState.manifest.archive, attempts, beforeFiles, beforeGraph, version},
        null,
        2
      )}\n`
    );
    throw error;
  }
  const evidence = {
    archive: archiveState.manifest.archive,
    graph: {after: afterGraph, before: beforeGraph},
    hook: {explicitArchiveDependency, path: hookPath, sha256: await sha256(hookPath)},
    hostFiles: {after: afterFiles, before: beforeFiles},
    manifestPath,
    manifestSha256: archiveState.manifestSha256,
    packageManager: {attempts, version: selectedVersion, versionCommand: version},
    priorInstallation,
    schemaVersion: 1,
    verification,
  };
  await writeFile(join(evidenceDir, "install-evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`, {flag: "wx"});
  return evidence;
}

async function main() {
  const {command, options} = parseOptions(process.argv.slice(2));
  if (command === "pack") {
    const manifest = await pack(options["--native-dir"], options["--out"], options["--build-record"]);
    process.stdout.write(`${JSON.stringify(manifest)}\n`);
    return;
  }
  if (command === "install") {
    const evidence = await install(options["--host-dir"], options["--manifest"], options["--evidence-dir"]);
    process.stdout.write(`${JSON.stringify(evidence.verification)}\n`);
    return;
  }
  const verification = await verifyInstalled(options["--host-dir"], options["--manifest"]);
  process.stdout.write(`${JSON.stringify(verification)}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
