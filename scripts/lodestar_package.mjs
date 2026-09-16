import {randomBytes} from "node:crypto";
import {mkdir, mkdtemp, realpath, rename, rm, stat, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {basename, dirname, join, relative, resolve} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {runBoundedCommand} from "./bounded_child.mjs";
import {
  assertNetworkExports,
  assertPackageExports,
  collectPackSources,
  inspectArchive,
  validateBuildRecord,
  verifyArchiveSources,
  verifyManifestArchive,
} from "./lodestar_package_archive.mjs";
import {
  MAX_FILES,
  MAX_OUTPUT_BYTES,
  collectFiles,
  exists,
  fail,
  failCommand,
  readDirectoryEntries,
  readJson,
  sha256,
} from "./lodestar_package_io.mjs";
import {activateRelease, copyRelease, prepareRelease} from "./lodestar_package_release.mjs";

const COMMAND_TIMEOUT_MS = 20 * 60 * 1000;
const MAX_PACKAGE_EXPORTS = 64;
const MAX_RESOLUTION_RECORDS = 16 * 1024;
const MAX_GRAPH_NODES = 8192;
const MAX_GRAPH_EDGES = 64 * 1024;
const SOURCE_PATHS = [
  "src",
  "bindings/napi",
  "bindings/src",
  "build.zig",
  "build.zig.zon",
  "package.json",
  "pnpm-lock.yaml",
];

async function runCommand(program, args, cwd, {allowFailure = false, env = process.env} = {}) {
  return runBoundedCommand(program, args, cwd, {
    allowFailure,
    env,
    maxOutputBytes: MAX_OUTPUT_BYTES,
    timeoutMs: COMMAND_TIMEOUT_MS,
  });
}

function boundedPrefix(value, maxBytes = 64 * 1024) {
  const source = Buffer.from(typeof value === "string" ? value : "");
  const prefix = source.subarray(0, maxBytes).toString("utf8");
  return {bytes: source.length, prefix, truncated: source.length > maxBytes};
}

function structuredError(error) {
  const message = boundedPrefix(error?.message);
  const evidence = {
    code: typeof error?.code === "string" ? error.code : "Error",
    message: message.prefix,
    messageBytes: message.bytes,
    messageTruncated: message.truncated,
  };
  const record = error?.commandRecord;
  if (record !== undefined) {
    const stdout = boundedPrefix(record.stdout);
    const stderr = boundedPrefix(record.stderr);
    evidence.commandRecord = {
      argv: record.argv,
      cwd: record.cwd,
      exitCode: record.exitCode,
      finishedAt: record.finishedAt,
      signal: record.signal,
      startedAt: record.startedAt,
      stderr: stderr.prefix,
      stderrBytes: stderr.bytes,
      stderrTruncated: stderr.truncated,
      stdout: stdout.prefix,
      stdoutBytes: stdout.bytes,
      stdoutTruncated: stdout.truncated,
    };
  }
  return {error: evidence};
}

function parseOptions(argv) {
  const command = argv[0];
  const allowed = {
    install: new Set(["--host-dir", "--manifest", "--evidence-dir", "--release-dir", "--active-link"]),
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
    const inspected = await inspectArchive(temporaryArchive, expectedAddon, runCommand);
    await verifyArchiveSources(nativeDir, inspected.files);
    const sourceFilesAfter = await collectPackSources(nativeDir, packageJson);
    assertSameInventory(sourceFilesBefore, sourceFilesAfter, "SourceChangedDuringPack");
    if (JSON.stringify(packageJson.exports) !== JSON.stringify(inspected.packageJson.exports)) {
      fail("PackageExportsMismatch");
    }
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
      ordinaryExports: {externalNamespaces: inspected.externalNamespaces, network: inspected.networkExports},
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

async function hostManifestPaths(hostDir) {
  const paths = [join(hostDir, "package.json")];
  const packages = join(hostDir, "packages");
  if (!(await exists(packages))) return paths;
  for (const entry of await readDirectoryEntries(packages, MAX_FILES, "HostManifestBound")) {
    const path = join(packages, entry.name, "package.json");
    if (entry.isDirectory() && (await exists(path))) paths.push(path);
  }
  if (paths.length > MAX_FILES) fail("HostManifestBound");
  return paths;
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

async function resolutionParents(manifests) {
  const parents = [];
  for (const manifest of manifests) {
    if (declaresPackage(await readJson(manifest, manifest))) parents.push(manifest);
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

async function resolveFromParents(hostDir, parents, exports) {
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
for (const specifier of specifiers) {
  const resolved = result.resolutions.find((row) => row.specifier === specifier && row.error === undefined)?.resolved;
  if (!resolved) continue;
  const module = await import(resolved);
  result.exports[specifier] = Object.keys(module).sort();
}
process.stdout.write(JSON.stringify(result));
`;
  const directory = await mkdtemp(join(tmpdir(), "lodestar-package-resolve-"));
  const scriptPath = join(directory, "resolve.mjs");
  try {
    await writeFile(scriptPath, source, {flag: "wx"});
    const command = await runCommand(process.execPath, ["--experimental-import-meta-resolve", scriptPath], hostDir, {
      allowFailure: true,
    });
    if (command.exitCode !== 0) failCommand("HostModuleEvaluationFailed", command);
    let result;
    try {
      result = JSON.parse(command.stdout);
    } catch (error) {
      fail("InvalidResolverOutput", `${error.message}: ${JSON.stringify(command)}`);
    }
    return {command, ...result};
  } finally {
    await rm(directory, {force: true, recursive: true});
  }
}

async function verifyInstalled(hostDir, manifestPath, verifiedArchive) {
  const archiveState = verifiedArchive ?? (await verifyManifestArchive(manifestPath, runCommand));
  const manifests = await hostManifestPaths(hostDir);
  const parents = await resolutionParents(manifests);
  if (parents.length === 0) fail("NoHostPackageConsumers");
  const resolved = await resolveFromParents(hostDir, parents, archiveState.inspected.packageJson.exports);
  const failures = resolved.resolutions.filter((row) => row.error !== undefined);
  if (failures.length !== 0) fail("HostResolutionFailed", JSON.stringify(failures));
  const networkExports = resolved.exports["@chainsafe/lodestar-z/network"] ?? [];
  assertNetworkExports(networkExports);
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
  const head = await runCommand("git", ["rev-parse", "HEAD"], hostDir, {allowFailure: true});
  return {
    archive: archiveState.manifest.archive,
    archiveExternalNamespaces: archiveState.inspected.externalNamespaces,
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

async function nodeModulesEdges(nodeModulesDir, graphRoot, maxEdges) {
  if (!(await exists(nodeModulesDir))) return [];
  const edges = [];
  const entries = await readDirectoryEntries(nodeModulesDir, MAX_GRAPH_NODES, "InstalledGraphBound");
  for (const entry of entries) {
    if (entry.name === ".bin" || entry.name === ".pnpm") continue;
    const path = join(nodeModulesDir, entry.name);
    if (entry.name.startsWith("@") && entry.isDirectory() && !entry.isSymbolicLink()) {
      const scoped = await readDirectoryEntries(path, MAX_GRAPH_NODES, "InstalledGraphBound");
      for (const child of scoped) {
        if (edges.length >= maxEdges) fail("InstalledGraphBound", nodeModulesDir);
        const childPath = join(path, child.name);
        edges.push({
          name: packageNameFromEntry(child.name, entry.name),
          target: relative(graphRoot, await realpath(childPath)),
        });
      }
      continue;
    }
    if (edges.length >= maxEdges) fail("InstalledGraphBound", nodeModulesDir);
    edges.push({name: entry.name, target: relative(graphRoot, await realpath(path))});
  }
  return edges;
}

async function installedGraph(hostDir, manifests) {
  const graphRoot = join(hostDir, "node_modules/.pnpm");
  const storeEntries = await readDirectoryEntries(graphRoot, MAX_GRAPH_NODES, "InstalledGraphBound");
  const nodes = [];
  let edgeCount = 0;
  for (const entry of storeEntries) {
    if (!entry.isDirectory() || entry.name === "node_modules") continue;
    if (nodes.length >= MAX_GRAPH_NODES) fail("InstalledGraphBound", graphRoot);
    const edges = await nodeModulesEdges(
      join(graphRoot, entry.name, "node_modules"),
      graphRoot,
      MAX_GRAPH_EDGES - edgeCount
    );
    edgeCount += edges.length;
    nodes.push({
      edges,
      location: `.pnpm/${entry.name}`,
    });
  }
  for (const manifest of manifests) {
    if (nodes.length >= MAX_GRAPH_NODES) fail("InstalledGraphBound", graphRoot);
    const workspace = relative(hostDir, dirname(manifest)) || ".";
    const edges = await nodeModulesEdges(
      join(dirname(manifest), "node_modules"),
      graphRoot,
      MAX_GRAPH_EDGES - edgeCount
    );
    edgeCount += edges.length;
    nodes.push({
      edges,
      location: workspace,
    });
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

async function install(hostDir, manifestPath, evidenceDir, releaseDir, activeLink) {
  if (!(await exists(hostDir))) fail("MissingPath", hostDir);
  const release = await prepareRelease(hostDir, releaseDir, activeLink, evidenceDir);
  let published = false;
  try {
    const archiveState = await verifyManifestArchive(manifestPath, runCommand);
    const copied = await copyRelease(release);
    const evidence = await installWithEvidence(release.directory, manifestPath, evidenceDir, archiveState);
    evidence.release = {...release, copied};
    await writeFile(join(evidenceDir, "install-evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`, {flag: "wx"});
    await activateRelease(release);
    published = true;
    return evidence;
  } catch (error) {
    const failurePath = join(evidenceDir, "install-failure.json");
    if (!(await exists(failurePath))) {
      await writeFile(
        failurePath,
        `${JSON.stringify({failure: structuredError(error).error, manifestPath}, null, 2)}\n`,
        {flag: "wx"}
      );
    }
    throw error;
  } finally {
    if (!published) await rm(release.directory, {force: true, recursive: true});
  }
}

async function installWithEvidence(hostDir, manifestPath, evidenceDir, archiveState) {
  const manifests = await hostManifestPaths(hostDir);
  const immutablePaths = [...manifests, join(hostDir, "pnpm-workspace.yaml"), join(hostDir, "pnpm-lock.yaml")];
  const internalLock = join(hostDir, "node_modules/.pnpm/lock.yaml");
  if (!(await exists(internalLock))) fail("MissingInternalLockBaseline", internalLock);
  const beforeFiles = await snapshotPaths([...immutablePaths, internalLock]);
  const beforeGraph = await installedGraph(hostDir, manifests);
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
  const installArgs = ["install", "--offline", "--ignore-scripts", "--lockfile=false", "--package-import-method=copy"];
  if (majorVersion >= 11) installArgs.push("--no-optimistic-repeat-install", "--no-prefer-frozen-lockfile");
  installArgs.push("--pnpmfile", hookPath);
  let command;
  try {
    command = await runCommand("pnpm", installArgs, hostDir, {allowFailure: true});
  } catch (error) {
    await writeFile(
      join(evidenceDir, "install-failure.json"),
      `${JSON.stringify(
        {archive: archiveState.manifest.archive, commandFailure: structuredError(error).error, version},
        null,
        2
      )}\n`,
      {flag: "wx"}
    );
    throw error;
  }
  let attemptGraph;
  try {
    attemptGraph = await installedGraph(hostDir, manifests);
  } catch (error) {
    await writeFile(
      join(evidenceDir, "install-failure.json"),
      `${JSON.stringify(
        {archive: archiveState.manifest.archive, command, graphFailure: structuredError(error).error, version},
        null,
        2
      )}\n`,
      {flag: "wx"}
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
    failCommand("PackageInstallFailed", command);
  }
  let afterFiles;
  let afterGraph;
  let verification;
  try {
    verification = await verifyInstalled(hostDir, manifestPath, archiveState);
    afterFiles = await snapshotPaths([...immutablePaths, internalLock]);
    assertSameInventory(
      beforeFiles.slice(0, immutablePaths.length),
      afterFiles.slice(0, immutablePaths.length),
      "HostSourceChanged"
    );
    afterGraph = await installedGraph(hostDir, manifests);
    assertSameInventory(beforeGraph.normalized, afterGraph.normalized, "UnrelatedInstalledGraphChanged");
  } catch (error) {
    attempts[0].verificationFailure = structuredError(error).error;
    await writeFile(
      join(evidenceDir, "install-failure.json"),
      `${JSON.stringify(
        {afterFiles, afterGraph, archive: archiveState.manifest.archive, attempts, beforeFiles, beforeGraph, version},
        null,
        2
      )}\n`,
      {flag: "wx"}
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
    schemaVersion: 1,
    verification,
  };
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
    const evidence = await install(
      options["--host-dir"],
      options["--manifest"],
      options["--evidence-dir"],
      options["--release-dir"],
      options["--active-link"]
    );
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
    process.stderr.write(`${JSON.stringify(structuredError(error))}\n`);
    process.exitCode = 1;
  }
}
