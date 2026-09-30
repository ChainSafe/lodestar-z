import {copyFile, mkdir, mkdtemp, rename, rm, stat, writeFile} from "node:fs/promises";
import {basename, dirname, join, resolve} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {isDeepStrictEqual} from "node:util";
import {runBoundedCommand} from "./bounded_child.mjs";
import {
  LEGAL_FILES,
  PLATFORM_ADDON_FILE,
  addonLayout,
  assertPackageExports,
  collectPackSources,
  inspectArchive,
  inspectPlatformArchive,
  validateBuildRecord,
  verifyArchiveSources,
} from "./lodestar_package_archive.mjs";
import {MAX_OUTPUT_BYTES, exists, fail, readJson, sha256} from "./lodestar_package_io.mjs";

const COMMAND_TIMEOUT_MS = 20 * 60 * 1000;
const MAX_PLATFORM_TARGETS = 16;
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
    notices: new Set(["--package-dir"]),
    pack: new Set(["--native-dir", "--out", "--build-record"]),
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

/**
 * Reproduces the release workflow for one target: zapi prepublish over the tracked package files and that target's
 * artifact, without zig-out/lib, then npm pack of the main and platform packages, as zapi publish runs npm publish.
 */
async function packPlatform(
  nativeDir,
  temporary,
  packageJson,
  sourceFiles,
  addon,
  target,
  mainArchive,
  platformArchive
) {
  if (!Array.isArray(packageJson.zapi?.targets) || !packageJson.zapi.targets.includes(target)) {
    fail("UnsupportedPlatformTarget", target);
  }
  const staging = join(temporary, "staging");
  for (const file of sourceFiles) {
    await mkdir(dirname(join(staging, file.path)), {recursive: true});
    await copyFile(join(nativeDir, file.path), join(staging, file.path));
  }
  await mkdir(join(staging, "artifacts", target), {recursive: true});
  await copyFile(join(nativeDir, addon.path), join(staging, "artifacts", target, PLATFORM_ADDON_FILE));
  const zapiCli = join(dirname(fileURLToPath(import.meta.resolve("@chainsafe/zapi"))), "cli.js");
  const prepublish = await runCommand(process.execPath, [zapiCli, "prepublish"], staging);
  await addPlatformLegalFiles(staging);
  const packed = [];
  for (const [directory, destination] of [
    [staging, mainArchive],
    [join(staging, "npm", target), platformArchive],
  ]) {
    const command = await runCommand(
      "npm",
      ["pack", "--ignore-scripts", "--json", "--pack-destination", temporary],
      directory
    );
    let filename;
    try {
      filename = JSON.parse(command.stdout)[0]?.filename;
    } catch (error) {
      fail("InvalidPackOutput", error.message);
    }
    if (typeof filename !== "string" || basename(filename) !== filename) fail("InvalidPackOutput", command.stdout);
    await rename(join(temporary, filename), destination);
    packed.push(command);
  }
  const inspected = await inspectArchive(mainArchive, null, runCommand);
  const platform = await inspectPlatformArchive(platformArchive, addon, target, inspected, runCommand);
  return {command: {main: packed[0], platform: packed[1], prepublish}, inspected, platform};
}

/**
 * Copies the legal files into each platform package zapi prepublish generated under `packageDir`/npm and adds them to
 * its `files`, since zapi ships the addon alone. The release workflow runs this between prepublish and publish.
 */
export async function addPlatformLegalFiles(packageDir) {
  const packageJson = await readJson(join(packageDir, "package.json"), "package.json");
  const targets = packageJson.zapi?.targets;
  if (!Array.isArray(targets) || targets.length > MAX_PLATFORM_TARGETS) fail("InvalidPackageTargets");
  for (const target of targets) {
    const directory = join(packageDir, "npm", target);
    const manifestPath = join(directory, "package.json");
    const manifest = await readJson(manifestPath, "platform package.json");
    if (
      manifest.name !== `${packageJson.name}-${target}` ||
      !isDeepStrictEqual(manifest.files, [PLATFORM_ADDON_FILE])
    ) {
      fail("PlatformPackageMismatch", JSON.stringify(manifest));
    }
    for (const file of LEGAL_FILES) await copyFile(join(packageDir, file), join(directory, file));
    manifest.files = [PLATFORM_ADDON_FILE, ...LEGAL_FILES];
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  }
  return targets;
}

async function archiveRecord(path, file) {
  return {bytes: (await stat(path)).size, file, sha256: await sha256(path)};
}

/** The build record's addon path selects the layout: zig-out/lib embeds the addon, artifacts/<target> ships it apart. */
export async function pack(nativeDir, out, buildRecordPath) {
  for (const path of [nativeDir, buildRecordPath]) if (!(await exists(path))) fail("MissingPath", path);
  const buildRecord = await readJson(buildRecordPath, "build record");
  const expectedAddon = validateBuildRecord(buildRecord);
  const {layout, target} = addonLayout(expectedAddon.path);
  const platformOut = layout === "platform" ? join(dirname(out), `${basename(out, ".tgz")}-${target}.tgz`) : null;
  for (const path of [out, `${out}.json`, platformOut])
    if (path !== null && (await exists(path))) fail("OutputExists", path);
  await mkdir(dirname(out), {recursive: true});
  const sourceCheck = await verifySource(nativeDir, buildRecord.sourceCommit);
  const addonPath = join(nativeDir, expectedAddon.path);
  const addonInfo = await stat(addonPath);
  const actualAddon = {bytes: addonInfo.size, path: expectedAddon.path, sha256: await sha256(addonPath)};
  if (actualAddon.bytes !== expectedAddon.bytes || actualAddon.sha256 !== expectedAddon.sha256) {
    fail("AddonMismatch", JSON.stringify({actual: actualAddon, expected: expectedAddon}));
  }
  const temporary = await mkdtemp(join(dirname(out), `.${basename(out)}.${process.pid}.`));
  const mainArchive = join(temporary, basename(out));
  const platformArchive = platformOut === null ? null : join(temporary, basename(platformOut));
  try {
    const packageJson = await readJson(join(nativeDir, "package.json"), "source package.json");
    assertPackageExports(packageJson);
    const sourceFilesBefore = await collectPackSources(nativeDir, packageJson, layout);
    for (const file of LEGAL_FILES) {
      if (!sourceFilesBefore.some((entry) => entry.path === file)) fail("MissingLegalFile", file);
    }
    let command;
    let inspected;
    let platform = null;
    if (layout === "embedded") {
      command = await runCommand(
        "pnpm",
        ["--config.ignore-scripts=true", "pack", "--json", "--out", mainArchive],
        nativeDir
      );
      inspected = await inspectArchive(mainArchive, expectedAddon, runCommand);
    } else {
      const packed = await packPlatform(
        nativeDir,
        temporary,
        packageJson,
        sourceFilesBefore,
        actualAddon,
        target,
        mainArchive,
        platformArchive
      );
      ({command, inspected} = packed);
      platform = {
        archive: await archiveRecord(platformArchive, basename(platformOut)),
        files: packed.platform.files,
        name: packed.platform.name,
        target,
      };
    }
    await verifyArchiveSources(nativeDir, inspected.files, inspected.packageJson, layout);
    const sourceFilesAfter = await collectPackSources(nativeDir, packageJson, layout);
    assertSameInventory(sourceFilesBefore, sourceFilesAfter, "SourceChangedDuringPack");
    if (JSON.stringify(packageJson.exports) !== JSON.stringify(inspected.packageJson.exports)) {
      fail("PackageExportsMismatch");
    }
    const manifest = {
      addon: actualAddon,
      archive: await archiveRecord(mainArchive, basename(out)),
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
      layout,
      ordinaryExports: {externalNamespaces: inspected.externalNamespaces, network: inspected.networkExports},
      package: {name: inspected.packageJson.name, version: inspected.packageJson.version},
      platform,
      schemaVersion: 2,
      sourceCheck: {...sourceCheck, packageFiles: sourceFilesBefore},
    };
    const temporaryManifest = join(temporary, `${basename(out)}.json`);
    await writeFile(temporaryManifest, `${JSON.stringify(manifest, null, 2)}\n`, {flag: "wx"});
    if (platformOut !== null) await rename(platformArchive, platformOut);
    await rename(mainArchive, out);
    await rename(temporaryManifest, `${out}.json`);
    return manifest;
  } finally {
    await rm(temporary, {force: true, recursive: true});
  }
}

function assertSameInventory(expected, actual, code) {
  if (!isDeepStrictEqual(expected, actual)) fail(code);
}

async function main() {
  const {command, options} = parseOptions(process.argv.slice(2));
  if (command === "pack") {
    const manifest = await pack(options["--native-dir"], options["--out"], options["--build-record"]);
    process.stdout.write(`${JSON.stringify(manifest)}\n`);
    return;
  }
  if (command === "notices") {
    const targets = await addPlatformLegalFiles(options["--package-dir"]);
    process.stdout.write(`${JSON.stringify({legalFiles: LEGAL_FILES, targets})}\n`);
    return;
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await main();
  } catch (error) {
    process.stderr.write(`${JSON.stringify(structuredError(error))}\n`);
    process.exitCode = 1;
  }
}
