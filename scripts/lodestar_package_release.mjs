import {randomBytes} from "node:crypto";
import {constants} from "node:fs";
import {chmod, copyFile, lstat, mkdir, opendir, readlink, realpath, rename, rm, symlink} from "node:fs/promises";
import {basename, dirname, isAbsolute, join, relative, resolve, sep} from "node:path";
import {fail} from "./lodestar_package_io.mjs";

const ENTRY_MAX = 250_000;
const BYTE_MAX = 32 * 1024 * 1024 * 1024;
const PATH_DEPTH_MAX = 4096;

export function contains(root, path) {
  const tail = relative(root, path);
  return tail === "" || (!tail.startsWith(`..${sep}`) && tail !== ".." && !isAbsolute(tail));
}

async function information(path) {
  return lstat(path).catch((error) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
}

async function prospectivePath(path) {
  const absolute = resolve(path);
  const suffix = [basename(absolute)];
  let parent = dirname(absolute);
  for (let depth = 0; depth < PATH_DEPTH_MAX; depth++) {
    const existing = await realpath(parent).catch((error) => {
      if (error.code === "ENOENT") return null;
      throw error;
    });
    if (existing !== null) return join(existing, ...suffix.reverse());
    suffix.push(basename(parent));
    parent = dirname(parent);
  }
  fail("ReleasePathDepthBound", path);
}

export async function prepareRelease(source, destination, activeLink, evidenceDir) {
  const sourceRoot = await realpath(source);
  const release = await prospectivePath(destination);
  const active = await prospectivePath(activeLink);
  const evidence = await prospectivePath(evidenceDir);
  if (
    contains(sourceRoot, release) ||
    contains(release, sourceRoot) ||
    contains(release, evidence) ||
    contains(sourceRoot, active) ||
    contains(sourceRoot, evidence) ||
    contains(release, active) ||
    contains(active, release) ||
    contains(active, evidence) ||
    contains(evidence, active) ||
    contains(evidence, release)
  ) {
    fail("OverlappingReleasePaths");
  }
  if (await information(evidence)) fail("EvidenceDirectoryExists", evidence);
  if (await information(release)) fail("ReleaseExists", release);
  const previous = await information(active);
  if (previous !== null && !previous.isSymbolicLink()) fail("ActivePathMustBeSymlink", active);
  await mkdir(evidence, {recursive: true});
  await mkdir(dirname(release), {recursive: true});
  await mkdir(dirname(active), {recursive: true});
  await mkdir(release);
  return {activeLink: active, directory: release, source: sourceRoot};
}

export async function copyRelease(release) {
  const queue = [""];
  const links = [];
  let entries = 0;
  let bytes = 0;
  while (queue.length > 0) {
    const path = queue.pop();
    const directory = await opendir(join(release.source, path));
    for await (const entry of directory) {
      if (path === "" && entry.name === ".git") continue;
      if (++entries > ENTRY_MAX) fail("ReleaseEntryBound");
      const child = join(path, entry.name);
      const source = join(release.source, child);
      const target = join(release.directory, child);
      const info = await lstat(source);
      if (info.isDirectory()) {
        await mkdir(target, {mode: info.mode & 0o777});
        queue.push(child);
      } else if (info.isFile()) {
        if (info.size > BYTE_MAX - bytes) fail("ReleaseByteBound");
        bytes += info.size;
        await copyFile(source, target, constants.COPYFILE_FICLONE);
        await chmod(target, info.mode & 0o777);
      } else if (info.isSymbolicLink()) {
        const linked = resolve(dirname(source), await readlink(source));
        if (!contains(release.source, linked)) fail("ExternalReleaseLink", source);
        const resolved = await realpath(source).catch((error) => {
          if (error.code === "ENOENT") return linked;
          throw error;
        });
        if (!contains(release.source, resolved)) fail("ExternalReleaseLink", source);
        const relocated = join(release.directory, relative(release.source, linked));
        await symlink(relative(dirname(target), relocated), target);
        links.push(target);
      } else fail("ReleaseFileType", source);
    }
  }
  for (const link of links) {
    const resolved = await realpath(link).catch((error) => {
      if (error.code === "ENOENT" || error.code === "ELOOP") fail("MissingReleaseLinkTarget", link);
      throw error;
    });
    if (!contains(release.directory, resolved)) fail("ExternalReleaseLink", link);
  }
  return {bytes, entries};
}

export async function activateRelease(release) {
  const temporary = `${release.activeLink}.${process.pid}-${randomBytes(8).toString("hex")}.tmp`;
  await symlink(relative(dirname(release.activeLink), release.directory), temporary, "dir");
  try {
    await rename(temporary, release.activeLink);
  } catch (error) {
    await rm(temporary, {force: true});
    throw error;
  }
}
