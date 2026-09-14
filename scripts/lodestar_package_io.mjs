import {createHash} from "node:crypto";
import {createReadStream} from "node:fs";
import {access, opendir, readFile, stat} from "node:fs/promises";
import {join, relative, sep} from "node:path";

export const MAX_FILES = 256;
export const MAX_SOURCE_BYTES = 512 * 1024 * 1024;
export const MAX_ARCHIVE_ENTRIES = 512;
export const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

export function fail(code, detail = "") {
  const error = new Error(detail === "" ? code : `${code}: ${detail}`);
  error.code = code;
  throw error;
}

export function failCommand(code, record) {
  const error = new Error(`${code}: exit code ${record.exitCode}`);
  error.code = code;
  error.commandRecord = record;
  throw error;
}

export async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

export async function readJson(path, label) {
  const info = await stat(path);
  if (!info.isFile()) fail("InvalidPath", `${label} is not a regular file`);
  if (info.size > MAX_OUTPUT_BYTES) fail("CommandOutputBound", `${label} exceeds ${MAX_OUTPUT_BYTES} bytes`);
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    fail("InvalidJson", `${label}: ${error.message}`);
  }
}

export async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

export async function readDirectoryEntries(path, maxEntries, code) {
  const entries = [];
  const directory = await opendir(path);
  for await (const entry of directory) {
    if (entries.length >= maxEntries) fail(code, path);
    entries.push(entry);
  }
  entries.sort((left, right) => left.name.localeCompare(right.name));
  return entries;
}

export async function collectFiles(
  root,
  {maxBytes = MAX_SOURCE_BYTES, maxDirectories = MAX_ARCHIVE_ENTRIES, maxFiles = MAX_FILES} = {}
) {
  const directories = [root];
  const files = [];
  let admittedDirectories = 1;
  let bytes = 0;
  while (directories.length > 0) {
    const current = directories.pop();
    const directory = await opendir(current);
    for await (const entry of directory) {
      if (current === root && entry.name === "node_modules") continue;
      const path = join(current, entry.name);
      const packagePath = relative(root, path).split(sep).join("/");
      if (entry.isSymbolicLink()) fail("PackageLink", packagePath);
      if (entry.isDirectory()) {
        if (admittedDirectories >= maxDirectories) fail("PackageDirectoryBound");
        admittedDirectories += 1;
        directories.push(path);
        continue;
      }
      if (!entry.isFile()) fail("PackageFileType", packagePath);
      if (files.length >= maxFiles) fail("PackageFileBound", `more than ${maxFiles} regular files`);
      const info = await stat(path);
      if (info.size > maxBytes - bytes) fail("PackageSourceByteBound", `more than ${maxBytes} bytes`);
      bytes += info.size;
      files.push({bytes: info.size, path: packagePath, sha256: await sha256(path)});
    }
  }
  return files.sort((left, right) => left.path.localeCompare(right.path));
}
