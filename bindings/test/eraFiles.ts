import * as fs from "node:fs";
import * as path from "node:path";

/**
 * Parses the zbuild.zon file and extracts era file configuration.
 * Returns the full paths to available era files.
 */
export function getEraFilePaths(projectRoot?: string): string[] {
  const root = projectRoot ?? path.resolve(import.meta.dirname, "../..");
  const zbuildPath = path.join(root, "zbuild.zon");

  const content = fs.readFileSync(zbuildPath, "utf-8");

  // Extract era_out_dir
  const outDirMatch = content.match(/\.era_out_dir\s*=\s*\.\{\s*\.default\s*=\s*"([^"]+)"/);
  const eraOutDir = outDirMatch?.[1] ?? "fixtures/era";

  // Extract era_files list
  const eraFilesMatch = content.match(/\.era_files\s*=\s*\.\{\s*\.default\s*=\s*\.\{([^}]+)\}/);
  if (!eraFilesMatch) {
    throw new Error("Could not find era_files in zbuild.zon");
  }

  // Parse the file names from the list
  const fileListContent = eraFilesMatch[1];
  const fileNames = [...fileListContent.matchAll(/"([^"]+)"/g)].map((m) => m[1]);

  if (fileNames.length === 0) {
    throw new Error("No era files found in zbuild.zon");
  }

  // Return full paths
  return fileNames.map((fileName) => path.join(root, eraOutDir, fileName));
}

/**
 * Returns the first available era file path.
 */
export function getFirstEraFilePath(projectRoot?: string): string {
  const paths = getEraFilePaths(projectRoot);
  return paths[0];
}

/**
 * Returns era file paths that match a pattern (e.g., "mainnet-01628").
 */
export function findEraFilePaths(pattern: string | RegExp, projectRoot?: string): string[] {
  const paths = getEraFilePaths(projectRoot);
  const regex = typeof pattern === "string" ? new RegExp(pattern) : pattern;
  return paths.filter((p) => regex.test(path.basename(p)));
}
