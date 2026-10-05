import {copyFile, readFile, writeFile} from "node:fs/promises";

const root = new URL("../", import.meta.url);
const {zapi} = JSON.parse(await readFile(new URL("package.json", root), "utf8"));

// zapi prepublish includes only the binary in each platform package.
for (const target of zapi.targets) {
  const directory = new URL(`npm/${target}/`, root);
  const manifestPath = new URL("package.json", directory);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  await copyFile(new URL("THIRD_PARTY_NOTICES.txt", root), new URL("THIRD_PARTY_NOTICES.txt", directory));
  manifest.files.push("THIRD_PARTY_NOTICES.txt");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}
