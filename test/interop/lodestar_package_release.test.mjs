import assert from "node:assert/strict";
import {access, chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {afterEach, test} from "node:test";
import {activateRelease, copyRelease, prepareRelease} from "../../scripts/lodestar_package_release.mjs";

const directories = [];
afterEach(async () => {
  for (const path of directories.splice(0)) await rm(path, {force: true, recursive: true});
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "lodestar-release-"));
  directories.push(root);
  const source = join(root, "host");
  const evidence = join(root, "evidence");
  const destination = join(root, "release");
  const active = join(root, "current");
  await mkdir(source);
  return {active, destination, evidence, root, source};
}

test("release copy isolates file writes and relocates internal links before activation", async () => {
  const f = await fixture();
  await mkdir(join(f.source, "bin"));
  await writeFile(join(f.source, "bin", "host"), "original");
  await chmod(join(f.source, "bin", "host"), 0o755);
  await writeFile(join(f.source, ".git"), "gitdir: external-worktree");
  await symlink(join(f.source, "bin", "host"), join(f.source, "absolute"));
  await symlink("bin/host", join(f.source, "relative"));
  await symlink(f.source, f.active, "dir");
  const release = await prepareRelease(f.source, f.destination, f.active, f.evidence);
  await copyRelease(release);
  assert.equal(await realpath(f.active), f.source);
  await assert.rejects(access(join(f.destination, ".git")), {code: "ENOENT"});
  for (const name of ["absolute", "relative"])
    assert.equal(await realpath(join(f.destination, name)), join(f.destination, "bin", "host"));
  assert.equal((await stat(join(f.destination, "bin", "host"))).mode & 0o777, 0o755);
  await writeFile(join(f.destination, "relative"), "replacement");
  assert.equal(await readFile(join(f.source, "bin", "host"), "utf8"), "original");
  await activateRelease(release);
  assert.equal(await realpath(f.active), f.destination);
  assert.equal(await readFile(join(f.active, "bin", "host"), "utf8"), "replacement");
});

test("release copy rejects dependency links that escape the template", async () => {
  const f = await fixture();
  await writeFile(join(f.root, "shared"), "original");
  await symlink("../shared", join(f.source, "shared"));
  await symlink(f.source, f.active, "dir");
  const release = await prepareRelease(f.source, f.destination, f.active, f.evidence);
  await assert.rejects(copyRelease(release), {code: "ExternalReleaseLink"});
  assert.equal(await realpath(f.active), f.source);
  assert.equal(await readFile(join(f.root, "shared"), "utf8"), "original");
});

test("release preflight rejects overlapping destinations and real activation directories", async () => {
  const f = await fixture();
  await assert.rejects(prepareRelease(f.source, join(f.source, "release"), f.active, f.evidence), {
    code: "OverlappingReleasePaths",
  });
  await assert.rejects(access(join(f.source, "release")), {code: "ENOENT"});
  await mkdir(f.active);
  await assert.rejects(prepareRelease(f.source, f.destination, f.active, f.evidence), {
    code: "ActivePathMustBeSymlink",
  });
  await assert.rejects(access(f.destination), {code: "ENOENT"});
  await rm(f.active, {recursive: true});
  await mkdir(f.destination);
  await writeFile(join(f.destination, "retained"), "existing release");
  await assert.rejects(prepareRelease(f.source, f.destination, f.active, f.evidence), {code: "ReleaseExists"});
  assert.equal(await readFile(join(f.destination, "retained"), "utf8"), "existing release");
});

test("release preflight leaves template untouched when missing parent paths overlap", async () => {
  const f = await fixture();
  const nested = join(f.source, "must-not-create");
  await symlink(f.source, join(f.root, "host-link"), "dir");
  const linked = join(f.root, "host-link", "must-not-create");
  for (const parent of [nested, linked]) {
    for (const [release, active, evidence] of [
      [join(parent, "release"), f.active, f.evidence],
      [f.destination, join(parent, "current"), f.evidence],
      [f.destination, f.active, join(parent, "evidence")],
    ]) {
      await assert.rejects(prepareRelease(f.source, release, active, evidence), {
        code: "OverlappingReleasePaths",
      });
    }
  }
  await assert.rejects(access(nested), {code: "ENOENT"});
  await assert.rejects(access(f.evidence), {code: "ENOENT"});
  await assert.rejects(access(f.destination), {code: "ENOENT"});
});
