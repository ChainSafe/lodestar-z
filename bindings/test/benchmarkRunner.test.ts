import {spawn, spawnSync} from "node:child_process";
import {once} from "node:events";
import {existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";
import {setTimeout as delay} from "node:timers/promises";
import {afterEach, describe, expect, it} from "vitest";

const root = resolve(import.meta.dirname, "../..");
const directories: string[] = [];

function fixture() {
  const dir = mkdtempSync(join(root, ".benchmark-test-"));
  directories.push(dir);
  const history = mkdtempSync(join(tmpdir(), "benchmark-history-"));
  directories.push(history);
  return {dir, history};
}

function run(files: string[], history?: string) {
  const script = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).scripts.benchmark.replace(
    "'bindings/perf/**/*.test.ts'",
    ""
  );
  return spawnSync(
    "/bin/sh",
    [
      "-c",
      `${script} "$@"`,
      "benchmark",
      ...files,
      ...(history ? ["--local", history, "--persist"] : []),
      "--skipPostComment",
      "--maxWarmUpMs",
      "0",
      "--maxWarmUpRuns",
      "0",
      "--minRuns",
      "1",
      "--maxRuns",
      "1",
    ],
    {
      cwd: root,
      encoding: "utf8",
      env: {...process.env, GITHUB_ACTIONS: "false"},
      timeout: 30000,
    }
  );
}

afterEach(() => {
  for (const dir of directories.splice(0)) rmSync(dir, {force: true, recursive: true});
});

describe("benchmark process isolation", () => {
  it("uses a fresh default history namespace", () => {
    const {dir} = fixture();
    const file = join(dir, "one.test.ts");
    writeFileSync(file, 'import {bench} from "@chainsafe/benchmark"; bench({id: "one", fn: () => {}});');
    const result = run([file]);
    expect(result.status, result.stdout + result.stderr).toBe(0);
    expect(result.stdout).toContain("dirpath ./benchmark_data/isolated-v1");
  });
  it.each(["SIGINT", "SIGTERM"] as const)("terminates the active worker on %s", async (signal) => {
    const {dir, history} = fixture();
    const ready = join(dir, "ready");
    const file = join(dir, "waiting.test.ts");
    writeFileSync(
      file,
      `import {writeFileSync} from "node:fs";
writeFileSync(${JSON.stringify(ready)}, String(process.pid));
setInterval(() => {}, 100);
await new Promise(() => {});`
    );
    const parent = spawn(
      process.execPath,
      ["--import", "tsx", "scripts/benchmark.mjs", file, "--defaultBranch", "main", "--local", history],
      {cwd: root, stdio: "ignore"}
    );
    let workerPid: number | undefined;
    try {
      for (let i = 0; i < 100 && !existsSync(ready); i++) await delay(20);
      expect(existsSync(ready)).toBe(true);
      workerPid = Number(readFileSync(ready, "utf8"));
      const exited = once(parent, "exit");
      parent.kill(signal);
      await exited;
      let alive = true;
      for (let i = 0; i < 50 && alive; i++) {
        try {
          process.kill(workerPid, 0);
        } catch {
          alive = false;
        }
        if (alive) await delay(20);
      }
      expect(alive).toBe(false);
    } finally {
      parent.kill("SIGKILL");
      if (workerPid) {
        try {
          process.kill(workerPid, "SIGKILL");
        } catch {
          // The worker normally exited before this failure-safe cleanup.
        }
      }
    }
  });
  it("rejects duplicate IDs across isolated files before persistence", () => {
    const {dir, history} = fixture();
    const files = ["a", "b"].map((name) => {
      const file = join(dir, `${name}.test.ts`);
      writeFileSync(file, 'import {bench} from "@chainsafe/benchmark"; bench({id: "duplicate", fn: () => {}});');
      return file;
    });
    const result = run(files, history);
    expect(result.status, result.stdout + result.stderr).toBe(1);
    expect(result.stdout + result.stderr).toContain("Duplicate benchmark ID");
    expect(existsSync(join(history, "history"))).toBe(false);
  });
  it("rejects collection errors without persisting a partial suite", () => {
    const {dir, history} = fixture();
    const good = join(dir, "a-good.test.ts");
    const bad = join(dir, "z-bad.test.ts");
    writeFileSync(good, 'import {bench} from "@chainsafe/benchmark"; bench({id: "good", fn: () => {}});');
    writeFileSync(bad, 'throw Error("intentional collection failure");');
    const result = run([good, bad], history);
    expect(result.status, result.stdout + result.stderr).toBe(1);
    expect(existsSync(join(history, "history"))).toBe(false);
  });

  it.each([
    [
      "failed benchmark",
      'import {bench} from "@chainsafe/benchmark"; bench({id: "broken", fn: () => { throw Error("intentional"); }});',
    ],
    ["clean exit without results", "process.exit(0);"],
    ["worker crash", 'process.kill(process.pid, "SIGKILL");'],
  ])("rejects %s without persisting results", (_name, source) => {
    const {dir, history} = fixture();
    const file = join(dir, "broken.test.ts");
    writeFileSync(file, source);
    const result = run([file], history);
    expect(result.status, result.stdout + result.stderr).toBe(1);
    expect(existsSync(join(history, "history"))).toBe(false);
  });

  it("preserves the framework regression exit", () => {
    const {dir, history} = fixture();
    const file = join(dir, "regression.test.ts");
    writeFileSync(file, 'import {bench} from "@chainsafe/benchmark"; bench({id: "regression", fn: () => {}});');
    const initial = run([file], history);
    expect(initial.status, initial.stdout + initial.stderr).toBe(0);
    const sha = spawnSync("git", ["rev-parse", "HEAD"], {cwd: root, encoding: "utf8"}).stdout.trim();
    const baseline = readFileSync(join(history, "history", `${sha}.csv`), "utf8").replace(
      /^regression,[^\n]+/m,
      "regression,1,1,1,3"
    );
    writeFileSync(join(history, "latest", "main.csv"), baseline);
    const result = run([file], history);
    expect(result.status, result.stdout + result.stderr).toBe(1);
    expect(result.stdout + result.stderr).toContain("Performance regression");
    // Two CLI runs each have a 30s subprocess deadline; allow both on busy CI runners.
  }, 65000);

  it("collects each file in a fresh process and persists all results together", () => {
    const {dir, history} = fixture();
    const finished = join(dir, "finished");
    const files = ["first", "second"].map((name) => {
      const file = join(dir, `${name}.test.ts`);
      writeFileSync(
        file,
        `import {bench} from "@chainsafe/benchmark";
import {existsSync, writeFileSync} from "node:fs";
if (${JSON.stringify(name)} === "first") process.on("exit", () => writeFileSync(${JSON.stringify(finished)}, "done"));
else if (!existsSync(${JSON.stringify(finished)})) throw Error("previous worker has not exited");
if (globalThis.benchmarkFixtureLoaded) throw Error("fixture leaked between files");
globalThis.benchmarkFixtureLoaded = true;
console.log("FIXTURE_PID=" + process.pid);
bench({id: "${name}", fn: () => {}});
`
      );
      return file;
    });
    const result = run(files, history);
    expect(result.status, result.stdout + result.stderr).toBe(0);
    const pids = [...result.stdout.matchAll(/FIXTURE_PID=(\d+)/g)].map((match) => match[1]);
    expect(new Set(pids).size).toBe(2);
    const sha = spawnSync("git", ["rev-parse", "HEAD"], {cwd: root, encoding: "utf8"}).stdout.trim();
    const csv = readFileSync(join(history, "history", `${sha}.csv`), "utf8");
    expect(csv).toContain("first,");
    expect(csv).toContain("second,");
  });
});
