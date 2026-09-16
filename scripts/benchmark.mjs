import {fork} from "node:child_process";
import {fileURLToPath} from "node:url";

// Keep the framework's comparison, persistence and GitHub report in the parent.
// Only its file execution is replaced; this adapter targets the pinned version.
const {BenchmarkRunner} = await import(new URL("./benchmark/runner.js", import.meta.resolve("@chainsafe/benchmark")));
const workerPath = fileURLToPath(new URL("./benchmarkWorker.mjs", import.meta.url));

BenchmarkRunner.prototype.process = async function (files) {
  const results = [];
  for (const file of files) {
    const batch = await new Promise((resolve, reject) => {
      const child = fork(workerPath, {serialization: "advanced", stdio: ["ignore", "inherit", "inherit", "ipc"]});
      let response;
      let interrupted;
      const onInterrupt = () => {
        interrupted = "SIGINT";
        child.kill("SIGINT");
      };
      const onTerminate = () => {
        interrupted = "SIGTERM";
        child.kill("SIGTERM");
      };
      process.once("SIGINT", onInterrupt);
      process.once("SIGTERM", onTerminate);
      child.on("message", (message) => {
        response = message;
      });
      child.once("error", reject);
      child.once("close", (code, signal) => {
        process.off("SIGINT", onInterrupt);
        process.off("SIGTERM", onTerminate);
        if (!interrupted && code === 0 && response?.results) resolve(response.results);
        else
          reject(new Error(response?.error ?? `Benchmark worker failed for ${file}: ${interrupted ?? signal ?? code}`));
      });
      child.send({benchmarkOpts: this.benchmarkOpts, file, prevBench: this.prevBench});
    });
    results.push(...batch);
  }
  const ids = new Set();
  for (const result of results) {
    if (ids.has(result.id)) throw new Error(`Duplicate benchmark ID: ${result.id}`);
    ids.add(result.id);
  }
  return results;
};

await import("@chainsafe/benchmark/cli");
