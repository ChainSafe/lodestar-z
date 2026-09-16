const {BenchmarkRunner} = await import(new URL("./benchmark/runner.js", import.meta.resolve("@chainsafe/benchmark")));

process.once("message", async ({file, prevBench, benchmarkOpts}) => {
  try {
    const runner = new BenchmarkRunner({benchmarkOpts, prevBench});
    let failed = false;
    const onAfterRunFiles = runner.onAfterRunFiles.bind(runner);
    runner.onAfterRunFiles = (files) => {
      failed = files.some((entry) => entry.result?.state !== "pass");
      onAfterRunFiles(files);
    };
    const results = await runner.process([file]);
    if (failed || results.length === 0) throw new Error(`Incomplete benchmark file: ${file}`);
    process.send({results}, () => process.disconnect());
  } catch (error) {
    process.exitCode = 1;
    process.send({error: error.stack ?? String(error)}, () => process.disconnect());
  }
});
